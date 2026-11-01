"""Pure-unit tests for app.services.users and app.services.registration."""

import datetime
from contextlib import asynccontextmanager
from dataclasses import fields as dataclass_fields
from datetime import UTC
from types import SimpleNamespace
from unittest.mock import AsyncMock, create_autospec, patch, sentinel

import pytest
from psycopg.errors import UniqueViolation
from psycopg.pq import DiagnosticField

from app.credentials import normalize_email, validate_seed_credentials
from app.services import email_change, password_verification, registration_setup, users
from app.services.session_ids import hash_session_id
from app.services.tokens import action_token_url
from app.services.users import (
    DISPLAY_NAME_MAX_LENGTH,
    User,
    normalize_display_name,
    parse_user,
    user_columns_sql,
    validate_user_schema,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool, make_sample_user_row

_ADMIN_MEMBERSHIP_SERVICES = [users.update_access_tier, users.set_user_active, users.set_user_admin]
_ADMIN_MEMBERSHIP_SERVICE_IDS = ["update_access_tier", "set_user_active", "set_user_admin"]


class TestDisplayNameNormalization:
    """normalize_display_name is the shared validator registration and rename both call."""

    def test_strips_whitespace_and_returns_stripped_value(self):
        """The validator strips leading/trailing whitespace and returns the
        stripped value, rather than validating it and passing the raw
        (padded) input through to the database."""
        assert normalize_display_name("  Alice  ") == "Alice"

    def test_rejects_c0_control_char(self):
        """C0 control characters (here BEL \\x07) are rejected."""
        with pytest.raises(ValueError, match="control characters"):
            normalize_display_name("Alice\x07")

    def test_rejects_del_char(self):
        """DEL (\\x7f) is rejected too: the ban is 'ord < 0x20 or == 0x7f',
        not just ord < 0x20. DEL is not whitespace, so strip() cannot save
        it."""
        with pytest.raises(ValueError, match="control characters"):
            normalize_display_name("\x7f")

    @pytest.mark.parametrize("raw", ["", "   "], ids=["empty", "whitespace_only"])
    def test_rejects_empty_and_whitespace_only(self, raw):
        """Empty input and whitespace-only input (empty after stripping) are
        both rejected with the empty-name error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            normalize_display_name(raw)

    def test_rejects_over_max_length(self):
        """201 characters exceeds DISPLAY_NAME_MAX_LENGTH=200 and raises."""
        assert DISPLAY_NAME_MAX_LENGTH == 200
        with pytest.raises(ValueError, match="at most 200 characters"):
            normalize_display_name("a" * 201)

    def test_accepts_exactly_max_length(self):
        """The boundary is inclusive: exactly 200 characters passes. Padding
        is stripped before the length check, so a padded 200-character name
        also passes (strip-then-validate ordering)."""
        name = "a" * 200
        assert normalize_display_name(name) == name
        assert normalize_display_name("  " + name + "  ") == name

    def test_accepts_unicode(self):
        """The control-character ban must not reject legitimate non-ASCII
        names (umlauts, accents): only C0 and DEL are banned, not 'not
        ASCII'."""
        assert normalize_display_name("Müller-Àé") == "Müller-Àé"


class TestSharedEmailNormalization:
    """Require bootstrap and registration to use the shared email normalization contract."""

    def test_seed_and_local_registration_normalize_an_address_identically(self):
        """Check seed and local registration normalize an address identically."""
        raw = "  ALICE@EXAMPLE.ORG  "
        assert (
            validate_seed_credentials(raw, "a-supported-long-password")
            == normalize_email(raw)
            == "alice@example.org"
        )

    def test_normalization_rejects_smtputf8_local_parts_but_allows_idn_domains(self):
        """Check normalization rejects SMTPUTF8 local parts but allows idn domains."""
        assert normalize_email("réader@example.org") is None
        assert normalize_email("reader@bücher.ch") == "reader@bücher.ch"


class TestUserRowParsing:
    """parse_user maps a database row dict onto the User dataclass."""

    def test_full_row_maps_every_field(self):
        """A full DB row (fixtures.make_sample_user_row) maps 1:1 onto the User dataclass: every
        dataclass field equals the row value of the same name.
        """
        row = make_sample_user_row()
        user = parse_user(row)

        assert isinstance(user, User)
        for f in dataclass_fields(User):
            assert getattr(user, f.name) == row[f.name], f"field {f.name} not mapped"

    def test_row_missing_a_required_key_raises_key_error(self):
        """Check row missing a required key raises key error."""
        created = datetime.datetime(2026, 5, 1, tzinfo=datetime.UTC)
        row = {
            "id": 7,
            "email": "min@example.org",
            "auth_method": "local",
            "access_tier": "public",
            "is_active": True,
            "created_at": created,
        }
        with pytest.raises(KeyError, match="display_name"):
            parse_user(row)


class TestUserSchemaValidation:
    """validate_user_schema keeps USER_COLUMNS and the User dataclass in sync."""

    def test_passes_on_real_lists(self):
        """Check passes on real lists."""
        validate_user_schema()

    def test_flags_duplicate_sql_column(self, monkeypatch):
        """Check flags duplicate SQL column (AssertionError)."""
        monkeypatch.setattr(users, "USER_COLUMNS", [*users.USER_COLUMNS, "email"])
        with pytest.raises(AssertionError, match=r"USER_COLUMNS.*duplicate.*email"):
            validate_user_schema()

    def test_flags_extra_sql_column(self, monkeypatch):
        """A column present in USER_COLUMNS but missing on the dataclass
        raises AssertionError naming the offending column."""
        monkeypatch.setattr(users, "USER_COLUMNS", [*users.USER_COLUMNS, "bogus_col"])
        with pytest.raises(AssertionError, match="bogus_col") as excinfo:
            validate_user_schema()
        assert "not on User" in str(excinfo.value)

    def test_flags_missing_sql_column(self, monkeypatch):
        """Check flags missing SQL column (AssertionError)."""
        monkeypatch.setattr(users, "USER_COLUMNS", [c for c in users.USER_COLUMNS if c != "email"])
        with pytest.raises(AssertionError, match="email") as excinfo:
            validate_user_schema()
        assert "not in USER_COLUMNS" in str(excinfo.value)


class TestUserColumnsSql:
    """user_columns_sql renders the SELECT column list (psycopg3 as_string(None))."""

    def test_unaliased_rendering_quotes_every_column_and_computes_totp_flag(self):
        """Check unaliased rendering quotes every column and computes TOTP flag."""
        rendered = user_columns_sql().as_string(None)

        assert '"id"' in rendered
        for col in users.USER_COLUMNS:
            assert f'"{col}"' in rendered, f"column {col} missing from SELECT list"
        assert "(totp_secret IS NOT NULL) AS totp_configured" in rendered
        assert '"totp_secret"' not in rendered

    def test_aliased_rendering_table_qualifies_every_column(self):
        """Check aliased rendering table qualifies every column."""
        rendered = user_columns_sql("u").as_string(None)

        assert '"u"."id"' in rendered
        for col in users.USER_COLUMNS:
            assert f'"u"."{col}"' in rendered, f"column {col} not alias-qualified"
        assert '("u".totp_secret IS NOT NULL) AS totp_configured' in rendered

    def test_cached_constant_matches_fresh_build(self):
        """The module-level cached USER_COLUMNS_SQL is exactly the unaliased
        build: the cache and the builder must not drift apart."""
        assert users.USER_COLUMNS_SQL.as_string(None) == user_columns_sql().as_string(None)


class TestPendingLocalActivation:
    """Administrator activation cannot bypass mailbox-bound credential setup."""

    async def test_passwordless_target_is_rejected_before_activation(self):
        """Check passwordless target is rejected before activation."""
        actor = {
            "is_active": True,
            "is_admin": True,
            "auth_method": "local",
            "totp_secret": "encrypted-secret",
            "totp_recovery_code_generation": 1,
            "recovery_codes_available": True,
        }
        pending = {
            "is_active": False,
            "is_admin": False,
            "auth_method": "local",
            "federated_status": None,
            "password_configured": False,
        }
        cursor = make_async_cursor(fetchone=[actor, {"session": 1}, pending])
        with (
            patch.object(
                users,
                "get_db_cursor",
                autospec=True,
                return_value=FakeCursorCtx(cursor),
            ),
            pytest.raises(users.AdminActionRejected, match="complete email setup"),
        ):
            await users.set_user_active(
                make_mock_pool(),
                2,
                True,
                actor_id=1,
                actor_session_id="resolved-session",
            )
        statements = [str(call.args[0]).strip() for call in cursor.execute.await_args_list]
        assert all(statement.startswith("SELECT") for statement in statements)
        assert "password_configured" in statements[-1]


class TestAdminMembershipActorGuard:
    """update_access_tier, set_user_active, set_user_admin and
    stage_admin_email_change all guard the acting administrator's own
    session before touching the target row."""

    @pytest.mark.parametrize(
        "service", _ADMIN_MEMBERSHIP_SERVICES, ids=_ADMIN_MEMBERSHIP_SERVICE_IDS
    )
    @pytest.mark.parametrize(
        "call_kwargs, missing_argument",
        [({}, "actor_id"), ({"actor_id": 2}, "actor_session_id")],
        ids=["actor_id_omitted", "actor_session_id_omitted"],
    )
    async def test_omitted_actor_argument_fails_before_database_access(
        self, service, call_kwargs, missing_argument
    ):
        """Calling an admin-membership service without actor_id, or without
        actor_session_id, raises TypeError before any database access."""
        with (
            patch.object(users, "get_db_cursor", autospec=True) as db,
            pytest.raises(TypeError, match=missing_argument),
        ):
            await service(make_mock_pool(), 1, False, **call_kwargs)
        db.assert_not_called()

    async def test_admin_email_staging_requires_actor_session_before_database_access(self):
        """stage_admin_email_change likewise requires actor_session_id
        before touching the database."""
        with (
            patch.object(email_change, "get_db_cursor", autospec=True) as db,
            pytest.raises(TypeError, match="actor_session_id"),
        ):
            await email_change.stage_admin_email_change(
                make_mock_pool(),
                actor_id=1,
                target_user_id=2,
                new_email="new@example.org",
            )
        db.assert_not_called()

    @pytest.mark.parametrize(
        "service", _ADMIN_MEMBERSHIP_SERVICES, ids=_ADMIN_MEMBERSHIP_SERVICE_IDS
    )
    @pytest.mark.parametrize(
        "actor",
        [None, {"is_active": False, "is_admin": True}, {"is_active": True, "is_admin": False}],
        ids=["actor_row_missing", "actor_inactive", "actor_not_admin"],
    )
    async def test_stale_actor_prevents_all_writes(self, service, actor):
        """Check stale actor prevents all writes."""
        cur = make_async_cursor(fetchone=actor)
        with (
            patch.object(
                users,
                "get_db_cursor",
                autospec=True,
                side_effect=lambda _pool: FakeCursorCtx(cur),
            ),
            pytest.raises(users.AdminActionRejected, match="access changed"),
        ):
            await service(
                make_mock_pool(),
                2,
                False,
                actor_id=1,
                actor_session_id="resolved-session",
            )
        statements = [str(call.args[0]).strip() for call in cur.execute.await_args_list]
        assert statements[0].startswith("SELECT pg_advisory_xact_lock")
        assert all(statement.startswith("SELECT") for statement in statements)

    @pytest.mark.parametrize(
        "service", _ADMIN_MEMBERSHIP_SERVICES, ids=_ADMIN_MEMBERSHIP_SERVICE_IDS
    )
    async def test_missing_exact_session_prevents_target_lock_and_write(self, service):
        """Check missing exact session prevents target lock and write."""
        healthy_actor = {
            "is_active": True,
            "is_admin": True,
            "auth_method": "local",
            "totp_secret": "encrypted-secret",
            "totp_recovery_code_generation": 1,
            "recovery_codes_available": True,
        }
        cur = make_async_cursor(fetchone=[healthy_actor, None])
        with (
            patch.object(
                users,
                "get_db_cursor",
                autospec=True,
                side_effect=lambda _pool: FakeCursorCtx(cur),
            ),
            pytest.raises(users.AdminActionRejected, match="session is no longer valid"),
        ):
            await service(
                make_mock_pool(),
                2,
                False,
                actor_id=1,
                actor_session_id="revoked-session",
            )

        statements = [str(call.args[0]).strip() for call in cur.execute.await_args_list]
        assert len(statements) == 3
        assert "FROM sessions" in statements[-1]
        assert "user_id = %s" in statements[-1]
        assert "purpose = 'full'" in statements[-1]
        assert "clock_timestamp()" in statements[-1]
        assert "FOR UPDATE" in statements[-1]
        assert cur.execute.await_args_list[-1].args[1] == (
            hash_session_id("revoked-session"),
            1,
        )

    async def test_healthy_actor_with_live_exact_session_reaches_target_lock_and_write(self):
        """Check healthy actor with live exact session reaches target lock and write."""
        healthy_actor = {
            "is_active": True,
            "is_admin": True,
            "auth_method": "local",
            "totp_secret": "encrypted-secret",
            "totp_recovery_code_generation": 1,
            "recovery_codes_available": True,
        }
        target_row = {"access_tier": "registered", "auth_method": "local", "federated_status": None}
        write_row = {"new_value": "vetted"}
        cur = make_async_cursor(fetchone=[healthy_actor, {"session": 1}, target_row, write_row])
        with patch.object(
            users,
            "get_db_cursor",
            autospec=True,
            side_effect=lambda _pool: FakeCursorCtx(cur),
        ):
            old_value, new_value = await users.update_access_tier(
                make_mock_pool(),
                2,
                "vetted",
                actor_id=1,
                actor_session_id="live-session",
            )

        assert (old_value, new_value) == ("registered", "vetted")
        statements = [str(call.args[0]) for call in cur.execute.await_args_list]
        assert statements[0].strip().startswith("SELECT pg_advisory_xact_lock")
        assert any("FROM sessions" in statement for statement in statements)
        assert "UPDATE users" in statements[-1]
        assert cur.execute.await_args_list[-1].args[1] == {"user_id": 2, "new_tier": "vetted"}


class TestEmailChangeMembership:
    """Self-service email-change staging must not query destination-email membership."""

    async def test_self_service_staging_never_queries_candidate_membership(self):
        """Self-service staging reads the actor, locks the exact session,
        and samples database time without checking candidate-email membership."""
        cursor = AsyncMock()
        cursor.fetchone = AsyncMock(
            side_effect=[
                {
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "login_unlocked": True,
                },
                {
                    "email_verified": True,
                    "totp_secret": "encrypted-secret",
                    "totp_recovery_required": False,
                    "email": "actor@example.org",
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "locked_until": None,
                },
                {"expires_at": datetime.datetime(2030, 1, 1, tzinfo=UTC)},
                {"database_now": datetime.datetime(2026, 1, 1, tzinfo=UTC)},
            ]
        )

        @asynccontextmanager
        async def cursor_context(_pool):
            """Yield the scripted cursor without a real database connection."""
            yield cursor

        action = SimpleNamespace(
            token_hash="token-hash",
            expires_at=datetime.datetime(2030, 1, 1, tzinfo=UTC),
        )
        store_pending = create_autospec(email_change.store_pending_email_cur)
        enqueue = create_autospec(email_change.enqueue_outbound_email_cur)

        with (
            patch.object(
                email_change,
                "get_db_cursor",
                new=create_autospec(email_change.get_db_cursor, side_effect=cursor_context),
            ),
            patch.object(
                email_change,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    email_change.reserve_session_step_up_attempt,
                    return_value=email_change.SessionStepUpAttemptOutcome.RESERVED,
                ),
            ),
            patch.object(
                password_verification,
                "run_password_work",
                new=create_autospec(password_verification.run_password_work),
            ),
            patch.object(
                email_change,
                "generate_email_change_token",
                new=create_autospec(
                    email_change.generate_email_change_token, return_value="signed-token"
                ),
            ),
            patch.object(
                email_change,
                "email_change_token_email_metadata",
                new=create_autospec(
                    email_change.email_change_token_email_metadata, return_value=action
                ),
            ),
            patch.object(
                email_change,
                "build_email_change_notice",
                new=create_autospec(
                    email_change.build_email_change_notice, return_value=sentinel.notice
                ),
            ),
            patch.object(
                email_change,
                "build_email_change_verification",
                new=create_autospec(
                    email_change.build_email_change_verification,
                    return_value=sentinel.verification,
                ),
            ),
            patch.object(
                email_change,
                "verify_and_consume_totp_cur",
                autospec=True,
                return_value=True,
            ) as consume_totp,
            patch.object(email_change, "store_pending_email_cur", new=store_pending),
            patch.object(email_change, "enqueue_outbound_email_cur", new=enqueue),
        ):
            result = await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=7,
                session_id="raw-session-id",
                current_password="correct password",
                new_email="candidate@example.org",
                totp_code="111111",
            )

        statements = [" ".join(call.args[0].split()) for call in cursor.execute.await_args_list]
        assert len(statements) == 4
        assert statements[-1] == "SELECT clock_timestamp() AS database_now"
        assert all("LOWER(email)" not in statement for statement in statements)
        assert result == email_change.SelfEmailChangeResult(
            user_id=7,
            old_email="actor@example.org",
            new_email="candidate@example.org",
        )
        consume_totp.assert_awaited_once_with(cursor, 7, "111111")
        store_pending.assert_awaited_once_with(
            cursor,
            7,
            "candidate@example.org",
            "token-hash",
            expected_auth_revision=4,
        )
        assert [call.kwargs["email"] for call in enqueue.await_args_list] == [
            sentinel.notice,
            sentinel.verification,
        ]

    async def test_valid_session_reaches_the_staging_write(self):
        """Check valid session reaches the staging write."""
        cursor = AsyncMock()
        cursor.fetchone = AsyncMock(
            side_effect=[
                {
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "login_unlocked": True,
                },
                {
                    "email_verified": True,
                    "totp_secret": "encrypted-secret",
                    "totp_recovery_required": False,
                    "email": "actor@example.org",
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "locked_until": None,
                },
                {"expires_at": datetime.datetime(2030, 1, 1, tzinfo=UTC)},
                {"database_now": datetime.datetime(2026, 1, 1, tzinfo=UTC)},
            ]
        )

        @asynccontextmanager
        async def cursor_context(_pool):
            """Yield the scripted cursor without a real database connection."""
            yield cursor

        action = SimpleNamespace(
            token_hash="token-hash",
            expires_at=datetime.datetime(2030, 1, 1, tzinfo=UTC),
        )
        store_pending = create_autospec(email_change.store_pending_email_cur)

        with (
            patch.object(
                email_change,
                "get_db_cursor",
                new=create_autospec(email_change.get_db_cursor, side_effect=cursor_context),
            ),
            patch.object(
                email_change,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    email_change.reserve_session_step_up_attempt,
                    return_value=email_change.SessionStepUpAttemptOutcome.RESERVED,
                ),
            ),
            patch.object(
                password_verification,
                "run_password_work",
                new=create_autospec(password_verification.run_password_work),
            ),
            patch.object(
                email_change,
                "generate_email_change_token",
                new=create_autospec(
                    email_change.generate_email_change_token, return_value="signed-token"
                ),
            ),
            patch.object(
                email_change,
                "email_change_token_email_metadata",
                new=create_autospec(
                    email_change.email_change_token_email_metadata, return_value=action
                ),
            ),
            patch.object(
                email_change,
                "build_email_change_notice",
                new=create_autospec(
                    email_change.build_email_change_notice, return_value=sentinel.notice
                ),
            ),
            patch.object(
                email_change,
                "build_email_change_verification",
                new=create_autospec(
                    email_change.build_email_change_verification,
                    return_value=sentinel.verification,
                ),
            ) as verification_builder,
            patch.object(
                email_change,
                "verify_and_consume_totp_cur",
                autospec=True,
                return_value=True,
            ) as consume_totp,
            patch.object(email_change, "store_pending_email_cur", new=store_pending),
            patch.object(
                email_change,
                "enqueue_outbound_email_cur",
                new=create_autospec(email_change.enqueue_outbound_email_cur),
            ),
        ):
            result = await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=7,
                session_id="raw-session-id",
                current_password="correct password",
                new_email="candidate@example.org",
                totp_code="111111",
            )

        assert result == email_change.SelfEmailChangeResult(
            user_id=7,
            old_email="actor@example.org",
            new_email="candidate@example.org",
        )
        consume_totp.assert_awaited_once_with(cursor, 7, "111111")
        store_pending.assert_awaited_once_with(
            cursor,
            7,
            "candidate@example.org",
            "token-hash",
            expected_auth_revision=4,
        )

        verification_builder.assert_called_once_with(
            "candidate@example.org",
            f"{email_change.settings.public_base_url}"
            f"{action_token_url('/account/confirm-email', 'signed-token')}",
            expires_at=action.expires_at,
            security_code="signed-token",
        )


class TestLocalUserEnrollmentBoundary:
    """Mailbox registration cannot accept a caller-supplied TOTP secret."""

    @pytest.mark.parametrize(
        "secret",
        [None, "JBSWY3DPEHPK3PXP", "encrypted-secret"],
        ids=["totp_secret_none", "totp_secret_base32_value", "totp_secret_already_encrypted"],
    )
    async def test_creation_rejects_totp_parameter_before_any_work(self, secret):
        """Enrollment happens after credential setup, never in the email request."""
        with (
            patch.object(registration_setup, "get_db_cursor", autospec=True) as db,
            patch.object(registration_setup, "run_password_work", autospec=True) as hash_password,
            pytest.raises(TypeError, match="totp_secret"),
        ):
            await registration_setup.begin_local_registration(
                make_mock_pool(),
                email="person@example.org",
                **{"totp_secret": secret},
            )
        db.assert_not_called()
        hash_password.assert_not_awaited()


async def test_registration_preserves_unrelated_unique_violation():
    """Only the email conflict target becomes a duplicate notice; other failures escape."""
    cursor = make_async_cursor()
    violation = UniqueViolation(
        "unrelated unique constraint",
        info={DiagnosticField.CONSTRAINT_NAME: b"other_unique_constraint"},
    )
    cursor.execute.side_effect = violation
    with (
        patch.object(
            registration_setup,
            "get_db_cursor",
            autospec=True,
            return_value=FakeCursorCtx(cursor),
        ),
        patch.object(
            registration_setup,
            "enqueue_outbound_email_cur",
            autospec=True,
        ) as queue,
        patch.object(registration_setup, "run_password_work", autospec=True) as hash_password,
        pytest.raises(UniqueViolation) as caught,
    ):
        await registration_setup.begin_local_registration(make_mock_pool(), email="new@example.org")
    assert caught.value is violation
    queue.assert_not_awaited()
    hash_password.assert_not_awaited()
