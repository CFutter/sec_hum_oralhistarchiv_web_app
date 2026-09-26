"""Pure-unit tests for app.services.users and app.services.registration.

Covers the model plumbing everything else builds on (parse_user row mapping,
the USER_COLUMNS/User schema-sync validator, the SELECT builder
user_columns_sql, and the UserAlreadyExistsError contract), the shared
normalize_display_name validator that both registration and rename call, the
administrator-membership guard that update_access_tier / set_user_active /
set_user_admin / stage_admin_email_change all run before touching the
database, the isolation of self-service email-change staging from candidate
membership state, and the removal of the totp_secret parameter from local
account creation.

No database, no TestClient — everything here is import-and-call or a mocked
cursor proving what a service will and will not do before it reaches one.
"""

import datetime
from contextlib import asynccontextmanager
from dataclasses import fields as dataclass_fields
from datetime import UTC
from types import SimpleNamespace
from unittest.mock import AsyncMock, create_autospec, patch, sentinel

import pytest

from app.credentials import normalize_email, validate_seed_credentials
from app.services import email_change, users
from app.services.registration import register_local_user as create_local_user
from app.services.session_ids import hash_session_id
from app.services.users import (
    DISPLAY_NAME_MAX_LENGTH,
    User,
    UserAlreadyExistsError,
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
    """`app.credentials.normalize_email` is the single normalization point
    both the admin-seed bootstrap (`validate_seed_credentials`) and local
    account creation (`insert_unverified_local_user_cur`) call — so a seeded
    admin and a self-registered user with the same address always collide
    on the same stored identity."""

    def test_seed_and_local_registration_normalize_an_address_identically(self):
        raw = "  ALICE@UZH.CH  "
        assert (
            validate_seed_credentials(raw, "a-supported-long-password")
            == normalize_email(raw)
            == "alice@uzh.ch"
        )

    def test_normalization_rejects_smtputf8_local_parts_but_allows_idn_domains(self):
        """Local-account normalization pins `allow_smtputf8=False`: a
        non-ASCII local part is rejected (no downstream SMTP relay is
        guaranteed to support the SMTPUTF8 extension), while a non-ASCII
        (IDN) domain with a plain ASCII local part is accepted and
        NFC-normalized — the positive control for the rejection."""
        assert normalize_email("réader@example.org") is None
        assert normalize_email("reader@bücher.ch") == "reader@bücher.ch"


class TestUserRowParsing:
    """parse_user maps a database row dict onto the User dataclass."""

    def test_full_row_maps_every_field(self):
        """A full DB row (fixtures.make_sample_user_row) maps 1:1 onto the
        User dataclass: every dataclass field equals the row value of the
        same name. A field silently dropped or renamed in parse_user fails
        here."""
        row = make_sample_user_row()
        user = parse_user(row)

        assert isinstance(user, User)
        for f in dataclass_fields(User):
            assert getattr(user, f.name) == row[f.name], f"field {f.name} not mapped"

    def test_row_missing_a_required_key_raises_key_error(self):
        """parse_user reads every dataclass field straight off the row
        (`row[field.name]`, no defaulting): a row missing a required key
        such as display_name raises KeyError naming it, rather than
        silently defaulting."""
        created = datetime.datetime(2026, 5, 1, tzinfo=datetime.UTC)
        row = {
            "id": 7,
            "email": "min@uzh.ch",
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
        """The shipped USER_COLUMNS and User dataclass are in sync: the
        startup validator must not raise on the real module state. This is
        the positive control for the two drift checks below."""
        validate_user_schema()  # must not raise

    def test_flags_extra_sql_column(self, monkeypatch):
        """A column present in USER_COLUMNS but missing on the dataclass
        raises AssertionError naming the offending column."""
        monkeypatch.setattr(users, "USER_COLUMNS", [*users.USER_COLUMNS, "bogus_col"])
        with pytest.raises(AssertionError, match="bogus_col") as excinfo:
            validate_user_schema()
        assert "not on User" in str(excinfo.value)

    def test_flags_missing_sql_column(self, monkeypatch):
        """A dataclass field absent from USER_COLUMNS raises AssertionError
        the other direction ('Fields on User but not in USER_COLUMNS'):
        dropping 'email' from the SELECT list must be caught at startup."""
        monkeypatch.setattr(users, "USER_COLUMNS", [c for c in users.USER_COLUMNS if c != "email"])
        with pytest.raises(AssertionError, match="email") as excinfo:
            validate_user_schema()
        assert "not in USER_COLUMNS" in str(excinfo.value)


class TestUserColumnsSql:
    """user_columns_sql renders the SELECT column list (psycopg3 as_string(None))."""

    def test_unaliased_rendering_quotes_every_column_and_computes_totp_flag(self):
        """Unaliased build: every USER_COLUMNS column renders as a quoted
        identifier ('"id"', ...) and the computed totp flag renders as
        '(totp_secret IS NOT NULL) AS totp_configured' — the encrypted
        secret itself is never selected as a column of its own."""
        rendered = user_columns_sql().as_string(None)

        assert '"id"' in rendered
        for col in users.USER_COLUMNS:
            assert f'"{col}"' in rendered, f"column {col} missing from SELECT list"
        assert "(totp_secret IS NOT NULL) AS totp_configured" in rendered
        assert '"totp_secret"' not in rendered

    def test_aliased_rendering_table_qualifies_every_column(self):
        """Alias 'u': every column is table-qualified ('"u"."id"') and the
        computed totp flag reads from the aliased table
        ('("u".totp_secret IS NOT NULL) AS totp_configured') — guards joined
        queries picking columns from the right table."""
        rendered = user_columns_sql("u").as_string(None)

        assert '"u"."id"' in rendered
        for col in users.USER_COLUMNS:
            assert f'"u"."{col}"' in rendered, f"column {col} not alias-qualified"
        assert '("u".totp_secret IS NOT NULL) AS totp_configured' in rendered

    def test_cached_constant_matches_fresh_build(self):
        """The module-level cached USER_COLUMNS_SQL is exactly the unaliased
        build: the cache and the builder must not drift apart."""
        assert users.USER_COLUMNS_SQL.as_string(None) == user_columns_sql().as_string(None)


class TestUserAlreadyExistsError:
    """UserAlreadyExistsError's except-ordering contract for the register route."""

    def test_is_value_error_carrying_email(self):
        """UserAlreadyExistsError subclasses ValueError and carries .email.
        The register route relies on `except UserAlreadyExistsError` staying
        ordered before `except ValueError` — which only works because of
        this subclass relationship; a plain `except ValueError` handler
        would swallow it too."""
        err = UserAlreadyExistsError("dup@uzh.ch")

        assert isinstance(err, ValueError)
        assert err.email == "dup@uzh.ch"
        assert "dup@uzh.ch" in str(err)

        with pytest.raises(ValueError):
            raise UserAlreadyExistsError("dup@uzh.ch")


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
                new_email="new@uzh.ch",
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
        """A missing, inactive, or non-admin actor is rejected by the
        session guard before any write statement executes: every statement
        the service issued is a SELECT, starting with the advisory lock."""
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
        """A healthy actor whose exact session was revoked is still
        rejected: the session lookup locks on the exact session id, user id
        and 'full' purpose, and no target row lock or write follows it."""
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
        """The positive control for the guard above: a healthy administrator
        actor holding the exact, live 'full' session named in the call is
        not rejected. `update_access_tier` reaches its target-row lock and
        issues the UPDATE with the target user id and the requested tier."""
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
        """stage_self_email_change issues exactly the actor-lookup,
        actor-refetch, and session-insert statements; none of them look at
        the candidate email's own membership or admin state (no
        LOWER(email) lookup against the candidate)."""
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
                    "email": "actor@uzh.ch",
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "login_unlocked": True,
                },
                {"session": 1},
            ]
        )

        @asynccontextmanager
        async def cursor_context(_pool):
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
                email_change,
                "run_password_work",
                new=create_autospec(email_change.run_password_work),
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
            patch.object(email_change, "store_pending_email_cur", new=store_pending),
            patch.object(email_change, "enqueue_outbound_email_cur", new=enqueue),
        ):
            result = await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=7,
                session_id="raw-session-id",
                current_password="correct password",
                new_email="candidate@uzh.ch",
            )

        statements = [" ".join(call.args[0].split()) for call in cursor.execute.await_args_list]
        assert len(statements) == 3
        assert all("LOWER(email)" not in statement for statement in statements)
        assert result == email_change.SelfEmailChangeResult(
            user_id=7,
            old_email="actor@uzh.ch",
            new_email="candidate@uzh.ch",
        )
        store_pending.assert_awaited_once_with(
            cursor,
            7,
            "candidate@uzh.ch",
            "token-hash",
            expected_auth_revision=4,
        )
        assert [call.kwargs["email"] for call in enqueue.await_args_list] == [
            sentinel.notice,
            sentinel.verification,
        ]

    async def test_valid_session_reaches_the_staging_write(self):
        """The positive control for the guard above: a request presenting
        the exact, live, unchanged-revision session it names reaches
        `store_pending_email_cur` and returns the staged result, rather than
        being rejected before ever writing."""
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
                    "email": "actor@uzh.ch",
                    "password_hash": "argon-hash",
                    "auth_revision": 4,
                    "is_active": True,
                    "auth_method": "local",
                    "login_unlocked": True,
                },
                {"session": 1},
            ]
        )

        @asynccontextmanager
        async def cursor_context(_pool):
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
                email_change,
                "run_password_work",
                new=create_autospec(email_change.run_password_work),
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
                new_email="candidate@uzh.ch",
            )

        assert result == email_change.SelfEmailChangeResult(
            user_id=7,
            old_email="actor@uzh.ch",
            new_email="candidate@uzh.ch",
        )
        store_pending.assert_awaited_once_with(
            cursor,
            7,
            "candidate@uzh.ch",
            "token-hash",
            expected_auth_revision=4,
        )


class TestLocalUserEnrollmentBoundary:
    """Local account creation cannot accept a caller-supplied TOTP secret."""

    @pytest.mark.parametrize(
        "secret",
        [None, "JBSWY3DPEHPK3PXP", "encrypted-secret"],
        ids=["totp_secret_none", "totp_secret_base32_value", "totp_secret_already_encrypted"],
    )
    async def test_creation_rejects_removed_totp_parameter_before_any_work(self, secret):
        """register_local_user no longer accepts a totp_secret keyword at
        all (enrollment is a separate, later step): passing one raises
        TypeError before password hashing or any database access, whatever
        value is passed."""
        with (
            patch("app.services.registration.get_db_cursor", autospec=True) as db,
            patch("app.services.registration.run_password_work", autospec=True) as hash_password,
            pytest.raises(TypeError, match="totp_secret"),
        ):
            await create_local_user(
                make_mock_pool(),
                email="person@example.org",
                display_name="Person",
                password="not-used",
                **{"totp_secret": secret},
            )
        db.assert_not_called()
        hash_password.assert_not_awaited()
