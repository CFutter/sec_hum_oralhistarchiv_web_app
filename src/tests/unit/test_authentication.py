"""Login-failure streaks, lockout-notice claims and atomic recovery resets."""

import re
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

from app.services import (
    authentication,
    password_reset,
    password_verification,
    totp,
    totp_recover,
    users,
)
from app.services.authentication import (
    queue_lockout_notice_cur,
    record_login_failure_cur,
)
from app.services.email_outbox import OutboundEmail
from app.services.session_ids import hash_session_id
from app.services.totp_recover import _RecoveryPasswordAttempt
from app.services.totp_recovery_codes import ReservedRecoveryCodePasswordAttempt
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool, make_sample_user_row

USER_ID = 7
AUTH_REVISION = 3


def _assert_placeholders_match_params(statement: str, params) -> None:
    """Require named placeholders to exist in the mapping and positional counts to match."""
    named = set(re.findall(r"%\(([a-zA-Z_]+)\)s", statement))
    remaining = re.sub(r"%\([a-zA-Z_]+\)s", "", statement)
    positional = re.findall(r"%s", remaining)
    if isinstance(params, dict):
        assert named, "expected named placeholders for a dict of params"
        assert not positional, "mixed named and positional placeholders"
        assert named == set(params), f"placeholders {named} do not match params {set(params)}"
    else:
        assert not named, "expected positional placeholders for a sequence of params"
        assert len(positional) == len(params), (
            f"{len(positional)} placeholders but {len(params)} params"
        )


class TestRecordLoginFailureTransitions:
    """Keep live locks unchanged and restart expired streaks at one."""

    @staticmethod
    def _cursor(*, failed_login_count, locked_until, database_now, updated=None):
        """Answer locked-user, database-clock and optional UPDATE reads in order."""
        rows = [
            {"failed_login_count": failed_login_count, "locked_until": locked_until},
            {"database_now": database_now},
        ]
        if updated is not None:
            rows.append(updated)
        return make_async_cursor(fetchone=rows)

    @staticmethod
    def _counter_update(cur):
        """The (statement, parameters) of the counter UPDATE, or None."""
        for call in cur.execute.await_args_list:
            statement = str(call.args[0])
            if "UPDATE users" in statement and "failed_login_count" in statement:
                return statement, call.args[1]
        return None

    async def test_failure_after_an_expired_lock_is_the_first_of_a_new_streak(self, monkeypatch):
        """Restart the failure count at one after lock expiry."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        monkeypatch.setattr(settings, "login_lockout_minutes", 15)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=5,
            locked_until=database_now - timedelta(minutes=1),
            database_now=database_now,
            updated={"failed_login_count": 1, "locked_until": None},
        )

        new_count, entered_lockout = await record_login_failure_cur(
            cur, USER_ID, expected_auth_revision=AUTH_REVISION
        )

        assert new_count == 1
        assert entered_lockout is False
        statement, params = self._counter_update(cur)
        assert params[:2] == (1, None), "an expired streak must restart at one with no new lock"
        _assert_placeholders_match_params(statement, params)

    async def test_failure_at_the_exact_expiry_instant_is_treated_as_expired(self, monkeypatch):
        """Treat expiry equal to the locked-row database clock as expired."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        monkeypatch.setattr(settings, "login_lockout_minutes", 15)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=5,
            locked_until=database_now,
            database_now=database_now,
            updated={"failed_login_count": 1, "locked_until": None},
        )

        new_count, entered_lockout = await record_login_failure_cur(
            cur, USER_ID, expected_auth_revision=AUTH_REVISION
        )

        assert new_count == 1
        assert entered_lockout is False

    async def test_the_fresh_streak_locks_again_when_it_reaches_the_threshold(self, monkeypatch):
        """The fresh streak locks again when it reaches the threshold."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        monkeypatch.setattr(settings, "login_lockout_minutes", 15)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        new_locked_until = database_now + timedelta(minutes=15)
        cur = self._cursor(
            failed_login_count=2,
            locked_until=None,
            database_now=database_now,
            updated={"failed_login_count": 3, "locked_until": new_locked_until},
        )

        new_count, entered_lockout = await record_login_failure_cur(
            cur, USER_ID, expected_auth_revision=AUTH_REVISION
        )

        assert new_count == 3
        assert entered_lockout is True
        _statement, params = self._counter_update(cur)
        assert params[:2] == (3, new_locked_until)

    async def test_a_threshold_of_one_locks_on_the_first_failure_of_the_new_streak(
        self, monkeypatch
    ):
        """Immediately lock a restarted streak when the threshold is one."""
        monkeypatch.setattr(settings, "login_failure_threshold", 1)
        monkeypatch.setattr(settings, "login_lockout_minutes", 15)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        new_locked_until = database_now + timedelta(minutes=15)
        cur = self._cursor(
            failed_login_count=9,
            locked_until=database_now - timedelta(minutes=1),
            database_now=database_now,
            updated={"failed_login_count": 1, "locked_until": new_locked_until},
        )

        new_count, entered_lockout = await record_login_failure_cur(
            cur, USER_ID, expected_auth_revision=AUTH_REVISION
        )

        assert new_count == 1
        assert entered_lockout is True
        _statement, params = self._counter_update(cur)
        assert params[:2] == (1, new_locked_until)

    async def test_failure_arriving_during_a_live_lock_writes_nothing(self, monkeypatch):
        """Failure arriving during a live lock writes nothing."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        monkeypatch.setattr(settings, "login_lockout_minutes", 15)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=3,
            locked_until=database_now + timedelta(minutes=10),
            database_now=database_now,
        )

        new_count, entered_lockout = await record_login_failure_cur(
            cur, USER_ID, expected_auth_revision=AUTH_REVISION
        )

        assert new_count == 3
        assert entered_lockout is False
        assert self._counter_update(cur) is None, "an active lock must not be written to at all"

    async def test_the_database_clock_is_read_only_after_the_user_row_is_locked(self, monkeypatch):
        """Read database time after acquiring the user-row lock."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=1,
            locked_until=None,
            database_now=database_now,
            updated={"failed_login_count": 2, "locked_until": None},
        )

        await record_login_failure_cur(cur, USER_ID, expected_auth_revision=AUTH_REVISION)

        statements = [str(call.args[0]) for call in cur.execute.await_args_list]
        assert "FOR UPDATE" in statements[0]
        assert "clock_timestamp()" in statements[1]

    async def test_an_expired_streak_clears_the_previous_lockout_notice_marker(self, monkeypatch):
        """Clear the old notice marker when starting a new failure streak."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=5,
            locked_until=database_now - timedelta(minutes=1),
            database_now=database_now,
            updated={"failed_login_count": 1, "locked_until": None},
        )

        await record_login_failure_cur(cur, USER_ID, expected_auth_revision=AUTH_REVISION)

        statement, params = self._counter_update(cur)
        assert "lockout_notice_enqueued_at" in statement
        assert params[2] is True, "the expired-streak flag must request the marker reset"

    async def test_a_continuing_streak_keeps_its_lockout_notice_marker(self, monkeypatch):
        """A continuing streak keeps its lockout notice marker."""
        monkeypatch.setattr(settings, "login_failure_threshold", 3)
        database_now = datetime(2031, 1, 1, tzinfo=UTC)
        cur = self._cursor(
            failed_login_count=1,
            locked_until=None,
            database_now=database_now,
            updated={"failed_login_count": 2, "locked_until": None},
        )

        await record_login_failure_cur(cur, USER_ID, expected_auth_revision=AUTH_REVISION)

        _statement, params = self._counter_update(cur)
        assert params[2] is False, "a continuing streak must not reset the marker"


class TestQueueLockoutNoticeClaim:
    """queue_lockout_notice_cur claims the notice with a compare-and-set UPDATE."""

    def _email(self) -> OutboundEmail:
        """Return a fixed account-lockout notice for enqueue assertions."""
        return OutboundEmail("account_locked_notice", "alice@example.org", "Subject", "Body")

    async def test_claim_succeeds_and_enqueues_exactly_once_when_marker_is_null(self):
        """Claim a NULL notice marker and enqueue exactly one email."""
        cur = make_async_cursor(fetchone={"id": USER_ID}, rowcount=1)
        enqueue = create_autospec(authentication.enqueue_outbound_email_cur, spec_set=True)

        with patch.object(authentication, "enqueue_outbound_email_cur", enqueue):
            claimed = await queue_lockout_notice_cur(
                cur,
                user_id=USER_ID,
                expected_auth_revision=AUTH_REVISION,
                email=self._email(),
            )

        assert claimed is True
        enqueue.assert_awaited_once()
        _, kwargs = enqueue.await_args
        assert kwargs["user_id"] == USER_ID
        assert kwargs["email"] == self._email()
        update = cur.execute.await_args_list[0]
        statement = str(update.args[0])
        assert "lockout_notice_enqueued_at IS NULL" in statement
        _assert_placeholders_match_params(statement, update.args[1])

    async def test_claim_fails_and_skips_enqueue_when_marker_already_set(self):
        """Claim fails and skips enqueue when marker already set."""
        cur = make_async_cursor(fetchone=None, rowcount=0)
        enqueue = create_autospec(authentication.enqueue_outbound_email_cur, spec_set=True)

        with patch.object(authentication, "enqueue_outbound_email_cur", enqueue):
            claimed = await queue_lockout_notice_cur(
                cur,
                user_id=USER_ID,
                expected_auth_revision=AUTH_REVISION,
                email=self._email(),
            )

        assert claimed is False
        enqueue.assert_not_awaited()


def _clears_lockout_state_call(cur):
    """The one cur.execute call that clears the lockout marker, or None."""
    for call in cur.execute.await_args_list:
        statement = str(call.args[0])
        if "lockout_notice_enqueued_at = NULL" in statement:
            return statement, call.args[1] if len(call.args) > 1 else {}
    return None


def _assert_single_statement_clears_lockout_state(cur):
    """Require one statement to clear the notice, failure count and lock expiry."""
    found = _clears_lockout_state_call(cur)
    assert found is not None, "no statement cleared lockout_notice_enqueued_at"
    statement, params = found
    assert "failed_login_count = 0" in statement
    assert "locked_until = NULL" in statement
    _assert_placeholders_match_params(statement, params)


class TestLockoutStateResetWriters:
    """Every recovery writer clears the counter, the lock, and the notice
    marker together in the single statement that ends the failure streak."""

    async def test_successful_login_finalization_clears_lockout_state(self):
        """Successful login finalization clears lockout state."""
        row = {
            **make_sample_user_row(totp_configured=False, totp_secret=None),
            "auth_revision": AUTH_REVISION,
            "locked_until": None,
        }
        updated_row = make_sample_user_row()
        cur = make_async_cursor(fetchone=[row, updated_row])

        with (
            patch.object(
                authentication, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)
            ),
            patch.object(
                authentication,
                "create_session_cur",
                new=create_autospec(
                    authentication.create_session_cur, spec_set=True, return_value="session-id"
                ),
            ),
        ):
            result = await authentication.finalize_local_login(
                make_mock_pool(),
                user_id=USER_ID,
                expected_auth_revision=AUTH_REVISION,
                totp_code="",
                ip_address="127.0.0.1",
            )

        assert isinstance(result, authentication.LocalLoginSuccess)
        _assert_single_statement_clears_lockout_state(cur)

    async def test_password_reset_completion_clears_lockout_state(self):
        """Password reset completion clears lockout state."""
        snapshot = {
            "email": "alice@example.org",
            "display_name": "Alice Müller",
            "password_hash": "argon2-existing-hash",
            "auth_revision": 0,
        }
        cur = make_async_cursor(fetchone=[snapshot, {**snapshot, "id": USER_ID}, {"id": USER_ID}])

        async def fake_hash(_func, *_args, **_kwargs):
            """Return a fixed replacement password hash."""
            return "argon2-new-hash"

        with (
            patch.object(
                password_reset, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)
            ),
            patch.object(
                password_reset,
                "_is_same_as_current_password",
                new=create_autospec(
                    password_reset._is_same_as_current_password,
                    spec_set=True,
                    return_value=False,
                ),
            ),
            patch.object(password_reset, "run_password_work", autospec=True, side_effect=fake_hash),
            patch.object(
                password_reset,
                "delete_user_sessions_cur",
                new=create_autospec(password_reset.delete_user_sessions_cur, spec_set=True),
            ),
            patch.object(
                password_reset,
                "invalidate_pending_authentication_state_cur",
                new=create_autospec(
                    password_reset.invalidate_pending_authentication_state_cur, spec_set=True
                ),
            ),
            patch.object(
                password_reset, "verify_and_consume_totp_cur", autospec=True, return_value=True
            ),
            patch.object(password_reset, "enqueue_outbound_email_cur", autospec=True),
        ):
            await password_reset.update_password_with_token(
                make_mock_pool(),
                USER_ID,
                password_reset.generate_reset_token(USER_ID, "alice@example.org"),
                "Fresh-Password-Without-Common-Words-824!",
                expected_email="alice@example.org",
                totp_code="123456",
            )

        _assert_single_statement_clears_lockout_state(cur)

    async def test_admin_reactivation_clears_lockout_state(self):
        """Admin reactivation clears lockout state."""
        target = {"is_active": False, "is_admin": False, "auth_method": "local"}
        row = {"old_value": False, "new_value": True, "lock_cleared": True}
        cur = make_async_cursor(fetchone=row)

        with (
            patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(
                users,
                "_guard_admin_membership_change_cur",
                new=create_autospec(
                    users._guard_admin_membership_change_cur,
                    spec_set=True,
                    return_value=target,
                ),
            ),
            patch.object(
                users,
                "invalidate_pending_email_change_cur",
                new=create_autospec(users.invalidate_pending_email_change_cur, spec_set=True),
            ),
        ):
            result = await users.set_user_active(
                make_mock_pool(),
                USER_ID,
                True,
                actor_id=99,
                actor_session_id="admin-session",
            )

        assert result.lock_cleared is True
        _assert_single_statement_clears_lockout_state(cur)

    async def test_federated_approval_clears_lockout_state(self, monkeypatch):
        """Federated approval clears lockout state."""
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", ["https://idp.example"])
        row = make_sample_user_row(
            auth_method="shibboleth",
            federated_status="approved",
            is_active=True,
            reviewed_proposal=None,
        )
        cur = make_async_cursor(fetchone=row)

        with (
            patch.object(users, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(
                users,
                "federation_policy_is_current_cur",
                new=create_autospec(
                    users.federation_policy_is_current_cur, spec_set=True, return_value=True
                ),
            ),
            patch.object(
                users,
                "guard_current_admin_session_cur",
                new=create_autospec(users.guard_current_admin_session_cur, spec_set=True),
            ),
            patch.object(
                users,
                "delete_user_sessions_cur",
                new=create_autospec(users.delete_user_sessions_cur, spec_set=True),
            ),
        ):
            await users.approve_federated_user(
                make_mock_pool(),
                USER_ID,
                expected_issuer="https://idp.example",
                expected_subject_id="urn:subject:7",
                expected_review_revision=1,
                access_tier="registered",
                actor_id=99,
                actor_session_id="admin-session",
            )

        _assert_single_statement_clears_lockout_state(cur)

    async def test_totp_recovery_redemption_clears_lockout_state(self):
        """TOTP recovery redemption clears lockout state."""
        reservation = ReservedRecoveryCodePasswordAttempt(
            user_id=USER_ID, generation=1, position=1, code_hash="code-hash"
        )
        attempt = _RecoveryPasswordAttempt(
            reservation=reservation, password_hash="argon2-hash", auth_revision=AUTH_REVISION
        )
        row = {
            "password_hash": "argon2-hash",
            "auth_revision": AUTH_REVISION,
            "auth_method": "local",
            "is_active": True,
            "email_verified": True,
            "totp_secret": None,
            "totp_recovery_required": True,
            "totp_recovery_code_generation": 1,
            "totp_recovery_authorized_at": datetime(2031, 1, 1, tzinfo=UTC),
            "totp_recovery_auth_revision": AUTH_REVISION,
            "totp_recovery_expires_at": datetime(2032, 1, 1, tzinfo=UTC),
        }
        cur = make_async_cursor(
            fetchone=[
                row,
                {"position": 1},
                {"database_now": datetime(2031, 2, 1, tzinfo=UTC)},
            ]
        )

        with (
            patch.object(
                totp_recover, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)
            ),
            patch.object(totp_recover, "queue_security_change_notice_cur", autospec=True),
            patch.object(
                totp_recover,
                "_reserve_recovery_password_attempt",
                new=create_autospec(
                    totp_recover._reserve_recovery_password_attempt,
                    spec_set=True,
                    return_value=attempt,
                ),
            ),
            patch.object(
                password_verification, "run_password_work", autospec=True, return_value=None
            ),
            patch.object(
                totp_recover,
                "consume_reserved_recovery_code_cur",
                new=create_autospec(
                    totp_recover.consume_reserved_recovery_code_cur,
                    spec_set=True,
                    return_value=True,
                ),
            ),
            patch.object(
                totp_recover,
                "delete_user_sessions_cur",
                new=create_autospec(totp_recover.delete_user_sessions_cur, spec_set=True),
            ),
            patch.object(
                totp_recover,
                "create_session_cur",
                new=create_autospec(
                    totp_recover.create_session_cur, spec_set=True, return_value="session-id"
                ),
            ),
        ):
            result = await totp_recover.redeem_totp_recovery(
                make_mock_pool(),
                email="alice@example.org",
                password="whatever-password",
                recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
                ip_address="127.0.0.1",
            )

        assert result.user_id == USER_ID
        _assert_single_statement_clears_lockout_state(cur)

    async def test_totp_recovery_reenrollment_clears_lockout_state(self):
        """TOTP recovery reenrollment clears lockout state."""
        row = {
            "is_active": True,
            "auth_method": "local",
            "email_verified": True,
            "totp_secret": None,
            "pending_totp_secret": "encrypted-pending-secret",
            "pending_totp_created_at": datetime.now(UTC),
            "pending_totp_session_hash": hash_session_id("session-id"),
            "totp_recovery_required": True,
        }
        cur = make_async_cursor(fetchone=row)

        with (
            patch.object(totp, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(totp, "queue_security_change_notice_cur", autospec=True),
            patch.object(
                totp,
                "_lock_authorizing_session_cur",
                new=create_autospec(
                    totp._lock_authorizing_session_cur,
                    spec_set=True,
                    return_value=datetime.now(UTC),
                ),
            ),
            patch.object(totp, "decrypt_value", autospec=True, return_value="decrypted-secret"),
            patch.object(totp, "matched_step", autospec=True, return_value=42),
            patch.object(
                totp,
                "activate_pending_recovery_code_set_cur",
                new=create_autospec(
                    totp.activate_pending_recovery_code_set_cur, spec_set=True, return_value=True
                ),
            ),
            patch.object(
                totp,
                "delete_user_sessions_cur",
                new=create_autospec(totp.delete_user_sessions_cur, spec_set=True),
            ),
            patch.object(
                totp,
                "invalidate_pending_authentication_state_cur",
                new=create_autospec(
                    totp.invalidate_pending_authentication_state_cur, spec_set=True
                ),
            ),
        ):
            outcome = await totp.verify_and_enroll_totp(
                make_mock_pool(),
                USER_ID,
                "123456",
                "AAAAA-BBBBB-CCCCC-DDDDD",
                session_id="session-id",
            )

        assert outcome is totp.TotpEnrollmentOutcome.RECOVERED
        _assert_single_statement_clears_lockout_state(cur)
