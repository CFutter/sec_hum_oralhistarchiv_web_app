"""Unit tests for the failed-login counter and the lockout-notice claim.

`record_login_failure_cur` reports a database transition (unlocked -> locked)
rather than merely a counter crossing a threshold. A live lock is never
extended by further failures, and once a lock expires the next failure opens
a new streak counted from one, so an attacker cannot keep an account locked
with one request per lockout window. `queue_lockout_notice_cur` claims the
one durable notice allowed per streak with a compare-and-set UPDATE. Every
writer that clears lockout state on recovery (a successful login, a password
reset, an administrator reactivation, a federated approval, TOTP recovery
redemption, and TOTP-recovery re-enrollment) must clear the failure counter,
the lock expiry, and the notice marker together in one statement, so a
recovered account can be locked again by a fresh failure streak.
"""

import re
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

from app.services import authentication, password_reset, totp, totp_recover, users
from app.services.authentication import (
    queue_lockout_notice_cur,
    record_login_failure_cur,
)
from app.services.email_outbox import OutboundEmail
from app.services.totp_recover import _RecoveryPasswordAttempt
from app.services.totp_recovery_codes import ReservedRecoveryCodePasswordAttempt
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool, make_sample_user_row

USER_ID = 7
AUTH_REVISION = 3


def _assert_placeholders_match_params(statement: str, params) -> None:
    """Named placeholders may repeat a key; positional ones may not repeat.

    For a dict of params, every %(name)s in the statement must name a
    supplied key (repeats are legitimate psycopg re-use of one bound value).
    For a sequence of params, the number of positional %s placeholders must
    equal the number of supplied values.
    """
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
    """A live lock is never extended, and an expired one starts over.

    `record_login_failure_cur` reads the database clock only after it holds
    the user row, so the three outcomes below are decided against the same
    serialized instant: a failure that arrives while a lock is still live
    changes nothing, a failure that arrives once the lock has expired is
    failure number one of a new streak, and that new streak locks the
    account again only when it reaches the configured threshold.
    """

    @staticmethod
    def _cursor(*, failed_login_count, locked_until, database_now, updated=None):
        """A cursor answering the three reads the helper performs in order.

        The reads are: the locked user row, the database clock, and the row
        returned by the counter UPDATE. `updated` is left out for the
        active-lock case, where the helper returns before updating anything.
        """
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
        """The account was locked once and the lock has run out. The next
        wrong password counts as one, not as "one more" on top of the old
        streak, so the account is not locked again on the spot."""
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
        """The boundary case: a lock whose expiry equals the database clock
        is over. Treating it as still live would let the lock outlive its own
        configured duration."""
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
        """Positive control for the two cases above: the new streak still
        locks the account, but only once it has collected as many failures as
        the configured threshold."""
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
        """With the threshold configured to one, restarting the streak at one
        must still arm a lock immediately — the fresh budget is allowed to be
        a single attempt."""
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
        """A second request whose password check overlapped the one that
        locked the account must not touch the row: no counter increment and,
        above all, no new expiry that would push the unlock time out."""
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
        """Reading the clock first would let a request that waited on another
        transaction decide "still locked" from a timestamp taken before the
        wait. The row lock has to come first."""
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
        """The notice marker allows one lockout email per streak. Starting a
        new streak has to release it, or the new lockout would be silent."""
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
        """Positive control for the marker reset: an ordinary increment
        inside one streak must leave the marker alone, so a streak still
        sends at most one notice."""
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
        return OutboundEmail("account_locked_notice", "alice@uzh.ch", "Subject", "Body")

    async def test_claim_succeeds_and_enqueues_exactly_once_when_marker_is_null(self):
        """A NULL marker lets the UPDATE claim the row (one row returned);
        the claim then enqueues exactly one outbox email in the same call."""
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
        """Positive control's inverse: an already-set marker means the
        compare-and-set UPDATE matches no row, so the claim reports False and
        no email is enqueued for this failure streak."""
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
        snapshot = {
            "email": "alice@uzh.ch",
            "display_name": "Alice Müller",
            "password_hash": "argon2-existing-hash",
        }
        cur = make_async_cursor(fetchone=[snapshot, {"id": USER_ID}])

        async def fake_hash(_func, *_args, **_kwargs):
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
        ):
            await password_reset.update_password_with_token(
                make_mock_pool(),
                USER_ID,
                "token-hash",
                "Fresh-Password-Without-Common-Words-824!",
                expected_email="alice@uzh.ch",
            )

        _assert_single_statement_clears_lockout_state(cur)

    async def test_admin_reactivation_clears_lockout_state(self):
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
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(settings, "shibboleth_trusted_issuers", ["https://idp.example"])
        row = make_sample_user_row(
            auth_method="shibboleth", federated_status="approved", is_active=True
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
                access_tier="registered",
                actor_id=99,
                actor_session_id="admin-session",
            )

        _assert_single_statement_clears_lockout_state(cur)

    async def test_totp_recovery_redemption_clears_lockout_state(self):
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
            "recovery_unexpired": True,
        }
        cur = make_async_cursor(fetchone=row)

        with (
            patch.object(
                totp_recover, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)
            ),
            patch.object(
                totp_recover,
                "_reserve_recovery_password_attempt",
                new=create_autospec(
                    totp_recover._reserve_recovery_password_attempt,
                    spec_set=True,
                    return_value=attempt,
                ),
            ),
            patch.object(totp_recover, "run_password_work", autospec=True, return_value=None),
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
                email="alice@uzh.ch",
                password="whatever-password",
                recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
                ip_address="127.0.0.1",
            )

        assert result.user_id == USER_ID
        _assert_single_statement_clears_lockout_state(cur)

    async def test_totp_recovery_reenrollment_clears_lockout_state(self):
        row = {
            "is_active": True,
            "auth_method": "local",
            "email_verified": True,
            "totp_secret": None,
            "pending_totp_secret": "encrypted-pending-secret",
            "pending_totp_created_at": datetime.now(UTC),
            "totp_recovery_required": True,
        }
        cur = make_async_cursor(fetchone=row)

        with (
            patch.object(totp, "get_db_cursor", autospec=True, return_value=FakeCursorCtx(cur)),
            patch.object(
                totp,
                "_lock_authorizing_session_cur",
                new=create_autospec(
                    totp._lock_authorizing_session_cur, spec_set=True, return_value=True
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
