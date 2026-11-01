"""Exceptional password-change boundaries without a database or credential logs."""

from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch, sentinel

import pytest
from psycopg import AsyncCursor

from app.services import password_change
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.password_verification import PasswordVerified
from app.services.password_work import PasswordWorkAdmissionTimeout
from config import settings

NOW = datetime(2026, 10, 26, 18, tzinfo=UTC)
CURRENT_PASSWORD = "Golden-cedars-482!Cloud"
NEW_PASSWORD = "Cobalt-forests-739!Rain"


def _row(**changes):
    """Build an eligible password-change account snapshot with caller field overrides."""
    row = {
        "email": "owner@example.org",
        "display_name": "Owner",
        "password_hash": "stored-hash",
        "auth_revision": 2,
        "is_active": True,
        "email_verified": True,
        "auth_method": "local",
        "totp_secret": "encrypted-factor",
        "totp_recovery_required": False,
        "locked_until": None,
        "login_unlocked": True,
    }
    row.update(changes)
    return row


def _session(**changes):
    """Build a live session row with one hour remaining and caller field overrides."""
    row = {"expires_at": NOW + timedelta(hours=1), "last_activity_at": NOW}
    row.update(changes)
    return row


class _CursorContext:
    """Track cursor scope exits as commit or rollback observations."""

    def __init__(self, cursor, events):
        """Store the scripted cursor and shared event list."""
        self.cursor = cursor
        self.events = events

    async def __aenter__(self):
        """Record cursor entry and return the scripted cursor."""
        self.events.append("enter")
        return self.cursor

    async def __aexit__(self, exc_type, _value, _traceback):
        """Record normal exit or rollback and propagate any exception."""
        self.events.append("exit" if exc_type is None else "rollback")
        return False


@contextmanager
def _dependencies(rows=(), *, reservation=SessionStepUpAttemptOutcome.RESERVED, failure=None):
    """Patch password-change dependencies; yield mocks and transaction/work ordering events."""
    events = []
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchone.side_effect = iter(rows)

    async def verify(**_kwargs):
        """Require released database scope before password proof; raise configured failure or verify."""
        assert events[-1] == "exit", "Password verification must release the connection"
        events.append("verify")
        if failure is not None:
            raise failure
        return PasswordVerified()

    async def hash_password(*_args, **_kwargs):
        """Require password proof first, record hashing, and return the replacement hash."""
        assert events[-1] == "verify", "Hashing must not hold a database connection"
        events.append("hash")
        return "replacement-hash"

    replacements = {
        "get_db_cursor": create_autospec(
            password_change.get_db_cursor,
            side_effect=lambda *_args, **_kwargs: _CursorContext(cursor, events),
        ),
        "reserve_session_step_up_attempt": create_autospec(
            password_change.reserve_session_step_up_attempt, return_value=reservation
        ),
        "verify_password_hash": create_autospec(
            password_change.verify_password_hash, side_effect=verify
        ),
        "run_password_work": create_autospec(
            password_change.run_password_work, side_effect=hash_password
        ),
        "database_now_cur": create_autospec(password_change.database_now_cur, return_value=NOW),
        "verify_and_consume_totp_cur": create_autospec(
            password_change.verify_and_consume_totp_cur, return_value=True
        ),
        "delete_user_sessions_cur": create_autospec(password_change.delete_user_sessions_cur),
        "invalidate_pending_authentication_state_cur": create_autospec(
            password_change.invalidate_pending_authentication_state_cur
        ),
        "enqueue_outbound_email_cur": create_autospec(password_change.enqueue_outbound_email_cur),
    }
    with ExitStack() as stack:
        for name, replacement in replacements.items():
            stack.enter_context(patch.object(password_change, name, replacement))
        yield replacements, events


async def _change(**changes):
    """Run password change against the sentinel pool with caller argument overrides."""
    arguments = {
        "user_id": 1,
        "session_id": "exact-session",
        "current_password": CURRENT_PASSWORD,
        "new_password": NEW_PASSWORD,
        "totp_code": "123456",
    }
    arguments.update(changes)
    await password_change.change_password(sentinel.pool, **arguments)


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (SessionStepUpAttemptOutcome.INVALID_SESSION, "invalid_session"),
        (SessionStepUpAttemptOutcome.ACCOUNT_LOCKED, "account_locked"),
        (SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED, "step_up_exhausted"),
    ],
)
async def test_rejected_attempt_budget_prevents_password_work(outcome, reason):
    """Check rejected attempt budget prevents password work."""
    with _dependencies(reservation=outcome) as (doubles, _events):
        with pytest.raises(password_change.PasswordChangeRejected) as caught:
            await _change()
        assert caught.value.reason == reason
        doubles["get_db_cursor"].assert_not_called()
        doubles["verify_password_hash"].assert_not_awaited()
        doubles["run_password_work"].assert_not_awaited()


async def test_password_capacity_failure_propagates_after_reserving_attempt():
    """Check password capacity failure propagates after reserving attempt
    (PasswordWorkAdmissionTimeout).
    """
    failure = PasswordWorkAdmissionTimeout(0.02)
    with _dependencies([_row()], failure=failure) as (doubles, events):
        with pytest.raises(PasswordWorkAdmissionTimeout) as caught:
            await _change()
        assert caught.value is failure
        assert events == ["enter", "exit", "verify"]
        doubles["reserve_session_step_up_attempt"].assert_awaited_once()
        doubles["verify_and_consume_totp_cur"].assert_not_awaited()


@pytest.mark.parametrize(
    ("locked", "session", "reason"),
    [
        ({"locked_until": NOW + timedelta(seconds=1)}, _session(expires_at=NOW), "invalid_session"),
        ({}, _session(expires_at=NOW), "invalid_session"),
        ({}, None, "invalid_session"),
        (
            {},
            _session(
                last_activity_at=NOW - timedelta(seconds=settings.session_idle_timeout_seconds)
            ),
            "invalid_session",
        ),
        (
            {},
            _session(
                last_activity_at=NOW - timedelta(seconds=settings.session_idle_timeout_seconds + 30)
            ),
            "invalid_session",
        ),
        ({"auth_revision": 3}, _session(), "retry_required"),
        (
            {"password_hash": "refreshed"},
            _session(),
            "retry_required",
        ),
    ],
)
async def test_final_live_authority_rejections_do_not_consume_totp_or_revoke(
    locked, session, reason
):
    """Check final live authority rejections do not consume TOTP or revoke."""
    with _dependencies([_row(), _row(**locked), session]) as (doubles, _events):
        with pytest.raises(password_change.PasswordChangeRejected) as caught:
            await _change()
        assert caught.value.reason == reason
        doubles["database_now_cur"].assert_awaited_once()
        doubles["verify_and_consume_totp_cur"].assert_not_awaited()
        doubles["delete_user_sessions_cur"].assert_not_awaited()
        doubles["enqueue_outbound_email_cur"].assert_not_awaited()


async def test_profile_change_rechecks_policy_before_consuming_totp():
    """Check profile change rechecks policy before consuming TOTP."""
    session = _session()
    with _dependencies([_row(), _row(display_name="Cobalt"), session]) as (doubles, _events):
        with pytest.raises(password_change.PasswordChangeRejected) as caught:
            await _change()
        assert caught.value.reason == "password_policy"
        assert caught.value.password_error == "Your password should not contain your name."
        doubles["verify_and_consume_totp_cur"].assert_not_awaited()
        doubles["enqueue_outbound_email_cur"].assert_not_awaited()


async def test_choosing_current_password_does_not_hash_or_consume_totp():
    """Check choosing current password does not hash or consume TOTP."""
    with _dependencies([_row()]) as (doubles, _events):
        with pytest.raises(password_change.PasswordChangeRejected) as caught:
            await _change(new_password=CURRENT_PASSWORD)
        assert caught.value.reason == "password_reused"
        doubles["run_password_work"].assert_not_awaited()
        doubles["verify_and_consume_totp_cur"].assert_not_awaited()
