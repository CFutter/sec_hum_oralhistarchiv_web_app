"""Exact-session attempt budgets and reservation-before-verification ordering."""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch, sentinel

import pytest

from app.services import credential_attempts, email_change, password_verification, totp
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.session_ids import hash_session_id
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

USER_ID = 41
RAW_SESSION_ID = "raw-session-secret-never-log-or-store"
SESSION_HASH = hash_session_id(RAW_SESSION_ID)
NOW = datetime(2026, 10, 26, 18, tzinfo=UTC)


def _session_row(count, *, login_unlocked=True, **changes):
    """Return an unexpired step-up session row with explicit field overrides."""
    row = {
        "step_up_attempt_count": count,
        "login_unlocked": login_unlocked,
        "expires_at": NOW + timedelta(hours=1),
        "last_activity_at": NOW,
    }
    row.update(changes)
    return row


@pytest.fixture(autouse=True)
def _fixed_reservation_clock(monkeypatch):
    """Fix reservation database time at NOW for the test."""
    monkeypatch.setattr(
        credential_attempts,
        "database_now_cur",
        create_autospec(credential_attempts.database_now_cur, return_value=NOW),
    )


async def _reserve(*, fetchone, execute_side_effect=None):
    """Run one reservation against a cursor with explicitly scripted results."""
    cur = make_async_cursor(fetchone=fetchone)
    if execute_side_effect is not None:
        cur.execute.side_effect = execute_side_effect
    with patch.object(
        credential_attempts,
        "get_db_cursor",
        create_autospec(
            credential_attempts.get_db_cursor,
            return_value=FakeCursorCtx(cur),
            spec_set=True,
        ),
    ):
        outcome = await credential_attempts.reserve_session_step_up_attempt(
            make_mock_pool(),
            user_id=USER_ID,
            session_id=RAW_SESSION_ID,
        )
    return outcome, cur


class TestSessionStepUpReservation:
    """The reservation query is scoped to one live, active, full session and records its own count."""

    async def test_reservation_increments_exact_session_attempt_count(self, monkeypatch):
        """Reservation increments exact session attempt count."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 5)

        outcome, cur = await _reserve(
            fetchone=[
                _session_row(2, login_unlocked=True),
                {"step_up_attempt_count": 3},
            ]
        )

        assert outcome is SessionStepUpAttemptOutcome.RESERVED
        assert cur.execute.await_count == 2
        select, update = cur.execute.await_args_list
        assert select.args[1] == (SESSION_HASH, USER_ID)
        assert update.args[1] == (SESSION_HASH, USER_ID)
        assert "step_up_attempt_count = step_up_attempt_count + 1" in update.args[0]
        assert "RETURNING step_up_attempt_count" in update.args[0]

    async def test_lookup_is_scoped_to_the_exact_live_active_full_session(self):
        """Lookup is scoped to the exact live active full session."""
        outcome, cur = await _reserve(fetchone=None)

        assert outcome is SessionStepUpAttemptOutcome.INVALID_SESSION
        assert cur.execute.await_count == 1
        select = cur.execute.await_args_list[0]
        statement = str(select.args[0])
        assert "JOIN users AS u ON u.id = s.user_id" in statement
        assert "s.id = %s" in statement
        assert "s.user_id = %s" in statement
        assert "s.purpose = 'full'" in statement
        assert "s.expires_at > clock_timestamp()" in statement
        assert "u.is_active" in statement
        assert "FOR UPDATE OF s" in statement
        assert select.args[1] == (SESSION_HASH, USER_ID)
        assert RAW_SESSION_ID not in repr(cur.execute.await_args_list)


class TestBudgetRefusals:
    """Attempt exhaustion and independence from username-triggered login locks."""

    async def test_reservation_allowed_up_to_the_limit_then_refused_on_the_next_request(
        self,
        monkeypatch,
        caplog,
    ):
        """The configured limit permits the last slot and expires the session on the request after it."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 3)

        allowed, allowed_cur = await _reserve(
            fetchone=[
                _session_row(2, login_unlocked=True),
                {"step_up_attempt_count": 3},
            ]
        )
        exhausted, exhausted_cur = await _reserve(fetchone=_session_row(3, login_unlocked=True))

        assert allowed is SessionStepUpAttemptOutcome.RESERVED
        assert allowed_cur.execute.await_count == 2
        assert exhausted is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED
        assert exhausted_cur.execute.await_count == 2
        expiry = exhausted_cur.execute.await_args_list[1]
        statement = str(expiry.args[0])
        assert "UPDATE sessions" in statement
        assert "expires_at = clock_timestamp()" in statement
        assert "DELETE FROM sessions" not in statement
        assert expiry.args[1] == (SESSION_HASH, USER_ID)
        assert RAW_SESSION_ID not in caplog.text
        assert SESSION_HASH[:8] in caplog.text

    async def test_login_lock_does_not_block_an_existing_full_sessions_proof_budget(self):
        """Username-only abuse cannot deny separately bounded authenticated proof."""
        outcome, cur = await _reserve(
            fetchone=[
                _session_row(1, login_unlocked=False),
                {"step_up_attempt_count": 2},
            ]
        )
        assert outcome is SessionStepUpAttemptOutcome.RESERVED
        assert cur.execute.await_count == 2
        assert "locked_until" not in str(cur.execute.await_args_list[0].args[0])


class TestReservationFailureHandling:
    """Storage failures and disappearing rows fail closed instead of reporting a reservation."""

    async def test_storage_error_propagates_without_reporting_a_reservation(self):
        """Storage error propagates without reporting a reservation."""
        cur = make_async_cursor(fetchone=_session_row(0, login_unlocked=True))
        storage_error = RuntimeError("database unavailable")
        cur.execute.side_effect = [None, storage_error]

        with (
            patch.object(
                credential_attempts,
                "get_db_cursor",
                create_autospec(
                    credential_attempts.get_db_cursor,
                    return_value=FakeCursorCtx(cur),
                    spec_set=True,
                ),
            ),
            pytest.raises(RuntimeError, match="database unavailable"),
        ):
            await credential_attempts.reserve_session_step_up_attempt(
                make_mock_pool(),
                user_id=USER_ID,
                session_id=RAW_SESSION_ID,
            )

        assert cur.execute.await_count == 2

    async def test_disappearing_locked_session_fails_closed(self):
        """Disappearing locked session fails closed."""
        outcome_row = _session_row(0, login_unlocked=True)
        cur = make_async_cursor(fetchone=[outcome_row, None])

        with (
            patch.object(
                credential_attempts,
                "get_db_cursor",
                create_autospec(
                    credential_attempts.get_db_cursor,
                    return_value=FakeCursorCtx(cur),
                    spec_set=True,
                ),
            ),
            pytest.raises(RuntimeError, match="session disappeared"),
        ):
            await credential_attempts.reserve_session_step_up_attempt(
                make_mock_pool(),
                user_id=USER_ID,
                session_id=RAW_SESSION_ID,
            )

        assert cur.execute.await_count == 2


SESSION_ID = "raw-session-secret"


class _ReservationStorageError(RuntimeError):
    """Sentinel proving a reservation failure is propagated unchanged."""


class _CredentialBoundaryReached(RuntimeError):
    """Sentinel raised at the first expensive credential check."""


def _reservation_mock(result):
    """Return a signature-checked reservation double with the requested outcome."""
    if isinstance(result, Exception):
        return create_autospec(
            credential_attempts.reserve_session_step_up_attempt,
            side_effect=result,
            spec_set=True,
        )
    return create_autospec(
        credential_attempts.reserve_session_step_up_attempt,
        return_value=result,
        spec_set=True,
    )


class TestTotpRotationSpendsReservationBeforePasswordWork:
    """totp.begin_totp_rotation must reserve an attempt before checking the candidate password."""

    @pytest.mark.parametrize(
        ("reservation", "expected_outcome"),
        [
            (
                SessionStepUpAttemptOutcome.INVALID_SESSION,
                totp.TotpRotationStartOutcome.SESSION_EXPIRED,
            ),
            (
                SessionStepUpAttemptOutcome.ACCOUNT_LOCKED,
                totp.TotpRotationStartOutcome.ACCOUNT_LOCKED,
            ),
            (
                SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED,
                totp.TotpRotationStartOutcome.ATTEMPTS_EXHAUSTED,
            ),
        ],
    )
    async def test_rejected_reservation_stops_before_password_work(
        self,
        reservation,
        expected_outcome,
    ):
        """Rejected reservation stops before password work."""
        reserve = _reservation_mock(reservation)
        password_work = create_autospec(
            totp.verify_password_snapshot,
            side_effect=AssertionError("password work must not run"),
            spec_set=True,
        )

        with (
            patch.object(totp, "reserve_session_step_up_attempt", reserve),
            patch.object(totp, "verify_password_snapshot", password_work),
        ):
            result = await totp.begin_totp_rotation(
                sentinel.pool,
                USER_ID,
                "candidate password",
                "123456",
                session_id=SESSION_ID,
            )

        assert result.outcome is expected_outcome
        reserve.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )
        password_work.assert_not_awaited()

    async def test_reservation_storage_error_stops_before_password_work(self):
        """Reservation storage error stops before password work."""
        storage_error = _ReservationStorageError("reservation unavailable")
        reserve = _reservation_mock(storage_error)
        password_work = create_autospec(
            totp.verify_password_snapshot,
            side_effect=AssertionError("password work must not run"),
            spec_set=True,
        )

        with (
            patch.object(totp, "reserve_session_step_up_attempt", reserve),
            patch.object(totp, "verify_password_snapshot", password_work),
            pytest.raises(_ReservationStorageError) as caught,
        ):
            await totp.begin_totp_rotation(
                sentinel.pool,
                USER_ID,
                "candidate password",
                "123456",
                session_id=SESSION_ID,
            )

        assert caught.value is storage_error
        password_work.assert_not_awaited()

    async def test_reservation_succeeds_before_password_work_runs(self):
        """A granted reservation runs before password work, in that order."""
        events: list[str] = []

        async def reserve(*_args, **_kwargs):
            """Record reservation and return RESERVED before credential verification."""
            events.append("reserve")
            return SessionStepUpAttemptOutcome.RESERVED

        async def verify_password(*_args, **_kwargs):
            """Record password verification and raise the boundary sentinel."""
            events.append("password")
            raise _CredentialBoundaryReached

        with (
            patch.object(
                totp,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    totp.reserve_session_step_up_attempt,
                    side_effect=reserve,
                    spec_set=True,
                ),
            ) as reserve_attempt,
            patch.object(
                totp,
                "verify_password_snapshot",
                new=create_autospec(
                    totp.verify_password_snapshot,
                    side_effect=verify_password,
                    spec_set=True,
                ),
            ),
            pytest.raises(_CredentialBoundaryReached),
        ):
            await totp.begin_totp_rotation(
                sentinel.pool,
                USER_ID,
                "candidate password",
                "123456",
                session_id=SESSION_ID,
            )

        assert events == ["reserve", "password"]
        reserve_attempt.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )


class TestEmailChangeSpendsReservationBeforePasswordWork:
    """email_change.stage_self_email_change must reserve an attempt before checking the current password."""

    @pytest.mark.parametrize(
        ("reservation", "expected_reason"),
        [
            (SessionStepUpAttemptOutcome.INVALID_SESSION, "invalid_session"),
            (SessionStepUpAttemptOutcome.ACCOUNT_LOCKED, "account_locked"),
            (SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED, "step_up_exhausted"),
        ],
    )
    async def test_rejected_reservation_stops_before_password_work(
        self,
        reservation,
        expected_reason,
    ):
        """Rejected reservation stops before password work."""
        reserve = _reservation_mock(reservation)
        acquire_cursor = create_autospec(
            email_change.get_db_cursor,
            side_effect=AssertionError("password snapshot must not run"),
            spec_set=True,
        )

        with (
            patch.object(email_change, "reserve_session_step_up_attempt", reserve),
            patch.object(email_change, "get_db_cursor", acquire_cursor),
            pytest.raises(email_change.SelfEmailChangeRejected) as caught,
        ):
            await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                current_password="candidate password",
                new_email="new-address@example.edu",
                totp_code="111111",
            )

        assert caught.value.reason == expected_reason
        acquire_cursor.assert_not_called()

    async def test_reservation_storage_error_stops_before_password_work(self):
        """Reservation storage error stops before password work."""
        storage_error = _ReservationStorageError("reservation unavailable")
        acquire_cursor = create_autospec(
            email_change.get_db_cursor,
            side_effect=AssertionError("password snapshot must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                email_change,
                "reserve_session_step_up_attempt",
                _reservation_mock(storage_error),
            ),
            patch.object(email_change, "get_db_cursor", acquire_cursor),
            pytest.raises(_ReservationStorageError) as caught,
        ):
            await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                current_password="candidate password",
                new_email="new-address@example.edu",
                totp_code="111111",
            )

        assert caught.value is storage_error
        acquire_cursor.assert_not_called()

    async def test_reservation_succeeds_before_argon2_work_runs(self):
        """A granted reservation runs before the argon2 password check, in that order."""
        events: list[str] = []
        cursor = make_async_cursor(
            fetchone={
                "password_hash": "argon2-hash",
                "auth_revision": 3,
                "is_active": True,
                "auth_method": "local",
                "login_unlocked": True,
            }
        )

        async def reserve(*_args, **_kwargs):
            """Record reservation and return RESERVED before credential verification."""
            events.append("reserve")
            return SessionStepUpAttemptOutcome.RESERVED

        async def password_work(*_args, **_kwargs):
            """Record password verification and raise the boundary sentinel."""
            events.append("password")
            raise _CredentialBoundaryReached

        with (
            patch.object(
                email_change,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    email_change.reserve_session_step_up_attempt,
                    side_effect=reserve,
                    spec_set=True,
                ),
            ) as reserve_attempt,
            patch.object(
                email_change,
                "get_db_cursor",
                create_autospec(
                    email_change.get_db_cursor,
                    return_value=FakeCursorCtx(cursor),
                    spec_set=True,
                ),
            ),
            patch.object(
                password_verification,
                "run_password_work",
                new=create_autospec(
                    password_verification.run_password_work,
                    side_effect=password_work,
                    spec_set=True,
                ),
            ),
            pytest.raises(_CredentialBoundaryReached),
        ):
            await email_change.stage_self_email_change(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                current_password="candidate password",
                new_email="new-address@example.edu",
                totp_code="111111",
            )

        assert events == ["reserve", "password"]
        reserve_attempt.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )


@pytest.mark.parametrize(
    "absolute_expired,idle_age_seconds",
    [
        (True, 0),
        (False, settings.session_idle_timeout_seconds),
        (False, settings.session_idle_timeout_seconds + 30),
    ],
)
async def test_expired_session_is_rejected_before_spending_or_exhausting_budget(
    absolute_expired, idle_age_seconds
):
    """Expired session is rejected before spending or exhausting budget."""
    row = _session_row(
        settings.session_step_up_attempt_limit,
        expires_at=NOW if absolute_expired else NOW + timedelta(hours=1),
        last_activity_at=NOW - timedelta(seconds=idle_age_seconds),
    )
    outcome, cur = await _reserve(fetchone=row)
    assert outcome is SessionStepUpAttemptOutcome.INVALID_SESSION
    assert cur.execute.await_count == 1
