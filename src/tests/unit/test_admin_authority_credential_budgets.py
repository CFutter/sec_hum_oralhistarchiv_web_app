"""Administrator-authority flows spend the credential step-up budget before
expensive verification (app.services.admin_promotion, app.services.totp_recover).

Split out of test_credential_budgets.py to stay under the module line cap;
shares the reservation-spending scenario with TestTotpRotationSpendsReservationBeforePasswordWork
and TestEmailChangeSpendsReservationBeforePasswordWork there, applied to the two
call sites that act on behalf of, or target, an administrator: preparing and
accepting an administrator-promotion invitation, and an administrator
authorizing another user's TOTP recovery.
"""

from datetime import UTC, datetime
from unittest.mock import create_autospec, patch, sentinel

import pytest

from app.services import admin_promotion, credential_attempts, totp_recover
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.session_ids import hash_session_id
from tests.fixtures import FakeCursorCtx, make_async_cursor

USER_ID = 41
ACTOR_ID = 91
TARGET_ID = 42
SESSION_ID = "raw-session-secret"


class _ReservationStorageError(RuntimeError):
    """Sentinel proving a reservation failure is propagated unchanged."""


class _CredentialBoundaryReached(RuntimeError):
    """Sentinel raised at the first expensive credential check."""


def _reservation_mock(result):
    """An autospecced double of reserve_session_step_up_attempt.

    Every caller-module binding (admin_promotion, totp_recover) imports the
    exact same function object from credential_attempts, so autospeccing
    against the defining module's reference enforces the real signature
    regardless of which binding a test patches.
    """
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


class TestAdminPromotionPrepareSpendsReservationBeforePasswordWork:
    """admin_promotion.prepare_admin_promotion must reserve an attempt before checking the password or TOTP code."""

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
        password_work = create_autospec(
            admin_promotion._verify_password_snapshot,
            side_effect=AssertionError("password work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                _reservation_mock(reservation),
            ),
            patch.object(admin_promotion, "_verify_password_snapshot", password_work),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.prepare_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                password="candidate password",
                totp_code="123456",
            )

        assert caught.value.reason == expected_reason
        password_work.assert_not_awaited()

    async def test_reservation_storage_error_stops_before_password_work(self):
        storage_error = _ReservationStorageError("reservation unavailable")
        password_work = create_autospec(
            admin_promotion._verify_password_snapshot,
            side_effect=AssertionError("password work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                _reservation_mock(storage_error),
            ),
            patch.object(admin_promotion, "_verify_password_snapshot", password_work),
            pytest.raises(_ReservationStorageError) as caught,
        ):
            await admin_promotion.prepare_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                password="candidate password",
                totp_code="123456",
            )

        assert caught.value is storage_error
        password_work.assert_not_awaited()

    async def test_reservation_succeeds_before_password_work_runs(self):
        """Positive control: a granted reservation runs before password work, in that order."""
        events: list[str] = []

        async def reserve(*_args, **_kwargs):
            events.append("reserve")
            return SessionStepUpAttemptOutcome.RESERVED

        async def password_work(*_args, **_kwargs):
            events.append("password")
            raise _CredentialBoundaryReached

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    admin_promotion.reserve_session_step_up_attempt,
                    side_effect=reserve,
                    spec_set=True,
                ),
            ) as reserve_attempt,
            patch.object(
                admin_promotion,
                "_verify_password_snapshot",
                new=create_autospec(
                    admin_promotion._verify_password_snapshot,
                    side_effect=password_work,
                    spec_set=True,
                ),
            ),
            pytest.raises(_CredentialBoundaryReached),
        ):
            await admin_promotion.prepare_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                password="candidate password",
                totp_code="123456",
            )

        assert events == ["reserve", "password"]
        reserve_attempt.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )

    async def test_malformed_totp_is_rejected_after_the_reservation_without_a_type_error(self):
        password_work = create_autospec(
            admin_promotion._verify_password_snapshot,
            side_effect=AssertionError("password work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                _reservation_mock(SessionStepUpAttemptOutcome.RESERVED),
            ) as reserve,
            patch.object(admin_promotion, "_verify_password_snapshot", password_work),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.prepare_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                password="candidate password",
                totp_code="not-a-code",
            )

        assert caught.value.reason == "invalid_totp"
        reserve.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )
        password_work.assert_not_awaited()


class TestAdminPromotionAcceptSpendsReservationBeforeRecoveryCodeWork:
    """admin_promotion.accept_admin_promotion must reserve an attempt before checking the recovery code."""

    @pytest.mark.parametrize(
        ("reservation", "expected_reason"),
        [
            (SessionStepUpAttemptOutcome.INVALID_SESSION, "invalid_session"),
            (SessionStepUpAttemptOutcome.ACCOUNT_LOCKED, "account_locked"),
            (SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED, "step_up_exhausted"),
        ],
    )
    async def test_rejected_reservation_stops_before_code_verification(
        self,
        reservation,
        expected_reason,
    ):
        acquire_cursor = create_autospec(
            admin_promotion.get_db_cursor,
            side_effect=AssertionError("recovery-code work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                _reservation_mock(reservation),
            ),
            patch.object(admin_promotion, "get_db_cursor", acquire_cursor),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.accept_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
            )

        assert caught.value.reason == expected_reason
        acquire_cursor.assert_not_called()

    async def test_reservation_storage_error_stops_before_code_verification(self):
        storage_error = _ReservationStorageError("reservation unavailable")
        acquire_cursor = create_autospec(
            admin_promotion.get_db_cursor,
            side_effect=AssertionError("recovery-code work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                _reservation_mock(storage_error),
            ),
            patch.object(admin_promotion, "get_db_cursor", acquire_cursor),
            pytest.raises(_ReservationStorageError) as caught,
        ):
            await admin_promotion.accept_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
            )

        assert caught.value is storage_error
        acquire_cursor.assert_not_called()

    async def test_reservation_succeeds_before_recovery_code_verification_runs(self):
        """Positive control: a granted reservation runs before recovery-code verification, in that order."""
        events: list[str] = []
        now = datetime.now(UTC)
        cursor = make_async_cursor(
            fetchone=[
                {
                    "auth_revision": 7,
                    "auth_method": "local",
                    "is_active": True,
                    "is_admin": False,
                    "email_verified": True,
                    "totp_secret": "encrypted-secret",
                    "totp_recovery_required": False,
                    "login_unlocked": True,
                },
                {
                    "requested_by": ACTOR_ID,
                    "expected_auth_revision": 7,
                    "unexpired": True,
                    "prepared_at": now,
                    "prepared_session_id": hash_session_id(SESSION_ID),
                },
                {"preparation_current": True},
            ]
        )

        async def reserve(*_args, **_kwargs):
            events.append("reserve")
            return SessionStepUpAttemptOutcome.RESERVED

        async def verify_code(*_args, **_kwargs):
            events.append("recovery_code")
            raise _CredentialBoundaryReached

        with (
            patch.object(
                admin_promotion,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    admin_promotion.reserve_session_step_up_attempt,
                    side_effect=reserve,
                    spec_set=True,
                ),
            ) as reserve_attempt,
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor,
                    return_value=FakeCursorCtx(cursor),
                    spec_set=True,
                ),
            ),
            patch.object(
                admin_promotion,
                "acquire_admin_action_lock_cur",
                new=create_autospec(admin_promotion.acquire_admin_action_lock_cur, spec_set=True),
            ),
            patch.object(
                admin_promotion,
                "_lock_full_session_cur",
                new=create_autospec(admin_promotion._lock_full_session_cur, spec_set=True),
            ),
            patch.object(
                admin_promotion,
                "_validate_requester_cur",
                new=create_autospec(admin_promotion._validate_requester_cur, spec_set=True),
            ),
            patch.object(
                admin_promotion,
                "activate_pending_recovery_code_set_cur",
                new=create_autospec(
                    admin_promotion.activate_pending_recovery_code_set_cur,
                    side_effect=verify_code,
                    spec_set=True,
                ),
            ),
            pytest.raises(_CredentialBoundaryReached),
        ):
            await admin_promotion.accept_admin_promotion(
                sentinel.pool,
                user_id=USER_ID,
                session_id=SESSION_ID,
                recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
            )

        assert events == ["reserve", "recovery_code"]
        reserve_attempt.assert_awaited_once_with(
            sentinel.pool,
            user_id=USER_ID,
            session_id=SESSION_ID,
        )


class TestAdminTotpRecoverySpendsReservationBeforeTotpVerification:
    """totp_recover.authorize_totp_recovery must reserve an attempt for the acting administrator before checking their TOTP code."""

    @pytest.mark.parametrize(
        ("reservation", "expected_reason"),
        [
            (SessionStepUpAttemptOutcome.INVALID_SESSION, "actor_session_invalid"),
            (SessionStepUpAttemptOutcome.ACCOUNT_LOCKED, "actor_account_locked"),
            (SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED, "actor_step_up_exhausted"),
        ],
    )
    async def test_rejected_reservation_stops_before_totp_verification(
        self,
        reservation,
        expected_reason,
    ):
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=AssertionError("administrator TOTP work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                totp_recover,
                "reserve_session_step_up_attempt",
                _reservation_mock(reservation),
            ),
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            pytest.raises(totp_recover.TotpRecoveryRejected) as caught,
        ):
            await totp_recover.authorize_totp_recovery(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=TARGET_ID,
                admin_totp_code="123456",
            )

        assert caught.value.reason == expected_reason
        acquire_cursor.assert_not_called()

    async def test_reservation_storage_error_stops_before_totp_verification(self):
        storage_error = _ReservationStorageError("reservation unavailable")
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=AssertionError("administrator TOTP work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                totp_recover,
                "reserve_session_step_up_attempt",
                _reservation_mock(storage_error),
            ),
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            pytest.raises(_ReservationStorageError) as caught,
        ):
            await totp_recover.authorize_totp_recovery(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=TARGET_ID,
                admin_totp_code="123456",
            )

        assert caught.value is storage_error
        acquire_cursor.assert_not_called()

    async def test_reservation_succeeds_before_totp_verification_runs(self):
        """Positive control: a granted reservation runs before the administrator's TOTP check, in that order."""
        events: list[str] = []
        cursor = make_async_cursor(
            fetchone={
                "auth_method": "local",
                "totp_configured": True,
                "login_unlocked": True,
            }
        )

        async def reserve(*_args, **_kwargs):
            events.append("reserve")
            return SessionStepUpAttemptOutcome.RESERVED

        async def verify_totp(*_args, **_kwargs):
            events.append("totp")
            raise _CredentialBoundaryReached

        with (
            patch.object(
                totp_recover,
                "reserve_session_step_up_attempt",
                new=create_autospec(
                    totp_recover.reserve_session_step_up_attempt,
                    side_effect=reserve,
                    spec_set=True,
                ),
            ) as reserve_attempt,
            patch.object(
                totp_recover,
                "get_db_cursor",
                create_autospec(
                    totp_recover.get_db_cursor,
                    return_value=FakeCursorCtx(cursor),
                    spec_set=True,
                ),
            ),
            patch.object(
                totp_recover,
                "guard_current_admin_session_cur",
                new=create_autospec(totp_recover.guard_current_admin_session_cur, spec_set=True),
            ),
            patch.object(
                totp_recover,
                "verify_and_consume_totp_cur",
                new=create_autospec(
                    totp_recover.verify_and_consume_totp_cur,
                    side_effect=verify_totp,
                    spec_set=True,
                ),
            ),
            pytest.raises(_CredentialBoundaryReached),
        ):
            await totp_recover.authorize_totp_recovery(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=TARGET_ID,
                admin_totp_code="123456",
            )

        assert events == ["reserve", "totp"]
        reserve_attempt.assert_awaited_once_with(
            sentinel.pool,
            user_id=ACTOR_ID,
            session_id=SESSION_ID,
        )

    async def test_malformed_totp_is_rejected_after_the_reservation_without_a_type_error(self):
        acquire_cursor = create_autospec(
            totp_recover.get_db_cursor,
            side_effect=AssertionError("administrator TOTP work must not run"),
            spec_set=True,
        )

        with (
            patch.object(
                totp_recover,
                "reserve_session_step_up_attempt",
                _reservation_mock(SessionStepUpAttemptOutcome.RESERVED),
            ) as reserve,
            patch.object(totp_recover, "get_db_cursor", acquire_cursor),
            pytest.raises(totp_recover.TotpRecoveryRejected) as caught,
        ):
            await totp_recover.authorize_totp_recovery(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=TARGET_ID,
                admin_totp_code="not-a-code",
            )

        assert caught.value.reason == "invalid_admin_totp"
        reserve.assert_awaited_once_with(
            sentinel.pool,
            user_id=ACTOR_ID,
            session_id=SESSION_ID,
        )
        acquire_cursor.assert_not_called()
