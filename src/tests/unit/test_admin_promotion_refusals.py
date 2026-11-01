"""Promotion validators and administrator-driven invitation/refusal branches."""

import logging
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch, sentinel

import pytest

from app.services import admin_promotion
from tests.fixtures import FakeCursorCtx, make_async_cursor

USER_ID = 41
ACTOR_ID = 91
SESSION_ID = "raw-session-secret"


def _target_row(**overrides):
    """An eligible local-account target row shared by request/prepare/accept."""
    row = {
        "auth_revision": 3,
        "auth_method": "local",
        "is_active": True,
        "is_admin": False,
        "email_verified": True,
        "totp_secret": "encrypted-secret",
        "totp_recovery_required": False,
    }
    row.update(overrides)
    return row


def _requester_row(**overrides):
    """Return an eligible administrator row with explicit field overrides."""
    row = {
        "is_active": True,
        "is_admin": True,
        "auth_method": "local",
        "totp_secret": "encrypted-secret",
        "totp_recovery_code_generation": 1,
        "recovery_codes_available": True,
    }
    row.update(overrides)
    return row


def _autospec(target):
    """Return a strict signature-checked double of target."""
    return create_autospec(target, spec_set=True)


class TestLockFullSessionCurAdmitsOnlyALiveMatchingFullSession:
    """_lock_full_session_cur admits only a live 'full' session row for the exact caller-supplied id."""

    async def test_blank_session_id_is_rejected_without_querying_the_database(self):
        """Blank session ID is rejected without querying the database."""
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._lock_full_session_cur(cur, user_id=USER_ID, session_id="")
        assert caught.value.reason == "invalid_session"
        cur.execute.assert_not_called()

    async def test_absent_or_expired_session_row_is_rejected(self):
        """Absent or expired session row is rejected."""
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._lock_full_session_cur(
                cur, user_id=USER_ID, session_id=SESSION_ID
            )
        assert caught.value.reason == "invalid_session"
        cur.execute.assert_awaited_once()

    async def test_matching_active_full_session_row_is_accepted(self):
        """A live full session for this exact user does not raise."""
        cur = make_async_cursor(fetchone={"?column?": 1})
        await admin_promotion._lock_full_session_cur(cur, user_id=USER_ID, session_id=SESSION_ID)
        cur.execute.assert_awaited_once()


class TestValidateTargetRowAdmitsOnlyAnEligibleLocalAccount:
    """_validate_target_row accepts only an active, verified local account with TOTP configured and no pending recovery requirement."""

    def test_missing_user_is_rejected(self):
        """Missing user is rejected."""
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            admin_promotion._validate_target_row(None)
        assert caught.value.reason == "user_not_found"

    @pytest.mark.parametrize(
        ("override", "value"),
        [
            ("auth_method", "shibboleth"),
            ("is_active", False),
            ("email_verified", False),
            ("totp_secret", None),
            ("totp_recovery_required", True),
        ],
        ids=(
            "federated-account",
            "deactivated-account",
            "unverified-email",
            "totp-not-configured",
            "recovery-already-required",
        ),
    )
    def test_ineligible_account_is_rejected(self, override, value):
        """Ineligible account is rejected."""
        row = _target_row()
        row[override] = value
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            admin_promotion._validate_target_row(row)
        assert caught.value.reason == "ineligible_account"

    def test_eligible_local_account_is_accepted(self):
        """A fully eligible local account raises nothing."""
        assert admin_promotion._validate_target_row(_target_row()) is None


class TestValidateRequesterCurAdmitsOnlyAnActiveAdministratorWithRecoveryCapacity:
    """_validate_requester_cur accepts only an active administrator who, if local, can still prove a recovery code."""

    async def test_missing_requester_is_rejected(self):
        """Missing requester is rejected."""
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._validate_requester_cur(cur, ACTOR_ID)
        assert caught.value.reason == "requester_ineligible"

    @pytest.mark.parametrize(
        ("override", "value"),
        [("is_active", False), ("is_admin", False)],
        ids=("deactivated-requester", "demoted-requester"),
    )
    async def test_inactive_or_non_admin_requester_is_rejected(self, override, value):
        """Inactive or non admin requester is rejected."""
        cur = make_async_cursor(fetchone=_requester_row(**{override: value}))
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._validate_requester_cur(cur, ACTOR_ID)
        assert caught.value.reason == "requester_ineligible"

    @pytest.mark.parametrize(
        ("override", "value"),
        [
            ("totp_secret", None),
            ("totp_recovery_code_generation", 0),
            ("recovery_codes_available", False),
        ],
        ids=(
            "totp-not-configured",
            "no-recovery-generation-issued",
            "recovery-code-budget-exhausted",
        ),
    )
    async def test_local_requester_without_an_available_recovery_code_is_rejected(
        self, override, value
    ):
        """Local requester without an available recovery code is rejected."""
        cur = make_async_cursor(fetchone=_requester_row(**{override: value}))
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._validate_requester_cur(cur, ACTOR_ID)
        assert caught.value.reason == "requester_ineligible"

    async def test_eligible_local_requester_with_an_available_recovery_code_is_accepted(self):
        """An active local administrator with a usable recovery code passes."""
        cur = make_async_cursor(fetchone=_requester_row())
        await admin_promotion._validate_requester_cur(cur, ACTOR_ID)

    async def test_eligible_federated_requester_is_accepted_without_a_recovery_code_check(self):
        """Federated administrators skip the local recovery-code budget entirely."""
        cur = make_async_cursor(
            fetchone=_requester_row(
                auth_method="shibboleth",
                totp_secret=None,
                totp_recovery_code_generation=0,
                recovery_codes_available=False,
            )
        )
        await admin_promotion._validate_requester_cur(cur, ACTOR_ID)


class TestGetAdminPromotionReturnsTargetVisibleState:
    """get_admin_promotion reports the invitation row as a dataclass, or None when there is no invitation."""

    async def test_no_invitation_returns_none(self):
        """No invitation returns None."""
        cur = make_async_cursor(fetchone=None)
        with patch.object(
            admin_promotion,
            "get_db_cursor",
            create_autospec(
                admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            ),
        ):
            result = await admin_promotion.get_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert result is None

    async def test_existing_invitation_row_is_returned_as_a_promotion(self):
        """An existing invitation row becomes an AdminPromotion with its exact fields."""
        requested_at = datetime(2026, 1, 1, tzinfo=UTC)
        expires_at = datetime(2026, 1, 8, tzinfo=UTC)
        row = {
            "user_id": USER_ID,
            "requested_by": ACTOR_ID,
            "requested_at": requested_at,
            "expires_at": expires_at,
            "expired": False,
            "prepared_for_current_session": True,
        }
        cur = make_async_cursor(fetchone=row)
        with patch.object(
            admin_promotion,
            "get_db_cursor",
            create_autospec(
                admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            ),
        ):
            result = await admin_promotion.get_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert result == admin_promotion.AdminPromotion(
            user_id=USER_ID,
            requested_by=ACTOR_ID,
            requested_at=requested_at,
            expires_at=expires_at,
            expired=False,
            prepared_for_current_session=True,
        )


class TestRequestAdminPromotionPersistsAnInvitation:
    """request_admin_promotion validates and locks the target before persisting an invitation, reporting whether it replaced a live one."""

    @pytest.mark.parametrize(
        ("existing_request_row", "expected_reissued"),
        [(None, False), ({"user_id": USER_ID}, True)],
        ids=("first-invitation", "reissued-invitation"),
    )
    async def test_eligible_target_persists_an_invitation_and_reports_whether_it_was_reissued(
        self, existing_request_row, expected_reissued
    ):
        """An eligible target always produces a persisted invitation."""
        expires_at = datetime(2026, 1, 8, tzinfo=UTC)
        cur = make_async_cursor(
            fetchone=[_target_row(), existing_request_row, {"expires_at": expires_at}]
        )
        discard = _autospec(admin_promotion.discard_pending_recovery_code_set_cur)
        with (
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(
                admin_promotion,
                "guard_current_admin_session_cur",
                _autospec(admin_promotion.guard_current_admin_session_cur),
            ),
            patch.object(admin_promotion, "discard_pending_recovery_code_set_cur", discard),
        ):
            result = await admin_promotion.request_admin_promotion(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=USER_ID,
            )
        assert result == admin_promotion.AdminPromotionRequestResult(
            user_id=USER_ID, expires_at=expires_at, reissued=expected_reissued
        )
        discard.assert_awaited_once_with(cur, user_id=USER_ID)

    async def test_target_row_disappearing_after_validation_raises_instead_of_silently_continuing(
        self,
    ):
        """Target row disappearing after validation raises instead of silently continuing."""
        cur = make_async_cursor(fetchone=None)
        with (
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(
                admin_promotion,
                "guard_current_admin_session_cur",
                _autospec(admin_promotion.guard_current_admin_session_cur),
            ),
            patch.object(
                admin_promotion,
                "_validate_target_row",
                _autospec(admin_promotion._validate_target_row),
            ),
            pytest.raises(RuntimeError, match="unexpectedly missing"),
        ):
            await admin_promotion.request_admin_promotion(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=USER_ID,
            )


class TestCancelAdminPromotionWithdrawsAnUnacceptedInvitation:
    """cancel_admin_promotion deletes a live invitation under the administrator lock order and reports whether there was one."""

    async def test_missing_target_user_is_rejected(self):
        """Missing target user is rejected."""
        cur = make_async_cursor(fetchone=None)
        with (
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(
                admin_promotion,
                "guard_current_admin_session_cur",
                _autospec(admin_promotion.guard_current_admin_session_cur),
            ),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.cancel_admin_promotion(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=USER_ID,
            )
        assert caught.value.reason == "user_not_found"

    async def test_absent_invitation_returns_false_without_logging(self, caplog):
        """Absent invitation returns False without logging."""
        cur = make_async_cursor(fetchone=[{"id": USER_ID}, None])
        discard = _autospec(admin_promotion.discard_pending_recovery_code_set_cur)
        with (
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(
                admin_promotion,
                "guard_current_admin_session_cur",
                _autospec(admin_promotion.guard_current_admin_session_cur),
            ),
            patch.object(admin_promotion, "discard_pending_recovery_code_set_cur", discard),
            caplog.at_level(logging.INFO, logger="app.services.admin_promotion"),
        ):
            result = await admin_promotion.cancel_admin_promotion(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=USER_ID,
            )
        assert result is False
        discard.assert_not_awaited()
        assert caplog.records == []

    async def test_existing_invitation_is_cancelled_and_logged(self, caplog):
        """An existing invitation is deleted, its staged codes discarded, and the cancellation
        logged.
        """
        cur = make_async_cursor(fetchone=[{"id": USER_ID}, {"user_id": USER_ID}])
        discard = _autospec(admin_promotion.discard_pending_recovery_code_set_cur)
        with (
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            ),
            patch.object(
                admin_promotion,
                "guard_current_admin_session_cur",
                _autospec(admin_promotion.guard_current_admin_session_cur),
            ),
            patch.object(admin_promotion, "discard_pending_recovery_code_set_cur", discard),
            caplog.at_level(logging.INFO, logger="app.services.admin_promotion"),
        ):
            result = await admin_promotion.cancel_admin_promotion(
                sentinel.pool,
                actor_id=ACTOR_ID,
                actor_session_id=SESSION_ID,
                target_user_id=USER_ID,
            )
        assert result is True
        discard.assert_awaited_once_with(cur, user_id=USER_ID)
        assert any("cancelled admin invitation" in record.message for record in caplog.records)
