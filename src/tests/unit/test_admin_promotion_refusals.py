"""Edge and defensive branches of app.services.admin_promotion: the target and
requester validators, the timing-safe password snapshot, and the read/write
entry points an administrator (not the target) drives.

Companion to test_admin_authority_credential_budgets.py, which proves the
step-up reservation always runs first. Companion to
test_admin_promotion_transition_refusals.py, which covers the same edge and
defensive branches for the target-driven prepare/accept/decline transitions.

Every test proving a validator rejects a state has a positive control in the
same class proving the eligible state still passes; every "this cannot
happen" guard is proven to actually raise instead of silently trusting its
precondition.
"""

import logging
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch, sentinel

import pytest
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

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
    return create_autospec(target, spec_set=True)


# ---------------------------------------------------------------------------
# _lock_full_session_cur
# ---------------------------------------------------------------------------


class TestLockFullSessionCurAdmitsOnlyALiveMatchingFullSession:
    """_lock_full_session_cur admits only a live 'full' session row for the exact caller-supplied id."""

    async def test_blank_session_id_is_rejected_without_querying_the_database(self):
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._lock_full_session_cur(cur, user_id=USER_ID, session_id="")
        assert caught.value.reason == "invalid_session"
        cur.execute.assert_not_called()

    async def test_absent_or_expired_session_row_is_rejected(self):
        cur = make_async_cursor(fetchone=None)
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._lock_full_session_cur(
                cur, user_id=USER_ID, session_id=SESSION_ID
            )
        assert caught.value.reason == "invalid_session"
        cur.execute.assert_awaited_once()

    async def test_matching_active_full_session_row_is_accepted(self):
        """Positive control: a live full session for this exact user does not raise."""
        cur = make_async_cursor(fetchone={"?column?": 1})
        await admin_promotion._lock_full_session_cur(cur, user_id=USER_ID, session_id=SESSION_ID)
        cur.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# _validate_target_row
# ---------------------------------------------------------------------------


class TestValidateTargetRowAdmitsOnlyAnEligibleLocalAccount:
    """_validate_target_row accepts only an active, verified local account with TOTP configured and no pending recovery requirement."""

    def test_missing_user_is_rejected(self):
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
        row = _target_row()
        row[override] = value
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            admin_promotion._validate_target_row(row)
        assert caught.value.reason == "ineligible_account"

    def test_eligible_local_account_is_accepted(self):
        """Positive control: a fully eligible local account raises nothing."""
        assert admin_promotion._validate_target_row(_target_row()) is None


# ---------------------------------------------------------------------------
# _validate_requester_cur
# ---------------------------------------------------------------------------


class TestValidateRequesterCurAdmitsOnlyAnActiveAdministratorWithRecoveryCapacity:
    """_validate_requester_cur accepts only an active administrator who, if local, can still prove a recovery code."""

    async def test_missing_requester_is_rejected(self):
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
        cur = make_async_cursor(fetchone=_requester_row(**{override: value}))
        with pytest.raises(admin_promotion.AdminPromotionRejected) as caught:
            await admin_promotion._validate_requester_cur(cur, ACTOR_ID)
        assert caught.value.reason == "requester_ineligible"

    async def test_eligible_local_requester_with_an_available_recovery_code_is_accepted(self):
        """Positive control: an active local administrator with a usable recovery code passes."""
        cur = make_async_cursor(fetchone=_requester_row())
        await admin_promotion._validate_requester_cur(cur, ACTOR_ID)

    async def test_eligible_federated_requester_is_accepted_without_a_recovery_code_check(self):
        """Positive control: federated administrators skip the local recovery-code budget entirely."""
        cur = make_async_cursor(
            fetchone=_requester_row(
                auth_method="shibboleth",
                totp_secret=None,
                totp_recovery_code_generation=0,
                recovery_codes_available=False,
            )
        )
        await admin_promotion._validate_requester_cur(cur, ACTOR_ID)


# ---------------------------------------------------------------------------
# _verify_password_snapshot
# ---------------------------------------------------------------------------


class TestVerifyPasswordSnapshotNarrowsTimingOnFailure:
    """_verify_password_snapshot always performs Argon2-equivalent work before rejecting, and returns the exact verified state only on success."""

    def _patches(self, cur, *, work=None):
        patches = [
            patch.object(
                admin_promotion,
                "get_db_cursor",
                create_autospec(
                    admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
                ),
            )
        ]
        dummy = create_autospec(admin_promotion.verify_dummy, spec_set=True)
        patches.append(patch.object(admin_promotion, "verify_dummy", dummy))
        if work is not None:
            patches.append(patch.object(admin_promotion, "run_password_work", work))
        return patches, dummy

    async def test_missing_user_row_still_performs_dummy_work_before_rejecting(self):
        cur = make_async_cursor(fetchone=None)
        patches, dummy = self._patches(cur)
        with (
            patches[0],
            patches[1],
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion._verify_password_snapshot(
                sentinel.pool, user_id=USER_ID, password="candidate"
            )
        assert caught.value.reason == "invalid_credentials"
        dummy.assert_awaited_once_with("candidate")

    async def test_blank_stored_hash_still_performs_dummy_work_before_rejecting(self):
        cur = make_async_cursor(fetchone={"password_hash": "", "auth_revision": 1})
        patches, dummy = self._patches(cur)
        with (
            patches[0],
            patches[1],
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion._verify_password_snapshot(
                sentinel.pool, user_id=USER_ID, password="candidate"
            )
        assert caught.value.reason == "invalid_credentials"
        dummy.assert_awaited_once_with("candidate")

    async def test_mismatched_password_is_rejected_without_a_dummy_verification(self):
        cur = make_async_cursor(fetchone={"password_hash": "argon2-hash", "auth_revision": 1})
        work = create_autospec(
            admin_promotion.run_password_work,
            side_effect=VerifyMismatchError("mismatch"),
            spec_set=True,
        )
        patches, dummy = self._patches(cur, work=work)
        with (
            patches[0],
            patches[1],
            patches[2],
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion._verify_password_snapshot(
                sentinel.pool, user_id=USER_ID, password="candidate"
            )
        assert caught.value.reason == "invalid_credentials"
        dummy.assert_not_awaited()

    @pytest.mark.parametrize(
        "exc_type",
        [InvalidHashError, VerificationError],
        ids=("invalid-hash", "verification-error"),
    )
    async def test_unverifiable_hash_logs_and_still_performs_dummy_work(self, exc_type, caplog):
        cur = make_async_cursor(fetchone={"password_hash": "corrupt-hash", "auth_revision": 1})
        work = create_autospec(
            admin_promotion.run_password_work, side_effect=exc_type("boom"), spec_set=True
        )
        patches, dummy = self._patches(cur, work=work)
        with (
            patches[0],
            patches[1],
            patches[2],
            caplog.at_level(logging.ERROR, logger="app.services.admin_promotion"),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion._verify_password_snapshot(
                sentinel.pool, user_id=USER_ID, password="candidate"
            )
        assert caught.value.reason == "invalid_credentials"
        dummy.assert_awaited_once_with("candidate")
        assert any("Unverifiable password hash" in record.message for record in caplog.records)

    async def test_correct_password_returns_the_verified_hash_and_revision(self):
        """Positive control: matching credentials return the exact snapshot without any dummy work."""
        cur = make_async_cursor(fetchone={"password_hash": "argon2-hash", "auth_revision": 5})
        work = create_autospec(admin_promotion.run_password_work, return_value=True, spec_set=True)
        patches, dummy = self._patches(cur, work=work)
        with patches[0], patches[1], patches[2]:
            result = await admin_promotion._verify_password_snapshot(
                sentinel.pool, user_id=USER_ID, password="candidate"
            )
        assert result == ("argon2-hash", 5)
        dummy.assert_not_awaited()


# ---------------------------------------------------------------------------
# get_admin_promotion
# ---------------------------------------------------------------------------


class TestGetAdminPromotionReturnsTargetVisibleState:
    """get_admin_promotion reports the invitation row as a dataclass, or None when there is no invitation."""

    async def test_no_invitation_returns_none(self):
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
        """Positive control: an existing invitation row becomes an AdminPromotion with its exact fields."""
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


# ---------------------------------------------------------------------------
# request_admin_promotion
# ---------------------------------------------------------------------------


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
        """Positive control: an eligible target always produces a persisted invitation."""
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


# ---------------------------------------------------------------------------
# cancel_admin_promotion
# ---------------------------------------------------------------------------


class TestCancelAdminPromotionWithdrawsAnUnacceptedInvitation:
    """cancel_admin_promotion deletes a live invitation under the administrator lock order and reports whether there was one."""

    async def test_missing_target_user_is_rejected(self):
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
        discard.assert_awaited_once_with(cur, user_id=USER_ID)
        assert caplog.records == []

    async def test_existing_invitation_is_cancelled_and_logged(self, caplog):
        """Positive control: an existing invitation is deleted, its staged codes discarded, and the cancellation logged."""
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
