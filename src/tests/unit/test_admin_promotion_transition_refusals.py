"""Edge and defensive branches of the target-driven admin_promotion
transitions: prepare_admin_promotion, accept_admin_promotion, and
decline_admin_promotion.

Companion to test_admin_promotion_refusals.py, which covers the same edge and
defensive branches for the validators and the administrator-driven entry
points. Companion to test_admin_authority_credential_budgets.py, which proves
the step-up reservation always runs first for prepare/accept; this module
proves what happens once that reservation is granted: every remaining
validation (locked account, stale password/TOTP snapshot, expired/mismatched
invitation, stale or foreign preparation, incorrect code) still rejects a
live-but-invalid state, an eligible state still proceeds end to end, and
every "this cannot happen" guard actually raises instead of silently
trusting its precondition.
"""

from contextlib import ExitStack
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch, sentinel

import pytest

from app.services import admin_promotion
from app.services.credential_attempts import SessionStepUpAttemptOutcome
from app.services.session_ids import hash_session_id
from app.services.totp_recovery_codes import PendingRecoveryCodeSet
from tests.fixtures import FakeCursorCtx, make_async_cursor

USER_ID = 41
ACTOR_ID = 91
SESSION_ID = "raw-session-secret"
RECOVERY_CODE = "AAAAA-BBBBB-CCCCC-DDDDD"


def _target_row(**overrides):
    """An eligible local-account target row shared by prepare/accept."""
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


def _prepare_target_row(**overrides):
    row = _target_row(password_hash="stored-hash")
    row["login_unlocked"] = True
    row.update(overrides)
    return row


def _accept_target_row(**overrides):
    row = _target_row()
    row["login_unlocked"] = True
    row.update(overrides)
    return row


def _prepare_promotion_row(**overrides):
    row = {
        "requested_by": ACTOR_ID,
        "expected_auth_revision": 3,
        "expires_at": datetime(2026, 1, 8, tzinfo=UTC),
        "unexpired": True,
    }
    row.update(overrides)
    return row


def _accept_promotion_row(**overrides):
    row = {
        "requested_by": ACTOR_ID,
        "expected_auth_revision": 3,
        "unexpired": True,
        "prepared_at": datetime(2026, 1, 1, tzinfo=UTC),
        "prepared_session_id": hash_session_id(SESSION_ID),
    }
    row.update(overrides)
    return row


def _autospec(target):
    return create_autospec(target, spec_set=True)


def _patched_prepare_dependencies(
    cur,
    *,
    reservation=SessionStepUpAttemptOutcome.RESERVED,
    verified=("stored-hash", 3),
    totp_ok=True,
    staged=None,
):
    stack = ExitStack()
    stack.enter_context(
        patch.object(
            admin_promotion,
            "reserve_session_step_up_attempt",
            create_autospec(
                admin_promotion.reserve_session_step_up_attempt,
                return_value=reservation,
                spec_set=True,
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "_verify_password_snapshot",
            create_autospec(
                admin_promotion._verify_password_snapshot,
                return_value=verified,
                spec_set=True,
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "get_db_cursor",
            create_autospec(
                admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "acquire_admin_action_lock_cur",
            _autospec(admin_promotion.acquire_admin_action_lock_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "_lock_full_session_cur",
            _autospec(admin_promotion._lock_full_session_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "_validate_requester_cur",
            _autospec(admin_promotion._validate_requester_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "verify_and_consume_totp_cur",
            create_autospec(
                admin_promotion.verify_and_consume_totp_cur, return_value=totp_ok, spec_set=True
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "stage_recovery_code_set_cur",
            create_autospec(
                admin_promotion.stage_recovery_code_set_cur,
                return_value=staged
                or PendingRecoveryCodeSet(generation=2, codes=("AAAAA-BBBBB",) * 10),
                spec_set=True,
            ),
        )
    )
    return stack


def _patched_accept_dependencies(
    cur,
    *,
    reservation=SessionStepUpAttemptOutcome.RESERVED,
    activate_result=True,
):
    stack = ExitStack()
    stack.enter_context(
        patch.object(
            admin_promotion,
            "reserve_session_step_up_attempt",
            create_autospec(
                admin_promotion.reserve_session_step_up_attempt,
                return_value=reservation,
                spec_set=True,
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "get_db_cursor",
            create_autospec(
                admin_promotion.get_db_cursor, return_value=FakeCursorCtx(cur), spec_set=True
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "acquire_admin_action_lock_cur",
            _autospec(admin_promotion.acquire_admin_action_lock_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "_lock_full_session_cur",
            _autospec(admin_promotion._lock_full_session_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "_validate_requester_cur",
            _autospec(admin_promotion._validate_requester_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "activate_pending_recovery_code_set_cur",
            create_autospec(
                admin_promotion.activate_pending_recovery_code_set_cur,
                return_value=activate_result,
                spec_set=True,
            ),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "delete_user_sessions_cur",
            _autospec(admin_promotion.delete_user_sessions_cur),
        )
    )
    stack.enter_context(
        patch.object(
            admin_promotion,
            "invalidate_pending_authentication_state_cur",
            _autospec(admin_promotion.invalidate_pending_authentication_state_cur),
        )
    )
    return stack


# ---------------------------------------------------------------------------
# prepare_admin_promotion
# ---------------------------------------------------------------------------


class TestPrepareAdminPromotionValidatesTheLiveInvitationUnderLock:
    """Once the credential reservation is granted, prepare_admin_promotion still refuses a locked account, a stale password/TOTP snapshot, or an expired/mismatched invitation."""

    async def _call(self, **kwargs):
        params = {
            "user_id": USER_ID,
            "session_id": SESSION_ID,
            "password": "candidate password",
            "totp_code": "123456",
        }
        params.update(kwargs)
        return await admin_promotion.prepare_admin_promotion(sentinel.pool, **params)

    async def test_locked_account_is_rejected_after_reauthentication_already_succeeded(self):
        cur = make_async_cursor(fetchone=[_prepare_target_row(login_unlocked=False), None, None])
        with (
            _patched_prepare_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "account_locked"

    async def test_password_hash_changed_since_verification_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_prepare_target_row(password_hash="a-different-hash"), None, None]
        )
        with (
            _patched_prepare_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "state_changed"

    async def test_missing_invitation_is_rejected(self):
        cur = make_async_cursor(fetchone=[_prepare_target_row(), None])
        with (
            _patched_prepare_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "no_request"

    async def test_expired_invitation_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_prepare_target_row(), _prepare_promotion_row(unexpired=False)]
        )
        with (
            _patched_prepare_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "invitation_expired"

    async def test_invitation_bound_to_a_stale_auth_revision_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_prepare_target_row(), _prepare_promotion_row(expected_auth_revision=99)]
        )
        with (
            _patched_prepare_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "state_changed"

    async def test_already_consumed_totp_step_is_rejected(self):
        cur = make_async_cursor(fetchone=[_prepare_target_row(), _prepare_promotion_row()])
        with (
            _patched_prepare_dependencies(cur, totp_ok=False),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "invalid_totp"

    async def test_unhandled_reservation_outcome_raises_instead_of_silently_proceeding(self):
        cur = make_async_cursor()
        with (
            _patched_prepare_dependencies(cur, reservation="not-a-real-outcome"),
            pytest.raises(RuntimeError, match="Unhandled step-up reservation outcome"),
        ):
            await self._call()

    async def test_target_row_disappearing_after_validation_raises_instead_of_silently_continuing(
        self,
    ):
        cur = make_async_cursor(fetchone=[None, None, None])
        with (
            _patched_prepare_dependencies(cur),
            patch.object(
                admin_promotion,
                "_validate_target_row",
                _autospec(admin_promotion._validate_target_row),
            ),
            pytest.raises(RuntimeError, match="unexpectedly missing"),
        ):
            await self._call()

    async def test_eligible_target_with_a_live_invitation_stages_a_fresh_code_set(self):
        """Positive control: a fully eligible target with a live, matching invitation stages a fresh code set and both expirations."""
        invitation_expires_at = datetime(2026, 1, 8, tzinfo=UTC)
        preparation_expires_at = datetime(2026, 1, 1, 0, 15, tzinfo=UTC)
        cur = make_async_cursor(
            fetchone=[
                _prepare_target_row(),
                _prepare_promotion_row(),
                {
                    "invitation_expires_at": invitation_expires_at,
                    "preparation_expires_at": preparation_expires_at,
                },
            ]
        )
        staged = PendingRecoveryCodeSet(generation=4, codes=("AAAAA-BBBBB",) * 10)
        with _patched_prepare_dependencies(cur, staged=staged):
            result = await self._call()
        assert result == admin_promotion.PreparedAdminPromotion(
            user_id=USER_ID,
            invitation_expires_at=invitation_expires_at,
            preparation_expires_at=preparation_expires_at,
            recovery_codes=staged.codes,
        )


# ---------------------------------------------------------------------------
# accept_admin_promotion
# ---------------------------------------------------------------------------


class TestAcceptAdminPromotionActivatesOnlyWithALiveMatchingPreparation:
    """Once the credential reservation is granted, accept_admin_promotion still refuses a locked account, an expired/unmatched/stale preparation, or an incorrect code."""

    async def _call(self, **kwargs):
        params = {"user_id": USER_ID, "session_id": SESSION_ID, "recovery_code": RECOVERY_CODE}
        params.update(kwargs)
        return await admin_promotion.accept_admin_promotion(sentinel.pool, **params)

    async def test_locked_account_is_rejected(self):
        cur = make_async_cursor(fetchone=[_accept_target_row(login_unlocked=False)])
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "account_locked"

    async def test_missing_invitation_is_rejected(self):
        cur = make_async_cursor(fetchone=[_accept_target_row(), None])
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "no_request"

    async def test_expired_invitation_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_accept_target_row(), _accept_promotion_row(unexpired=False)]
        )
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "invitation_expired"

    async def test_invitation_bound_to_a_stale_auth_revision_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_accept_target_row(), _accept_promotion_row(expected_auth_revision=99)]
        )
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "state_changed"

    async def test_preparation_from_a_different_session_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[
                _accept_target_row(),
                _accept_promotion_row(prepared_session_id=hash_session_id("a-different-session")),
            ]
        )
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "codes_not_prepared"

    async def test_preparation_never_completed_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[_accept_target_row(), _accept_promotion_row(prepared_at=None)]
        )
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "codes_not_prepared"

    async def test_stale_preparation_window_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[
                _accept_target_row(),
                _accept_promotion_row(),
                {"preparation_current": False},
            ]
        )
        with (
            _patched_accept_dependencies(cur),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "codes_not_prepared"

    async def test_incorrect_recovery_code_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[
                _accept_target_row(),
                _accept_promotion_row(),
                {"preparation_current": True},
            ]
        )
        with (
            _patched_accept_dependencies(cur, activate_result=False),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await self._call()
        assert caught.value.reason == "invalid_recovery_code"

    async def test_unhandled_reservation_outcome_raises_instead_of_silently_proceeding(self):
        cur = make_async_cursor()
        with (
            _patched_accept_dependencies(cur, reservation="not-a-real-outcome"),
            pytest.raises(RuntimeError, match="Unhandled step-up reservation outcome"),
        ):
            await self._call()

    async def test_target_row_disappearing_after_validation_raises_instead_of_silently_continuing(
        self,
    ):
        cur = make_async_cursor(fetchone=[None])
        with (
            _patched_accept_dependencies(cur),
            patch.object(
                admin_promotion,
                "_validate_target_row",
                _autospec(admin_promotion._validate_target_row),
            ),
            pytest.raises(RuntimeError, match="unexpectedly missing"),
        ):
            await self._call()

    async def test_matching_preparation_and_correct_code_activates_administrator_access(self):
        """Positive control: a live, matching preparation with the correct code activates administrator access."""
        cur = make_async_cursor(
            fetchone=[
                _accept_target_row(),
                _accept_promotion_row(),
                {"preparation_current": True},
            ]
        )
        with _patched_accept_dependencies(cur, activate_result=True):
            result = await self._call()
        assert result == admin_promotion.AcceptedAdminPromotion(
            user_id=USER_ID, requested_by=ACTOR_ID
        )


# ---------------------------------------------------------------------------
# decline_admin_promotion
# ---------------------------------------------------------------------------


class TestDeclineAdminPromotionRequiresAnEligibleLocalTarget:
    """decline_admin_promotion withdraws only an eligible local target's own live invitation, and never returns an untyped requester id."""

    async def test_missing_user_is_rejected(self):
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
                "acquire_admin_action_lock_cur",
                _autospec(admin_promotion.acquire_admin_action_lock_cur),
            ),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.decline_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert caught.value.reason == "user_not_found"

    @pytest.mark.parametrize(
        ("override", "value"),
        [("is_active", False), ("auth_method", "shibboleth")],
        ids=("deactivated-target", "federated-target"),
    )
    async def test_ineligible_target_is_rejected(self, override, value):
        row = {"id": USER_ID, "is_active": True, "auth_method": "local"}
        row[override] = value
        cur = make_async_cursor(fetchone=row)
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
                "acquire_admin_action_lock_cur",
                _autospec(admin_promotion.acquire_admin_action_lock_cur),
            ),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.decline_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert caught.value.reason == "ineligible_account"

    async def test_no_pending_invitation_is_rejected(self):
        cur = make_async_cursor(
            fetchone=[{"id": USER_ID, "is_active": True, "auth_method": "local"}, None]
        )
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
                "acquire_admin_action_lock_cur",
                _autospec(admin_promotion.acquire_admin_action_lock_cur),
            ),
            patch.object(
                admin_promotion,
                "_lock_full_session_cur",
                _autospec(admin_promotion._lock_full_session_cur),
            ),
            pytest.raises(admin_promotion.AdminPromotionRejected) as caught,
        ):
            await admin_promotion.decline_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert caught.value.reason == "no_request"

    async def test_corrupt_requester_id_raises_instead_of_returning_a_bad_type(self):
        cur = make_async_cursor(
            fetchone=[
                {"id": USER_ID, "is_active": True, "auth_method": "local"},
                {"requested_by": "not-an-id"},
            ]
        )
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
                "acquire_admin_action_lock_cur",
                _autospec(admin_promotion.acquire_admin_action_lock_cur),
            ),
            patch.object(
                admin_promotion,
                "_lock_full_session_cur",
                _autospec(admin_promotion._lock_full_session_cur),
            ),
            pytest.raises(TypeError, match="requester ID is invalid"),
        ):
            await admin_promotion.decline_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )

    async def test_eligible_target_declines_and_returns_the_inviting_administrator_id(self):
        """Positive control: an eligible target with a live invitation declines it and reports who invited them."""
        cur = make_async_cursor(
            fetchone=[
                {"id": USER_ID, "is_active": True, "auth_method": "local"},
                {"requested_by": ACTOR_ID},
            ]
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
                "acquire_admin_action_lock_cur",
                _autospec(admin_promotion.acquire_admin_action_lock_cur),
            ),
            patch.object(
                admin_promotion,
                "_lock_full_session_cur",
                _autospec(admin_promotion._lock_full_session_cur),
            ),
            patch.object(admin_promotion, "discard_pending_recovery_code_set_cur", discard),
        ):
            result = await admin_promotion.decline_admin_promotion(
                sentinel.pool, user_id=USER_ID, session_id=SESSION_ID
            )
        assert result == ACTOR_ID
        discard.assert_awaited_once_with(cur, user_id=USER_ID)
