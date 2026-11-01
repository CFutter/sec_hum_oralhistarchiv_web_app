"""Public credential-budget exports and private-helper boundaries."""

from app import services
from app.services import (
    admin_promotion,
    credential_attempts,
    email_change,
    password_verification,
    totp,
    totp_recover,
    users,
)


class TestReservationFunctionExport:
    """The shared step-up reservation entry point is part of the public surface."""

    def test_reserve_session_step_up_attempt_is_exported(self):
        """Reserve session step up attempt is exported."""
        assert services.reserve_session_step_up_attempt is (
            credential_attempts.reserve_session_step_up_attempt
        )

    def test_session_step_up_attempt_outcome_is_exported(self):
        """Session step up attempt outcome is exported."""
        assert (
            services.SessionStepUpAttemptOutcome is credential_attempts.SessionStepUpAttemptOutcome
        )


class TestStepUpAndRecoveryOutcomeTypesAreExported:
    """Export the defining credential outcome/rejection types without wrappers."""

    def test_admin_action_rejected_is_exported(self):
        """Admin action rejected is exported."""
        assert services.AdminActionRejected is users.AdminActionRejected

    def test_admin_email_change_rejected_is_exported(self):
        """Admin email change rejected is exported."""
        assert services.AdminEmailChangeRejected is email_change.AdminEmailChangeRejected

    def test_admin_promotion_rejected_is_exported(self):
        """Admin promotion rejected is exported."""
        assert services.AdminPromotionRejected is admin_promotion.AdminPromotionRejected

    def test_self_email_change_rejected_is_exported(self):
        """Self email change rejected is exported."""
        assert services.SelfEmailChangeRejected is email_change.SelfEmailChangeRejected

    def test_totp_recovery_redemption_rejected_is_exported(self):
        """TOTP recovery redemption rejected is exported."""
        assert (
            services.TotpRecoveryRedemptionRejected is totp_recover.TotpRecoveryRedemptionRejected
        )

    def test_totp_recovery_rejected_is_exported(self):
        """TOTP recovery rejected is exported."""
        assert services.TotpRecoveryRejected is totp_recover.TotpRecoveryRejected

    def test_pending_totp_outcome_is_exported(self):
        """Pending TOTP outcome is exported."""
        assert services.PendingTotpOutcome is totp.PendingTotpOutcome

    def test_totp_decryption_error_is_exported(self):
        """TOTP decryption error is exported."""
        assert services.TotpDecryptionError is totp.TotpDecryptionError

    def test_totp_enrollment_outcome_is_exported(self):
        """TOTP enrollment outcome is exported."""
        assert services.TotpEnrollmentOutcome is totp.TotpEnrollmentOutcome

    def test_totp_rotation_outcome_is_exported(self):
        """TOTP rotation outcome is exported."""
        assert services.TotpRotationOutcome is totp.TotpRotationOutcome

    def test_totp_rotation_start_outcome_is_exported(self):
        """TOTP rotation start outcome is exported."""
        assert services.TotpRotationStartOutcome is totp.TotpRotationStartOutcome


class TestPrivateHelpersAreNotExported:
    """Raw proof and cursor helpers stay outside the public account-operation surface."""

    def test_verify_password_snapshot_is_not_exported(self):
        """Account callers use public workflow services rather than a raw proof helper."""
        assert not hasattr(services, "verify_password_snapshot")

    def test_lock_full_session_cur_is_not_exported(self):
        """Keep the transaction-bound session-lock helper private."""
        assert not hasattr(services, "_lock_full_session_cur")

    def test_verify_password_snapshot_is_still_reachable_on_its_own_module(self):
        """Hiding a name from app.services does not delete it — the lower-level module defines the
        shared helper.
        """
        assert callable(password_verification.verify_password_snapshot)
