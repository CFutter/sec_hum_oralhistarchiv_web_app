"""app.services re-exports the credential step-up budget and the outcome/
rejection types the routes need to interpret it, without re-exporting the
services' private implementation helpers.

Split out of test_credential_budgets.py (which is at its line cap) rather
than appended to it.
"""

from app import services
from app.services import (
    admin_promotion,
    credential_attempts,
    email_change,
    totp,
    totp_recover,
    users,
)


class TestReservationFunctionExport:
    """The shared step-up reservation entry point is part of the public surface."""

    def test_reserve_session_step_up_attempt_is_exported(self):
        assert services.reserve_session_step_up_attempt is (
            credential_attempts.reserve_session_step_up_attempt
        )

    def test_session_step_up_attempt_outcome_is_exported(self):
        assert (
            services.SessionStepUpAttemptOutcome is credential_attempts.SessionStepUpAttemptOutcome
        )


class TestStepUpAndRecoveryOutcomeTypesAreExported:
    """Every outcome/rejection type a route imports from app.services resolves
    to the exact object its defining module raises or returns, so an
    ``isinstance``/``except`` check in a route matches what the service layer
    actually produces.
    """

    def test_admin_action_rejected_is_exported(self):
        assert services.AdminActionRejected is users.AdminActionRejected

    def test_admin_email_change_rejected_is_exported(self):
        assert services.AdminEmailChangeRejected is email_change.AdminEmailChangeRejected

    def test_admin_promotion_rejected_is_exported(self):
        assert services.AdminPromotionRejected is admin_promotion.AdminPromotionRejected

    def test_self_email_change_rejected_is_exported(self):
        assert services.SelfEmailChangeRejected is email_change.SelfEmailChangeRejected

    def test_totp_recovery_redemption_rejected_is_exported(self):
        assert (
            services.TotpRecoveryRedemptionRejected is totp_recover.TotpRecoveryRedemptionRejected
        )

    def test_totp_recovery_rejected_is_exported(self):
        assert services.TotpRecoveryRejected is totp_recover.TotpRecoveryRejected

    def test_pending_totp_outcome_is_exported(self):
        assert services.PendingTotpOutcome is totp.PendingTotpOutcome

    def test_totp_decryption_error_is_exported(self):
        assert services.TotpDecryptionError is totp.TotpDecryptionError

    def test_totp_enrollment_outcome_is_exported(self):
        assert services.TotpEnrollmentOutcome is totp.TotpEnrollmentOutcome

    def test_totp_rotation_outcome_is_exported(self):
        assert services.TotpRotationOutcome is totp.TotpRotationOutcome

    def test_totp_rotation_start_outcome_is_exported(self):
        assert services.TotpRotationStartOutcome is totp.TotpRotationStartOutcome


class TestPrivateHelpersAreNotExported:
    """Positive control for the exports above: a name that a defining module
    deliberately keeps private (a leading underscore, never imported into
    app.services.__init__) is absent from the public service surface, not
    silently re-exported alongside the outcome types.
    """

    def test_verify_password_snapshot_is_not_exported(self):
        """admin_promotion._verify_password_snapshot never leaves the module:
        callers use prepare_admin_promotion, never the raw password check.
        """
        assert not hasattr(services, "_verify_password_snapshot")

    def test_lock_full_session_cur_is_not_exported(self):
        """admin_promotion._lock_full_session_cur is an internal, cursor-bound
        helper that requires a caller-held transaction; it is not part of the
        public service surface."""
        assert not hasattr(services, "_lock_full_session_cur")

    def test_verify_password_snapshot_is_still_reachable_on_its_own_module(self):
        """Positive control: hiding a name from app.services does not delete
        it — admin_promotion still defines and can call its own helper."""
        assert callable(admin_promotion._verify_password_snapshot)
