"""TOTP enrollment and rotation outcomes that overflowed the two capped
sibling modules (test_totp_enrollment_routes.py, test_totp_rotation_routes.py
are both near the 800-line cap): the non-recovery twin of each recovery-purpose
branch already pinned there, and the best-effort session-revocation exception
paths of both restart helpers.
"""

from unittest.mock import patch

from app.middleware import CSRF_COOKIE_NAME
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    PendingTotpResult,
    TotpEnrollmentOutcome,
    TotpRotationOutcome,
)
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

RECOVERY_CODE = "AAAAA-BBBBB-CCCCC-DDDDD"


def _patch(name, **kw):
    return patch(f"app.routes.auth.totp.{name}", autospec=True, **kw)


def _assert_auth_cookies_cleared(response):
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )


def _post_setup(client, totp_code="123456", recovery_code_confirmation=RECOVERY_CODE, **extra):
    data = {
        "totp_code": totp_code,
        "recovery_code_confirmation": recovery_code_confirmation,
        "csrf_token": client.csrf_token,
        **extra,
    }
    return client.post("/setup-totp", data=data, follow_redirects=False)


def _recovery_client(client_builder, **user_overrides):
    user = make_sample_user(totp_configured=False, totp_recovery_required=True, **user_overrides)
    return client_builder(session_user=user, session_purpose="totp_recovery")


def _post_reset_confirm(client, new_totp_code="222222"):
    return client.post(
        "/account/reset-totp/confirm",
        data={"new_totp_code": new_totp_code, "csrf_token": client.csrf_token},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# GET /setup-totp — the totp_setup-purpose twin of the recovery-purpose
# SESSION_EXPIRED case pinned in test_totp_enrollment_routes.py
# ---------------------------------------------------------------------------


class TestSetupTotpPageSessionExpiredNonRecovery:
    def test_expired_totp_setup_session_restarts_at_a_fresh_login(self, totp_setup_client):
        """A totp_setup-purpose session (not a recovery capability) whose
        pending-secret authority expired is sent to a fresh /login, not back
        to /recover-totp — that destination is reserved for a recovery
        session's own expiry, pinned in
        TestSetupTotpRecoveryPurposeGet.test_expired_recovery_session_is_sent_back_to_the_recovery_entry_point."""
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.SESSION_EXPIRED),
            ) as pending,
            _patch("delete_session") as delete,
        ):
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=totp_setup_completed"
        pending.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=RAW_SESSION_ID,
        )
        delete.assert_awaited_once_with(totp_setup_client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)


# ---------------------------------------------------------------------------
# POST /setup-totp — the totp_setup-purpose twin of the recovery-purpose
# INELIGIBLE case pinned in test_totp_enrollment_routes.py
# ---------------------------------------------------------------------------


class TestSetupTotpSubmitIneligibleNonRecovery:
    def test_ineligible_account_gets_the_branded_unavailable_page(self, totp_setup_client):
        """A totp_setup-purpose session found ineligible during submission
        gets the branded unavailable page and stays on that session (unlike
        the recovery-purpose twin, which restarts at /recover-totp — pinned
        in TestSetupTotpSubmitRecoveryPurpose.test_ineligible_account_returns_to_the_recovery_entry_point)."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=TotpEnrollmentOutcome.INELIGIBLE,
        ) as enroll:
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 403
        assert "cannot complete authenticator setup" in resp.text
        enroll.assert_awaited_once()


# ---------------------------------------------------------------------------
# Best-effort session revocation tolerates a failed delete in BOTH restart
# helpers — the totp_setup-restart half is pinned in
# test_totp_enrollment_routes.py::TestCompletedSetupSessionEscapesLoop; this
# is the recovery-restart half.
# ---------------------------------------------------------------------------


class TestRecoveryRestartToleratesRevocationFailure:
    def test_recovery_session_still_restarts_even_if_revocation_itself_raises(self, client_builder):
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.SESSION_EXPIRED,
            ),
            patch(
                "app.routes.auth.totp.delete_session",
                autospec=True,
                side_effect=RuntimeError("db unavailable"),
            ) as delete,
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/recover-totp?error=session_expired"
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)

    def test_positive_control_recovery_restart_revokes_the_session_when_it_succeeds(
        self, client_builder
    ):
        """Positive control: the same race with a healthy delete_session call
        (pinned throughout TestSetupTotpSubmitRecoveryPurpose) revokes the
        session rather than merely tolerating a failure to."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.SESSION_EXPIRED,
            ),
            _patch("delete_session") as delete,
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)


class TestRecoveryRestartSkipsRevocationWithNoDerivableSessionId:
    """The `71->80` branch: when the session id cannot be re-derived from the
    cookie at all, the recovery restart skips the revocation attempt
    entirely, exactly like the totp_setup restart does (pinned in
    test_totp_enrollment_routes.py::TestSetupTotpBestEffortRevocation)."""

    def test_skips_revocation_when_no_session_id_is_derivable_from_the_cookie(self, client_builder):
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.SESSION_EXPIRED,
            ),
            _patch("delete_session") as delete,
            patch(
                "app.routes.auth.totp.get_session_id_from_cookie",
                autospec=True,
                return_value=None,
            ),
        ):
            resp = _post_setup(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/recover-totp?error=session_expired"
        delete.assert_not_awaited()
        _assert_auth_cookies_cleared(resp)


class TestResetTotpConfirmAttemptsExhausted:
    """The confirmation step's own attempts-exhausted outcome (distinct from
    the rotation-start step's ATTEMPTS_EXHAUSTED, which restarts at login):
    too many wrong new-code guesses restarts at fresh authentication instead,
    the same destination as a missing pending secret."""

    def test_too_many_confirmation_attempts_restarts_the_flow(self, authenticated_client):
        with (
            _patch(
                "confirm_totp_rotation",
                return_value=TotpRotationOutcome.ATTEMPTS_EXHAUSTED,
            ) as confirm,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account/reset-totp"
        assert "Too many confirmation attempts" in flash.await_args.args[2]
        confirm.assert_awaited_once()
