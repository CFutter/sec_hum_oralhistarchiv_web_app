"""Contract tests for TOTP route refusals."""

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
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.totp.{name}", autospec=True, **kw)


def _assert_auth_cookies_cleared(response):
    """Require deletion headers for the authentication cookies."""
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )


def _post_setup(client, totp_code="123456", recovery_code_confirmation=RECOVERY_CODE, **extra):
    """Submit the valid CSRF-protected form without following redirects."""
    data = {
        "totp_code": totp_code,
        "recovery_code_confirmation": recovery_code_confirmation,
        "csrf_token": client.csrf_token,
        **extra,
    }
    return client.post("/setup-totp", data=data, follow_redirects=False)


def _recovery_client(client_builder, **user_overrides):
    """Build a recovery-only client for a user with no configured authenticator."""
    user = make_sample_user(totp_configured=False, totp_recovery_required=True, **user_overrides)
    return client_builder(session_user=user, session_purpose="totp_recovery")


def _post_reset_confirm(client, new_totp_code="222222"):
    """Submit the replacement TOTP code with CSRF without following redirects."""
    return client.post(
        "/account/reset-totp/confirm",
        data={"new_totp_code": new_totp_code, "csrf_token": client.csrf_token},
        follow_redirects=False,
    )


class TestSetupTotpPageSessionExpiredNonRecovery:
    """Cover setup TOTP page session expired non recovery."""

    def test_expired_totp_setup_session_restarts_at_a_fresh_login(self, totp_setup_client):
        """Check expired TOTP setup session restarts at a fresh login (HTTP 303)."""
        with (
            _patch(
                "get_or_create_pending_totp_secret",
                return_value=PendingTotpResult(PendingTotpOutcome.SESSION_EXPIRED),
            ) as pending,
            _patch("delete_session") as delete,
        ):
            resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=session_expired"
        pending.assert_awaited_once_with(
            totp_setup_client.mock_pool,
            1,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=RAW_SESSION_ID,
        )
        delete.assert_awaited_once_with(totp_setup_client.mock_pool, RAW_SESSION_ID)
        _assert_auth_cookies_cleared(resp)


class TestSetupTotpSubmitIneligibleNonRecovery:
    """Cover setup TOTP submit ineligible non recovery."""

    def test_ineligible_account_gets_the_branded_unavailable_page(self, totp_setup_client):
        """Check ineligible account gets the branded unavailable page (HTTP 403)."""
        with _patch(
            "verify_and_enroll_totp",
            return_value=TotpEnrollmentOutcome.INELIGIBLE,
        ) as enroll:
            resp = _post_setup(totp_setup_client)

        assert resp.status_code == 403
        assert "cannot complete authenticator setup" in resp.text
        enroll.assert_awaited_once()


class TestRecoveryRestartToleratesRevocationFailure:
    """Cover recovery restart tolerates revocation failure."""

    def test_recovery_session_still_restarts_even_if_revocation_itself_raises(self, client_builder):
        """Check recovery session still restarts even if revocation itself raises (HTTP 303)."""
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
        """Check positive control recovery restart revokes the session when it succeeds (HTTP 303)."""
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
    """Cover recovery restart skips revocation with no derivable session ID."""

    def test_skips_revocation_when_no_session_id_was_resolved(self, client_builder):
        """Check skips revocation when no session ID was resolved (HTTP 303)."""
        client = _recovery_client(client_builder)
        with (
            _patch(
                "verify_and_enroll_totp",
                return_value=TotpEnrollmentOutcome.SESSION_EXPIRED,
            ),
            _patch("delete_session") as delete,
            patch(
                "app.routes.auth.totp.get_resolved_session_id",
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
    """Cover reset TOTP confirm attempts exhausted."""

    def test_too_many_confirmation_attempts_restarts_the_flow(self, authenticated_client):
        """Check too many confirmation attempts restarts the flow (HTTP 303)."""
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
