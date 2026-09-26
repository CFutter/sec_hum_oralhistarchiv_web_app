"""Administrator TOTP-recovery confirmation page and invitation cancellation.

`GET /admin/users/{user_id}/totp-recovery` shows the destructive recovery
confirmation without changing any state; `POST
/admin/users/{user_id}/cancel-admin-promotion` withdraws an unaccepted
administrator invitation. Both are `RouteAccess.ADMIN`: `require_admin`
cloaks the entire `/admin/...` surface behind 404 for anyone who isn't an
authenticated administrator, guest or not. This is the sibling scenario
class to test_admin_membership_routes.py's mutation routes, split into its
own module (that file is near the 800-line cap) and named for the TOTP
recovery / promotion-cancellation surface it proves.
"""

from unittest.mock import patch

from app.services.totp_recover import TotpRecoveryTarget
from tests.fixtures import RAW_SESSION_ID, make_sample_user

TARGET = TotpRecoveryTarget(
    user_id=7,
    email="target@uzh.ch",
    display_name="Target User",
    auth_method="local",
    is_active=True,
    email_verified=True,
    totp_configured=True,
    recovery_required=False,
    recovery_codes_available=True,
    recovery_authorization_active=False,
    recovery_expires_at=None,
)


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


# ---------------------------------------------------------------------------
# GET /admin/users/{user_id}/totp-recovery
# ---------------------------------------------------------------------------


class TestAdminTotpRecoveryPageAccess:
    def test_guest_gets_404_not_a_login_redirect(self, guest_client):
        """require_admin cloaks the admin surface: a guest sees 404, never a
        redirect that would confirm the path exists."""
        with _patch("get_totp_recovery_target") as lookup:
            response = guest_client.get("/admin/users/7/totp-recovery")

        assert response.status_code == 404
        lookup.assert_not_awaited()

    def test_non_admin_full_session_gets_404(self, authenticated_client):
        with _patch("get_totp_recovery_target") as lookup:
            response = authenticated_client.get("/admin/users/7/totp-recovery")

        assert response.status_code == 404
        lookup.assert_not_awaited()

    def test_admin_sees_the_confirmation_form_without_changing_any_state(self, admin_client):
        with _patch("get_totp_recovery_target", return_value=TARGET) as lookup:
            response = admin_client.get("/admin/users/7/totp-recovery")

        assert response.status_code == 200
        assert TARGET.email in response.text
        lookup.assert_awaited_once_with(admin_client.mock_pool, 7)


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/cancel-admin-promotion
# ---------------------------------------------------------------------------


class TestAdminCancelPromotionAccess:
    def _post(self, client, **extra):
        data = {"page": "1", "page_size": "25", "csrf_token": client.csrf_token, **extra}
        return client.post(
            "/admin/users/7/cancel-admin-promotion", data=data, follow_redirects=False
        )

    def test_guest_gets_404_not_a_login_redirect(self, guest_client):
        with _patch("cancel_admin_promotion") as cancel:
            response = guest_client.post(
                "/admin/users/7/cancel-admin-promotion",
                data={"page": "1", "page_size": "25"},
                follow_redirects=False,
            )

        assert response.status_code == 404
        cancel.assert_not_awaited()

    def test_non_admin_full_session_gets_404(self, authenticated_client):
        with _patch("cancel_admin_promotion") as cancel:
            response = self._post(authenticated_client)

        assert response.status_code == 404
        cancel.assert_not_awaited()

    def test_admin_cancellation_calls_the_service_exactly_once_and_redirects(self, admin_client):
        with (
            _patch("cancel_admin_promotion", return_value=True) as cancel,
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists"),
        ):
            response = self._post(admin_client)

        assert response.status_code == 303
        assert response.headers["location"].startswith("/admin")
        cancel.assert_awaited_once_with(
            admin_client.mock_pool,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
            target_user_id=7,
        )
        audit.assert_called_once()

    def test_no_pending_invitation_still_redirects_without_auditing(self, admin_client):
        """Positive-control pair: nothing to cancel is a normal (not error)
        outcome — no admin_promotion_cancelled audit event fires."""
        with (
            _patch("cancel_admin_promotion", return_value=False),
            _patch("audit_admin_action") as audit,
            _patch("set_flash_if_exists"),
        ):
            response = self._post(admin_client)

        assert response.status_code == 303
        audit.assert_not_called()


def test_admin_client_is_a_local_admin_with_recovery_codes_available():
    """Sanity check on the fixture assumption every test above relies on:
    admin_client (conftest.py) must clear require_admin's own local-admin
    recovery-code gate, or every request above would 403 instead of
    reaching the routes under test."""
    admin = make_sample_user(is_admin=True, id=99)
    assert admin.totp_recovery_code_generation > 0
    assert admin.totp_recovery_codes_available is True
