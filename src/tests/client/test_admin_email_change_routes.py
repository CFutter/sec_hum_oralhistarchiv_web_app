"""Administrator-initiated email change actions at the client tier."""

from unittest.mock import patch

from app.services.email_change import AdminEmailChangeRejected, AdminEmailChangeResult
from tests.fixtures import RAW_SESSION_ID


def _patch(name, **kw):
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


class TestAdminChangeEmail:
    """The admin-driven email change route delegates the resolved actor
    identity, and enforces the same account-state policy as the service."""

    def test_admin_email_change_delegates_resolved_authority(self, admin_client):
        """Check admin email change delegates resolved authority (HTTP 303)."""
        result = AdminEmailChangeResult(
            target_user_id=7,
            old_email="old@example.org",
            new_email="new@example.org",
        )
        with (
            _patch("stage_admin_email_change", return_value=result) as stage,
            _patch("set_flash_if_exists"),
            _patch("audit_admin_action"),
        ):
            response = admin_client.post(
                "/admin/users/7/change-email",
                data={"new_email": "new@example.org", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        stage.assert_awaited_once_with(
            admin_client.mock_pool,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
            target_user_id=7,
            new_email="new@example.org",
        )

    def test_admin_cannot_stage_email_for_inactive_account(self, admin_client):
        """Check admin cannot stage email for inactive account (HTTP 303)."""
        with (
            _patch(
                "stage_admin_email_change",
                side_effect=AdminEmailChangeRejected("inactive_account"),
            ) as stage,
            _patch("set_flash_if_exists") as flash,
            _patch("audit_admin_action") as audit,
        ):
            response = admin_client.post(
                "/admin/users/7/change-email",
                data={
                    "new_email": "new@example.org",
                    "csrf_token": admin_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        stage.assert_awaited_once()
        assert flash.await_args.args[2:] == (
            "Activate the account before changing its email.",
            "error",
        )
        audit.assert_not_called()


def test_admin_own_email_change_directs_to_protected_account_form(admin_client):
    """Check admin own email change directs to protected account form (HTTP 303)."""
    with (
        _patch("stage_admin_email_change", side_effect=AdminEmailChangeRejected("self_change")),
        _patch("set_flash_if_exists") as flash,
        _patch("audit_admin_action") as audit,
    ):
        response = admin_client.post(
            "/admin/users/99/change-email",
            data={"new_email": "new@example.org", "csrf_token": admin_client.csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert flash.await_args.args[2:] == (
        "Use Change Email on your account page to change your own email.",
        "error",
    )
    audit.assert_not_called()
