"""Administrator-initiated email change actions at the client tier.

`POST /admin/users/{id}/change-email` lets an administrator stage an email
change for another account, delegating to the same staging service and
confirm route as the self-service flow, but authorized by admin session
rather than the current password. These tests need no database: the
staging service is mocked, only the route's delegation and flash/audit
behaviour is under test.
"""

from unittest.mock import patch

from app.services.email_change import AdminEmailChangeRejected, AdminEmailChangeResult
from tests.fixtures import RAW_SESSION_ID


def _patch(name, **kw):
    return patch(f"app.routes.auth.admin.{name}", autospec=True, **kw)


class TestAdminChangeEmail:
    """The admin-driven email change route delegates the resolved actor
    identity, and enforces the same account-state policy as the service."""

    def test_admin_email_change_delegates_resolved_authority(self, admin_client):
        result = AdminEmailChangeResult(
            target_user_id=7,
            old_email="old@uzh.ch",
            new_email="new@uzh.ch",
        )
        with (
            _patch("stage_admin_email_change", return_value=result) as stage,
            _patch("set_flash_if_exists"),
            _patch("audit_admin_action"),
        ):
            response = admin_client.post(
                "/admin/users/7/change-email",
                data={"new_email": "new@uzh.ch", "csrf_token": admin_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        stage.assert_awaited_once_with(
            admin_client.mock_pool,
            actor_id=99,
            actor_session_id=RAW_SESSION_ID,
            target_user_id=7,
            new_email="new@uzh.ch",
        )

    def test_admin_cannot_stage_email_for_inactive_account(self, admin_client):
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
                    "new_email": "new@uzh.ch",
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
