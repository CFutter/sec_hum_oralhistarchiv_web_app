"""Email-change route authorization, capability submission, audit, and conditional cookie deletion."""

import logging
from unittest.mock import patch

from app.middleware.csrf import CSRF_COOKIE_NAME
from app.services.email_change import SelfEmailChangeRejected
from app.services.tokens import action_token_public_id
from app.services.totp import TotpDecryptionError
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

NEW_EMAIL = "new@example.org"
TOKEN = "irrelevant-opaque-token"  # validate_email_change_token is patched, so
# the raw string never gets parsed — any value works as the Form field.

AUTH_REVISION = 12


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


def _assert_cookie_deleted(response, name: str) -> None:
    """Require exactly one deletion header for the named cookie."""
    headers = _set_cookie_headers(response, name)
    assert len(headers) == 1, (name, headers)
    assert "max-age=0" in headers[0].lower(), (name, headers[0])


def _assert_cookie_untouched(response, name: str) -> None:
    """Require no Set-Cookie header for the named cookie."""
    assert _set_cookie_headers(response, name) == []


def _patch_confirm(*, token_data, confirm_result=True):
    """Patch validation and confirmation with a complete revision payload."""
    complete_token_data = {
        "auth_revision": AUTH_REVISION,
        **token_data,
    }
    return (
        patch(
            "app.routes.auth.email_change.validate_email_change_token",
            autospec=True,
            return_value=complete_token_data,
        ),
        patch(
            "app.routes.auth.email_change.confirm_email_change",
            autospec=True,
            return_value=confirm_result,
        ),
    )


def test_local_full_session_sees_the_change_email_form(authenticated_client):
    """GET renders for a local full session (authenticated_client's default
    sample user is a local account)."""
    response = authenticated_client.get("/account/change-email")
    assert response.status_code == 200
    assert 'name="new_email"' in response.text


def test_federated_session_is_refused_the_local_only_page(client_builder):
    """Check federated session is refused the local only page (HTTP 403)."""
    federated = make_sample_user(auth_method="shibboleth", federated_status="approved")
    client = client_builder(session_user=federated)
    response = client.get("/account/change-email")
    assert response.status_code == 403


def test_valid_confirmation_token_renders_the_form_without_consuming_it(guest_client):
    """Check valid confirmation token renders the form without consuming it (HTTP 200)."""
    with (
        patch(
            "app.routes.auth.email_change.validate_email_change_token", autospec=True
        ) as validate,
        patch("app.routes.auth.email_change.confirm_email_change", autospec=True) as confirm,
    ):
        response = guest_client.get(f"/account/confirm-email/{action_token_public_id(TOKEN)}")
    assert response.status_code == 200
    assert NEW_EMAIL not in response.text and TOKEN not in response.text
    assert 'name="public_id"' in response.text and 'name="token"' in response.text
    validate.assert_not_called()
    confirm.assert_not_awaited()
    guest_client.mock_pool.connection.assert_not_called()


def test_self_service_confirm_redirects_and_clears_session_cookie(authenticated_client):
    """Require the target user's confirmation to redirect to login and delete both authentication
    cookies.
    """
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p as validate, confirm_p:
        response = authenticated_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=email_changed"
    validate.assert_called_once_with(TOKEN)

    _assert_cookie_deleted(response, settings.session_cookie_name)
    _assert_cookie_deleted(response, CSRF_COOKIE_NAME)


def test_admin_confirming_own_email_change_still_clears_cookie(admin_client):
    """Require the same cookie deletion when an administrator confirms their own change."""
    token_data = {"user_id": 99, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = admin_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=email_changed"
    _assert_cookie_deleted(response, settings.session_cookie_name)
    _assert_cookie_deleted(response, CSRF_COOKIE_NAME)


def test_admin_session_confirming_other_users_token_keeps_admin_logged_in(admin_client):
    """Require another user's confirmation to leave the presenting administrator's cookies untouched."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = admin_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=email_changed"

    _assert_cookie_untouched(response, settings.session_cookie_name)
    _assert_cookie_untouched(response, CSRF_COOKIE_NAME)


def test_guest_confirm_no_session_cookie_deletion_header_at_all(guest_client):
    """Require anonymous confirmation to redirect without deleting authentication cookies."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p:
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=email_changed"

    _assert_cookie_untouched(response, settings.session_cookie_name)
    _assert_cookie_untouched(response, CSRF_COOKIE_NAME)


def test_invalid_or_expired_token_renders_error_page_before_any_service_call(guest_client):
    """Reject a failed token validation with HTTP 400 before calling confirmation."""
    with (
        patch(
            "app.routes.auth.email_change.validate_email_change_token",
            autospec=True,
            return_value=None,
        ) as validate,
        patch("app.routes.auth.email_change.confirm_email_change", autospec=True) as confirm,
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": "bad-token", "public_id": action_token_public_id("bad-token")},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "Invalid or expired link" in response.text
    validate.assert_called_once_with("bad-token")
    confirm.assert_not_awaited()
    _assert_cookie_untouched(response, settings.session_cookie_name)


def test_confirm_email_change_failure_logs_audit_event_and_renders_error(guest_client, caplog):
    """Require failed confirmation to audit email_change_failed and return HTTP 400 without deleting
    cookies.
    """
    token_data = {"user_id": 1, "new_email": NEW_EMAIL}
    validate_p, confirm_p = _patch_confirm(token_data=token_data, confirm_result=False)
    with (
        validate_p,
        confirm_p as confirm,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": "stale-token", "public_id": action_token_public_id("stale-token")},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "Could not change email" in response.text
    confirm.assert_awaited_once()
    _assert_cookie_untouched(response, settings.session_cookie_name)

    events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "email_change_failed"
    ]
    assert len(events) == 1
    assert events[0].user_id == 1


def test_admin_initiated_success_logs_admin_email_changed_not_email_changed(guest_client, caplog):
    """Audit the signed administrator as initiator without also emitting the self-service event."""
    token_data = {"user_id": 1, "new_email": NEW_EMAIL, "acting_admin_id": 99}
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with (
        validate_p,
        confirm_p,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303

    admin_events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "admin_email_changed"
    ]
    self_events = [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "email_changed"
    ]
    assert len(admin_events) == 1
    assert admin_events[0].actor_admin_id == 99
    assert admin_events[0].target_user_id == 1
    assert self_events == []


def test_confirm_forwards_signed_auth_revision(guest_client):
    """Check confirm forwards signed auth revision (HTTP 303)."""
    token_data = {
        "user_id": 1,
        "new_email": NEW_EMAIL,
        "auth_revision": 37,
    }
    validate_p, confirm_p = _patch_confirm(token_data=token_data)
    with validate_p, confirm_p as confirm:
        response = guest_client.post(
            "/account/confirm-email",
            data={"token": TOKEN, "public_id": action_token_public_id(TOKEN)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    confirm.assert_awaited_once_with(
        guest_client.mock_pool,
        1,
        NEW_EMAIL,
        TOKEN,
        expected_auth_revision=37,
    )


def test_change_email_requires_totp_in_the_form(authenticated_client):
    """Check change email requires TOTP in the form (HTTP 422)."""
    response = authenticated_client.get("/account/change-email")
    assert 'name="totp_code"' in response.text
    assert 'autocomplete="one-time-code"' in response.text
    with patch("app.routes.auth.email_change.stage_self_email_change", autospec=True) as stage:
        response = authenticated_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": "current password",
                "csrf_token": authenticated_client.csrf_token,
            },
        )
    assert response.status_code == 422
    stage.assert_not_awaited()


def test_change_email_forwards_fresh_totp_and_never_echoes_it(authenticated_client):
    """Check change email forwards fresh TOTP and never echoes it (HTTP 422)."""
    with patch(
        "app.routes.auth.email_change.stage_self_email_change",
        autospec=True,
        side_effect=SelfEmailChangeRejected("invalid_totp"),
    ) as stage:
        response = authenticated_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": "very-specific-current-password",
                "totp_code": "123456",
                "csrf_token": authenticated_client.csrf_token,
            },
        )
    assert response.status_code == 422
    assert "Enter a fresh authentication code" in response.text
    assert "123456" not in response.text and "very-specific-current-password" not in response.text
    stage.assert_awaited_once_with(
        authenticated_client.mock_pool,
        user_id=1,
        session_id=RAW_SESSION_ID,
        current_password="very-specific-current-password",
        new_email=NEW_EMAIL,
        totp_code="123456",
    )


def test_change_email_authenticator_storage_failure_returns_support_guidance(authenticated_client):
    """Check change email authenticator storage failure returns support guidance (HTTP 503)."""
    with patch(
        "app.routes.auth.email_change.stage_self_email_change",
        autospec=True,
        side_effect=TotpDecryptionError(1),
    ):
        response = authenticated_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": "very-specific-current-password",
                "totp_code": "123456",
                "csrf_token": authenticated_client.csrf_token,
            },
        )
    assert response.status_code == 503
    assert "authenticator is temporarily unavailable" in response.text
    assert "123456" not in response.text and "very-specific-current-password" not in response.text
