"""Login success messages are fixed, separate from errors, and display-only."""

from unittest.mock import patch

import pytest
from lxml import html

from app.services.authentication import PasswordCheck


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (
            "totp_setup_completed",
            "Authenticator setup is complete. Wait for a fresh code, then sign in again.",
        ),
        (
            "totp_recovery_completed",
            "Your replacement authenticator is configured. Please sign in again.",
        ),
        ("admin_promotion_completed", "Administrator setup is complete. Please sign in again."),
        ("email_changed", "Your email was changed. Please log in with your new address."),
        (
            "totp_changed",
            "Your authenticator was changed. Wait for its next code, then sign in again.",
        ),
    ],
)
def test_completed_action_renders_a_fixed_success_notice(guest_client, code, message):
    """Check completed action renders a fixed success notice (HTTP 200)."""
    response = guest_client.get("/login", params={"notice": code})

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    document = html.fromstring(response.text)
    notices = document.xpath('//div[@class="auth-success"]')
    assert len(notices) == 1
    assert notices[0].get("role") == "status"
    assert notices[0].text_content().strip() == message
    assert not document.xpath('//div[@class="auth-error"]')


@pytest.mark.parametrize("code", ["", "unknown", "<script>alert(1)</script>"])
def test_unknown_notice_is_not_reflected(guest_client, code):
    """Check unknown notice is not reflected (HTTP 200)."""
    response = guest_client.get("/login", params={"notice": code})

    assert response.status_code == 200
    document = html.fromstring(response.text)
    assert not document.xpath('//div[@class="auth-success"]')
    assert not document.xpath('//div[@class="auth-error"]')
    assert "alert(1)" not in response.text


def test_recognized_error_takes_precedence_over_success(guest_client):
    """Check recognized error takes precedence over success (HTTP 200)."""
    response = guest_client.get(
        "/login",
        params={"error": "session_expired", "notice": "totp_setup_completed"},
    )

    assert response.status_code == 200
    document = html.fromstring(response.text)
    errors = document.xpath('//div[@class="auth-error"]')
    assert len(errors) == 1
    assert errors[0].get("role") == "alert"
    assert errors[0].text_content().strip() == "Your session has expired. Please sign in again."
    assert not document.xpath('//div[@class="auth-success"]')


def test_failed_login_cannot_display_query_supplied_success(guest_client):
    """Check failed login cannot display query supplied success (HTTP 401)."""
    with patch(
        "app.routes.auth.login.verify_password",
        autospec=True,
        return_value=PasswordCheck(
            user=None,
            password_ok=False,
            locked_until=None,
            failure_reason="unknown_user",
            auth_revision=None,
        ),
    ):
        response = guest_client.post(
            "/login?notice=totp_setup_completed&email_changed=1&totp_changed=1",
            data={
                "email": "reader@example.org",
                "password": "incorrect-password",
                "csrf_token": guest_client.csrf_token,
            },
        )

    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    document = html.fromstring(response.text)
    assert document.xpath('//div[@class="auth-error" and @role="alert"]')
    assert not document.xpath('//div[@class="auth-success"]')
