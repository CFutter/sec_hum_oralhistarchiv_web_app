"""Mailbox-protected sign-in keeps CSRF, content and capability checks."""

from unittest.mock import patch

import pytest

from app.services.password_reset import InvalidResetToken, InvalidResetTotp, generate_reset_token
from app.services.tokens import action_token_public_id
from config import settings


def _form(client):
    """Build a signed password-reset form with a TOTP code and current CSRF token."""
    token = generate_reset_token(7, "owner@example.org")
    return {
        "public_id": action_token_public_id(token),
        "token": token,
        "totp_code": "123456",
        "csrf_token": client.csrf_token,
    }


def test_mailbox_unlock_sets_new_cookie_after_service_commit(guest_client):
    """Check mailbox unlock sets new cookie after service commit (HTTP 303)."""
    form = _form(guest_client)
    with patch(
        "app.routes.auth.password_reset.unlock_account_with_token",
        autospec=True,
        return_value="fresh-full-session-token",
    ) as unlock:
        response = guest_client.post("/unlock-account", data=form, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/account"
    unlock.assert_awaited_once_with(
        guest_client.mock_pool,
        7,
        form["token"],
        expected_email="owner@example.org",
        totp_code="123456",
        ip_address="testclient",
    )
    assert any(
        value.startswith(f"{settings.session_cookie_name}=")
        for value in response.headers.get_list("set-cookie")
    )


@pytest.mark.parametrize("failure", [InvalidResetToken("invalid"), InvalidResetTotp("invalid")])
def test_rejected_mailbox_proof_does_not_create_a_browser_session(guest_client, failure):
    """Check rejected mailbox proof does not create a browser session (HTTP 422)."""
    with patch(
        "app.routes.auth.password_reset.unlock_account_with_token",
        autospec=True,
        side_effect=failure,
    ):
        response = guest_client.post("/unlock-account", data=_form(guest_client))
    assert response.status_code == 422
    assert not any(
        value.startswith(f"{settings.session_cookie_name}=")
        for value in response.headers.get_list("set-cookie")
    )


@pytest.mark.parametrize("case", ["csrf", "json", "public-id", "token"])
def test_invalid_unlock_requests_stop_before_proof_work(guest_client, case):
    """Check invalid unlock requests stop before proof work."""
    form = _form(guest_client)
    kwargs = {"data": form}
    expected = 422
    if case == "csrf":
        form.pop("csrf_token")
        expected = 403
    elif case == "json":
        kwargs = {"json": form}
        expected = 415
    elif case == "public-id":
        form["public_id"] = "invalid"
    else:
        form["token"] = "invalid"
    with patch("app.routes.auth.password_reset.unlock_account_with_token", autospec=True) as unlock:
        response = guest_client.post("/unlock-account", **kwargs)
    assert response.status_code == expected
    unlock.assert_not_awaited()
