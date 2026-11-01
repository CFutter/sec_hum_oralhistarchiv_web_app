"""Password capacity failures cross real route and middleware boundaries as 503s."""

from contextlib import ExitStack
from unittest.mock import patch

import httpx
import pytest

from app.services.password_work import PasswordWorkAdmissionTimeout
from app.services.registration_setup import RegistrationSetup
from app.services.tokens import action_token_public_id
from config import settings

_PASSWORD = "Unprinted-password-marker-08!"
_TOKEN = "unprinted-mailbox-capability-marker"
_PUBLIC_ID = action_token_public_id(_TOKEN)


def _assert_capacity_response(
    response: httpx.Response, caplog: pytest.LogCaptureFixture, path: str
) -> None:
    """Require a private, correlated 503 response and one admission-timeout event."""
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in response.headers
    assert "X-Request-ID" in response.headers
    assert "Service temporarily busy" in response.text
    assert _PASSWORD not in response.text and _TOKEN not in response.text
    assert _PASSWORD not in str(caplog.record_tuples) and _TOKEN not in str(caplog.record_tuples)
    events = [
        record
        for record in caplog.records
        if getattr(record, "event_type", None) == "password_work_admission_timeout"
    ]
    assert len(events) == 1
    assert getattr(events[0], "request_id", None) == response.headers["X-Request-ID"]
    assert getattr(events[0], "path", None) == path
    assert getattr(events[0], "timeout_seconds", None) == 0.1
    assert events[0].exc_info is None


@pytest.mark.parametrize(
    ("module", "service", "path", "form"),
    [
        (
            "login",
            "verify_password",
            "/login",
            {"email": "alice@example.org", "password": _PASSWORD},
        ),
        (
            "totp_recover",
            "redeem_totp_recovery",
            "/recover-totp",
            {
                "email": "alice@example.org",
                "password": _PASSWORD,
                "recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD",
            },
        ),
        (
            "password_reset",
            "update_password_with_token",
            "/reset-password",
            {
                "token": _TOKEN,
                "public_id": _PUBLIC_ID,
                "password": _PASSWORD,
                "password_confirm": _PASSWORD,
                "totp_code": "123456",
            },
        ),
        (
            "verify_email",
            "complete_local_registration",
            "/verify-email",
            {
                "token": _TOKEN,
                "public_id": _PUBLIC_ID,
                "display_name": "Alice",
                "password": _PASSWORD,
                "password_confirm": _PASSWORD,
            },
        ),
    ],
)
def test_public_password_routes_return_capacity_responses(
    guest_client, caplog, module: str, service: str, path: str, form: dict[str, str]
) -> None:
    """Check public password routes return capacity responses."""
    with ExitStack() as stack:
        if module == "password_reset":
            stack.enter_context(
                patch(
                    "app.routes.auth.password_reset.validate_reset_token",
                    autospec=True,
                    return_value={"user_id": 1, "email": "alice@example.org"},
                )
            )
        elif module == "verify_email":
            stack.enter_context(
                patch(
                    "app.routes.auth.verify_email.inspect_local_registration",
                    autospec=True,
                    return_value=RegistrationSetup(1, "alice@example.org"),
                )
            )
        work = stack.enter_context(
            patch(
                f"app.routes.auth.{module}.{service}",
                autospec=True,
                side_effect=PasswordWorkAdmissionTimeout(0.1),
            )
        )
        response = guest_client.post(
            path, data={**form, "csrf_token": guest_client.csrf_token}, follow_redirects=False
        )
    work.assert_awaited_once()
    _assert_capacity_response(response, caplog, path)
    if module in {"password_reset", "verify_email"}:
        assert response.headers["Referrer-Policy"] == "strict-origin"


@pytest.mark.parametrize(
    ("module", "service", "path", "form"),
    [
        (
            "email_change",
            "stage_self_email_change",
            "/account/change-email",
            {
                "new_email": "alice.new@example.org",
                "current_password": _PASSWORD,
                "totp_code": "111111",
            },
        ),
        (
            "totp",
            "begin_totp_rotation",
            "/account/reset-totp",
            {"current_password": _PASSWORD, "current_totp_code": "111111"},
        ),
        (
            "admin_promotion",
            "prepare_admin_promotion",
            "/account/admin-promotion/prepare",
            {"current_password": _PASSWORD, "totp_code": "111111"},
        ),
        (
            "account_deletion",
            "delete_own_account",
            "/account/delete",
            {"password": _PASSWORD, "totp_code": "111111", "confirm": "delete"},
        ),
    ],
)
def test_authenticated_password_routes_preserve_sessions_on_capacity_failure(
    authenticated_client, caplog, module: str, service: str, path: str, form: dict[str, str]
) -> None:
    """Check authenticated password routes preserve sessions on capacity failure."""
    with patch(
        f"app.routes.auth.{module}.{service}",
        autospec=True,
        side_effect=PasswordWorkAdmissionTimeout(0.1),
    ) as work:
        response = authenticated_client.post(
            path,
            data={**form, "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )
    work.assert_awaited_once()
    _assert_capacity_response(response, caplog, path)
    assert authenticated_client.cookies.get(settings.session_cookie_name) is not None
    assert not any(
        cookie.startswith(f"{settings.session_cookie_name}=") and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )


def test_unrelated_worker_timeout_remains_an_internal_error(guest_client) -> None:
    """Check unrelated worker timeout remains an internal error (HTTP 500)."""
    marker = "synthetic execution timeout"
    with patch(
        "app.routes.auth.login.verify_password", autospec=True, side_effect=TimeoutError(marker)
    ):
        response = guest_client.post(
            "/login",
            data={
                "email": "alice@example.org",
                "password": _PASSWORD,
                "csrf_token": guest_client.csrf_token,
            },
            follow_redirects=False,
        )
    assert response.status_code == 500
    assert "Retry-After" not in response.headers
    assert marker not in response.text
