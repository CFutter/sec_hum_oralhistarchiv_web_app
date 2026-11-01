"""Domain refusals remain useful; unexpected service ValueErrors remain server faults."""

import logging
from unittest.mock import create_autospec, patch

import pytest

from app.routes.auth import account, admin, password_reset, register, verify_email
from app.service_errors import UserInputRejected, UserNotFound
from app.services.password_reset import generate_reset_token
from app.services.registration_setup import RegistrationSetup
from app.services.tokens import action_token_public_id

_INTERNAL_DETAIL = "unexpected internal conversion failure"


@pytest.mark.parametrize(
    ("path", "service", "form"),
    [
        (
            "/admin/users/7/approve-federated",
            "approve_federated_user",
            {
                "expected_issuer": "https://idp.example.org",
                "expected_subject_id": "subject-7",
                "expected_review_revision": "1",
                "access_tier": "public",
            },
        ),
        ("/admin/users/7/set-active", "set_user_active", {"is_active": "false"}),
        ("/admin/users/7/set-tier", "update_access_tier", {"access_tier": "registered"}),
        ("/admin/users/7/set-admin", "set_user_admin", {"is_admin": "false"}),
    ],
)
def test_unexpected_admin_value_error_is_not_reported_as_missing_user(
    admin_client, caplog, path, service, form
):
    """Check unexpected admin value error is not reported as missing user (HTTP 500)."""
    failure = create_autospec(getattr(admin, service), side_effect=ValueError(_INTERNAL_DETAIL))
    flash = create_autospec(admin.set_flash_if_exists)
    with (
        patch.object(admin, service, failure),
        patch.object(admin, "set_flash_if_exists", flash),
        caplog.at_level(logging.ERROR, logger="app.main"),
    ):
        response = admin_client.post(
            path, data={**form, "csrf_token": admin_client.csrf_token}, follow_redirects=False
        )
    assert response.status_code == 500
    assert "Internal Server Error" in response.text
    assert _INTERNAL_DETAIL not in response.text
    flash.assert_not_awaited()
    assert any(record.getMessage() == "Unhandled exception" for record in caplog.records)


@pytest.mark.parametrize(
    ("error", "expected_message"),
    [
        (UserInputRejected("Display name cannot be empty."), "Display name cannot be empty."),
        (UserNotFound("User 7 not found"), "User not found."),
    ],
)
def test_name_edit_maps_only_declared_refusals(authenticated_client, error, expected_message):
    """Check name edit maps only declared refusals (HTTP 303)."""
    with (
        patch.object(
            account,
            "update_display_name",
            create_autospec(account.update_display_name, side_effect=error),
        ),
        patch.object(
            account, "set_flash_if_exists", create_autospec(account.set_flash_if_exists)
        ) as flash,
    ):
        response = authenticated_client.post(
            "/account/change-name",
            data={"display_name": "Name", "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert flash.await_args.args[2] == expected_message


@pytest.mark.parametrize(
    "flow", ["name", "registration", "resend", "setup", "reset_request", "reset"]
)
def test_unexpected_validation_error_is_logged_without_rendering_its_message(request, caplog, flow):
    """Check unexpected validation error is logged without rendering its message (HTTP 500)."""
    client = request.getfixturevalue("authenticated_client" if flow == "name" else "guest_client")
    token = generate_reset_token(7, "owner@example.org")
    cases = {
        "name": (account, "update_display_name", "/account/change-name", {"display_name": "Name"}),
        "registration": (
            register,
            "begin_local_registration",
            "/register",
            {"email": "owner@example.org"},
        ),
        "resend": (
            register,
            "resend_local_registration",
            "/send_verification",
            {"email": "owner@example.org"},
        ),
        "setup": (
            verify_email,
            "complete_local_registration",
            "/verify-email",
            {
                "token": token,
                "public_id": action_token_public_id(token),
                "display_name": "Owner",
                "password": "ChosenPassword!739",
                "password_confirm": "ChosenPassword!739",
            },
        ),
        "reset_request": (
            password_reset,
            "request_password_reset",
            "/forgot-password",
            {"email": "owner@example.org"},
        ),
        "reset": (
            password_reset,
            "update_password_with_token",
            "/reset-password",
            {
                "token": token,
                "public_id": action_token_public_id(token),
                "password": "ChosenPassword!739",
                "password_confirm": "ChosenPassword!739",
                "totp_code": "123456",
            },
        ),
    }
    module, service, path, form = cases[flow]
    failure = create_autospec(getattr(module, service), side_effect=ValueError(_INTERNAL_DETAIL))
    with (
        patch.object(module, service, failure),
        patch.object(
            verify_email,
            "inspect_local_registration",
            create_autospec(
                verify_email.inspect_local_registration,
                return_value=RegistrationSetup(7, "owner@example.org"),
            ),
        ),
        caplog.at_level(logging.ERROR, logger="app.main"),
    ):
        response = client.post(
            path, data={**form, "csrf_token": client.csrf_token}, follow_redirects=False
        )
    assert response.status_code == 500
    assert _INTERNAL_DETAIL not in response.text
    assert "Internal Server Error" in response.text
    failure.assert_awaited_once()
    assert any(record.getMessage() == "Unhandled exception" for record in caplog.records)
