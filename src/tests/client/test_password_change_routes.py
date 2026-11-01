"""Authenticated password changes keep real route, form and cookie boundaries."""

import logging
from unittest.mock import patch

import pytest

from app.middleware.csrf import CSRF_COOKIE_NAME
from app.services.password_change import PasswordChangeRejected
from app.services.password_work import PasswordWorkAdmissionTimeout
from app.services.totp import TotpDecryptionError
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

_CURRENT_PASSWORD = "CURRENT-PASSWORD-MUST-NOT-LEAK"
_NEW_PASSWORD = "NEW-PASSWORD-MUST-NOT-LEAK"
_CODE = "123456"
_PATH = "/account/change-password"


def _patch(name, **kwargs):
    """Patch the route collaborator with its real signature."""
    return patch(f"app.routes.auth.password_change.{name}", autospec=True, **kwargs)


def _data(client, **overrides):
    """Build the valid form with caller overrides and the current CSRF token."""
    return {
        "current_password": _CURRENT_PASSWORD,
        "new_password": _NEW_PASSWORD,
        "password_confirm": _NEW_PASSWORD,
        "totp_code": _CODE,
        "csrf_token": client.csrf_token,
        **overrides,
    }


def _assert_deleted_cookie(response, name):
    """Require exactly one deletion header for the named cookie."""
    cookies = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]
    assert len(cookies) == 1
    assert "max-age=0" in cookies[0].lower()


def _assert_no_credentials(response):
    """Require response text to omit both passwords and the submitted TOTP value."""
    assert _CURRENT_PASSWORD not in response.text
    assert _NEW_PASSWORD not in response.text
    assert f'value="{_CODE}"' not in response.text


def test_account_page_links_to_password_change_for_local_users(authenticated_client):
    """Check account page links to password change for local users (HTTP 200)."""
    response = authenticated_client.get("/account")
    assert response.status_code == 200
    assert f'href="{_PATH}"' in response.text


def test_federated_account_page_explains_institutional_password_management(client_builder):
    """Check federated account page explains institutional password management (HTTP 200)."""
    client = client_builder(session_user=make_sample_user(auth_method="shibboleth"))
    response = client.get("/account")
    assert response.status_code == 200
    assert f'href="{_PATH}"' not in response.text
    assert "Your password is managed by your institution" in response.text


def test_change_form_is_read_only_and_does_not_cache_credentials(authenticated_client):
    """Check change form is read only and does not cache credentials (HTTP 200)."""
    with _patch("change_password") as change:
        response = authenticated_client.get(_PATH)
    assert response.status_code == 200
    assert f'action="{_PATH}"' in response.text
    for field in ("current_password", "new_password", "password_confirm", "totp_code"):
        assert f'name="{field}"' in response.text
    assert 'autocomplete="current-password"' in response.text
    assert 'autocomplete="new-password"' in response.text
    assert 'autocomplete="one-time-code"' in response.text
    assert response.headers["cache-control"] == "no-store"
    change.assert_not_awaited()


def test_success_uses_resolved_identity_revokes_browser_and_audits_once(
    authenticated_client, caplog
):
    """Check success uses resolved identity revokes browser and audits once (HTTP 303)."""
    with (
        _patch("change_password", return_value=None) as change,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=password_changed"
    change.assert_awaited_once_with(
        authenticated_client.mock_pool,
        user_id=1,
        session_id=RAW_SESSION_ID,
        current_password=_CURRENT_PASSWORD,
        new_password=_NEW_PASSWORD,
        totp_code=_CODE,
    )
    _assert_deleted_cookie(response, settings.session_cookie_name)
    _assert_deleted_cookie(response, CSRF_COOKIE_NAME)
    events = [r for r in caplog.records if getattr(r, "event_type", None) == "password_changed"]
    assert len(events) == 1
    assert events[0].user_id == 1
    for secret in (_CURRENT_PASSWORD, _NEW_PASSWORD, _CODE):
        assert secret not in repr(events[0].__dict__)


def test_password_confirmation_is_checked_before_credential_work(authenticated_client):
    """Check password confirmation is checked before credential work (HTTP 422)."""
    with _patch("change_password") as change:
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client, password_confirm="different")
        )
    assert response.status_code == 422
    change.assert_not_awaited()
    _assert_no_credentials(response)


@pytest.mark.parametrize("method", ["get", "post"])
def test_federated_accounts_cannot_use_local_password_change(client_builder, method):
    """Check federated accounts cannot use local password change (HTTP 403)."""
    client = client_builder(session_user=make_sample_user(auth_method="shibboleth"))
    with _patch("change_password") as change:
        response = client.get(_PATH) if method == "get" else client.post(_PATH, data=_data(client))
    assert response.status_code == 403
    change.assert_not_awaited()


@pytest.mark.parametrize("method", ["get", "post"])
def test_setup_sessions_cannot_change_passwords(totp_setup_client, method):
    """Check setup sessions cannot change passwords (HTTP 303)."""
    with _patch("change_password") as change:
        response = (
            totp_setup_client.get(_PATH, follow_redirects=False)
            if method == "get"
            else totp_setup_client.post(
                _PATH, data=_data(totp_setup_client), follow_redirects=False
            )
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/setup-totp"
    change.assert_not_awaited()


@pytest.mark.parametrize("method", ["get", "post"])
def test_guests_are_sent_to_login(guest_client, method):
    """Check guests are sent to login (HTTP 303)."""
    with _patch("change_password") as change:
        response = (
            guest_client.get(_PATH, follow_redirects=False)
            if method == "get"
            else guest_client.post(_PATH, data=_data(guest_client), follow_redirects=False)
        )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
    change.assert_not_awaited()


def test_csrf_is_required_before_password_change(authenticated_client):
    """Check CSRF is required before password change (HTTP 403)."""
    with _patch("change_password") as change:
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client, csrf_token="forged")
        )
    assert response.status_code == 403
    change.assert_not_awaited()


def test_non_form_input_is_rejected_before_password_change(authenticated_client):
    """Check non form input is rejected before password change (HTTP 415)."""
    with _patch("change_password") as change:
        response = authenticated_client.post(_PATH, json=_data(authenticated_client))
    assert response.status_code == 415
    change.assert_not_awaited()


@pytest.mark.parametrize(
    "field", ["current_password", "new_password", "password_confirm", "totp_code"]
)
def test_oversized_fields_are_rejected_before_work(authenticated_client, field):
    """Check oversized fields are rejected before work (HTTP 422)."""
    with _patch("change_password") as change:
        response = authenticated_client.post(
            _PATH,
            data=_data(
                authenticated_client, **{field: "x" * (17 if field == "totp_code" else 201)}
            ),
        )
    assert response.status_code == 422
    change.assert_not_awaited()


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("invalid_session", 303),
        ("step_up_exhausted", 303),
        ("account_locked", 423),
        ("ineligible_account", 422),
        ("invalid_password", 422),
        ("invalid_totp", 422),
        ("retry_required", 409),
        ("password_reused", 422),
        ("password_policy", 422),
    ],
)
def test_rejections_do_not_audit_success_or_reflect_credentials(
    authenticated_client, reason, status
):
    """Check rejections do not audit success or reflect credentials."""
    rejection = PasswordChangeRejected(
        reason, password_error="Choose a longer password." if reason == "password_policy" else None
    )
    with _patch("change_password", side_effect=rejection), _patch("audit_user_event") as audit:
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == status
    audit.assert_not_called()
    _assert_no_credentials(response)
    if reason in {"invalid_session", "step_up_exhausted"}:
        assert response.headers["location"] == "/login?error=session_expired"
        _assert_deleted_cookie(response, settings.session_cookie_name)
    if reason == "password_policy":
        assert "Choose a longer password." in response.text


def test_undecryptable_factor_fails_closed(authenticated_client):
    """Check undecryptable factor fails closed (HTTP 503)."""
    with (
        _patch("change_password", side_effect=TotpDecryptionError(1)),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == 503
    audit.assert_not_called()
    _assert_no_credentials(response)


def test_admission_failure_uses_shared_retry_response(authenticated_client):
    """Check admission failure uses shared retry response (HTTP 503)."""
    with (
        _patch("change_password", side_effect=PasswordWorkAdmissionTimeout(0.1)),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    audit.assert_not_called()
    _assert_no_credentials(response)


def test_storage_failure_does_not_claim_success(authenticated_client):
    """Check storage failure does not claim success (HTTP 500)."""
    with (
        _patch("change_password", side_effect=RuntimeError("storage unavailable")),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            _PATH, data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == 500
    audit.assert_not_called()
    _assert_no_credentials(response)


def test_password_change_has_a_route_specific_proof_rate_limit(authenticated_client):
    """Check password change has a route specific proof rate limit."""
    with _patch(
        "change_password", side_effect=PasswordChangeRejected("invalid_password")
    ) as change:
        responses = [
            authenticated_client.post(_PATH, data=_data(authenticated_client)) for _ in range(6)
        ]
    assert [response.status_code for response in responses] == [422] * 5 + [429]
    assert change.await_count == 5
