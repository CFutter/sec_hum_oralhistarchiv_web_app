"""Account-deletion confirmation, authorization and committed audit boundaries."""

import logging
from unittest.mock import create_autospec, patch

import pytest

from app.middleware.csrf import CSRF_COOKIE_NAME
from app.services import get_user_by_id
from app.services.account_deletion import AccountDeletionRejected, AccountDeletionResult
from app.services.totp import TotpDecryptionError
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

PASSWORD = "DELETION-PASSWORD-MUST-NOT-LEAK"
CODE = "123456"
EMAIL_HASH = "a76549eaa120c43f"
TARGET = make_sample_user(
    id=7, email="target@example.org", display_name='<script>alert("x")</script>'
)


def _patch(name, **kwargs):
    """Patch the route collaborator with its real signature."""
    if name == "get_user_by_id":
        # The default target fixture can be overridden by one test without
        # autospeccing an already installed mock.
        return patch(
            f"app.routes.auth.account_deletion.{name}",
            new=create_autospec(get_user_by_id, **kwargs),
        )
    return patch(f"app.routes.auth.account_deletion.{name}", autospec=True, **kwargs)


@pytest.fixture(autouse=True)
def _confirmation_target():
    """Resolve confirmation targets to the default user for this test."""
    with _patch("get_user_by_id", return_value=TARGET):
        yield


def _data(client, **extra):
    """Build the valid form with caller overrides and the current CSRF token."""
    return {
        "password": PASSWORD,
        "totp_code": CODE,
        "confirm": "delete",
        "csrf_token": client.csrf_token,
        **extra,
    }


def _assert_deleted_cookie(response, name):
    """Require exactly one deletion header for the named cookie."""
    headers = [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]
    assert len(headers) == 1
    assert "max-age=0" in headers[0].lower()


def test_local_account_confirmation_is_read_only_and_not_cached(authenticated_client):
    """Check local account confirmation is read only and not cached (HTTP 200)."""
    with _patch("delete_own_account") as delete:
        response = authenticated_client.get("/account/delete")

    assert response.status_code == 200
    assert 'action="/account/delete"' in response.text
    assert 'name="password"' in response.text
    assert 'name="totp_code"' in response.text
    assert 'name="confirm"' in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "strict-origin"
    delete.assert_not_awaited()
    ordinary_page = authenticated_client.get("/about")
    assert ordinary_page.status_code == 200
    assert ordinary_page.headers["referrer-policy"] == "strict-origin-when-cross-origin"


def test_self_deletion_delegates_current_session_and_audits_one_pseudonym(
    authenticated_client, caplog
):
    """Check self deletion delegates current session and audits one pseudonym (HTTP 303)."""
    result = AccountDeletionResult(target_user_id=1, email_hash=EMAIL_HASH, auth_method="local")
    with (
        _patch("delete_own_account", return_value=result) as delete,
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = authenticated_client.post(
            "/account/delete", data=_data(authenticated_client), follow_redirects=False
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?notice=account_deleted"
    delete.assert_awaited_once_with(
        authenticated_client.mock_pool,
        user_id=1,
        session_id=RAW_SESSION_ID,
        password=PASSWORD,
        totp_code=CODE,
    )
    _assert_deleted_cookie(response, settings.session_cookie_name)
    _assert_deleted_cookie(response, CSRF_COOKIE_NAME)
    events = [r for r in caplog.records if getattr(r, "event_type", None) == "account_deleted"]
    assert len(events) == 1
    assert events[0].email_hash == EMAIL_HASH
    assert events[0].user_id == 1
    assert "alice@example.org" not in repr(events[0].__dict__)
    assert PASSWORD not in repr(events[0].__dict__)
    assert CODE not in repr(events[0].__dict__)


def test_admin_confirmation_escapes_target_and_does_not_remove_it(admin_client):
    """Check admin confirmation escapes target and does not remove it (HTTP 200)."""
    with (
        _patch("get_user_by_id", return_value=TARGET) as lookup,
        _patch("delete_account_as_admin") as delete,
    ):
        response = admin_client.get("/admin/users/7/delete")

    assert response.status_code == 200
    assert TARGET.email in response.text
    assert "&lt;script&gt;" in response.text
    assert TARGET.display_name not in response.text
    assert 'action="/admin/users/7/delete"' in response.text
    assert response.headers["cache-control"] == "no-store"
    lookup.assert_awaited_once_with(admin_client.mock_pool, 7)
    delete.assert_not_awaited()


def test_admin_deletion_uses_resolved_actor_and_audits_committed_pseudonym(admin_client, caplog):
    """Check admin deletion uses resolved actor and audits committed pseudonym (HTTP 303)."""
    result = AccountDeletionResult(
        target_user_id=7, email_hash=EMAIL_HASH, auth_method="shibboleth"
    )
    with (
        _patch("delete_account_as_admin", return_value=result) as delete,
        _patch("set_flash_if_exists"),
        caplog.at_level(logging.INFO, logger="audit"),
    ):
        response = admin_client.post(
            "/admin/users/7/delete", data=_data(admin_client), follow_redirects=False
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    delete.assert_awaited_once_with(
        admin_client.mock_pool,
        actor_id=99,
        actor_session_id=RAW_SESSION_ID,
        target_user_id=7,
        password=PASSWORD,
        totp_code=CODE,
    )
    assert not any(
        h.startswith(f"{settings.session_cookie_name}=") and "max-age=0" in h.lower()
        for h in response.headers.get_list("set-cookie")
    )
    events = [
        r for r in caplog.records if getattr(r, "event_type", None) == "admin_account_deleted"
    ]
    assert len(events) == 1
    assert events[0].email_hash == EMAIL_HASH
    assert events[0].actor_admin_id == 99
    assert events[0].target_user_id == 7
    for canary in (TARGET.email, PASSWORD, CODE, "urn:test:private-subject"):
        assert canary not in repr(events[0].__dict__)


@pytest.mark.parametrize("path", ["/account/delete", "/admin/users/7/delete"])
@pytest.mark.parametrize("confirm", ["", "yes"])
def test_explicit_confirmation_is_required_before_credential_work(admin_client, path, confirm):
    """Check explicit confirmation is required before credential work (HTTP 422)."""
    with _patch("delete_own_account") as own, _patch("delete_account_as_admin") as other:
        response = admin_client.post(
            path, data=_data(admin_client, confirm=confirm), follow_redirects=False
        )

    assert response.status_code == 422
    own.assert_not_awaited()
    other.assert_not_awaited()
    assert PASSWORD not in response.text
    assert f'value="{CODE}"' not in response.text


@pytest.mark.parametrize("path", ["/account/delete", "/admin/users/7/delete"])
def test_bad_csrf_does_not_reach_a_deletion_service(admin_client, path):
    """Check bad CSRF does not reach a deletion service (HTTP 403)."""
    with _patch("delete_own_account") as own, _patch("delete_account_as_admin") as other:
        response = admin_client.post(path, data=_data(admin_client, csrf_token="forged"))

    assert response.status_code == 403
    own.assert_not_awaited()
    other.assert_not_awaited()


@pytest.mark.parametrize("path", ["/account/delete", "/admin/users/7/delete"])
def test_json_is_rejected_before_deletion(admin_client, path):
    """Check JSON is rejected before deletion (HTTP 415)."""
    with _patch("delete_own_account") as own, _patch("delete_account_as_admin") as other:
        response = admin_client.post(path, json=_data(admin_client))

    assert response.status_code == 415
    own.assert_not_awaited()
    other.assert_not_awaited()


@pytest.mark.parametrize("method", ["get", "post"])
def test_federated_account_cannot_use_local_self_deletion(client_builder, method):
    """Check federated account cannot use local self deletion (HTTP 403)."""
    client = client_builder(session_user=make_sample_user(auth_method="shibboleth"))
    with _patch("delete_own_account") as delete:
        response = (
            client.get("/account/delete")
            if method == "get"
            else client.post("/account/delete", data=_data(client))
        )

    assert response.status_code == 403
    delete.assert_not_awaited()


@pytest.mark.parametrize("method", ["get", "post"])
def test_admin_removal_is_cloaked_from_non_admins(authenticated_client, method):
    """Check admin removal is cloaked from non admins (HTTP 404)."""
    with _patch("get_user_by_id") as lookup, _patch("delete_account_as_admin") as delete:
        response = (
            authenticated_client.get("/admin/users/7/delete")
            if method == "get"
            else authenticated_client.post(
                "/admin/users/7/delete", data=_data(authenticated_client)
            )
        )

    assert response.status_code == 404
    lookup.assert_not_awaited()
    delete.assert_not_awaited()


@pytest.mark.parametrize("path", ["/account/delete", "/admin/users/7/delete"])
def test_enrollment_session_cannot_delete_accounts(totp_setup_client, path):
    """Check enrollment session cannot delete accounts."""
    with _patch("delete_own_account") as own, _patch("delete_account_as_admin") as other:
        response = totp_setup_client.post(
            path, data=_data(totp_setup_client), follow_redirects=False
        )

    assert response.status_code in {303, 404}
    own.assert_not_awaited()
    other.assert_not_awaited()


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("invalid_session", 303),
        ("account_locked", 423),
        ("step_up_exhausted", 303),
        ("ineligible_account", 422),
        ("invalid_password", 422),
        ("invalid_totp", 422),
        ("retry_required", 409),
        ("last_active_admin", 422),
    ],
)
def test_self_rejections_never_audit_or_reflect_credentials(
    authenticated_client, caplog, reason, status
):
    """Check self rejections never audit or reflect credentials."""
    with (
        _patch("delete_own_account", side_effect=AccountDeletionRejected(reason)),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            "/account/delete", data=_data(authenticated_client), follow_redirects=False
        )

    assert response.status_code == status
    audit.assert_not_called()
    assert PASSWORD not in response.text
    assert f'value="{CODE}"' not in response.text
    assert not any(getattr(r, "event_type", None) == "account_deleted" for r in caplog.records)
    if reason in {"invalid_session", "step_up_exhausted"}:
        _assert_deleted_cookie(response, settings.session_cookie_name)


@pytest.mark.parametrize(
    ("reason", "status"),
    [("admin_required", 303), ("user_not_found", 404), ("self_admin_deletion", 422)],
)
def test_admin_rejections_do_not_reread_or_audit_a_target(admin_client, reason, status):
    """Check admin rejections do not reread or audit a target."""
    with (
        _patch("delete_account_as_admin", side_effect=AccountDeletionRejected(reason)),
        _patch("get_user_by_id", return_value=TARGET) as lookup,
        _patch("audit_admin_action") as audit,
    ):
        response = admin_client.post(
            "/admin/users/7/delete", data=_data(admin_client), follow_redirects=False
        )

    assert response.status_code == status
    lookup.assert_awaited_once_with(admin_client.mock_pool, 7)
    audit.assert_not_called()
    if reason == "admin_required":
        _assert_deleted_cookie(response, settings.session_cookie_name)


def test_undecryptable_authenticator_fails_closed_without_a_success_audit(authenticated_client):
    """Check undecryptable authenticator fails closed without a success audit (HTTP 503)."""
    with (
        _patch("delete_own_account", side_effect=TotpDecryptionError(1)),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            "/account/delete", data=_data(authenticated_client), follow_redirects=False
        )

    assert response.status_code == 503
    audit.assert_not_called()
    assert "key mismatch" not in response.text


def test_absent_admin_confirmation_target_is_404(admin_client):
    """Check absent admin confirmation target is 404."""
    with _patch("get_user_by_id", return_value=None):
        response = admin_client.get("/admin/users/7/delete")
    assert response.status_code == 404


@pytest.mark.parametrize("field", ["password", "totp_code"])
def test_oversized_credentials_are_rejected_before_work(authenticated_client, field):
    """Check oversized credentials are rejected before work (HTTP 422)."""
    value = "x" * (201 if field == "password" else 17)
    with _patch("delete_own_account") as delete:
        response = authenticated_client.post(
            "/account/delete", data=_data(authenticated_client, **{field: value})
        )
    assert response.status_code == 422
    delete.assert_not_awaited()


def test_database_failure_does_not_emit_a_success_event(authenticated_client):
    """Check database failure does not emit a success event (HTTP 500)."""
    with (
        _patch("delete_own_account", side_effect=RuntimeError("storage unavailable")),
        _patch("audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            "/account/delete", data=_data(authenticated_client), follow_redirects=False
        )
    assert response.status_code == 500
    audit.assert_not_called()
    assert PASSWORD not in response.text


@pytest.mark.parametrize(
    "path,service,target_id",
    [
        ("/account/delete", "delete_own_account", 99),
        ("/admin/users/7/delete", "delete_account_as_admin", 7),
    ],
)
def test_deletion_accepts_bounded_pasted_totp(admin_client, path, service, target_id):
    """Check deletion accepts bounded pasted TOTP (HTTP 303)."""
    result = AccountDeletionResult(target_id, EMAIL_HASH, "local")
    with _patch(service, return_value=result) as delete, _patch("set_flash_if_exists"):
        response = admin_client.post(
            path, data=_data(admin_client, totp_code="123 456"), follow_redirects=False
        )
    assert response.status_code == 303
    assert delete.await_args.kwargs["totp_code"] == "123 456"


@pytest.mark.parametrize("path", ["/account/delete", "/admin/users/7/delete"])
def test_deletion_rejects_overlong_raw_totp_before_service(admin_client, path):
    """Check deletion rejects overlong raw TOTP before service (HTTP 422)."""
    with _patch("delete_own_account") as own, _patch("delete_account_as_admin") as other:
        response = admin_client.post(path, data=_data(admin_client, totp_code=" " * 11 + CODE))
    assert response.status_code == 422
    own.assert_not_awaited()
    other.assert_not_awaited()
