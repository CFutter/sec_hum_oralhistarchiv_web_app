"""Logout retries are inert only after anonymous resolution without a session cookie."""

import logging
from unittest.mock import patch

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient
from lxml import html
from starlette.datastructures import UploadFile

from app.middleware.csrf import verify_csrf
from app.middleware.session import set_session_cookie
from app.routes.auth import login
from config import settings
from tests.fixtures import RAW_SESSION_ID, csrf_token_for, make_sample_user, sign_session_id


def _install_session_cookie(client, session_id):
    """Use the real response attributes and host scope, including cookie deletion."""
    issued = Response()
    set_session_cookie(issued, session_id)
    client.cookies.extract_cookies(
        httpx.Response(
            200,
            headers=issued.headers.raw,
            request=httpx.Request("GET", client.base_url.join("/login")),
        )
    )


def _assert_inert_redirect(response):
    """Require an uncached home redirect without cookie mutations."""
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert response.headers.get_list("set-cookie") == []
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


@pytest.mark.parametrize("federation_enabled", [False, True])
@pytest.mark.parametrize("render_guest_page", [False, True])
def test_repeated_logout_redirects_without_repeating_cleanup(
    client_builder, monkeypatch, caplog, federation_enabled, render_guest_page
):
    """Check repeated logout redirects without repeating cleanup."""
    monkeypatch.setattr(settings, "shibboleth_enabled", federation_enabled)
    client = client_builder(session_user=make_sample_user())
    client.cookies.clear()
    _install_session_cookie(client, RAW_SESSION_ID)
    account = client.get("/account")
    assert account.status_code == 200
    token = html.fromstring(account.text).xpath(
        '//form[@action="/logout"]/input[@name="csrf_token"]/@value'
    )[0]

    with (
        patch.object(login, "delete_session", autospec=True) as delete,
        patch.object(
            login, "clear_session_cookie", autospec=True, side_effect=login.clear_session_cookie
        ) as clear,
        caplog.at_level(logging.INFO, logger="app.middleware.csrf"),
    ):
        first = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
        assert first.status_code == 303
        if federation_enabled:
            assert first.headers["location"].startswith("/Shibboleth.sso/Logout?return=")
        else:
            assert first.headers["location"] == "/"
        assert settings.session_cookie_name not in client.cookies
        assert settings.csrf_cookie_name not in client.cookies
        if render_guest_page:
            assert client.get("/about").status_code == 200
        before = dict(client.cookies)
        lookups = client.session_spy.await_count
        retry = client.post(
            "/logout?return=https://untrusted.example/",
            data={"csrf_token": token},
            follow_redirects=False,
        )

    _assert_inert_redirect(retry)
    assert dict(client.cookies) == before
    assert client.session_spy.await_count == lookups
    delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)
    clear.assert_called_once()
    records = [
        record
        for record in caplog.records
        if getattr(record, "event_type", None) == "logout_already_anonymous"
    ]
    assert len(records) == 1
    assert records[0].request_id == retry.headers["x-request-id"]
    assert records[0].path == "/logout"
    assert token not in repr(records[0].__dict__)
    assert "untrusted.example" not in repr(records[0].__dict__)


@pytest.mark.parametrize(
    "failure", ["missing_cookie", "missing_field", "nonstring", "mismatch", "no_identifier", "hmac"]
)
def test_anonymous_token_failures_never_enter_logout_or_write_cookies(
    guest_client, monkeypatch, failure
):
    """Check anonymous token failures never enter logout or write cookies."""
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    guest_client.cookies.clear()
    token = csrf_token_for("existing-anonymous")
    if failure != "no_identifier":
        guest_client.cookies.set(settings.pre_session_cookie_name, "existing-anonymous")
    if failure != "missing_cookie":
        guest_client.cookies.set(
            settings.csrf_cookie_name,
            "invalid-hmac" if failure in {"hmac", "no_identifier"} else token,
        )
    data = {"csrf_token": "invalid-hmac" if failure in {"hmac", "no_identifier"} else token}
    files = None
    if failure == "missing_field":
        data = {"unrelated": "field"}
    elif failure == "mismatch":
        data = {"csrf_token": "old-form-token"}
    elif failure == "nonstring":
        data = {"unrelated": "field"}
        files = {"csrf_token": ("token.txt", b"invalid-token", "text/plain")}
    before = dict(guest_client.cookies)

    with (
        patch.object(login, "delete_session", autospec=True) as delete,
        patch.object(login, "clear_session_cookie", autospec=True) as clear,
    ):
        retry = guest_client.post("/logout", data=data, files=files, follow_redirects=False)

    _assert_inert_redirect(retry)
    assert dict(guest_client.cookies) == before
    delete.assert_not_awaited()
    clear.assert_not_called()


def test_anonymous_retry_closes_uploaded_files_before_returning(guest_client):
    """Check anonymous retry closes uploaded files before returning."""
    guest_client.cookies.clear()
    uploads = []
    original = UploadFile.__init__

    def retain(self, *args, **kwargs):
        """Initialize the upload and retain it so the test can check closure."""
        original(self, *args, **kwargs)
        uploads.append(self)

    with patch.object(UploadFile, "__init__", retain):
        retry = guest_client.post(
            "/logout",
            files={"csrf_token": ("token.txt", b"x" * (1024 * 1024 + 1))},
            follow_redirects=False,
        )
    _assert_inert_redirect(retry)
    assert uploads and all(upload.file.closed for upload in uploads)


def test_old_logout_form_cannot_revoke_a_new_login(client_builder):
    """Check old logout form cannot revoke a new login."""
    client = client_builder(session_user=make_sample_user())
    client.cookies.clear()
    _install_session_cookie(client, RAW_SESSION_ID)
    assert client.get("/account").status_code == 200
    old_token = client.cookies[settings.csrf_cookie_name]
    with patch.object(login, "delete_session", autospec=True) as delete:
        assert (
            client.post(
                "/logout", data={"csrf_token": old_token}, follow_redirects=False
            ).status_code
            == 303
        )
        delayed_retry = client.post(
            "/logout", data={"csrf_token": old_token}, follow_redirects=False
        )
        _assert_inert_redirect(delayed_retry)

        _install_session_cookie(client, "newly-issued-session")
        assert client.get("/account").status_code == 200
        assert client.cookies[settings.csrf_cookie_name] != old_token
        before = dict(client.cookies)
        # A retry sent anonymously may finish after a different tab logs in.
        client.cookies.extract_cookies(delayed_retry)
        assert dict(client.cookies) == before

        rejected = client.post("/logout", data={"csrf_token": old_token}, follow_redirects=False)
        assert rejected.status_code == 403
        assert rejected.headers.get_list("set-cookie") == []
        assert dict(client.cookies) == before
        delete.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)
        assert client.get("/account").status_code == 200


@pytest.mark.parametrize(
    "session_cookie",
    ["", "invalid-signature", sign_session_id("revoked")],
    ids=["empty", "invalid-signature", "signed-revoked"],
)
def test_any_present_session_cookie_keeps_invalid_csrf_rejection(guest_client, session_cookie):
    """Check any present session cookie keeps invalid CSRF rejection (HTTP 403)."""
    guest_client.cookies.set(settings.session_cookie_name, session_cookie)
    with (
        patch.object(login, "delete_session", autospec=True) as delete,
        patch.object(login, "clear_session_cookie", autospec=True) as clear,
    ):
        rejected = guest_client.post("/logout", data={"unrelated": "field"}, follow_redirects=False)
    assert rejected.status_code == 403
    delete.assert_not_awaited()
    clear.assert_not_called()
    assert guest_client.cookies[settings.session_cookie_name] == session_cookie


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Origin", "null")],
        [("Origin", "https://foreign.example.org")],
        [("Origin", "https://archive.example.org:444")],
        [("Origin", "https://archive.example.org")] * 2,
        [("Referer", "https://foreign.example.org/account")],
    ],
)
def test_anonymous_retry_still_rejects_invalid_hardened_origins(guest_client, monkeypatch, headers):
    """Check anonymous retry still rejects invalid hardened origins (HTTP 403)."""
    guest_client.cookies.clear()
    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")
    response = guest_client.post(
        "/logout", data={"csrf_token": "old-form-token"}, headers=headers, follow_redirects=False
    )
    assert response.status_code == 403


@pytest.mark.parametrize("header", ["Origin", "Referer"])
def test_anonymous_retry_accepts_a_valid_hardened_origin(guest_client, monkeypatch, header):
    """Check anonymous retry accepts a valid hardened origin."""
    guest_client.cookies.clear()
    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")
    value = "https://archive.example.org" + ("/account" if header == "Referer" else "")
    response = guest_client.post(
        "/logout",
        data={"csrf_token": "old-form-token"},
        headers={header: value},
        follow_redirects=False,
    )
    _assert_inert_redirect(response)


def test_anonymous_retry_still_requires_form_content_type(guest_client):
    """Check anonymous retry still requires form content type (HTTP 415)."""
    guest_client.cookies.clear()
    response = guest_client.post("/logout", json={"csrf_token": "old-form-token"})
    assert response.status_code == 415


@pytest.mark.parametrize(
    "state",
    [
        {},
        {"session_resolution_completed": False, "user": None, "session_id": None},
        {"session_resolution_completed": True, "user": None},
        {"session_resolution_completed": True, "session_id": None},
        {"session_resolution_completed": True, "user": True, "session_id": None},
        {"session_resolution_completed": True, "user": None, "session_id": "resolved"},
    ],
)
def test_invalid_csrf_requires_explicit_completed_anonymous_state(state):
    """Check invalid CSRF requires explicit completed anonymous state (HTTP 403)."""
    probe = FastAPI()
    calls = []

    @probe.middleware("http")
    async def resolve(request: Request, call_next):
        """Install the selected resolution state before dispatching the probe request."""
        for name, value in state.items():
            setattr(request.state, name, value)
        return await call_next(request)

    @probe.post("/logout", dependencies=[Depends(verify_csrf)])
    async def endpoint():
        """Record that logout ran and return an empty response."""
        calls.append("logout")
        return Response()

    with TestClient(probe) as client:
        response = client.post("/logout", data={"unrelated": "field"}, follow_redirects=False)
    assert response.status_code == 403
    assert calls == []


@pytest.mark.parametrize("federation_enabled", [False, True])
def test_valid_anonymous_logout_preserves_normal_cleanup(
    guest_client, monkeypatch, federation_enabled
):
    """Check valid anonymous logout preserves normal cleanup (HTTP 303)."""
    monkeypatch.setattr(settings, "shibboleth_enabled", federation_enabled)
    response = guest_client.post(
        "/logout", data={"csrf_token": guest_client.csrf_token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith(
        "/Shibboleth.sso/Logout?return=" if federation_enabled else "/"
    )
    expired = response.headers.get_list("set-cookie")
    assert len(expired) == 3
    assert all("max-age=0" in header.lower() for header in expired)


@pytest.mark.parametrize(
    ("method", "path"), [("PUT", "/logout"), ("POST", "/logout/"), ("POST", "/reset-password")]
)
def test_anonymous_token_failure_on_other_method_or_path_still_rejects(method, path):
    """Check anonymous token failure on other method or path still rejects (HTTP 403)."""
    probe = FastAPI()
    calls = []

    @probe.middleware("http")
    async def resolve(request: Request, call_next):
        """Mark anonymous session resolution complete before continuing dispatch."""
        request.state.session_resolution_completed = True
        request.state.user = None
        request.state.session_id = None
        return await call_next(request)

    @probe.api_route(path, methods=[method], dependencies=[Depends(verify_csrf)])
    async def endpoint():
        """Record that the guarded mutation ran and return an empty response."""
        calls.append("mutation")
        return Response()

    with TestClient(probe) as client:
        response = client.request(method, path, data={"unrelated": "field"}, follow_redirects=False)
    assert response.status_code == 403
    assert calls == []
