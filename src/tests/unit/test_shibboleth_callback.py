"""Shibboleth callback trust boundary (ported from legacy edge-case tests).

The callback trusts IdP attribute headers, so it must be certain the request
came from nginx: (1) no TCP peer (Unix socket only), (2) X-Internal-Auth
matches the configured secret. Every rejection is a silent 303 to /login —
never an error page that would confirm the endpoint's behavior to a prober.

Tests call the route function directly with fabricated ASGI requests so the
no-TCP-peer condition (client=None) can be simulated — TestClient always has
a synthetic peer.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import SecretStr
from starlette.requests import Request

from config import settings
from app.routes.auth.login import shibboleth_callback
from tests.fixtures import make_sample_user

SECRET = "shib-internal-secret-value-for-tests-0123456789"


def make_request(headers: dict | None = None, client=None, query: bytes = b""):
    """A raw ASGI request: client=None + server=None models the Unix socket."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/auth/shibboleth/callback",
        "query_string": query,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": client,
        "server": None,
        "scheme": "http",
        "app": SimpleNamespace(state=SimpleNamespace(db_pool=MagicMock())),
    }
    return Request(scope)


def shib_settings(monkeypatch):
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET))


async def test_disabled_redirects_to_login():
    """shibboleth_enabled=False → the endpoint is inert (303, no processing)."""
    response = await shibboleth_callback(make_request())
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_tcp_peer_is_refused(monkeypatch):
    """A request with a TCP peer can only mean the app is exposed on TCP —
    refuse even with a valid secret (the socket is the only trusted path)."""
    shib_settings(monkeypatch)
    request = make_request({"X-Internal-Auth": SECRET}, client=("10.0.0.9", 4321))
    response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_wrong_internal_secret_refused(monkeypatch):
    """X-Internal-Auth is THE gate: nginx injects it only on this location and
    strips client-supplied copies everywhere."""
    shib_settings(monkeypatch)
    response = await shibboleth_callback(make_request({"X-Internal-Auth": "wrong"}))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_missing_attributes_refused(monkeypatch):
    """Valid secret but no REMOTE_USER/mail → no session (mod_shib misconfig)."""
    shib_settings(monkeypatch)
    response = await shibboleth_callback(make_request({"X-Internal-Auth": SECRET}))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_invalid_email_refused_with_error_param(monkeypatch):
    shib_settings(monkeypatch)
    request = make_request({
        "X-Internal-Auth": SECRET,
        "REMOTE_USER": "abc123@idp",
        "mail": "not-an-email",
    })
    response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=shibboleth_invalid_email"


async def test_local_account_collision_never_issues_session(monkeypatch):
    """create_shibboleth_user returns None when a LOCAL account owns the email
    (the never-merge guard) — the caller must treat that as login failure."""
    shib_settings(monkeypatch)
    request = make_request({
        "X-Internal-Auth": SECRET,
        "REMOTE_USER": "abc123@idp",
        "mail": "owned@uzh.ch",
    })
    with patch("app.routes.auth.login.create_shibboleth_user",
               new=AsyncMock(return_value=None)), \
         patch("app.routes.auth.login.create_session") as create_session:
        response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=account_conflict"
    create_session.assert_not_called()


async def test_valid_callback_provisions_and_sets_cookie(monkeypatch):
    """Happy path: user upserted, FULL session issued (Shibboleth users skip
    TOTP — the IdP is their second factor), signed cookie set."""
    shib_settings(monkeypatch)
    user = make_sample_user(auth_method="shibboleth", email="jane@x.org")
    request = make_request({
        "X-Internal-Auth": SECRET,
        "REMOTE_USER": "abc123@idp",
        "mail": "Jane@X.org",
        "displayName": "Jane",
    })
    with patch("app.routes.auth.login.create_shibboleth_user",
               new=AsyncMock(return_value=user)) as upsert, \
         patch("app.routes.auth.login.create_session",
               new=AsyncMock(return_value="raw-session-id")) as create_session:
        response = await shibboleth_callback(request)

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    # Email was validated+normalized before the upsert.
    assert upsert.await_args.kwargs["email"] == "jane@x.org"
    assert create_session.await_args.kwargs["purpose"] == "full"
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "HttpOnly" in set_cookie
