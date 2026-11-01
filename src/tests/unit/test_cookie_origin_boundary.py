"""Security-cookie identity and browser mutation origins form one strict boundary."""

import json
import logging
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException, Request, Response

from app.middleware.cookies import get_session_id_from_cookie, reject_ambiguous_security_cookies
from app.middleware.csrf import _verify_browser_origin
from app.middleware.session import clear_session_cookie, set_session_cookie
from app.middleware.validators import validate_security_settings
from config import settings
from config.logging import JSONFormatter
from config.settings import Settings
from tests.unit.settings_builders import base_kwargs, prod_kwargs


def _request(headers=()):
    """Build a POST /login request with the supplied raw headers."""
    return Request({"type": "http", "method": "POST", "path": "/login", "headers": list(headers)})


@pytest.fixture
def _hardened(monkeypatch):
    """Select production, secure host cookies and a fixed HTTPS public origin."""
    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "cookies_secure", True)
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")
    monkeypatch.setattr(settings, "session_cookie_name", "__Host-oha_session")


def test_hardened_cookie_names_and_expiration_attributes(_hardened):
    """Hardened cookie names and expiration attributes."""
    configured = Settings(_env_file=None, **prod_kwargs())
    assert configured.session_cookie_name == "__Host-oha_session"
    assert configured.pre_session_cookie_name == "__Host-oha_pre_session"
    assert configured.csrf_cookie_name == "__Host-oha_csrf"
    created, expired = Response(), Response()
    set_session_cookie(created, "test-token")
    clear_session_cookie(expired)
    for response in (created, expired):
        for value in response.headers.getlist("set-cookie"):
            cookie = SimpleCookie(value)
            for name, morsel in cookie.items():
                assert name.startswith("__Host-")
                assert morsel["secure"]
                assert morsel["httponly"]
                assert morsel["path"] == "/"
                assert not morsel["domain"]
    assert len(expired.headers.getlist("set-cookie")) == 3


@pytest.mark.parametrize(
    "name", ["__Host-oha_session", "__Host-oha_csrf", "__Host-oha_pre_session"]
)
@pytest.mark.parametrize("multiple_headers", [False, True])
def test_duplicate_security_cookie_names_are_rejected(_hardened, name, multiple_headers):
    """Duplicate security cookie names are rejected."""
    values = [f"{name}=first", f"{name}=second"]
    headers = (
        [(b"cookie", value.encode()) for value in values]
        if multiple_headers
        else [(b"cookie", "; ".join(values).encode())]
    )
    with pytest.raises(HTTPException) as caught:
        reject_ambiguous_security_cookies(_request(headers))
    assert caught.value.status_code == 400


def test_hardened_lookup_ignores_legacy_parent_domain_names(_hardened):
    """Hardened lookup ignores legacy parent domain names."""
    request = _request(
        [(b"cookie", b"oha_session=injected; pre_session_id=attacker; csrf_token=token")]
    )
    assert get_session_id_from_cookie(request) is None


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"origin", b"https://sibling.example.org")],
        [(b"origin", b"null")],
        [(b"origin", b"http://archive.example.org")],
        [(b"origin", b"https://archive.example.org:444")],
        [(b"origin", b"https://archive.example.org:0")],
        [(b"referer", b"https://sibling.example.org/login")],
        [(b"origin", b"https://archive.example.org"), (b"origin", b"https://archive.example.org")],
        [
            (b"origin", b"https://sibling.example.org"),
            (b"referer", b"https://archive.example.org/login"),
        ],
    ],
)
def test_hardened_mutation_rejects_untrusted_or_ambiguous_origin(_hardened, headers):
    """Hardened mutation rejects untrusted or ambiguous origin."""
    with pytest.raises(HTTPException) as caught:
        _verify_browser_origin(_request(headers))
    assert caught.value.status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        [(b"origin", b"https://archive.example.org")],
        [(b"origin", b"https://archive.example.org:443")],
        [(b"referer", b"https://archive.example.org/login?next=/account")],
    ],
)
def test_hardened_mutation_accepts_canonical_origin_or_referer(_hardened, headers):
    """Hardened mutation accepts canonical origin or referer."""
    _verify_browser_origin(_request(headers))


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ([], "missing_origin"),
        ([(b"origin", b"null")], "origin_mismatch"),
        (
            [
                (b"origin", b"https://private-header-canary.example.org"),
                (b"referer", b"https://archive.example.org/private-referrer-canary?code=secret"),
            ],
            "origin_mismatch",
        ),
        (
            [(b"origin", b"https://archive.example.org")] * 2,
            "ambiguous_origin_headers",
        ),
    ],
)
def test_origin_rejections_log_safe_correlated_reasons(_hardened, caplog, headers, reason):
    """Origin rejections log safe correlated reasons."""
    request = _request(headers)
    request.state.request_id = "0123456789abcdef"
    with (
        caplog.at_level(logging.WARNING, logger="app.middleware.csrf"),
        pytest.raises(HTTPException) as caught,
    ):
        _verify_browser_origin(request)
    assert caught.value.status_code == 403
    records = [record for record in caplog.records if record.name == "app.middleware.csrf"]
    assert len(records) == 1
    record = records[0]
    assert record.getMessage() == "CSRF origin validation failed"
    assert record.request_id == "0123456789abcdef"
    assert record.reason == reason
    formatted = JSONFormatter().format(record)
    event = json.loads(formatted)
    assert event["request_id"] == request.state.request_id
    assert event["reason"] == reason
    assert "private-header-canary" not in formatted
    assert "private-referrer-canary" not in formatted


def test_hardened_configuration_cannot_select_unprefixed_session_cookie():
    """Hardened configuration cannot select unprefixed session cookie."""
    with pytest.raises(ValueError, match="__Host-"):
        Settings(_env_file=None, **prod_kwargs(session_cookie_name="oha_session"))
    with pytest.raises(ValueError, match="COOKIES_SECURE"):
        Settings(
            _env_file=None, **base_kwargs(session_cookie_name="__Host-custom", cookies_secure=False)
        )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("session_cookie_name", "legacy-name", "SESSION_COOKIE_NAME"),
        ("cookies_secure", False, "COOKIES_SECURE"),
    ],
)
def test_final_startup_gate_rejects_mutated_cookie_boundary(
    _hardened, monkeypatch, field, value, expected
):
    """Final startup gate rejects mutated cookie boundary."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    monkeypatch.setattr(settings, field, value)
    with pytest.raises(RuntimeError, match=expected):
        validate_security_settings()
