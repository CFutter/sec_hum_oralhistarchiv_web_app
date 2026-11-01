"""Signed double-submit CSRF — cookie minting middleware + verify_csrf dependency."""

import logging
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.content_type import validate_form_content_type
from app.middleware.cookies import PRE_SESSION_COOKIE_NAME
from app.middleware.csrf import CSRF_COOKIE_NAME, verify_csrf
from app.middleware.session import (
    require_full_session,
    require_local_auth,
    require_public_or_full_session,
    require_totp_enrollment_session,
)
from config import settings
from tests.fixtures import (
    RAW_SESSION_ID,
    csrf_token_for,
    make_sample_user,
    sign_session_id,
)

BOGUS_TOKEN = "deadbeef" * 8  # right length/shape, but not HMAC(secret, id)
LIVE_RESET_TOKEN_CANARY = "LIVE-RESET-CAPABILITY-MUST-NOT-ENTER-LOGS"
CONTENT_TYPE_VALUE_CANARY = "CONTENT-TYPE-VALUE-MUST-NOT-ENTER-LOGS"


def _both_guard_routes():
    """List POST routes that require both CSRF verification and a session guard."""
    session_guards = {
        require_full_session,
        require_local_auth,
        require_public_or_full_session,
        require_totp_enrollment_session,
    }
    out = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or "POST" not in route.methods:
            continue
        deps = {d.call for d in route.dependant.dependencies}
        if verify_csrf in deps and deps & session_guards:
            out.append(route.path)
    return out


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


def _cookie_value(header: str) -> str:
    """Extract the cookie value from a raw Set-Cookie header."""
    return header.split(";", 1)[0].split("=", 1)[1].strip('"')


def _is_deletion(header: str) -> bool:
    """True if the Set-Cookie header expires the cookie (delete_cookie)."""
    return "max-age=0" in header.lower()


def _assert_canary_absent_from_records(caplog, canary: str) -> None:
    """Check messages and structured extras, not only rendered messages."""
    for record in caplog.records:
        assert canary not in record.getMessage()
        assert canary not in repr(record.__dict__)


def test_first_get_mints_pre_session_and_hmac_bound_csrf_cookie(client_builder):
    """Check first GET mints pre session and HMAC bound CSRF cookie (HTTP 200)."""
    client = client_builder(session_user=None)
    client.cookies.clear()

    # /about is a public GET whose source diagnostics are mocked by the
    # client harness; the cookie preparation under test runs on every GET.
    response = client.get("/about")
    assert response.status_code == 200

    pre_headers = _set_cookie_headers(response, PRE_SESSION_COOKIE_NAME)
    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    assert len(pre_headers) == 1, "expected exactly one pre-session mint"
    assert len(csrf_headers) == 1, "expected exactly one CSRF mint"

    pre_session_value = _cookie_value(pre_headers[0])
    csrf_value = _cookie_value(csrf_headers[0])
    assert pre_session_value, "pre-session id must be non-empty"
    assert csrf_value == csrf_token_for(pre_session_value)


def test_second_get_with_valid_cookies_does_not_remint(client_builder):
    """Steady state: once the pre-session + matching CSRF cookies exist, a follow-up GET sets NO
    csrf_token cookie (and no new pre-session).
    """
    client = client_builder(session_user=None)
    client.cookies.clear()

    first = client.get("/about")
    assert _set_cookie_headers(first, CSRF_COOKIE_NAME)
    second = client.get("/about")

    assert second.status_code == 200
    assert _set_cookie_headers(second, CSRF_COOKIE_NAME) == []
    assert _set_cookie_headers(second, PRE_SESSION_COOKIE_NAME) == []


def test_get_transition_deletes_pre_session_and_rebinds_csrf_to_session_id(
    authenticated_client,
):
    """A live session replaces the anonymous identifier and binds the next form."""
    authenticated_client.cookies.clear()
    authenticated_client.cookies.set(PRE_SESSION_COOKIE_NAME, "old-pre-session")
    authenticated_client.cookies.set(CSRF_COOKIE_NAME, csrf_token_for("old-pre-session"))
    authenticated_client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))

    response = authenticated_client.get("/about", follow_redirects=False)
    assert response.status_code == 200

    pre_headers = _set_cookie_headers(response, PRE_SESSION_COOKIE_NAME)
    assert pre_headers, "pre-session cookie must be deleted on transition"
    assert all(_is_deletion(h) for h in pre_headers)

    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    minted = [h for h in csrf_headers if not _is_deletion(h)]
    assert len(minted) == 1, "expected exactly one CSRF re-mint"
    assert _cookie_value(minted[0]) == csrf_token_for(RAW_SESSION_ID)


def test_post_without_csrf_form_field_rejected_403(guest_client, caplog):
    """Reject a missing CSRF field with HTTP 403."""
    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = guest_client.post("/reset-password", data={"unrelated": "field"})

    assert response.status_code == 403
    assert "Request could not be verified" in response.text
    assert any("CSRF token missing" in r.getMessage() for r in caplog.records)


def test_reset_capability_not_logged_when_csrf_rejects(guest_client, caplog):
    """A still-live form capability token must not escape on a CSRF failure."""
    with caplog.at_level(logging.WARNING):
        response = guest_client.post(
            "/reset-password",
            data={
                "token": LIVE_RESET_TOKEN_CANARY,
                "password": "correct horse battery staple",
                "password_confirm": "correct horse battery staple",
            },
        )

    assert response.status_code == 403
    csrf_records = [r for r in caplog.records if r.name == "app.middleware.csrf"]
    assert len(csrf_records) == 1
    assert csrf_records[0].getMessage() == "CSRF token missing"
    assert csrf_records[0].path == "/reset-password"
    _assert_canary_absent_from_records(caplog, LIVE_RESET_TOKEN_CANARY)


def test_csrf_logger_uses_route_template_for_token_path(caplog):
    """Reverting to request.url.path must expose the canary and fail."""
    probe_app = FastAPI()

    @probe_app.post(
        "/reset-password/{token}",
        dependencies=[Depends(verify_csrf)],
    )
    async def csrf_probe(token: str) -> dict[str, str]:
        """Echo the token only if the installed dependency accepts the request."""
        return {"token": token}

    with (
        TestClient(probe_app) as client,
        caplog.at_level(logging.WARNING, logger="app.middleware.csrf"),
    ):
        response = client.post(
            f"/reset-password/{LIVE_RESET_TOKEN_CANARY}",
            data={"not_csrf": "present"},
        )

    assert response.status_code == 403
    records = [r for r in caplog.records if r.name == "app.middleware.csrf"]
    assert len(records) == 1
    assert records[0].path == "/reset-password/{token}"
    _assert_canary_absent_from_records(caplog, LIVE_RESET_TOKEN_CANARY)


def test_post_with_cookie_form_mismatch_rejected_403(guest_client, caplog):
    """Valid cookie token, different form token → 403 at the double-submit
    compare (before the HMAC recompute is ever reached)."""
    # Cookie half is the fixture's real token bound to GUEST_PRE_SESSION_ID;
    # the form half deliberately disagrees.
    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = guest_client.post("/reset-password", data={"csrf_token": "not-the-cookie-value"})

    assert response.status_code == 403
    assert "Request could not be verified" in response.text
    assert any("CSRF double-submit mismatch" in r.getMessage() for r in caplog.records)


def test_post_with_self_minted_matching_pair_rejected_403(guest_client, caplog):
    """Cookie and form MATCH but carry a value not derived from the server secret -> 403 via the HMAC
    recompute.
    """
    guest_client.cookies.set(CSRF_COOKIE_NAME, BOGUS_TOKEN)
    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = guest_client.post("/reset-password", data={"csrf_token": BOGUS_TOKEN})

    assert response.status_code == 403
    assert "Request could not be verified" in response.text

    messages = [r.getMessage() for r in caplog.records]
    assert any("CSRF HMAC mismatch" in m for m in messages)
    assert not any("double-submit mismatch" in m for m in messages)
    assert not any("no identifier" in m for m in messages)


def test_post_with_valid_pair_passes_csrf_as_guest(guest_client):
    """The real HMAC pair (cookie + form, bound to the guest pre-session) passes verify_csrf: logout
    proceeds to its 303 redirect.
    """
    with patch("app.routes.auth.login.delete_session", autospec=True) as mock_delete:
        response = guest_client.post(
            "/logout",
            data={"csrf_token": guest_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    mock_delete.assert_not_awaited()


def test_csrf_login_ordering_surface_is_nonempty():
    """Anti-vacuity: if this hits zero, the behavioral ordering test below
    is passing over an empty parametrize and proves nothing."""
    assert _both_guard_routes(), "no mutation route carries a session-policy dependency"


@pytest.mark.parametrize(
    "path",
    [
        "/account/change-name",
        "/account/change-email",
        "/setup-totp",
        "/account/reset-totp",
    ],
)
def test_bad_csrf_anonymous_post_is_403_not_redirect(guest_client, path):
    """An anonymous POST with a bad CSRF token must be rejected by verify_csrf (403), not redirected by
    the later session-policy dependency.
    """
    resp = guest_client.post(
        path,
        data={"csrf_token": "wrong"},
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert resp.status_code == 403, f"{path} redirected instead of rejecting CSRF"


def test_authenticated_logout_with_valid_pair_deletes_session_and_rotates_cookies(
    authenticated_client,
):
    """Require authenticated logout to revoke the exact session and expire both authentication cookies."""
    with patch("app.routes.auth.login.delete_session", autospec=True) as mock_delete:
        response = authenticated_client.post(
            "/logout",
            data={"csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/"
    mock_delete.assert_awaited_once()
    _, session_id_arg = mock_delete.await_args.args
    assert session_id_arg == RAW_SESSION_ID

    session_headers = _set_cookie_headers(response, settings.session_cookie_name)
    assert session_headers and all(_is_deletion(h) for h in session_headers)
    csrf_headers = _set_cookie_headers(response, CSRF_COOKIE_NAME)
    assert csrf_headers and all(_is_deletion(h) for h in csrf_headers)


def test_json_post_rejected_415_before_csrf_runs(authenticated_client):
    """Check JSON POST rejected 415 before CSRF runs."""
    response = authenticated_client.post(
        "/logout", json={"csrf_token": authenticated_client.csrf_token}
    )

    assert response.status_code == 415
    assert "Unsupported Media Type" in response.text


@pytest.mark.parametrize(
    "content_type",
    [
        f"application/x-www-form-urlencoded{CONTENT_TYPE_VALUE_CANARY}",
        f"multipart/form-data{CONTENT_TYPE_VALUE_CANARY}",
    ],
)
def test_content_type_prefix_smuggling_is_rejected_without_logging_value(
    caplog,
    content_type,
):
    """Exact media types, route templates, and no raw header value logged."""
    probe_app = FastAPI()

    @probe_app.post(
        "/reset-password/{token}",
        dependencies=[Depends(validate_form_content_type)],
    )
    async def content_type_probe(token: str) -> dict[str, str]:
        """Echo the token only if the installed dependency accepts the request."""
        return {"token": token}

    with (
        TestClient(probe_app) as client,
        caplog.at_level(logging.WARNING, logger="app.middleware.content_type"),
    ):
        response = client.post(
            f"/reset-password/{LIVE_RESET_TOKEN_CANARY}",
            content="token=irrelevant",
            headers={"Content-Type": content_type},
        )

    assert response.status_code == 415
    records = [r for r in caplog.records if r.name == "app.middleware.content_type"]
    assert len(records) == 1
    assert records[0].getMessage() == "Rejected form Content-Type"
    assert records[0].path == "/reset-password/{token}"
    assert records[0].content_type_present is True
    _assert_canary_absent_from_records(caplog, CONTENT_TYPE_VALUE_CANARY)
    _assert_canary_absent_from_records(caplog, LIVE_RESET_TOKEN_CANARY)


def test_form_content_type_parameters_remain_supported(guest_client):
    """Splitting at ';' must not reject a valid form media type with charset."""
    response = guest_client.post(
        "/reset-password",
        content="token=irrelevant",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
    )

    assert response.status_code == 403


def test_planted_pre_session_pair_rejected_for_authenticated_user(client_builder, caplog):
    """Check planted pre session pair rejected for authenticated user (HTTP 403)."""
    client = client_builder(session_user=make_sample_user())
    planted_id = "attacker-planted-pre-session"
    planted_token = csrf_token_for(planted_id)
    client.cookies.set(PRE_SESSION_COOKIE_NAME, planted_id)
    client.cookies.set(CSRF_COOKIE_NAME, planted_token)

    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = client.post("/logout", data={"csrf_token": planted_token})

    assert response.status_code == 403
    assert "Request could not be verified" in response.text

    messages = [r.getMessage() for r in caplog.records]
    assert any("CSRF HMAC mismatch" in m for m in messages)
    # The planted pair MATCHES and an identifier (the session) EXISTS — the
    # rejection must come from the session-binding recompute alone.
    assert not any("double-submit mismatch" in m for m in messages)
    assert not any("no identifier" in m for m in messages)


def test_session_bound_pair_still_passes_with_planted_pre_session(
    authenticated_client,
):
    """Check session bound pair still passes with planted pre session (HTTP 303)."""
    authenticated_client.cookies.set(PRE_SESSION_COOKIE_NAME, "attacker-harvested-pre-session")
    session_token = csrf_token_for(RAW_SESSION_ID)
    authenticated_client.cookies.set(CSRF_COOKIE_NAME, session_token)

    with patch("app.routes.auth.login.delete_session", autospec=True):
        response = authenticated_client.post(
            "/logout",
            data={"csrf_token": session_token},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_multipart_file_csrf_token_is_403_not_500(authenticated_client, caplog):
    """csrf_token arriving as a FILE part (UploadFile, not str) must hit the
    isinstance guard and 403 — not TypeError-500 inside compare_digest."""
    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = authenticated_client.post(
            "/logout",
            files={"csrf_token": ("token.txt", b"some-bytes", "text/plain")},
        )

    assert response.status_code == 403
    assert "Request could not be verified" in response.text
    assert any("CSRF token was not a string form field" in r.getMessage() for r in caplog.records)


def test_missing_identifier_is_403_not_500(client_builder, caplog):
    """Matching cookie/form pair but NO session and NO pre-session cookie →
    the identifier lookup returns None and must 403, not NoneType-crash into
    the HMAC recompute."""
    client = client_builder(session_user=None)
    client.cookies.delete(PRE_SESSION_COOKIE_NAME)
    matching = "a-matching-but-unbindable-token-value"
    client.cookies.set(CSRF_COOKIE_NAME, matching)

    with caplog.at_level(logging.WARNING, logger="app.middleware.csrf"):
        response = client.post("/reset-password", data={"csrf_token": matching})

    assert response.status_code == 403
    assert "Request could not be verified" in response.text
    assert any("CSRF verification with no identifier" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("first_method", ["GET", "POST"])
@pytest.mark.parametrize("has_pre_session", [False, True])
def test_revoked_session_form_roundtrip_uses_surviving_anonymous_cookie(
    guest_client, first_method, has_pre_session
):
    """Check revoked session form roundtrip uses surviving anonymous cookie."""
    from lxml import html  # noqa: PLC0415

    from app.services.authentication import PasswordCheck  # noqa: PLC0415

    guest_client.cookies.clear()
    for name, value in (
        (settings.session_cookie_name, sign_session_id("revoked-session")),
        (CSRF_COOKIE_NAME, csrf_token_for("revoked-session")),
    ):
        guest_client.cookies.set(name, value, domain="localhost.local", path="/")
    if has_pre_session:
        guest_client.cookies.set(
            PRE_SESSION_COOKIE_NAME, "existing-anonymous", domain="localhost.local", path="/"
        )
    with patch(
        "app.routes.auth.login.verify_password",
        autospec=True,
        return_value=PasswordCheck(None, False, None, "unknown_email", None),
    ):
        if first_method == "GET":
            response = guest_client.get("/login")
            assert response.status_code == 200
        else:
            response = guest_client.post(
                "/login",
                data={
                    "email": "nobody@example.org",
                    "password": "wrong",
                    "csrf_token": csrf_token_for("revoked-session"),
                },
            )
            assert response.status_code == 401
        form_token = html.fromstring(response.text).xpath('//input[@name="csrf_token"]/@value')[0]
        assert settings.session_cookie_name in guest_client.cookies
        identifier = "revoked-session"
        assert form_token == guest_client.cookies[CSRF_COOKIE_NAME] == csrf_token_for(identifier)
        followup = guest_client.post(
            "/login",
            data={"email": "nobody@example.org", "password": "wrong", "csrf_token": form_token},
        )
        assert followup.status_code == 401


@pytest.mark.parametrize("path", ["/health", "/static/css/style.css"])
def test_requests_that_skip_session_lookup_cannot_overwrite_form_cookies(guest_client, path):
    """Check requests that skip session lookup cannot overwrite form cookies (HTTP 200)."""
    guest_client.cookies.clear()
    guest_client.cookies.set(
        settings.session_cookie_name,
        sign_session_id("revoked-session"),
        domain="localhost.local",
        path="/",
    )
    response = guest_client.get(path)
    assert response.status_code == 200
    assert response.headers.get_list("set-cookie") == []
