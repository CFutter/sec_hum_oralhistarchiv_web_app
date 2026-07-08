"""Error handling — 500s carry security headers; branded 404/422 pages.

Backlog §2.16: bare-``Exception`` handlers run in ServerErrorMiddleware,
*outside* the user middleware stack, so a 500 would bypass
``set_secure_headers`` entirely unless ``unhandled_exception_handler``
re-applies CSP + ``Cache-Control: no-store`` + ``X-Request-ID`` itself.
Only an actually-raised exception proves this framework-interaction
behavior, hence the ``/__test_boom`` route registered below.

Also covers: branded 404/422 pages (which DO pass through
``set_secure_headers`` via ExceptionMiddleware — the backlog's "verify"
note), the §2.8 guard that ``error.html`` renders when flash is None, and
the no-store scoping rules (authenticated pages only; guests and static
assets stay cacheable).
"""
import logging
import re
from unittest.mock import patch

import pytest


BOOM_PATH = "/__test_boom"


@pytest.fixture(scope="module")
def boom_route():
    """Register a route on the singleton app that raises an unhandled
    exception. Added once per module; client fixtures wrap the same app
    object, so they see it. Idempotent across reruns in one process."""
    from app.main import app

    if not any(getattr(r, "path", None) == BOOM_PATH for r in app.routes):
        @app.get(BOOM_PATH)
        async def boom():  # pragma: no cover - body IS the test payload
            raise RuntimeError("kaboom")
    return BOOM_PATH


# ---------------------------------------------------------------------------
# §2.16 — unhandled exception → 500 with security headers
# ---------------------------------------------------------------------------

def test_unhandled_500_carries_security_headers(boom_route, guest_client):
    """§2.16: the 500 from ServerErrorMiddleware runs OUTSIDE
    set_secure_headers, so the handler must re-apply CSP itself, force
    Cache-Control: no-store (an authenticated user's error page must not be
    cached), and attach X-Request-ID for log correlation."""
    response = guest_client.get(boom_route)

    assert response.status_code == 500
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert "X-Request-ID" in response.headers
    # Branded page, not a bare traceback / JSON blob.
    assert "Internal Server Error" in response.text


def test_unhandled_500_request_id_correlates_with_audit_log(
    boom_route, guest_client, caplog
):
    """§2.16: the X-Request-ID response header must equal the request_id on
    the audit 'Request failed with unhandled exception' record — the whole
    point of shipping the id on error responses is log<->response
    correlation when a user reports an error. Also pins the root-logger
    'Unhandled exception' line with exc_info (the traceback survives)."""
    with caplog.at_level(logging.INFO, logger="audit"):
        response = guest_client.get(boom_route)

    assert response.status_code == 500
    header_rid = response.headers["X-Request-ID"]
    # Audit middleware format: 16-hex-char uuid4 prefix.
    assert re.fullmatch(r"[0-9a-f]{16}", header_rid)

    audit_records = [
        r for r in caplog.records
        if r.name == "audit"
        and r.getMessage() == "Request failed with unhandled exception"
    ]
    assert len(audit_records) == 1
    assert audit_records[0].request_id == header_rid

    root_records = [
        r for r in caplog.records
        if r.getMessage() == "Unhandled exception: kaboom"
    ]
    assert len(root_records) == 1
    assert root_records[0].levelno == logging.ERROR
    assert root_records[0].exc_info  # traceback attached
    assert root_records[0].request_id == header_rid


# ---------------------------------------------------------------------------
# Branded 404 / 422 pages (pass through set_secure_headers normally)
# ---------------------------------------------------------------------------

def test_404_branded_page_carries_csp_and_request_id(guest_client):
    """Unmatched path → not_found_handler renders the branded error page.
    404s are raised inside ExceptionMiddleware, so the response passes
    through set_secure_headers (CSP) and audit (X-Request-ID) — verifying
    the backlog §2.16 'verify' note that these need no special handling."""
    response = guest_client.get("/no-such-page")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Page not found" in response.text
    assert "Content-Security-Policy" in response.headers
    assert "X-Request-ID" in response.headers


def test_422_branded_page_carries_csp_and_logs_warning(guest_client, caplog):
    """Path-param coercion failure → validation_error_handler renders the
    branded 'Invalid request' page (not FastAPI's default JSON), carries
    CSP, and emits a root-logger WARNING 'Validation error' naming the
    offending path (ops visibility for malformed-request probing)."""
    with caplog.at_level(logging.WARNING):
        response = guest_client.get("/dataset/not-an-int")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")
    assert "Invalid request" in response.text
    assert "Content-Security-Policy" in response.headers

    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and r.getMessage() == "Validation error on /dataset/not-an-int"
    ]
    assert len(warnings) == 1
    assert warnings[0].path == "/dataset/not-an-int"


def test_error_page_renders_with_flash_none(boom_route, guest_client):
    """§2.8 error-path guard: error.html extends base.html whose
    '{% if flash %}' must tolerate flash=None — regression guard for the
    'cannot unpack None' crash that once took down the 500 handler itself.
    The successful renders above prove no crash; here we also assert the
    flash <div class="auth-..."> markup is absent when no flash is set."""
    for path, status in ((boom_route, 500), ("/no-such-page", 404)):
        response = guest_client.get(path)
        assert response.status_code == status
        assert '<div class="auth-' not in response.text


# ---------------------------------------------------------------------------
# Cache-Control: no-store scoping (set_secure_headers happy path)
# ---------------------------------------------------------------------------

def test_authenticated_page_gets_no_store(authenticated_client):
    """Authenticated non-static pages must not be browser-cached: /account
    (restricted personal data) gets Cache-Control: no-store from
    set_secure_headers."""
    response = authenticated_client.get("/account")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_guest_page_is_not_no_stored(guest_client):
    """Guests are NOT no-stored: public pages stay cacheable. GET / with the
    page services patched out (the harness pool fails loudly on real
    queries) → 200 without any Cache-Control header. Guards against the
    no-store scope silently widening to anonymous traffic."""
    with patch("app.routes.pages.get_recent_datasets",
        autospec=True, return_value=([], 0)), \
         patch("app.routes.pages.get_last_full_rebuild_date",
        autospec=True, return_value=None), \
         patch("app.routes.pages.get_keyword_count",
        autospec=True, return_value=0):
        response = guest_client.get("/")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") != "no-store"
    assert "Cache-Control" not in response.headers


def test_static_asset_not_no_stored_even_when_authenticated(authenticated_client):
    """Static assets are excluded from no-store even for authenticated users
    (fonts/CSS must cache normally); the /static/ prefix check in
    set_secure_headers is the guard. Uses the real shipped stylesheet."""
    response = authenticated_client.get("/static/css/style.css")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") != "no-store"
