"""Error handling — 500s carry security headers; branded 404/422 pages.

Bare-``Exception`` handlers run in ServerErrorMiddleware, *outside* the user
middleware stack, so a 500 would bypass ``set_secure_headers`` entirely
unless ``unhandled_exception_handler`` re-applies CSP + ``Cache-Control:
no-store`` + ``X-Request-ID`` itself. Only an actually-raised exception
proves this framework-interaction behavior, hence the ``/__test_boom`` route
registered below.

Also covers: branded 404/422 pages (which DO pass through
``set_secure_headers`` via ExceptionMiddleware), the guard that
``error.html`` renders when flash is None, and the no-store scoping rules.
Authenticated pages and anonymous action-capability pages are never stored;
ordinary guest pages and static assets stay cacheable.
"""

import logging
import re
from contextlib import ExitStack
from unittest.mock import patch

import pytest
from psycopg_pool import PoolTimeout, TooManyRequests

from app.main import app
from app.route_security import RouteAccess, SecureAPIRouter

BOOM_PATH = "/__test_boom"


@pytest.fixture(scope="module")
def boom_route():
    """Temporarily install a protected, policy-classified failure route."""
    original_routes = list(app.router.routes)
    router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

    @router.get(BOOM_PATH)
    async def boom():  # pragma: no cover - body IS the test payload
        raise RuntimeError("kaboom")

    app.include_router(router)
    try:
        yield BOOM_PATH
    finally:
        app.router.routes[:] = original_routes


# ---------------------------------------------------------------------------
# Unhandled exception → 500 with security headers
# ---------------------------------------------------------------------------


def test_unhandled_500_carries_security_headers(boom_route, authenticated_client):
    """The 500 from ServerErrorMiddleware runs OUTSIDE
    set_secure_headers, so the handler must re-apply CSP itself, force
    Cache-Control: no-store (an authenticated user's error page must not be
    cached), and attach X-Request-ID for log correlation."""
    response = authenticated_client.get(boom_route)

    assert response.status_code == 500
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert "X-Request-ID" in response.headers
    # Branded page, not a bare traceback / JSON blob.
    assert "Internal Server Error" in response.text


def test_unhandled_500_request_id_correlates_with_audit_log(
    boom_route, authenticated_client, caplog
):
    """The X-Request-ID response header must equal the request_id on
    the audit 'Request failed with unhandled exception' record — the whole
    point of shipping the id on error responses is log<->response
    correlation when a user reports an error. Also pins the root-logger
    'Unhandled exception' line with exc_info (the traceback survives)."""
    with caplog.at_level(logging.INFO, logger="audit"):
        response = authenticated_client.get(boom_route)

    assert response.status_code == 500
    header_rid = response.headers["X-Request-ID"]
    # Audit middleware format: 16-hex-char uuid4 prefix.
    assert re.fullmatch(r"[0-9a-f]{16}", header_rid)

    audit_records = [
        r
        for r in caplog.records
        if r.name == "audit" and r.getMessage() == "Request failed with unhandled exception"
    ]
    assert len(audit_records) == 1
    assert audit_records[0].request_id == header_rid

    root_records = [
        r
        for r in caplog.records
        if r.name == "app.main" and r.getMessage() == "Unhandled exception"
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
    the framework-routed 404/422 paths need no special handling."""
    response = guest_client.get("/no-such-page")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Page not found" in response.text
    assert "Content-Security-Policy" in response.headers
    assert "X-Request-ID" in response.headers


def test_422_branded_page_carries_csp_and_logs_warning(guest_client, caplog):
    """Path-param coercion failure → validation_error_handler renders the
    branded 'Invalid request' page (not FastAPI's default JSON), carries
    CSP, and emits a structured root-logger WARNING naming only the matched
    route template (ops visibility without persisting attacker input)."""
    with caplog.at_level(logging.WARNING):
        response = guest_client.get("/dataset/not-an-int")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")
    assert "Invalid request" in response.text
    assert "Content-Security-Policy" in response.headers

    warnings = [
        r
        for r in caplog.records
        if r.name == "app.main"
        and r.levelno == logging.WARNING
        and r.getMessage() == "Request validation failed"
    ]
    assert len(warnings) == 1
    assert warnings[0].path == "/dataset/{dataset_id}"


def test_error_page_renders_with_flash_none(boom_route, authenticated_client):
    """error.html extends base.html whose
    '{% if flash %}' must tolerate flash=None — a guard against the
    'cannot unpack None' crash that once took down the 500 handler itself.
    The successful renders above prove no crash; here we also assert the
    flash <div class="auth-..."> markup is absent when no flash is set."""
    for path, status in ((boom_route, 500), ("/no-such-page", 404)):
        response = authenticated_client.get(path)
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


def test_guest_dynamic_page_is_no_stored(guest_client):
    """All dynamic catalogue pages are no-store, including anonymous pages.

    This is deliberate: a browser or intermediary must not retain a dynamic
    page after a withdrawal, a later tier change, or use on a shared device.
    Static assets remain the only cacheable application responses.
    """
    with (
        patch(
            "app.routes.pages.get_recent_datasets",
            autospec=True,
            return_value=[],
        ),
        patch(
            "app.routes.pages.get_facets",
            autospec=True,
            return_value={
                "keywords": [],
                "languages": [],
                "access_levels": [],
            },
        ),
        patch(
            "app.routes.pages.get_home_metadata_counts",
            autospec=True,
            return_value=(0, 0),
        ),
    ):
        response = guest_client.get("/")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_static_asset_not_no_stored_even_when_authenticated(authenticated_client):
    """Static assets are excluded from no-store even for authenticated users
    (fonts/CSS must cache normally); the /static/ prefix check in
    set_secure_headers is the guard. Uses the real shipped stylesheet."""
    response = authenticated_client.get("/static/css/style.css")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") != "no-store"


# ---------------------------------------------------------------------------
# Action capabilities are neither cached nor disclosed by Referer
# ---------------------------------------------------------------------------


def _assert_sensitive_action_headers(response):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize(
    ("path", "patches"),
    [
        pytest.param(
            "/reset-password/live-reset-capability-token",
            [
                (
                    "app.routes.auth.password_reset.validate_reset_token",
                    {"return_value": {"user_id": 7, "email": "alice@example.org"}},
                ),
                (
                    "app.routes.auth.password_reset.verify_reset_token_hash",
                    {"return_value": True},
                ),
            ],
            id="password-reset",
        ),
        pytest.param(
            "/verify-email/live-verification-capability-token",
            [
                (
                    "app.routes.auth.verify_email.validate_verification_token",
                    {"return_value": {"user_id": 7, "email": "alice@example.org"}},
                ),
            ],
            id="email-verification",
        ),
        pytest.param(
            "/account/confirm-email/live-email-change-capability-token",
            [
                (
                    "app.routes.auth.email_change.validate_email_change_token",
                    {
                        "return_value": {
                            "user_id": 7,
                            "new_email": "new@example.org",
                            "acting_admin_id": None,
                            "auth_revision": 0,
                        }
                    },
                ),
                (
                    "app.routes.auth.email_change.pending_email_change_matches",
                    {"return_value": True},
                ),
            ],
            id="email-change",
        ),
    ],
)
def test_action_capability_pages_are_no_store_and_no_referrer(
    guest_client,
    path,
    patches,
):
    """A successful action landing page contains a live credential.

    Even for an anonymous visitor, it must not enter a browser/shared cache or
    be copied into same-origin static-request Referer headers.
    """
    with ExitStack() as stack:
        for target, kwargs in patches:
            stack.enter_context(patch(target, autospec=True, **kwargs))
        response = guest_client.get(path)

    assert response.status_code == 200
    _assert_sensitive_action_headers(response)


@pytest.mark.parametrize(
    "route_prefix",
    ["/reset-password", "/verify-email", "/account/confirm-email"],
    ids=["password-reset", "email-verification", "email-change"],
)
def test_a_rejected_capability_link_keeps_the_same_headers(guest_client, route_prefix):
    """The everyday case is a link that no longer works — followed late, or
    already used. That response still discloses which capability was
    attempted, and the browser reached it from a URL carrying the credential,
    so it needs the same cache and referrer treatment as a successful one."""
    response = guest_client.get(f"{route_prefix}/expired-or-forged-capability-token")

    assert response.status_code != 200
    _assert_sensitive_action_headers(response)


def test_reset_password_csrf_rejection_gets_sensitive_action_headers(guest_client):
    """The action-page header guarantee holds even on an early CSRF 403,
    before the route handler itself ever runs."""
    response = guest_client.post(
        "/reset-password",
        data={
            "token": "live-reset-capability-token",
            "password": "Long-enough-password-1!",
            "password_confirm": "Long-enough-password-1!",
            # Deliberately omit csrf_token.
        },
    )

    assert response.status_code == 403
    _assert_sensitive_action_headers(response)


def test_reset_password_content_type_rejection_gets_sensitive_action_headers(guest_client):
    """The content-type dependency can short-circuit before route execution."""
    response = guest_client.post(
        "/reset-password",
        content='{"token":"live-reset-capability-token"}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 415
    _assert_sensitive_action_headers(response)


def test_reset_password_validation_error_gets_sensitive_action_headers(guest_client):
    """Framework-generated 422 responses retain action-page protections."""
    response = guest_client.post(
        "/reset-password",
        data={"csrf_token": guest_client.csrf_token},
    )

    assert response.status_code == 422
    _assert_sensitive_action_headers(response)


def test_sensitive_action_500_gets_no_store_and_no_referrer(guest_client):
    """The outer 500 handler must reapply both action-specific headers."""
    with (
        patch(
            "app.routes.auth.password_reset.validate_reset_token",
            autospec=True,
            return_value={"user_id": 7, "email": "alice@example.org"},
        ),
        patch(
            "app.routes.auth.password_reset.verify_reset_token_hash",
            autospec=True,
            side_effect=RuntimeError("synthetic action-page failure"),
        ),
    ):
        response = guest_client.get("/reset-password/live-reset-capability-token")

    assert response.status_code == 500
    _assert_sensitive_action_headers(response)


# ---------------------------------------------------------------------------
# Branded 405 with the RFC-9110-required Allow header
# ---------------------------------------------------------------------------


def test_get_on_post_only_route_is_branded_405_with_allow_header(guest_client):
    """main.py's 405 handler is registered, documented (RFC 9110 section
    15.5.6 requires the Allow header on a 405), and was otherwise untested —
    404/422/500 all had branded-page tests, 405 did not. /logout is
    POST-only, so a GET is the probe."""
    resp = guest_client.get("/logout", follow_redirects=False)

    assert resp.status_code == 405
    assert resp.headers["content-type"].startswith("text/html")
    assert "only accepts form submissions" in resp.text  # branded, not JSON
    assert "POST" in resp.headers.get("Allow", "")  # THE RFC assertion
    assert resp.headers.get("Content-Security-Policy")  # headers still applied
    assert resp.headers.get("X-Request-ID")


# ---------------------------------------------------------------------------
# Pool-capacity exhaustion from an ordinary route service
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def capacity_boom_route():
    """A protected route whose handler raises whatever exception the test
    stores in the returned mutable holder — reused across the parametrized
    exception types below and the unrelated-exception control."""
    original_routes = list(app.router.routes)
    router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
    holder: dict[str, BaseException] = {"exc": RuntimeError("unset")}

    @router.get("/__test_capacity_boom")
    async def capacity_boom():  # pragma: no cover - body IS the test payload
        raise holder["exc"]

    app.include_router(router)
    try:
        yield "/__test_capacity_boom", holder
    finally:
        app.router.routes[:] = original_routes


@pytest.mark.parametrize(
    "exception",
    [PoolTimeout("pool exhausted"), TooManyRequests("queue full")],
    ids=["pool_timeout", "too_many_requests"],
)
def test_pool_capacity_exhaustion_from_a_route_service_is_a_controlled_503(
    capacity_boom_route, authenticated_client, exception
):
    """A saturated connection pool is an operational capacity condition, not
    an application bug: it must render a 503 with Retry-After and
    Cache-Control: no-store so a client or load balancer can back off."""
    path, holder = capacity_boom_route
    holder["exc"] = exception

    response = authenticated_client.get(path)

    assert response.status_code == 503
    assert "Retry-After" in response.headers
    assert response.headers["Cache-Control"] == "no-store"


def test_unrelated_exception_from_the_same_route_is_the_generic_500_and_hides_its_text(
    capacity_boom_route, authenticated_client
):
    """Positive control: an ordinary bug (not a capacity condition) from the
    identical route correctly renders today's generic 500, and its message
    text never reaches the client — this passes today and must keep passing
    once the capacity mapping above is implemented."""
    path, holder = capacity_boom_route
    marker = "unrelated-failure-marker-64f1"
    holder["exc"] = RuntimeError(marker)

    response = authenticated_client.get(path)

    assert response.status_code == 500
    assert marker not in response.text
