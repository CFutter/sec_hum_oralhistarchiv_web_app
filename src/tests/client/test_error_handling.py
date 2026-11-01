"""Error handling — 500s carry security headers; branded 404/422 pages."""

import logging
import re
from unittest.mock import patch

import pytest
from psycopg_pool import PoolTimeout, TooManyRequests

from app.main import app
from app.route_security import RouteAccess, SecureAPIRouter
from app.services.tokens import action_token_public_id

BOOM_PATH = "/__test_boom"


@pytest.fixture(scope="module")
def boom_route():
    """Temporarily install a protected, policy-classified failure route."""
    original_routes = list(app.router.routes)
    router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

    @router.get(BOOM_PATH)
    async def boom():  # pragma: no cover - body IS the test payload
        """Raise the sentinel RuntimeError from a real endpoint."""
        raise RuntimeError("kaboom")

    app.include_router(router)
    try:
        yield BOOM_PATH
    finally:
        app.router.routes[:] = original_routes


def test_unhandled_500_carries_security_headers(boom_route, authenticated_client):
    """Require an actual unhandled 500 response to retain CSP, no-store, and request correlation."""
    response = authenticated_client.get(boom_route)

    assert response.status_code == 500
    assert "Content-Security-Policy" in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert "X-Request-ID" in response.headers
    assert "Internal Server Error" in response.text


def test_unhandled_500_request_id_correlates_with_audit_log(
    boom_route, authenticated_client, caplog
):
    """Require response, request-audit, and structured exception records to share the request ID."""
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
    assert root_records[0].exc_info
    assert root_records[0].request_id == header_rid


def test_404_branded_page_carries_csp_and_request_id(guest_client):
    """Require branded 404 responses to retain CSP and request correlation."""
    response = guest_client.get("/no-such-page")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Page not found" in response.text
    assert "Content-Security-Policy" in response.headers
    assert "X-Request-ID" in response.headers


def test_422_branded_page_carries_csp_and_logs_warning(guest_client, caplog):
    """Require branded validation errors to log the route template without attacker input."""
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
    """Render the error page without flash markup when no flash exists."""
    for path, status in ((boom_route, 500), ("/no-such-page", 404)):
        response = authenticated_client.get(path)
        assert response.status_code == status
        assert '<div class="auth-' not in response.text


def test_authenticated_page_gets_no_store(authenticated_client):
    """Authenticated non-static pages must not be browser-cached: /account
    (restricted personal data) gets Cache-Control: no-store from
    set_secure_headers."""
    response = authenticated_client.get("/account")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_guest_dynamic_page_is_no_stored(guest_client):
    """All dynamic catalogue pages are no-store, including anonymous pages."""
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
    ):
        response = guest_client.get("/")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_static_asset_not_no_stored_even_when_authenticated(authenticated_client):
    """Check static asset not no stored even when authenticated (HTTP 200)."""
    response = authenticated_client.get("/static/css/style.css")

    assert response.status_code == 200
    assert response.headers.get("Cache-Control") != "no-store"


def _assert_sensitive_action_headers(response):
    """Require uncached responses with the strict-origin referrer policy."""
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "strict-origin"


@pytest.mark.parametrize(
    ("path", "patches"),
    [
        pytest.param("/reset-password/live-reset-capability-token", [], id="password-reset"),
        pytest.param(
            "/verify-email/live-verification-capability-token", [], id="email-verification"
        ),
        pytest.param(
            "/account/confirm-email/live-email-change-capability-token", [], id="email-change"
        ),
    ],
)
def test_action_capability_pages_are_no_store_with_origin_only_referrers(
    guest_client, path, patches
):
    """Generic action landing forms retain privacy without resolving their identifier."""
    del patches
    prefix, _, token = path.rpartition("/")
    response = guest_client.get(f"{prefix}/{action_token_public_id(token)}")
    assert response.status_code == 200
    assert token not in response.text and "alice@example.org" not in response.text
    guest_client.mock_pool.connection.assert_not_called()
    _assert_sensitive_action_headers(response)


@pytest.mark.parametrize(
    "route_prefix",
    ["/reset-password", "/verify-email", "/account/confirm-email"],
    ids=["password-reset", "email-verification", "email-change"],
)
def test_a_rejected_capability_link_keeps_the_same_headers(guest_client, route_prefix):
    """Malformed public identifiers return the same privacy headers as valid forms."""
    response = guest_client.get(f"{route_prefix}/expired-or-forged-capability-token")

    assert response.status_code == 404
    _assert_sensitive_action_headers(response)


def test_reset_password_csrf_rejection_gets_sensitive_action_headers(guest_client):
    """The action-page header guarantee holds even on an early CSRF 403,
    before the route handler itself ever runs."""
    response = guest_client.post(
        "/reset-password",
        data={
            "token": "live-reset-capability-token",
            "public_id": action_token_public_id("live-reset-capability-token"),
            "password": "Long-enough-password-1!",
            "password_confirm": "Long-enough-password-1!",
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
    """Only a POST contains the secret and can reach a capability-storage failure."""
    token = "live-reset-capability-token"
    with (
        patch(
            "app.routes.auth.password_reset.validate_reset_token",
            autospec=True,
            return_value={"user_id": 7, "email": "alice@example.org"},
        ),
        patch(
            "app.routes.auth.password_reset.update_password_with_token",
            autospec=True,
            side_effect=RuntimeError("synthetic action-page failure"),
        ),
    ):
        response = guest_client.post(
            "/reset-password",
            data={
                "token": token,
                "public_id": action_token_public_id(token),
                "password": "Long-enough-password-1!",
                "password_confirm": "Long-enough-password-1!",
                "totp_code": "123456",
                "csrf_token": guest_client.csrf_token,
            },
        )
    assert response.status_code == 500
    _assert_sensitive_action_headers(response)


def test_get_on_post_only_route_is_branded_405_with_allow_header(guest_client):
    """Require a branded 405 response with Allow for GET on the POST-only logout route."""
    resp = guest_client.get("/logout", follow_redirects=False)

    assert resp.status_code == 405
    assert resp.headers["content-type"].startswith("text/html")
    assert "only accepts form submissions" in resp.text
    assert "POST" in resp.headers.get("Allow", "")
    assert resp.headers.get("Content-Security-Policy")
    assert resp.headers.get("X-Request-ID")


@pytest.fixture(scope="module")
def capacity_boom_route():
    """Install a temporary protected route and yield a holder selecting the exception it raises."""
    original_routes = list(app.router.routes)
    router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
    holder: dict[str, BaseException] = {"exc": RuntimeError("unset")}

    @router.get("/__test_capacity_boom")
    async def capacity_boom():  # pragma: no cover - body IS the test payload
        """Raise the selected capacity exception from the probe endpoint."""
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
    """Map pool capacity exhaustion to an uncached 503 with retry guidance."""
    path, holder = capacity_boom_route
    holder["exc"] = exception

    response = authenticated_client.get(path)

    assert response.status_code == 503
    assert "Retry-After" in response.headers
    assert response.headers["Cache-Control"] == "no-store"


def test_unrelated_exception_from_the_same_route_is_the_generic_500_and_hides_its_text(
    capacity_boom_route, authenticated_client
):
    """Return a generic 500 without the unrelated exception message."""
    path, holder = capacity_boom_route
    marker = "unrelated-failure-marker-64f1"
    holder["exc"] = RuntimeError(marker)

    response = authenticated_client.get(path)

    assert response.status_code == 500
    assert marker not in response.text
