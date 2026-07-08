"""Rate limiting behavior — backlog §5.1, §5.2 (comment), §5.3, §2.15.

Covers the sync-handler landmine (default-limit breaches must render the
branded error page, not slowapi's JSON), the Retry-After header derivation,
and the /health rate-limit exemption vs. the /health/detail backstop.

Test-env default limits (set in the root conftest): 30/minute;1000/hour;
10000/day. The autouse ``_reset_rate_limiter`` fixture clears the in-memory
counters between tests, so every test starts from a clean window. All
TestClient requests share one client IP ("testclient"), and slowapi scopes
the default-limit counters per path.
"""
import asyncio
import importlib
import logging
from contextlib import ExitStack
from unittest.mock import patch

import pytest


def test_default_limit_breach_renders_branded_429_with_retry_after_and_log(
    guest_client, caplog
):
    """§5.1 + §5.3: an UNDECORATED route past the 30/minute default limit gets
    the branded HTML 429 (rate_limit_handler), the audit WARNING, and a
    Retry-After header of the limit's window (60s for a per-minute limit).

    Regression guard for the sync-handler landmine: slowapi's
    SlowAPIMiddleware enforces DEFAULT limits via sync_check_limits, which
    only uses the app-registered RateLimitExceeded handler if it is NOT a
    coroutine function — otherwise it silently falls back to slowapi's plain
    JSON ``{"error": "Rate limit exceeded: ..."}`` responder. If someone
    "cleans up" rate_limit_handler into ``async def``, nothing crashes; the
    branded page, the warning log, and the Retry-After header just vanish for
    every default-limit breach — and THIS test fails.

    §5.3 regression guard: the header comes from
    ``str(exc.limit.limit.get_expiry())``. The old
    ``getattr(exc, "retry_after", None)`` read an attribute RateLimitExceeded
    never has, so the header was silently never sent.
    """
    with caplog.at_level(logging.WARNING):
        # /about has no @limiter.limit decorator -> governed by the default
        # limits, enforced by SlowAPIMiddleware (the sync-handler code path).
        for i in range(30):
            response = guest_client.get("/about")
            assert response.status_code == 200, f"request {i + 1} unexpectedly limited"

        response = guest_client.get("/about")

    assert response.status_code == 429

    # Branded error.html, NOT slowapi's JSON fallback.
    assert response.headers["content-type"].startswith("text/html")
    assert "Too many requests" in response.text
    # slowapi's default handler body is {"error": "Rate limit exceeded: ..."} —
    # its presence would mean the sync handler was bypassed.
    assert "Rate limit exceeded" not in response.text

    # §5.3: Retry-After == the tripped limit's window in seconds. The
    # 30/minute default is the limit that breaks first -> 60.
    assert response.headers.get("Retry-After") == "60"

    # The handler's observability side effect: a WARNING on the root-propagated
    # app.main logger naming the rate-limited path.
    warning_messages = [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
    ]
    assert "Rate limit exceeded on /about" in warning_messages


def test_rate_limit_handler_must_stay_sync():
    """§5.1 structural tripwire (belt and braces; the behavioral test above is
    primary).

    Quoting the MUST-stay-def comment in app/main.py: "MUST stay `def` (sync):
    slowapi's SlowAPIMiddleware ignores coroutine handlers for default-limit
    breaches and falls back to its own JSON handler (see
    slowapi.middleware.sync_check_limits)." Verified against pinned slowapi
    0.1.9: sync_check_limits swaps in _rate_limit_exceeded_handler whenever
    inspect.iscoroutinefunction(exception_handler) is true.
    """
    import app.main

    assert not asyncio.iscoroutinefunction(app.main.rate_limit_handler), (
        "rate_limit_handler became a coroutine function — slowapi's middleware "
        "will silently replace it with the plain-JSON default for every "
        "default-limit breach (branded page, warning log, and Retry-After all "
        "disappear)."
    )


def test_decorated_login_limit_governs_and_carries_retry_after(guest_client):
    """§5.3 on a DECORATED route: POST /login is @limiter.limit("5/minute;20/hour"),
    so the 6th attempt in a minute is a 429 carrying Retry-After "60" (the
    5/minute window) and the branded error page.

    §5.2 note (documented behavior): a per-route @limiter.limit REPLACES the
    global default rather than stacking — /login trips at request 6, governed
    by its own 5/minute, not at request 31 under the 30/minute default. The
    breach here is raised by the route decorator (not the middleware), so it
    reaches rate_limit_handler through Starlette's ExceptionMiddleware, which
    proves the same handler brands decorated-route 429s too.
    """
    with patch(
        "app.routes.auth.login.verify_password",
        autospec=True, return_value=(None, False, None),
    ):
        form = {
            "email": "alice@uzh.ch",
            "password": "wrong-password",
            "totp_code": "",
            "csrf_token": guest_client.csrf_token,
        }
        for i in range(5):
            response = guest_client.post("/login", data=form)
            # 401 (login error page), not 403 — proves the CSRF pair was valid
            # and the request really reached the credential check.
            assert response.status_code == 401, f"attempt {i + 1}: {response.status_code}"

        response = guest_client.post("/login", data=form)

    assert response.status_code == 429
    assert response.headers.get("Retry-After") == "60"
    assert response.headers["content-type"].startswith("text/html")
    assert "Too many requests" in response.text


def test_health_is_exempt_from_rate_limits(guest_client):
    """§2.15: /health is @limiter.exempt — polling it far past the 30/minute
    default limit never yields a 429.

    Regression guard for "/health silently became rate-limited again": an
    uptime monitor polling every 5s (~17k/day) would otherwise flap to 429 by
    design. Safe to exempt because /health is DB-free liveness (§2.14) —
    nothing to amplify.
    """
    for i in range(40):
        response = guest_client.get("/health")
        assert response.status_code == 200, (
            f"/health request {i + 1} returned {response.status_code} — the "
            "rate-limit exemption is gone and monitoring will flap"
        )
        assert response.json() == {"status": "alive"}


# ---------------------------------------------------------------------------
# TEST-009 / TEST-039 — every abuse-sensitive endpoint's per-route limit is
# PINNED (before this, only /login's 5/minute had a test; deleting any other
# @limiter.limit decorator shipped green)
# ---------------------------------------------------------------------------

# (fixture, method, path, per-window trip count, form fields or None,
#  service patches needed so the handler runs cleanly against the mock pool)
#
# The trip count is the FIRST limit component that binds within one minute
# (e.g. "3/hour" also trips at the 4th call inside a minute). Every request
# must actually REACH the handler (valid CSRF, parseable form) — slowapi
# counts at handler entry, so a request rejected by a dependency (403/422
# from framework validation) would not consume the budget.
ENDPOINT_LIMITS = [
    ("guest_client", "POST", "/register", 3,
     {"email": "not-an-email", "display_name": "Probe",
      "password": "x-Yz1!x-Yz1!", "password_confirm": "x-Yz1!x-Yz1!"}, []),
    ("guest_client", "POST", "/send_verification", 3,
     {"email": "not-an-email"}, []),
    ("guest_client", "POST", "/forgot-password", 3,
     {"email": "not-an-email"}, []),
    ("guest_client", "GET", "/reset-password/garbage-token", 10, None, []),
    ("guest_client", "POST", "/reset-password/garbage-token", 5,
     {"password": "x-Yz1!x-Yz1!", "password_confirm": "x-Yz1!x-Yz1!"}, []),
    ("guest_client", "GET", "/verify-email/garbage-token", 10, None, []),
    ("guest_client", "POST", "/verify-email", 10, {"token": "garbage"}, []),
    ("authenticated_client", "POST", "/account/change-email", 5,
     {"new_email": "n@uzh.ch", "current_password": "wrong"},
     [("app.routes.auth.email_change.verify_current_password",
       {"return_value": False})]),
    ("authenticated_client", "GET", "/setup-totp", 10, None, []),
    ("authenticated_client", "POST", "/setup-totp", 5, {"totp_code": "000000"},
     [("app.routes.auth.totp.get_pending_totp_secret", {"return_value": None})]),
    ("authenticated_client", "GET", "/account/reset-totp", 10, None,
     [("app.routes.auth.totp.get_totp_secret", {"return_value": None})]),
    ("authenticated_client", "POST", "/account/reset-totp", 5,
     {"current_totp_code": "000000", "new_totp_code": "000000"},
     [("app.routes.auth.totp.get_totp_secret", {"return_value": None})]),
]


@pytest.mark.parametrize(
    ("fixture", "method", "path", "limit", "form", "patches"),
    ENDPOINT_LIMITS,
    ids=[f"{m}-{p}-{n}" for _, m, p, n, _, _ in ENDPOINT_LIMITS],
)
def test_per_route_limit_is_pinned(request, fixture, method, path, limit,
                                   form, patches):
    """N requests inside the window are NOT 429 (control: the limit isn't
    tighter than documented), the N+1th IS 429 (the decorator exists and
    binds). Removing or loosening any per-route @limiter.limit fails here."""
    client = request.getfixturevalue(fixture)
    with ExitStack() as stack:
        for target, kwargs in patches:
            stack.enter_context(patch(target, autospec=True, **kwargs))

        def hit():
            if method == "GET":
                return client.get(path, follow_redirects=False)
            data = {**form, "csrf_token": client.csrf_token}
            return client.post(path, data=data, follow_redirects=False)

        for i in range(limit):
            resp = hit()
            assert resp.status_code != 429, (
                f"request {i + 1}/{limit} already limited — the route's limit "
                f"is TIGHTER than the documented {limit}/window"
            )
        resp = hit()

    assert resp.status_code == 429, (
        f"request {limit + 1} was not limited — the per-route limit on "
        f"{method} {path} is gone or looser than {limit}/window"
    )
    assert "Too many requests" in resp.text  # branded handler, not JSON


def test_rotating_forwarded_headers_share_one_counter(guest_client):
    """TEST-010 — the XFF-spoof bypass: with RATE_LIMIT_TRUST_PROXY false and
    an untrusted peer ('testclient'), X-Forwarded-For MUST be ignored by the
    limiter's key_func. If a cleanup swaps key_func to a header-trusting
    helper (slowapi.util.get_ipaddr), every attacker bypasses every limit by
    rotating a header — and this test's 31 distinct-XFF requests would all
    land in separate buckets and never 429."""
    statuses = [
        guest_client.get("/about", headers={"X-Forwarded-For": f"9.9.9.{i}"})
        .status_code
        for i in range(31)
    ]
    assert 429 in statuses, (
        "rotating X-Forwarded-For evaded the shared 30/minute bucket — "
        "the limiter key_func is trusting client-controlled headers"
    )


def test_limiter_storage_uri_uses_redis_when_enabled(monkeypatch):
    """TEST-039 — the multi-worker wiring branch: with redis_enabled=True the
    module-level limiter must be constructed with storage_uri = the REAL
    redis URL string (SecretStr unwrapped), not the memory:// fallback that
    silently gives every gunicorn worker its own counters (N× the ceiling).

    The module builds the limiter at import, so this reloads it under
    patched settings and restores the original limiter object afterwards
    (the route decorators hold references to the original instance)."""
    from pydantic import SecretStr

    import app.middleware.rate_limiting as rl
    from config import settings

    original_limiter = rl.limiter
    monkeypatch.setattr(settings, "redis_enabled", True)
    monkeypatch.setattr(settings, "redis_url", SecretStr("redis://fake-host:6379/9"))
    try:
        reloaded = importlib.reload(rl)
        assert reloaded.limiter._storage_uri == "redis://fake-host:6379/9"
    finally:
        monkeypatch.undo()
        importlib.reload(rl)
        # Reload minted ANOTHER limiter; restore the instance the app's route
        # decorators (and the autouse reset fixture) actually use.
        rl.limiter = original_limiter


def test_limiter_storage_uri_is_memory_when_redis_disabled():
    """Control for the wiring test: the test env (REDIS_ENABLED=false) runs
    on the in-process memory backend."""
    from app.middleware.rate_limiting import limiter

    assert limiter._storage_uri == "memory://"


# ---------------------------------------------------------------------------
# TEST-022 / TEST-023 — what a throttle event looks like to an operator
# ---------------------------------------------------------------------------

def test_throttle_log_carries_real_client_ip_and_request_id(guest_client, caplog):
    """TEST-022 — the rate_limit_handler's own WARNING must carry the actual
    client ip (via get_client_ip), not a hardcoded-fallback 'unknown': an
    operator investigating abuse reads exactly this line. (This pinned a live
    bug: the handler read request.state.client_ip, which nothing ever set.)"""
    with caplog.at_level(logging.WARNING):
        for _ in range(31):
            resp = guest_client.get("/about")
    assert resp.status_code == 429

    rec = next(
        r for r in caplog.records
        if r.getMessage().startswith("Rate limit exceeded")
    )
    assert rec.client_ip == "testclient", (
        f"throttle log carries client_ip={rec.client_ip!r} — operators "
        "cannot see the offending IP"
    )
    assert rec.request_id not in (None, "unknown")


def test_429_response_is_audited_with_request_id(guest_client, caplog):
    """TEST-023 — audit middleware is registered OUTSIDE rate limiting so
    the abuse traffic you most need logged is captured: the 429 response
    carries X-Request-ID and the audit channel records the request with
    status_code 429. Reordering the two setup_* calls in main.py loses both."""
    with caplog.at_level(logging.INFO, logger="audit"):
        for _ in range(31):
            resp = guest_client.get("/about")
    assert resp.status_code == 429
    assert resp.headers.get("X-Request-ID"), "429 lost its X-Request-ID"

    audited_429s = [
        r for r in caplog.records
        if r.name == "audit"
        and getattr(r, "status_code", None) == 429
        and getattr(r, "path", None) == "/about"
    ]
    assert audited_429s, "the 429 never reached the audit middleware"
    assert audited_429s[0].request_id == resp.headers["X-Request-ID"]


def test_health_detail_keeps_the_default_limit_backstop(guest_client):
    """§2.15: /health/detail still enforces the 30/minute default limit — the
    31st unauthorized probe from one IP is a 429. The /health vs /health/detail
    asymmetry is intentional: detail is token-gated and runs DB queries, so
    the default limit stays on as an anti-probing backstop.

    Unauthorized requests (no Bearer token, FASTAPI_DEBUG=false in the test
    env) get the fail-secure 404 — which still counts against the limit.
    """
    for i in range(30):
        response = guest_client.get("/health/detail")
        assert response.status_code == 404, f"request {i + 1}: {response.status_code}"

    response = guest_client.get("/health/detail")
    assert response.status_code == 429
    # Same branded handler + Retry-After as every other breach (§5.1/§5.3).
    assert response.headers.get("Retry-After") == "60"
    assert "Too many requests" in response.text
