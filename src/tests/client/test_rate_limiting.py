"""Rate limiting behavior at the route layer, exercised through real
requests over the full middleware stack (``app.middleware.rate_limiting``).

Covers the branded default-limit and decorator-limit 429 responses, the
client-facing headers a throttled response carries, the per-route abuse
limits pinned on every sensitive endpoint, the ``/health`` exemption versus
the ``/health/detail`` backstop, the client-identity/storage wiring, and what
a throttle event looks like to an operator.

Test-env default limits (set in the root conftest): 30/minute;1000/hour;
10000/day. The autouse ``_reset_rate_limiter`` fixture clears the in-memory
counters between tests, so every test starts from a clean window. All
TestClient requests share one client IP ("testclient"), and slowapi scopes
the default-limit counters per path.
"""

import importlib
import logging
from contextlib import ExitStack
from unittest.mock import create_autospec, patch

import pytest
from pydantic import SecretStr

import app.middleware.rate_limiting as rl
from app.services.authentication import PasswordCheck
from app.services.datasets import search_datasets as _real_search_datasets
from app.services.email_change import SelfEmailChangeResult
from app.services.totp import (
    TotpEnrollmentOutcome,
    TotpRotationStartOutcome,
    TotpRotationStartResult,
)
from config import settings


class TestBrandedRejectionResponse:
    """A breach of either the default limit or a per-route decorator limit
    renders the application's own branded 429 page, not slowapi's JSON
    fallback, and carries a Retry-After matching the limit's window."""

    def test_default_limit_breach_renders_branded_429_with_retry_after_and_log(
        self, guest_client, caplog
    ):
        """An UNDECORATED route past the 30/minute default limit gets the
        branded HTML 429 (rate_limit_handler), an audit WARNING, and a
        Retry-After header of the limit's window (60s for a per-minute
        limit). The bounded adapter must preserve the branded page, warning
        attribution, and worker-captured window statistics on
        default-policy breaches.
        """
        with caplog.at_level(logging.WARNING):
            # /about has no @limiter.limit decorator -> governed by the
            # default limits, enforced by SlowAPIMiddleware (the
            # sync-handler code path).
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

        # Retry-After == the tripped limit's window in seconds. The
        # 30/minute default is the limit that breaks first -> 60.
        assert 1 <= int(response.headers["Retry-After"]) <= 60

        # The handler's observability side effect: a structured WARNING on
        # the root-propagated app.main logger carrying the safe route path.
        warning_records = [
            record
            for record in caplog.records
            if record.name == "app.main"
            and record.levelno == logging.WARNING
            and record.getMessage() == "Rate limit exceeded"
        ]
        assert len(warning_records) == 1
        assert warning_records[0].path == "/about"

    def test_decorated_login_limit_governs_and_carries_retry_after(self, guest_client):
        """On a DECORATED route: POST /login is
        @limiter.limit("5/minute;20/hour"), so the 6th attempt in a minute
        is a 429 carrying Retry-After "60" (the 5/minute window) and the
        branded error page.

        Documented behavior: a per-route @limiter.limit REPLACES the global
        default rather than stacking — /login trips at request 6, governed
        by its own 5/minute, not at request 31 under the 30/minute default.
        The breach here is raised by the route decorator (not the
        middleware), so it reaches rate_limit_handler through Starlette's
        ExceptionMiddleware, which proves the same handler brands
        decorated-route 429s too.
        """
        with patch(
            "app.routes.auth.login.verify_password",
            autospec=True,
            return_value=PasswordCheck(
                user=None,
                password_ok=False,
                locked_until=None,
                failure_reason="unknown_email",
                auth_revision=None,
            ),
        ):
            form = {
                "email": "alice@uzh.ch",
                "password": "wrong-password",
                "totp_code": "",
                "csrf_token": guest_client.csrf_token,
            }
            for i in range(5):
                response = guest_client.post("/login", data=form)
                # 401 (login error page), not 403 — proves the CSRF pair was
                # valid and the request really reached the credential check.
                assert response.status_code == 401, f"attempt {i + 1}: {response.status_code}"

            response = guest_client.post("/login", data=form)

        assert response.status_code == 429
        assert 1 <= int(response.headers["Retry-After"]) <= 60
        assert response.headers["content-type"].startswith("text/html")
        assert "Too many requests" in response.text


class TestThrottledResponseHeaders:
    """The 429 response carries client-actionable headers, computed from
    the public API (limits' get_window_stats), not slowapi's private
    _inject_headers; ordinary responses never expose limit configuration."""

    def test_429_carries_retry_after_and_ratelimit_trio(self, guest_client):
        """Trip the 30/minute default limit; the 429 must carry a plausible
        delta-seconds Retry-After (1..61) and the X-RateLimit trio with
        Remaining=0 — the one response where rate-limit headers appear."""
        for _ in range(30):
            assert guest_client.get("/about").status_code == 200
        response = guest_client.get("/about")
        assert response.status_code == 429

        retry_after = response.headers.get("Retry-After")
        assert retry_after is not None, dict(response.headers)
        assert retry_after.isdigit() and 1 <= int(retry_after) <= 61

        assert response.headers.get("X-RateLimit-Limit") == "30"
        assert response.headers.get("X-RateLimit-Remaining") == "0"
        assert response.headers.get("X-RateLimit-Reset", "").isdigit()

    def test_success_responses_do_not_leak_ratelimit_headers(self, guest_client):
        """The other half of the header-exposure policy: normal responses
        carry none of the trio (limit configuration is only revealed on the
        429). Positive control for the trio-on-429 test above."""
        response = guest_client.get("/about")
        assert response.status_code == 200
        for header in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
            assert header not in response.headers

    def test_429_carries_security_headers(self, guest_client):
        """Positive control: a normal 200 response on the same route DOES
        carry these headers (applied by the set_secure_headers ASGI
        middleware, which correctly awaits set_headers_async) -- proving the
        assertion style is right and the gap is specific to the 429
        exception-handler path."""
        ok_response = guest_client.get("/about")
        assert ok_response.status_code == 200
        assert ok_response.headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in ok_response.headers.get("Content-Security-Policy", "")
        assert ok_response.headers.get("X-Content-Type-Options") == "nosniff"

        for _ in range(29):
            assert guest_client.get("/about").status_code == 200
        response = guest_client.get("/about")
        assert response.status_code == 429

        assert response.headers.get("X-Frame-Options") == "DENY", dict(response.headers)
        assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", ""), (
            dict(response.headers)
        )
        assert response.headers.get("X-Content-Type-Options") == "nosniff", dict(response.headers)


class TestHealthEndpointExemption:
    """``/health`` is declared @limiter.exempt for DB-free liveness polling;
    ``/health/detail`` runs DB queries and keeps the default-limit backstop
    as its positive control."""

    def test_health_is_exempt_from_rate_limits(self, guest_client):
        """/health is @limiter.exempt — polling it far past the 30/minute
        default limit never yields a 429.

        Guards against an uptime monitor polling every 5s (~17k/day)
        flapping to 429 by design. Safe to exempt because /health is
        DB-free liveness — nothing to amplify.
        """
        for i in range(40):
            response = guest_client.get("/health")
            assert response.status_code == 200, (
                f"/health request {i + 1} returned {response.status_code} — the "
                "rate-limit exemption is gone and monitoring will flap"
            )
            assert response.json() == {"status": "alive"}

    def test_health_detail_keeps_the_default_limit_backstop(self, guest_client):
        """/health/detail still enforces the 30/minute default limit — the
        31st unauthorized probe from one IP is a 429. The /health vs
        /health/detail asymmetry is intentional: detail is token-gated and
        runs DB queries, so the default limit stays on as an anti-probing
        backstop.

        Unauthorized requests (no Bearer token, FASTAPI_DEBUG=false in the
        test env) get the fail-secure 404 — which still counts against the
        limit.
        """
        for i in range(30):
            response = guest_client.get("/health/detail")
            assert response.status_code == 404, f"request {i + 1}: {response.status_code}"

        response = guest_client.get("/health/detail")
        assert response.status_code == 429
        # Same branded handler + Retry-After as every other breach.
        assert 1 <= int(response.headers["Retry-After"]) <= 60
        assert "Too many requests" in response.text


# ---------------------------------------------------------------------------
# Every abuse-sensitive endpoint's per-route limit is PINNED here (before
# this, only /login's 5/minute had a test; deleting any other
# @limiter.limit decorator shipped green).
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
    (
        "guest_client",
        "POST",
        "/register",
        3,
        {
            "email": "not-an-email",
            "display_name": "Probe",
            "password": "x-Yz1!x-Yz1!",
            "password_confirm": "x-Yz1!x-Yz1!",
        },
        [],
    ),
    ("guest_client", "POST", "/send_verification", 3, {"email": "not-an-email"}, []),
    ("guest_client", "POST", "/forgot-password", 3, {"email": "not-an-email"}, []),
    ("guest_client", "GET", "/reset-password/garbage-token", 10, None, []),
    (
        "guest_client",
        "POST",
        "/reset-password",
        5,
        {
            "token": "garbage-token",
            "password": "x-Yz1!x-Yz1!",
            "password_confirm": "x-Yz1!x-Yz1!",
        },
        [],
    ),
    ("guest_client", "GET", "/verify-email/garbage-token", 10, None, []),
    ("guest_client", "POST", "/verify-email", 10, {"token": "garbage"}, []),
    ("guest_client", "GET", "/account/confirm-email/garbage-token", 10, None, []),
    ("guest_client", "POST", "/account/confirm-email", 10, {"token": "garbage"}, []),
    (
        "authenticated_client",
        "POST",
        "/account/change-email",
        5,
        {"new_email": "n@uzh.ch", "current_password": "wrong"},
        [
            (
                "app.routes.auth.email_change.stage_self_email_change",
                {
                    "return_value": SelfEmailChangeResult(
                        user_id=1,
                        old_email="user@example.com",
                        new_email="n@uzh.ch",
                    )
                },
            )
        ],
    ),
    ("authenticated_client", "GET", "/setup-totp", 10, None, []),
    (
        "authenticated_client",
        "POST",
        "/setup-totp",
        5,
        {"totp_code": "000000", "recovery_code_confirmation": "not-a-real-code"},
        [
            (
                "app.routes.auth.totp.verify_and_enroll_totp",
                {"return_value": TotpEnrollmentOutcome.INELIGIBLE},
            )
        ],
    ),
    (
        # reset_totp_page (GET) renders the fresh-authentication form directly
        # from request.state.user; it calls no rotation service (totp.py:318-343).
        "authenticated_client",
        "GET",
        "/account/reset-totp",
        10,
        None,
        [],
    ),
    (
        "authenticated_client",
        "POST",
        "/account/reset-totp",
        5,
        {"current_password": "wrong", "current_totp_code": "000000"},
        [
            (
                "app.routes.auth.totp.begin_totp_rotation",
                {
                    "return_value": TotpRotationStartResult(
                        TotpRotationStartOutcome.CURRENT_SECRET_MISSING
                    )
                },
            )
        ],
    ),
]


class TestPerRouteLimits:
    """Every abuse-sensitive route retains its documented per-route limit."""

    @pytest.mark.parametrize(
        ("fixture", "method", "path", "limit", "form", "patches"),
        ENDPOINT_LIMITS,
        ids=[f"{method}-{path}-{limit}" for _, method, path, limit, _, _ in ENDPOINT_LIMITS],
    )
    def test_per_route_limit_is_pinned(self, request, fixture, method, path, limit, form, patches):
        client = request.getfixturevalue(fixture)
        with ExitStack() as stack:
            for target, kwargs in patches:
                stack.enter_context(patch(target, autospec=True, **kwargs))

            def hit():
                if method == "GET":
                    return client.get(path, follow_redirects=False)
                data = {**form, "csrf_token": client.csrf_token}
                return client.post(path, data=data, follow_redirects=False)

            for request_number in range(limit):
                response = hit()
                assert response.status_code != 429, (
                    f"request {request_number + 1}/{limit} already limited — "
                    f"{method} {path} is tighter than documented"
                )
            response = hit()

        assert response.status_code == 429, (
            f"request {limit + 1} was not limited — the per-route limit on "
            f"{method} {path} is gone or looser than {limit}/window"
        )
        assert "Too many requests" in response.text


class TestClientIdentityDerivation:
    """The limiter's key_func must key on the real client, not on
    attacker-controlled headers."""

    def test_rotating_forwarded_headers_share_one_counter(self, guest_client):
        """The XFF-spoof bypass: with RATE_LIMIT_TRUST_PROXY false and
        an untrusted peer ('testclient'), X-Forwarded-For MUST be ignored by
        the limiter's key_func. If a cleanup swaps key_func to a
        header-trusting helper (slowapi.util.get_ipaddr), every attacker
        bypasses every limit by rotating a header — and this test's 31
        distinct-XFF requests would all land in separate buckets and never
        429."""
        statuses = [
            guest_client.get("/about", headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code
            for i in range(31)
        ]
        assert 429 in statuses, (
            "rotating X-Forwarded-For evaded the shared 30/minute bucket — "
            "the limiter key_func is trusting client-controlled headers"
        )

    def test_ipv6_addresses_in_one_prefix_draw_on_one_budget(self, client_builder):
        """A client with a routed IPv6 prefix can source every request from a
        different address of its own. Those addresses must share the route's
        30/minute budget, or the per-client limit costs nothing to evade.

        The address is varied through the connecting peer the ASGI scope
        reports, which is where the application takes client attribution from;
        rotating a forwarded header instead would only re-test the
        untrusted-proxy rejection above.
        """
        first_address = client_builder(peer_address="2001:db8:abcd:1234::1")
        for request_number in range(30):
            response = first_address.get("/about")
            assert response.status_code == 200, (
                f"request {request_number + 1} was limited before the budget ran out"
            )

        same_prefix = client_builder(peer_address="2001:db8:abcd:1234::99")
        assert same_prefix.get("/about").status_code == 429, (
            "a fresh address from the same prefix received a budget of its own"
        )

    def test_a_neighbouring_ipv6_prefix_keeps_its_own_budget(self, client_builder):
        """Positive control for the aggregation above: exhausting one prefix
        must not throttle the network next to it, which belongs to someone
        else."""
        exhausted = client_builder(peer_address="2001:db8:abcd:1234::1")
        for _ in range(30):
            assert exhausted.get("/about").status_code == 200

        neighbour = client_builder(peer_address="2001:db8:abcd:1235::1")
        assert neighbour.get("/about").status_code == 200


class TestLimiterStorageWiring:
    """The module-level limiter's storage backend follows
    settings.rate_limit_storage_uri: a dedicated Redis URL when the shared
    backend is enabled, and the in-process memory backend otherwise."""

    def test_limiter_storage_uri_uses_redis_when_enabled(self, monkeypatch):
        """The multi-worker wiring branch: with no dedicated rate-limit
        Redis URL and redis_enabled=True, the module-level limiter must be
        constructed with storage_uri = the shared REAL redis URL string
        (SecretStr unwrapped), not the None fallback that silently
        gives every gunicorn worker its own counters (N* the ceiling).
        settings.rate_limit_storage_uri (config/settings.py) prefers a
        dedicated rate_limit_redis_url first, so it is pinned empty here to
        isolate the redis_enabled branch.

        The module builds the limiter at import, so this reloads it under
        patched settings and restores the original limiter object
        afterwards (the route decorators hold references to the original
        instance)."""
        original_limiter = rl.limiter
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr(settings, "redis_url", SecretStr("redis://fake-host:6379/9"))
        try:
            reloaded = importlib.reload(rl)
            assert reloaded.limiter._storage_uri == "redis://fake-host:6379/9"
        finally:
            monkeypatch.undo()
            importlib.reload(rl)
            # Reload minted ANOTHER limiter; restore the instance the app's
            # route decorators (and the autouse reset fixture) actually use.
            rl.limiter = original_limiter

    def test_limiter_storage_uri_is_none_when_redis_disabled(self, monkeypatch):
        """Positive control for the wiring test above: with no dedicated
        rate-limit Redis URL and the shared Redis backend disabled,
        settings.rate_limit_storage_uri falls all the way through to the
        in-process memory backend."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", False)
        assert settings.rate_limit_storage_uri is None


class TestThrottleObservability:
    """What a throttle event looks like to an operator: the WARNING log line
    and the audit trail both carry enough to investigate the offending
    client."""

    def test_throttle_log_carries_real_client_ip_and_request_id(self, guest_client, caplog):
        """The rate_limit_handler's own WARNING must carry the actual
        client ip (via get_client_ip), not a hardcoded-fallback 'unknown':
        an operator investigating abuse reads exactly this line."""
        with caplog.at_level(logging.WARNING):
            for _ in range(31):
                resp = guest_client.get("/about")
        assert resp.status_code == 429

        rec = next(
            r
            for r in caplog.records
            if r.name == "app.main" and r.getMessage() == "Rate limit exceeded"
        )
        assert rec.client_ip == "testclient", (
            f"throttle log carries client_ip={rec.client_ip!r} — operators cannot see the "
            "offending IP"
        )
        assert rec.request_id not in (None, "unknown")
        assert rec.path == "/about"

    def test_429_response_is_audited_with_request_id(self, guest_client, caplog):
        """Audit middleware is registered OUTSIDE rate limiting so the abuse
        traffic you most need logged is captured: the 429 response carries
        X-Request-ID and the audit channel records the request with
        status_code 429. Reordering the two setup_* calls in main.py loses
        both."""
        with caplog.at_level(logging.INFO, logger="audit"):
            for _ in range(31):
                resp = guest_client.get("/about")
        assert resp.status_code == 429
        assert resp.headers.get("X-Request-ID"), "429 lost its X-Request-ID"

        audited_429s = [
            r
            for r in caplog.records
            if r.name == "audit"
            and getattr(r, "status_code", None) == 429
            and getattr(r, "path", None) == "/about"
        ]
        assert audited_429s, "the 429 never reached the audit middleware"
        assert audited_429s[0].request_id == resp.headers["X-Request-ID"]


class TestParameterizedRouteSharesOneBucketAcrossConcreteValues:
    """``key_style="endpoint"`` aggregates a parameterized route's distinct
    URL values into one per-IP bucket rather than one bucket per concrete
    path, so a token in the URL cannot be rotated to multiply the budget."""

    def test_distinct_reset_password_tokens_share_one_bucket(self, guest_client):
        """GET /reset-password/<token> is 10/minute; ten DIFFERENT token
        values must still trip the limit on the 11th request."""
        for i in range(10):
            response = guest_client.get(
                f"/reset-password/garbage-token-{i}", follow_redirects=False
            )
            assert response.status_code != 429, f"request {i + 1} already limited"

        response = guest_client.get("/reset-password/garbage-token-final", follow_redirects=False)
        assert response.status_code == 429

    def test_login_and_about_keep_independent_buckets(self, guest_client):
        """Positive control: a decorated route's own limit and the default
        limit on an unrelated route do not share a counter — tripping
        /login's tighter 5/minute limit leaves /about's separate 30/minute
        budget untouched."""
        with patch(
            "app.routes.auth.login.verify_password",
            autospec=True,
            return_value=PasswordCheck(
                user=None,
                password_ok=False,
                locked_until=None,
                failure_reason="unknown_email",
                auth_revision=None,
            ),
        ):
            form = {
                "email": "alice@uzh.ch",
                "password": "wrong-password",
                "totp_code": "",
                "csrf_token": guest_client.csrf_token,
            }
            for _ in range(5):
                guest_client.post("/login", data=form)
            tripped = guest_client.post("/login", data=form)

        assert tripped.status_code == 429
        assert guest_client.get("/about").status_code == 200


class TestExemptRouteInventory:
    """``/health`` is the only route the limiter is configured to skip
    entirely; every other reviewed sensitive route keeps a real limit even
    when the backend itself is failing."""

    def test_only_health_check_is_exempt(self):
        assert rl.limiter._exempt_routes == {"app.routes.health.health_check"}

    def test_health_stays_200_during_a_forced_backend_failure(self, guest_client):
        """Positive control for the non-exempt routes below: because
        /health never reaches the limiter at all, a broken storage backend
        cannot make it fail."""
        with patch.object(
            rl.limiter,
            "_check_request_limit",
            autospec=True,
            side_effect=RuntimeError("storage backend unavailable"),
        ):
            response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}

    @pytest.mark.parametrize(
        ("method", "path", "limit", "form"),
        [
            ("GET", "/health/detail", 30, None),
            ("POST", "/login", 5, {"email": "a@uzh.ch", "password": "wrong", "totp_code": ""}),
            ("GET", "/recover-totp", 10, None),
            ("POST", "/send_verification", 3, {"email": "not-an-email"}),
            ("GET", "/search", 30, None),
            ("POST", "/forgot-password", 3, {"email": "not-an-email"}),
        ],
        ids=[
            "health-detail",
            "login",
            "recover-totp",
            "send_verification",
            "search",
            "forgot-password",
        ],
    )
    def test_non_exempt_reviewed_routes_hit_429_at_their_limit(
        self, guest_client, method, path, limit, form
    ):
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "app.routes.auth.login.verify_password",
                    autospec=True,
                    return_value=PasswordCheck(
                        user=None,
                        password_ok=False,
                        locked_until=None,
                        failure_reason="unknown_email",
                        auth_revision=None,
                    ),
                )
            )
            stack.enter_context(
                patch(
                    "app.routes.pages.search_datasets",
                    new=create_autospec(_real_search_datasets, return_value=([], 0)),
                )
            )

            def hit():
                if method == "GET":
                    return guest_client.get(path, follow_redirects=False)
                return guest_client.post(
                    path,
                    data={**form, "csrf_token": guest_client.csrf_token},
                    follow_redirects=False,
                )

            for request_number in range(limit):
                response = hit()
                assert response.status_code != 429, (
                    f"request {request_number + 1}/{limit} already limited on {method} {path}"
                )
            response = hit()

        assert response.status_code == 429, f"{method} {path} never limited at {limit + 1}"
