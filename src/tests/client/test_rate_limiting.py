"""Rate limiting behavior at the route layer, exercised through real requests over the full middleware
stack (``app.middleware.rate_limiting``).
"""

import logging
from contextlib import ExitStack
from unittest.mock import create_autospec, patch

import pytest
from pydantic import SecretStr

import app.middleware.rate_limiting as rl
from app.services.authentication import PasswordCheck
from app.services.datasets import SearchPage, search_catalogue_page
from app.services.email_change import SelfEmailChangeResult
from app.services.tokens import action_token_public_id
from app.services.totp import (
    TotpEnrollmentOutcome,
    TotpRotationStartOutcome,
    TotpRotationStartResult,
)
from config import settings


class TestBrandedRejectionResponse:
    """Cover branded rejection response."""

    def test_default_limit_breach_renders_branded_429_with_retry_after_and_log(
        self, guest_client, caplog
    ):
        """Check default limit breach renders branded 429 with retry after and log."""
        with caplog.at_level(logging.WARNING):
            # /about exercises the middleware default without a per-route override.
            for i in range(30):
                response = guest_client.get("/about")
                assert response.status_code == 200, f"request {i + 1} unexpectedly limited"

            response = guest_client.get("/about")

        assert response.status_code == 429

        assert response.headers["content-type"].startswith("text/html")
        assert "Too many requests" in response.text
        assert "Rate limit exceeded" not in response.text

        assert 1 <= int(response.headers["Retry-After"]) <= 60

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
        """Check decorated login limit governs and carries retry after."""
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
                "email": "alice@example.org",
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
    """Cover throttled response headers."""

    def test_429_carries_retry_after_and_ratelimit_trio(self, guest_client):
        """Check 429 carries retry after and ratelimit trio."""
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
        """Check success responses do not leak ratelimit headers (HTTP 200)."""
        response = guest_client.get("/about")
        assert response.status_code == 200
        for header in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
            assert header not in response.headers

    def test_429_carries_security_headers(self, guest_client):
        """Require both normal and throttled responses to carry the application security headers."""
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
    """Cover health endpoint exemption."""

    def test_health_is_exempt_from_rate_limits(self, guest_client):
        """/health is @limiter.exempt — polling it far past the 30/minute default limit never yields a
        429.
        """
        for i in range(40):
            response = guest_client.get("/health")
            assert response.status_code == 200, (
                f"/health request {i + 1} returned {response.status_code} — the "
                "rate-limit exemption is gone and monitoring will flap"
            )
            assert response.json() == {"status": "alive"}

    def test_health_detail_keeps_the_default_limit_backstop(self, guest_client):
        """/health/detail still enforces the 30/minute default limit — the 31st unauthorized probe from
        one IP is a 429.
        """
        for i in range(30):
            response = guest_client.get("/health/detail")
            assert response.status_code == 404, f"request {i + 1}: {response.status_code}"

        response = guest_client.get("/health/detail")
        assert response.status_code == 429
        assert 1 <= int(response.headers["Retry-After"]) <= 60
        assert "Too many requests" in response.text


# Requests use parseable forms and valid CSRF so validation failures do not mask limits.
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
        422,
    ),
    ("guest_client", "POST", "/send_verification", 3, {"email": "not-an-email"}, [], 200),
    ("guest_client", "POST", "/forgot-password", 3, {"email": "not-an-email"}, [], 422),
    (
        "guest_client",
        "GET",
        "/reset-password/" + action_token_public_id("garbage-token"),
        10,
        None,
        [],
        200,
    ),
    (
        "guest_client",
        "POST",
        "/reset-password",
        5,
        {
            "token": "garbage-token",
            "public_id": action_token_public_id("garbage-token"),
            "totp_code": "000000",
            "password": "x-Yz1!x-Yz1!",
            "password_confirm": "x-Yz1!x-Yz1!",
        },
        [],
        422,
    ),
    (
        "guest_client",
        "GET",
        "/verify-email/" + action_token_public_id("garbage-token"),
        10,
        None,
        [],
        200,
    ),
    (
        "guest_client",
        "POST",
        "/verify-email",
        10,
        {
            "token": "garbage",
            "public_id": action_token_public_id("garbage"),
            "display_name": "Probe",
            "password": "x-Yz1!x-Yz1!",
            "password_confirm": "x-Yz1!x-Yz1!",
        },
        [],
        400,
    ),
    (
        "guest_client",
        "GET",
        "/account/confirm-email/" + action_token_public_id("garbage-token"),
        10,
        None,
        [],
        200,
    ),
    (
        "guest_client",
        "POST",
        "/account/confirm-email",
        10,
        {"token": "garbage", "public_id": action_token_public_id("garbage")},
        [],
        400,
    ),
    (
        "authenticated_client",
        "POST",
        "/account/change-email",
        5,
        {"new_email": "n@example.org", "current_password": "wrong", "totp_code": "111111"},
        [
            (
                "app.routes.auth.email_change.stage_self_email_change",
                {
                    "return_value": SelfEmailChangeResult(
                        user_id=1,
                        old_email="user@example.com",
                        new_email="n@example.org",
                    )
                },
            ),
            ("app.routes.auth.email_change.set_flash_if_exists", {"return_value": None}),
        ],
        303,
    ),
    ("authenticated_client", "GET", "/setup-totp", 10, None, [], 303),
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
        403,
    ),
    (
        "authenticated_client",
        "GET",
        "/account/reset-totp",
        10,
        None,
        [],
        200,
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
        303,
    ),
]


class TestPerRouteLimits:
    """Every abuse-sensitive route retains its documented per-route limit."""

    @pytest.mark.parametrize(
        ("fixture", "method", "path", "limit", "form", "patches", "expected_status"),
        ENDPOINT_LIMITS,
        ids=[f"{method}-{path}-{limit}" for _, method, path, limit, _, _, _ in ENDPOINT_LIMITS],
    )
    def test_per_route_limit_is_pinned(
        self, request, fixture, method, path, limit, form, patches, expected_status
    ):
        """Check per route limit is pinned (HTTP 429)."""
        client = request.getfixturevalue(fixture)
        with ExitStack() as stack:
            service_mocks = [
                stack.enter_context(patch(target, autospec=True, **kwargs))
                for target, kwargs in patches
            ]

            def hit():
                """Issue the selected route request with CSRF for POST and no redirect following."""
                if method == "GET":
                    return client.get(path, follow_redirects=False)
                data = {**form, "csrf_token": client.csrf_token}
                return client.post(path, data=data, follow_redirects=False)

            for request_number in range(limit):
                response = hit()
                assert response.status_code == expected_status, (
                    f"request {request_number + 1}/{limit} returned an unexpected response — "
                    f"{method} {path}: {response.text[:200]}"
                )
            if method == "POST" and path == "/reset-password":
                assert "This reset link has already been used" in response.text
            response = hit()
            for service in service_mocks:
                assert service.await_count == limit

        assert response.status_code == 429, (
            f"request {limit + 1} was not limited — the per-route limit on "
            f"{method} {path} is gone or looser than {limit}/window"
        )
        assert "Too many requests" in response.text


class TestClientIdentityDerivation:
    """The limiter's key_func must key on the real client, not on
    attacker-controlled headers."""

    def test_rotating_forwarded_headers_share_one_counter(self, guest_client):
        """The XFF-spoof bypass: with RATE_LIMIT_TRUST_PROXY false and an untrusted peer
        ('testclient'), X-Forwarded-For MUST be ignored by the limiter's key_func.
        """
        statuses = [
            guest_client.get("/about", headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code
            for i in range(31)
        ]
        assert 429 in statuses, (
            "rotating X-Forwarded-For evaded the shared 30/minute bucket — "
            "the limiter key_func is trusting client-controlled headers"
        )

    def test_ipv6_addresses_in_one_prefix_draw_on_one_budget(self, client_builder):
        """A client with a routed IPv6 prefix can source every request from a different address of its
        own.
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
        """Check a neighbouring ipv6 prefix keeps its own budget (HTTP 200)."""
        exhausted = client_builder(peer_address="2001:db8:abcd:1234::1")
        for _ in range(30):
            assert exhausted.get("/about").status_code == 200

        neighbour = client_builder(peer_address="2001:db8:abcd:1235::1")
        assert neighbour.get("/about").status_code == 200


class TestLimiterStorageWiring:
    """Cover limiter storage wiring."""

    def test_limiter_storage_uri_uses_redis_when_enabled(self, monkeypatch):
        """Check limiter storage uri uses Redis when enabled."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr(settings, "redis_url", SecretStr("redis://fake-host:6379/9"))
        constructed = rl._build_limiter()
        assert constructed._storage_uri == "bounded+redis://fake-host:6379/9"

    def test_limiter_storage_uri_is_none_when_redis_disabled(self, monkeypatch):
        """Check limiter storage uri is none when Redis disabled."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", False)
        assert settings.rate_limit_storage_uri is None


class TestThrottleObservability:
    """What a throttle event looks like to an operator: the WARNING log line
    and the audit trail both carry enough to investigate the offending
    client."""

    def test_throttle_log_carries_real_client_ip_and_request_id(self, guest_client, caplog):
        """Check throttle log carries real client ip and request ID (HTTP 429)."""
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
        """Check 429 response is audited with request ID."""
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
    """Cover parameterized route shares one bucket across concrete values."""

    def test_distinct_reset_password_tokens_share_one_bucket(self, guest_client):
        """GET /reset-password/<public_id> is 10/minute; ten DIFFERENT identifier
        values must still trip the limit on the 11th request."""
        for i in range(10):
            response = guest_client.get(
                f"/reset-password/{action_token_public_id(f'probe-{i}')}", follow_redirects=False
            )
            assert response.status_code == 200, f"request {i + 1} failed before its limit"

        response = guest_client.get(
            "/reset-password/" + action_token_public_id("final-probe"), follow_redirects=False
        )
        assert response.status_code == 429

    def test_login_and_about_keep_independent_buckets(self, guest_client):
        """Check login and about keep independent buckets."""
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
                "email": "alice@example.org",
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
        """Check only health check is exempt."""
        assert rl.limiter._exempt_routes == {"app.routes.health.health_check"}

    def test_health_stays_200_during_a_forced_backend_failure(self, guest_client):
        """Check health stays 200 during a forced backend failure."""
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
        ("method", "path", "limit", "form", "expected_status"),
        [
            ("GET", "/health/detail", 30, None, 404),
            (
                "POST",
                "/login",
                5,
                {"email": "a@example.org", "password": "wrong", "totp_code": ""},
                401,
            ),
            ("GET", "/recover-totp", 10, None, 200),
            ("POST", "/send_verification", 3, {"email": "not-an-email"}, 200),
            ("GET", "/search", 30, None, 200),
            ("POST", "/forgot-password", 3, {"email": "not-an-email"}, 422),
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
        self, guest_client, method, path, limit, form, expected_status
    ):
        """Check non exempt reviewed routes hit 429 at their limit."""
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
                    "app.routes.pages.search_catalogue_page",
                    new=create_autospec(
                        search_catalogue_page, return_value=SearchPage([], None, 1)
                    ),
                )
            )

            stack.enter_context(
                patch(
                    "app.routes.pages.get_facets",
                    autospec=True,
                    return_value={"keywords": [], "languages": [], "access_levels": []},
                )
            )

            def hit():
                """Issue the selected route request with CSRF for POST and no redirect following."""
                if method == "GET":
                    return guest_client.get(path, follow_redirects=False)
                return guest_client.post(
                    path,
                    data={**form, "csrf_token": guest_client.csrf_token},
                    follow_redirects=False,
                )

            for request_number in range(limit):
                response = hit()
                assert response.status_code == expected_status, (
                    f"request {request_number + 1}/{limit} already limited on {method} {path}"
                )
            response = hit()

        assert response.status_code == 429, f"{method} {path} never limited at {limit + 1}"
