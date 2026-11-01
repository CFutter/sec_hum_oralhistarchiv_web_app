"""Unit coverage for how the rate limiter is built and how it identifies clients."""

import asyncio
import logging
import socket
import threading
import time
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI, Request, Response
from limits.errors import StorageError
from limits.storage.memory import MemoryStorage
from pydantic import SecretStr
from redis.exceptions import ConnectionError as RedisConnectionError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

import app.middleware.rate_limiting as rl
from app.middleware.rate_limiting import (
    BoundedRateLimitMiddleware,
    redis_storage_options,
    setup_rate_limiting,
    validate_rate_limit_configuration,
)
from app.request_utils import get_client_ip
from app.thread_work import ThreadWorkAdmissionTimeout
from config import settings


def make_request(
    peer: str | None = "127.0.0.1",
    server: tuple[str, int] | None = ("127.0.0.1", 8000),
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    """Build a request scope; peer=None models a Unix socket without a TCP client."""
    return Request(
        {
            "type": "http",
            "client": (peer, 1234) if peer is not None else None,
            "server": server,
            "headers": headers or [],
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "scheme": "http",
        }
    )


class TestRateLimitingWiring:
    """setup_rate_limiting's enable/disable wiring.

    Both modes retain the explicit instance on app.state for readiness.
    Both modes retain admission middleware for the shared search gate.
    """

    def test_disabled_setup_keeps_shared_search_admission(self, monkeypatch):
        """Disabled client limits retain the independent global search gate."""
        monkeypatch.setattr(settings, "rate_limit_enabled", False)
        monkeypatch.setattr(rl.limiter, "enabled", False)
        app = FastAPI()

        with patch.object(app, "add_middleware", autospec=True) as add_mw:
            setup_rate_limiting(app, rl.limiter)
            add_mw.assert_called_once_with(BoundedRateLimitMiddleware, search_busy_response=None)

        assert app.state.limiter is rl.limiter

    def test_enabled_setup_wires_limiter_and_middleware(self, monkeypatch):
        """RATE_LIMIT_ENABLED=true -> app.state.limiter is set and the
        SlowAPI middleware is added."""
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        app = FastAPI()

        with patch.object(app, "add_middleware", autospec=True) as add_mw:
            setup_rate_limiting(app, rl.limiter)
            assert add_mw.call_count == 1

        assert app.state.limiter is not None


class TestStorageModeValidation:
    """The startup validator accepts every storage mode the settings resolve to."""

    def test_validator_admits_the_limiter_built_for_a_redis_url(self, monkeypatch):
        """Check validator admits the limiter built for a Redis URL."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr("redis://fake-host:6379/9"))
        monkeypatch.setattr(settings, "redis_enabled", False)

        validate_rate_limit_configuration(rl._build_limiter())

    def test_validator_admits_the_limiter_built_for_process_local_memory_mode(self, monkeypatch):
        """A development process without any Redis URL must still start."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", False)

        validate_rate_limit_configuration(rl._build_limiter())


class TestClientIpAttribution:
    """Trust-gated client IP extraction — app.request_utils.get_client_ip."""

    @pytest.mark.parametrize(
        ("peer", "server", "headers", "expected_ip"),
        [
            pytest.param(
                "127.0.0.1",
                ("127.0.0.1", 8000),
                [(b"x-real-ip", b"9.9.9.9")],
                "9.9.9.9",
                id="trusted_peer_honors_x_real_ip",
            ),
            pytest.param(
                "127.0.0.1",
                ("127.0.0.1", 8000),
                [(b"x-real-ip", b"  9.9.9.9  ")],
                "9.9.9.9",
                id="x_real_ip_whitespace_is_stripped",
            ),
            pytest.param(
                "127.0.0.1",
                ("127.0.0.1", 8000),
                [(b"x-real-ip", b"not-an-ip"), (b"x-forwarded-for", b"8.8.8.8, 1.1.1.1")],
                "8.8.8.8",
                id="invalid_x_real_ip_falls_through_to_first_xff_hop",
            ),
            pytest.param(
                "127.0.0.1",
                ("127.0.0.1", 8000),
                [(b"x-real-ip", b"not-an-ip"), (b"x-forwarded-for", b"also-garbage, 1.1.1.1")],
                "127.0.0.1",
                id="malformed_xff_first_hop_falls_back_to_peer",
            ),
            pytest.param(
                None,
                None,
                [(b"x-real-ip", b"9.9.9.9")],
                "9.9.9.9",
                id="unix_socket_no_server_counts_as_trusted_upstream",
            ),
            pytest.param(
                None,
                ("/run/oha/gunicorn.sock", None),
                [(b"x-real-ip", b"9.9.9.9")],
                "9.9.9.9",
                id="unix_socket_server_port_none_counts_as_trusted_upstream",
            ),
            pytest.param(
                "::1",
                ("127.0.0.1", 8000),
                [(b"x-real-ip", b"2001:db8::1")],
                "2001:db8::1",
                id="ipv6_x_real_ip_is_accepted",
            ),
        ],
    )
    def test_trusted_upstream_honors_valid_forwarded_header(
        self, monkeypatch, peer, server, headers, expected_ip
    ):
        """Check trusted upstream honors valid forwarded header."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        request = make_request(peer=peer, server=server, headers=headers)
        assert get_client_ip(request) == expected_ip

    def test_untrusted_peer_ignores_forwarded_headers(self, monkeypatch):
        """The security boundary: a direct (untrusted) peer 5.5.5.5 sending both forwarded headers gets
        attributed to 5.5.5.5, not the header values.
        """
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        request = make_request(
            peer="5.5.5.5",
            headers=[
                (b"x-real-ip", b"9.9.9.9"),
                (b"x-forwarded-for", b"8.8.8.8"),
            ],
        )
        assert get_client_ip(request) == "5.5.5.5"

    def test_trust_proxy_off_ignores_headers_even_from_trusted_peer(self, monkeypatch):
        """Disabling proxy trust ignores forwarded headers from a trusted peer."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", False)
        request = make_request(
            peer="127.0.0.1",
            headers=[
                (b"x-real-ip", b"9.9.9.9"),
                (b"x-forwarded-for", b"8.8.8.8"),
            ],
        )
        assert get_client_ip(request) == "127.0.0.1"

    def test_no_client_no_server_no_headers_returns_unknown(self, monkeypatch):
        """Total absence of attribution inputs yields the literal 'unknown' —
        the final `peer or "unknown"` fallback — never None or an exception."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        request = make_request(peer=None, server=None, headers=[])
        assert get_client_ip(request) == "unknown"

    def test_trusted_upstream_set_is_frozen_at_import(self, monkeypatch):
        """_TRUSTED_UPSTREAM_IPS is frozen from settings.trusted_proxy_ips at module import; mutating
        the setting afterwards must NOT widen the trust set.
        """
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        monkeypatch.setattr(settings, "trusted_proxy_ips", ["5.5.5.5"])
        request = make_request(peer="5.5.5.5", headers=[(b"x-real-ip", b"9.9.9.9")])
        assert get_client_ip(request) == "5.5.5.5"


def _rate_limited_app(limiter: Limiter) -> FastAPI:
    """A minimal app wired with the real BoundedRateLimitMiddleware."""
    app = FastAPI()
    app.state.limiter = limiter
    app.add_middleware(BoundedRateLimitMiddleware)

    @app.get("/default")
    async def default(request: Request):
        """Echo the request path from the rate-limited probe route."""
        return Response(request.url.path)

    @app.get("/decorated")
    @limiter.limit("1/minute")
    async def decorated(request: Request):
        """Echo the request path from the rate-limited probe route."""
        return Response(request.url.path)

    @app.exception_handler(RateLimitExceeded)
    async def exceeded(request, _exc):
        """Require collected limit statistics before returning HTTP 429."""
        assert request.state.rate_limit_stats is not None
        return Response("limited", status_code=429)

    return app


class TestMiddlewareOffloadingAndBackendDeadlines:
    """BoundedRateLimitMiddleware keeps the event loop free and bounds the time it will wait on a dead
    storage backend.
    """

    @pytest.mark.parametrize(
        "path",
        ["/default", "/decorated"],
        ids=["default_route_uses_the_global_limit", "decorated_route_uses_its_own_limit"],
    )
    async def test_checks_and_429_statistics_run_off_the_event_loop(self, path, monkeypatch):
        """Check checks and 429 statistics run off the event loop."""
        limiter = Limiter(
            key_func=lambda: "client", default_limits=["1/minute"], headers_enabled=False
        )
        app = _rate_limited_app(limiter)
        original_hit = limiter.limiter.hit
        original_stats = limiter.limiter.get_window_stats
        main_thread = threading.get_ident()
        worker_calls = []
        worker_parked = threading.Event()
        release_worker = threading.Event()

        def slow(function, *args, **kwargs):
            """Require a worker thread, wait up to two seconds for release, and run the limiter
            operation.
            """
            assert threading.get_ident() != main_thread
            worker_calls.append(function.__name__)
            worker_parked.set()
            released = release_worker.wait(2)
            assert released, "the loop-side watcher never released the parked worker"
            return function(*args, **kwargs)

        monkeypatch.setattr(limiter.limiter, "hit", lambda *a, **k: slow(original_hit, *a, **k))
        monkeypatch.setattr(
            limiter.limiter, "get_window_stats", lambda *a, **k: slow(original_stats, *a, **k)
        )
        ticks = 0

        async def watch_and_release() -> None:
            """Wait for the worker to park, then prove the loop keeps
            ticking for a bounded number of turns before releasing it."""
            nonlocal ticks
            await asyncio.wait_for(asyncio.to_thread(worker_parked.wait), timeout=2)
            ticks_when_parked = ticks
            while ticks - ticks_when_parked < 10:
                ticks += 1
                await asyncio.sleep(0)
            release_worker.set()

        async def call_with_heartbeat(path: str) -> httpx.Response:
            """Issue a bounded request while a loop-side watcher releases the parked worker."""
            worker_parked.clear()
            release_worker.clear()
            watcher = asyncio.create_task(watch_and_release())
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await asyncio.wait_for(client.get(path), timeout=2)
            await asyncio.wait_for(watcher, timeout=2)
            return response

        assert (await call_with_heartbeat(path)).status_code == 200
        assert (await call_with_heartbeat(path)).status_code == 429
        assert ticks >= 10
        assert worker_calls.count("hit") == 2
        assert worker_calls.count("get_window_stats") == 1

    async def test_a_dead_backend_returns_503_without_falling_back_to_in_memory_counters(self):
        """Check a dead backend returns 503 without falling back to in memory counters."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(2)
        stop = threading.Event()

        def blackhole():
            """Accept one TCP connection and hold it for up to five seconds without replying."""
            with listener:
                connection, _ = listener.accept()
                with connection:
                    stop.wait(5)

        server = threading.Thread(target=blackhole)
        server.start()

        limiter = Limiter(
            key_func=rl.get_rate_limit_client_id,
            default_limits=["1/minute"],
            strategy="fixed-window",
            storage_uri=f"redis://127.0.0.1:{listener.getsockname()[1]}/0",
            storage_options=redis_storage_options(),
            enabled=True,
            headers_enabled=False,
            key_prefix="oralhistarchiv-security-v1",
            key_style="endpoint",
            in_memory_fallback_enabled=False,
            swallow_errors=False,
        )
        original_storage = limiter.limiter.storage
        endpoint_ran = False
        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(BoundedRateLimitMiddleware)

        @app.get("/default")
        async def default(request: Request):
            """Record route execution and echo the request path."""
            nonlocal endpoint_ran
            endpoint_ran = True
            return Response(request.url.path)

        @app.exception_handler(RateLimitExceeded)
        async def exceeded(_request, _exc):
            """Return the synthetic HTTP 429 response for RateLimitExceeded."""
            return Response("limited", status_code=429)

        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                start = time.monotonic()
                response = await asyncio.wait_for(client.get("/default"), timeout=5)
                elapsed = time.monotonic() - start
        finally:
            stop.set()
            await asyncio.to_thread(server.join, 5)
        assert not server.is_alive()

        assert elapsed < 5
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "1"
        assert response.headers["Cache-Control"] == "no-store"
        assert endpoint_ran is False
        assert limiter._storage_dead is False
        assert limiter.limiter.storage is original_storage
        assert not isinstance(limiter.limiter.storage, MemoryStorage)


def _counting_app(limiter: Limiter, **middleware_kwargs) -> tuple[FastAPI, list[str]]:
    """A minimal app wired with the real middleware; ``calls`` records every
    time the routed endpoint body actually ran."""
    app = FastAPI()
    app.state.limiter = limiter
    app.add_middleware(BoundedRateLimitMiddleware, **middleware_kwargs)
    calls: list[str] = []

    @app.get("/default")
    async def default(request: Request):
        """Record a default-route hit and echo the request path."""
        calls.append("default")
        return Response(request.url.path)

    @app.exception_handler(RateLimitExceeded)
    async def exceeded(_request, _exc):
        """Return the synthetic HTTP 429 response for RateLimitExceeded."""
        return Response("limited", status_code=429)

    return app, calls


def _unlimited_limiter() -> Limiter:
    """Build a high-limit fixed-window limiter for middleware dispatch tests."""
    return Limiter(
        key_func=lambda: "client",
        default_limits=["1000/minute"],
        strategy="fixed-window",
        headers_enabled=False,
    )


class TestDispatchFailsClosedOnEveryRejectionPath:
    """Cover dispatch fails closed on every rejection path."""

    async def test_healthy_backend_admits_the_request_and_calls_the_endpoint(self):
        """Check healthy backend admits the request and calls the endpoint (HTTP 200)."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/default")
        assert response.status_code == 200
        assert calls == ["default"]

    async def test_backend_storage_error_returns_503_and_logs_its_category(self, caplog):
        """Check backend storage error returns 503 and logs its category."""
        app, calls = _counting_app(_unlimited_limiter())
        with (
            patch.object(rl, "run_thread_work", autospec=True) as run_thread_work,
            caplog.at_level(logging.ERROR, logger="app.middleware.rate_limiting"),
        ):
            run_thread_work.side_effect = RedisConnectionError("connection refused")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/default")

        assert response.status_code == 503
        assert response.headers["Retry-After"] == "1"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert calls == []
        (record,) = [r for r in caplog.records if r.event_type == "rate_limit_backend_unavailable"]
        assert record.backend_failure_category == "connection"
        assert record.exception_type == "ConnectionError"

    async def test_bare_storage_error_is_categorized_as_storage(self, caplog):
        """A bare (unwrapped) `StorageError` — not a redis-py subclass — is
        still recognised as a backend failure and categorised as
        ``storage``, its fallback category."""
        app, calls = _counting_app(_unlimited_limiter())
        with (
            patch.object(rl, "run_thread_work", autospec=True) as run_thread_work,
            caplog.at_level(logging.ERROR, logger="app.middleware.rate_limiting"),
        ):
            run_thread_work.side_effect = StorageError("boom")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/default")

        assert response.status_code == 503
        assert calls == []
        (record,) = [r for r in caplog.records if r.event_type == "rate_limit_backend_unavailable"]
        assert record.backend_failure_category == "storage"
        assert record.exception_type == "StorageError"

    async def test_admission_timeout_returns_503_and_logs_the_timeout(self, caplog):
        """Check admission timeout returns 503 and logs the timeout."""
        app, calls = _counting_app(_unlimited_limiter())
        with (
            patch.object(rl, "run_thread_work", autospec=True) as run_thread_work,
            caplog.at_level(logging.WARNING, logger="app.middleware.rate_limiting"),
        ):
            run_thread_work.side_effect = ThreadWorkAdmissionTimeout(0.25)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/default")

        assert response.status_code == 503
        assert response.headers["Retry-After"] == "1"
        assert response.headers["Cache-Control"] == "no-store"
        assert calls == []
        (record,) = [r for r in caplog.records if r.event_type == "rate_limit_admission_timed_out"]
        assert not hasattr(record, "backend_failure_category")

    async def test_outstanding_capacity_exhaustion_rejects_a_concurrent_request(self):
        """Check outstanding capacity exhaustion rejects a concurrent request."""
        limiter = _unlimited_limiter()
        app, calls = _counting_app(limiter, max_outstanding_checks=1)
        original_hit = limiter.limiter.hit
        entered = threading.Event()
        release = threading.Event()

        def paused_hit(*args, **kwargs):
            """Pause a limiter hit for at most two seconds before invoking the real backend."""
            entered.set()
            assert release.wait(2), "test never released the parked worker"
            return original_hit(*args, **kwargs)

        with patch.object(limiter.limiter, "hit", side_effect=paused_hit):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                first = asyncio.ensure_future(client.get("/default"))
                await asyncio.wait_for(asyncio.to_thread(entered.wait), timeout=2)

                second = await client.get("/default")

                release.set()
                first_response = await asyncio.wait_for(first, timeout=2)

        assert second.status_code == 503
        assert second.headers["Retry-After"] == "1"
        assert first_response.status_code == 200
        assert calls == ["default"]

    async def test_unexpected_evaluation_exception_returns_503_and_logs_it(self, caplog):
        """Check unexpected evaluation exception returns 503 and logs it."""
        app, calls = _counting_app(_unlimited_limiter())
        with (
            patch.object(rl, "run_thread_work", autospec=True) as run_thread_work,
            caplog.at_level(logging.ERROR, logger="app.middleware.rate_limiting"),
        ):
            run_thread_work.side_effect = ValueError("unexpected")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/default")

        assert response.status_code == 503
        assert calls == []
        (record,) = [r for r in caplog.records if r.event_type == "rate_limit_evaluation_failed"]
        assert record.backend_failure_category == "unexpected"
        assert record.exception_type == "ValueError"

    async def test_route_resolution_failure_returns_503_and_logs_it(self, caplog):
        """A resolver exception (before any admission check ran) is fail
        closed the same way: 503, the endpoint never runs, and the log
        record names the resolution failure."""
        app, calls = _counting_app(_unlimited_limiter())
        with (
            patch.object(rl, "_resolve_rate_limit_handler", autospec=True) as resolve,
            caplog.at_level(logging.ERROR, logger="app.middleware.rate_limiting"),
        ):
            resolve.side_effect = RuntimeError("route table is broken")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/default")

        assert response.status_code == 503
        assert calls == []
        (record,) = [
            r for r in caplog.records if r.event_type == "rate_limit_route_resolution_failed"
        ]
        assert record.backend_failure_category == "unexpected"
        assert record.exception_type == "RuntimeError"


class TestDispatchNeverCallsTheEndpointOnA429Decision:
    """A 429 rate-limit decision, unlike a 503 admission failure, still
    reaches the SlowAPI exception handler — but must not run the routed
    endpoint body either."""

    async def test_429_decision_skips_the_endpoint_body(self):
        """Check 429 decision skips the endpoint body."""
        limiter = Limiter(
            key_func=lambda: "client",
            default_limits=["1/minute"],
            strategy="fixed-window",
            headers_enabled=False,
        )
        app, calls = _counting_app(limiter)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.get("/default")
            second = await client.get("/default")

        assert first.status_code == 200
        assert second.status_code == 429
        assert calls == ["default"]

    async def test_within_limit_requests_all_reach_the_endpoint_body(self):
        """Check within limit requests all reach the endpoint body."""
        limiter = Limiter(
            key_func=lambda: "client",
            default_limits=["3/minute"],
            strategy="fixed-window",
            headers_enabled=False,
        )
        app, calls = _counting_app(limiter)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            responses = [await client.get("/default") for _ in range(3)]

        assert [r.status_code for r in responses] == [200, 200, 200]
        assert calls == ["default", "default", "default"]


class TestUnnamedRouteAndResolverFailuresFailClosed:
    """Cover unnamed route and resolver failures fail closed."""

    async def test_an_unnamed_full_route_match_fails_closed(self):
        """Check an unnamed full route match fails closed (HTTP 503)."""
        limiter = _unlimited_limiter()
        app, calls = _counting_app(limiter)
        app.mount("/mounted", Response("mounted"))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/mounted/")

        assert response.status_code == 503
        assert calls == []

    async def test_ordinary_404_charges_the_sentinel_and_still_reaches_the_router(self):
        """Check ordinary 404 charges the sentinel and still reaches the router."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/no-such-route")

        assert response.status_code == 404
        assert calls == []

    async def test_ordinary_405_charges_the_sentinel_and_still_reaches_the_router(self):
        """Check ordinary 405 charges the sentinel and still reaches the router."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/default")

        assert response.status_code == 405
        assert calls == []
