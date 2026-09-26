"""Unit coverage for how the rate limiter is built and how it identifies clients.

Three production surfaces are pinned here:

- ``app.middleware.rate_limiting.setup_rate_limiting`` and
  ``validate_rate_limit_configuration``: the enable/disable wiring done at
  startup, and the startup validator that must admit every storage mode
  ``settings.rate_limit_storage_uri`` can resolve to.
- ``app.request_utils.get_client_ip``: the trust-gated client identity that
  becomes the limiter key. Forwarded headers (X-Real-IP, then
  X-Forwarded-For) are honored ONLY when the request came through a trusted
  upstream (TCP peer in the import-frozen ``_TRUSTED_UPSTREAM_IPS``, or a
  Unix-socket connection) AND ``settings.rate_limit_trust_proxy`` is True.
  Reading them unconditionally would let any client forge its apparent IP and
  evade per-IP rate limits, so the untrusted-peer cases pin the security
  boundary of this function.
- ``app.middleware.rate_limiting.BoundedRateLimitMiddleware``: every check and
  429-statistics read runs off the event loop in a worker thread, and the
  Redis backend has a bounded admission deadline so a dead backend falls back
  to in-memory storage instead of hanging every request.

No client for the first two surfaces: a minimal FastAPI app and raw ASGI
scopes are inspected structurally. The middleware class below is exercised
through a minimal FastAPI app of its own via ``httpx.AsyncClient`` (not the
application's ``guest_client`` fixtures); route-level rate-limit behavior on
the real application routes lives in the client tier and is not covered
here.
"""

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
    """Build a starlette Request from a raw ASGI scope.

    peer=None means no TCP client (Unix-socket style); combine with
    server=None or server=(host, None) to make the scope socket-shaped.
    """
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

    setup_rate_limiting has a disabled early-return (when RATE_LIMIT_ENABLED
    is false) that is otherwise unexercised — the test env runs with rate
    limiting ON. Pins both arms:

    - disabled -> returns without wiring anything (no app.state.limiter, no
      SlowAPIMiddleware added), so a deployment that turns limiting off
      doesn't half-install the middleware;
    - enabled  -> installs app.state.limiter and adds the middleware.
    """

    def test_disabled_setup_wires_nothing(self, monkeypatch):
        """RATE_LIMIT_ENABLED=false -> early return: no limiter on app.state
        and no middleware added. A disabled deployment must not pay for (or
        half-wire) the SlowAPI middleware."""
        monkeypatch.setattr(settings, "rate_limit_enabled", False)
        app = FastAPI()

        with patch.object(app, "add_middleware", autospec=True) as add_mw:
            setup_rate_limiting(app)
            add_mw.assert_not_called()

        assert not hasattr(app.state, "limiter")

    def test_enabled_setup_wires_limiter_and_middleware(self, monkeypatch):
        """RATE_LIMIT_ENABLED=true -> app.state.limiter is set and the
        SlowAPI middleware is added."""
        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        app = FastAPI()

        with patch.object(app, "add_middleware", autospec=True) as add_mw:
            setup_rate_limiting(app)
            assert add_mw.call_count == 1

        assert app.state.limiter is not None


class TestStorageModeValidation:
    """The startup validator accepts every storage mode the settings resolve to.

    ``settings.rate_limit_storage_uri`` (config/settings.py) resolves to the
    dedicated Redis URL, then the shared Redis URL, then ``"memory://"`` for a
    development process without Redis. The validator must admit the limiter
    that ``_build_limiter`` constructs for each of those outcomes.
    """

    def test_validator_admits_the_limiter_built_for_a_redis_url(self, monkeypatch):
        """Positive control: a dedicated Redis URL builds a limiter the validator accepts."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr("redis://fake-host:6379/9"))
        monkeypatch.setattr(settings, "redis_enabled", False)

        validate_rate_limit_configuration(rl._build_limiter())

    def test_validator_admits_the_limiter_built_for_process_local_memory_mode(self, monkeypatch):
        """A development process without any Redis URL must still start.

        With no dedicated URL and the shared Redis disabled the settings
        resolve to ``"memory://"`` and ``_build_limiter`` constructs an
        in-process MemoryStorage limiter; validating that limiter must not
        raise. Today the validator treats the resolved URI as a Redis URL and
        rejects the memory storage it asked for.
        """
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", False)

        validate_rate_limit_configuration(rl._build_limiter())


class TestClientIpAttribution:
    """Trust-gated client IP extraction — app.request_utils.get_client_ip.

    Forwarded headers (X-Real-IP, then X-Forwarded-For) must be honored ONLY
    when the request came through a trusted upstream (TCP peer in the
    import-frozen _TRUSTED_UPSTREAM_IPS, or a Unix-socket connection) AND
    settings.rate_limit_trust_proxy is True. Reading them unconditionally
    would let any client forge its apparent IP and evade per-IP rate limits,
    so the untrusted-peer and trust-off cases pin the security boundary of
    this function; each has a positive control in this class proving the
    permitted case still works.
    """

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
        """A trusted upstream (allowlisted TCP peer or Unix-socket connection)
        with trust enabled gets its forwarded header honored: whitespace is
        stripped, an invalid X-Real-IP falls through to the first
        X-Forwarded-For hop, a fully malformed pair falls back to the peer,
        both Unix-socket scope shapes count as trusted, and IPv6 values are
        accepted as-is. Losing this collapses every client onto nginx's IP
        and per-IP rate limits throttle everyone together."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        request = make_request(peer=peer, server=server, headers=headers)
        assert get_client_ip(request) == expected_ip

    def test_untrusted_peer_ignores_forwarded_headers(self, monkeypatch):
        """The security boundary: a direct (untrusted) peer 5.5.5.5 sending
        both forwarded headers gets attributed to 5.5.5.5, not the header
        values. Honoring these headers from arbitrary peers would let any
        client spoof its IP and evade per-IP rate limiting."""
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        request = make_request(
            peer="5.5.5.5",
            headers=[
                (b"x-real-ip", b"9.9.9.9"),
                (b"x-forwarded-for", b"8.8.8.8"),
            ],
        )
        assert get_client_ip(request) == "5.5.5.5"

    def test_trust_proxy_off_ignores_headers_even_from_trusted_peer(self):
        """Config gate: rate_limit_trust_proxy=False (the test-env default)
        means forwarded headers are ignored even when the peer IS a trusted
        upstream. Pins settings.rate_limit_trust_proxy being read at call time."""
        assert settings.rate_limit_trust_proxy is False  # test-env default
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
        """_TRUSTED_UPSTREAM_IPS is frozen from settings.trusted_proxy_ips at
        module import; mutating the setting afterwards must NOT widen the
        trust set. Guards against a refactor that re-reads the setting at
        call time and lets a runtime config mutation open the spoofing
        boundary."""
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
        return Response(request.url.path)

    @app.get("/decorated")
    @limiter.limit("1/minute")
    async def decorated(request: Request):
        return Response(request.url.path)

    @app.exception_handler(RateLimitExceeded)
    async def exceeded(request, _exc):
        assert request.state.rate_limit_stats is not None
        return Response("limited", status_code=429)

    return app


class TestMiddlewareOffloadingAndBackendDeadlines:
    """BoundedRateLimitMiddleware keeps the event loop free and bounds the
    time it will wait on a dead storage backend.

    Every limiter check and every 429-statistics read is dispatched onto a
    worker thread, never run inline on the event loop; and a storage backend
    that stops responding must not stall requests indefinitely — it has a
    fixed admission deadline and the limiter falls back to in-memory
    storage once that deadline is exceeded.
    """

    @pytest.mark.parametrize(
        "path",
        ["/default", "/decorated"],
        ids=["default_route_uses_the_global_limit", "decorated_route_uses_its_own_limit"],
    )
    async def test_checks_and_429_statistics_run_off_the_event_loop(self, path, monkeypatch):
        """`hit` and `get_window_stats` both run on a worker thread (never
        the main thread) while the event loop keeps ticking, and a decorated
        route's own limit check is not followed by a second, redundant
        check.

        Instead of sleeping a fixed wall-clock duration inside the worker
        call, the worker parks on a `threading.Event` and a loop-side watcher
        only releases it once the event loop has observably kept advancing
        (a bounded tick counter) while the call was parked — proving the
        offload, not just coincidental timing.
        """
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
        assert worker_calls.count("hit") == 2  # The decorator never performs a second check.
        assert worker_calls.count("get_window_stats") == 1

    async def test_a_dead_backend_returns_503_without_falling_back_to_in_memory_counters(self):
        """The application limiter policy (`_build_limiter`'s exact options:
        `in_memory_fallback_enabled=False`, `swallow_errors=False`,
        `redis_storage_options()`) against a backend that accepts the socket
        and never replies returns a fail-closed 503 within the bounded
        admission/socket deadline, never falls back to an in-process counter
        (`limiter._storage_dead` stays False and storage is never swapped),
        and never runs the endpoint body."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(2)
        stop = threading.Event()

        def blackhole():
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
            nonlocal endpoint_ran
            endpoint_ran = True
            return Response(request.url.path)

        @app.exception_handler(RateLimitExceeded)
        async def exceeded(_request, _exc):
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
        calls.append("default")
        return Response(request.url.path)

    @app.exception_handler(RateLimitExceeded)
    async def exceeded(_request, _exc):
        return Response("limited", status_code=429)

    return app, calls


def _unlimited_limiter() -> Limiter:
    return Limiter(
        key_func=lambda: "client",
        default_limits=["1000/minute"],
        strategy="fixed-window",
        headers_enabled=False,
    )


class TestDispatchFailsClosedOnEveryRejectionPath:
    """Every way BoundedRateLimitMiddleware.dispatch can refuse a request
    returns the same fail-closed contract — 503, a Retry-After header, a
    no-store cache directive, and the routed endpoint body never runs —
    proven against the real middleware object, and each carries a log
    record naming the failure so an operator can tell them apart. The
    healthy-backend control in this class proves the contract isn't
    tripped for an ordinary accepted request.
    """

    async def test_healthy_backend_admits_the_request_and_calls_the_endpoint(self):
        """Positive control: a working limiter and backend admit the request
        with 200 and the endpoint body runs exactly once."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/default")
        assert response.status_code == 200
        assert calls == ["default"]

    async def test_backend_storage_error_returns_503_and_logs_its_category(self, caplog):
        """A `StorageError`/`RedisError` raised while evaluating limits is
        caught as a backend failure: 503, Retry-After, no-store, the
        endpoint never runs, and the log record names the failure
        category and exception class."""
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
        """A `ThreadWorkAdmissionTimeout` from the worker adapter (the
        bounded evaluation queue was full for too long) is a 503, not a
        backend failure category: the endpoint never runs and the log
        record names the timeout event."""
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
        """`_outstanding_capacity`'s `WouldBlock` (too many checks already in
        flight) rejects the second of two concurrent requests with 503
        while the first — genuinely still running in its worker thread —
        is unaffected and eventually completes normally. Two independent
        anyio capacity slots are exercised for real; nothing about
        `anyio.CapacityLimiter` is mocked."""
        limiter = _unlimited_limiter()
        app, calls = _counting_app(limiter, max_outstanding_checks=1)
        original_hit = limiter.limiter.hit
        entered = threading.Event()
        release = threading.Event()

        def paused_hit(*args, **kwargs):
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
        """Any exception from evaluation besides the recognised backend and
        timeout errors is still fail-closed: 503, the endpoint never
        runs, and the log record captures the exception class under the
        ``unexpected`` category."""
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
        """Positive control: while under the configured limit, every request
        reaches the endpoint."""
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
    """`_resolve_rate_limit_handler` failing, or a full match on an unnamed
    ASGI mount, must fail closed rather than share the ordinary
    unmatched-route sentinel bucket; ordinary 404/405 traffic keeps using
    that sentinel and still reaches the router (the permitted case)."""

    async def test_an_unnamed_full_route_match_fails_closed(self):
        """A full route match whose endpoint has no stable
        ``__module__``/``__name__`` identity (an unnamed ASGI mount) raises
        inside the resolver and must return 503, not the sentinel bucket,
        and never call the endpoint."""
        limiter = _unlimited_limiter()
        app, calls = _counting_app(limiter)
        app.mount("/mounted", Response("mounted"))  # a bare ASGI callable, no __name__

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/mounted/")

        assert response.status_code == 503
        assert calls == []

    async def test_ordinary_404_charges_the_sentinel_and_still_reaches_the_router(self):
        """Positive control: an ordinary unmatched path is not a resolver
        failure — it charges the shared sentinel bucket and still reaches
        the router for its normal 404 response."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/no-such-route")

        assert response.status_code == 404
        assert calls == []

    async def test_ordinary_405_charges_the_sentinel_and_still_reaches_the_router(self):
        """Positive control: a method mismatch on a real route is not a
        resolver failure — it charges the shared sentinel bucket and still
        reaches the router for its normal 405 response."""
        app, calls = _counting_app(_unlimited_limiter())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/default")

        assert response.status_code == 405
        assert calls == []
