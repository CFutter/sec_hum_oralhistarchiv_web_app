"""Rate-limit admission against a real Redis backend and the real database."""

import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import create_autospec

import httpx
import pytest
import redis as redis_lib
from limits import RateLimitItemPerMinute
from limits.storage import storage_from_string
from limits.storage.redis import RedisStorage
from limits.strategies import FixedWindowRateLimiter

import app.middleware.session as _session_module
from app.middleware.bounded_rate_limit_storage import CONTROL_KEYS, bounded_redis_uri
from app.middleware.rate_limiting import (
    _RATE_LIMIT_KEY_PREFIX,
    bounded_storage_options,
    limiter,
)
from app.services.sessions import get_session_user as _real_get_session_user
from config import settings

from .conftest import login_with_totp
from .server_processes import free_port as _free_port
from .server_processes import start_private_redis as _start_private_redis
from .server_processes import terminate_process as _terminate

pytestmark = pytest.mark.usefixtures("clean_db")

_BOUNDED_WAIT_SECONDS = 10.0
_REPO_SRC_DIR = Path(__file__).resolve().parent.parent.parent
_GUNICORN_BIN = shutil.which("gunicorn") or str(_REPO_SRC_DIR.parent / ".venv" / "bin" / "gunicorn")


def _rate_limit_redis_url() -> str:
    """Return the configured limiter Redis URL as plain text."""
    return settings.rate_limit_redis_url.get_secret_value()


def _inspection_client() -> redis_lib.Redis:
    """Create a decoded-response Redis client for the limiter database."""
    return redis_lib.Redis.from_url(_rate_limit_redis_url(), decode_responses=True)


@contextmanager
def _limiter_pointed_at(storage_uri: str) -> Iterator[RedisStorage]:
    """Swap only the real global limiter's storage backend for the duration.

    Preserves every other production wire-up on the SAME ``Limiter``
    singleton the application registers as ``app.state.limiter`` (exempt
    routes, per-view decorator limits, default limits), so ``/health``
    remains exempt and named-route budgets keep applying while only the
    Redis backend changes.
    """
    storage = storage_from_string(bounded_redis_uri(storage_uri), **bounded_storage_options())
    assert isinstance(storage, RedisStorage), "test limiter requires synchronous Redis storage"

    original_storage = limiter.limiter.storage
    limiter.limiter.storage = storage
    try:
        yield storage
    finally:
        limiter.limiter.storage = original_storage


def _route_segment(redis_key: str) -> str:
    """Return the route-identity segment of a real limiter key.

    A key produced by ``limits``' Redis storage looks like
    ``LIMITS:LIMITER/oralhistarchiv-security-v1/ip-v2:<hmac>/<route>/<amount>/<multiple>/<unit>``
    — three such keys per request (day/hour/minute). The fourth-from-last
    ``/``-separated segment is the route identity that many distinct unknown
    paths must collapse onto for the sentinel bucket.
    """
    return redis_key.split("/")[-4]


# Unmatched-route sentinel sharing and named-route independence


class TestUnmatchedRouteSentinelIsSharedAndIndependentOfNamedBudgets:
    """Check unmatched Route Sentinel Is Shared And Independent Of Named Budgets."""

    def test_404_and_405_traffic_share_one_sentinel_allowance(self, e2e_client):
        """Verify 404 and 405 traffic share one sentinel allowance."""
        per_minute = settings.rate_limit_per_minute
        responses = []
        for i in range(per_minute):
            if i % 2 == 0:
                responses.append(e2e_client.get(f"/no-such-route-{i}"))
            else:
                # /login only accepts GET/POST; PUT is a method mismatch (405).
                responses.append(e2e_client.put("/login"))

        assert all(r.status_code in (404, 405) for r in responses)

        exhausted = e2e_client.get("/still-not-a-route")
        assert exhausted.status_code == 429, (
            "404 and 405 traffic did not share one sentinel allowance"
        )

    def test_a_named_route_keeps_its_own_budget_after_the_sentinel_is_exhausted(self, e2e_client):
        """Positive control: exhausting the sentinel doesn't touch /login's budget."""
        per_minute = settings.rate_limit_per_minute
        for i in range(per_minute + 5):
            e2e_client.get(f"/no-such-route-{i}")

        response = e2e_client.get("/login")
        assert response.status_code == 200, (
            "a named route was rejected by the unrelated sentinel bucket"
        )


# Concurrent admission against the real, pinned Redis


class TestConcurrentAdmissionAgainstRealRedis:
    """Check concurrent Admission Against Real Redis."""

    def test_concurrent_hits_from_independent_connections_admit_exactly_the_limit(self):
        """Verify concurrent hits from independent connections admit exactly the limit."""
        item = RateLimitItemPerMinute(10, 1)
        key = f"concurrent-admission-{os.getpid()}-{time.time_ns()}"
        contenders = 25

        def _hit() -> bool:
            # Independent Storage/connection per contender.
            """Attempt admission through a real Redis-backed fixed-window limiter."""
            storage = storage_from_string(
                bounded_redis_uri(_rate_limit_redis_url()), **bounded_storage_options()
            )
            strategy = FixedWindowRateLimiter(storage)
            return strategy.hit(item, key)

        try:
            with ThreadPoolExecutor(max_workers=contenders) as pool:
                results = list(pool.map(lambda _: _hit(), range(contenders)))
            admitted = sum(results)
            assert admitted == item.amount, (
                f"expected exactly {item.amount} admissions, got {admitted}"
            )
        finally:
            storage_from_string(
                bounded_redis_uri(_rate_limit_redis_url()), **bounded_storage_options()
            ).clear(item.key_for(key))

    def test_a_single_contender_is_admitted_up_to_the_limit(self):
        """Positive control: sequential hits admit until the same limit, no more."""
        item = RateLimitItemPerMinute(4, 1)
        key = f"sequential-admission-{os.getpid()}-{time.time_ns()}"
        storage = storage_from_string(
            bounded_redis_uri(_rate_limit_redis_url()), **bounded_storage_options()
        )
        strategy = FixedWindowRateLimiter(storage)
        try:
            results = [strategy.hit(item, key) for _ in range(6)]
            assert results == [True, True, True, True, False, False]
        finally:
            storage.clear(item.key_for(key))


# Key namespace, HMAC-only identity, bounded TTL, single sentinel scope


class TestLimiterKeysCarryOnlyTheReviewedNamespaceIdentityAndTtl:
    """Check limiter Keys Carry Only The Reviewed Namespace Identity And TTL."""

    def test_keys_created_by_real_traffic_use_the_reviewed_prefix_identity_and_ttl(
        self, e2e_client
    ):
        """Verify keys created by real traffic use the reviewed prefix identity and TTL."""
        e2e_client.get("/login")
        e2e_client.put("/login")  # 405, feeds the sentinel bucket too

        inspector = _inspection_client()
        try:
            keys = [
                k
                for k in inspector.scan_iter(match="*")
                if _RATE_LIMIT_KEY_PREFIX in k and k not in CONTROL_KEYS
            ]
            assert keys, "no limiter keys were created by real traffic"
            largest_window_seconds = 24 * 60 * 60  # the configured per-day window
            for key in keys:
                assert f"/{_RATE_LIMIT_KEY_PREFIX}/" in key
                assert "ip-v2:" in key, f"key {key!r} does not carry the reviewed identity"
                identity_start = key.index("ip-v2:") + len("ip-v2:")
                identity = key[identity_start:].split("/", 1)[0]
                assert all(c in "0123456789abcdef" for c in identity), (
                    f"identity segment of {key!r} is not an opaque HMAC digest"
                )
                assert "127.0.0.1" not in key
                assert "testclient" not in key
                assert "?" not in key
                assert "@" not in key
                ttl = inspector.ttl(key)
                assert 0 < ttl <= largest_window_seconds + 1
        finally:
            inspector.close()

    def test_ipv6_addresses_in_one_prefix_share_the_stored_counter(self, e2e_client_from_address):
        """Against the real Redis: two addresses from one routed IPv6 prefix
        must land on the same stored key, and an address from the next prefix
        must land on a different one. The stored key still carries nothing but
        the opaque identity — never the address or the prefix it came from."""
        first_address = e2e_client_from_address("2001:db8:abcd:1234::1")
        second_address = e2e_client_from_address("2001:db8:abcd:1234::99")
        neighbouring_prefix = e2e_client_from_address("2001:db8:abcd:1235::1")

        for client in (first_address, second_address, neighbouring_prefix):
            assert client.get("/login").status_code == 200

        inspector = _inspection_client()
        try:
            keys = [
                key
                for key in inspector.scan_iter(match="*")
                if _RATE_LIMIT_KEY_PREFIX in key and "login_page" in key and "/1/minute" in key
            ]
            assert len(keys) == 2, (
                "three addresses from two prefixes must produce exactly two "
                f"per-minute counters, got: {sorted(keys)}"
            )
            shared_key = next(key for key in keys if inspector.get(key) == "2")
            separate_key = next(key for key in keys if key != shared_key)
            assert inspector.get(separate_key) == "1"

            for key in keys:
                for leak in ("2001", "db8", "abcd:1234", "abcd:1235"):
                    assert leak not in key, f"key {key!r} discloses the client network"
                assert 0 < inspector.ttl(key) <= 61
        finally:
            inspector.close()

    def test_unknown_paths_collapse_into_one_sentinel_key_scope(self, e2e_client):
        """Verify unknown paths collapse into one sentinel key scope."""
        for i in range(12):
            e2e_client.get(f"/definitely-not-a-real-endpoint-{i}/{'x' * i}")

        inspector = _inspection_client()
        try:
            keys = [
                k
                for k in inspector.scan_iter(match="*")
                if _RATE_LIMIT_KEY_PREFIX in k and k not in CONTROL_KEYS
            ]
            assert keys, "no limiter keys were created by the unknown-path traffic"
            routes = {_route_segment(k) for k in keys}
            # However the route segment is spelled, all 12 distinct unknown
            # paths must resolve to the SAME route identity (one key scope
            # per limit period, not one per attacker-chosen path).
            assert len(routes) == 1, f"unknown paths created more than one route identity: {routes}"
        finally:
            inspector.close()


# A private redis-server outage (SIGSTOP) and recovery


class TestPrivateRedisOutageFailsClosedAndRecoversOnItsOwnWindow:
    """Check private Redis Outage Fails Closed And Recovers On Its Own Window."""

    def test_a_stopped_backend_returns_503_without_running_the_endpoint_then_429_after_resume(
        self, e2e_client, private_redis
    ):
        """Verify a stopped backend returns 503 without running the endpoint then 429 after resume."""
        port, proc = private_redis
        with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
            for _ in range(settings.rate_limit_per_minute):
                response = e2e_client.get("/login")
                assert response.status_code == 200

            exhausted = e2e_client.get("/login")
            assert exhausted.status_code == 429

            os.kill(proc.pid, signal.SIGSTOP)
            try:
                unavailable = e2e_client.get("/login")
                assert unavailable.status_code == 503
                assert "temporarily unavailable" in unavailable.text
                assert e2e_client.get("/health").status_code == 200
            finally:
                os.kill(proc.pid, signal.SIGCONT)

            still_exhausted = e2e_client.get("/login")
            assert still_exhausted.status_code == 429, (
                "the counter did not survive the outage; a fresh allowance appeared"
            )

    def test_after_the_limiter_is_reset_the_route_serves_again(self, e2e_client, private_redis):
        """Positive control: recovery is real, not a permanently stuck 429."""
        port, _proc = private_redis
        with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0") as storage:
            for _ in range(settings.rate_limit_per_minute):
                e2e_client.get("/login")
            assert e2e_client.get("/login").status_code == 429

            # A fresh key, not a sleep, proves recovery: the window itself
            # would also clear after 60s, but the test may not wait for it.
            storage.reset()

            assert e2e_client.get("/login").status_code == 200


# Memory pressure with noeviction rejects writes without a fallback


class TestPrivateRedisMemoryPressureFailsClosedWithoutAnInMemoryFallback:
    """Check private Redis Memory Pressure Fails Closed Without An In Memory Fallback."""

    def test_a_write_rejected_under_maxmemory_returns_503_and_keeps_existing_keys(
        self, tmp_path, e2e_client
    ):
        """Verify a write rejected under maxmemory returns 503 and keeps existing keys."""
        port = _free_port()
        proc = _start_private_redis(
            tmp_path,
            port,
            "--maxmemory",
            "4mb",
            "--maxmemory-policy",
            "noeviction",
        )
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                baseline = e2e_client.get("/login")
                assert baseline.status_code == 200

                raw = redis_lib.Redis(host="127.0.0.1", port=port)
                try:
                    filler = b"x" * 1024
                    with pytest.raises(redis_lib.exceptions.ResponseError):
                        for i in range(16384):  # 16 MB of values: always exceeds 4mb
                            raw.set(f"filler:{i}", filler)
                    existing_keys = raw.dbsize()
                    assert existing_keys > 0

                    rejected = e2e_client.get("/login")
                    assert rejected.status_code == 503

                    assert raw.dbsize() == existing_keys, (
                        "a rejected write still mutated the keyspace"
                    )
                finally:
                    raw.close()

                assert limiter._storage_dead is False, (
                    "storage-dead in-memory fallback flag must never be used"
                )
                assert not isinstance(limiter.limiter.storage, type(None))
                assert isinstance(limiter.limiter.storage, RedisStorage), (
                    "the limiter fell back to a non-Redis storage under memory pressure"
                )
        finally:
            _terminate(proc)

    def test_the_same_backend_serves_normally_before_it_is_full(self, tmp_path, e2e_client):
        """Positive control: a private backend with room to spare works normally."""
        port = _free_port()
        proc = _start_private_redis(tmp_path, port, "--maxmemory", "64mb")
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                assert e2e_client.get("/login").status_code == 200
        finally:
            _terminate(proc)


# Persistence across a server restart


class TestPrivateRedisPersistenceSurvivesARestart:
    """Check private Redis Persistence Survives ARestart."""

    def test_counter_and_ttl_survive_a_server_restart_with_appendonly(self, tmp_path, e2e_client):
        """Verify counter and TTL survive a server restart with appendonly."""
        port = _free_port()
        proc = _start_private_redis(tmp_path, port, "--appendonly", "yes")
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                for _ in range(settings.rate_limit_per_minute):
                    e2e_client.get("/login")
                assert e2e_client.get("/login").status_code == 429

            _terminate(proc)
            proc = _start_private_redis(tmp_path, port, "--appendonly", "yes")

            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                still_exhausted = e2e_client.get("/login")
                assert still_exhausted.status_code == 429, (
                    "the counter did not survive a restart of a persistent backend"
                )
        finally:
            _terminate(proc)

    def test_a_freshly_restarted_backend_without_appendonly_starts_with_no_counters(
        self, tmp_path, e2e_client
    ):
        """Positive control: without persistence, a restart legitimately clears state."""
        port = _free_port()
        proc = _start_private_redis(tmp_path, port, "--appendonly", "no")
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                for _ in range(settings.rate_limit_per_minute):
                    e2e_client.get("/login")
                assert e2e_client.get("/login").status_code == 429

            _terminate(proc)
            proc = _start_private_redis(tmp_path, port, "--appendonly", "no")

            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/0"):
                assert e2e_client.get("/login").status_code == 200
        finally:
            _terminate(proc)


# The cache Redis database and the limiter's Redis database stay separate


class TestLimiterCountersAreIsolatedFromTheApplicationCacheDatabase:
    """Check limiter Counters Are Isolated From The Application Cache Database."""

    def test_flushing_the_cache_database_leaves_limiter_counters_intact(self, tmp_path, e2e_client):
        """Verify flushing the cache database leaves limiter counters intact."""
        port = _free_port()
        proc = _start_private_redis(tmp_path, port, "--appendonly", "no")
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/1"):
                for _ in range(3):
                    e2e_client.get("/login")

                cache_db = redis_lib.Redis(host="127.0.0.1", port=port, db=0)
                try:
                    cache_db.set("cache:some-application-key", "value")
                    cache_db.flushdb()
                    assert cache_db.dbsize() == 0
                finally:
                    cache_db.close()

                limiter_db = redis_lib.Redis(host="127.0.0.1", port=port, db=1)
                try:
                    assert limiter_db.dbsize() > 0, (
                        "flushing db 0 also cleared the limiter's db 1 counters"
                    )
                finally:
                    limiter_db.close()

                assert e2e_client.get("/login").status_code == 200
        finally:
            _terminate(proc)

    def test_flushing_the_limiter_database_leaves_a_separate_cache_key_intact(
        self, tmp_path, e2e_client
    ):
        """Positive control for the same isolation, in the other direction."""
        port = _free_port()
        proc = _start_private_redis(tmp_path, port, "--appendonly", "no")
        try:
            with _limiter_pointed_at(f"redis://127.0.0.1:{port}/1"):
                e2e_client.get("/login")

                cache_db = redis_lib.Redis(host="127.0.0.1", port=port, db=0)
                limiter_db = redis_lib.Redis(host="127.0.0.1", port=port, db=1)
                try:
                    cache_db.set("cache:some-application-key", "value")
                    limiter_db.flushdb()
                    assert cache_db.get("cache:some-application-key") == b"value"
                finally:
                    cache_db.close()
                    limiter_db.close()
        finally:
            _terminate(proc)


# Admission ordering against the real stack


class TestAdmissionOrderingAgainstTheLiveStack:
    """Default limits are scoped per resolved endpoint (``key_style="endpoint"``),
    so exhausting one named route's bucket never touches another's; every
    scenario below exhausts the SAME bucket it later probes: ``/account``'s
    own default bucket for the known-route case, and the shared unmatched-route
    sentinel bucket (one scope for every 404/405) for the other two.
    """

    async def test_an_exhausted_bucket_rejects_authenticated_traffic_without_running_the_route(
        self, e2e_client, user_factory, monkeypatch
    ):
        """Verify an exhausted bucket rejects authenticated traffic without running the route."""
        login_with_totp(e2e_client, user_factory)

        spy = create_autospec(_real_get_session_user, side_effect=_real_get_session_user)
        monkeypatch.setattr(_session_module, "get_session_user", spy)

        for _ in range(settings.rate_limit_per_minute):
            e2e_client.get("/account", follow_redirects=False)
        for i in range(settings.rate_limit_per_minute):
            e2e_client.get(f"/no-such-route-{i}")

        calls_before = spy.await_count
        known_route = e2e_client.get("/account", follow_redirects=False)
        not_found = e2e_client.get(f"/no-such-route-{time.time_ns()}")
        method_mismatch = e2e_client.put("/login")

        assert known_route.status_code == 429
        assert not_found.status_code == 429
        assert method_mismatch.status_code == 429
        assert spy.await_count == calls_before, (
            "expected the session-resolution spy to run once per rejected request"
        )

    async def test_an_exhausted_bucket_rejects_traffic_before_any_session_lookup(
        self, e2e_client, user_factory, monkeypatch
    ):
        """Verify an exhausted bucket rejects traffic before any session lookup."""
        login_with_totp(e2e_client, user_factory)

        spy = create_autospec(_real_get_session_user, side_effect=_real_get_session_user)
        monkeypatch.setattr(_session_module, "get_session_user", spy)

        for _ in range(settings.rate_limit_per_minute):
            e2e_client.get("/account", follow_redirects=False)

        calls_before = spy.await_count
        response = e2e_client.get("/account", follow_redirects=False)

        assert response.status_code == 429
        assert spy.await_count == calls_before, (
            "a rejected request performed a session lookup before admission decided it"
        )

    def test_redis_unavailable_rejects_every_request_with_503(self, e2e_client, user_factory):
        """Verify Redis unavailable rejects every request with 503."""
        login_with_totp(e2e_client, user_factory)
        closed_port = _free_port()  # nothing is listening; connection refused
        with _limiter_pointed_at(f"redis://127.0.0.1:{closed_port}/0"):
            response = e2e_client.get("/account", follow_redirects=False)
            assert response.status_code == 503

    async def test_redis_unavailable_rejects_before_any_pool_checkout(
        self, e2e_client, user_factory, monkeypatch
    ):
        """Verify Redis unavailable rejects before any pool checkout."""
        login_with_totp(e2e_client, user_factory)

        spy = create_autospec(_real_get_session_user, side_effect=_real_get_session_user)
        monkeypatch.setattr(_session_module, "get_session_user", spy)

        closed_port = _free_port()
        with _limiter_pointed_at(f"redis://127.0.0.1:{closed_port}/0"):
            calls_before = spy.await_count
            response = e2e_client.get("/account", follow_redirects=False)

        assert response.status_code == 503
        assert spy.await_count == calls_before

    def test_a_fresh_bucket_admits_authenticated_traffic_normally(self, e2e_client, user_factory):
        """Positive control: without exhausting or breaking anything, /account works."""
        login_with_totp(e2e_client, user_factory)
        response = e2e_client.get("/account", follow_redirects=False)
        assert response.status_code == 200


# Two real Gunicorn workers sharing one Redis-backed bucket


def _http_get(base_url: str, path: str) -> httpx.Response:
    # A fresh, non-keep-alive connection per call so consecutive requests are
    # free to land on either worker instead of pinning one TCP connection.
    """GET a path with a fresh five-second HTTP client and a close connection header."""
    with httpx.Client(base_url=base_url, headers={"Connection": "close"}, timeout=5.0) as client:
        return client.get(path)


def _http_get_through_worker_recycling(
    base_url: str, path: str, *, timeout: float = 40.0
) -> httpx.Response:
    """Retry a request while a worker mid-recycle briefly refuses connections.

    ``--max-requests`` recycling closes and forks a new worker; a request
    landing in that gap sees a connection error or timeout, not an HTTP
    response — a real, bounded condition of the process under test, not an
    arbitrary sleep. Each attempt uses a short per-request timeout so many
    attempts fit inside the overall deadline.
    """
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with httpx.Client(
                base_url=base_url, headers={"Connection": "close"}, timeout=2.0
            ) as client:
                return client.get(path)
        except httpx.TransportError as exc:
            last_exc = exc
            time.sleep(0.05)
    raise RuntimeError(f"{path} kept failing through worker recycling: {last_exc}")


def _spawn_gunicorn(
    port: int, *, extra_args: tuple[str, ...] = (), hourly_quota: int | None = None
) -> subprocess.Popen[bytes]:
    """Launch real workers, optionally retaining a focused process test's quota for an hour."""
    env = os.environ.copy()
    env["ENV_STATE"] = "dev"
    if hourly_quota is not None:
        env["RATE_LIMIT_PER_HOUR"] = str(hourly_quota)
    cmd = [
        _GUNICORN_BIN,
        "-w",
        "2",
        "-k",
        "app.server_worker.SafeUvicornWorker",
        "-b",
        f"127.0.0.1:{port}",
        *extra_args,
        "app.main:app",
    ]
    # A session of its own so the whole master+workers group can be reaped;
    # output discarded rather than piped, because an unread pipe would block
    # the master's own logging and stall its graceful shutdown.
    return subprocess.Popen(
        cmd,
        cwd=_REPO_SRC_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _wait_for_http_ready(base_url: str, *, timeout: float = 20.0) -> None:
    """Poll /health for HTTP 200; raise RuntimeError after the timeout in seconds."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = _http_get(base_url, "/health")
            if response.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(0.2)
    raise RuntimeError(f"gunicorn at {base_url} never became ready: {last_exc}")


def _worker_pids(proc: subprocess.Popen[bytes]) -> set[int]:
    """PIDs of the gunicorn master's current worker processes (Linux)."""
    children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children")
    return {int(pid) for pid in children.read_text().split()}


def _wait_for_worker_replacement(
    proc: subprocess.Popen[bytes], old_workers: set[int], *, workers: int = 2, timeout: float = 30.0
) -> None:
    """Wait until a SIGHUP reload has replaced every pre-reload worker, so a
    readiness probe cannot be answered by a worker that is about to exit."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = _worker_pids(proc)
        if len(current) == workers and not current & old_workers:
            return
        time.sleep(0.1)
    raise RuntimeError(f"gunicorn did not replace its workers within {timeout}s")


@pytest.fixture
def gunicorn_pair() -> Iterator[tuple[str, subprocess.Popen[bytes]]]:
    """Start the configured two-worker Gunicorn master and terminate its process group on teardown."""
    if not Path(_GUNICORN_BIN).exists():
        pytest.fail(f"gunicorn binary not found at {_GUNICORN_BIN}")
    port = _free_port()
    proc = _spawn_gunicorn(port)
    try:
        _wait_for_http_ready(f"http://127.0.0.1:{port}")
        yield f"http://127.0.0.1:{port}", proc
    finally:
        _terminate(proc, timeout=10.0)


class TestTwoGunicornWorkersShareOneRedisBackedBucket:
    """Check two Gunicorn Workers Share One Redis Backed Bucket."""

    def test_every_worker_rejects_once_the_shared_bucket_is_exhausted(self, gunicorn_pair):
        """Verify every worker rejects once the shared bucket is exhausted."""
        base_url, _proc = gunicorn_pair
        for _ in range(settings.rate_limit_per_minute):
            response = _http_get(base_url, "/login")
            assert response.status_code == 200

        rejections = [_http_get(base_url, "/login").status_code for _ in range(10)]
        assert all(status == 429 for status in rejections), rejections

    def test_a_graceful_reload_does_not_restore_the_exhausted_quota(self, gunicorn_pair):
        """Verify a graceful reload does not restore the exhausted quota."""
        base_url, proc = gunicorn_pair
        for _ in range(settings.rate_limit_per_minute):
            _http_get(base_url, "/login")
        assert _http_get(base_url, "/login").status_code == 429

        old_workers = _worker_pids(proc)
        proc.send_signal(signal.SIGHUP)
        _wait_for_worker_replacement(proc, old_workers)
        _wait_for_http_ready(base_url)

        assert _http_get(base_url, "/login").status_code == 429

    def test_worker_recycling_via_max_requests_does_not_restore_the_quota(self, tmp_path):
        # Process startup/recycling can outlive a legitimate one-minute window
        # on a loaded host. Exhaust the same request allowance in a real hourly
        # Redis bucket as well, then prove that bucket survived actual recycling.
        """Verify worker recycling via max requests does not restore the quota."""
        quota = settings.rate_limit_per_minute
        worker_log = tmp_path / "gunicorn-workers.log"
        port = _free_port()
        proc = _spawn_gunicorn(
            port,
            extra_args=("--max-requests", "5", "--error-logfile", str(worker_log)),
            hourly_quota=quota,
        )
        inspector = _inspection_client()

        def booted_workers() -> set[int]:
            """Extract distinct Gunicorn worker PIDs from the captured log."""
            return {
                int(pid)
                for pid in re.findall(r"Booting worker with pid: (\d+)", worker_log.read_text())
            }

        try:
            base_url = f"http://127.0.0.1:{port}"
            _wait_for_http_ready(base_url)
            # Transport retries can charge an admission whose response was lost
            # mid-recycle. The stored counter, rather than an exact HTTP count,
            # establishes exhaustion of the real shared bucket.
            for _ in range(quota):
                _http_get_through_worker_recycling(base_url, "/login")
            assert _http_get_through_worker_recycling(base_url, "/login").status_code == 429
            hourly_keys = [
                key
                for key in inspector.scan_iter(match="*")
                if _RATE_LIMIT_KEY_PREFIX in key
                and "login_page" in key
                and key.endswith(f"/{quota}/1/hour")
            ]
            assert len(hourly_keys) == 1, hourly_keys
            key = hourly_keys[0]
            before = inspector.get(key)
            assert before is not None and int(before) >= quota
            ttl_before = inspector.pttl(key)
            assert ttl_before > RateLimitItemPerMinute(1).get_expiry() * 1000
            workers_before = booted_workers()
            assert workers_before

            # /health is exempt from rate limiting but counts toward Gunicorn's
            # max_requests. Its boot log proves a new worker actually started.
            for _ in range(30):
                response = _http_get_through_worker_recycling(base_url, "/health")
                assert response.status_code == 200
            # Uvicorn checks max_requests on its periodic server tick; a fast
            # burst may finish before shutdown/replacement has begun.
            deadline = time.monotonic() + _BOUNDED_WAIT_SECONDS
            while not booted_workers() - workers_before and time.monotonic() < deadline:
                time.sleep(0.05)
            assert booted_workers() - workers_before, "no worker recycled during health traffic"
            after = inspector.get(key)
            assert after is not None and int(after) >= int(before), (
                "worker recycling removed or reduced the exhausted hourly counter"
            )
            assert 0 < inspector.pttl(key) <= ttl_before, (
                "the exhausted hourly bucket expired or acquired a fresh window"
            )
            assert _http_get_through_worker_recycling(base_url, "/login").status_code == 429, (
                "worker recycling restored the exhausted quota"
            )
        finally:
            inspector.close()
            _terminate(proc, timeout=10.0)

    def test_a_freshly_started_pair_admits_normal_traffic(self, gunicorn_pair):
        """Positive control: two real workers serve ordinary traffic normally."""
        base_url, _proc = gunicorn_pair
        response = _http_get(base_url, "/login")
        assert response.status_code == 200
