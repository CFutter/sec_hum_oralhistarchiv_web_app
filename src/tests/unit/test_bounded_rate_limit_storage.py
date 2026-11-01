"""Actual Redis allocation, expiry, restart, and shared search admission."""

import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
import redis
from fastapi import FastAPI, Request, Response
from limits.errors import StorageError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

import app.middleware.bounded_rate_limit_storage as storage_module
import app.middleware.rate_limiting as rl
from app.middleware.bounded_rate_limit_storage import (
    CONTROL_KEYS,
    MAX_COUNTER_KEY_BYTES,
    META_KEY,
    REGISTRY_KEY,
    SEARCH_GATE_KEY,
    BoundedRedisStorage,
    CounterCapacityError,
    CounterNamespaceError,
    SearchStartGate,
)
from config import settings


@pytest.fixture
def storage():
    """Yield an eight-counter backend in isolated Redis; clear LIMITS:* and reset singleton
    readiness.
    """
    backend = BoundedRedisStorage(
        settings.rate_limit_storage_uri,
        counter_capacity=8,
        cleanup_batch_size=2,
        **rl.redis_storage_options(),
    )
    connection = backend.get_connection()
    # The suite already requires an isolated per-worker Redis database.
    keys = list(connection.scan_iter(match="LIMITS:*"))
    if keys:
        connection.delete(*keys)
    yield backend
    keys = list(connection.scan_iter(match="LIMITS:*"))
    if keys:
        connection.delete(*keys)
    # Other tests reuse the application singleton after this isolated backend.
    rl.limiter.limiter.storage._ready = False


def test_concurrent_new_identities_cannot_exceed_capacity_or_reset_live_quota(storage):
    """Concurrent new identities cannot exceed capacity or reset live quota."""
    storage.validate_namespace()

    def attempt(index):
        """Increment a one-day identity counter, returning None only on verified capacity refusal."""
        try:
            return storage.incr(f"identity-{index}/day", 86400)
        except StorageError as error:
            assert isinstance(error.__cause__, CounterCapacityError)
            return None

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(attempt, range(100)))
    assert results.count(1) == 8
    assert storage.get_connection().zcard(REGISTRY_KEY) == 8
    assert (
        len(
            [
                key
                for key in storage.get_connection().scan_iter("LIMITS:*")
                if key.decode() not in CONTROL_KEYS
            ]
        )
        == 8
    )
    live = storage.get_connection().zrange(REGISTRY_KEY, 0, 0)[0].decode()
    key = live.removeprefix("LIMITS:")
    deadline = storage.get_connection().zscore(REGISTRY_KEY, live)
    assert storage.incr(key, 86400) == 2
    assert storage.get_connection().zscore(REGISTRY_KEY, live) == deadline


def test_expiry_reclaims_slots_and_clear_removes_registry_member(storage):
    """Expiry reclaims slots and clear removes registry member."""
    for index in range(8):
        storage.incr(f"short-{index}", 1)
    deadline = time.monotonic() + 2
    while storage.get_connection().exists("LIMITS:short-0"):
        assert time.monotonic() < deadline, "short fixed-window counter did not expire"
        time.sleep(0.02)
    for index in range(8):
        assert storage.incr(f"new-{index}", 86400) == 1
    assert storage.get_connection().zcard(REGISTRY_KEY) == 8
    storage.clear("new-0")
    assert storage.get("new-0") == 0
    assert storage.get_connection().zscore(REGISTRY_KEY, "LIMITS:new-0") is None
    assert storage.incr("replacement", 60) == 1


def test_registry_deadline_exactly_matches_counter_deadline(storage):
    """Registry deadline exactly matches counter deadline."""
    storage.incr("deadline", 60)
    connection = storage.get_connection()
    # PEXPIRETIME is Redis 7-only; compute using one atomic script on Redis 6.2 too.
    result = connection.eval(
        "local t=redis.call('TIME'); return {tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)+redis.call('PTTL',KEYS[1]),redis.call('ZSCORE',KEYS[2],KEYS[1])}",
        2,
        "LIMITS:deadline",
        REGISTRY_KEY,
    )
    assert int(result[0]) == int(float(result[1]))


def test_startup_refuses_legacy_counter_without_deleting_or_shortening_it(storage):
    """Startup refuses legacy counter without deleting or shortening it."""
    connection = storage.get_connection()
    connection.set("LIMITS:legacy", 17, ex=600)
    with pytest.raises(CounterNamespaceError, match="drain required"):
        storage.validate_namespace()
    assert connection.get("LIMITS:legacy") == b"17"
    assert connection.ttl("LIMITS:legacy") > 590


def test_restart_preserves_quota_and_rejects_disagreeing_capacity(storage):
    """Restart preserves quota and rejects disagreeing capacity."""
    storage.incr("survivor", 600, 7)
    restarted = BoundedRedisStorage(settings.rate_limit_storage_uri, counter_capacity=8)
    assert restarted.probe()
    assert restarted.incr("survivor", 600) == 8
    incompatible = BoundedRedisStorage(settings.rate_limit_storage_uri, counter_capacity=9)
    with pytest.raises(CounterNamespaceError, match="differs"):
        incompatible.validate_namespace()


def test_startup_validation_batches_network_roundtrips_under_its_total_budget(storage, monkeypatch):
    """Startup validation batches network roundtrips under its total budget."""
    connection = storage.get_connection()
    connection.delete(META_KEY)
    populated = BoundedRedisStorage(settings.rate_limit_storage_uri, counter_capacity=1024)
    for index in range(1024):
        populated.incr(f"startup-{index}", 600)
    restarted = BoundedRedisStorage(settings.rate_limit_storage_uri, counter_capacity=1024)
    clock = [0.0]
    connection = restarted._redis()
    original_command = connection.execute_command
    original_pipeline = connection.pipeline

    def slow_roundtrip(*args, **kwargs):
        """Charge 20 ms to the fake clock before executing the Redis command."""
        clock[0] += 0.02
        return original_command(*args, **kwargs)

    def delayed_pipeline(*args, **kwargs):
        """Return a pipeline whose execution advances the fake clock by 20 ms."""
        pipeline = original_pipeline(*args, **kwargs)
        execute = pipeline.execute

        def send(*args, **kwargs):
            """Charge 20 ms to the fake clock before executing the pipeline."""
            clock[0] += 0.02
            return execute(*args, **kwargs)

        pipeline.execute = send
        return pipeline

    monkeypatch.setattr(connection, "execute_command", slow_roundtrip)
    monkeypatch.setattr(connection, "pipeline", delayed_pipeline)
    monkeypatch.setattr(storage_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    # Model a 20 ms Redis RTT: per-counter synchronous checks cannot meet the
    # ten-second startup budget; bounded batches can without lowering quotas.
    restarted.validate_namespace()
    assert clock[0] < 10
    assert restarted.get("startup-1023") == 1


def test_namespace_validation_total_timeout_fails_closed(storage, monkeypatch):
    """Namespace validation total timeout fails closed."""
    ticks = iter([0.0, 11.0])
    monkeypatch.setattr(storage_module, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    with pytest.raises(CounterNamespaceError, match="startup budget"):
        storage.validate_namespace()
    assert not storage._ready


def test_key_length_and_ttl_bounds_refuse_without_counter_allocation(storage):
    """Key length and ttl bounds refuse without counter allocation."""
    for key, expiry in (("x" * MAX_COUNTER_KEY_BYTES, 60), ("valid", 86401)):
        with pytest.raises(StorageError):
            storage.incr(key, expiry)
    assert storage.get_connection().zcard(REGISTRY_KEY) == 0


def test_control_probe_and_global_gate_still_work_when_counter_capacity_is_full(storage):
    """Control probe and global gate still work when counter capacity is full."""
    for index in range(8):
        storage.incr(f"full-{index}", 600)
    assert storage.probe()
    assert SearchStartGate(storage, rate=0.5, burst=1).acquire()
    assert storage.get_connection().zcard(REGISTRY_KEY) == 8


async def test_real_counter_capacity_returns_503_before_downstream_work(storage):
    """Real counter capacity returns 503 before downstream work."""
    app = FastAPI()
    active = Limiter(
        key_func=lambda request: request.headers["client-id"],
        storage_uri="memory://",
        default_limits=["100/day"],
    )
    active.limiter.storage = storage
    app.state.limiter = active
    downstream = []

    @app.middleware("http")
    async def session_lookup(request: Request, call_next):
        """Record downstream client identity before calling the next middleware."""
        downstream.append(request.headers["client-id"])
        return await call_next(request)

    @app.get("/protected")
    async def protected():
        """Return a successful response without external work."""
        return Response("ok")

    app.add_middleware(rl.BoundedRateLimitMiddleware)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for index in range(8):
            assert (
                await client.get("/protected", headers={"client-id": str(index)})
            ).status_code == 200
        refused = await client.get("/protected", headers={"client-id": "new"})
        assert refused.status_code == 503
        assert refused.headers["Cache-Control"] == "no-store"
        assert refused.headers["Retry-After"] == "1"
        assert "X-Content-Type-Options" in refused.headers
        assert (await client.get("/protected", headers={"client-id": "0"})).status_code == 200
    assert downstream == [*map(str, range(8)), "0"]


def test_reset_clears_counters_but_preserves_global_gate_and_metadata(storage):
    """Reset clears counters but preserves global gate and metadata."""
    storage.incr("counter", 60)
    gate = SearchStartGate(storage, rate=0.5, burst=1)
    assert gate.acquire()
    assert storage.reset() == 1
    assert storage.get("counter") == 0
    assert storage.get_connection().exists(META_KEY, SEARCH_GATE_KEY) == 2
    assert not gate.acquire()


def test_global_gate_shared_across_workers_without_identity_keys(storage):
    """Global gate shared across workers without identity keys."""
    gates = [SearchStartGate(storage, rate=0.5, burst=1) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(lambda gate: gate.acquire(), gates))
    assert results.count(True) == 1
    assert storage.get_connection().zcard(REGISTRY_KEY) == 0
    assert list(storage.get_connection().scan_iter("*search-start*")) == [SEARCH_GATE_KEY.encode()]


def test_gate_readiness_preserves_tokens_and_refuses_changed_policy(storage):
    """Gate readiness preserves tokens and refuses changed policy."""
    gate = SearchStartGate(storage, rate=0.5, burst=1)
    assert gate.check()
    assert gate.acquire()
    before = storage.get_connection().hgetall(SEARCH_GATE_KEY)
    assert gate.check()
    assert storage.get_connection().hgetall(SEARCH_GATE_KEY) == before
    with pytest.raises(ResponseError, match="CONFIGURATION_MISMATCH"):
        SearchStartGate(storage, rate=1.0, burst=1).check()
    assert storage.get_connection().hgetall(SEARCH_GATE_KEY) == before


@pytest.mark.parametrize("enabled", [True, False])
async def test_global_search_gate_precedes_downstream_session_work_when_limits_disabled(
    monkeypatch, caplog, enabled
):
    """Global search gate precedes downstream session work when limits disabled."""
    gate = SearchStartGate(None, rate=0.0001, burst=1)
    monkeypatch.setattr(rl, "get_search_start_gate", lambda: gate)
    app = FastAPI()
    limiter = Limiter(key_func=lambda: "client", storage_uri="memory://", enabled=enabled)
    app.state.limiter = limiter
    session_calls = []

    @app.middleware("http")
    async def session_lookup(request: Request, call_next):
        """Record downstream request paths before calling the next middleware."""
        session_calls.append(request.url.path)
        return await call_next(request)

    @app.get("/search")
    async def search():
        """Return a successful response without external work."""
        return Response("ok")

    @app.get("/other")
    async def other():
        """Return a successful response without external work."""
        return Response("ok")

    app.add_middleware(rl.BoundedRateLimitMiddleware)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/search?invalid=1")).status_code == 200
        rejected = await client.get("/search?invalid=2", headers={"X-Forwarded-For": "203.0.113.2"})
        assert rejected.status_code == 503
        assert rejected.text == "Search is temporarily busy. Please wait briefly and try again."
        assert rejected.headers["Cache-Control"] == "no-store"
        assert rejected.headers["Retry-After"] == "1"
        assert "X-Content-Type-Options" in rejected.headers
        assert "frame-ancestors 'none'" in rejected.headers["Content-Security-Policy"]
        assert (await client.get("/other")).status_code == 200
    assert session_calls == ["/search", "/other"]
    records = [
        record
        for record in caplog.records
        if getattr(record, "event_type", None) == "search_start_budget_exhausted"
    ]
    assert len(records) == 1
    assert records[0].getMessage() == "Search start budget exhausted"
    assert records[0].path == "/search"


async def test_search_gate_backend_error_does_not_reach_session_work(monkeypatch):
    """Search gate backend error does not reach session work."""

    class UnavailableGate:
        """Simulate Redis failure during global-token acquisition."""

        def acquire(self):
            """Raise RedisConnectionError before granting a global token."""
            raise RedisConnectionError("unavailable")

    monkeypatch.setattr(rl, "get_search_start_gate", UnavailableGate)
    app = FastAPI()
    app.state.limiter = Limiter(key_func=lambda: "client", storage_uri="memory://", enabled=False)
    calls = []

    @app.get("/search")
    async def search():
        """Record database work and return a successful response."""
        calls.append("database")
        return Response("ok")

    app.add_middleware(rl.BoundedRateLimitMiddleware)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        rejected = await client.get("/search")
        assert rejected.status_code == 503
        assert rejected.text == "Rate-limit service temporarily unavailable."
    assert calls == []


async def test_exhausted_client_cannot_consume_the_global_token(monkeypatch):
    """Exhausted client cannot consume the global token."""
    gate = SearchStartGate(None, rate=0.0001, burst=1)
    monkeypatch.setattr(rl, "get_search_start_gate", lambda: gate)
    app = FastAPI()
    limiter = Limiter(
        key_func=lambda request: request.headers.get("client-id", "a"),
        storage_uri="memory://",
        default_limits=["1/hour"],
    )
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def exceeded(_request: Request, _error: RateLimitExceeded):
        """Return HTTP 429 without downstream work."""
        return Response(status_code=429)

    @app.get("/search")
    async def search():
        """Return a successful response without external work."""
        return Response("ok")

    app.add_middleware(rl.BoundedRateLimitMiddleware)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/search", headers={"client-id": "a"})).status_code == 200
        gate.reset()
        assert (await client.get("/search", headers={"client-id": "a"})).status_code == 429
        assert (await client.get("/search", headers={"client-id": "b"})).status_code == 200


def test_reference_capacity_with_maximum_key_lengths_has_memory_headroom(storage):
    """Measure real Redis allocation, including duplicate names in the registry."""
    connection = storage.get_connection()
    connection.delete(META_KEY)
    full = BoundedRedisStorage(settings.rate_limit_storage_uri, counter_capacity=20000)
    baseline = connection.info("memory")["used_memory"]
    for index in range(20000):
        suffix = str(index).zfill(5)
        key = "x" * (MAX_COUNTER_KEY_BYTES - len("LIMITS:") - len(suffix)) + suffix
        full.incr(key, 86400)
    assert connection.zcard(REGISTRY_KEY) == 20000
    allocated = connection.info("memory")["used_memory"] - baseline
    # Reference Redis 7, 128 MiB maxmemory: at least half remains available for
    # baseline/control/allocator headroom. Operators still budget process RSS/AOF.
    assert allocated < 64 * 1024 * 1024
    print(f"maximum bounded-counter allocation: {allocated} bytes")


@contextmanager
def _persistent_redis(directory, port):
    """Start/stop redis-server on a free localhost port, retaining AOF in directory; yield its URL."""
    process = subprocess.Popen(
        [
            "redis-server",
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--dir",
            str(directory),
            "--save",
            "",
            "--appendonly",
            "yes",
            "--appendfsync",
            "always",
            "--maxmemory-policy",
            "noeviction",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = redis.Redis(host="127.0.0.1", port=port, socket_timeout=0.5)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                if client.ping():
                    break
            except redis.RedisError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        client.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_actual_aof_restart_preserves_registry_deadline_quota_and_global_budget(tmp_path):
    """Actual aof restart preserves registry deadline quota and global budget."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with _persistent_redis(tmp_path, port) as uri:
        before = BoundedRedisStorage(uri, counter_capacity=1)
        assert before.incr("persistent", 86400, 7) == 7
        gate = SearchStartGate(before, rate=0.0001, burst=1)
        assert gate.check()
        assert gate.acquire()
        deadline = before.get_connection().zscore(REGISTRY_KEY, "LIMITS:persistent")
        before.get_connection().close()
    with _persistent_redis(tmp_path, port) as uri:
        after = BoundedRedisStorage(uri, counter_capacity=1)
        assert after.probe()
        assert after.get_connection().hget(META_KEY, "capacity") == b"1"
        assert after.get_connection().zscore(REGISTRY_KEY, "LIMITS:persistent") == deadline
        assert after.incr("persistent", 86400) == 8
        with pytest.raises(CounterCapacityError):
            after.incr("another", 60)
        gate = SearchStartGate(after, rate=0.0001, burst=1)
        assert gate.check()
        assert not gate.acquire()
        after.get_connection().close()
