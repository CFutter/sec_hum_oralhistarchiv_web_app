"""Fixed-window Redis counters with a finite allocation budget.

The sorted-set registry and each counter are changed by one script. A full
registry refuses new counters; it never evicts an unexpired quota. All keys
are bounded in length, cleanup work is bounded, and four fixed control keys
are reserved independently of the counter budget. This backend deliberately
supports only the fixed-window strategy and standalone Redis.
"""

import math
import threading
import time
from typing import Any, cast

from limits.storage.redis import RedisStorage
from redis import Redis
from redis.exceptions import RedisError

CONTROL_PREFIX = "LIMITS:oralhistarchiv-security-v1:bounded:"
REGISTRY_KEY = CONTROL_PREFIX + "counters"
META_KEY = CONTROL_PREFIX + "meta"
SEARCH_GATE_KEY = CONTROL_PREFIX + "search-start"
READINESS_KEY = CONTROL_PREFIX + "readiness"
CONTROL_KEYS = frozenset({REGISTRY_KEY, META_KEY, SEARCH_GATE_KEY, READINESS_KEY})
_STARTUP_VALIDATION_TIMEOUT_SECONDS = 10.0
_STARTUP_BATCH_SIZE = 128
MAX_COUNTER_CAPACITY = 20000
MAX_CLEANUP_BATCH_SIZE = 1024
_REDIS_KEY_MISSING_TTL = -2
MAX_COUNTER_KEY_BYTES = 512
MAX_COUNTER_TTL_SECONDS = 86400


class CounterCapacityError(RedisError):
    """A new quota would exceed the configured allocation budget."""


class CounterNamespaceError(RedisError):
    """Existing counters or metadata do not satisfy the bounded contract."""


def bounded_redis_uri(uri: str) -> str:
    """Select our registered backend without changing the Redis destination."""
    return "bounded+" + uri


_INCREMENT = """
local cap = tonumber(ARGV[1])
local batch = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local amount = tonumber(ARGV[4])
if redis.call('HGET', KEYS[3], 'capacity') ~= ARGV[1] then
    return redis.error_reply('BOUNDED_NAMESPACE_NOT_READY')
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, batch)
for _, key in ipairs(expired) do
    -- Physical expiry may lag. Delete before releasing the allocation slot.
    redis.call('DEL', key)
    redis.call('ZREM', KEYS[2], key)
end
local score = redis.call('ZSCORE', KEYS[2], KEYS[1])
local exists = redis.call('EXISTS', KEYS[1])
if exists == 1 then
    if not score then return redis.error_reply('BOUNDED_UNREGISTERED_COUNTER') end
    -- Preserve the original fixed-window deadline, including rejected hits.
    return redis.call('INCRBY', KEYS[1], amount)
end
if not score and redis.call('ZCARD', KEYS[2]) >= cap then return -1 end
local deadline = now + ttl * 1000
-- Reserve first: a subsequent command failure may waste a slot but cannot
-- create an untracked counter. Lua errors do not roll back previous writes.
redis.call('ZADD', KEYS[2], deadline, KEYS[1])
redis.call('SET', KEYS[1], amount, 'PXAT', deadline)
return amount
"""

_CLEAR = """
local count = redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], KEYS[1])
return count
"""

_PROBE = """
redis.call('SET', KEYS[1], '1', 'PX', 5000)
local value = redis.call('GET', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
redis.call('DEL', KEYS[1])
return value == '1' and ttl > 0 and ttl <= 5000
"""

_SEARCH_START_SCRIPT = """
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + tonumber(clock[2]) / 1000000
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local prior_rate = redis.call('HGET', KEYS[1], 'rate')
local prior_burst = redis.call('HGET', KEYS[1], 'burst')
if prior_rate and (prior_rate ~= ARGV[1] or prior_burst ~= ARGV[2]) then
    return redis.error_reply('SEARCH_GATE_CONFIGURATION_MISMATCH')
end
local last = tonumber(redis.call('HGET', KEYS[1], 'time')) or now
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens')) or burst
-- A backward wall-clock adjustment cannot refill or move the clock backward.
local effective_now = math.max(now, last)
tokens = math.min(burst, tokens + (effective_now - last) * rate)
local admitted = 0
if tokens >= 1 then tokens = tokens - 1; admitted = 1 end
redis.call('HSET', KEYS[1], 'time', effective_now, 'tokens', tokens,
           'rate', ARGV[1], 'burst', ARGV[2])
return admitted
"""

_CHECK_GATE = """
local rate = redis.call('HGET', KEYS[1], 'rate')
local burst = redis.call('HGET', KEYS[1], 'burst')
if rate then
    if rate ~= ARGV[1] or burst ~= ARGV[2] then
        return redis.error_reply('SEARCH_GATE_CONFIGURATION_MISMATCH')
    end
    return 1
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + tonumber(clock[2]) / 1000000
redis.call('HSET', KEYS[1], 'time', now, 'tokens', ARGV[2],
           'rate', ARGV[1], 'burst', ARGV[2])
return 1
"""


class BoundedRedisStorage(RedisStorage):
    """Exact fixed-window counters, at most ``counter_capacity`` live keys."""

    STORAGE_SCHEME: list[str] = [  # noqa: RUF012 - limits storage registration API
        "bounded+redis",
        "bounded+rediss",
        "bounded+redis+unix",
    ]

    def __init__(
        self,
        uri: str,
        *,
        counter_capacity: int = 20000,
        cleanup_batch_size: int = 128,
        **options: Any,
    ) -> None:
        """Configure counters with capacity 1..20000 and cleanup batches 1..1024.

        Raise ValueError outside those bounds. Strip the bounded+ URI prefix and
        pass remaining options to RedisStorage; initialize client scripts without
        executing them. Namespace validation occurs before the first increment.
        """
        if not 1 <= counter_capacity <= MAX_COUNTER_CAPACITY:
            raise ValueError("counter_capacity must be between 1 and 20000")
        if not 1 <= cleanup_batch_size <= MAX_CLEANUP_BATCH_SIZE:
            raise ValueError("cleanup_batch_size must be between 1 and 1024")
        self.counter_capacity = counter_capacity
        self.cleanup_batch_size = cleanup_batch_size
        self._ready = False
        self._ready_lock = threading.Lock()
        super().__init__(uri.removeprefix("bounded+"), **options)
        connection = self._redis()
        self._increment = connection.register_script(_INCREMENT.encode())
        self._clear = connection.register_script(_CLEAR.encode())
        self._probe = connection.register_script(_PROBE.encode())
        self._token_bucket = connection.register_script(_SEARCH_START_SCRIPT.encode())
        self._check_gate = connection.register_script(_CHECK_GATE.encode())

    def _redis(self) -> Redis:
        """The concrete standalone redis-py client behind limits' narrow protocol."""
        return cast(Redis, self.get_connection())

    def _validate_batch(self, keys: list[str]) -> None:
        # One bounded non-transactional pipeline: TIME precedes all PTTL reads,
        # so the observed deadline is conservative despite transport latency.
        """Read Redis TTLs/registry scores; raise CounterNamespaceError for unsafe live keys."""
        with self._redis().pipeline(transaction=False) as pipeline:
            pipeline.time()
            for key in keys:
                pipeline.pttl(key)
                pipeline.zscore(REGISTRY_KEY, key)
            result = pipeline.execute()
        seconds, micros = result[0]
        observed_ms = seconds * 1000 + micros // 1000
        for index in range(len(keys)):
            ttl, score = result[1 + 2 * index : 3 + 2 * index]
            if ttl == _REDIS_KEY_MISSING_TTL:
                continue
            if ttl < 0 or score is None or score < observed_ms + ttl:
                raise CounterNamespaceError(
                    "unregistered or invalid existing counter; drain required"
                )

    def validate_namespace(self) -> None:
        """Once per worker, verify existing quotas without discarding them.

        Stop old writers and drain their TTLs before the first upgraded start.
        Validation uses bounded pipelines and a cumulative ten-second budget,
        in addition to per-operation socket deadlines. The dedicated database
        must not contain other LIMITS writers. A timeout prevents startup.
        """
        with self._ready_lock:
            if self._ready:
                return
            started = time.monotonic()
            connection = self._redis()
            connection.hsetnx(META_KEY, "capacity", str(self.counter_capacity))
            metadata = cast(str | bytes | None, connection.hget(META_KEY, "capacity"))
            if metadata is not None and int(metadata) != self.counter_capacity:
                raise CounterNamespaceError("counter capacity differs across workers")
            if cast(int, connection.zcard(REGISTRY_KEY)) > self.counter_capacity:
                raise CounterNamespaceError("counter registry exceeds capacity")
            inspected = 0
            cursor = 0
            batch: list[str] = []
            while True:
                cursor, keys = cast(
                    tuple[int, list[bytes]],
                    connection.scan(cursor=cursor, match="LIMITS:*", count=_STARTUP_BATCH_SIZE),
                )
                for raw_key in keys:
                    key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else raw_key
                    if key in CONTROL_KEYS:
                        continue
                    inspected += 1
                    if (
                        inspected > self.counter_capacity
                        or len(key.encode()) > MAX_COUNTER_KEY_BYTES
                    ):
                        raise CounterNamespaceError(
                            "counter namespace exceeds its allocation budget"
                        )
                    batch.append(key)
                    if len(batch) == _STARTUP_BATCH_SIZE:
                        self._validate_batch(batch)
                        batch.clear()
                if time.monotonic() - started > _STARTUP_VALIDATION_TIMEOUT_SECONDS:
                    raise CounterNamespaceError(
                        "counter namespace validation exceeded startup budget"
                    )
                if cursor == 0:
                    break
            if batch:
                self._validate_batch(batch)
            if time.monotonic() - started > _STARTUP_VALIDATION_TIMEOUT_SECONDS:
                raise CounterNamespaceError("counter namespace validation exceeded startup budget")
            self._ready = True

    def _ensure_ready(self) -> None:
        """Validate the namespace once before this worker increments counters."""
        if not self._ready:
            self.validate_namespace()

    def incr(self, key: str, expiry: int, amount: int = 1) -> int:
        """Increment a Redis fixed window without extending its original expiry.

        Require a prefixed UTF-8 key of at most 512 bytes outside control keys,
        expiry 1..86400 seconds and amount >= 1. Validate the namespace on first
        use, remove bounded expired registry entries, and return the new count.
        Raise CounterNamespaceError for invalid arguments, CounterCapacityError
        when a new counter cannot fit, or propagate Redis failures.
        """
        full_key = self.prefixed_key(key)
        if (
            len(full_key.encode()) > MAX_COUNTER_KEY_BYTES
            or full_key in CONTROL_KEYS
            or not 1 <= expiry <= MAX_COUNTER_TTL_SECONDS
            or amount < 1
        ):
            raise CounterNamespaceError(
                "counter key, expiry, or amount exceeds the supported contract"
            )
        self._ensure_ready()
        result = int(
            self._increment(
                [full_key, REGISTRY_KEY, META_KEY],
                [self.counter_capacity, self.cleanup_batch_size, expiry, amount],
            )
        )
        if result == -1:
            raise CounterCapacityError("counter allocation capacity exhausted")
        return result

    def clear(self, key: str) -> None:
        """Delete one counter and registry entry; raise CounterNamespaceError for control keys."""
        full_key = self.prefixed_key(key)
        if full_key in CONTROL_KEYS:
            raise CounterNamespaceError("control keys cannot be cleared as counters")
        self._clear([full_key, REGISTRY_KEY])

    def reset(self) -> int:
        """Delete registered counters in bounded batches and return the number removed.

        Retain metadata and the independent search gate; do not run during traffic.
        Redis failures propagate.
        """
        connection = self._redis()
        removed = 0
        while keys := cast(
            list[bytes], connection.zrange(REGISTRY_KEY, 0, self.cleanup_batch_size - 1)
        ):
            for raw_key in keys:
                key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
                removed += int(self._clear([key, REGISTRY_KEY]))
        return removed

    def probe(self) -> bool:
        """Validate the namespace, ping Redis and test readiness-key set/read/TTL/delete."""
        self.validate_namespace()
        return bool(self._redis().ping() and self._probe([READINESS_KEY]))

    def acquire_entry(self, key: str, limit: int, expiry: int, amount: int = 1) -> bool:  # noqa: ARG002 - reject unsupported inherited API
        """Raise CounterNamespaceError: moving-window counters are unsupported."""
        raise CounterNamespaceError("only fixed-window counters are supported")

    def acquire_sliding_window_entry(
        self,
        key: str,  # noqa: ARG002 - unsupported inherited API
        limit: int,  # noqa: ARG002 - unsupported inherited API
        expiry: int,  # noqa: ARG002 - unsupported inherited API
        amount: int = 1,  # noqa: ARG002 - unsupported inherited API
    ) -> bool:
        """Raise CounterNamespaceError: sliding-window counters are unsupported."""
        raise CounterNamespaceError("only fixed-window counters are supported")

    def acquire_search_start(self, rate: float, burst: int) -> bool:
        """Consume a shared token at rate starts/second and burst capacity; return admission.

        Use Redis time and propagate Redis errors, including mismatched policy.
        Callers must validate positive finite rate and positive burst.
        """
        return bool(self._token_bucket([SEARCH_GATE_KEY], [rate, burst]))

    def validate_search_policy(self, rate: float, burst: int) -> bool:
        """Initialize/verify Redis rate/burst policy; return success or propagate Redis errors."""
        return bool(self._check_gate([SEARCH_GATE_KEY], [rate, burst]))


class SearchStartGate:
    """One deployment-wide start budget; process-local only in development."""

    def __init__(self, storage: BoundedRedisStorage | None, *, rate: float, burst: int) -> None:
        """Set starts/second and burst capacity, using Redis or a thread-locked local bucket.

        Raise ValueError for a nonfinite/nonpositive rate or burst < 1. None storage
        selects process-local state, intended only for development.
        """
        if not math.isfinite(rate) or rate <= 0 or burst < 1:
            raise ValueError("search start rate and burst must be positive")
        self.storage = storage
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """Consume one shared/local token and return admission; Redis errors propagate."""
        if self.storage is not None:
            return self.storage.acquire_search_start(self.rate, self.burst)
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                return False
            self._tokens -= 1
            return True

    def check(self) -> bool:
        """Return local readiness or probe/initialize the Redis gate; Redis errors propagate."""
        if self.storage is None:
            return True
        return self.storage.probe() and self.storage.validate_search_policy(self.rate, self.burst)

    def reset(self) -> None:
        """Delete the shared gate and refill local tokens; never run during active admission."""
        if self.storage is not None:
            self.storage.get_connection().delete(SEARCH_GATE_KEY)
        with self._lock:
            self._tokens = float(self.burst)
            self._last = time.monotonic()
