"""The Redis option set and the startup readiness probe."""

import logging
import time
from unittest.mock import create_autospec

import pytest
import redis
from limits.errors import ConcurrentUpdateError, ConfigurationError, StorageError
from limits.storage.base import Storage
from limits.storage.redis import RedisStorage
from pydantic import SecretStr
from redis.backoff import NoBackoff
from redis.exceptions import (
    AuthenticationError,
    AuthorizationError,
    MaxConnectionsError,
    NoPermissionError,
    OutOfMemoryError,
    ResponseError,
)
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from redis.retry import Retry
from slowapi import Limiter

import app.middleware.rate_limiting as rl
from app.middleware.rate_limiting import (
    _backend_failure_category,
    bounded_storage_options,
    redis_storage_options,
)


class TestRedisStorageOptionsAreTheReviewedExactSet:
    """Cover Redis storage options are the reviewed exact set."""

    def test_redis_storage_options_has_exactly_the_five_reviewed_keys(self):
        """Check Redis storage options has exactly the five reviewed keys."""
        options = redis_storage_options()
        assert set(options) == {
            "socket_connect_timeout",
            "socket_timeout",
            "retry",
            "retry_on_timeout",
            "wrap_exceptions",
        }
        assert options["socket_connect_timeout"] == 0.5
        assert options["socket_timeout"] == 0.5
        assert isinstance(options["retry"], Retry)
        assert options["retry"]._retries == 0
        assert isinstance(options["retry"]._backoff, NoBackoff)
        assert options["retry_on_timeout"] is False
        assert options["wrap_exceptions"] is True

    def _limiter_and_storage(self, **option_overrides):
        """Build a bounded Redis limiter with caller overrides and return it with its storage."""
        options = bounded_storage_options()
        options.update(option_overrides)
        limiter = Limiter(
            key_func=lambda: "client",
            default_limits=["1/minute"],
            strategy="fixed-window",
            storage_uri="bounded+redis://fake-host:6379/0",
            storage_options=options,
            headers_enabled=False,
        )
        return limiter, limiter.limiter.storage

    def test_the_production_options_pass_redis_configuration_review(self):
        """Check the production options pass Redis configuration review."""
        limiter, storage = self._limiter_and_storage()
        assert rl._redis_configuration_issues(limiter, storage) == []

    def test_an_injected_extra_option_is_rejected(self):
        """Check an injected extra option is rejected."""
        limiter, storage = self._limiter_and_storage(ssl=True)
        issues = rl._redis_configuration_issues(limiter, storage)
        assert any("exact set" in issue for issue in issues)

    def test_a_timeout_above_half_a_second_is_rejected(self):
        """Check a timeout above half a second is rejected."""
        limiter, storage = self._limiter_and_storage(socket_timeout=0.6)
        issues = rl._redis_configuration_issues(limiter, storage)
        assert any("0.5 seconds" in issue for issue in issues)

    def test_retries_enabled_are_rejected(self):
        """Check retries enabled are rejected."""
        limiter, storage = self._limiter_and_storage(retry=Retry(NoBackoff(), 1))
        issues = rl._redis_configuration_issues(limiter, storage)
        assert any("retries are not disabled" in issue for issue in issues)

    def test_retry_on_timeout_enabled_is_rejected(self):
        """Check retry on timeout enabled is rejected."""
        limiter, storage = self._limiter_and_storage(retry_on_timeout=True)
        issues = rl._redis_configuration_issues(limiter, storage)
        assert any("retry_on_timeout" in issue for issue in issues)

    def test_wrap_exceptions_disabled_is_rejected(self):
        """Check wrap exceptions disabled is rejected."""
        limiter, storage = self._limiter_and_storage(wrap_exceptions=False)
        issues = rl._redis_configuration_issues(limiter, storage)
        assert any("wrap_exceptions" in issue for issue in issues)


class TestBackendFailureCategoryMapsEveryKnownExceptionClass:
    """Cover backend failure category maps every known exception class."""

    @pytest.mark.parametrize(
        ("error", "expected_category"),
        [
            (OutOfMemoryError("oom"), "capacity"),
            (MaxConnectionsError("max"), "capacity"),
            (AuthenticationError("auth"), "authentication"),
            (AuthorizationError("authz"), "authorization"),
            (NoPermissionError("perm"), "authorization"),
            (RedisTimeoutError("timeout"), "timeout"),
            (RedisConnectionError("conn"), "connection"),
            (ResponseError("resp"), "command"),
            (ConcurrentUpdateError("cu", 1), "concurrency"),
            (ConfigurationError("cfg"), "configuration"),
            (StorageError(RuntimeError("bare")), "storage"),
            (RuntimeError("other"), "storage"),
        ],
    )
    def test_bare_exception_is_categorized(self, error, expected_category):
        """Check bare exception is categorized."""
        category, exception_type = _backend_failure_category(error)
        assert category == expected_category
        assert exception_type == type(error).__name__

    @pytest.mark.parametrize(
        "wrapped",
        [
            OutOfMemoryError("oom"),
            AuthenticationError("auth"),
            RedisTimeoutError("timeout"),
            RedisConnectionError("conn"),
            ResponseError("resp"),
        ],
    )
    def test_a_storage_error_wrapping_a_redis_error_unwraps_to_it(self, wrapped):
        """Check a storage error wrapping a Redis error unwraps to it."""
        outer = StorageError("wrapped")
        outer.__cause__ = wrapped
        category, exception_type = _backend_failure_category(outer)
        expected_category, _ = _backend_failure_category(wrapped)
        assert category == expected_category
        assert exception_type == type(wrapped).__name__

    def test_unwrapping_depth_is_capped_at_four(self):
        """A chain deeper than four `StorageError` wrappers stops
        unwrapping at the cap rather than reaching the real cause,
        reporting `StorageError` itself instead of the innermost error."""
        innermost = RedisConnectionError("conn")
        current: BaseException = innermost
        for _ in range(5):
            wrapper = StorageError("layer")
            wrapper.__cause__ = current
            current = wrapper

        category, exception_type = _backend_failure_category(current)
        assert exception_type == "StorageError"
        assert category == "storage"

    def test_a_chain_within_the_cap_still_reaches_its_real_cause(self):
        """Check a chain within the cap still reaches its real cause."""
        innermost = RedisConnectionError("conn")
        current: BaseException = innermost
        for _ in range(3):
            wrapper = StorageError("layer")
            wrapper.__cause__ = current
            current = wrapper

        category, exception_type = _backend_failure_category(current)
        assert category == "connection"
        assert exception_type == "ConnectionError"


class TestBackendProbeAgainstAFakeStorage:
    """Cover backend probe against afake storage."""

    def _redis_double(self, *, ping=True):
        """Build Redis storage whose signature-checked connection returns the configured ping result."""
        storage = create_autospec(RedisStorage, instance=True, spec_set=True)
        connection = create_autospec(redis.Redis, instance=True)
        connection.ping.return_value = ping
        storage.get_connection.return_value = connection
        return storage

    def test_a_healthy_redis_backend_passes_and_clears_its_probe_key(self):
        """Check a healthy Redis backend passes and clears its probe key."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 1
        storage.get.side_effect = [1, 0]
        storage.get_expiry.return_value = time.time() + 2

        assert rl._probe_rate_limit_backend(storage) is True
        storage.clear.assert_called_once()
        cleared_key = storage.clear.call_args.args[0]
        incremented_key = storage.incr.call_args.args[0]
        assert cleared_key == incremented_key
        assert storage.get.call_count == 2

    def test_a_healthy_non_redis_backend_passes_via_check(self):
        """Check a healthy non Redis backend passes via check."""
        storage = create_autospec(Storage, instance=True, spec_set=True)
        storage.check.return_value = True
        storage.incr.return_value = 1
        storage.get.side_effect = [1, 0]
        storage.get_expiry.return_value = time.time() + 2

        assert rl._probe_rate_limit_backend(storage) is True

    def test_ping_only_backend_is_rejected_when_the_increment_does_not_stick(self):
        """PING succeeds but the ACL forbids writes: `incr` returns
        something other than 1."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 0
        storage.get.side_effect = [0, 0]
        storage.get_expiry.return_value = time.time() + 2

        assert rl._probe_rate_limit_backend(storage) is False
        storage.clear.assert_called_once()

    def test_read_only_backend_is_rejected_when_get_does_not_confirm_the_increment(self):
        """Check read only backend is rejected when GET does not confirm the increment."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 1
        storage.get.side_effect = [0, 0]
        storage.get_expiry.return_value = time.time() + 2

        assert rl._probe_rate_limit_backend(storage) is False
        storage.clear.assert_called_once()

    def test_a_backend_with_no_expiry_support_is_rejected(self):
        """Check a backend with no expiry support is rejected."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 1
        storage.get.side_effect = [1, 0]
        storage.get_expiry.return_value = 0.0

        assert rl._probe_rate_limit_backend(storage) is False
        storage.clear.assert_called_once()

    def test_a_backend_that_cannot_delete_the_probe_key_raises(self):
        """`clear` runs, but the key survives: cleanup itself must fail
        loudly rather than leave probe residue silently unnoticed."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 1
        storage.get.side_effect = [1, 5]
        storage.get_expiry.return_value = time.time() + 2

        with pytest.raises(RuntimeError, match="cleanup failed"):
            rl._probe_rate_limit_backend(storage)
        storage.clear.assert_called_once()

    def test_cleanup_runs_even_when_the_probe_fails_after_the_increment(self):
        """A failure detected after the key was written (bad expiry) must
        still trigger cleanup of that key."""
        storage = self._redis_double(ping=True)
        storage.incr.return_value = 1
        storage.get.side_effect = [1, 0]
        storage.get_expiry.return_value = 0.0

        assert rl._probe_rate_limit_backend(storage) is False
        storage.clear.assert_called_once()

    def test_ping_failure_never_attempts_an_increment_or_cleanup(self):
        """Check ping failure never attempts an increment or cleanup."""
        storage = self._redis_double(ping=False)

        assert rl._probe_rate_limit_backend(storage) is False
        storage.incr.assert_not_called()
        storage.clear.assert_not_called()


class TestValidateRateLimitBackendLogsAndRaisesOnFailure:
    """Cover validate rate limit backend logs and raises on failure."""

    async def test_a_failing_probe_logs_the_category_and_raises(self, monkeypatch, caplog):
        """Check a failing probe logs the category and raises (RuntimeError)."""
        validate_configuration = create_autospec(
            rl.validate_rate_limit_configuration, spec_set=True
        )
        validate_configuration.return_value = None
        monkeypatch.setattr(rl, "validate_rate_limit_configuration", validate_configuration)
        monkeypatch.setattr(rl.settings, "rate_limit_enabled", True)
        monkeypatch.setattr(
            rl.settings, "rate_limit_redis_url", SecretStr("redis://fake-host:6379/0")
        )
        monkeypatch.setattr(rl.limiter.limiter, "storage", object())

        probe = create_autospec(rl._probe_rate_limit_backend, spec_set=True)
        probe.side_effect = RedisConnectionError("refused")
        monkeypatch.setattr(rl, "_probe_rate_limit_backend", probe)

        with (
            caplog.at_level(logging.CRITICAL, logger="app.middleware.rate_limiting"),
            pytest.raises(RuntimeError, match="unavailable"),
        ):
            await rl.validate_rate_limit_backend(rl.limiter)

        (record,) = [r for r in caplog.records if r.event_type == "rate_limit_startup_probe_failed"]
        assert record.backend_failure_category == "connection"
        assert record.exception_type == "ConnectionError"

    async def test_a_healthy_probe_starts_without_raising(self, monkeypatch):
        """Check a healthy probe starts without raising."""
        validate_configuration = create_autospec(
            rl.validate_rate_limit_configuration, spec_set=True
        )
        validate_configuration.return_value = None
        monkeypatch.setattr(rl, "validate_rate_limit_configuration", validate_configuration)
        monkeypatch.setattr(rl.settings, "rate_limit_enabled", True)
        monkeypatch.setattr(
            rl.settings, "rate_limit_redis_url", SecretStr("redis://fake-host:6379/0")
        )
        monkeypatch.setattr(rl.limiter.limiter, "storage", object())

        probe = create_autospec(rl._probe_rate_limit_backend, spec_set=True)
        probe.return_value = True
        monkeypatch.setattr(rl, "_probe_rate_limit_backend", probe)

        await rl.validate_rate_limit_backend(rl.limiter)
