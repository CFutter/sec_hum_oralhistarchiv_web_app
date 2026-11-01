"""Contract tests for rate limiter configuration validation."""

from collections.abc import Callable
from typing import Literal

import pytest
from pydantic import SecretStr
from slowapi import Limiter

import app.middleware.rate_limiting as rl
from app.middleware.bounded_rate_limit_storage import bounded_redis_uri
from app.middleware.rate_limiting import bounded_storage_options, validate_rate_limit_configuration
from config import settings


def _redis_backed_limiter(
    *,
    in_memory_fallback_enabled: bool = False,
    swallow_errors: bool = False,
    headers_enabled: bool = False,
    strategy: str = "fixed-window",
    key_style: Literal["endpoint", "url"] = "endpoint",
    key_prefix: str = rl._RATE_LIMIT_KEY_PREFIX,
    application_limits: list[str | Callable[..., str]] | None = None,
) -> Limiter:
    """Build a Redis limiter from current application settings with explicit constructor overrides."""
    storage_uri = settings.rate_limit_storage_uri
    assert storage_uri is not None
    return Limiter(
        key_func=rl.get_rate_limit_client_id,
        default_limits=["100/minute"],
        application_limits=[] if application_limits is None else application_limits,
        strategy=strategy,
        storage_uri=bounded_redis_uri(storage_uri),
        storage_options=bounded_storage_options(),
        enabled=True,
        headers_enabled=headers_enabled,
        key_prefix=key_prefix,
        key_style=key_style,
        in_memory_fallback_enabled=in_memory_fallback_enabled,
        swallow_errors=swallow_errors,
    )


class TestConstructorOptionsThatMustBeRejected:
    """Cover constructor options that must be rejected."""

    def test_the_application_equivalent_construction_passes(self):
        """Check the application equivalent construction passes."""
        validate_rate_limit_configuration(_redis_backed_limiter())

    @pytest.mark.parametrize(
        ("overrides", "expected_fragment"),
        [
            pytest.param(
                {"in_memory_fallback_enabled": True},
                "process-local fallback",
                id="in_memory_fallback_enabled",
            ),
            pytest.param({"swallow_errors": True}, "swallowed", id="swallow_errors"),
            pytest.param({"headers_enabled": True}, "header I/O", id="headers_enabled"),
            pytest.param({"strategy": "moving-window"}, "not fixed-window", id="wrong_strategy"),
            pytest.param({"key_style": "url"}, "not endpoint", id="wrong_key_style"),
            pytest.param(
                {"key_prefix": "some-other-namespace"},
                "reviewed namespace",
                id="wrong_key_prefix",
            ),
            pytest.param(
                {"application_limits": ["5/minute"]},
                "outside the edge policy",
                id="application_limits_configured",
            ),
        ],
    )
    def test_an_unsafe_constructor_option_is_rejected(self, overrides, expected_fragment):
        """Check an unsafe constructor option is rejected (RuntimeError)."""
        limiter = _redis_backed_limiter(**overrides)
        with pytest.raises(RuntimeError, match=expected_fragment):
            validate_rate_limit_configuration(limiter)


def _memory_limiter() -> Limiter:
    """Build a memory limiter with the production key policy and no error fallback."""
    return Limiter(
        key_func=rl.get_rate_limit_client_id,
        default_limits=["100/minute"],
        strategy="fixed-window",
        storage_uri="memory://",
        storage_options={},
        enabled=True,
        headers_enabled=False,
        key_prefix=rl._RATE_LIMIT_KEY_PREFIX,
        key_style="endpoint",
        in_memory_fallback_enabled=False,
        swallow_errors=False,
    )


class TestHardenedEnvironmentRequiresADedicatedRedisUrl:
    """Hardened web startup rejects a missing dedicated rate-limit Redis URL."""

    def test_a_hardened_environment_with_no_resolved_url_is_rejected(self, monkeypatch):
        """Check a hardened environment with no resolved URL is rejected (RuntimeError)."""
        monkeypatch.setattr(type(settings), "rate_limit_storage_uri", property(lambda _self: None))
        monkeypatch.setattr(settings, "env_state", "production")

        with pytest.raises(RuntimeError, match="no dedicated rate-limit Redis URL"):
            validate_rate_limit_configuration(_memory_limiter())

    def test_a_dev_environment_with_no_resolved_url_is_not_rejected_for_that_reason(
        self, monkeypatch
    ):
        """Check a dev environment with no resolved URL is not rejected for that reason."""
        monkeypatch.setattr(type(settings), "rate_limit_storage_uri", property(lambda _self: None))
        monkeypatch.setattr(settings, "env_state", "dev")

        validate_rate_limit_configuration(_memory_limiter())

    def test_a_hardened_environment_rejects_the_shared_redis_url_substitution(self, monkeypatch):
        """Check a hardened environment rejects the shared Redis URL substitution (RuntimeError)."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr(settings, "redis_url", SecretStr("redis://shared-cache:6379/0"))
        monkeypatch.setattr(settings, "env_state", "production")
        limiter = rl._build_limiter()

        with pytest.raises(RuntimeError):
            validate_rate_limit_configuration(limiter)


class TestMutatingAConstructedLimiterIsAlwaysCaught:
    """Cover mutating aconstructed limiter is always caught."""

    def test_the_unmutated_limiter_passes(self):
        """Check the unmutated limiter passes."""
        validate_rate_limit_configuration(_redis_backed_limiter())

    @pytest.mark.parametrize(
        ("attribute", "value", "expected_fragment"),
        [
            pytest.param("_key_func", lambda _request: "x", "client identity", id="_key_func"),
            pytest.param("_swallow_errors", True, "swallowed", id="_swallow_errors"),
            pytest.param(
                "_in_memory_fallback_enabled", True, "fallback", id="_in_memory_fallback_enabled"
            ),
            pytest.param("_headers_enabled", True, "header I/O", id="_headers_enabled"),
            pytest.param("_strategy", "moving-window", "fixed-window", id="_strategy"),
            pytest.param("_key_style", "url", "endpoint", id="_key_style"),
            pytest.param("_key_prefix", "other", "namespace", id="_key_prefix"),
            pytest.param(
                "_application_limits", ["5/minute"], "edge policy", id="_application_limits"
            ),
            pytest.param("_storage_uri", "redis://other-host:6379/0", "differs", id="_storage_uri"),
            pytest.param("_storage_options", {}, "exact set", id="_storage_options"),
        ],
    )
    def test_a_mutated_private_attribute_is_rejected(self, attribute, value, expected_fragment):
        """Check a mutated private attribute is rejected (RuntimeError)."""
        limiter = _redis_backed_limiter()
        setattr(limiter, attribute, value)
        with pytest.raises(RuntimeError, match=expected_fragment):
            validate_rate_limit_configuration(limiter)
