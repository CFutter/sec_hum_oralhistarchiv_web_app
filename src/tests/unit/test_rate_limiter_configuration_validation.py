"""``validate_rate_limit_configuration`` rejects every unsafe effective
configuration SlowAPI could otherwise construct — whether the constructor
was called with unsafe options, an already-built limiter's private state is
mutated afterwards, or the environment's own settings resolve to something
unsafe — and admits the exact policy the application actually builds.
"""

import pytest
from pydantic import SecretStr
from slowapi import Limiter

import app.middleware.rate_limiting as rl
from app.middleware.rate_limiting import redis_storage_options, validate_rate_limit_configuration
from config import settings


def _redis_backed_limiter(**overrides) -> Limiter:
    """A limiter built with exactly `_build_limiter`'s options, against the
    test environment's own configured Redis URL so its constructed storage
    URI matches what `validate_rate_limit_configuration` resolves from
    settings."""
    kwargs = {
        "key_func": rl.get_rate_limit_client_id,
        "default_limits": ["100/minute"],
        "strategy": "fixed-window",
        "storage_uri": settings.rate_limit_storage_uri,
        "storage_options": redis_storage_options(),
        "enabled": True,
        "headers_enabled": False,
        "key_prefix": rl._RATE_LIMIT_KEY_PREFIX,
        "key_style": "endpoint",
        "in_memory_fallback_enabled": False,
        "swallow_errors": False,
    }
    kwargs.update(overrides)
    return Limiter(**kwargs)


class TestConstructorOptionsThatMustBeRejected:
    """Positive control plus one parametrize id per unsafe constructor
    option; each unsafe limiter must fail validation while the exact
    application-equivalent construction passes."""

    def test_the_application_equivalent_construction_passes(self):
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
        limiter = _redis_backed_limiter(**overrides)
        with pytest.raises(RuntimeError, match=expected_fragment):
            validate_rate_limit_configuration(limiter)


def _memory_limiter() -> Limiter:
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
    """`settings.rate_limit_storage_uri` never actually resolves to `None`
    today (its final fallback is the literal string `"memory://"`), so this
    exercises the `resolved_storage_uri is None` branch directly by
    patching the property — the defensive check `validate_rate_limit_configuration`
    itself performs, independent of whether anything can reach it today."""

    def test_a_hardened_environment_with_no_resolved_url_is_rejected(self, monkeypatch):
        monkeypatch.setattr(type(settings), "rate_limit_storage_uri", property(lambda _self: None))
        monkeypatch.setattr(settings, "env_state", "production")

        with pytest.raises(RuntimeError, match="no dedicated rate-limit Redis URL"):
            validate_rate_limit_configuration(_memory_limiter())

    def test_a_dev_environment_with_no_resolved_url_is_not_rejected_for_that_reason(
        self, monkeypatch
    ):
        """Positive control: the same unresolved-URL condition, in a
        non-hardened (dev) environment, does not trip this check."""
        monkeypatch.setattr(type(settings), "rate_limit_storage_uri", property(lambda _self: None))
        monkeypatch.setattr(settings, "env_state", "dev")

        validate_rate_limit_configuration(_memory_limiter())

    def test_a_hardened_environment_rejects_the_shared_redis_url_substitution(self, monkeypatch):
        """The specification requires a hardened web process to refuse
        `rate_limit_storage_uri`'s fallback to the shared `REDIS_URL` cache
        when no dedicated `RATE_LIMIT_REDIS_URL` is configured — that cache
        is not provisioned or access-controlled as the rate-limit store."""
        monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
        monkeypatch.setattr(settings, "redis_enabled", True)
        monkeypatch.setattr(settings, "redis_url", SecretStr("redis://shared-cache:6379/0"))
        monkeypatch.setattr(settings, "env_state", "production")
        limiter = rl._build_limiter()

        with pytest.raises(RuntimeError):
            validate_rate_limit_configuration(limiter)


class TestMutatingAConstructedLimiterIsAlwaysCaught:
    """A limiter built exactly like the application's, then mutated on one
    private attribute after construction, must still be rejected —
    validation inspects the live object, not a snapshot taken at
    construction time."""

    def test_the_unmutated_limiter_passes(self):
        """Positive control for every mutation below."""
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
        limiter = _redis_backed_limiter()
        setattr(limiter, attribute, value)
        with pytest.raises(RuntimeError, match=expected_fragment):
            validate_rate_limit_configuration(limiter)
