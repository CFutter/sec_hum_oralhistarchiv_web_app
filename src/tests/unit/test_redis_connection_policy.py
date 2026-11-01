"""Connection constructors must preserve the validated Redis policy."""

import ssl
from unittest.mock import patch

import pytest
import redis
from pydantic import SecretStr, ValidationError
from redis.backoff import NoBackoff
from redis.retry import Retry

import app.middleware.rate_limiting as rl
import app.services.redis_client as cache_redis
from config import redis_connection_policy_issues, redis_url_policy_issues, settings
from tests.unit.settings_builders import base_kwargs, make_settings, prod_kwargs, staging_kwargs


@pytest.mark.parametrize("field", ["redis_url", "rate_limit_redis_url"])
@pytest.mark.parametrize(
    "suffix",
    ["?socket_timeout=999", "?socket_connect_timeout=998", "?ssl_cert_reqs=none", "?", "#", "#x"],
)
def test_settings_reject_url_overrides_without_exposing_credentials(field, suffix):
    """Check settings reject URL overrides without exposing credentials (ValidationError)."""
    password = "private-url-credential-must-not-appear"
    kwargs = base_kwargs(redis_enabled=field == "redis_url")
    kwargs[field] = f"rediss://reader:{password}@redis.example.org/0{suffix}"
    with pytest.raises(ValidationError) as caught:
        make_settings(**kwargs)
    assert "query parameters or a fragment" in str(caught.value)
    assert password not in str(caught.value)


@pytest.mark.parametrize(
    "url",
    [
        "redis://remote.example.org/0",
        "rediss://default:password@remote.example.org/0",
        "rediss://named@remote.example.org/0",
        "rediss://named:password@remote.example.org/1",
        "http://named:password@remote.example.org/0",
        "redis+unix:///run/../redis.sock",
    ],
)
def test_hardened_dedicated_url_policy(url):
    """Check hardened dedicated URL policy."""
    assert redis_url_policy_issues(url, hardened=True, dedicated=True)


@pytest.mark.parametrize(
    "url",
    [
        "redis://named:password@127.0.0.1/0",
        "redis://named:password@[::1]/0",
        "rediss://named:password@remote.example.org/0",
        "redis+unix://named:password@/run/redis/redis.sock",
    ],
)
def test_supported_hardened_transports(url):
    """Check supported hardened transports."""
    assert not redis_url_policy_issues(url, hardened=True, dedicated=True)


def _effective_options(url, **overrides):
    """Construct a Redis client without connecting and expose its effective connection options."""
    client = redis.Redis.from_url(
        url,
        socket_timeout=0.5,
        socket_connect_timeout=0.5,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
        **overrides,
    )
    pool = client.connection_pool
    return {**pool.connection_kwargs, "connection_class": pool.connection_class}


def test_locked_client_url_precedence_is_checked_after_construction():
    """Check locked client URL precedence is checked after construction."""
    options = _effective_options(
        "rediss://named:secret@redis.example.org/0"
        "?socket_timeout=999&socket_connect_timeout=998&ssl_cert_reqs=none"
    )
    assert options["socket_timeout"] == 999
    assert options["socket_connect_timeout"] == 998
    issues = redis_connection_policy_issues(options, maximum_timeout=0.5)
    assert len(issues) == 3


@pytest.mark.parametrize(
    "override",
    [
        {"ssl_cert_reqs": None},
        {"ssl_cert_reqs": ssl.CERT_NONE},
        {"ssl_cert_reqs": "optional"},
        {"ssl_check_hostname": False},
    ],
)
def test_effective_tls_weakening_is_rejected(override):
    """Check effective tls weakening is rejected."""
    options = _effective_options("rediss://redis.example.org/0", **override)
    assert redis_connection_policy_issues(options, maximum_timeout=0.5)


def test_tls_defaults_and_exact_bounded_options_pass():
    """Check tls defaults and exact bounded options pass."""
    options = _effective_options("rediss://redis.example.org/0")
    assert not redis_connection_policy_issues(options, maximum_timeout=0.5)


def test_limiter_checks_mutated_effective_pool_not_only_constructor_options():
    """Check limiter checks mutated effective pool not only constructor options (RuntimeError)."""
    limiter = rl._build_limiter()
    pool = limiter.limiter.storage.get_connection().connection_pool
    pool.connection_kwargs["socket_timeout"] = 999
    with pytest.raises(RuntimeError, match="Effective Redis socket_timeout"):
        rl.validate_rate_limit_configuration(limiter)


def test_mutated_url_is_rejected_at_limiter_preflight(monkeypatch):
    """Check mutated URL is rejected at limiter preflight (RuntimeError)."""
    monkeypatch.setattr(
        settings, "rate_limit_redis_url", SecretStr("redis://127.0.0.1/0?socket_timeout=999")
    )
    limiter = rl._build_limiter()
    with pytest.raises(RuntimeError, match="query parameters"):
        rl.validate_rate_limit_configuration(limiter)


@pytest.mark.parametrize("builder", [prod_kwargs, staging_kwargs])
def test_hardened_settings_require_enabled_web_admission(builder):
    """Check hardened settings require enabled web admission (ValidationError)."""
    with pytest.raises(ValidationError, match="RATE_LIMIT_ENABLED must be true"):
        make_settings(**builder(rate_limit_enabled=False))


def test_development_can_disable_per_client_admission():
    """Check development can disable per client admission."""
    assert not make_settings(**base_kwargs(rate_limit_enabled=False)).rate_limit_enabled


@pytest.mark.parametrize("mutate_settings", [True, False])
def test_hardened_preflight_rejects_disabled_effective_admission(monkeypatch, mutate_settings):
    """Check hardened preflight rejects disabled effective admission (RuntimeError)."""
    limiter = rl._build_limiter()
    monkeypatch.setattr(settings, "env_state", "production")
    if mutate_settings:
        monkeypatch.setattr(settings, "rate_limit_enabled", False)
    else:
        limiter.enabled = False
    with pytest.raises(RuntimeError, match="hardened web admission must be enabled"):
        rl.validate_rate_limit_configuration(limiter)


def test_optional_cache_rejects_mutated_url_before_constructor(monkeypatch, caplog):
    """Check optional cache rejects mutated URL before constructor."""
    monkeypatch.setattr(cache_redis, "_client", None)
    monkeypatch.setattr(cache_redis, "_last_failure_time", None)
    monkeypatch.setattr(settings, "redis_enabled", True)
    monkeypatch.setattr(
        settings, "redis_url", SecretStr("redis://named:private-cache-secret@localhost/0?db=1")
    )
    with patch.object(redis.Redis, "from_url", autospec=True) as constructor:
        assert cache_redis.get_redis() is None
        constructor.assert_not_called()
    assert "private-cache-secret" not in caplog.text


def test_optional_cache_checks_effective_options_before_network(monkeypatch):
    """Check optional cache checks effective options before network."""
    actual = redis.Redis.from_url("redis://localhost/0?socket_timeout=999")
    monkeypatch.setattr(cache_redis, "_client", None)
    monkeypatch.setattr(cache_redis, "_last_failure_time", None)
    monkeypatch.setattr(settings, "redis_enabled", True)
    monkeypatch.setattr(settings, "redis_url", SecretStr("redis://localhost/0"))
    with (
        patch.object(redis.Redis, "from_url", autospec=True, return_value=actual),
        patch.object(actual, "ping", autospec=True) as ping,
    ):
        assert cache_redis.get_redis() is None
        ping.assert_not_called()


def test_hardened_security_gate_rejects_disabled_admission(monkeypatch):
    """Check hardened security gate rejects disabled admission (RuntimeError)."""
    from app.middleware.validators import validate_security_settings  # noqa: PLC0415

    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    with pytest.raises(RuntimeError, match="RATE_LIMIT_ENABLED must be true"):
        validate_security_settings()
