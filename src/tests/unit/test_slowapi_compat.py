"""Exercise the pinned request-check semantics and explicit instance ownership."""

from unittest.mock import call, create_autospec

import pytest
from fastapi import FastAPI, Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.middleware import rate_limiting as rl
from app.middleware.slowapi_compat import (
    check_request_limit,
    route_is_exempt,
    validate_dependency_shape,
)


def _memory_limiter() -> Limiter:
    """Build a memory-backed limiter with endpoint keys and a hundred requests per minute."""
    return Limiter(
        key_func=lambda: "client",
        default_limits=["100/minute"],
        storage_uri="memory://",
        key_style="endpoint",
    )


def _request() -> Request:
    """Build a minimal GET request for the shared path."""
    return Request({"type": "http", "method": "GET", "path": "/same", "headers": []})


def test_route_override_is_charged_before_default_and_exemptions_survive():
    """Check route override is charged before default and exemptions survive (RateLimitExceeded)."""
    active = _memory_limiter()

    @active.limit("1/minute")
    def endpoint(request: Request) -> None:
        """Provide an inert endpoint carrying the decorator under test."""
        del request

    @active.exempt
    def exempt(request: Request) -> None:
        """Provide an inert endpoint carrying the decorator under test."""
        del request

    validate_dependency_shape(active)
    assert not route_is_exempt(active, endpoint)
    assert route_is_exempt(active, exempt)
    check_request_limit(active, _request(), endpoint)
    with pytest.raises(RateLimitExceeded):
        check_request_limit(active, _request(), endpoint)
    for _ in range(3):
        check_request_limit(active, _request(), exempt)


def test_changed_private_checker_signature_is_rejected_at_startup(monkeypatch):
    """Check changed private checker signature is rejected at startup (RuntimeError)."""
    active = _memory_limiter()
    monkeypatch.setattr(active, "_check_request_limit", lambda _request, _endpoint: None)
    with pytest.raises(RuntimeError, match="request checker"):
        validate_dependency_shape(active)


def test_positional_only_checker_is_rejected_before_keyword_dispatch(monkeypatch):
    """Check positional only checker is rejected before keyword dispatch (RuntimeError)."""
    active = _memory_limiter()

    def checker(request, endpoint_func, in_middleware, /):
        """Provide a positional-only checker that must fail compatibility validation."""
        del request, endpoint_func, in_middleware

    monkeypatch.setattr(active, "_check_request_limit", checker)
    with pytest.raises(RuntimeError, match="request checker"):
        validate_dependency_shape(active)


def test_changed_private_layout_is_rejected_at_startup(monkeypatch):
    """Check changed private layout is rejected at startup (RuntimeError)."""
    active = _memory_limiter()
    monkeypatch.delattr(active, "_storage_options")
    with pytest.raises(RuntimeError, match="dependency layout"):
        validate_dependency_shape(active)


async def test_setup_and_readiness_use_the_supplied_instance(monkeypatch):
    """Check setup and readiness use the supplied instance."""
    active = rl._build_limiter()
    app = FastAPI()
    validate = create_autospec(rl.validate_rate_limit_configuration)
    monkeypatch.setattr(rl, "validate_rate_limit_configuration", validate)
    rl.setup_rate_limiting(app, active)
    assert app.state.limiter is active
    assert active is not rl.limiter
    probe = create_autospec(rl._probe_rate_limit_backend, return_value=True)
    monkeypatch.setattr(rl, "_probe_rate_limit_backend", probe)
    await rl.validate_rate_limit_backend(app.state.limiter)
    assert validate.call_args_list == [call(active), call(active)]
    probe.assert_called_once_with(active.limiter.storage)


def test_configuration_validation_requires_explicit_instance():
    """Check configuration validation requires explicit instance (TypeError)."""
    with pytest.raises(TypeError):
        rl.validate_rate_limit_configuration()
