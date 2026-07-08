"""Root conftest — test environment bootstrap and shared fixtures.

ENVIRONMENT BOOTSTRAP (must happen before anything imports `config`):
`config.settings` constructs `Settings()` at import time, and several modules
freeze settings-derived values at import (the rate limiter's default limits,
the cookie signer, the CSRF HMAC key). This file is imported by pytest before
any test module, so the `os.environ.setdefault` block below is the single
place the test configuration is defined.

DATABASE_URL is read from the environment with a local default, so the SAME
suite runs against local docker-compose (`docker compose up -d db`) and the
CI service container with no code difference. Because the app itself reads
DATABASE_URL through Settings, pointing the env var at the test database is
all it takes for integration tests to hit it.

Tiering: everything under src/tests/integration/ is auto-marked `integration`
by the collection hook below. The unit tier (`pytest -m "not integration"`)
must stay green with no database, Redis, or SMTP available.
"""
import os

_TEST_ENV_DEFAULTS = {
    "ENV_STATE": "dev",
    # Launcher-agnostic DB selection: CI sets DATABASE_URL on the job; locally
    # the default matches docker-compose.yml exactly (user test / pw test).
    "DATABASE_URL": "postgresql://test:test@localhost:5432/oralhistarchiv_test",
    "PUBLIC_BASE_URL": "http://127.0.0.1:5000",
    # Fixed, strong-looking secrets: >=43 chars and high character diversity so
    # the startup strength validator stays quiet even when left unpatched.
    "SECRET_KEY": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
    "SESSION_SECRET": "aQ3eT6yU9iP2sD5fG8hJ1kL4zX7cV0bN3mW6rE9tY2uI5oS8",
    "TOTP_ENCRYPTION_KEYS": '["mB5nV8cX2zL7kJ4hG1fD9sA6qW3eR0tY5uI8oP2lM7wE4rT9"]',
    "HEALTH_DETAIL_TOKEN": "hT7dK2mQ9wX4vB8zN1cR5jF0aG3sL6eY9uP2iO5tM8kW3qE7",
    "ALLOWED_HOSTS": '["localhost", "127.0.0.1", "testserver"]',
    "OAI_INSTITUTION_FILTER": "Universität Kassel",
    # Rate limiting ON with a low per-minute default: the §5.1/§5.3 tests trip
    # it with ~31 requests. The autouse reset below isolates tests from each
    # other (TestClient requests all share the "testclient" client IP).
    "RATE_LIMIT_ENABLED": "true",
    "RATE_LIMIT_PER_MINUTE": "30",
    "RATE_LIMIT_PER_HOUR": "1000",
    "RATE_LIMIT_PER_DAY": "10000",
    # Threshold 3 keeps the HTTP lockout test under /login's 5/minute limit.
    "LOGIN_FAILURE_THRESHOLD": "3",
    "LOGIN_LOCKOUT_MINUTES": "15",
    "SMTP_ENABLED": "false",
    "REDIS_ENABLED": "false",
    "SHIBBOLETH_ENABLED": "false",
    "CORS_ENABLED": "false",
    # TestClient talks plain http; Secure-flagged cookies would be dropped.
    "COOKIES_SECURE": "false",
    "FASTAPI_DEBUG": "false",
    "LOG_LEVEL": "INFO",
    "LOG_FORMAT": "json",
}
for _k, _v in _TEST_ENV_DEFAULTS.items():
    os.environ.setdefault(_k, _v)

import pytest  # noqa: E402


def pytest_collection_modifyitems(config, items):
    """Auto-mark everything under tests/integration/ with the marker the CI
    jobs split on, so a test can't silently land in the wrong tier."""
    for item in items:
        if "integration" in item.path.parts:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear slowapi's in-memory counters between tests.

    All TestClient requests share one client IP ("testclient"), so without
    this, request counts would leak across tests and trip the low test-env
    default limits at random.
    """
    from app.middleware.rate_limiting import limiter

    limiter.reset()
    yield


# ---------------------------------------------------------------------------
# Client fixtures (unit tier — mocked pool, real middleware stack)
# ---------------------------------------------------------------------------

from tests.fixtures import build_client, teardown_client, make_sample_user  # noqa: E402


@pytest.fixture
def guest_client():
    """TestClient as an unauthenticated guest (request.state.user is None)."""
    client = build_client(session_user=None)
    try:
        yield client
    finally:
        teardown_client(client)


@pytest.fixture
def authenticated_client():
    """TestClient authenticated as a regular user with TOTP configured."""
    client = build_client(session_user=make_sample_user())
    try:
        yield client
    finally:
        teardown_client(client)


@pytest.fixture
def admin_client():
    """TestClient authenticated as an admin user."""
    admin = make_sample_user(
        id=99,
        email="admin@uzh.ch",
        display_name="Admin User",
        access_tier="vetted",
        is_admin=True,
    )
    client = build_client(session_user=admin)
    try:
        yield client
    finally:
        teardown_client(client)


@pytest.fixture
def totp_setup_client():
    """TestClient with a limited 'totp_setup' session (TOTP not yet enrolled)."""
    user = make_sample_user(totp_configured=False)
    client = build_client(session_user=user, session_purpose="totp_setup")
    try:
        yield client
    finally:
        teardown_client(client)


@pytest.fixture
def client_builder():
    """Factory for custom client states (flash pending, custom users, ...).

    Yields build_client; every client built through it is torn down after the
    test regardless of how many were created.
    """
    built = []

    def _build(**kwargs):
        client = build_client(**kwargs)
        built.append(client)
        return client

    try:
        yield _build
    finally:
        # Reverse build order: unittest.mock restores the value seen at patch
        # START, so tearing down client1 before client2 would permanently
        # re-install client1's mock over the real function for the rest of
        # the process (pinned by the test_client_builder_reverse_teardown_*
        # pair in unit/test_harness_smoke.py).
        for client in reversed(built):
            teardown_client(client)


@pytest.fixture
def restore_logging():
    """Snapshot and restore global logging state.

    For tests that call setup_logging() for real: it clears root handlers
    (which would otherwise break caplog for every later test) and mutates the
    audit logger. Restores handlers, levels, and propagate flags afterwards.
    """
    import logging

    root = logging.getLogger()
    audit = logging.getLogger("audit")
    saved = (
        root.handlers[:], root.level,
        audit.handlers[:], audit.level, audit.propagate,
    )
    try:
        yield
    finally:
        root.handlers[:], root.level = saved[0], saved[1]
        root.setLevel(saved[1])
        audit.handlers[:] = saved[2]
        audit.setLevel(saved[3])
        audit.propagate = saved[4]
