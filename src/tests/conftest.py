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

Parallel workers (pytest-xdist, `-n auto`): each worker process gets a private
integration database whose name carries the worker id
(oralhistarchiv_test -> oralhistarchiv_test_gw0) and a Redis database of its
own for the rate limiter's counters, so two workers can never truncate each
other's tables or reset each other's counters. Both are settled below, before
the application freezes the values into `Settings`.
"""

import logging
import os
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urlunsplit

_TEST_ENV_DEFAULTS = {
    "ENV_STATE": "dev",
    # Launcher-agnostic DB selection: CI sets DATABASE_URL on the job; locally
    # the default matches docker-compose.yml exactly (user test / pw test).
    "DATABASE_URL": "postgresql://test:test@localhost:5432/oralhistarchiv_test",
    "PUBLIC_BASE_URL": "http://127.0.0.1:5000",
    "SWISSUBASE_OAI_PMH_URL": "https://www.swissubase.ch/oai-pmh/v1/oai",
    # Fixed, strong-looking secrets: >=43 chars and high character diversity so
    # the startup strength validator stays quiet even when left unpatched.
    "SECRET_KEY": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
    "SESSION_SECRET": "aQ3eT6yU9iP2sD5fG8hJ1kL4zX7cV0bN3mW6rE9tY2uI5oS8",
    "TOTP_ENCRYPTION_KEYS": '["mB5nV8cX2zL7kJ4hG1fD9sA6qW3eR0tY5uI8oP2lM7wE4rT9"]',
    "OUTBOX_ENCRYPTION_KEYS": '["pQ8vN2rL6xB9mD4sF7hJ1kC5wY0zA3eR6tU9iO2gH5bV8nM4"]',
    "HEALTH_DETAIL_TOKEN": "hT7dK2mQ9wX4vB8zN1cR5jF0aG3sL6eY9uP2iO5tM8kW3qE7",
    "ALLOWED_HOSTS": '["localhost", "127.0.0.1", "testserver"]',
    "OAI_INSTITUTION_FILTER": "Universität Kassel",
    # Rate limiting ON with a low per-minute default: the route-level rate-limit
    # tests trip it with ~31 requests. The autouse reset below isolates tests from each
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

# FORCED, not setdefault: a developer shell that exports FASTAPI_DEBUG=true
# (direnv/nix devshell sourcing .env) would otherwise open /docs and the
# unauthenticated /health/detail branch, breaking the fail-secure health
# tests. (Mock seeding is no longer tied to this flag — it is driven by
# SEED_MOCK_DATA below.) Tests that need debug behaviour patch `settings`
# directly (see test_health_routes.py), so pinning it here is safe.
os.environ["FASTAPI_DEBUG"] = "false"

# FORCED for the same reason: SEED_MOCK_DATA=true in a developer's .env or
# shell would make the integration tier's REAL lifespan insert mock rows into
# the test database, breaking every dataset-count and search-result assertion.
# (The client tier is immune — fixtures autospec seed_mock_data — but the
# integration tier runs the real thing.)
os.environ["SEED_MOCK_DATA"] = "false"

# pytest-xdist sets PYTEST_XDIST_WORKER (gw0, gw1, ...) in the worker process
# before pytest starts. Both pins below key off it; a serial run has no worker.
_XDIST_WORKER = os.environ.get("PYTEST_XDIST_WORKER")
_XDIST_WORKER_INDEX = int(_XDIST_WORKER.removeprefix("gw")) if _XDIST_WORKER else None

# FORCED: the limiter's counters are pinned to a Redis database of this
# process's own. The application refuses to start in its documented
# process-local memory mode (validate_rate_limit_configuration treats the
# "memory://" fallback as a Redis URL; recorded in docs/known-defects.md), so
# the suite cannot simply leave RATE_LIMIT_REDIS_URL empty. Left to the
# environment, a developer's .env would put every test process's counters in
# the same database, where the autouse reset below wipes another process's
# counters and the low test-environment limits trip at random. A serial run
# uses database TEST_RATE_LIMIT_REDIS_DB (default 0); xdist worker gwN uses
# the base plus N+1, so no two workers of one run share a database. Two
# suites run side by side serially need different bases
# (TEST_RATE_LIMIT_REDIS_DB=15 for the second one). Redis ships sixteen
# databases, hence the bound.
_REDIS_TEST_INSTANCE = urlsplit(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
_RATE_LIMIT_REDIS_DB = int(os.environ.get("TEST_RATE_LIMIT_REDIS_DB", "0"))
if _XDIST_WORKER_INDEX is not None:
    _RATE_LIMIT_REDIS_DB += _XDIST_WORKER_INDEX + 1
if not 0 <= _RATE_LIMIT_REDIS_DB <= 15:
    raise RuntimeError(
        f"no Redis database left for the rate limiter's counters (database "
        f"{_RATE_LIMIT_REDIS_DB} requested, worker {_XDIST_WORKER or 'none'}): Redis "
        "provides sixteen, one per process, so lower TEST_RATE_LIMIT_REDIS_DB or "
        "run fewer workers"
    )
os.environ["RATE_LIMIT_REDIS_URL"] = urlunsplit(
    _REDIS_TEST_INSTANCE._replace(path=f"/{_RATE_LIMIT_REDIS_DB}", query="", fragment="")
)

# Give an xdist worker its own integration database by suffixing the
# configured name with the worker id; src/tests/integration/conftest.py
# creates the database when it is missing. The rewrite has to happen here,
# ahead of the `config.settings` import below, because the application's
# connection pool reads DATABASE_URL from the Settings object constructed at
# import time.
if _XDIST_WORKER:
    _head, _, _tail = os.environ["DATABASE_URL"].rpartition("/")
    _name, _sep, _query = _tail.partition("?")
    if not _name.endswith(f"_{_XDIST_WORKER}"):
        os.environ["DATABASE_URL"] = f"{_head}/{_name}_{_XDIST_WORKER}{_sep}{_query}"

import pytest  # noqa: E402

from app.middleware.rate_limiting import limiter  # noqa: E402


def pytest_collection_modifyitems(items):
    """Auto-mark everything under tests/integration/ with the marker the CI
    jobs split on, so a test can't silently land in the wrong tier."""
    for item in items:
        if "integration" in item.path.parts:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear slowapi's counters between tests.

    All TestClient requests share one client IP ("testclient"), so without
    this, request counts would leak across tests and trip the low test-env
    default limits at random. The counters live in this process's own Redis
    database (see the RATE_LIMIT_REDIS_URL pin above), so this reset cannot
    reach another worker's counters.
    """
    limiter.reset()
    yield


# ---------------------------------------------------------------------------
# Client fixtures (unit tier — mocked pool, real middleware stack)
# ---------------------------------------------------------------------------

from tests.fixtures import build_client, make_sample_user, teardown_client  # noqa: E402


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


# ---------------------------------------------------------------------------
# Skipping is opt-in: under CI a skipped integration test fails the run.
# ---------------------------------------------------------------------------


def running_under_ci() -> bool:
    """GitHub Actions exports CI=true; any value but an explicit off means CI."""
    return os.environ.get("CI", "").strip().lower() not in ("", "0", "false", "no")


def _is_integration_tier(nodeid: str) -> bool:
    """The same test as the collection hook above, on a report's node id."""
    return "integration" in PurePosixPath(nodeid.split("::", 1)[0]).parts


def _skipped_integration_nodeids(config) -> list[str]:
    """Node ids of every integration-tier item this process saw skipped: its
    own in a serial run, every worker's on the xdist controller. Expected
    failures are reported under "xfailed", not "skipped", so a guarded defect
    never counts as a skip."""
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return []
    skipped = reporter.stats.get("skipped", [])
    return sorted({report.nodeid for report in skipped if _is_integration_tier(report.nodeid)})


def pytest_sessionfinish(session, exitstatus):
    """A run in which any integration-tier item was skipped exits non-zero
    under CI, even though nothing failed. REQUIRE_DB and REQUIRE_REDIS already
    turn a dead service into an error; this closes every other reason an
    integration test might skip. Without CI the skip stays a skip and the
    summary below says so. An xdist worker leaves the decision to the
    controller, which sees every worker's reports."""
    if _XDIST_WORKER or not running_under_ci() or exitstatus != pytest.ExitCode.OK:
        return
    if _skipped_integration_nodeids(session.config):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config):  # noqa: ARG001
    """Pytest exits 0 on an all-skipped tier. A green local run with no
    database verified NONE of the auth/session/access-control assurance —
    every SQL-layer security property lives in the integration tier. Say so,
    loudly, and name what was skipped. Under CI the session hook above has
    already turned the skips into a non-zero exit; this names them."""
    integration_skips = _skipped_integration_nodeids(config)
    if not integration_skips:
        return
    if running_under_ci():
        terminalreporter.write_sep("=", "INTEGRATION TESTS SKIPPED UNDER CI", red=True, bold=True)
        terminalreporter.write_line(
            f"{len(integration_skips)} integration tests skipped while CI is set. Under CI "
            "every integration test runs, so this run exits non-zero. Skipped:"
        )
    elif not os.environ.get("REQUIRE_DB"):
        terminalreporter.write_sep("=", "INTEGRATION TESTS SKIPPED", red=True, bold=True)
        terminalreporter.write_line(
            f"{len(integration_skips)} integration tests skipped and REQUIRE_DB is unset. "
            "When the whole tier skipped there was no database, and this run verified NO "
            "SQL-layer security property: tier gating, TOTP replay, lockout, sessions and "
            "CSRF roundtrip. Skipped:"
        )
    else:
        return
    shown = integration_skips[:10]
    for nodeid in shown:
        terminalreporter.write_line(f"  {nodeid}")
    if len(integration_skips) > len(shown):
        terminalreporter.write_line(f"  ... and {len(integration_skips) - len(shown)} more")
    if not running_under_ci():
        terminalreporter.write_line(
            "  Fix: docker compose up -d db redis && REQUIRE_DB=1 REQUIRE_REDIS=1 pytest"
        )


@pytest.fixture
def restore_logging():
    """Snapshot and restore global logging state.

    For tests that call setup_logging() for real: it clears root handlers
    (which would otherwise break caplog for every later test) and mutates the
    audit logger. Restores handlers, levels, and propagate flags afterwards.
    """
    root = logging.getLogger()
    audit = logging.getLogger("audit")
    saved = (
        root.handlers[:],
        root.level,
        audit.handlers[:],
        audit.level,
        audit.propagate,
    )
    try:
        yield
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])
        audit.handlers[:] = saved[2]
        audit.setLevel(saved[3])
        audit.propagate = saved[4]


@pytest.fixture
def admin_actor(user_factory, session_factory):
    """A committed active administrator with an authorizing full session."""
    actor = user_factory(is_admin=True, is_active=True)
    actor.session_id = session_factory(actor.id, purpose="full")
    return actor
