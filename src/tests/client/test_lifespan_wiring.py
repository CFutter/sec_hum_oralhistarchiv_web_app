"""Lifespan wiring — startup security calls and flag-driven mock seeding.

The lifespan imports seed_mock_data lazily inside the function, resolving the
module attribute at call time — exactly the seam the client harness patches
(app.services.seed_mock_data.seed_mock_data). The entered spy is exposed as
client.lifespan_mocks["seed_mock_data"], so these tests observe the REAL
lifespan's seeding decision without a database.

Because the lifespan runs during client construction, any settings monkeypatch
must land BEFORE the builder is called.
"""

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

import pytest
from starlette.concurrency import run_in_threadpool as _real_run_in_threadpool

from app import main
from app.main import lifespan
from config import settings


async def test_rate_limit_probe_failure_aborts_before_opening_database():
    """An unavailable security-counter store prevents web startup."""
    test_app = SimpleNamespace(state=SimpleNamespace())
    with (
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True),
        patch.object(main, "validate_route_security_contract", autospec=True),
        patch.object(
            main,
            "validate_rate_limit_backend",
            autospec=True,
            side_effect=RuntimeError("Required rate-limit backend is unavailable"),
        ) as probe,
        patch.object(main, "create_pool", autospec=True) as create_pool,
        pytest.raises(RuntimeError, match="Required rate-limit backend is unavailable"),
    ):
        async with lifespan(test_app):
            pytest.fail("web startup accepted an unavailable limiter")

    probe.assert_awaited_once_with()
    create_pool.assert_not_called()


def test_federated_session_policy_is_reconciled_after_schema_validation(client_builder):
    """Startup must fail closed before accepting any HTTP request.

    The client harness exposes both awaited spies. Their call order pins that
    the policy-state table has first passed the runtime schema contract and
    that reconciliation uses the newly opened application pool.
    """
    client = client_builder()

    schema_call = client.lifespan_mocks["validate_runtime_schema"].await_args_list[0]
    policy_call = client.lifespan_mocks["reconcile_federated_session_policy"].await_args_list[0]
    assert schema_call.args == (client.mock_pool,)
    assert policy_call.args == (client.mock_pool,)
    assert (
        client.lifespan_mocks["validate_runtime_schema"].await_count
        == client.lifespan_mocks["reconcile_federated_session_policy"].await_count
        == 1
    )
    source = inspect.getsource(lifespan)
    assert source.index('await validate_runtime_schema(pool, process="web")') < source.index(
        "await reconcile_federated_session_policy(pool)"
    )


async def test_federated_policy_reconciliation_failure_aborts_startup_and_closes_pool():
    """A stale authority policy must never degrade into an available app."""
    pool = MagicMock(name="pool")
    pool.open = AsyncMock()
    pool.close = AsyncMock()
    test_app = SimpleNamespace(state=SimpleNamespace())
    reconcile_error = RuntimeError("policy reconciliation failed")

    with (
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True),
        patch.object(main, "validate_route_security_contract", autospec=True) as validate_routes,
        patch.object(main, "validate_rate_limit_backend", autospec=True),
        patch.object(main, "run_in_threadpool", new=create_autospec(_real_run_in_threadpool)),
        patch.object(main, "Config", autospec=True),
        patch.object(main, "create_pool", autospec=True, return_value=pool),
        patch.object(main, "validate_runtime_schema", autospec=True),
        patch.object(
            main,
            "reconcile_federated_session_policy",
            autospec=True,
            side_effect=reconcile_error,
        ) as reconcile,
        patch.object(main, "CatalogueStatsCache", autospec=True) as cache,
        pytest.raises(RuntimeError, match="policy reconciliation failed"),
    ):
        async with lifespan(test_app):
            pytest.fail("lifespan yielded after federation-policy failure")

    pool.open.assert_awaited_once_with()
    validate_routes.assert_called_once_with(test_app)
    reconcile.assert_awaited_once_with(pool)
    cache.assert_not_called()
    pool.close.assert_awaited_once_with()


def test_seed_flag_true_drives_lifespan_seeding(client_builder, monkeypatch):
    """Seeding follows settings.seed_mock_data — with the flag
    on, the lifespan awaits seed_mock_data exactly once, on the pool it just
    built. Positive control for the two negative wirings below; a lifespan
    that dropped the flag branch (or seeded through some other pool) fails
    here, not in staging."""
    monkeypatch.setattr(settings, "seed_mock_data", True)
    client = client_builder()
    client.lifespan_mocks["seed_mock_data"].assert_awaited_once_with(client.mock_pool)


def test_seed_flag_default_false_never_seeds(client_builder):
    """With the flag at its (conftest-pinned) default False,
    the lifespan must not touch seed_mock_data at all. Guards the accidental-
    seeding class — a startup path that inserts demo rows into a real
    environment because the opt-in stopped gating it."""
    assert settings.seed_mock_data is False  # precondition: the conftest pin
    client = client_builder()
    assert client.lifespan_mocks["seed_mock_data"].await_count == 0


def test_fastapi_debug_alone_does_not_seed(client_builder, monkeypatch):
    """Seeding is decided by seed_mock_data alone, never by fastapi_debug:
    debug-coupled seeding would mean flipping debug on quietly implies demo
    data. With debug True but seed_mock_data False, the lifespan must still
    not seed; debug-coupled seeding fails exactly here."""
    monkeypatch.setattr(settings, "fastapi_debug", True)
    client = client_builder()
    assert client.lifespan_mocks["seed_mock_data"].await_count == 0


def test_staging_web_never_seeds_with_its_read_only_role(client_builder, monkeypatch):
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "seed_mock_data", True)
    client = client_builder()
    client.lifespan_mocks["seed_mock_data"].assert_not_awaited()
