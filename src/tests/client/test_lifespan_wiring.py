"""Lifespan wiring — startup preflights and source selection.

Patch settings before client construction; the real lifespan runs then.
"""

import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

import pytest
from starlette.concurrency import run_in_threadpool as _real_run_in_threadpool

from app import main
from app.main import lifespan
from app.sources import FixtureAdapter, FixtureConfig, SourceDisplay, configure_sources
from config import settings


@pytest.mark.parametrize("role", ("scheduler", "maintenance"))
async def test_web_refuses_another_process_role_before_loading_sources(monkeypatch, role):
    """Check web refuses another process role before loading sources (RuntimeError)."""
    monkeypatch.setattr(settings, "app_process_role", role)
    test_app = SimpleNamespace(state=SimpleNamespace(limiter=main.limiter))
    with (
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True) as validate,
        patch.object(main, "load_runtime_catalogue_sources", autospec=True) as load,
        patch.object(main, "create_pool", autospec=True) as create_pool,
        pytest.raises(RuntimeError, match="APP_PROCESS_ROLE=web"),
    ):
        async with lifespan(test_app):
            pytest.fail("web accepted another process role")
    validate.assert_not_called()
    load.assert_not_called()
    create_pool.assert_not_called()


async def test_rate_limit_probe_failure_aborts_before_opening_database():
    """An unavailable security-counter store prevents web startup."""
    test_app = SimpleNamespace(state=SimpleNamespace(limiter=main.limiter))
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

    probe.assert_awaited_once_with(test_app.state.limiter)
    create_pool.assert_not_called()


def test_federated_session_policy_is_reconciled_after_schema_validation(client_builder):
    """Require schema validation before federated-policy reconciliation and fail startup on refusal."""
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
    test_app = SimpleNamespace(state=SimpleNamespace(limiter=main.limiter))
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


@pytest.mark.parametrize(
    ("environment", "debug"),
    [("dev", False), ("dev", True), ("staging", False)],
    ids=["development", "development-debug", "staging"],
)
def test_web_startup_retains_fixture_selection_without_populating_the_catalogue(
    client_builder, monkeypatch, environment, debug
):
    """Check web startup retains fixture selection without populating the catalogue."""
    monkeypatch.setattr(settings, "env_state", environment)
    monkeypatch.setattr(settings, "fastapi_debug", debug)
    sources = configure_sources(
        (FixtureConfig(name="fixture_demo", display=SourceDisplay(label="Offline archive")),)
    )
    with patch.object(
        FixtureAdapter,
        "fetch",
        autospec=True,
        side_effect=AssertionError("Web startup must not harvest"),
    ) as fetch:
        client = client_builder(configured_sources=sources)

    fetch.assert_not_called()
    client.mock_pool.connection.assert_not_called()
    assert tuple(source.config for source in client.app.state.configured_sources) == tuple(
        source.config for source in sources
    )
    assert all(not hasattr(source, "adapter") for source in client.app.state.configured_sources)


def test_web_startup_publishes_detached_metadata_in_selection_order(client_builder):
    """Web consumers retain policy fields without any scheduler fetch adapter."""
    sources = configure_sources(
        (
            FixtureConfig(name="archive_one", display=SourceDisplay(label="Archive one")),
            FixtureConfig(name="archive_two", display=SourceDisplay(label="Archive two")),
        )
    )
    client = client_builder(configured_sources=sources)
    source_loader = client.lifespan_mocks["load_runtime_catalogue_sources"]

    source_loader.assert_called_once_with()
    metadata = client.app.state.configured_sources
    assert tuple(source.config for source in metadata) == tuple(source.config for source in sources)
    assert all(not hasattr(source, "adapter") for source in metadata)
    assert client.app.state.catalogue_policy.sources is metadata
    assert client.app.state.catalogue_policy.source_by_name == {
        source.name: source for source in metadata
    }
    assert source_loader.return_value is sources
    client.lifespan_mocks["publish_catalogue_sources"].assert_awaited_once_with(
        client.app, client.mock_pool, sources
    )
    client.lifespan_mocks["CatalogueStatsCache"].assert_called_once_with(
        client.mock_pool,
        source_names=tuple(source.name for source in sources),
        policy_fingerprint=client.app.state.catalogue_policy.fingerprint,
        subscribe=True,
    )


@pytest.mark.parametrize(
    ("selected_path", "endpoint", "message"),
    [
        (
            None,
            "https://archive.example.edu/oai",
            r"SOURCES_CONFIG_FILE.*required",
        ),
        (
            "/etc/oralhistarchiv-sources/sources.toml",
            "http://archive.example.edu/oai",
            r"requires.*HTTPS endpoint",
        ),
        (
            "/etc/oralhistarchiv-sources/sources.toml",
            "https://archive.example.org/oai",
            "placeholder endpoint host",
        ),
    ],
    ids=["missing-selection", "plaintext", "placeholder"],
)
async def test_source_selection_refusal_precedes_runtime_resources(
    monkeypatch, selected_path, endpoint, message
):
    """Check source selection refusal precedes runtime resources (ValueError)."""
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "sources_config_file", selected_path)
    document = (
        "[[sources]]\n"
        'name = "selected_archive"\n'
        'adapter = "oai_pmh_cmdi"\n'
        'label = "Selected archive"\n'
        'institution_filter = "Configured archive"\n'
        f'endpoint = "{endpoint}"\n'
    )
    test_app = SimpleNamespace(state=SimpleNamespace(limiter=main.limiter))

    with (
        patch(
            "app.sources.startup_file._read_hardened_file",
            autospec=True,
            return_value=document,
        ) as reader,
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True),
        patch.object(main, "validate_route_security_contract", autospec=True) as validate_routes,
        patch.object(main, "validate_rate_limit_backend", autospec=True) as limiter_probe,
        patch.object(
            main,
            "run_in_threadpool",
            new=create_autospec(_real_run_in_threadpool),
        ) as offload,
        patch.object(main, "warm_password_blocklist", autospec=True) as warm_blocklist,
        patch.object(main, "warm_dummy_password_hash", autospec=True) as warm_dummy,
        patch.object(main, "Config", autospec=True) as migration_config,
        patch.object(main, "create_pool", autospec=True) as create_pool,
        patch.object(main, "CatalogueStatsCache", autospec=True) as cache,
        pytest.raises(ValueError, match=message),
    ):
        async with lifespan(test_app):
            pytest.fail("web startup accepted invalid source selection")

    assert reader.call_count == int(selected_path is not None)
    validate_routes.assert_not_called()
    limiter_probe.assert_not_awaited()
    offload.assert_not_awaited()
    warm_blocklist.assert_not_called()
    warm_dummy.assert_not_awaited()
    migration_config.assert_not_called()
    create_pool.assert_not_called()
    cache.assert_not_called()
    assert not hasattr(test_app.state, "configured_sources")
