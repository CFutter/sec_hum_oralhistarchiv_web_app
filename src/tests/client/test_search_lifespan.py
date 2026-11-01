"""Search resources have independent ownership and explicit startup/cleanup."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app import main
from app.services import SearchUnavailable
from tests.fixtures import make_mock_pool


def test_search_pool_and_work_are_separate_from_account_pool(client_builder):
    """Check search pool and work are separate from account pool."""
    client = client_builder()
    assert client.app.state.search_pool is client.mock_search_pool
    assert client.mock_search_pool is not client.mock_pool
    client.lifespan_mocks["SearchWork"].assert_called_once_with(client.mock_search_pool)
    client.mock_search_pool.open.assert_awaited_once_with()
    client.mock_search_pool.wait.assert_awaited_once_with(timeout=10.0)


def test_search_busy_response_is_retryable_and_never_runs_page_or_facets(guest_client):
    """Check search busy response is retryable and never runs page or facets (HTTP 503)."""
    with (
        patch.object(
            guest_client.mock_search_work.connection.return_value,
            "__aenter__",
            new=AsyncMock(side_effect=SearchUnavailable()),
        ),
        patch("app.routes.pages.search_catalogue_page", autospec=True) as page,
        patch("app.routes.pages.get_facets", autospec=True) as facets,
    ):
        response = guest_client.get("/search")
    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert int(response.headers["Retry-After"]) > 0
    assert response.headers.get("Content-Security-Policy")
    assert "Catalogue temporarily unavailable" in response.text
    page.assert_not_awaited()
    facets.assert_not_awaited()


async def test_search_start_readiness_failure_precedes_database_startup():
    """Check search start readiness failure precedes database startup (RuntimeError)."""
    app = MagicMock()
    app.state.limiter = main.limiter
    with (
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True),
        patch.object(main, "load_runtime_catalogue_sources", autospec=True, return_value=()),
        patch.object(main, "publish_catalogue_sources", autospec=True),
        patch.object(main, "validate_route_security_contract", autospec=True),
        patch.object(main, "validate_rate_limit_backend", autospec=True),
        patch.object(
            main,
            "validate_search_start_gate",
            autospec=True,
            side_effect=RuntimeError("Search admission unavailable"),
        ),
        patch.object(main, "create_pool", autospec=True) as ordinary,
        patch.object(main, "create_search_pool", autospec=True) as search,
        pytest.raises(RuntimeError, match="Search admission unavailable"),
    ):
        async with main.lifespan(app):
            pytest.fail("Startup accepted missing search admission")
    ordinary.assert_not_called()
    search.assert_not_called()


async def test_search_pool_startup_failure_closes_both_pools():
    """Check search pool startup failure closes both pools (RuntimeError)."""
    app = MagicMock()
    ordinary, search = make_mock_pool(), make_mock_pool()
    search.wait.side_effect = RuntimeError("search connection unavailable")
    with (
        patch.object(main, "setup_logging", autospec=True),
        patch.object(main, "warn_unconsumed_env_keys", autospec=True),
        patch.object(main, "validate_security_settings", autospec=True),
        patch.object(main, "load_runtime_catalogue_sources", autospec=True, return_value=()),
        patch.object(main, "publish_catalogue_sources", autospec=True),
        patch.object(main, "validate_route_security_contract", autospec=True),
        patch.object(main, "validate_rate_limit_backend", autospec=True),
        patch.object(main, "validate_search_start_gate", autospec=True),
        patch.object(main, "run_in_threadpool", autospec=True),
        patch.object(main, "warm_dummy_password_hash", autospec=True),
        patch.object(main, "Config", autospec=True),
        patch.object(main, "create_pool", autospec=True, return_value=ordinary),
        patch.object(main, "create_search_pool", autospec=True, return_value=search),
        patch.object(main, "validate_runtime_schema", autospec=True),
        patch.object(main, "reconcile_federated_session_policy", autospec=True),
        pytest.raises(RuntimeError, match="search connection unavailable"),
    ):
        async with main.lifespan(app):
            pytest.fail("Startup yielded with an unavailable search pool")
    ordinary.close.assert_awaited_once_with()
    search.close.assert_awaited_once_with()
