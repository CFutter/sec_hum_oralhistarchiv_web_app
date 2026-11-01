"""Unit clients must not alter another lifespan or leak mocks when setup fails."""

from contextlib import ExitStack
from unittest.mock import create_autospec, patch

import pytest
from starlette.datastructures import State

import app.middleware.session as sessions
from app import main
from app.catalogue_runtime import replace_catalogue_sources
from app.routes import pages
from app.routes.auth import account
from app.services.cache import CatalogueStatsCache
from tests import fixtures
from tests.source_fixtures import fixture_source


def _collaborators() -> tuple[object, ...]:
    """Snapshot every global collaborator the client builder patches."""
    targets = (
        *((main, name) for name in fixtures._REAL_LIFESPAN_TARGETS),
        (sessions, "get_session_user"),
        (sessions, "consume_flash"),
        (account, "get_admin_promotion"),
        (pages, "get_source_statuses"),
    )
    return tuple(getattr(module, name) for module, name in targets)


@pytest.fixture
def prior_state(monkeypatch):
    """Keep each test's prior lifespan state separate from the surrounding suite."""
    state = State(main.app.state._state.copy())
    state.catalogue_stats_cache = None
    monkeypatch.setattr(main.app, "state", state)
    return state


def test_empty_selection_does_not_rebind_a_previous_real_cache(prior_state):
    """A stopped integration cache remains untouched by an empty unit selection."""
    policy = replace_catalogue_sources(main.app, (fixture_source(name="retained"),))
    prior_pool = fixtures.make_mock_pool()
    prior_cache = CatalogueStatsCache(
        prior_pool,
        source_names=("retained",),
        policy_fingerprint=policy.fingerprint,
        subscribe=False,
    )
    prior_cache.stop()
    prior_state.catalogue_stats_cache = prior_cache

    with ExitStack() as cleanup:
        client = fixtures.build_client(configured_sources=())
        cleanup.callback(fixtures.teardown_client, client)
        assert client.app.state is not prior_state
        assert client.app.state.configured_sources == ()
        assert client.app.state.catalogue_stats_cache is client.catalogue_stats_cache
        assert client.get("/login").status_code == 200

    assert main.app.state is prior_state
    assert main.app.state.catalogue_stats_cache is prior_cache
    assert main.app.state.catalogue_policy is policy
    prior_pool.connection.assert_not_called()
    prior_pool.close.assert_not_awaited()


@pytest.mark.parametrize("failure_stage", ("startup", "cookie"))
def test_failed_setup_closes_client_and_restores_state_and_collaborators(
    monkeypatch, prior_state, failure_stage
):
    """Failures before and after startup must leave the next client and autospec usable."""
    originals = _collaborators()
    clients = []
    real_client = fixtures.TestClient

    def capture_client(*args, **kwargs):
        """Retain the actual client to verify portal and lifespan cleanup."""
        client = real_client(*args, **kwargs)
        clients.append(client)
        return client

    with monkeypatch.context() as changes:
        changes.setattr(
            fixtures, "TestClient", create_autospec(real_client, side_effect=capture_client)
        )
        target = (
            "_publish_test_catalogue_sources" if failure_stage == "startup" else "csrf_token_for"
        )
        changes.setattr(
            fixtures,
            target,
            create_autospec(
                getattr(fixtures, target), side_effect=RuntimeError("forced setup failure")
            ),
        )
        with pytest.raises(RuntimeError, match="forced setup failure"):
            fixtures.build_client()

    assert main.app.state is prior_state
    assert all(
        actual is expected for actual, expected in zip(_collaborators(), originals, strict=True)
    )
    assert len(clients) == 1
    assert clients[0].portal is None
    assert clients[0].task.done()
    with patch("app.main.CatalogueStatsCache", autospec=True):
        pass
    with ExitStack() as cleanup:
        following = fixtures.build_client()
        cleanup.callback(fixtures.teardown_client, following)
        assert following.get("/login").status_code == 200
    assert main.app.state is prior_state


def test_nested_clients_restore_outer_resources_and_then_prior_state(prior_state):
    """Reverse teardown restores both the outer session and its catalogue resources."""
    originals = _collaborators()
    with ExitStack() as outer_cleanup:
        outer = fixtures.build_client(
            session_user=fixtures.make_sample_user(),
            configured_sources=(fixture_source(name="outer"),),
        )
        outer_cleanup.callback(fixtures.teardown_client, outer)
        outer_state = main.app.state
        with ExitStack() as inner_cleanup:
            inner = fixtures.build_client(configured_sources=(fixture_source(name="inner"),))
            inner_cleanup.callback(fixtures.teardown_client, inner)
            assert main.app.state is not outer_state
            assert main.app.state.db_pool is inner.mock_pool
            assert tuple(source.name for source in main.app.state.configured_sources) == ("inner",)
        assert main.app.state is outer_state
        assert main.app.state.db_pool is outer.mock_pool
        assert main.app.state.catalogue_stats_cache is outer.catalogue_stats_cache
        assert tuple(source.name for source in main.app.state.configured_sources) == ("outer",)
        assert outer.get("/account").status_code == 200
    assert main.app.state is prior_state
    assert all(
        actual is expected for actual, expected in zip(_collaborators(), originals, strict=True)
    )


def test_late_policy_undo_restores_its_owner_after_client_teardown(prior_state):
    """Fixture teardown order must not apply a closed client's policy to prior state."""
    prior_policy = replace_catalogue_sources(main.app, (fixture_source(name="prior"),))
    with ExitStack() as cleanup:
        client = fixtures.build_client(configured_sources=(fixture_source(name="original"),))
        cleanup.callback(fixtures.teardown_client, client)
        owned_state = main.app.state
        original_policy = owned_state.catalogue_policy
        with pytest.MonkeyPatch.context() as changes:
            fixtures.replace_test_catalogue_sources(
                changes, main.app, (fixture_source(name="replacement"),)
            )
            fixtures.teardown_client(client)
            assert main.app.state is prior_state
        assert main.app.state.catalogue_policy is prior_policy
        assert owned_state.catalogue_policy is original_policy
