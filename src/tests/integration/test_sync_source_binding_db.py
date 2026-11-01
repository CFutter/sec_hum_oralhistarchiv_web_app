"""Source-configuration fencing against a real committed catalogue."""

from collections.abc import Callable
from typing import Any
from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import ingestion
from app.services.cache import CatalogueStatsCache
from app.services.scheduler import sync_and_invalidate
from app.sources import ConfiguredSource
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, SourceCase, harvest_result, make_record
from tests.source_fixtures import fixture_source, legacy_source


def _facet_cache_double():
    """Return a signature-checked catalogue-cache double."""
    return create_autospec(CatalogueStatsCache, instance=True, spec_set=True)


def _fetch_target(source: ConfiguredSource) -> str:
    """Select the fixture or OAI fetch patch target for this adapter."""
    return (
        "app.sources.fixture.FixtureAdapter.fetch" if source.config.adapter == "fixture" else FETCH
    )


def _approve_rebinding(conn, source: ConfiguredSource) -> None:
    """Explicit owner approval lets these tests exercise the later rebuild phase."""
    previous = conn.execute(
        "SELECT COALESCE(source_fetch_fingerprint, source_fingerprint) "
        "FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO source_binding_acknowledgements "
        "(source, previous_fingerprint, source_fingerprint) VALUES (%s, %s, %s)",
        (source.name, previous, source.adapter.config_fingerprint()),
    )
    conn.commit()


@pytest.fixture(params=["institution_filter", "max_visibility", "requires_record_tier"])
def reconfigure_source(
    request: pytest.FixtureRequest,
    sync_conn: psycopg.Connection[tuple[Any, ...]],
    sync_source: ConfiguredSource,
) -> Callable[[], ConfiguredSource]:
    """Bind one configuration and construct a changed successor for the same source."""
    build = fixture_source if request.param == "requires_record_tier" else legacy_source
    baseline = build(name=sync_source.name, max_visibility="public", requires_record_tier=False)
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (baseline.adapter.config_fingerprint(), baseline.name),
    )
    sync_conn.commit()

    def reconfigure() -> ConfiguredSource:
        """Build the parametrized changed source configuration and update test selection."""
        changes: dict[str, object] = {
            "name": sync_source.name,
            "max_visibility": "public",
            "requires_record_tier": False,
        }
        if request.param == "institution_filter":
            changes["institution_filter"] = (
                baseline.config.model_dump()["institution_filter"] + " (reconfigured)"
            )
        elif request.param == "max_visibility":
            changes["max_visibility"] = "registered"
        else:
            changes["requires_record_tier"] = True
        configured_source = build(**changes)
        assert configured_source.name == baseline.name
        assert (
            configured_source.adapter.config_fingerprint() != baseline.adapter.config_fingerprint()
        )
        return configured_source

    return reconfigure


class TestIncrementalFencedByAReconfiguredSource(SourceCase):
    """Check incremental Fenced By AReconfigured Source."""

    async def test_incremental_makes_no_request_and_reports_a_typed_recovery_outcome(
        self, db_pool, sync_conn, dataset_factory, reconfigure_source
    ):
        """Verify incremental makes no request and reports a typed recovery outcome."""
        configured_source = reconfigure_source()
        dataset_factory(uuid="oai:x:bound-a", source=configured_source.name)
        old_cursor = sync_conn.execute(
            "SELECT source_cursor FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone()[0]
        old_fingerprint = sync_conn.execute(
            "SELECT source_fingerprint FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone()[0]

        with patch(_fetch_target(configured_source), autospec=True) as fetch:
            outcome = await ingestion.run_sync(db_pool, configured_source=configured_source)

        fetch.assert_not_called()
        assert outcome == ingestion.SyncOutcome(
            "failed",
            reason="source configuration acknowledgement required",
            requires_source_acknowledgement=True,
        )
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE source = %s AND uuid = %s",
                (configured_source.name, "oai:x:bound-a"),
            ).fetchone()[0]
            == 1
        )
        after = sync_conn.execute(
            "SELECT source_cursor, source_fingerprint, last_sync_error "
            "FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone()
        assert after[0] == old_cursor
        assert after[1] == old_fingerprint
        assert after[2] is not None and "full rebuild" in after[2]


class TestAuthoritativeRebuildUnderTheNewConfiguration(SourceCase):
    """Check authoritative Rebuild Under The New Configuration."""

    async def test_full_rebuild_commits_catalogue_cursor_fingerprint_and_both_error_channels_together(
        self, db_pool, sync_conn, reconfigure_source
    ):
        """Verify full rebuild commits catalogue cursor fingerprint and both error channels
        together.
        """
        configured_source = reconfigure_source()
        _approve_rebinding(sync_conn, configured_source)
        sync_conn.execute(
            "UPDATE sync_status SET last_sync_error = 'stale incremental error', "
            "last_rebuild_error = 'stale rebuild error' WHERE source = %s",
            (configured_source.name,),
        )
        sync_conn.commit()
        new_fingerprint = configured_source.adapter.config_fingerprint()

        with patch(
            _fetch_target(configured_source),
            autospec=True,
            return_value=harvest_result([make_record("oai:x:bound-b", visibility_tier="public")]),
        ):
            outcome = await ingestion.run_full_rebuild(
                db_pool,
                configured_source=configured_source,
            )

        assert outcome.status == "success"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert (
                fresh.execute(
                    "SELECT count(*) FROM oral_history_datasets WHERE source = %s AND uuid = %s",
                    (configured_source.name, "oai:x:bound-b"),
                ).fetchone()[0]
                == 1
            )
            assert (
                fresh.execute(
                    "SELECT visibility_tier FROM oral_history_datasets "
                    "WHERE source = %s AND uuid = %s",
                    (configured_source.name, "oai:x:bound-b"),
                ).fetchone()[0]
                == configured_source.policy.max_visibility
            )
            after = fresh.execute(
                "SELECT source_cursor, source_fingerprint, last_sync_error, last_rebuild_error "
                "FROM sync_status WHERE source = %s",
                (configured_source.name,),
            ).fetchone()
        assert after[0] is not None
        assert after[1] == new_fingerprint
        assert after[2] is None
        assert after[3] is None


class TestAFailedRebuildLeavesTheOldBindingFenced(SourceCase):
    """Check aFailed Rebuild Leaves The Old Binding Fenced."""

    @pytest.mark.parametrize(
        ("harvest_for_rebuild", "fetch_kwargs"),
        [
            pytest.param(
                None, {"side_effect": RuntimeError("upstream unreachable")}, id="fetch-error"
            ),
            pytest.param(harvest_result(), {}, id="zero-matching-records"),
            pytest.param(
                harvest_result([make_record("oai:x:new-only", visibility_tier="public")]),
                {},
                id="contraction-guard-trip",
            ),
        ],
    )
    async def test_a_failed_rebuild_leaves_the_old_cursor_fingerprint_and_catalogue_and_still_fences_the_next_incremental(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
        reconfigure_source,
        harvest_for_rebuild,
        fetch_kwargs,
    ):
        """Verify a failed rebuild leaves the old cursor fingerprint and catalogue and still fences
        the next incremental.
        """
        configured_source = reconfigure_source()
        _approve_rebinding(sync_conn, configured_source)
        dataset_factory(uuid="oai:x:bound-a", source=configured_source.name)
        old_cursor = sync_conn.execute(
            "SELECT source_cursor FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone()[0]
        old_fingerprint = sync_conn.execute(
            "SELECT source_fingerprint FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone()[0]

        patch_kwargs = dict(fetch_kwargs)
        if harvest_for_rebuild is not None:
            patch_kwargs["return_value"] = harvest_for_rebuild
        with patch(_fetch_target(configured_source), autospec=True, **patch_kwargs):
            rebuild_outcome = await ingestion.run_full_rebuild(
                db_pool,
                configured_source=configured_source,
            )

        assert rebuild_outcome.status == "failed"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert fresh.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = %s",
                (configured_source.name,),
            ).fetchall() == [("oai:x:bound-a",)]
            after_rebuild = fresh.execute(
                "SELECT source_cursor, source_fingerprint FROM sync_status WHERE source = %s",
                (configured_source.name,),
            ).fetchone()
        assert after_rebuild == (old_cursor, old_fingerprint)

        with patch(_fetch_target(configured_source), autospec=True) as fetch:
            incremental_outcome = await ingestion.run_sync(
                db_pool,
                configured_source=configured_source,
            )

        fetch.assert_not_called()
        assert incremental_outcome == ingestion.SyncOutcome(
            "failed", reason="full rebuild required", requires_full_rebuild=True
        )


class TestFreshCatalogueEscalatesItsFirstTickStraightToARebuild(SourceCase):
    """Check fresh Catalogue Escalates Its First Tick Straight To ARebuild."""

    async def test_the_first_scheduler_tick_against_an_unbound_catalogue_runs_the_rebuild_fetch_before_any_incremental_request(
        self, db_pool, sync_conn
    ):
        """Verify the first scheduler tick against an unbound catalogue runs the rebuild fetch
        before any incremental request.
        """
        configured_source = self.source
        sync_conn.execute(
            "UPDATE sync_status SET source_fingerprint = NULL WHERE source = %s",
            (configured_source.name,),
        )
        sync_conn.commit()
        facet_cache = _facet_cache_double()

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:first-bind")])
        ) as fetch:
            outcome = await sync_and_invalidate(db_pool, facet_cache, configured_source)

        assert outcome.status == "success"
        fetch.assert_called_once()
        assert fetch.call_args.kwargs["since"] == "1900-01-01"
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE source = %s AND uuid = %s",
                (configured_source.name, "oai:x:first-bind"),
            ).fetchone()[0]
            == 1
        )
        assert (
            sync_conn.execute(
                "SELECT source_fingerprint FROM sync_status WHERE source = %s",
                (configured_source.name,),
            ).fetchone()[0]
            == configured_source.adapter.config_fingerprint()
        )
        facet_cache.invalidate_cache.assert_called_once()
