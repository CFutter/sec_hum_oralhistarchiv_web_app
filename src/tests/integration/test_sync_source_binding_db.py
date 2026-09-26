"""The catalogue's source-configuration fencing, against a real catalogue.

``sync_status.source_fingerprint`` binds the catalogue to the exact upstream
configuration (OAI-PMH URL and institution filter) that produced it
(``app.services.sync._source_a_fingerprint``, sync.py:206-211). An incremental
sync refuses to run against a catalogue bound to a DIFFERENT configuration
(sync.py:574-579); only an authoritative full rebuild may re-bind it. This
module drives that fence with a real committed catalogue, cursor and
fingerprint, and reconfigures the process (not the database) to simulate an
operator changing the upstream URL or institution filter between deploys.
"""

from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import sync
from app.services.cache import CatalogueStatsCache
from app.services.scheduler import sync_and_invalidate
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, harvest_result, make_record


def _facet_cache_double():
    """Autospecced ``CatalogueStatsCache`` instance double; every wrapper
    under test calls only ``invalidate_cache()`` on it."""
    return create_autospec(CatalogueStatsCache, instance=True, spec_set=True)


def _reconfigure_to_a_different_institution_filter(monkeypatch) -> None:
    """Change the running process's configuration so its computed source
    fingerprint no longer matches whatever ``clean_db`` seeded for the
    settings that were active at import time — modelling an operator
    changing the upstream institution filter without having re-run a full
    rebuild yet."""
    monkeypatch.setattr(
        settings,
        "oai_institution_filter",
        settings.oai_institution_filter + " (reconfigured)",
    )


class TestIncrementalFencedByAReconfiguredSource:
    async def test_incremental_makes_no_request_and_reports_a_typed_recovery_outcome(
        self, db_pool, sync_conn, dataset_factory, monkeypatch
    ):
        """A catalogue committed under configuration A, whose current
        process configuration has moved to B, refuses to run an incremental:
        no OAI request is made, no catalogue row is written, and the caller
        gets back a typed ``SyncOutcome(requires_full_rebuild=True)`` rather
        than an exception — the escalation signal a scheduler acts on."""
        dataset_factory(uuid="oai:x:bound-a", source="swissubase")
        old_cursor = sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone()[0]
        old_fingerprint = sync_conn.execute(
            "SELECT source_fingerprint FROM sync_status"
        ).fetchone()[0]

        _reconfigure_to_a_different_institution_filter(monkeypatch)

        with patch(FETCH, autospec=True) as fetch:
            outcome = await sync.run_sync(db_pool)

        fetch.assert_not_called()
        assert outcome == sync.SyncOutcome(
            "failed", reason="full rebuild required", requires_full_rebuild=True
        )
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("oai:x:bound-a",)
            ).fetchone()[0]
            == 1
        )
        after = sync_conn.execute(
            "SELECT source_cursor, source_fingerprint, last_sync_error FROM sync_status"
        ).fetchone()
        assert after[0] == old_cursor
        assert after[1] == old_fingerprint
        assert after[2] is not None and "full rebuild" in after[2]


class TestAuthoritativeRebuildUnderTheNewConfiguration:
    async def test_full_rebuild_commits_catalogue_cursor_fingerprint_and_both_error_channels_together(
        self, db_pool, sync_conn, monkeypatch
    ):
        """Positive control for the fence above: the SAME reconfigured
        process, running the authoritative full rebuild instead of an
        incremental, commits the new catalogue, advances the cursor, rebinds
        the fingerprint to the new configuration, and clears BOTH health
        channels together in the one committing transaction."""
        sync_conn.execute(
            "UPDATE sync_status SET last_sync_error = 'stale incremental error', "
            "last_rebuild_error = 'stale rebuild error' WHERE id = 1"
        )
        sync_conn.commit()

        _reconfigure_to_a_different_institution_filter(monkeypatch)
        new_fingerprint = sync._source_a_fingerprint()

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:bound-b")])
        ):
            outcome = await sync.run_full_rebuild(db_pool)

        assert outcome.status == "success"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert (
                fresh.execute(
                    "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s",
                    ("oai:x:bound-b",),
                ).fetchone()[0]
                == 1
            )
            after = fresh.execute(
                "SELECT source_cursor, source_fingerprint, last_sync_error, last_rebuild_error "
                "FROM sync_status"
            ).fetchone()
        assert after[0] is not None
        assert after[1] == new_fingerprint
        assert after[2] is None
        assert after[3] is None


class TestAFailedRebuildLeavesTheOldBindingFenced:
    @pytest.mark.parametrize(
        ("harvest_for_rebuild", "fetch_kwargs"),
        [
            pytest.param(
                None, {"side_effect": RuntimeError("upstream unreachable")}, id="fetch-error"
            ),
            pytest.param(harvest_result(), {}, id="zero-matching-records"),
            pytest.param(
                harvest_result([make_record("oai:x:new-only")]),
                {},
                id="contraction-guard-trip",
            ),
        ],
    )
    async def test_a_failed_rebuild_leaves_the_old_cursor_fingerprint_and_catalogue_and_still_fences_the_next_incremental(
        self, db_pool, sync_conn, dataset_factory, monkeypatch, harvest_for_rebuild, fetch_kwargs
    ):
        """Whichever way a full rebuild under the new configuration fails
        (a fetch error, an ambiguous zero-matching-record harvest, or the
        absence-based contraction guard tripping on a catalogue that looks
        truncated), the OLD cursor, fingerprint and catalogue survive
        untouched — and because the fingerprint never moved, the very next
        incremental attempt is STILL fenced exactly as before the rebuild
        was attempted."""
        dataset_factory(uuid="oai:x:bound-a", source="swissubase")
        old_cursor = sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone()[0]
        old_fingerprint = sync_conn.execute(
            "SELECT source_fingerprint FROM sync_status"
        ).fetchone()[0]

        _reconfigure_to_a_different_institution_filter(monkeypatch)

        patch_kwargs = dict(fetch_kwargs)
        if harvest_for_rebuild is not None:
            patch_kwargs["return_value"] = harvest_for_rebuild
        with patch(FETCH, autospec=True, **patch_kwargs):
            rebuild_outcome = await sync.run_full_rebuild(db_pool)

        assert rebuild_outcome.status == "failed"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert fresh.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase'"
            ).fetchall() == [("oai:x:bound-a",)]
            after_rebuild = fresh.execute(
                "SELECT source_cursor, source_fingerprint FROM sync_status"
            ).fetchone()
        assert after_rebuild == (old_cursor, old_fingerprint)

        with patch(FETCH, autospec=True) as fetch:
            incremental_outcome = await sync.run_sync(db_pool)

        fetch.assert_not_called()
        assert incremental_outcome == sync.SyncOutcome(
            "failed", reason="full rebuild required", requires_full_rebuild=True
        )


class TestFreshCatalogueEscalatesItsFirstTickStraightToARebuild:
    @pytest.mark.usefixtures("unbound_catalogue")
    async def test_the_first_scheduler_tick_against_an_unbound_catalogue_runs_the_rebuild_fetch_before_any_incremental_request(
        self, db_pool, sync_conn
    ):
        """A fresh (never rebuilt) schema has no committed fingerprint at
        all. The very first scheduled tick, ``sync_and_invalidate``, must
        escalate to ``run_full_rebuild`` before any incremental OAI request
        is attempted — the isolated fetch is called exactly once, and with
        the rebuild's unbounded ``since``, never with an incremental
        watermark-derived one."""
        facet_cache = _facet_cache_double()

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:first-bind")])
        ) as fetch:
            outcome = await sync_and_invalidate(db_pool, facet_cache)

        assert outcome.status == "success"
        fetch.assert_called_once()
        assert fetch.call_args.kwargs["since"] == "1900-01-01"
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("oai:x:first-bind",)
            ).fetchone()[0]
            == 1
        )
        assert (
            sync_conn.execute("SELECT source_fingerprint FROM sync_status").fetchone()[0]
            == sync._source_a_fingerprint()
        )
        facet_cache.invalidate_cache.assert_called_once()
