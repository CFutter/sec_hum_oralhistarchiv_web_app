"""Persisted recovery, staged replay and ingestion-lock regressions."""

import asyncio
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import ingestion
from app.services.cache import CatalogueStatsCache
from app.services.db import get_db_cursor
from app.services.harvest import HarvestResult
from app.services.ingestion import _sync_source
from app.services.scheduler import rebuild_and_invalidate, sync_and_invalidate
from app.services.stored_harvest import encode_stored_harvest
from app.sources import ConfiguredSource
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, SourceCase, harvest_result, make_record
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record

REBUILD_SINCE = "1900-01-01"
WAIT_TIMEOUT = 15


def _state(conn, *, source: str):
    """Return last-harvest time, failure messages by UUID and sync error; commit the observer
    transaction.
    """
    row = conn.execute(
        "SELECT last_harvest_date, last_sync_error FROM sync_status WHERE source = %s",
        (source,),
    ).fetchone()
    failures = dict(
        conn.execute(
            "SELECT uuid, message FROM ingestion_failures WHERE source = %s",
            (source,),
        ).fetchall()
    )
    conn.commit()
    return (row[0], failures, row[1])


def _facet_cache_double():
    """Return a signature-checked catalogue-cache double."""
    return create_autospec(CatalogueStatsCache, instance=True, spec_set=True)


async def _fail_one(pool, *, configured_source: ConfiguredSource):
    """Sync a harvest containing one healthy and one uncertain record."""
    with patch(
        FETCH,
        autospec=True,
        return_value=harvest_result(
            [make_record("healthy")], uncertain_records={"broken": "invalid metadata"}
        ),
    ):
        await _sync_source(pool, configured_source=configured_source)


class TestIncrementalFailureRecovery(SourceCase):
    """Check incremental Failure Recovery."""

    async def test_failure_survives_empty_poll_and_repaired_record_releases_cursor(
        self,
        db_pool,
        sync_conn,
    ):
        """Verify failure survives empty poll and repaired record releases cursor."""
        original = _state(sync_conn, source=self.source.name)[0]
        await _fail_one(db_pool, configured_source=self.source)
        first = _state(sync_conn, source=self.source.name)
        assert first[0] == original
        assert "broken" in first[1]

        with patch(FETCH, autospec=True, return_value=harvest_result()) as fetch:
            await _sync_source(db_pool, configured_source=self.source)

        assert fetch.call_args is not None
        assert (
            fetch.call_args.kwargs["since"]
            == (SOURCE_CURSOR - timedelta(days=2)).date().isoformat()
        )
        assert _state(sync_conn, source=self.source.name) == first

        with patch(FETCH, autospec=True, return_value=harvest_result([make_record("broken")])):
            await _sync_source(db_pool, configured_source=self.source)

        resolved = _state(sync_conn, source=self.source.name)
        assert resolved[0] > original
        assert resolved[1:] == ({}, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 2

    async def test_successful_tombstone_resolves_failed_identity(self, db_pool, sync_conn):
        """Verify successful tombstone resolves failed identity."""
        await _fail_one(db_pool, configured_source=self.source)
        with patch(FETCH, autospec=True, return_value=harvest_result(deleted_uuids={"broken"})):
            await _sync_source(db_pool, configured_source=self.source)
        assert _state(sync_conn, source=self.source.name)[1:] == ({}, None)

    async def test_status_write_failure_does_not_advance_cursor(
        self,
        db_pool,
        sync_conn,
        monkeypatch,
    ):
        """Verify status write failure does not advance cursor."""
        original = _state(sync_conn, source=self.source.name)[0]
        real = ingestion._update_sync_timestamp

        async def fail_after_update(cur, started, *, source, source_cursor):
            """Perform the real status update, then raise to roll back its transaction."""
            await real(
                cur,
                started,
                source=source,
                source_cursor=source_cursor,
            )
            raise RuntimeError("status transaction failed")

        monkeypatch.setattr(
            ingestion,
            "_update_sync_timestamp",
            create_autospec(real, side_effect=fail_after_update),
        )
        with (
            patch(FETCH, autospec=True, return_value=harvest_result([make_record("healthy")])),
            pytest.raises(RuntimeError, match="status transaction failed"),
        ):
            await _sync_source(db_pool, configured_source=self.source)

        assert _state(sync_conn, source=self.source.name)[0] == original
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 1


class TestFullRebuildFailureRecovery(SourceCase):
    """Check full Rebuild Failure Recovery."""

    async def test_clean_full_rebuild_resolves_record_missing_upstream(self, db_pool, sync_conn):
        """Verify clean full rebuild resolves record missing upstream."""
        await _fail_one(db_pool, configured_source=self.source)
        before = _state(sync_conn, source=self.source.name)[0]
        with patch(FETCH, autospec=True, return_value=harvest_result([make_record("healthy")])):
            await ingestion._full_rebuild_source(db_pool, configured_source=self.source)
        after = _state(sync_conn, source=self.source.name)
        assert after[0] > before
        assert after[1:] == ({}, None)

    async def test_partial_rebuild_cannot_skip_its_failed_record(self, db_pool, sync_conn):
        """Verify partial rebuild cannot skip its failed record."""
        original = _state(sync_conn, source=self.source.name)[0]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("healthy")], uncertain_records={"broken": "invalid metadata"}
            ),
        ):
            await ingestion._full_rebuild_source(db_pool, configured_source=self.source)

        state = _state(sync_conn, source=self.source.name)
        assert state[0] == original
        assert "broken" in state[1]

        with patch(FETCH, autospec=True, return_value=harvest_result()):
            await _sync_source(db_pool, configured_source=self.source)

        after_empty = _state(sync_conn, source=self.source.name)
        assert after_empty[:2] == state[:2]
        assert "broken" in after_empty[2]


def _full_record(uuid: str) -> dict[str, Any]:
    """A complete parsed record so the stale rebuild really can reinsert X."""
    return {
        "uuid": uuid,
        "title": "Resurrection candidate",
        "project_title": None,
        "description": "Dataset that upstream deleted mid-rebuild.",
        "resource_description": None,
        "languages": ["en"],
        "project_description": None,
        "authors": ["Doe, Jane"],
        "keywords": [],
        "resource_proxies": [],
        "license_val": "Open Access",
        "license_url": None,
        "institutions": [],
        "version": "1.0.0",
        "doi": f"10.99999/{uuid}",
        "resource_type": "Audio",
        "main_disciplines": [],
        "bibliographical_citation": None,
        "upstream_modified_at": None,
    }


async def _poll_until(predicate, timeout: float = 10.0) -> None:
    """Poll until true or raise TimeoutError after the supplied seconds."""

    async def _loop():
        """Poll the predicate every 20 milliseconds until it succeeds."""
        while not predicate():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(_loop(), timeout)


def _uuid_exists(sync_conn, uuid: str) -> bool:
    """Check whether any catalogue row has this UUID."""
    row = sync_conn.execute(
        "SELECT 1 FROM oral_history_datasets WHERE uuid = %s", (uuid,)
    ).fetchone()
    return row is not None


class TestSyncMutexSerialization(SourceCase):
    """Check sync Mutex Serialization."""

    @pytest.fixture(autouse=True)
    def _fresh_sync_mutex(self, monkeypatch, sync_conn, sync_source):
        """Depend directly on sync_source rather than fixture execution order."""
        monkeypatch.setattr(ingestion, "_sync_mutex", asyncio.Lock())
        sync_conn.execute(
            "UPDATE sync_status SET source_cursor = '2026-01-01T00:00:00Z' WHERE source = %s",
            (sync_source.name,),
        )
        sync_conn.commit()

    async def test_tombstone_survives_concurrent_rebuild_with_stale_snapshot(
        self, db_pool, dataset_factory, sync_conn
    ):
        """The shared mutex orders a stale rebuild before the queued tombstone."""
        configured_source = self.source
        dataset_factory(source=self.source.name, uuid="X")
        assert _uuid_exists(sync_conn, "X"), "seed row must exist before the race"

        events: list[str] = []
        gate = threading.Event()
        x_present_at_tombstone_fetch: list[bool] = []

        def fake_fetch(*, since, **_kwargs):
            """Return the case's synthetic harvest and apply its test-controlled synchronization."""
            if since == REBUILD_SINCE:
                events.append("rebuild_fetch_start")
                gate.wait(timeout=10)
                return HarvestResult(
                    source_cursor=SOURCE_CURSOR, matching_records=[_full_record("X")]
                )
            with psycopg.connect(TEST_DATABASE_URL) as probe:
                x_present_at_tombstone_fetch.append(_uuid_exists(probe, "X"))
            events.append("sync_fetch_start")
            return HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"X"})

        facet_cache = _facet_cache_double()
        sync_task = None
        with patch(FETCH, autospec=True, side_effect=fake_fetch):
            rebuild_task = asyncio.create_task(
                rebuild_and_invalidate(db_pool, facet_cache, configured_source)
            )
            try:
                await _poll_until(lambda: "rebuild_fetch_start" in events)

                sync_task = asyncio.create_task(
                    sync_and_invalidate(db_pool, facet_cache, configured_source)
                )
                await _poll_until(
                    lambda: ingestion._sync_mutex.locked() and bool(ingestion._sync_mutex._waiters)
                )
                assert "sync_fetch_start" not in events, (
                    "incremental sync body started while the rebuild held (should "
                    "hold) _sync_mutex — the cross-job overlap guard is gone"
                )

                gate.set()
                await asyncio.wait_for(asyncio.gather(rebuild_task, sync_task), WAIT_TIMEOUT)
            finally:
                gate.set()
                pending = [t for t in (rebuild_task, sync_task) if t is not None]
                await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True), WAIT_TIMEOUT
                )

        assert not _uuid_exists(sync_conn, "X"), (
            "uuid X was resurrected: the rebuild's stale snapshot re-insert was "
            "not serialized against the incremental's tombstone DELETE"
        )
        assert events == ["rebuild_fetch_start", "sync_fetch_start"]

        # Prove the rebuild really reinserted X before the tombstone removed it.
        assert x_present_at_tombstone_fetch == [True], (
            "X was absent when the incremental's fetch ran: the rebuild never "
            "re-inserted it, so this test proved nothing about the mutex"
        )
        assert facet_cache.invalidate_cache.call_count == 2

    async def test_mutex_released_when_rebuild_fetch_fails(
        self, db_pool, dataset_factory, sync_conn
    ):
        """A failed rebuild releases the mutex and preserves its own diagnostic."""
        configured_source = self.source
        dataset_factory(source=self.source.name, uuid="X")
        sync_since_calls: list[str] = []

        def fake_fetch(*, since, **_kwargs):
            """Return the case's synthetic harvest and apply its test-controlled synchronization."""
            if since == REBUILD_SINCE:
                raise ConnectionError("upstream OAI endpoint down")
            sync_since_calls.append(since)
            return HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"X"})

        facet_cache = _facet_cache_double()
        with patch(FETCH, autospec=True, side_effect=fake_fetch):
            await asyncio.wait_for(
                rebuild_and_invalidate(db_pool, facet_cache, configured_source),
                WAIT_TIMEOUT,
            )

            assert not ingestion._sync_mutex.locked(), (
                "_sync_mutex still held after a failed rebuild — every future sync job would deadlock"
            )
            row = sync_conn.execute(
                "SELECT last_rebuild_error FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()
            assert row[0] is not None and "Full rebuild" in row[0]
            assert _uuid_exists(sync_conn, "X")

            # A non-NULL seed makes clearing the incremental error observable.
            sync_conn.execute(
                "UPDATE sync_status SET last_sync_error = %s, last_sync_error_at = now() "
                "WHERE source = %s",
                ("stale error from a previous incremental run", self.source.name),
            )
            sync_conn.commit()

            await asyncio.wait_for(
                sync_and_invalidate(db_pool, facet_cache, configured_source),
                WAIT_TIMEOUT,
            )

        assert len(sync_since_calls) == 1, "incremental fetch did not run after the failed rebuild"
        assert not _uuid_exists(sync_conn, "X"), "tombstone not processed by the follow-up sync"
        row = sync_conn.execute(
            "SELECT last_sync_error, last_rebuild_error FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone()
        assert row[0] is None, (
            "successful incremental should clear its own last_sync_error "
            "(seeded non-NULL above by this test, not just left at its initial NULL)"
        )
        assert row[1] is not None and "Full rebuild" in row[1], (
            "the earlier rebuild failure must survive a successful incremental — "
            "channels are isolated (ingestion.py _clear_sync_error is channel-scoped)"
        )
        assert facet_cache.invalidate_cache.call_count == 2


class TestCrossProcessLockRecovery(SourceCase):
    """Check cross Process Lock Recovery."""

    @pytest.mark.parametrize(
        "runner_name",
        ["incremental", "full_rebuild"],
        ids=["incremental", "full_rebuild"],
    )
    async def test_lost_lock_session_cannot_write_after_a_replacement_scheduler(
        self, db_pool, sync_conn, dataset_factory, monkeypatch, runner_name
    ):
        """A terminated lock-holder cannot overwrite a replacement holder's commit."""
        configured_source = self.source
        dataset_factory(source=self.source.name, uuid="existing")
        recovery_cursor = datetime(2030, 1, 1, tzinfo=UTC)
        runner = (
            ingestion._run_full_rebuild_on_locked_connection
            if runner_name == "full_rebuild"
            else ingestion._run_sync_on_locked_connection
        )

        with pytest.raises(psycopg.OperationalError):
            async with ingestion._cross_process_sync_lock(db_pool) as original_owner:

                async def fetch_after_lock_loss(*_args, **_kwargs):
                    """Terminate the lock owner and commit newer source state under a replacement
                    lock.
                    """
                    pid = original_owner.info.backend_pid
                    assert sync_conn.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[
                        0
                    ]
                    sync_conn.commit()
                    async with (
                        ingestion._cross_process_sync_lock(db_pool) as replacement,
                        get_db_cursor(replacement) as cur,
                    ):
                        await ingestion._upsert_public_catalogue_record(
                            cur,
                            parsed_record("newer-record"),
                            configured_source.policy,
                        )
                        await cur.execute(
                            "UPDATE sync_status SET source_cursor = %s WHERE source = %s",
                            (recovery_cursor, self.source.name),
                        )
                    return HarvestResult(
                        source_cursor=SOURCE_CURSOR,
                        matching_records=[parsed_record("stale-record")],
                    )

                original_threadpool = ingestion.run_source_fetch
                monkeypatch.setattr(
                    ingestion,
                    "run_source_fetch",
                    create_autospec(original_threadpool, side_effect=fetch_after_lock_loss),
                )
                await runner(original_owner, configured_source=configured_source)

        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets ORDER BY uuid"
        ).fetchall() == [
            ("existing",),
            ("newer-record",),
        ]
        assert (
            sync_conn.execute(
                "SELECT source_cursor FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()[0]
            == recovery_cursor
        )

    async def test_cancelled_sync_releases_the_session_lock_and_rolls_back(
        self, db_pool, sync_conn
    ):
        """Cancellation rolls back the open transaction and releases its lock."""
        entered = asyncio.Event()

        async def job():
            """Hold the cross-process sync lock with an uncommitted write until cancellation."""
            async with (
                ingestion._cross_process_sync_lock(db_pool) as connection,
                get_db_cursor(connection) as cur,
            ):
                await ingestion._upsert_public_catalogue_record(
                    cur, parsed_record("uncommitted"), self.source.policy
                )
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(job())
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with asyncio.timeout(5), ingestion._cross_process_sync_lock(db_pool) as connection:
            assert not connection.closed
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0


def _stage_decodable_harvest(
    conn: psycopg.Connection,
    harvest: HarvestResult,
    *,
    configured_source: ConfiguredSource,
    position: int,
    affected: int,
    started_at: datetime | None,
) -> bytes:
    """Stage valid encoded bytes with an explicit resumable-progress triple."""
    payload = encode_stored_harvest(
        harvest, source_fingerprint=configured_source.adapter.config_fingerprint()
    )
    conn.execute(
        """UPDATE sync_status
           SET incremental_harvest = %s, incremental_started_at = %s,
               incremental_position = %s, incremental_affected = %s
           WHERE source = %s""",
        (payload, started_at, position, affected, configured_source.name),
    )
    conn.commit()
    return payload


STAGED_AT = datetime(2026, 1, 5, tzinfo=UTC)


class TestFullRebuildRecoversAnUnreplayableStagedHarvest(SourceCase):
    """Check full Rebuild Recovers An Unreplayable Staged Harvest."""

    @pytest.mark.parametrize(
        ("position", "affected", "started_at"),
        [
            pytest.param(5, 0, STAGED_AT, id="position-past-the-work-list"),
        ],
    )
    async def test_an_unreplayable_staged_harvest_is_discarded_and_the_full_rebuild_still_commits(
        self, db_pool, sync_conn, position, affected, started_at
    ):
        """Verify an unreplayable staged harvest is discarded and the full rebuild still commits."""
        stale_harvest = harvest_result([_full_record("unreplayable")])
        _stage_decodable_harvest(
            sync_conn,
            stale_harvest,
            configured_source=self.source,
            position=position,
            affected=affected,
            started_at=started_at,
        )
        rebuild_t0 = datetime.now(UTC)

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("authoritative-1")])
        ):
            outcome = await ingestion._full_rebuild_source(db_pool, configured_source=self.source)

        assert outcome.status == "success"
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s",
                ("authoritative-1",),
            ).fetchone()[0]
            == 1
        )
        after = sync_conn.execute(
            """SELECT incremental_harvest, incremental_started_at, incremental_position,
                      incremental_affected, last_full_rebuild_date
               FROM sync_status WHERE source = %s""",
            (self.source.name,),
        ).fetchone()
        assert after[:4] == (None, None, 0, 0)
        assert after[4] is not None and after[4] >= rebuild_t0


class TestFullRebuildFetchFailureAfterReplayRecovery(SourceCase):
    """Check full Rebuild Fetch Failure After Replay Recovery."""

    async def test_the_authoritative_fetch_failing_after_replay_recovery_leaves_the_original_payload_for_a_later_retry(
        self, db_pool, sync_conn
    ):
        """A failed authoritative fetch leaves the original staged bytes available."""
        stale_harvest = harvest_result([_full_record("unreplayable-2")])
        original_payload = _stage_decodable_harvest(
            sync_conn,
            stale_harvest,
            configured_source=self.source,
            position=9,
            affected=0,
            started_at=STAGED_AT,
        )

        with patch(FETCH, autospec=True, side_effect=RuntimeError("upstream unreachable")):
            outcome = await ingestion._full_rebuild_source(db_pool, configured_source=self.source)

        assert outcome.status == "failed"
        after = sync_conn.execute(
            """SELECT incremental_harvest, incremental_started_at, incremental_position,
                      incremental_affected
               FROM sync_status WHERE source = %s""",
            (self.source.name,),
        ).fetchone()
        assert after == (original_payload, STAGED_AT, 9, 0)


class TestFullRebuildGuardedClearProtectsANewerStagedPayload(SourceCase):
    """Check full Rebuild Guarded Clear Protects ANewer Staged Payload."""

    async def test_a_payload_staged_concurrently_during_the_rebuild_survives_the_exact_payload_guarded_clear(
        self, db_pool, sync_conn, monkeypatch
    ):
        """Exact-payload clearing must preserve newer concurrently staged work."""
        stale_harvest = harvest_result([_full_record("unreplayable-3")])
        _stage_decodable_harvest(
            sync_conn,
            stale_harvest,
            configured_source=self.source,
            position=9,
            affected=0,
            started_at=STAGED_AT,
        )

        newer_payload = encode_stored_harvest(
            harvest_result([make_record("newer-process-work")]),
            source_fingerprint=self.source.adapter.config_fingerprint(),
        )
        real_reconcile = ingestion._reconcile_rebuild_records

        async def reconcile_then_stage_a_newer_payload(
            cur,
            records,
            *,
            policy,
            private_errors,
            audit=None,
            write_failures=None,
            harvest_started_at=None,
            source_cursor=None,
        ):
            """Reconcile the real harvest, then publish a newer staged payload from another
            connection.
            """
            result = await real_reconcile(
                cur,
                records,
                policy=policy,
                private_errors=private_errors,
                audit=audit,
                write_failures=write_failures,
                harvest_started_at=harvest_started_at,
                source_cursor=source_cursor,
            )
            with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as concurrent:
                concurrent.execute(
                    """UPDATE sync_status
                       SET incremental_harvest = %s, incremental_started_at = %s,
                           incremental_position = 0, incremental_affected = 0
                       WHERE source = %s""",
                    (newer_payload, STAGED_AT, self.source.name),
                )
            return result

        monkeypatch.setattr(
            ingestion,
            "_reconcile_rebuild_records",
            create_autospec(real_reconcile, side_effect=reconcile_then_stage_a_newer_payload),
        )

        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result([make_record("authoritative-2")]),
            ),
            pytest.raises(
                RuntimeError, match="staged harvest changed while held under the ingestion lock"
            ),
        ):
            await ingestion._full_rebuild_source(db_pool, configured_source=self.source)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            survivor = fresh.execute(
                "SELECT incremental_harvest FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()[0]
        assert bytes(survivor) == newer_payload


class TestValidStagedHarvestReplaysWithoutTriggeringAFullFetch(SourceCase):
    """Check valid Staged Harvest Replays Without Triggering AFull Fetch."""

    async def test_a_valid_staged_position_finalises_incrementally_without_ever_reaching_the_full_fetch_path(
        self, db_pool, sync_conn
    ):
        """Valid staged progress replays completely without another fetch."""
        good_harvest = harvest_result([_full_record("valid-replay")])
        _stage_decodable_harvest(
            sync_conn,
            good_harvest,
            configured_source=self.source,
            position=0,
            affected=0,
            started_at=STAGED_AT,
        )

        with patch(FETCH, autospec=True) as fetch:
            outcome = await _sync_source(db_pool, configured_source=self.source)

        fetch.assert_not_called()
        assert outcome.status == "success"
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("valid-replay",)
            ).fetchone()[0]
            == 1
        )
        after = sync_conn.execute(
            "SELECT incremental_harvest, incremental_position FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone()
        assert after == (None, 0)
