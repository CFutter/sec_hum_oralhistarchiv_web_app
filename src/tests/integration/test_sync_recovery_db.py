"""Recovery of an interrupted sync, and the cross-job mutex that protects it.

Real PostgreSQL persistence and replay across separate runs prove that a
failed record's cursor stays pinned until it is repaired, and that the
shared ``app.services.sync._sync_mutex`` serializes an incremental sync
against a concurrent full rebuild so that a deletion tombstone can never be
resurrected by a stale rebuild snapshot.
"""

import asyncio
import threading
from datetime import UTC, datetime
from typing import Any
from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import sync
from app.services.cache import CatalogueStatsCache
from app.services.db import get_db_cursor
from app.services.oai_client import HarvestResult
from app.services.scheduler import rebuild_and_invalidate, sync_and_invalidate
from app.services.stored_harvest import encode_stored_harvest
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, harvest_result, make_record
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record

# _full_rebuild_source_a always harvests from the epoch-of-everything; the
# incremental computes `since` from sync_status.last_harvest_date (which is
# never 1900). This is how the patched fetch tells the two callers apart.
REBUILD_SINCE = "1900-01-01"

# Generous ceilings so a deadlock (e.g. the lock becomes non-reentrant in a
# way that self-blocks, or a gate never opens) FAILS the test instead of
# hanging CI. Actual happy-path runtime is well under a second per await.
WAIT_TIMEOUT = 15


def _state(conn):
    """(last_harvest_date, {uuid: message} unresolved failures, last_sync_error).

    Unresolved identities live in ``ingestion_failures`` (source, uuid, message,
    updated_at) — ``sync_status.incremental_failures`` is never written by
    production (sync.py:360-503) — so the failure set is read from that table,
    scoped to the Source A policy name used throughout this module.
    """
    row = conn.execute(
        "SELECT last_harvest_date, last_sync_error FROM sync_status WHERE id = 1"
    ).fetchone()
    failures = dict(
        conn.execute(
            "SELECT uuid, message FROM ingestion_failures WHERE source = 'swissubase'"
        ).fetchall()
    )
    conn.commit()
    return (row[0], failures, row[1])


def _facet_cache_double():
    """Autospecced CatalogueStatsCache instance double.

    Every wrapper under test calls only ``invalidate_cache()`` on this
    collaborator; autospeccing against the real class catches a rename or
    signature change instead of accepting any call shape silently.
    """
    return create_autospec(CatalogueStatsCache, instance=True, spec_set=True)


async def _fail_one(pool):
    # Structurally invalid source metadata is classified before the worker seam.
    with patch(
        FETCH,
        autospec=True,
        return_value=harvest_result(
            [make_record("healthy")], uncertain_records={"broken": "invalid metadata"}
        ),
    ):
        await sync._sync_source_a(pool)


class TestIncrementalFailureRecovery:
    """A failed record's cursor stays pinned across empty polls and clears on repair."""

    async def test_failure_survives_empty_poll_and_repaired_record_releases_cursor(
        self,
        db_pool,
        sync_conn,
    ):
        original = _state(sync_conn)[0]
        await _fail_one(db_pool)
        first = _state(sync_conn)
        assert first[0] == original
        assert "broken" in first[1]

        with patch(FETCH, autospec=True, return_value=harvest_result()) as fetch:
            await sync._sync_source_a(db_pool)

        assert fetch.call_args.kwargs["since"] == "1900-01-01"
        assert _state(sync_conn) == first

        with patch(FETCH, autospec=True, return_value=harvest_result([make_record("broken")])):
            await sync._sync_source_a(db_pool)

        resolved = _state(sync_conn)
        assert resolved[0] > original
        assert resolved[1:] == ({}, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 2

    async def test_successful_tombstone_resolves_failed_identity(self, db_pool, sync_conn):
        await _fail_one(db_pool)
        with patch(FETCH, autospec=True, return_value=harvest_result(deleted_uuids={"broken"})):
            await sync._sync_source_a(db_pool)
        assert _state(sync_conn)[1:] == ({}, None)

    async def test_status_write_failure_does_not_advance_cursor(
        self,
        db_pool,
        sync_conn,
        monkeypatch,
    ):
        original = _state(sync_conn)[0]
        real = sync._update_sync_timestamp

        async def fail_after_update(cur, started, *, source_cursor):
            await real(cur, started, source_cursor=source_cursor)
            raise RuntimeError("status transaction failed")

        monkeypatch.setattr(sync, "_update_sync_timestamp", fail_after_update)
        with (
            patch(FETCH, autospec=True, return_value=harvest_result([make_record("healthy")])),
            pytest.raises(RuntimeError, match="status transaction failed"),
        ):
            await sync._sync_source_a(db_pool)

        assert _state(sync_conn)[0] == original
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 1


class TestFullRebuildFailureRecovery:
    """A full rebuild resolves failures the same way an incremental sync does."""

    async def test_clean_full_rebuild_resolves_record_missing_upstream(self, db_pool, sync_conn):
        await _fail_one(db_pool)
        before = _state(sync_conn)[0]
        with patch(FETCH, autospec=True, return_value=harvest_result([make_record("healthy")])):
            await sync._full_rebuild_source_a(db_pool)
        after = _state(sync_conn)
        assert after[0] > before
        assert after[1:] == ({}, None)

    async def test_partial_rebuild_cannot_skip_its_failed_record(self, db_pool, sync_conn):
        original = _state(sync_conn)[0]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("healthy")], uncertain_records={"broken": "invalid metadata"}
            ),
        ):
            await sync._full_rebuild_source_a(db_pool)

        state = _state(sync_conn)
        assert state[0] == original
        assert "broken" in state[1]

        with patch(FETCH, autospec=True, return_value=harvest_result()):
            await sync._sync_source_a(db_pool)

        after_empty = _state(sync_conn)
        assert after_empty[:2] == state[:2]
        assert "broken" in after_empty[2]


def _full_record(uuid: str) -> dict[str, Any]:
    """A record satisfying the parser contract (PARSER_OWNED key presence).

    build_record_params raises KeyError if any _parse_cmdi_to_dict-emitted
    key is missing, so the rebuild's re-insert of X only exercises the real
    upsert path if every parser-owned key is present (values may be None/[]).
    """
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
    """Await a wall-clock condition set from a threadpool thread."""

    async def _loop():
        while not predicate():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(_loop(), timeout)


def _uuid_exists(sync_conn, uuid: str) -> bool:
    row = sync_conn.execute(
        "SELECT 1 FROM oral_history_datasets WHERE uuid = %s", (uuid,)
    ).fetchone()
    return row is not None


class TestSyncMutexSerialization:
    """``app.services.sync._sync_mutex`` serializes a rebuild against an incremental.

    An incremental sync carrying uuid X's deletion tombstone fires while a
    full rebuild — whose harvest snapshot still CONTAINS X — is mid-flight.
    With the shared lock the two jobs serialize and X stays deleted; without
    it the rebuild would re-insert X from its stale snapshot and resurrect
    the deleted record until the next rebuild.

    Why nothing else covers this:
    - ``ON CONFLICT (source, uuid) DO UPDATE`` cannot fix it — the upsert
      arbitrates insert-vs-insert collisions, not insert-vs-delete ordering:
      the rebuild's INSERT of X after the incremental's DELETE simply
      succeeds.
    - APScheduler's ``max_instances=1`` only guards each job against ITSELF
      (incremental-vs-incremental, rebuild-vs-rebuild); the shared
      ``asyncio.Lock`` is the only cross-job guard.

    ``run_sync``/``run_full_rebuild`` (app.services.sync) reference the
    module global ``_sync_mutex`` at call time, so patching it per test both
    isolates tests (a fresh Lock can't stay bound to a previous test's event
    loop) and — because ``monkeypatch.setattr`` raises if the attribute
    vanishes — fails loudly if the lock is ever removed. The scheduler
    wrappers under test (``sync_and_invalidate``/``rebuild_and_invalidate``)
    call straight through to those two functions without touching the mutex
    themselves.
    """

    @pytest.fixture(autouse=True)
    def _fresh_sync_mutex(self, monkeypatch, sync_conn):
        """Fresh lock per test: same object the code uses, no cross-loop binding."""
        monkeypatch.setattr(sync, "_sync_mutex", asyncio.Lock())
        sync_conn.execute("UPDATE sync_status SET source_cursor = '2026-01-01T00:00:00Z'")
        sync_conn.commit()

    async def test_tombstone_survives_concurrent_rebuild_with_stale_snapshot(
        self, db_pool, dataset_factory, sync_conn
    ):
        """Deleted stays deleted when a rebuild's stale snapshot still has the row.

        Timeline forced here: rebuild acquires _sync_mutex and blocks inside
        its (threadpool-offloaded) fetch, snapshot containing X already
        decided; an incremental carrying X's deletion tombstone fires. The
        outcome under test is the mid-flight assert that the incremental's
        sync body has NOT begun — if `async with _sync_mutex` were removed
        from either wrapper, the incremental's fetch would run while the
        rebuild is mid-flight, that assert would fail, and the rebuild's
        stale snapshot would re-insert X after the tombstone's DELETE,
        resurrecting a deleted record until the next rebuild.
        """
        dataset_factory(source="swissubase", uuid="X")
        assert _uuid_exists(sync_conn, "X"), "seed row must exist before the race"

        events: list[str] = []  # appended from threadpool threads
        gate = threading.Event()  # holds the rebuild's fetch mid-flight
        # Non-vacuity guard: _full_rebuild_source_a's per-record upsert
        # swallows exceptions into last_rebuild_error (the "rebuild" channel
        # — sync.py's _SYNC_ERROR_COLUMNS), so a broken _full_record (e.g.
        # PARSER_OWNED drift) would mean X is never re-inserted and the
        # final "X is gone" assert would pass WITHOUT the mutex doing
        # anything. The incremental's fetch runs strictly after the rebuild
        # finishes (that is the serialization under test), so X must be
        # PRESENT at that moment — proving the resurrection actually
        # happened before the tombstone undid it.
        x_present_at_tombstone_fetch: list[bool] = []

        def fake_fetch(*, since, **_kwargs):
            if since == REBUILD_SINCE:
                events.append("rebuild_fetch_start")
                gate.wait(timeout=10)
                return HarvestResult(
                    source_cursor=SOURCE_CURSOR, matching_records=[_full_record("X")]
                )  # the STALE snapshot: still contains X
            with psycopg.connect(TEST_DATABASE_URL) as probe:
                x_present_at_tombstone_fetch.append(_uuid_exists(probe, "X"))
            events.append("sync_fetch_start")
            return HarvestResult(
                source_cursor=SOURCE_CURSOR, deleted_uuids={"X"}
            )  # X's deletion tombstone

        facet_cache = _facet_cache_double()
        sync_task = None
        with patch("app.services.sync.fetch_updates_isolated", new=fake_fetch):
            rebuild_task = asyncio.create_task(rebuild_and_invalidate(db_pool, facet_cache))
            try:
                # Rebuild is now mid-flight: mutex held, fetch parked on the gate.
                await _poll_until(lambda: "rebuild_fetch_start" in events)

                sync_task = asyncio.create_task(sync_and_invalidate(db_pool, facet_cache))
                # Observe the blocked state instead of sleeping-then-asserting:
                # wait until the incremental task is actually parked waiting to
                # acquire the shared _sync_mutex (locked by the rebuild, and a
                # waiter queued behind it) before checking that its sync body
                # has not started. A waiter can only be queued before the lock
                # is granted, so this is a deterministic proof, not a timing
                # guess.
                await _poll_until(
                    lambda: sync._sync_mutex.locked() and bool(sync._sync_mutex._waiters)
                )
                # The outcome under test: the incremental's sync body
                # (watermark read + fetch) must not have begun — it is
                # blocked on _sync_mutex.
                assert "sync_fetch_start" not in events, (
                    "incremental sync body started while the rebuild held (should "
                    "hold) _sync_mutex — the cross-job overlap guard is gone"
                )

                gate.set()
                await asyncio.wait_for(asyncio.gather(rebuild_task, sync_task), WAIT_TIMEOUT)
            finally:
                # On any failure above: open the gate and drain both tasks so no
                # background task outlives the test's event loop.
                gate.set()
                pending = [t for t in (rebuild_task, sync_task) if t is not None]
                await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True), WAIT_TIMEOUT
                )

        # Serialized outcome: rebuild deleted+re-inserted X from its stale
        # snapshot, THEN the incremental processed the tombstone. Deleted stays
        # deleted. (Resurrection would leave the X row present here.)
        assert not _uuid_exists(sync_conn, "X"), (
            "uuid X was resurrected: the rebuild's stale snapshot re-insert was "
            "not serialized against the incremental's tombstone DELETE"
        )

        # Wall order proves both bodies ran, rebuild strictly first.
        assert events == ["rebuild_fetch_start", "sync_fetch_start"]

        # The rebuild really did re-insert X from its stale snapshot before the
        # tombstone deleted it — without this, a rebuild whose upsert failed
        # silently (swallowed into last_rebuild_error, only cleared by a later
        # successful rebuild — never by the incremental, a different channel)
        # would fake the "deleted stays deleted" outcome.
        assert x_present_at_tombstone_fetch == [True], (
            "X was absent when the incremental's fetch ran: the rebuild never "
            "re-inserted it, so this test proved nothing about the mutex"
        )

        # Each wrapper still invalidates the facet cache exactly once (outside
        # the lock — invalidation itself is not what the mutex serializes).
        assert facet_cache.invalidate_cache.call_count == 2

    async def test_mutex_released_when_rebuild_fetch_fails(
        self, db_pool, dataset_factory, sync_conn
    ):
        """A failing rebuild must not wedge the shared lock.

        _full_rebuild_source_a swallows fetch exceptions (records them in
        sync_status.last_rebuild_error — the "rebuild" channel, distinct from
        the incremental's last_sync_error, per sync.py's _SYNC_ERROR_COLUMNS —
        and returns), and `async with _sync_mutex` releases on any exit path.
        A lock held past a failed rebuild would silently starve EVERY future
        sync job (no more incremental syncs, no more rebuilds) until process
        restart. This also pins channel isolation end-to-end through the
        scheduler wrappers: the follow-up incremental's success clears only
        its own (last_sync_error) channel and must never erase the
        still-relevant rebuild error.
        """
        dataset_factory(source="swissubase", uuid="X")
        sync_since_calls: list[str] = []

        def fake_fetch(*, since, **_kwargs):
            if since == REBUILD_SINCE:
                raise ConnectionError("upstream OAI endpoint down")

            sync_since_calls.append(since)
            return HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"X"})

        facet_cache = _facet_cache_double()
        with patch("app.services.sync.fetch_updates_isolated", new=fake_fetch):
            # Rebuild completes despite the fetch error (error recorded, no raise).
            await asyncio.wait_for(rebuild_and_invalidate(db_pool, facet_cache), WAIT_TIMEOUT)

            assert not sync._sync_mutex.locked(), (
                "_sync_mutex still held after a failed rebuild — every future sync job would deadlock"
            )
            # The failure lands on the REBUILD channel (last_rebuild_error), not
            # last_sync_error — see sync.py's _SYNC_ERROR_COLUMNS channel split.
            row = sync_conn.execute(
                "SELECT last_rebuild_error FROM sync_status WHERE id = 1"
            ).fetchone()
            assert row[0] is not None and "Full rebuild" in row[0]
            # Fetch failed before any write: existing data untouched.
            assert _uuid_exists(sync_conn, "X")

            # Positive control: seed last_sync_error with a stale value before the
            # follow-up run. clean_db (conftest) inserts sync_status with every
            # error column NULL, so without this seed the assertion below
            # ("last_sync_error is None") would pass identically even if
            # _clear_sync_error(channel="incremental") were deleted from sync.py —
            # the column would just never have moved off its initial NULL.
            sync_conn.execute(
                "UPDATE sync_status SET last_sync_error = %s, last_sync_error_at = now() WHERE id = 1",
                ("stale error from a previous incremental run",),
            )
            sync_conn.commit()

            # A following incremental acquires the lock and runs its full body:
            # fetches and processes X's tombstone. It clears only its OWN
            # (last_sync_error) channel — the rebuild error just recorded is a
            # different column and must survive this run untouched.
            await asyncio.wait_for(sync_and_invalidate(db_pool, facet_cache), WAIT_TIMEOUT)

        assert len(sync_since_calls) == 1, "incremental fetch did not run after the failed rebuild"
        assert not _uuid_exists(sync_conn, "X"), "tombstone not processed by the follow-up sync"
        row = sync_conn.execute(
            "SELECT last_sync_error, last_rebuild_error FROM sync_status WHERE id = 1"
        ).fetchone()
        assert row[0] is None, (
            "successful incremental should clear its own last_sync_error "
            "(seeded non-NULL above by this test, not just left at its initial NULL)"
        )
        assert row[1] is not None and "Full rebuild" in row[1], (
            "the earlier rebuild failure must survive a successful incremental — "
            "channels are isolated (sync.py _clear_sync_error is channel-scoped)"
        )
        assert facet_cache.invalidate_cache.call_count == 2


class TestCrossProcessLockRecovery:
    """The advisory-lock guard (``sync._cross_process_sync_lock``) around the
    connection-level sync/rebuild entry points: a session that loses the
    lock is fenced off from writing, and a cancelled run leaves neither an
    uncommitted row nor a wedged lock behind.
    """

    @pytest.mark.parametrize(
        "runner_name",
        ["incremental", "full_rebuild"],
        ids=["incremental", "full_rebuild"],
    )
    async def test_lost_lock_session_cannot_write_after_a_replacement_scheduler(
        self, db_pool, sync_conn, dataset_factory, monkeypatch, runner_name
    ):
        """A session whose PostgreSQL backend is terminated after it has
        already acquired the advisory lock must not go on to write: the
        write phase surfaces the connection loss as a psycopg.OperationalError,
        and the row a REPLACEMENT lock-holder committed while the original
        session was down is what survives — not anything from the harvest
        the original session was mid-fetch of."""
        dataset_factory(source="swissubase", uuid="existing")
        recovery_cursor = datetime(2030, 1, 1, tzinfo=UTC)
        # The connection-level entry points, not run_sync/run_full_rebuild
        # (which now acquire the lock themselves): this test already owns
        # the lock (via `original_owner` below) and drives the write phase
        # directly.
        runner = (
            sync._run_full_rebuild_on_locked_connection
            if runner_name == "full_rebuild"
            else sync._run_sync_on_locked_connection
        )

        # Calling the cross-process guard directly models a second process
        # with its own local mutex. Both jobs still use real PostgreSQL
        # advisory locks.
        with pytest.raises(psycopg.OperationalError):
            async with sync._cross_process_sync_lock(db_pool) as original_owner:

                async def fetch_after_lock_loss(*_args, **_kwargs):
                    pid = original_owner.info.backend_pid
                    assert sync_conn.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[
                        0
                    ]
                    sync_conn.commit()
                    async with (
                        sync._cross_process_sync_lock(db_pool) as replacement,
                        get_db_cursor(replacement) as cur,
                    ):
                        await sync._upsert_public_catalogue_record(
                            cur, parsed_record("newer-record"), sync._SWISSUBASE_POLICY
                        )
                        await cur.execute(
                            "UPDATE sync_status SET source_cursor = %s", (recovery_cursor,)
                        )
                    return HarvestResult(
                        source_cursor=SOURCE_CURSOR,
                        matching_records=[parsed_record("stale-record")],
                    )

                monkeypatch.setattr(sync, "run_in_threadpool", fetch_after_lock_loss)
                await runner(original_owner)

        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets ORDER BY uuid"
        ).fetchall() == [
            ("existing",),
            ("newer-record",),
        ]
        assert (
            sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone()[0]
            == recovery_cursor
        )

    async def test_cancelled_sync_releases_the_session_lock_and_rolls_back(
        self, db_pool, sync_conn
    ):
        """Cancelling a task mid-write, while it holds both the advisory
        lock and an open write transaction, must roll back the uncommitted
        row AND release the lock — the connection returns usable and empty
        to the next lock acquirer instead of staying wedged or leaking a
        partial write."""
        entered = asyncio.Event()

        async def job():
            async with (
                sync._cross_process_sync_lock(db_pool) as connection,
                get_db_cursor(connection) as cur,
            ):
                await sync._upsert_public_catalogue_record(
                    cur, parsed_record("uncommitted"), sync._SWISSUBASE_POLICY
                )
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(job())
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with asyncio.timeout(5), sync._cross_process_sync_lock(db_pool) as connection:
            assert not connection.closed
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0


def _stage_decodable_harvest(
    conn: psycopg.Connection,
    harvest: HarvestResult,
    *,
    position: int,
    affected: int,
    started_at: datetime | None,
) -> bytes:
    """Persist a harvest that ``decode_stored_harvest`` accepts, with an
    explicit (possibly invalid) resumable-progress triple, mirroring exactly
    what a real staged incremental leaves behind mid-run."""
    payload = encode_stored_harvest(harvest, source_fingerprint=sync._source_a_fingerprint())
    conn.execute(
        """UPDATE sync_status
           SET incremental_harvest = %s, incremental_started_at = %s,
               incremental_position = %s, incremental_affected = %s
           WHERE id = 1""",
        (payload, started_at, position, affected),
    )
    conn.commit()
    return payload


STAGED_AT = datetime(2026, 1, 5, tzinfo=UTC)


class TestFullRebuildRecoversAnUnreplayableStagedHarvest:
    """A staged incremental whose resumable-progress triple cannot be
    trusted (an out-of-range position, a negative affected count, or a
    missing start time) is not replayed; ``run_full_rebuild`` catches the
    resulting typed recovery signal, discards it, and still runs the
    authoritative full harvest to completion."""

    @pytest.mark.parametrize(
        ("position", "affected", "started_at"),
        [
            pytest.param(5, 0, STAGED_AT, id="position-past-the-work-list"),
        ],
    )
    async def test_an_unreplayable_staged_harvest_is_discarded_and_the_full_rebuild_still_commits(
        self, db_pool, sync_conn, position, affected, started_at
    ):
        stale_harvest = harvest_result([_full_record("unreplayable")])
        _stage_decodable_harvest(
            sync_conn, stale_harvest, position=position, affected=affected, started_at=started_at
        )
        rebuild_t0 = datetime.now(UTC)

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("authoritative-1")])
        ):
            outcome = await sync._full_rebuild_source_a(db_pool)

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
               FROM sync_status"""
        ).fetchone()
        assert after[:4] == (None, None, 0, 0)
        assert after[4] is not None and after[4] >= rebuild_t0


class TestFullRebuildFetchFailureAfterReplayRecovery:
    async def test_the_authoritative_fetch_failing_after_replay_recovery_leaves_the_original_payload_for_a_later_retry(
        self, db_pool, sync_conn
    ):
        """When the discarded staged harvest above is followed by a fetch
        that ALSO fails, the rebuild never reaches the clear step at all:
        the original staged bytes and progress survive untouched, available
        for a later retry, instead of being silently dropped."""
        stale_harvest = harvest_result([_full_record("unreplayable-2")])
        original_payload = _stage_decodable_harvest(
            sync_conn, stale_harvest, position=9, affected=0, started_at=STAGED_AT
        )

        with patch(FETCH, autospec=True, side_effect=RuntimeError("upstream unreachable")):
            outcome = await sync._full_rebuild_source_a(db_pool)

        assert outcome.status == "failed"
        after = sync_conn.execute(
            """SELECT incremental_harvest, incremental_started_at, incremental_position,
                      incremental_affected
               FROM sync_status"""
        ).fetchone()
        assert after == (original_payload, STAGED_AT, 9, 0)


class TestFullRebuildGuardedClearProtectsANewerStagedPayload:
    async def test_a_payload_staged_concurrently_during_the_rebuild_survives_the_exact_payload_guarded_clear(
        self, db_pool, sync_conn, monkeypatch
    ):
        """Between the moment ``run_full_rebuild`` captured the OLD staged
        payload for clearing and the moment it actually tries to clear it, a
        second process stages a NEWER payload (via an independent
        connection). The exact-payload guard on that clear must refuse to
        remove state it never captured — the rebuild fails loudly instead of
        silently destroying the newer process's in-flight work."""
        stale_harvest = harvest_result([_full_record("unreplayable-3")])
        _stage_decodable_harvest(
            sync_conn, stale_harvest, position=9, affected=0, started_at=STAGED_AT
        )

        newer_payload = encode_stored_harvest(
            harvest_result([make_record("newer-process-work")]),
            source_fingerprint=sync._source_a_fingerprint(),
        )
        real_reconcile = sync._reconcile_rebuild_records

        async def reconcile_then_stage_a_newer_payload(cur, records):
            result = await real_reconcile(cur, records)
            with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as concurrent:
                concurrent.execute(
                    """UPDATE sync_status
                       SET incremental_harvest = %s, incremental_started_at = %s,
                           incremental_position = 0, incremental_affected = 0
                       WHERE id = 1""",
                    (newer_payload, STAGED_AT),
                )
            return result

        monkeypatch.setattr(
            sync, "_reconcile_rebuild_records", reconcile_then_stage_a_newer_payload
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
            await sync._full_rebuild_source_a(db_pool)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            survivor = fresh.execute(
                "SELECT incremental_harvest FROM sync_status WHERE id = 1"
            ).fetchone()[0]
        assert bytes(survivor) == newer_payload


class TestValidStagedHarvestReplaysWithoutTriggeringAFullFetch:
    async def test_a_valid_staged_position_finalises_incrementally_without_ever_reaching_the_full_fetch_path(
        self, db_pool, sync_conn
    ):
        """Positive control for the discarded-payload scenarios above: a
        staged harvest whose position, affected count and start time are all
        legitimate is replayed to completion by the plain incremental
        entry point alone. The full-rebuild fetch (``since='1900-01-01'``)
        is never invoked."""
        good_harvest = harvest_result([_full_record("valid-replay")])
        _stage_decodable_harvest(
            sync_conn, good_harvest, position=0, affected=0, started_at=STAGED_AT
        )

        with patch(FETCH, autospec=True) as fetch:
            outcome = await sync._sync_source_a(db_pool)

        fetch.assert_not_called()
        assert outcome.status == "success"
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("valid-replay",)
            ).fetchone()[0]
            == 1
        )
        after = sync_conn.execute(
            "SELECT incremental_harvest, incremental_position FROM sync_status"
        ).fetchone()
        assert after == (None, 0)
