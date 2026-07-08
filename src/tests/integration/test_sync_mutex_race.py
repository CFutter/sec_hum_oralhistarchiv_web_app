"""Backlog §3.11c — the deletion-resurrection race (integration, real PG).

The behavioral proof that scheduler._sync_mutex exists: an incremental sync
carrying uuid X's deletion tombstone fires while a full rebuild — whose
harvest snapshot still CONTAINS X — is mid-flight. With the shared lock the
two jobs serialize and X stays deleted; without it the rebuild would re-insert
X from its stale snapshot and resurrect the deleted record for up to 24h
(until the next rebuild).

Why nothing else covers this:
- ON CONFLICT (uuid) DO UPDATE cannot fix it — the upsert arbitrates
  insert-vs-insert collisions, not insert-vs-delete ordering: the rebuild's
  INSERT of X after the incremental's DELETE simply succeeds.
- APScheduler's max_instances=1 only guards each job against ITSELF
  (incremental-vs-incremental, rebuild-vs-rebuild); the shared asyncio.Lock
  is the only cross-job guard.

Both scheduler wrappers reference the module global `_sync_mutex` at call
time, so patching it per test both isolates tests (a fresh Lock can't stay
bound to a previous test's event loop) and — because monkeypatch.setattr
raises if the attribute vanishes — fails loudly if the lock is ever removed.
"""

import asyncio
import threading
from unittest.mock import MagicMock, patch

import pytest

import app.services.scheduler as scheduler
from app.services.scheduler import rebuild_and_invalidate, sync_and_invalidate

# _full_rebuild_source_a always harvests from the epoch-of-everything; the
# incremental computes `since` from sync_status.last_harvest_date (which is
# never 1900). This is how the patched fetch tells the two callers apart.
REBUILD_SINCE = "1900-01-01T00:00:00Z"

# Generous ceilings so a deadlock (e.g. someone makes the lock non-reentrant
# in a way that self-blocks, or the gate never opens) FAILS the test instead
# of hanging CI. Actual happy-path runtime is well under a second per await.
WAIT_TIMEOUT = 15


@pytest.fixture(autouse=True)
def fresh_sync_mutex(monkeypatch):
    """Fresh lock per test: same object the code uses, no cross-loop binding."""
    monkeypatch.setattr(scheduler, "_sync_mutex", asyncio.Lock())


def _full_record(uuid: str) -> dict:
    """A record satisfying the parser contract (_PARSER_OWNED key presence).

    _build_record_params raises KeyError if any parse_cmdi_to_dict-emitted
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


async def test_tombstone_survives_concurrent_rebuild_with_stale_snapshot(
    db_pool, dataset_factory, sync_conn
):
    """§3.11c — THE resurrection race: deleted stays deleted under the lock.

    Timeline forced here: rebuild acquires _sync_mutex and blocks inside its
    (threadpool-offloaded) fetch, snapshot containing X already decided; an
    incremental carrying X's deletion tombstone fires. The regression trigger
    is the mid-flight assert that the incremental's sync body has NOT begun —
    if someone removes `async with _sync_mutex` from either wrapper, the
    incremental's fetch runs while the rebuild is mid-flight, that assert
    fails, and (end state) the rebuild's stale snapshot re-inserts X after
    the tombstone's DELETE — resurrecting a deleted record for up to 24h.
    """
    dataset_factory(source="swissubase", uuid="X")
    assert _uuid_exists(sync_conn, "X"), "seed row must exist before the race"

    events: list[str] = []          # appended from threadpool threads (append is atomic)
    gate = threading.Event()        # holds the rebuild's fetch mid-flight

    def fake_fetch(*, oai_url, since, institution_filter):
        if since == REBUILD_SINCE:
            events.append("rebuild_fetch_start")
            # Runs in a run_in_threadpool worker thread — blocking here
            # freezes only the rebuild, never the event loop (§3.11a).
            gate.wait(timeout=10)
            return [_full_record("X")]  # the STALE snapshot: still contains X
        events.append("sync_fetch_start")
        return [{"_deleted": True, "uuid": "X"}]  # X's deletion tombstone

    facet_cache = MagicMock()
    sync_task = None
    with patch("app.services.sync.fetch_updates", new=fake_fetch):
        rebuild_task = asyncio.create_task(rebuild_and_invalidate(db_pool, facet_cache))
        try:
            # Rebuild is now mid-flight: mutex held, fetch parked on the gate.
            await _poll_until(lambda: "rebuild_fetch_start" in events)

            sync_task = asyncio.create_task(sync_and_invalidate(db_pool, facet_cache))
            await asyncio.sleep(0.3)
            # THE regression trigger: the incremental's sync body (watermark
            # read + fetch) must not have begun — it is blocked on _sync_mutex.
            assert "sync_fetch_start" not in events, (
                "incremental sync body started while the rebuild held (should "
                "hold) _sync_mutex — the cross-job overlap guard is gone"
            )

            gate.set()
            await asyncio.wait_for(
                asyncio.gather(rebuild_task, sync_task), WAIT_TIMEOUT
            )
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

    # Each wrapper still invalidates the facet cache exactly once (outside
    # the lock — invalidation itself is not what the mutex serializes).
    assert facet_cache.invalidate_cache.call_count == 2


async def test_mutex_released_when_rebuild_fetch_fails(
    db_pool, dataset_factory, sync_conn
):
    """§3.11c hygiene — a failing rebuild must not wedge the shared lock.

    _full_rebuild_source_a swallows fetch exceptions (records them in
    sync_status.last_sync_error and returns), and `async with _sync_mutex`
    releases on any exit path. Regression guarded: a lock held past a failed
    rebuild would silently starve EVERY future sync job (no more incremental
    syncs, no more rebuilds) until process restart.
    """
    dataset_factory(source="swissubase", uuid="X")
    sync_since_calls: list[str] = []

    def fake_fetch(*, oai_url, since, institution_filter):
        if since == REBUILD_SINCE:
            raise ConnectionError("upstream OAI endpoint down")
        sync_since_calls.append(since)
        return [{"_deleted": True, "uuid": "X"}]

    facet_cache = MagicMock()
    with patch("app.services.sync.fetch_updates", new=fake_fetch):
        # Rebuild completes despite the fetch error (error recorded, no raise).
        await asyncio.wait_for(rebuild_and_invalidate(db_pool, facet_cache), WAIT_TIMEOUT)

        assert not scheduler._sync_mutex.locked(), (
            "_sync_mutex still held after a failed rebuild — every future "
            "sync job would deadlock"
        )
        row = sync_conn.execute(
            "SELECT last_sync_error FROM sync_status WHERE id = 1"
        ).fetchone()
        assert row[0] is not None and "Full rebuild" in row[0]
        # Fetch failed before any write: existing data untouched.
        assert _uuid_exists(sync_conn, "X")

        # A following incremental acquires the lock and runs its full body:
        # fetches, processes X's tombstone, clears the recorded error.
        await asyncio.wait_for(sync_and_invalidate(db_pool, facet_cache), WAIT_TIMEOUT)

    assert len(sync_since_calls) == 1, "incremental fetch did not run after the failed rebuild"
    assert not _uuid_exists(sync_conn, "X"), "tombstone not processed by the follow-up sync"
    row = sync_conn.execute(
        "SELECT last_sync_error FROM sync_status WHERE id = 1"
    ).fetchone()
    assert row[0] is None, "successful sync should clear last_sync_error"
    assert facet_cache.invalidate_cache.call_count == 2
