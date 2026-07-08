"""Scheduler unit tests — mutual exclusion, job execution, and registration pins.

Backlog coverage:
- §3.11b: `sync_and_invalidate` and `rebuild_and_invalidate` share the
  module-level `_sync_mutex` (asyncio.Lock). The lock is the CROSS-JOB overlap
  guard (incremental sync vs. full rebuild must never interleave, or a
  tombstoned uuid can be resurrected from the rebuild's stale snapshot);
  `max_instances=1` on each job is the PER-JOB self-overlap guard. Both layers
  are needed and both are pinned here.
- §3.5: an AsyncIOScheduler actually EXECUTES coroutine jobs. A
  BackgroundScheduler would call the async job on a worker thread, receive a
  coroutine object, and discard it — the "looks healthy, does nothing" failure
  (the lifecycle listener would even log EVENT_JOB_EXECUTED).
- Registration pins: scheduler class, exact job-id set, max_instances=1.

All DB-touching services (run_sync, run_full_rebuild, cleanup_expired_sessions)
are patched in the scheduler module's namespace — no database is needed.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import app.services.scheduler as scheduler_module
from app.services.scheduler import create_scheduler


@pytest.fixture
def fresh_mutex(monkeypatch):
    """Replace the module-level _sync_mutex with a per-test asyncio.Lock.

    The real lock is created at import time; asyncio primitives bind to the
    first event loop that acquires them and raise RuntimeError when reused
    from another loop. pytest-asyncio gives every test a fresh loop, so each
    lock-touching test gets its own Lock (monkeypatch restores the original).
    The wrappers look the lock up via the module global at call time, so
    patching the module attribute is what they see.
    """
    lock = asyncio.Lock()
    monkeypatch.setattr(scheduler_module, "_sync_mutex", lock)
    return lock


async def test_sync_mutex_serializes_rebuild_then_sync(fresh_mutex, monkeypatch):
    """§3.11b: while a rebuild holds _sync_mutex, an incremental sync blocks.

    Regression guard for the CQ-008 seam: once the full-rebuild harvest was
    offloaded to a threadpool (§3.11a), nothing but this lock stops an
    incremental DELETE of a tombstoned uuid interleaving with the rebuild
    re-inserting that uuid from its pre-deletion snapshot (resurrection for up
    to 24h). Pins: sync's body cannot start until the rebuild's body finishes,
    both wrappers still invalidate the facet cache, and the mutex ends released.
    """
    order = []
    rebuild_started = asyncio.Event()
    release = asyncio.Event()
    facet_cache = MagicMock()
    pool = MagicMock()
    invalidate_count_when_sync_ran = []

    async def fake_rebuild(_pool):
        rebuild_started.set()
        await release.wait()
        order.append("rebuild")

    async def fake_sync(_pool):
        # Invalidate-outside-lock pin (in-flight view): the wrapper calls
        # invalidate_cache AFTER the with-block, so while the sync body runs
        # the lock is held and sync's own invalidation has not happened yet —
        # only the completed rebuild's single call is on the mock.
        assert scheduler_module._sync_mutex.locked() is True
        invalidate_count_when_sync_ran.append(facet_cache.invalidate_cache.call_count)
        order.append("sync")

    monkeypatch.setattr(scheduler_module, "run_full_rebuild", fake_rebuild)
    monkeypatch.setattr(scheduler_module, "run_sync", fake_sync)

    rebuild_task = asyncio.create_task(
        scheduler_module.rebuild_and_invalidate(pool, facet_cache)
    )
    await rebuild_started.wait()

    sync_task = asyncio.create_task(
        scheduler_module.sync_and_invalidate(pool, facet_cache)
    )
    await asyncio.sleep(0.05)

    # The sync body must NOT have started: it is parked on the lock the
    # rebuild still holds. (Without the shared lock, 'sync' would already be
    # in `order` here — max_instances=1 alone would not prevent this.)
    assert "sync" not in order
    assert order == []
    assert scheduler_module._sync_mutex.locked() is True

    release.set()
    await asyncio.gather(rebuild_task, sync_task)

    # Strict serialization: rebuild body finished before sync body began.
    assert order == ["rebuild", "sync"]
    # Both wrappers invalidated the facet cache (once each).
    assert facet_cache.invalidate_cache.call_count == 2
    # When the sync body ran, only the rebuild's invalidation had fired.
    assert invalidate_count_when_sync_ran == [1]
    # The mutex is released once both wrappers complete.
    assert scheduler_module._sync_mutex.locked() is False


async def test_invalidate_cache_runs_after_lock_released(fresh_mutex, monkeypatch):
    """§3.11b invalidate-outside-lock pin, sync-only form.

    Pins the wrapper's ordering: the sync body runs WITH the lock held and
    with zero invalidations recorded; invalidate_cache fires exactly once,
    after the with-block (so cache invalidation is never serialized under the
    sync mutex — a future edit moving it inside the lock fails here).
    """
    facet_cache = MagicMock()
    lock_held_in_body = []
    invalidate_count_in_body = []

    async def fake_sync(_pool):
        lock_held_in_body.append(scheduler_module._sync_mutex.locked())
        invalidate_count_in_body.append(facet_cache.invalidate_cache.call_count)

    monkeypatch.setattr(scheduler_module, "run_sync", fake_sync)

    await scheduler_module.sync_and_invalidate(MagicMock(), facet_cache)

    assert lock_held_in_body == [True]
    # invalidate_cache had NOT yet been called when run_sync ran ...
    assert invalidate_count_in_body == [0]
    # ... it happens after the with-block, exactly once, lock already free.
    facet_cache.invalidate_cache.assert_called_once()
    assert scheduler_module._sync_mutex.locked() is False


async def test_mutex_released_when_rebuild_raises(fresh_mutex, monkeypatch):
    """§3.11b: a failing rebuild must not leave the mutex held.

    `async with` guarantees release on exception; if that ever regressed to a
    manual acquire/release, one rebuild failure would deadlock every future
    sync AND rebuild forever (silent total sync outage). Pins: the wrapper
    propagates the error, the lock is free afterwards, and a subsequent
    incremental sync still runs to completion.
    """
    facet_cache = MagicMock()

    async def failing_rebuild(_pool):
        raise RuntimeError("harvest exploded")

    monkeypatch.setattr(scheduler_module, "run_full_rebuild", failing_rebuild)

    with pytest.raises(RuntimeError, match="harvest exploded"):
        await scheduler_module.rebuild_and_invalidate(MagicMock(), facet_cache)

    assert scheduler_module._sync_mutex.locked() is False
    # The failure happened inside the with-block, before invalidation.
    facet_cache.invalidate_cache.assert_not_called()

    # A subsequent sync acquires the lock and completes normally.
    ran = []

    async def ok_sync(_pool):
        ran.append("sync")

    monkeypatch.setattr(scheduler_module, "run_sync", ok_sync)
    await scheduler_module.sync_and_invalidate(MagicMock(), facet_cache)
    assert ran == ["sync"]
    assert facet_cache.invalidate_cache.call_count == 1
    assert scheduler_module._sync_mutex.locked() is False


async def test_asyncio_scheduler_executes_coroutine_jobs(monkeypatch):
    """§3.5: the scheduler actually AWAITS coroutine jobs (spy form).

    session_cleanup is registered with next_run_time=now, so a started
    AsyncIOScheduler must execute it almost immediately. A BackgroundScheduler
    regression would call the coroutine function on a worker thread and
    discard the coroutine object — the spy would never be awaited, while the
    lifecycle listener still logged EVENT_JOB_EXECUTED ("looks healthy, does
    nothing"). Asserting the spy was AWAITED (not the log) is the point.
    """
    cleanup_spy = AsyncMock()
    monkeypatch.setattr(scheduler_module, "cleanup_expired_sessions", cleanup_spy)
    # Neuter the sync wrappers so no real harvest/DB work fires
    # (incremental_sync also has next_run_time=now).
    monkeypatch.setattr(scheduler_module, "sync_and_invalidate", AsyncMock())
    monkeypatch.setattr(scheduler_module, "rebuild_and_invalidate", AsyncMock())

    sched = scheduler_module.create_scheduler(MagicMock(), MagicMock())
    sched.start()
    try:
        # Poll up to ~2s (typically <100ms) instead of one fixed sleep, to
        # keep the test fast and non-flaky under load.
        deadline = asyncio.get_running_loop().time() + 2.0
        while (
            cleanup_spy.await_count == 0
            and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.05)
        cleanup_spy.assert_awaited()
    finally:
        sched.shutdown(wait=False)


def test_create_scheduler_registration_pins():
    """Registration pins: scheduler class, exact job ids, max_instances=1.

    - AsyncIOScheduler is load-bearing (see §3.5 above): any other scheduler
      class silently drops the coroutine jobs.
    - The job-id set is exact: a renamed/dropped job would break the lifecycle
      listener's log correlation and ops runbooks silently.
    - max_instances=1 on EVERY job is the per-job self-overlap guard; the
      shared _sync_mutex is the cross-job guard between incremental_sync and
      full_rebuild. Two layers, both required (§3.11b).
    """
    # Never started, so no shutdown needed; get_jobs() returns pending jobs.
    sched = create_scheduler(MagicMock(), MagicMock())
    assert isinstance(sched, AsyncIOScheduler)

    jobs = sched.get_jobs()
    assert {job.id for job in jobs} == {
        "incremental_sync",
        "full_rebuild",
        "session_cleanup",
        "reap_unverified",
    }
    for job in jobs:
        assert job.max_instances == 1, f"{job.id} lost its self-overlap guard"

    # session_cleanup (and incremental_sync) are registered to fire
    # immediately — the mechanism the §3.5 execution test relies on.
    by_id = {job.id: job for job in jobs}
    assert by_id["session_cleanup"].next_run_time is not None
    assert by_id["incremental_sync"].next_run_time is not None


def test_scheduler_binds_correct_callable_args_and_intervals():
    """TEST-034: the registration test above pins ids/max_instances but NOT
    the callable, args, or intervals — so binding full_rebuild to
    sync_and_invalidate (stale versions never purged: the docstrings say the
    full rebuild is the ONLY purge mechanism) or swapping the two intervals
    (hammer upstream hourly while incremental lags 24h) would ship green while
    the lifecycle listener still logged 'completed'. This pins all three."""
    from config import settings

    pool, facet_cache = MagicMock(), MagicMock()
    jobs = {j.id: j for j in create_scheduler(pool, facet_cache).get_jobs()}

    # func identity — the exact coroutine each id must invoke.
    assert jobs["incremental_sync"].func is scheduler_module.sync_and_invalidate
    assert jobs["full_rebuild"].func is scheduler_module.rebuild_and_invalidate
    assert jobs["session_cleanup"].func is scheduler_module.cleanup_expired_sessions
    assert jobs["reap_unverified"].func is scheduler_module.reap_unverified_accounts

    # args — the sync/rebuild jobs get (pool, facet_cache); the DB-only jobs
    # get just the pool. A dropped facet_cache arg means stale search sidebars.
    assert jobs["incremental_sync"].args == (pool, facet_cache)
    assert jobs["full_rebuild"].args == (pool, facet_cache)
    assert jobs["session_cleanup"].args == (pool,)
    assert jobs["reap_unverified"].args == (pool,)

    # interval seconds — driven by settings, not swapped.
    def _interval_seconds(job):
        return job.trigger.interval.total_seconds()

    assert _interval_seconds(jobs["incremental_sync"]) == settings.sync_interval_seconds
    assert _interval_seconds(jobs["full_rebuild"]) == settings.full_rebuild_interval_seconds
    assert _interval_seconds(jobs["session_cleanup"]) == 3600
    assert _interval_seconds(jobs["reap_unverified"]) == 24 * 3600
