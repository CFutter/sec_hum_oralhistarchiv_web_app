"""Scheduler unit tests — mutual exclusion, job execution, and registration pins.

Coverage notes:
- `sync_and_invalidate` and `rebuild_and_invalidate` (app.services.scheduler)
  call straight through to `run_sync`/`run_full_rebuild` (app.services.sync),
  which hold the module-level `_sync_mutex` (asyncio.Lock) there. That lock is
  the CROSS-JOB overlap guard (incremental sync vs. full rebuild must never
  interleave, or a tombstoned uuid can be resurrected from the rebuild's stale
  snapshot); `max_instances=1` on each job is the separate PER-JOB
  self-overlap guard. Both layers are needed and both are pinned here.
- An AsyncIOScheduler actually EXECUTES coroutine jobs. A BackgroundScheduler
  in its place would call the async job on a worker thread, receive a
  coroutine object, and discard it — the "looks healthy, does nothing"
  failure (the lifecycle listener would even log EVENT_JOB_EXECUTED).
- Registration pins: scheduler class, exact job-id set, max_instances=1.

All DB-touching services (outbox delivery, synchronization, and session
cleanup) are patched in the scheduler module's namespace — no database is
needed.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import MagicMock, create_autospec

import pytest
from apscheduler.events import (
    EVENT_JOB_ERROR,
    EVENT_JOB_EXECUTED,
    EVENT_JOB_MISSED,
    JobExecutionEvent,
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from psycopg_pool import AsyncConnectionPool

import app.services.scheduler as scheduler_module
import app.services.sync as sync_module
from app.services.scheduler import RunningJobTracker, create_scheduler
from config import settings
from tests.fixtures import make_mock_catalogue_stats_cache

_EXPECTED_INVALIDATION_COUNT = 2
_EMAIL_OUTBOX_INTERVAL_SECONDS = 15
_SESSION_CLEANUP_INTERVAL_SECONDS = 60 * 60
_UNVERIFIED_REAP_INTERVAL_SECONDS = 60 * 60


def _scheduler_pool_mock() -> MagicMock:
    """Return a pool mock that passes the scheduler's size guard."""
    pool = MagicMock(spec=AsyncConnectionPool)
    pool.max_size = 2
    return pool


def _interval_seconds(job) -> float:
    """Return an interval job's configured period in seconds."""
    return job.trigger.interval.total_seconds()


async def _wait_until_registered_as_a_waiter(lock: asyncio.Lock) -> None:
    """Bounded poll of a real external condition: a second task has
    registered itself on `lock`'s own FIFO of pending acquirers.

    `asyncio.Lock` exposes `_waiters` (None until first contended, then a
    deque of pending-acquire futures). Polling this observes the blocked
    state directly instead of a timed "sleep, then assert not done", which
    proves nothing about why nothing happened yet.
    """

    async def _poll() -> None:
        while not lock._waiters:
            await asyncio.sleep(0)

    await asyncio.wait_for(_poll(), timeout=2)


@pytest.fixture
def fresh_mutex(monkeypatch):
    """Install fresh local and no-op cross-process locks for unit tests.

    `_sync_mutex` and `_cross_process_sync_lock` live in `app.services.sync`;
    `run_sync`/`run_full_rebuild` (which the scheduler's
    `sync_and_invalidate`/`rebuild_and_invalidate` call unmodified) acquire
    both. Patching them here, rather than on the scheduler module, exercises
    the real serialization path.
    """
    lock = asyncio.Lock()
    monkeypatch.setattr(sync_module, "_sync_mutex", lock)

    async def run_in_threadpool_inline(func, *args):
        """Keep lock tests independent from the host's thread-pool runtime."""
        return func(*args)

    monkeypatch.setattr(scheduler_module, "run_in_threadpool", run_in_threadpool_inline)

    @asynccontextmanager
    async def no_op_cross_process_lock(pool):
        yield pool

    monkeypatch.setattr(
        sync_module,
        "_cross_process_sync_lock",
        no_op_cross_process_lock,
    )
    return lock


@pytest.mark.usefixtures("fresh_mutex")
class TestSyncMutexSerializesIncrementalAndFullRebuild:
    """`_sync_mutex` (asyncio.Lock, app.services.sync) is the only thing that
    stops an incremental sync's DELETE of a tombstoned uuid interleaving with
    a full rebuild's re-insertion of that same uuid from its pre-deletion
    snapshot — a resurrection window of up to 24h. `max_instances=1` alone
    does not prevent this because the two jobs are different job ids.
    """

    async def test_incremental_sync_blocks_while_full_rebuild_holds_the_lock(self, monkeypatch):
        """A full rebuild in progress must fully finish before a concurrently
        requested incremental sync's body starts, and the mutex must end
        released with both cache invalidations recorded.
        """
        order = []
        rebuild_started = asyncio.Event()
        release = asyncio.Event()
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        pool = MagicMock()

        async def fake_rebuild_body(_connection):
            rebuild_started.set()
            await release.wait()
            order.append("rebuild")

        async def fake_sync_body(_connection):
            assert sync_module._sync_mutex.locked() is True
            order.append("sync")

        # `run_full_rebuild`/`run_sync` (unpatched here) hold the real lock;
        # only the connection-level bodies they delegate to are faked out.
        monkeypatch.setattr(
            sync_module, "_run_full_rebuild_on_locked_connection", fake_rebuild_body
        )
        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", fake_sync_body)

        rebuild_task = asyncio.create_task(
            scheduler_module.rebuild_and_invalidate(pool, catalogue_stats_cache)
        )
        await rebuild_started.wait()

        sync_task = asyncio.create_task(
            scheduler_module.sync_and_invalidate(pool, catalogue_stats_cache)
        )
        await _wait_until_registered_as_a_waiter(sync_module._sync_mutex)

        # The sync body must NOT have started: it is parked on the lock the
        # rebuild still holds — observed directly above as a registered
        # waiter, not inferred from a fixed delay. Without the shared lock,
        # "sync" would already be in `order` here.
        assert "sync" not in order
        assert order == []
        assert sync_module._sync_mutex.locked() is True

        release.set()
        await asyncio.gather(rebuild_task, sync_task)

        # Strict serialization: rebuild body finished before sync body began.
        assert order == ["rebuild", "sync"]
        # Both wrappers invalidated the catalogue statistics cache (once each).
        assert catalogue_stats_cache.invalidate_cache.call_count == _EXPECTED_INVALIDATION_COUNT
        # The mutex is released once both wrappers complete.
        assert sync_module._sync_mutex.locked() is False

    async def test_cache_invalidation_runs_after_the_lock_is_released(self, monkeypatch):
        """The sync body runs WITH the lock held and with zero invalidations
        recorded so far; invalidate_cache fires exactly once, after the
        with-block — cache invalidation is never serialized under the sync
        mutex, so moving it inside the lock would fail this test.
        """
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        lock_held_in_body = []
        invalidate_count_in_body = []

        async def fake_sync_body(_connection):
            lock_held_in_body.append(sync_module._sync_mutex.locked())
            invalidate_count_in_body.append(catalogue_stats_cache.invalidate_cache.call_count)

        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", fake_sync_body)

        await scheduler_module.sync_and_invalidate(MagicMock(), catalogue_stats_cache)

        assert lock_held_in_body == [True]
        # invalidate_cache had NOT yet been called when run_sync ran ...
        assert invalidate_count_in_body == [0]
        # ... it happens after the with-block, exactly once, lock already free.
        catalogue_stats_cache.invalidate_cache.assert_called_once()
        assert sync_module._sync_mutex.locked() is False

    async def test_mutex_is_released_and_usable_after_a_failing_rebuild(self, monkeypatch):
        """`async with` guarantees release on exception; a failing rebuild
        must not leave the mutex held, or every future sync and rebuild would
        deadlock forever (silent total sync outage). The wrapper must
        propagate the error, leave the lock free afterwards, and let a
        subsequent incremental sync run to completion.
        """
        catalogue_stats_cache = make_mock_catalogue_stats_cache()

        async def failing_rebuild_body(_connection):
            raise RuntimeError("harvest exploded")

        monkeypatch.setattr(
            sync_module, "_run_full_rebuild_on_locked_connection", failing_rebuild_body
        )

        with pytest.raises(RuntimeError, match="harvest exploded"):
            await scheduler_module.rebuild_and_invalidate(MagicMock(), catalogue_stats_cache)

        assert sync_module._sync_mutex.locked() is False
        # The failure happened inside the with-block, before invalidation.
        catalogue_stats_cache.invalidate_cache.assert_called_once()

        # A subsequent sync acquires the lock and completes normally.
        ran = []

        async def ok_sync_body(_connection):
            ran.append("sync")

        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", ok_sync_body)
        await scheduler_module.sync_and_invalidate(MagicMock(), catalogue_stats_cache)
        assert ran == ["sync"]
        assert catalogue_stats_cache.invalidate_cache.call_count == _EXPECTED_INVALIDATION_COUNT
        assert sync_module._sync_mutex.locked() is False


class TestSyncAndInvalidateEscalatesTheTypedRecoverySignal:
    """`sync_and_invalidate` escalates to an authoritative full rebuild
    exactly once when (and only when) `run_sync` returns a typed outcome with
    `requires_full_rebuild=True` — driven by that boolean field alone, never
    by matching text in `.reason`."""

    async def test_a_typed_recovery_outcome_escalates_to_exactly_one_full_rebuild(
        self, monkeypatch
    ):
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        pool = MagicMock()
        recovery_outcome = sync_module.SyncOutcome(
            "failed",
            # A reason that would fool naive substring matching on "success"
            # if the escalation were driven by text instead of the flag.
            reason="looks like success but is not",
            requires_full_rebuild=True,
        )
        rebuild_outcome = sync_module.SyncOutcome("success", affected_count=5)
        monkeypatch.setattr(
            scheduler_module,
            "run_sync",
            create_autospec(sync_module.run_sync, return_value=recovery_outcome),
        )
        run_full_rebuild = create_autospec(
            sync_module.run_full_rebuild, return_value=rebuild_outcome
        )
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(pool, catalogue_stats_cache)

        run_full_rebuild.assert_awaited_once_with(pool)
        assert result == rebuild_outcome
        catalogue_stats_cache.invalidate_cache.assert_called_once()

    async def test_an_ordinary_failure_without_the_recovery_flag_does_not_escalate(
        self, monkeypatch
    ):
        """Positive control: a `failed` outcome with `requires_full_rebuild`
        left at its default (False) is returned as-is."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        pool = MagicMock()
        ordinary_failure = sync_module.SyncOutcome("failed", reason="fetch timed out")
        monkeypatch.setattr(
            scheduler_module,
            "run_sync",
            create_autospec(sync_module.run_sync, return_value=ordinary_failure),
        )
        run_full_rebuild = create_autospec(sync_module.run_full_rebuild)
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(pool, catalogue_stats_cache)

        run_full_rebuild.assert_not_awaited()
        assert result == ordinary_failure
        catalogue_stats_cache.invalidate_cache.assert_called_once()

    async def test_an_ordinary_success_does_not_escalate(self, monkeypatch):
        """Positive control: an ordinary success never triggers a rebuild."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        pool = MagicMock()
        ordinary_success = sync_module.SyncOutcome("success", affected_count=2)
        monkeypatch.setattr(
            scheduler_module,
            "run_sync",
            create_autospec(sync_module.run_sync, return_value=ordinary_success),
        )
        run_full_rebuild = create_autospec(sync_module.run_full_rebuild)
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(pool, catalogue_stats_cache)

        run_full_rebuild.assert_not_awaited()
        assert result == ordinary_success
        catalogue_stats_cache.invalidate_cache.assert_called_once()


class TestAsyncIOSchedulerExecutesCoroutineJobs:
    """An AsyncIOScheduler must actually AWAIT coroutine jobs. Swapping in a
    BackgroundScheduler would call the coroutine function on a worker thread
    and discard the coroutine object, so the job would never run even though
    the lifecycle listener still logs EVENT_JOB_EXECUTED.
    """

    async def test_maintenance_and_delivery_jobs_run_almost_immediately(self, monkeypatch):
        """session_cleanup and email_outbox_delivery are registered with
        next_run_time=now, so a started scheduler must execute both almost
        immediately.
        """
        cleanup_ran = asyncio.Event()
        delivery_ran = asyncio.Event()

        async def record_cleanup(*_args) -> None:
            cleanup_ran.set()

        async def record_delivery(*_args) -> None:
            delivery_ran.set()

        cleanup_spy = create_autospec(
            scheduler_module.cleanup_expired_sessions, side_effect=record_cleanup
        )
        monkeypatch.setattr(scheduler_module, "cleanup_expired_sessions", cleanup_spy)
        # Neuter the sync wrappers so no real harvest/DB work fires
        # (incremental_sync also has next_run_time=now).
        monkeypatch.setattr(
            scheduler_module,
            "sync_and_invalidate",
            create_autospec(scheduler_module.sync_and_invalidate),
        )
        monkeypatch.setattr(
            scheduler_module,
            "rebuild_and_invalidate",
            create_autospec(scheduler_module.rebuild_and_invalidate),
        )

        delivery_spy = create_autospec(
            scheduler_module.deliver_email_outbox_batch, side_effect=record_delivery
        )
        monkeypatch.setattr(
            scheduler_module,
            "deliver_email_outbox_batch",
            delivery_spy,
        )

        running_jobs = RunningJobTracker()
        sched = scheduler_module.create_scheduler(
            _scheduler_pool_mock(),
            make_mock_catalogue_stats_cache(),
            running_jobs,
        )
        sched.start()
        try:
            await asyncio.wait_for(
                asyncio.gather(cleanup_ran.wait(), delivery_ran.wait()),
                timeout=2,
            )
            cleanup_spy.assert_awaited()
            delivery_spy.assert_awaited()
        finally:
            sched.shutdown(wait=False)


class TestSchedulerJobRegistration:
    """Registration pins: scheduler class, exact job ids, callables, args,
    intervals, and the per-job self-overlap guard.
    """

    def test_registers_asyncio_scheduler_with_the_exact_job_id_set(self):
        """AsyncIOScheduler is load-bearing: any other scheduler class
        silently drops the coroutine jobs. The job-id set is exact: a
        renamed or dropped job would break the lifecycle listener's log
        correlation and ops runbooks silently. `max_instances=1` on EVERY
        job is the per-job self-overlap guard, separate from the shared
        `_sync_mutex` cross-job guard between incremental_sync and
        full_rebuild.
        """
        # Never started, so no shutdown needed; get_jobs() returns pending jobs.
        running_jobs = RunningJobTracker()
        sched = create_scheduler(
            _scheduler_pool_mock(),
            make_mock_catalogue_stats_cache(),
            running_jobs,
        )
        assert isinstance(sched, AsyncIOScheduler)

        jobs = sched.get_jobs()
        assert {job.id for job in jobs} == {
            "email_outbox_delivery",
            "outbox_retention",
            "incremental_sync",
            "full_rebuild",
            "session_cleanup",
            "reap_unverified",
        }
        for job in jobs:
            assert job.max_instances == 1, f"{job.id} lost its self-overlap guard"

        # These three jobs fire immediately — the mechanism the coroutine
        # execution test above relies on for the maintenance jobs.
        by_id = {job.id: job for job in jobs}
        assert by_id["email_outbox_delivery"].next_run_time is not None
        assert by_id["session_cleanup"].next_run_time is not None
        assert by_id["incremental_sync"].next_run_time is not None

    def test_binds_the_correct_callable_args_and_intervals_per_job(self):
        """The job-id test above pins ids/max_instances but NOT the callable,
        args, or intervals — so binding full_rebuild to sync_and_invalidate
        (stale versions never purged, since the full rebuild is the only
        purge mechanism) or swapping the two intervals (hammering upstream
        hourly while incremental lags 24h) would ship green while the
        lifecycle listener still logged "completed". This pins all three.
        """
        pool = _scheduler_pool_mock()
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        running_jobs = RunningJobTracker()
        jobs = {
            job.id: job
            for job in create_scheduler(pool, catalogue_stats_cache, running_jobs).get_jobs()
        }

        # Every job must enter the same tracker. The underlying callable and
        # its application arguments follow the tracker metadata in job.args.
        for job in jobs.values():
            assert job.func.__self__ is running_jobs
            assert job.func.__func__ is RunningJobTracker.run

        assert jobs["email_outbox_delivery"].args == (
            "email_outbox_delivery",
            scheduler_module.deliver_email_outbox_batch,
            pool,
        )
        assert _interval_seconds(jobs["email_outbox_delivery"]) == _EMAIL_OUTBOX_INTERVAL_SECONDS
        assert jobs["email_outbox_delivery"].next_run_time is not None
        assert jobs["email_outbox_delivery"].max_instances == 1
        assert jobs["email_outbox_delivery"].coalesce is True

        assert jobs["incremental_sync"].args == (
            "incremental_sync",
            scheduler_module.sync_and_invalidate,
            pool,
            catalogue_stats_cache,
        )
        assert jobs["full_rebuild"].args == (
            "full_rebuild",
            scheduler_module.rebuild_and_invalidate,
            pool,
            catalogue_stats_cache,
        )
        assert jobs["session_cleanup"].args == (
            "session_cleanup",
            scheduler_module.cleanup_expired_sessions,
            pool,
        )
        assert jobs["reap_unverified"].args == (
            "reap_unverified",
            scheduler_module.reap_unverified_accounts,
            pool,
        )

        # Interval seconds — driven by settings, not swapped.
        assert _interval_seconds(jobs["incremental_sync"]) == settings.sync_interval_seconds
        assert _interval_seconds(jobs["full_rebuild"]) == settings.full_rebuild_interval_seconds
        assert _interval_seconds(jobs["session_cleanup"]) == _SESSION_CLEANUP_INTERVAL_SECONDS
        assert _interval_seconds(jobs["reap_unverified"]) == _UNVERIFIED_REAP_INTERVAL_SECONDS


def _job_event(code, *, exception=None, retval=None):
    """Build a JobExecutionEvent as APScheduler would dispatch it."""
    return JobExecutionEvent(
        code=code,
        job_id="incremental_sync",
        jobstore="default",
        scheduled_run_time=datetime(2026, 1, 1, tzinfo=UTC),
        exception=exception,
        retval=retval,
    )


def _events_for_level(caplog, level):
    return [r for r in caplog.records if r.name == "app.services.scheduler" and r.levelno == level]


class TestSchedulerEventLogging:
    """Scheduler health must be visible through structured logs, not only
    discoverable after something explicitly breaks.
    """

    def test_executed_event_logs_info_with_the_job_id(self, caplog):
        """EVENT_JOB_EXECUTED -> INFO with event_type 'scheduler_job_executed'
        and the job id, so a healthy run is visible at INFO.
        """
        with caplog.at_level(logging.INFO, logger="app.services.scheduler"):
            scheduler_module._on_scheduler_event(_job_event(EVENT_JOB_EXECUTED))

        infos = _events_for_level(caplog, logging.INFO)
        assert any(
            getattr(r, "event_type", None) == "scheduler_job_executed"
            and getattr(r, "job_id", None) == "incremental_sync"
            for r in infos
        )

    def test_error_event_logs_error_with_the_exception_type(self, caplog):
        """EVENT_JOB_ERROR -> ERROR with event_type 'scheduler_job_error' and
        the exception's type name captured in the structured extra, so a
        failing sync surfaces at ERROR (not swallowed).
        """
        with caplog.at_level(logging.INFO, logger="app.services.scheduler"):
            scheduler_module._on_scheduler_event(
                _job_event(EVENT_JOB_ERROR, exception=ValueError("sync blew up"))
            )

        errors = _events_for_level(caplog, logging.ERROR)
        assert errors, "job error must log at ERROR level"
        rec = errors[-1]
        assert getattr(rec, "event_type", None) == "scheduler_job_error"
        assert getattr(rec, "exception_type", None) == "ValueError"

    def test_missed_event_logs_a_warning(self, caplog):
        """EVENT_JOB_MISSED -> WARNING with event_type 'scheduler_job_missed':
        a scheduled run whose time passed without executing (overloaded loop
        or downtime) must be visible as a warning, not silence.
        """
        with caplog.at_level(logging.INFO, logger="app.services.scheduler"):
            scheduler_module._on_scheduler_event(_job_event(EVENT_JOB_MISSED))

        warnings = _events_for_level(caplog, logging.WARNING)
        assert any(getattr(r, "event_type", None) == "scheduler_job_missed" for r in warnings)

    @pytest.mark.parametrize("status", ["success", "partial", "failed"])
    def test_executed_event_with_a_sync_outcome_reports_the_ingestion_status(self, status, caplog):
        """When the completed job's return value is a `SyncOutcome`,
        EVENT_JOB_EXECUTED logs `event_type='ingestion_job_outcome'` carrying
        the outcome's own status/affected/failed counts — not the generic
        'scheduler_job_executed' event a plain successful coroutine gets —
        so a job that ran to completion but partially or fully failed its
        ingestion is distinguishable from one that actually succeeded."""
        outcome = sync_module.SyncOutcome(
            status, affected_count=2, failed_count=1, reason="safe reason"
        )
        event = _job_event(EVENT_JOB_EXECUTED, retval=outcome)

        with caplog.at_level(logging.INFO, logger="app.services.scheduler"):
            scheduler_module._on_scheduler_event(event)

        records = [r for r in caplog.records if getattr(r, "event_type", None)]
        assert len(records) == 1
        assert records[0].event_type == "ingestion_job_outcome"
        assert records[0].status == status
        assert records[0].affected_count == 2
        assert records[0].failed_count == 1


class TestRunningJobTracker:
    """`RunningJobTracker` (app.services.scheduler) is the application-owned
    running-job registry the process entry point drains at shutdown.
    """

    async def test_idle_waiter_blocks_until_every_active_job_exits(self):
        """The idle waiter remains blocked until every active job exits."""
        tracker = RunningJobTracker()
        first_started = asyncio.Event()
        second_started = asyncio.Event()
        release = asyncio.Event()

        async def blocked(started: asyncio.Event) -> None:
            started.set()
            await release.wait()

        first = asyncio.create_task(tracker.run("first", blocked, first_started))
        second = asyncio.create_task(tracker.run("second", blocked, second_started))

        await first_started.wait()
        await second_started.wait()
        assert tracker.active_job_ids == ("first", "second")

        waiter = asyncio.create_task(tracker.wait_until_empty())
        await asyncio.sleep(0)
        assert not waiter.done()

        release.set()
        await asyncio.gather(first, second)
        await asyncio.wait_for(waiter, timeout=1)

        assert tracker.active_job_ids == ()

    async def test_a_failing_job_still_releases_the_tracker(self):
        """A job exception propagates without leaving the tracker non-idle."""
        tracker = RunningJobTracker()

        async def failing() -> None:
            raise RuntimeError("job failed")

        with pytest.raises(RuntimeError, match="job failed"):
            await tracker.run("failing_job", failing)

        assert tracker.active_job_ids == ()
        await asyncio.wait_for(tracker.wait_until_empty(), timeout=1)

    async def test_a_cancelled_job_still_releases_the_tracker(self):
        """Forced APScheduler cancellation also releases tracker state."""
        tracker = RunningJobTracker()
        started = asyncio.Event()
        never_release = asyncio.Event()

        async def blocked() -> None:
            started.set()
            await never_release.wait()

        task = asyncio.create_task(tracker.run("cancelled_job", blocked))
        await started.wait()
        assert tracker.active_job_ids == ("cancelled_job",)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert tracker.active_job_ids == ()
        await asyncio.wait_for(tracker.wait_until_empty(), timeout=1)
