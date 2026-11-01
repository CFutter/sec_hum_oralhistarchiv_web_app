"""Scheduler unit tests — mutual exclusion, job execution, and registration pins."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
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

import app.services.ingestion as sync_module
import app.services.scheduler as scheduler_module
from app.services.scheduler import RunningJobTracker, create_scheduler
from app.sources import (
    ConfiguredSource,
    FixtureConfig,
    SourceDisplay,
    SourceSchedule,
    configure_sources,
)
from tests.fixtures import make_mock_catalogue_stats_cache
from tests.source_fixtures import legacy_source

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
    """Wait for a real mutex waiter with a bounded poll rather than inferring contention from a delay."""

    async def _poll() -> None:
        """Yield to the loop until the mutex has a registered waiter."""
        while not lock._waiters:
            await asyncio.sleep(0)

    await asyncio.wait_for(_poll(), timeout=2)


@pytest.fixture
def fresh_mutex(monkeypatch):
    """Install a fresh ingestion mutex and bypass the cross-process lock for this test."""
    lock = asyncio.Lock()
    monkeypatch.setattr(sync_module, "_sync_mutex", lock)

    async def run_in_threadpool_inline(func, *args):
        """Keep lock tests independent from the host's thread-pool runtime."""
        return func(*args)

    monkeypatch.setattr(scheduler_module, "run_in_threadpool", run_in_threadpool_inline)

    @asynccontextmanager
    async def no_op_cross_process_lock(pool):
        """Yield the supplied pool without taking a cross-process lock."""
        yield pool

    monkeypatch.setattr(
        sync_module,
        "_cross_process_sync_lock",
        no_op_cross_process_lock,
    )
    return lock


@pytest.mark.usefixtures("fresh_mutex")
class TestSyncMutexSerializesIncrementalAndFullRebuild:
    """The shared in-process lock prevents incremental sync and rebuild overlap."""

    async def test_incremental_sync_blocks_while_full_rebuild_holds_the_lock(self, monkeypatch):
        """A full rebuild in progress must fully finish before a concurrently
        requested incremental sync's body starts, and the mutex must end
        released with both cache invalidations recorded.
        """
        order = []
        rebuild_started = asyncio.Event()
        release = asyncio.Event()
        selected_source = legacy_source()
        incremental_source = legacy_source(name="other_archive")
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        pool = MagicMock()

        async def fake_rebuild_body(_connection, *, configured_source):
            """Check the selected source, hold rebuild execution until released, and record completion."""
            assert configured_source is selected_source
            rebuild_started.set()
            await release.wait()
            order.append("rebuild")

        async def fake_sync_body(_connection, *, configured_source):
            """Require the incremental source and held mutex, then record sync execution."""
            assert configured_source is incremental_source
            assert sync_module._sync_mutex.locked() is True
            order.append("sync")

        # `run_full_rebuild`/`run_sync` (unpatched here) hold the real lock;
        # only the connection-level bodies they delegate to are faked out.
        monkeypatch.setattr(
            sync_module, "_run_full_rebuild_on_locked_connection", fake_rebuild_body
        )
        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", fake_sync_body)

        rebuild_task = asyncio.create_task(
            scheduler_module.rebuild_and_invalidate(pool, catalogue_stats_cache, selected_source)
        )
        await rebuild_started.wait()

        sync_task = asyncio.create_task(
            scheduler_module.sync_and_invalidate(pool, catalogue_stats_cache, incremental_source)
        )
        await _wait_until_registered_as_a_waiter(sync_module._sync_mutex)

        assert "sync" not in order
        assert order == []
        assert sync_module._sync_mutex.locked() is True

        release.set()
        await asyncio.gather(rebuild_task, sync_task)

        assert order == ["rebuild", "sync"]
        assert catalogue_stats_cache.invalidate_cache.call_count == _EXPECTED_INVALIDATION_COUNT
        assert sync_module._sync_mutex.locked() is False

    async def test_cache_invalidation_runs_after_the_lock_is_released(self, monkeypatch):
        """Check cache invalidation runs after the lock is released."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        selected_source = legacy_source()
        lock_held_in_body = []
        invalidate_count_in_body = []

        def invalidate_after_unlock():
            """Require cache invalidation to occur after mutex release."""
            assert sync_module._sync_mutex.locked() is False

        catalogue_stats_cache.invalidate_cache.side_effect = invalidate_after_unlock

        async def fake_sync_body(_connection, *, configured_source):
            """Record mutex ownership and cache invalidation count inside the selected sync body."""
            assert configured_source is selected_source
            lock_held_in_body.append(sync_module._sync_mutex.locked())
            invalidate_count_in_body.append(catalogue_stats_cache.invalidate_cache.call_count)

        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", fake_sync_body)

        await scheduler_module.sync_and_invalidate(
            MagicMock(),
            catalogue_stats_cache,
            selected_source,
        )

        assert lock_held_in_body == [True]
        assert invalidate_count_in_body == [0]
        catalogue_stats_cache.invalidate_cache.assert_called_once()
        assert sync_module._sync_mutex.locked() is False

    async def test_mutex_is_released_and_usable_after_a_failing_rebuild(self, monkeypatch):
        """Check mutex is released and usable after a failing rebuild (RuntimeError)."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        selected_source = legacy_source()

        async def failing_rebuild_body(_connection, *, configured_source):
            """Check the selected source and raise an injected harvest failure."""
            assert configured_source is selected_source
            raise RuntimeError("harvest exploded")

        monkeypatch.setattr(
            sync_module, "_run_full_rebuild_on_locked_connection", failing_rebuild_body
        )

        with pytest.raises(RuntimeError, match="harvest exploded"):
            await scheduler_module.rebuild_and_invalidate(
                MagicMock(),
                catalogue_stats_cache,
                selected_source,
            )

        assert sync_module._sync_mutex.locked() is False
        catalogue_stats_cache.invalidate_cache.assert_called_once()

        ran = []

        async def ok_sync_body(_connection, *, configured_source):
            """Check the selected source and record successful sync execution."""
            assert configured_source is selected_source
            ran.append("sync")

        monkeypatch.setattr(sync_module, "_run_sync_on_locked_connection", ok_sync_body)
        await scheduler_module.sync_and_invalidate(
            MagicMock(),
            catalogue_stats_cache,
            selected_source,
        )
        assert ran == ["sync"]
        assert catalogue_stats_cache.invalidate_cache.call_count == _EXPECTED_INVALIDATION_COUNT
        assert sync_module._sync_mutex.locked() is False


class TestSyncAndInvalidateEscalatesTheTypedRecoverySignal:
    """Cover sync and invalidate escalates the typed recovery signal."""

    async def test_a_typed_recovery_outcome_escalates_to_exactly_one_full_rebuild(
        self, monkeypatch
    ):
        """Check a typed recovery outcome escalates to exactly one full rebuild."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        selected_source = legacy_source()
        pool = MagicMock()
        recovery_outcome = sync_module.SyncOutcome(
            "failed",
            # A reason that would fool naive substring matching on "success"
            # if the escalation were driven by text instead of the flag.
            reason="looks like success but is not",
            requires_full_rebuild=True,
        )
        rebuild_outcome = sync_module.SyncOutcome("success", affected_count=5)
        run_sync = create_autospec(
            sync_module.run_sync,
            return_value=recovery_outcome,
        )
        monkeypatch.setattr(scheduler_module, "run_sync", run_sync)
        run_full_rebuild = create_autospec(
            sync_module.run_full_rebuild, return_value=rebuild_outcome
        )
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(
            pool,
            catalogue_stats_cache,
            selected_source,
        )

        run_sync.assert_awaited_once_with(
            pool,
            configured_source=selected_source,
        )
        run_full_rebuild.assert_awaited_once_with(
            pool,
            configured_source=selected_source,
        )
        assert result == rebuild_outcome
        catalogue_stats_cache.invalidate_cache.assert_called_once()

    async def test_an_ordinary_failure_without_the_recovery_flag_does_not_escalate(
        self, monkeypatch
    ):
        """Check an ordinary failure without the recovery flag does not escalate."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        selected_source = legacy_source()
        pool = MagicMock()
        ordinary_failure = sync_module.SyncOutcome("failed", reason="fetch timed out")
        monkeypatch.setattr(
            scheduler_module,
            "run_sync",
            create_autospec(sync_module.run_sync, return_value=ordinary_failure),
        )
        run_full_rebuild = create_autospec(sync_module.run_full_rebuild)
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(
            pool,
            catalogue_stats_cache,
            selected_source,
        )

        run_full_rebuild.assert_not_awaited()
        assert result == ordinary_failure
        catalogue_stats_cache.invalidate_cache.assert_called_once()

    async def test_an_ordinary_success_does_not_escalate(self, monkeypatch):
        """Check an ordinary success does not escalate."""
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        selected_source = legacy_source()
        pool = MagicMock()
        ordinary_success = sync_module.SyncOutcome("success", affected_count=2)
        monkeypatch.setattr(
            scheduler_module,
            "run_sync",
            create_autospec(sync_module.run_sync, return_value=ordinary_success),
        )
        run_full_rebuild = create_autospec(sync_module.run_full_rebuild)
        monkeypatch.setattr(scheduler_module, "run_full_rebuild", run_full_rebuild)

        result = await scheduler_module.sync_and_invalidate(
            pool,
            catalogue_stats_cache,
            selected_source,
        )

        run_full_rebuild.assert_not_awaited()
        assert result == ordinary_success
        catalogue_stats_cache.invalidate_cache.assert_called_once()


class TestAsyncIOSchedulerExecutesCoroutineJobs:
    """An AsyncIOScheduler must actually AWAIT coroutine jobs."""

    async def test_maintenance_and_delivery_jobs_run_almost_immediately(self, monkeypatch):
        """session_cleanup and email_outbox_delivery are registered with
        next_run_time=now, so a started scheduler must execute both almost
        immediately.
        """
        cleanup_ran = asyncio.Event()
        delivery_ran = asyncio.Event()
        selected_source = legacy_source()

        async def record_cleanup(*_args) -> None:
            """Signal maintenance-job execution."""
            cleanup_ran.set()

        async def record_delivery(*_args) -> None:
            """Signal delivery-job execution."""
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
            (selected_source,),
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
    """Source-specific ingestion jobs share one tracker and global maintenance."""

    @staticmethod
    def _sources() -> tuple[ConfiguredSource, ...]:
        """Build online and offline sources with distinct scheduling intervals."""
        online = legacy_source(
            schedule=SourceSchedule(
                incremental_interval_seconds=17,
                rebuild_interval_seconds=41,
                write_timeout_seconds=119,
            )
        )
        offline = configure_sources(
            (
                FixtureConfig(
                    name="offline_archive",
                    display=SourceDisplay(label="Offline archive"),
                    schedule=SourceSchedule(
                        incremental_interval_seconds=23,
                        rebuild_interval_seconds=59,
                        write_timeout_seconds=113,
                    ),
                ),
            )
        )[0]
        return online, offline

    def test_registers_asyncio_scheduler_with_the_exact_job_id_set(self):
        """Check registers asyncio scheduler with the exact job ID set."""
        running_jobs = RunningJobTracker()
        sources = self._sources()
        scheduler = create_scheduler(
            _scheduler_pool_mock(),
            make_mock_catalogue_stats_cache(),
            running_jobs,
            sources,
        )
        assert isinstance(scheduler, AsyncIOScheduler)

        jobs = scheduler.get_jobs()
        assert len(jobs) == 8
        assert {job.id for job in jobs} == {
            "email_outbox_delivery",
            "outbox_retention",
            f"incremental_sync:{sources[0].name}",
            f"full_rebuild:{sources[0].name}",
            "incremental_sync:offline_archive",
            "full_rebuild:offline_archive",
            "session_cleanup",
            "reap_unverified",
        }
        for job in jobs:
            assert job.max_instances == 1, f"{job.id} lost its self-overlap guard"

        by_id = {job.id: job for job in jobs}
        assert by_id["email_outbox_delivery"].next_run_time is not None
        assert by_id["session_cleanup"].next_run_time is not None

        first_run = by_id[f"incremental_sync:{sources[0].name}"].next_run_time
        assert first_run is not None
        for position, source in enumerate(sources, start=1):
            incremental = by_id[f"incremental_sync:{source.name}"]
            rebuild = by_id[f"full_rebuild:{source.name}"]
            assert incremental.next_run_time == first_run
            assert rebuild.next_run_time - first_run == timedelta(minutes=5 * position)

        ingestion_ids = [
            job.id for job in jobs if job.id.startswith(("incremental_sync:", "full_rebuild:"))
        ]
        assert ingestion_ids == [
            f"incremental_sync:{sources[0].name}",
            f"full_rebuild:{sources[0].name}",
            "incremental_sync:offline_archive",
            "full_rebuild:offline_archive",
        ]

    def test_binds_the_correct_callable_args_and_intervals_per_job(self):
        """Check binds the correct callable args and intervals per job."""
        pool = _scheduler_pool_mock()
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        running_jobs = RunningJobTracker()
        sources = self._sources()
        scheduler = create_scheduler(pool, catalogue_stats_cache, running_jobs, sources)
        jobs = {job.id: job for job in scheduler.get_jobs()}

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
        assert jobs["email_outbox_delivery"].coalesce is True

        for source in sources:
            incremental_id = f"incremental_sync:{source.name}"
            rebuild_id = f"full_rebuild:{source.name}"
            assert jobs[incremental_id].args == (
                incremental_id,
                scheduler_module.sync_and_invalidate,
                pool,
                catalogue_stats_cache,
                source,
            )
            assert jobs[rebuild_id].args == (
                rebuild_id,
                scheduler_module.rebuild_and_invalidate,
                pool,
                catalogue_stats_cache,
                source,
            )
            assert jobs[incremental_id].args[-1] is source
            assert jobs[rebuild_id].args[-1] is source
            assert _interval_seconds(jobs[incremental_id]) == (
                source.schedule.incremental_interval_seconds
            )
            assert _interval_seconds(jobs[rebuild_id]) == source.schedule.rebuild_interval_seconds
            assert jobs[incremental_id].name == f"{source.display.label} incremental sync"
            assert jobs[rebuild_id].name == f"{source.display.label} full rebuild"

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
        assert _interval_seconds(jobs["session_cleanup"]) == _SESSION_CLEANUP_INTERVAL_SECONDS
        assert _interval_seconds(jobs["reap_unverified"]) == _UNVERIFIED_REAP_INTERVAL_SECONDS

    @pytest.mark.parametrize("duplicate", [False, True], ids=["empty", "duplicate-name"])
    def test_invalid_source_sets_fail_before_scheduler_construction(self, duplicate, monkeypatch):
        """Check invalid source sets fail before scheduler construction (ValueError)."""
        source = legacy_source()
        sources = (source, source) if duplicate else ()
        constructor = create_autospec(AsyncIOScheduler)
        monkeypatch.setattr(scheduler_module, "AsyncIOScheduler", constructor)

        with pytest.raises(ValueError):
            create_scheduler(
                _scheduler_pool_mock(),
                make_mock_catalogue_stats_cache(),
                RunningJobTracker(),
                sources,
            )

        constructor.assert_not_called()

    async def test_registered_ingestion_jobs_deliver_each_selected_snapshot(self, monkeypatch):
        """Check registered ingestion jobs deliver each selected snapshot."""
        sources = self._sources()
        pool = _scheduler_pool_mock()
        catalogue_stats_cache = make_mock_catalogue_stats_cache()
        running_jobs = RunningJobTracker()
        outcome = sync_module.SyncOutcome("success")
        incremental = create_autospec(scheduler_module.sync_and_invalidate, return_value=outcome)
        rebuild = create_autospec(scheduler_module.rebuild_and_invalidate, return_value=outcome)
        monkeypatch.setattr(scheduler_module, "sync_and_invalidate", incremental)
        monkeypatch.setattr(scheduler_module, "rebuild_and_invalidate", rebuild)
        scheduler = create_scheduler(pool, catalogue_stats_cache, running_jobs, sources)

        for source in sources:
            for operation in ("incremental_sync", "full_rebuild"):
                job = scheduler.get_job(f"{operation}:{source.name}")
                assert job is not None
                assert await job.func(*job.args, **job.kwargs) is outcome

        assert incremental.await_count == 2
        assert rebuild.await_count == 2
        for index, source in enumerate(sources):
            assert incremental.await_args_list[index].args == (pool, catalogue_stats_cache, source)
            assert rebuild.await_args_list[index].args == (pool, catalogue_stats_cache, source)
            assert incremental.await_args_list[index].args[-1] is source
            assert rebuild.await_args_list[index].args[-1] is source
        assert running_jobs.active_job_ids == ()


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
    """Select scheduler log records with the requested severity."""
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
        """Check missed event logs a warning."""
        with caplog.at_level(logging.INFO, logger="app.services.scheduler"):
            scheduler_module._on_scheduler_event(_job_event(EVENT_JOB_MISSED))

        warnings = _events_for_level(caplog, logging.WARNING)
        assert any(getattr(r, "event_type", None) == "scheduler_job_missed" for r in warnings)

    @pytest.mark.parametrize("status", ["success", "partial", "failed"])
    def test_executed_event_with_a_sync_outcome_reports_the_ingestion_status(self, status, caplog):
        """Check executed event with a sync outcome reports the ingestion status."""
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
            """Signal job entry and wait for the test release event."""
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
            """Raise an injected scheduler-job failure."""
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
            """Signal job entry and wait indefinitely for cancellation."""
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
