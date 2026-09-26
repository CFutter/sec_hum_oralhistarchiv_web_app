"""Background scheduler for periodic sync and maintenance tasks.

Runs independently of user traffic in a dedicated process (run_scheduler.py),
rather than piggybacking sync work on user requests.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from apscheduler.events import (
    EVENT_JOB_ERROR,
    EVENT_JOB_EXECUTED,
    EVENT_JOB_MISSED,
    JobExecutionEvent,
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from psycopg_pool import AsyncConnectionPool
from starlette.concurrency import run_in_threadpool

from config import settings

from .cache import CatalogueStatsCache
from .email_delivery import deliver_email_outbox_batch
from .outbox_maintenance import purge_terminal_emails
from .sessions import cleanup_expired_sessions
from .sync import SyncOutcome, run_full_rebuild, run_sync
from .users import reap_unverified_accounts

logger = logging.getLogger(__name__)

_EMAIL_OUTBOX_INTERVAL_SECONDS = 15
_SESSION_CLEANUP_INTERVAL_SECONDS = 3600  # 1 hour
_MIN_SCHEDULER_POOL_SIZE = 2


class RunningJobTracker:
    """Track every APScheduler coroutine currently running.

    All access occurs on the scheduler's event loop, so no additional lock is
    needed. Job exceptions propagate unchanged to APScheduler after the job
    has been removed from the active set.
    """

    def __init__(self) -> None:
        """Initialize an empty tracker in its owning event loop."""
        self._running: dict[object, str] = {}
        self._idle = asyncio.Event()
        self._idle.set()

    @property
    def active_job_ids(self) -> tuple[str, ...]:
        """Return active job IDs for shutdown-time diagnostics."""
        return tuple(sorted(self._running.values()))

    async def run(
        self,
        job_id: str,
        job: Callable[..., Awaitable[object]],
        *args: object,
    ) -> object:
        """Run one scheduled callable while tracking its complete lifetime."""
        token = object()
        self._running[token] = job_id
        self._idle.clear()

        try:
            return await job(*args)
        finally:
            del self._running[token]
            if not self._running:
                self._idle.set()

    async def wait_until_empty(self) -> None:
        """Wait until every submitted scheduled job has finished.

        The event-loop yield handles a job task that APScheduler submitted
        immediately before scheduling was paused but which has not yet entered
        run().
        """
        while True:
            await self._idle.wait()
            await asyncio.sleep(0)
            if not self._running:
                return


async def sync_and_invalidate(
    pool: AsyncConnectionPool,
    catalogue_stats_cache: CatalogueStatsCache,
) -> SyncOutcome:
    """Run incremental sync, immediately rebuilding when requested by its outcome.

    Always invalidate statistics in a threadpool, including on failure;
    return the final SyncOutcome and propagate errors.
    """
    try:
        outcome = await run_sync(pool)
        if isinstance(outcome, SyncOutcome) and outcome.requires_full_rebuild:
            logger.warning(
                "Incremental sync requires an authoritative full rebuild; starting it now",
                extra={
                    "event_type": "ingestion_full_rebuild_fallback",
                    "reason": outcome.reason,
                },
            )
            return await run_full_rebuild(pool)
        return outcome
    finally:
        await run_in_threadpool(catalogue_stats_cache.invalidate_cache)


async def rebuild_and_invalidate(
    pool: AsyncConnectionPool,
    catalogue_stats_cache: CatalogueStatsCache,
) -> SyncOutcome:
    """Return the rebuild outcome and always invalidate
    statistics in a threadpool; errors propagate.
    """
    try:
        return await run_full_rebuild(pool)
    finally:
        await run_in_threadpool(catalogue_stats_cache.invalidate_cache)


def _on_scheduler_event(event: JobExecutionEvent) -> None:
    """Log success, typed ingestion outcomes, errors, or missed runs; ignore other event codes."""
    job_id = event.job_id
    scheduled_run = event.scheduled_run_time.isoformat() if event.scheduled_run_time else None

    if event.code == EVENT_JOB_EXECUTED:
        if isinstance(event.retval, SyncOutcome):
            outcome = event.retval
            level = logging.INFO if outcome.status == "success" else logging.WARNING
            logger.log(
                level,
                "Ingestion job %s: %s",
                job_id,
                outcome.status,
                extra={
                    "event_type": "ingestion_job_outcome",
                    "job_id": job_id,
                    "scheduled_run_time": scheduled_run,
                    "status": outcome.status,
                    "affected_count": outcome.affected_count,
                    "failed_count": outcome.failed_count,
                    "reason": outcome.reason,
                    "requires_full_rebuild": outcome.requires_full_rebuild,
                },
            )
            return
        logger.info(
            "Scheduled job completed: %s",
            job_id,
            extra={
                "event_type": "scheduler_job_executed",
                "job_id": job_id,
                "scheduled_run_time": scheduled_run,
            },
        )
    elif event.code == EVENT_JOB_ERROR:
        logger.error(
            "Scheduled job failed: %s",
            job_id,
            extra={
                "event_type": "scheduler_job_error",
                "job_id": job_id,
                "scheduled_run_time": scheduled_run,
                "exception_type": (type(event.exception).__name__ if event.exception else None),
            },
            exc_info=event.exception if event.exception else None,
        )

    elif event.code == EVENT_JOB_MISSED:
        logger.warning(
            "Scheduled job missed its run time: %s",
            job_id,
            extra={
                "event_type": "scheduler_job_missed",
                "job_id": job_id,
                "scheduled_run_time": scheduled_run,
            },
        )


def create_scheduler(
    pool: AsyncConnectionPool,
    catalogue_stats_cache: CatalogueStatsCache,
    running_jobs: RunningJobTracker,
) -> AsyncIOScheduler:
    """Return an unstarted UTC scheduler; require pool.max_size >= 2 or raise RuntimeError.

    All jobs use running_jobs and max_instances=1. Delivery runs immediately
    and every 15 seconds; incremental sync immediately and every
    SYNC_INTERVAL_SECONDS; rebuild after five minutes and every
    FULL_REBUILD_INTERVAL_SECONDS; session cleanup immediately/hourly;
    unverified-account reaping after ten minutes/hourly; retention after
    30 seconds and every OUTBOX_RETENTION_INTERVAL_SECONDS. Delivery and
    retention explicitly coalesce missed runs. Callers start/stop the scheduler.
    """
    if pool.max_size < _MIN_SCHEDULER_POOL_SIZE:
        raise RuntimeError(
            "Scheduler requires a database pool with max_size >= 2: "
            "one connection is reserved for ingestion while other "
            "maintenance jobs remain able to run."
        )

    scheduler = AsyncIOScheduler(timezone="UTC")

    scheduler.add_job(
        running_jobs.run,
        "interval",
        seconds=_EMAIL_OUTBOX_INTERVAL_SECONDS,
        args=[
            "email_outbox_delivery",
            deliver_email_outbox_batch,
            pool,
        ],
        id="email_outbox_delivery",
        name="Transactional email outbox delivery",
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(UTC),
    )

    scheduler.add_job(
        running_jobs.run,
        "interval",
        seconds=settings.sync_interval_seconds,
        args=[
            "incremental_sync",
            sync_and_invalidate,
            pool,
            catalogue_stats_cache,
        ],
        id="incremental_sync",
        name="OAI-PMH incremental sync",
        max_instances=1,
        next_run_time=datetime.now(UTC),
    )

    scheduler.add_job(
        running_jobs.run,
        "interval",
        seconds=settings.full_rebuild_interval_seconds,
        args=[
            "full_rebuild",
            rebuild_and_invalidate,
            pool,
            catalogue_stats_cache,
        ],
        id="full_rebuild",
        name="OAI-PMH full rebuild",
        max_instances=1,
        next_run_time=datetime.now(UTC) + timedelta(minutes=5),
    )

    scheduler.add_job(
        running_jobs.run,
        "interval",
        seconds=_SESSION_CLEANUP_INTERVAL_SECONDS,
        args=[
            "session_cleanup",
            cleanup_expired_sessions,
            pool,
        ],
        id="session_cleanup",
        name="Expired session cleanup",
        max_instances=1,
        next_run_time=datetime.now(UTC),
    )

    scheduler.add_job(
        running_jobs.run,
        "interval",
        hours=1,
        args=[
            "reap_unverified",
            reap_unverified_accounts,
            pool,
        ],
        id="reap_unverified",
        name="Reap unverified accounts",
        max_instances=1,
        next_run_time=datetime.now(UTC) + timedelta(minutes=10),
    )
    scheduler.add_job(
        running_jobs.run,
        "interval",
        seconds=settings.outbox_retention_interval_seconds,
        args=["outbox_retention", purge_terminal_emails, pool],
        id="outbox_retention",
        name="Terminal email outbox retention",
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(UTC) + timedelta(seconds=30),
    )
    scheduler.add_listener(
        _on_scheduler_event,
        EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED,
    )

    return scheduler
