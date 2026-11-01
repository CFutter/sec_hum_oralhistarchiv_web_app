"""Background scheduler for periodic sync and maintenance tasks.

Runs independently of user traffic in a dedicated process (run_scheduler.py),
rather than piggybacking sync work on user requests.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
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

from app.sources import ConfiguredSource
from config import settings

from .cache import CatalogueStatsCache
from .email_delivery import deliver_email_outbox_batch
from .ingestion import SyncOutcome, run_full_rebuild, run_sync
from .outbox_maintenance import purge_terminal_emails
from .sessions import cleanup_expired_sessions
from .users import reap_unverified_accounts

logger = logging.getLogger(__name__)

_EMAIL_OUTBOX_INTERVAL_SECONDS = 15
_SESSION_CLEANUP_INTERVAL_SECONDS = 3600  # 1 hour
_MIN_SCHEDULER_POOL_SIZE = 2
_SOURCE_REBUILD_STAGGER_MINUTES = 5
_UNVERIFIED_REAP_INTERVAL_HOURS = 1
_UNVERIFIED_REAP_INITIAL_DELAY_MINUTES = 10
_OUTBOX_RETENTION_INITIAL_DELAY_SECONDS = 30


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
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Run incremental sync, rebuilding only an already approved source binding.

    Always invalidate statistics in a threadpool, including on failure;
    return the final SyncOutcome and propagate errors.
    """
    try:
        outcome = await run_sync(pool, configured_source=configured_source)
        if isinstance(outcome, SyncOutcome) and outcome.requires_source_acknowledgement:
            logger.error(
                "Source configuration changed; operator acknowledgement is required",
                extra={
                    "event_type": "source_binding_review_required",
                    "source": configured_source.name,
                },
            )
            return outcome
        if isinstance(outcome, SyncOutcome) and outcome.requires_full_rebuild:
            logger.warning(
                "Incremental sync requires an authoritative full rebuild; starting it now",
                extra={
                    "event_type": "ingestion_full_rebuild_fallback",
                    "source": configured_source.name,
                    "reason": outcome.reason,
                },
            )
            return await run_full_rebuild(pool, configured_source=configured_source)
        return outcome
    finally:
        await run_in_threadpool(catalogue_stats_cache.invalidate_cache)


async def rebuild_and_invalidate(
    pool: AsyncConnectionPool,
    catalogue_stats_cache: CatalogueStatsCache,
    configured_source: ConfiguredSource,
) -> SyncOutcome:
    """Return the rebuild outcome and always invalidate
    statistics in a threadpool; errors propagate.
    """
    try:
        return await run_full_rebuild(pool, configured_source=configured_source)
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
    configured_sources: Sequence[ConfiguredSource],
) -> AsyncIOScheduler:
    """Return an unstarted UTC scheduler for a nonempty, uniquely named source set.

    Require pool.max_size >= 2. Every job uses running_jobs and max_instances=1.
    Each source gets an immediate incremental job and its own configured
    intervals. Initial rebuilds start five minutes apart in configuration order.
    The existing global ingestion locks continue to serialize all sources.

    Global maintenance runs once: delivery immediately/every 15 seconds;
    session cleanup immediately/hourly; account reaping after ten minutes/hourly;
    retention after 30 seconds/every OUTBOX_RETENTION_INTERVAL_SECONDS.
    Delivery and retention coalesce missed runs. Callers start/stop the scheduler.
    """
    if pool.max_size < _MIN_SCHEDULER_POOL_SIZE:
        raise RuntimeError(
            "Scheduler requires a database pool with max_size >= 2: "
            "one connection is reserved for ingestion while other "
            "maintenance jobs remain able to run."
        )

    sources = tuple(configured_sources)
    if not sources:
        raise ValueError("At least one source must be configured")
    if len({source.name for source in sources}) != len(sources):
        raise ValueError("Configured source names must be unique")

    scheduler = AsyncIOScheduler(timezone="UTC")
    now = datetime.now(UTC)

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
        next_run_time=now,
    )

    for position, configured_source in enumerate(sources, start=1):
        incremental_job_id = f"incremental_sync:{configured_source.name}"
        rebuild_job_id = f"full_rebuild:{configured_source.name}"

        scheduler.add_job(
            running_jobs.run,
            "interval",
            seconds=configured_source.schedule.incremental_interval_seconds,
            args=[
                incremental_job_id,
                sync_and_invalidate,
                pool,
                catalogue_stats_cache,
                configured_source,
            ],
            id=incremental_job_id,
            name=f"{configured_source.display.label} incremental sync",
            max_instances=1,
            next_run_time=now,
        )

        scheduler.add_job(
            running_jobs.run,
            "interval",
            seconds=configured_source.schedule.rebuild_interval_seconds,
            args=[
                rebuild_job_id,
                rebuild_and_invalidate,
                pool,
                catalogue_stats_cache,
                configured_source,
            ],
            id=rebuild_job_id,
            name=f"{configured_source.display.label} full rebuild",
            max_instances=1,
            next_run_time=now + timedelta(minutes=_SOURCE_REBUILD_STAGGER_MINUTES * position),
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
        next_run_time=now,
    )

    scheduler.add_job(
        running_jobs.run,
        "interval",
        hours=_UNVERIFIED_REAP_INTERVAL_HOURS,
        args=[
            "reap_unverified",
            reap_unverified_accounts,
            pool,
        ],
        id="reap_unverified",
        name="Reap unverified accounts",
        max_instances=1,
        next_run_time=now + timedelta(minutes=_UNVERIFIED_REAP_INITIAL_DELAY_MINUTES),
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
        next_run_time=now + timedelta(seconds=_OUTBOX_RETENTION_INITIAL_DELAY_SECONDS),
    )
    scheduler.add_listener(
        _on_scheduler_event,
        EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED,
    )

    return scheduler
