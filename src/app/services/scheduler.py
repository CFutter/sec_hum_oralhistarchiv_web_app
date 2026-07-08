"""Background scheduler for periodic sync and maintenance tasks.

Runs independently of user traffic in a dedicated process (run_scheduler.py),
rather than piggybacking sync work on user requests.
"""

import logging
from datetime import datetime, timedelta, timezone
import asyncio

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.events import (
    EVENT_JOB_EXECUTED,
    EVENT_JOB_ERROR,
    EVENT_JOB_MISSED,
)
from psycopg_pool import AsyncConnectionPool

from .cache import FacetCache
from .sync import run_sync, run_full_rebuild
from .sessions import cleanup_expired_sessions
from .users import reap_unverified_accounts

from config import settings

logger = logging.getLogger(__name__)


_SESSION_CLEANUP_INTERVAL_SECONDS = 3600  # 1 hour

# Serializes incremental sync and full rebuild so they can't interleave: a
# concurrent incremental DELETE of a tombstoned uuid + the rebuild re-inserting
# that uuid from its pre-deletion snapshot would resurrect a deleted record
# (until the next rebuild, up to 24h). In-process lock is sufficient because both
# jobs run on the one event loop in the dedicated scheduler process. If a second
# scheduler instance ever runs (HA), upgrade to pg_try_advisory_lock.
_sync_mutex = asyncio.Lock()

def _on_scheduler_event(event) -> None:
    """Emit structured logs for scheduled job lifecycle events.
    
    Listens for EXECUTED (success), ERROR (raised exception), and
    MISSED (scheduled time passed without execution). Without this,
    scheduler health is invisible until something explicitly breaks.
    """
    job_id = event.job_id
    scheduled_run = (
        event.scheduled_run_time.isoformat() 
        if event.scheduled_run_time else None
    )
    
    if event.code == EVENT_JOB_EXECUTED:
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
                "exception_type": (
                    type(event.exception).__name__ 
                    if event.exception else None
                ),
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


async def sync_and_invalidate(pool: AsyncConnectionPool, facet_cache: FacetCache) -> None:
    """Run incremental sync and clear the facet cache."""
    async with _sync_mutex:
        await run_sync(pool)
    facet_cache.invalidate_cache()


async def rebuild_and_invalidate(pool: AsyncConnectionPool, facet_cache: FacetCache) -> None:
    """Run full rebuild and clear the facet cache."""
    async with _sync_mutex:
        await run_full_rebuild(pool)
    facet_cache.invalidate_cache()

def create_scheduler(pool: AsyncConnectionPool, facet_cache: FacetCache) -> AsyncIOScheduler:
    """Create and configure the background scheduler.

    Jobs:
    - Incremental sync: runs every sync_interval_seconds
    - Full rebuild: runs every full_rebuild_interval_seconds
    - Session cleanup: runs every hour
    - Reap unverified accounts: runs every 24 hours
    
    A lifecycle listener emits structured logs for job executions,
    errors, and missed runs.
    """

    scheduler = AsyncIOScheduler(timezone="UTC")

    scheduler.add_job(
        sync_and_invalidate,
        "interval",
        seconds=settings.sync_interval_seconds,
        args=[pool, facet_cache],
        id="incremental_sync",
        name="OAI-PMH incremental sync",
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    scheduler.add_job(
        rebuild_and_invalidate,
        "interval",
        seconds=settings.full_rebuild_interval_seconds,
        args=[pool, facet_cache],
        id="full_rebuild",
        name="OAI-PMH full rebuild",
        max_instances=1,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    scheduler.add_job(
        cleanup_expired_sessions,
        "interval",
        seconds=_SESSION_CLEANUP_INTERVAL_SECONDS,
        args=[pool],
        id="session_cleanup",
        name="Expired session cleanup",
        max_instances=1,
        next_run_time=datetime.now(timezone.utc),
    )

    scheduler.add_job(
        reap_unverified_accounts,
        "interval",
        hours=24,
        args=[pool],
        id="reap_unverified",
        name="Reap unverified accounts",
        max_instances=1,
    )

    scheduler.add_listener(
        _on_scheduler_event,
        EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED,
    )

    return scheduler