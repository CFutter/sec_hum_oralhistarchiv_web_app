"""Run background jobs once per deployment: python run_scheduler.py.

Production uses oralhistarchiv-scheduler.service; do not run a scheduler in
each web worker.
"""

import asyncio
import logging
import signal

from app.middleware.validators import validate_security_settings
from app.runtime_preflight import validate_runtime_schema
from app.services import (
    CatalogueStatsCache,
    RunningJobTracker,
    build_catalogue_policy,
    create_pool,
    create_scheduler,
    ensure_source_status_rows,
    load_runtime_sources,
)
from app.sources import validate_parser_service
from config import settings, setup_logging

logger = logging.getLogger(__name__)

# Paired with TimeoutStopSec=330s in oralhistarchiv-scheduler.service.
# The deployment contract test reserves 25 seconds beyond both phases.
_JOB_DRAIN_TIMEOUT_SECONDS = 300
_JOB_CANCELLATION_GRACE_SECONDS = 5


async def main() -> None:
    """Validate settings/schema, run scheduled jobs, and wait for SIGINT/SIGTERM.

    Requires an event loop with signal-handler support. Opens PostgreSQL;
    jobs perform ingestion, mail delivery and cleanup.
    Shutdown allows 300 seconds to drain and 5 seconds after cancellation, then
    closes the cache and pool. Startup/database errors propagate.
    """
    setup_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
    )

    # The scheduler can write harvested metadata and drain encrypted action
    # email independently of the web process. Reject unsafe configuration
    # before opening PostgreSQL or allowing any job to be constructed.
    if settings.env_state != "dev" and settings.app_process_role != "scheduler":
        raise RuntimeError("Scheduler runtime requires APP_PROCESS_ROLE=scheduler")
    validate_security_settings()
    validate_parser_service(environment=settings.env_state, mode=settings.parser_execution_mode)
    configured_sources = load_runtime_sources()

    pool = create_pool(
        application_name="oralhistarchiv-scheduler",
        statement_timeout=settings.scheduler_statement_timeout,
    )
    await pool.open()

    catalogue_stats_cache: CatalogueStatsCache | None = None

    try:
        await validate_runtime_schema(pool, process="scheduler")
        await ensure_source_status_rows(
            pool,
            tuple(source.name for source in configured_sources),
        )

        catalogue_stats_cache = CatalogueStatsCache(
            pool,
            source_names=tuple(source.name for source in configured_sources),
            policy_fingerprint=build_catalogue_policy(configured_sources).fingerprint,
            subscribe=False,
        )
        running_jobs = RunningJobTracker()
        scheduler = create_scheduler(
            pool,
            catalogue_stats_cache,
            running_jobs,
            configured_sources,
        )

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop_event.set)

        scheduler.start()
        logger.info("Scheduler started")

        try:
            await stop_event.wait()
        finally:
            logger.info("Shutting down scheduler")

            try:
                # Prevent APScheduler from submitting additional jobs while
                # already-submitted jobs finish normally.
                scheduler.pause()

                try:
                    async with asyncio.timeout(_JOB_DRAIN_TIMEOUT_SECONDS):
                        await running_jobs.wait_until_empty()
                except TimeoutError:
                    logger.warning(
                        "Scheduled jobs did not finish before the shutdown "
                        "deadline; forcing cancellation. Active jobs: %s",
                        running_jobs.active_job_ids,
                    )
            finally:
                # APScheduler cancellation happens here, after the normal
                # completion window. wait=False is required because this
                # synchronous method cannot drain coroutine jobs from their
                # own event loop.
                scheduler.shutdown(wait=False)

                # AsyncIOScheduler schedules its shutdown callback onto this
                # event loop. Give cancellation a bounded opportunity to run
                # job finally-blocks before closing their database pool.
                try:
                    async with asyncio.timeout(_JOB_CANCELLATION_GRACE_SECONDS):
                        await running_jobs.wait_until_empty()
                except TimeoutError:
                    logger.exception(
                        "Cancelled scheduled jobs did not stop within the "
                        "cancellation grace period. Active jobs: %s",
                        running_jobs.active_job_ids,
                    )
    finally:
        try:
            if catalogue_stats_cache is not None:
                catalogue_stats_cache.stop()
        finally:
            await pool.close()

    logger.info("Scheduler stopped")


if __name__ == "__main__":
    asyncio.run(main())
