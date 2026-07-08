"""Standalone scheduler entry point.

Runs the APScheduler-driven background jobs in a dedicated process,
separate from gunicorn workers. This prevents the scheduler from
running once per worker (which would multiply sync calls by 4).

Usage:
    python run_scheduler.py

Or via systemd: see oralhistarchiv-scheduler.service
"""
import logging
import signal
import asyncio

from config import settings, setup_logging
from app.services import create_pool, create_scheduler, FacetCache

logger = logging.getLogger(__name__)


async def main() -> None:
    setup_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
    )
    
    pool = create_pool(application_name="oralhistarchiv-scheduler")
    await pool.open()
    facet_cache = FacetCache(pool)
    scheduler = create_scheduler(pool, facet_cache)

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
        scheduler.shutdown(wait=True)          
        await pool.close()
        logger.info("Scheduler stopped")


if __name__ == "__main__":
    asyncio.run(main())