"""Development Uvicorn launcher; deployed services use systemd (Deployment.md)."""

import logging
import sys

import uvicorn

from config import settings


def start_server() -> None:
    """Run the reload-enabled server using FASTAPI_HOST/PORT; exit 1 outside dev."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger(__name__)

    if settings.is_hardened:
        logger.error(
            "run.py is a dev-only launcher (ENV_STATE=%s). Follow Deployment.md's reviewed "
            "migration workflow, then start oralhistarchiv.service and "
            "oralhistarchiv-scheduler.service via systemd.",
            settings.env_state,
        )
        sys.exit(1)

    logger.info(
        "Starting development server on %s:%s",
        settings.fastapi_host,
        settings.fastapi_port,
    )
    uvicorn.run(
        "app.main:app",
        host=settings.fastapi_host,
        port=settings.fastapi_port,
        reload=True,
    )


if __name__ == "__main__":
    start_server()
