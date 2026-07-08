"""Entry point for the application server.

In development (is_production == False): runs uvicorn with auto-reload.
In production: runs gunicorn with the production config file.
"""

import sys
import logging
import uvicorn
import gunicorn.app.wsgiapp

from config import settings
from app.paths import GUNICORN_CONF

def start_server() -> None:
    """Launch the appropriate server based on environment."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger(__name__)


    if settings.is_production:
        logger.info("Starting production server via Gunicorn")
        sys.argv = [
            "gunicorn",
            "--config", str(GUNICORN_CONF),
            "app.main:app",
        ]
        gunicorn.app.wsgiapp.run()

    else:
        logger.info(
            "Starting development server on %s:%s",
            settings.fastapi_host, settings.fastapi_port,
        )
        uvicorn.run(
            "app.main:app",
            host=settings.fastapi_host,
            port=settings.fastapi_port,
            reload=True,
        )
        

if __name__ == "__main__":
    start_server()