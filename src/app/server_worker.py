"""Gunicorn's pinned Uvicorn worker with safe import and lifespan error boundaries."""

import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send
from uvicorn_worker import UvicornWorker  # type: ignore[import-untyped]

from .bootstrap_logging import setup_bootstrap_logging, startup_failure_boundary

logger = logging.getLogger(__name__)


class _LifespanDiagnostics:
    """Keep Starlette's preformatted failure traceback out of Uvicorn's message field."""

    def __init__(self, app: ASGIApp) -> None:
        """Store the wrapped ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Sanitize lifespan failure messages and log exceptions; pass other scopes through."""
        if scope["type"] != "lifespan":
            await self.app(scope, receive, send)
            return

        async def send_lifespan(message: Message) -> None:
            """Replace preformatted failure details before forwarding the lifespan message."""
            if message["type"] in {"lifespan.startup.failed", "lifespan.shutdown.failed"}:
                # Starlette embeds traceback.format_exc() here. Redacting the
                # already formatted string cannot enforce message-free errors.
                message = {**message, "message": "Application lifespan failed"}
            await send(message)

        try:
            await self.app(scope, receive, send_lifespan)
        except BaseException:
            logger.exception("Application lifespan failed")
            raise


class SafeUvicornWorker(UvicornWorker):
    """Preserve Uvicorn behavior while establishing logging before load_wsgi runs."""

    wsgi: ASGIApp

    def init_process(self) -> None:
        """Install safe logging and replace worker-startup exceptions with a safe error."""
        setup_bootstrap_logging()
        with startup_failure_boundary("worker_startup"):
            super().init_process()

    def load_wsgi(self) -> None:
        """Load the ASGI application and wrap its lifespan diagnostics."""
        super().load_wsgi()
        self.wsgi = _LifespanDiagnostics(self.wsgi)
