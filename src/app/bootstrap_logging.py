"""Settings-independent diagnostics before the application can configure logging.

Keep this module stdlib-only: the Gunicorn config imports it before Settings.
Bootstrap records deliberately omit messages, arguments and source-code text;
those can contain invalid configuration or exception values before redaction exists.
"""

import logging
import sys
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from json import dumps
from pathlib import Path
from typing import Literal

StartupPhase = Literal["settings_import", "worker_startup"]
_MAX_BOOTSTRAP_FRAMES = 25


class BootstrapFormatter(logging.Formatter):
    """Emit categorical JSON, without formatting any supplied log/exception value."""

    def format(self, record: logging.LogRecord) -> str:
        """Return JSON metadata and at most 25 trailing frames, omitting supplied messages."""
        diagnostic: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": "Server bootstrap diagnostic",
        }
        phase = getattr(record, "startup_phase", None)
        if isinstance(phase, str) and phase in {"settings_import", "worker_startup"}:
            diagnostic["startup_phase"] = phase
        if record.exc_info and record.exc_info[1] is not None:
            exception = record.exc_info[1]
            frames: deque[str] = deque(maxlen=_MAX_BOOTSTRAP_FRAMES)
            traceback = record.exc_info[2]
            while traceback is not None:
                code = traceback.tb_frame.f_code
                frames.append(f"{Path(code.co_filename).name}:{traceback.tb_lineno}:{code.co_name}")
                traceback = traceback.tb_next
            diagnostic["exception_type"] = type(exception).__name__
            diagnostic["frames"] = list(frames)
        return dumps(diagnostic)


def route_server_logs() -> None:
    """Detach Gunicorn/Uvicorn's plain worker handlers in favor of the root pipeline."""
    for name in ("gunicorn", "gunicorn.error", "uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        # Uvicorn initially aliases Gunicorn's handler list. Its standalone
        # config also installs a nonpropagating parent handler. Detach both
        # levels rather than letting an error reach an ancestor's plain formatter.
        logger.handlers = []
        logger.propagate = True


def setup_bootstrap_logging() -> None:
    """Replace root handlers with a safe INFO stderr pipeline and reroute server logs."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(BootstrapFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    route_server_logs()


@contextmanager
def startup_failure_boundary(phase: StartupPhase) -> Iterator[None]:
    """Log a safe diagnostic and replace errors that Gunicorn also prints directly.

    Gunicorn's configuration loader and worker supervisor write exceptions to
    stderr outside the logging API. A formatter alone cannot protect that path.
    Interrupts/SystemExit retain their normal process semantics.
    """
    try:
        yield
    except Exception:
        # Use an independent logger even if Settings/application import failed
        # before global handlers existed or replaced them only partially.
        logger = logging.Logger("server.bootstrap", level=logging.ERROR)  # noqa: LOG001 - isolated from partially configured global handlers
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(BootstrapFormatter())
        logger.addHandler(handler)
        logger.exception("Server startup failed", extra={"startup_phase": phase})
        raise RuntimeError(
            "Server startup failed; inspect structured bootstrap diagnostics"
        ) from None
