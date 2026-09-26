"""Private Linux SMTP subprocess entrypoint; no credentials in command arguments."""

import contextlib
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from types import FrameType
from typing import Literal

logger = logging.getLogger("app.services.smtp_child")

_MAX_RESULT_BYTES = 512
_DeliveryStatus = Literal["sent", "temporary_failure", "permanent_failure"]


class _OutboxContext(logging.Filter):
    """Attach an outbox ID to every accepted log record."""

    def __init__(self, outbox_id: int) -> None:
        """Store the outbox ID used to correlate child-process logs."""
        super().__init__()
        self.outbox_id = outbox_id

    def filter(self, record: logging.LogRecord) -> bool:
        """Set the record's outbox_id in place and accept it."""
        record.outbox_id = self.outbox_id
        return True


class _DeliveryDeadline(BaseException):
    """Bypass the SMTP adapter's ordinary Exception-to-result conversion."""


def _deadline_expired(
    _signum: int,
    _frame: FrameType | None,
) -> None:
    """Raise _DeliveryDeadline from the SIGALRM handler."""
    raise _DeliveryDeadline


def _write_result(
    result_fd: int,
    *,
    status: _DeliveryStatus,
    reason: str,
    smtp_code: int | None,
) -> None:
    """Write one JSON result of at most 512 bytes to result_fd.

    Raises ValueError for oversized results and OSError for failed or partial writes.
    """
    encoded = json.dumps(
        {
            "status": status,
            "reason": reason,
            "smtp_code": smtp_code,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_RESULT_BYTES:
        raise ValueError("SMTP child result exceeds the IPC size limit")
    if os.write(result_fd, encoded) != len(encoded):
        raise OSError("SMTP child result pipe was only partially written")


def _best_effort_result(
    result_fd: int,
    *,
    status: _DeliveryStatus,
    reason: str,
    smtp_code: int | None = None,
) -> None:
    """Write a result, suppressing OSError and ValueError."""
    with contextlib.suppress(OSError, ValueError):
        _write_result(
            result_fd,
            status=status,
            reason=reason,
            smtp_code=smtp_code,
        )


def main() -> int:
    """Read timeout seconds and result FD from argv, then deliver stdin JSON.

    The payload contains outbox_id, an absolute monotonic deadline, and email
    fields for OutboundEmail. Installs SIGALRM, configures logging, sends mail,
    writes a result, and closes the FD. Returns 0 for sent, 1 for failure,
    2 for invalid arguments, or 124 for deadline expiry.
    """
    try:
        startup_timeout = float(sys.argv[1])
        result_fd = int(sys.argv[2])
    except (IndexError, ValueError):
        logger.exception("SMTP child requires a numeric timeout and result file descriptor")
        return 2
    if startup_timeout <= 0 or result_fd < 0:
        logger.error("SMTP child requires a positive timeout and result file descriptor")
        return 2

    signal.signal(signal.SIGALRM, _deadline_expired)
    signal.setitimer(signal.ITIMER_REAL, startup_timeout)
    try:
        # The script also works from a source checkout with no editable install.
        sys.path[0] = str(Path(__file__).resolve().parents[2])

        from config import settings, setup_logging  # noqa: PLC0415

        setup_logging(
            log_level=settings.log_level,
            log_format="json",  # Retain durable correlation even when the web uses text logs.
        )

        # Imports require the source path and must run inside the deadline.
        from app.services.email import send_outbound_email  # noqa: PLC0415
        from app.services.email_outbox import OutboundEmail  # noqa: PLC0415

        payload = json.load(sys.stdin)
        context = _OutboxContext(int(payload["outbox_id"]))
        for handler in (*logging.getLogger().handlers, *logging.getLogger("audit").handlers):
            handler.addFilter(context)

        remaining = payload["deadline"] - time.monotonic()
        if remaining <= 0:
            _write_result(
                result_fd,
                status="temporary_failure",
                reason="smtp_delivery_deadline_elapsed",
                smtp_code=None,
            )
            return 124

        signal.setitimer(signal.ITIMER_REAL, remaining)
        email = OutboundEmail(**payload["email"])
        result = send_outbound_email(email)
        _write_result(
            result_fd,
            status=result.status,
            reason=result.reason,
            smtp_code=result.smtp_code,
        )
        return 0 if result.status == "sent" else 1
    except _DeliveryDeadline:
        signal.setitimer(signal.ITIMER_REAL, 0)
        logger.exception("SMTP operation exceeded its complete-operation deadline")
        _best_effort_result(
            result_fd,
            status="temporary_failure",
            reason="smtp_child_deadline_exceeded",
        )
        return 124
    except Exception:
        logger.exception("SMTP subprocess failed")
        _best_effort_result(
            result_fd,
            status="temporary_failure",
            reason="smtp_child_failed",
        )
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        with contextlib.suppress(OSError):
            os.close(result_fd)


if __name__ == "__main__":
    raise SystemExit(main())
