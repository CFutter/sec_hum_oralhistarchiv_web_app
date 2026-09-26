"""Run SMTP in a process that can be stopped before its outbox lease expires."""

import asyncio
import contextlib
import json
import os
import re
import sys
import time
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Literal, TypeVar

from .email import DeliveryResult
from .email_outbox import ClaimedEmail, OutboundEmail

SMTP_SEND_SECONDS = 60
_PROCESS_TIMEOUT_SECONDS = 65
_TERMINATE_GRACE_SECONDS = 5
SMTP_OPERATION_BUDGET = timedelta(
    seconds=_PROCESS_TIMEOUT_SECONDS + _TERMINATE_GRACE_SECONDS,
)
_T = TypeVar("_T")
_MAX_CHILD_RESULT_BYTES = 512
_REASON_PATTERN = re.compile(r"[a-z0-9_]{1,128}\Z")
_ChildStatus = Literal["sent", "temporary_failure", "permanent_failure"]
_SMTP_STATUS_CODE_FIRST = 100
_SMTP_STATUS_CODE_LAST = 599


async def _drain_task(task: asyncio.Task[_T]) -> _T:
    """Finish cleanup even if the caller receives another cancellation."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    """Terminate and reap the child; send SIGKILL if it survives five seconds."""
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), _TERMINATE_GRACE_SECONDS)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
    await process.wait()


async def _read_child_result(result_fd: int) -> bytes:
    """Read the child's single atomic result write without blocking the loop."""
    return await asyncio.to_thread(os.read, result_fd, _MAX_CHILD_RESULT_BYTES + 1)


def _decode_child_result(payload: bytes) -> DeliveryResult:
    """Decode at most 512 bytes into DeliveryResult.

    Require exactly status, reason, smtp_code; reason is 1-128 lowercase
    ASCII letters/digits/underscores, and the optional integer code is
    100-599. Malformed JSON, UTF-8, or fields raise ValueError.
    """
    if len(payload) > _MAX_CHILD_RESULT_BYTES:
        raise ValueError("SMTP child result exceeds the IPC size limit")

    raw: object = json.loads(payload.decode("utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"status", "reason", "smtp_code"}:
        raise ValueError("SMTP child result has an invalid shape")

    status_value = raw["status"]
    if status_value == "sent":
        status: _ChildStatus = "sent"
    elif status_value == "temporary_failure":
        status = "temporary_failure"
    elif status_value == "permanent_failure":
        status = "permanent_failure"
    else:
        raise ValueError("SMTP child result has an invalid status")

    reason = raw["reason"]
    if not isinstance(reason, str) or _REASON_PATTERN.fullmatch(reason) is None:
        raise ValueError("SMTP child result has an invalid reason")

    smtp_code = raw["smtp_code"]
    if smtp_code is not None and (
        type(smtp_code) is not int
        or not _SMTP_STATUS_CODE_FIRST <= smtp_code <= _SMTP_STATUS_CODE_LAST
    ):
        raise ValueError("SMTP child result has an invalid SMTP code")

    return DeliveryResult(status=status, reason=reason, smtp_code=smtp_code)


def _temporary_failure(reason: str) -> DeliveryResult:
    """Wrap a reason in a temporary-failure delivery result."""
    return DeliveryResult(status="temporary_failure", reason=reason)


async def _run_process(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
) -> DeliveryResult:
    """Send payload to child stdin and read its dedicated result pipe.

    Append the inherited result FD to command. timeout_seconds bounds
    normal startup/delivery; cleanup may outlast it. Return temporary
    failures for transport, timeout, or invalid/mismatched output.
    Cancellation stops and reaps the child before propagating.
    """
    if timeout_seconds <= 0:
        return _temporary_failure("smtp_process_timeout")

    owner = asyncio.current_task()
    cancellations_before = owner.cancelling() if owner is not None else 0
    result_read_fd, result_write_fd = os.pipe()
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *command,
            str(result_write_fd),
            stdin=asyncio.subprocess.PIPE,
            stdout=None,
            stderr=None,
            pass_fds=(result_write_fd,),
        )
    )
    process: asyncio.subprocess.Process | None = None
    result_reader: asyncio.Task[bytes] | None = None
    child_payload: bytes | None = None
    result: DeliveryResult | None = None
    try:
        async with asyncio.timeout(timeout_seconds):
            process = await asyncio.shield(spawn)
            os.close(result_write_fd)
            result_write_fd = -1
            result_reader = asyncio.create_task(_read_child_result(result_read_fd))
            await process.communicate(payload)
            child_payload = await asyncio.shield(result_reader)
    except TimeoutError:
        result = _temporary_failure("smtp_process_timeout")
    except (OSError, ValueError):
        result = _temporary_failure("smtp_process_start_failed")
    finally:
        # Shield spawning so cancellation cannot orphan a child before its
        # Process handle has been returned to us.
        if process is None:
            with contextlib.suppress(Exception):
                process = await _drain_task(spawn)
        if process is not None:
            with contextlib.suppress(Exception):
                await _drain_task(asyncio.create_task(_stop_process(process)))
        if result_write_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(result_write_fd)
        if result_reader is not None:
            with contextlib.suppress(OSError):
                child_payload = await _drain_task(result_reader)
        with contextlib.suppress(OSError):
            os.close(result_read_fd)
        if owner is not None and owner.cancelling() > cancellations_before:
            raise asyncio.CancelledError

    if result is not None:
        return result
    if process is None:
        return _temporary_failure("smtp_process_start_failed")
    if child_payload is None:
        return _temporary_failure("smtp_child_result_missing")

    try:
        child_result = _decode_child_result(child_payload)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return _temporary_failure("smtp_child_result_invalid")

    if process.returncode == 0 and child_result.status == "sent":
        return child_result
    if process.returncode in {1, 124} and child_result.status != "sent":
        return child_result
    return _temporary_failure("smtp_child_exit_mismatch")


async def send_claimed_email(
    message: ClaimedEmail,
    email: OutboundEmail,
    *,
    deadline: float,
) -> DeliveryResult:
    """Deliver email in a Linux subprocess before an absolute monotonic deadline.

    message supplies the correlation ID; email supplies plaintext content.
    The parent allows up to min(65, remaining+5) seconds before cleanup;
    cancellation terminates and reaps the child. Return DeliveryResult;
    serialization and uncaught process setup errors propagate.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _temporary_failure("smtp_delivery_deadline_elapsed")

    child = Path(__file__).with_name("_smtp_child.py")
    payload = json.dumps(
        {
            "outbox_id": message.id,
            "email": asdict(email),
            "deadline": deadline,
        }
    ).encode()
    return await _run_process(
        (sys.executable, str(child), str(SMTP_SEND_SECONDS)),
        payload,
        timeout_seconds=min(_PROCESS_TIMEOUT_SECONDS, remaining + 5),
    )
