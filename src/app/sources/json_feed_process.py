"""Bounded spawned-worker IPC with one absolute deadline and mandatory reaping."""

import contextlib
import multiprocessing
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import Any

from app.ingestion_contracts.cancellation import (
    HarvestCancelled,
    check_harvest_cancellation,
    wait_for_harvest_step,
)

from .json_feed_http import FeedTransportError

_WORKER_SHUTDOWN_SECONDS = 1.0
_MIN_FRAME_BYTES = 32


def check_feed_deadline(deadline: float) -> float:
    """Return remaining monotonic time or fail with a fixed resource diagnostic."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FeedTransportError("resource_limit")
    return remaining


@dataclass(slots=True)
class _ReceiveState:
    """Publish a receiver thread's bounded frame or failure before setting done."""

    done: threading.Event = field(default_factory=threading.Event)
    message: bytes | None = None
    failed: bool = False
    receiver: threading.Thread | None = field(default=None, repr=False)


def _receive(connection: Connection, state: _ReceiveState, limit: int) -> None:
    """Receive one size-limited frame into state; catch BaseException and always signal
    completion.
    """
    try:
        state.message = connection.recv_bytes(limit)
    except BaseException:
        state.failed = True
    finally:
        state.done.set()


def _stop_worker(process: Any) -> None:
    """Terminate then kill/reap a live worker with one-second waits; reject survivors and close
    its handle.
    """
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.terminate()
        process.join(timeout=_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.kill()
        process.join(timeout=_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        raise FeedTransportError("worker")
    process.join(timeout=0)
    process.close()


def _wait_for_frame(
    process: Any,
    connection: Connection,
    state: _ReceiveState,
    *,
    max_bytes: int,
    deadline: float,
    cancel_event: threading.Event | None = None,
) -> None:
    """Start a bounded receiver, await its frame and clean worker exit under one
    deadline/cancellation event.
    """
    if not wait_for_harvest_step(connection.poll, deadline=deadline, cancel_event=cancel_event):
        raise FeedTransportError("resource_limit")
    state.receiver = threading.Thread(
        target=_receive,
        args=(connection, state, max(max_bytes + 1, _MIN_FRAME_BYTES)),
        name="json-feed-page-receiver",
        daemon=True,
    )
    state.receiver.start()
    if not wait_for_harvest_step(state.done.wait, deadline=deadline, cancel_event=cancel_event):
        raise FeedTransportError("resource_limit")
    if state.failed or state.message is None:
        raise FeedTransportError("worker")

    def exited(timeout: float) -> bool:
        """Join for timeout seconds and report whether the worker has exited."""
        process.join(timeout=timeout)
        return not process.is_alive()

    if not wait_for_harvest_step(exited, deadline=deadline, cancel_event=cancel_event):
        raise FeedTransportError("resource_limit")
    if process.exitcode != 0:
        raise FeedTransportError("worker")


def run_feed_process(
    worker: Callable[..., None],
    args: tuple[object, ...],
    *,
    max_bytes: int,
    deadline: float,
    process_name: str,
    cancel_event: threading.Event | None = None,
) -> bytes:
    """Return one bounded raw frame only after the child exits within its deadline.

    Readiness alone cannot establish complete IPC: a bounded receiver thread
    handles partial frames while the parent enforces the same absolute cutoff.
    Failed/blocked children are terminated, then killed if needed, and reaped.
    Cleanup has a small fixed grace beyond the operation's deadline. No pickle
    payload is accepted from the child; callers interpret fixed frame prefixes.
    """
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("JSON feed process byte budget must be a positive integer")
    check_feed_deadline(deadline)
    check_harvest_cancellation(cancel_event)
    receive: Connection | None = None
    send: Connection | None = None
    process: Any = None
    state = _ReceiveState()
    started = False
    primary_error: BaseException | None = None
    try:
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(
            target=worker,
            args=(send, *args),
            name=process_name,
            daemon=True,
        )
        process.start()
        started = True
        send.close()
        _wait_for_frame(
            process,
            receive,
            state,
            max_bytes=max_bytes,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except (FeedTransportError, HarvestCancelled) as exc:
        primary_error = exc
        raise
    except Exception:
        primary_error = FeedTransportError("worker")
        raise primary_error from None
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            if started or (process is not None and process.pid is not None):
                _stop_worker(process)
            elif process is not None:
                process.close()
        except Exception:
            if primary_error is None:
                raise FeedTransportError("worker") from None
            primary_error.add_note("JSON feed worker cleanup failed")
        finally:
            if receive is not None:
                with contextlib.suppress(OSError):
                    receive.close()
            if send is not None:
                with contextlib.suppress(OSError):
                    send.close()
            if state.receiver is not None and state.receiver.ident is not None:
                state.receiver.join(timeout=_WORKER_SHUTDOWN_SECONDS)
                if state.receiver.is_alive():
                    if primary_error is None:
                        raise FeedTransportError("worker")
                    primary_error.add_note("JSON feed receiver cleanup failed")
    check_feed_deadline(deadline)
    check_harvest_cancellation(cancel_event)
    if state.message is None:
        raise FeedTransportError("worker")
    return state.message
