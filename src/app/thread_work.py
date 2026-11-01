"""Cancellation-safe ownership of bounded blocking work."""

import asyncio
from collections.abc import Callable
from math import inf
from typing import TypeVar

from anyio import CancelScope, CapacityLimiter, to_thread

R = TypeVar("R")


class ThreadWorkAdmissionTimeout(TimeoutError):
    """Blocking work could not acquire capacity within its admission budget."""

    def __init__(self, timeout_seconds: float) -> None:
        """Store the admission timeout in seconds and initialize the error message."""
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Blocking work capacity was unavailable for {timeout_seconds:g} seconds")


async def run_thread_work(
    function: Callable[[], R],
    limiter: CapacityLimiter,
    *,
    admission_timeout_seconds: float | None = None,
    on_cancel: Callable[[], None] | None = None,
) -> R:
    """Run function in a worker thread, retaining both capacity tokens until it finishes.

    Acquire limiter and AnyIO thread capacity within admission_timeout_seconds
    (None: no deadline). Raise ValueError for nonpositive timeouts and
    ThreadWorkAdmissionTimeout if admission expires; worker errors propagate.
    Cancellation during admission is immediate; after admission call on_cancel
    once if supplied, drain the worker, then propagate cancellation. Callback
    errors are attached to cancellation instead of abandoning the worker.
    """
    if admission_timeout_seconds is not None and admission_timeout_seconds <= 0:
        raise ValueError("admission_timeout_seconds must be positive")

    worker_limiter = to_thread.current_default_thread_limiter()
    capacities = (limiter,) if limiter is worker_limiter else (limiter, worker_limiter)
    borrower = object()
    acquired: list[CapacityLimiter] = []
    try:
        try:
            async with asyncio.timeout(admission_timeout_seconds):
                for capacity in capacities:
                    await capacity.acquire_on_behalf_of(borrower)
                    acquired.append(capacity)
        except TimeoutError as exc:
            if admission_timeout_seconds is None:
                raise
            raise ThreadWorkAdmissionTimeout(admission_timeout_seconds) from exc

        # Both permits already belong to this invocation. Let the child submit
        # directly instead of acquiring the shared limiter a second time; that
        # would introduce another queue (or deadlock a one-token budget).
        work = asyncio.create_task(to_thread.run_sync(function, limiter=CapacityLimiter(inf)))

        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError as cancelled:
            if on_cancel is not None:
                try:
                    on_cancel()
                except BaseException as callback_error:
                    # A bad signal callback must never abandon admitted work.
                    cancelled.add_note(
                        f"Thread cancellation callback failed: {type(callback_error).__name__}"
                    )
            with CancelScope(shield=True):
                while not work.done():
                    try:
                        await asyncio.shield(work)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break

                if not work.cancelled():
                    work.exception()

            raise
    finally:
        for capacity in reversed(acquired):
            capacity.release_on_behalf_of(borrower)
