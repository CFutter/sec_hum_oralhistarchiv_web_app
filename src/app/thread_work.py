"""Cancellation-safe ownership of bounded blocking work."""

import asyncio
from collections.abc import Callable
from typing import TypeVar

from anyio import CancelScope, CapacityLimiter, to_thread

R = TypeVar("R")


class ThreadWorkAdmissionTimeout(TimeoutError):
    """Blocking work could not acquire capacity within its admission budget."""

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Blocking work capacity was unavailable for {timeout_seconds:g} seconds")


async def run_thread_work(
    function: Callable[[], R],
    limiter: CapacityLimiter,
    *,
    admission_timeout_seconds: float | None = None,
) -> R:
    """Run blocking work without releasing capacity before its thread finishes.

    Cancellation while queued remains immediate. Once admitted, cancellation
    waits for the worker to finish before releasing its token, preventing a
    supposedly single-worker caller from accidentally running two threads.
    """
    if admission_timeout_seconds is None:
        await limiter.acquire()
    else:
        if admission_timeout_seconds <= 0:
            raise ValueError("admission_timeout_seconds must be positive")
        try:
            async with asyncio.timeout(admission_timeout_seconds):
                await limiter.acquire()
        except TimeoutError as exc:
            raise ThreadWorkAdmissionTimeout(admission_timeout_seconds) from exc

    try:
        work = asyncio.create_task(to_thread.run_sync(function))

        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
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
        limiter.release()
