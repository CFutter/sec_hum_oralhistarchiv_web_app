"""Keep asynchronous ingestion ownership until a synchronous fetch is reaped."""

from datetime import datetime
from functools import partial
from threading import Event
from typing import Protocol

from anyio import CapacityLimiter

from app.ingestion_contracts import HarvestResult
from app.thread_work import run_thread_work

_fetch_capacity = CapacityLimiter(1)


class _FetchOperation(Protocol):
    """Synchronous fetch accepting an optional cutoff and cooperative cancellation event."""

    def __call__(self, *, since: datetime | None, cancel_event: Event) -> HarvestResult:
        """Fetch since the optional cutoff, observing cancellation, and return a harvest result."""
        ...


async def run_source_fetch(fetch: _FetchOperation, *, since: datetime | None) -> HarvestResult:
    """Signal cancellation promptly, then drain before releasing the caller's locks.

    Every invocation owns a fresh event. Adapters forward it to parent-side
    process supervision; it is never pickled into the source worker itself.
    """
    cancel_event = Event()
    return await run_thread_work(
        partial(fetch, since=since, cancel_event=cancel_event),
        _fetch_capacity,
        on_cancel=cancel_event.set,
    )
