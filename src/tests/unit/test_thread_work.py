"""Thread admission and cancellation retain both workload and global budgets."""

import asyncio
import threading
from collections.abc import AsyncIterator

import anyio
import pytest

from app.thread_work import ThreadWorkAdmissionTimeout, run_thread_work


@pytest.fixture
async def worker_capacity() -> AsyncIterator[anyio.CapacityLimiter]:
    """Temporarily constrain the shared thread limiter to one token and restore its capacity on exit."""
    capacity = anyio.to_thread.current_default_thread_limiter()
    original_tokens = capacity.total_tokens
    capacity.total_tokens = 1
    try:
        yield capacity
    finally:
        capacity.total_tokens = original_tokens


async def _wait_for_waiter(capacity: anyio.CapacityLimiter) -> None:
    """Wait at most one second for the limiter to report a queued task."""
    async with asyncio.timeout(1):
        while capacity.statistics().tasks_waiting == 0:
            await anyio.lowlevel.checkpoint()


async def test_default_pool_saturation_times_out_without_starting_work(
    worker_capacity: anyio.CapacityLimiter,
) -> None:
    """Check default pool saturation times out without starting work (ThreadWorkAdmissionTimeout)."""
    workload = anyio.CapacityLimiter(1)
    blocker = object()
    started = threading.Event()
    await worker_capacity.acquire_on_behalf_of(blocker)
    queued = asyncio.create_task(
        run_thread_work(started.set, workload, admission_timeout_seconds=0.02)
    )
    try:
        done, _ = await asyncio.wait({queued}, timeout=1)
        assert queued in done, "default-pool admission escaped its deadline"
        with pytest.raises(ThreadWorkAdmissionTimeout) as failure:
            await queued
        assert failure.value.timeout_seconds == 0.02
        assert not started.is_set()
        assert workload.borrowed_tokens == 0
        assert worker_capacity.borrowed_tokens == 1
        assert worker_capacity.statistics().tasks_waiting == 0
    finally:
        worker_capacity.release_on_behalf_of(blocker)
        queued.cancel()
        await asyncio.gather(queued, return_exceptions=True)

    assert await run_thread_work(lambda: "reused", workload) == "reused"
    assert workload.borrowed_tokens == worker_capacity.borrowed_tokens == 0
    assert not started.is_set()


async def test_cancellation_in_default_pool_queue_releases_workload_immediately(
    worker_capacity: anyio.CapacityLimiter,
) -> None:
    """Check cancellation in default pool queue releases workload immediately."""
    workload = anyio.CapacityLimiter(1)
    blocker = object()
    started = threading.Event()
    await worker_capacity.acquire_on_behalf_of(blocker)
    queued = asyncio.create_task(run_thread_work(started.set, workload))
    try:
        await _wait_for_waiter(worker_capacity)
        assert workload.borrowed_tokens == 1
        queued.cancel()
        done, _ = await asyncio.wait({queued}, timeout=1)
        assert queued in done, "queued cancellation waited for thread admission"
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert not started.is_set()
        assert workload.borrowed_tokens == 0
        assert worker_capacity.borrowed_tokens == 1
        assert worker_capacity.statistics().tasks_waiting == 0
    finally:
        worker_capacity.release_on_behalf_of(blocker)
        queued.cancel()
        await asyncio.gather(queued, return_exceptions=True)


async def test_cancellation_in_workload_queue_never_reserves_a_worker(
    worker_capacity: anyio.CapacityLimiter,
) -> None:
    """Check cancellation in workload queue never reserves a worker."""
    workload = anyio.CapacityLimiter(1)
    blocker = object()
    started = threading.Event()
    await workload.acquire_on_behalf_of(blocker)
    queued = asyncio.create_task(run_thread_work(started.set, workload))
    try:
        await _wait_for_waiter(workload)
        queued.cancel()
        done, _ = await asyncio.wait({queued}, timeout=1)
        assert queued in done, "queued cancellation waited for thread admission"
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert not started.is_set()
        assert workload.borrowed_tokens == 1
        assert workload.statistics().tasks_waiting == 0
        assert worker_capacity.borrowed_tokens == 0
    finally:
        workload.release_on_behalf_of(blocker)
        queued.cancel()
        await asyncio.gather(queued, return_exceptions=True)


async def test_running_cancellation_holds_both_budgets_until_the_thread_finishes(
    worker_capacity: anyio.CapacityLimiter,
) -> None:
    """Check running cancellation holds both budgets until the thread finishes."""
    workload = anyio.CapacityLimiter(1)
    loop = asyncio.get_running_loop()
    started = asyncio.Event()
    release = threading.Event()
    next_started = threading.Event()

    def blocked() -> None:
        """Signal loop-side entry, then wait at most five seconds before failing if unreleased."""
        loop.call_soon_threadsafe(started.set)
        if not release.wait(timeout=5):
            raise RuntimeError("test did not release worker")

    running = asyncio.create_task(run_thread_work(blocked, workload))
    ordinary_worker: asyncio.Task[None] | None = None
    try:
        async with asyncio.timeout(1):
            await started.wait()
        running.cancel()
        # Ordinary AnyIO work must still see the global token held, even though
        # the cancelled helper's actual run_sync uses an already-admitted path.
        ordinary_worker = asyncio.create_task(anyio.to_thread.run_sync(next_started.set))
        await _wait_for_waiter(worker_capacity)
        assert not running.done()
        assert workload.borrowed_tokens == worker_capacity.borrowed_tokens == 1
        assert not next_started.is_set()
        running.cancel()  # Repeated cancellation also must not release permits.
        await anyio.lowlevel.checkpoint()
        assert not running.done()
        assert workload.borrowed_tokens == worker_capacity.borrowed_tokens == 1
    finally:
        release.set()
        await asyncio.gather(
            running,
            *([ordinary_worker] if ordinary_worker is not None else []),
            return_exceptions=True,
        )
    assert running.cancelled()
    assert next_started.is_set()
    assert workload.borrowed_tokens == worker_capacity.borrowed_tokens == 0


async def test_using_default_limiter_as_workload_does_not_acquire_it_twice(
    worker_capacity: anyio.CapacityLimiter,
) -> None:
    """Check using default limiter as workload does not acquire it twice."""
    task = asyncio.create_task(run_thread_work(lambda: 7, worker_capacity))
    try:
        done, _ = await asyncio.wait({task}, timeout=1)
        assert task in done, "the shared limiter was acquired twice"
        assert await task == 7
    finally:
        if not task.done():
            # Let a defective double acquisition unwind instead of hanging the
            # test runner while it drains an already-admitted child.
            worker_capacity.total_tokens = 2
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert worker_capacity.borrowed_tokens == 0


@pytest.mark.parametrize("error_type", [ValueError, TimeoutError])
async def test_worker_exceptions_release_both_budgets_without_reclassification(
    worker_capacity: anyio.CapacityLimiter,
    error_type: type[Exception],
) -> None:
    """Check worker exceptions release both budgets without reclassification (error_type)."""
    workload = anyio.CapacityLimiter(1)
    failure = error_type("worker failed")

    def fail() -> None:
        """Raise the injected failure unchanged."""
        raise failure

    with pytest.raises(error_type) as captured:
        await run_thread_work(fail, workload, admission_timeout_seconds=0.02)
    assert captured.value is failure
    assert not isinstance(captured.value, ThreadWorkAdmissionTimeout)
    assert workload.borrowed_tokens == worker_capacity.borrowed_tokens == 0


@pytest.mark.parametrize("callback_fails", [False, True])
async def test_cancel_callback_runs_once_and_failure_still_drains(callback_fails):
    """Check cancel callback runs once and failure still drains."""
    workload = anyio.CapacityLimiter(1)
    started, release, signalled, finished = (threading.Event() for _ in range(4))
    calls = 0

    def worker():
        """Signal entry, wait up to three seconds, and signal worker completion."""
        started.set()
        release.wait(3)
        finished.set()

    def cancel():
        """Count and signal cancellation, optionally raising the injected callback failure."""
        nonlocal calls
        calls += 1
        signalled.set()
        if callback_fails:
            raise RuntimeError("callback error")

    task = asyncio.create_task(run_thread_work(worker, workload, on_cancel=cancel))
    try:
        async with asyncio.timeout(1):
            while not started.is_set():
                await asyncio.sleep(0)
        task.cancel()
        async with asyncio.timeout(1):
            while not signalled.is_set():
                await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and workload.borrowed_tokens == 1
        release.set()
        with pytest.raises(asyncio.CancelledError) as failure:
            await task
        assert calls == 1 and finished.is_set()
        assert workload.borrowed_tokens == 0
        assert bool(getattr(failure.value, "__notes__", ())) is callback_fails
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
