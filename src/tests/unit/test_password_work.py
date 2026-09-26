"""Unit tests for `app.services.password_work` — the bounded Argon2 thread
budget, separate from the general thread pool.

Pure unit tier: no DB, no TestClient. Each event loop gets its own
`CapacityLimiter` (an `anyio.lowlevel.RunVar`), so these tests exercise the
real limiter with real threads rather than mocking concurrency away.
"""

import asyncio
import threading

import anyio
import anyio.lowlevel

from app.services import password_work
from app.services.password_work import run_password_work
from config import settings

_CALLERS = 40


class TestPasswordWorkCapacityBudget:
    """`run_password_work` bounds concurrent Argon2 work to
    `settings.password_work_concurrency`, independently of the general
    thread pool, and never releases a cancelled slot before its thread
    actually finishes."""

    async def test_concurrent_password_work_never_exceeds_its_own_capacity(self, monkeypatch):
        """A burst of password-hashing calls, each of which would run
        happily on the general thread pool's much larger capacity, is
        instead bounded by password_work's OWN limiter (here set to 1): at
        no point does more than one hash run at a time, and every submitted
        unit of work still completes."""
        monkeypatch.setattr(settings, "password_work_concurrency", 1)
        active = peak = completed = 0
        guard = threading.Lock()
        release = threading.Event()

        def expensive_work():
            nonlocal active, peak, completed
            with guard:
                active += 1
                peak = max(peak, active)
            release.wait(timeout=5)
            with guard:
                active -= 1
                completed += 1

        async def limiter_for_current_loop() -> anyio.CapacityLimiter:
            with anyio.fail_after(2):
                while True:
                    try:
                        return password_work._limiter.get()
                    except LookupError:
                        await anyio.lowlevel.checkpoint()

        async with anyio.create_task_group() as group:
            for _ in range(_CALLERS):
                group.start_soon(run_password_work, expensive_work)

            limiter = await limiter_for_current_loop()
            with anyio.fail_after(2):
                while not (active == 1 and limiter.statistics().tasks_waiting >= _CALLERS - 1):
                    await anyio.lowlevel.checkpoint()

            # One caller holds the only slot; every other caller is
            # registered as waiting behind it — proof the bound held under
            # real concurrent contention, not just by construction.
            assert limiter.statistics().borrowed_tokens == 1
            assert peak == 1
            release.set()

        assert completed == _CALLERS
        assert peak == 1

    async def test_cancelling_a_request_keeps_its_capacity_until_the_thread_finishes(
        self, monkeypatch
    ):
        """Cancelling the awaiting coroutine must NOT release the limiter
        slot early: a second caller queued behind a cancelled-but-still-
        running first call must stay blocked until the first thread actually
        finishes, or a single-worker capacity budget could be oversubscribed
        by a caller that gives up waiting."""
        monkeypatch.setattr(settings, "password_work_concurrency", 1)
        started = threading.Event()
        release = threading.Event()
        second_started = threading.Event()

        def first_work():
            started.set()
            release.wait(timeout=5)

        first = asyncio.create_task(run_password_work(first_work))
        second = None
        try:
            with anyio.fail_after(2):
                await anyio.to_thread.run_sync(started.wait, 5)
            assert started.is_set()
            first.cancel()

            limiter = password_work._limiter.get()
            second = asyncio.create_task(run_password_work(second_started.set))
            with anyio.fail_after(2):
                while limiter.statistics().tasks_waiting < 1:
                    await anyio.lowlevel.checkpoint()

            # The cancelled first call still holds the only token, and the
            # second call is registered as waiting behind it — the slot was
            # not released early, and the second thread never started.
            assert limiter.statistics().borrowed_tokens == 1
            assert not second_started.is_set()
        finally:
            release.set()
            await asyncio.gather(
                first, *([second] if second is not None else []), return_exceptions=True
            )
            assert second_started.is_set()
