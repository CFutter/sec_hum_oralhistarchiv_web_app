"""Bound real spawn readiness separately from a short, real hostile-stage cutoff."""

import multiprocessing
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import create_autospec

from app.ingestion_contracts import cancellation
from app.sources import json_feed_process as process

TEST_FETCH_DEADLINE_SECONDS = 60
_STARTUP_SECONDS = 30.0
_PHASE_SECONDS = 0.2
_TERMINATION_SECONDS = 5.0


@dataclass
class WorkerDeadlineTiming:
    """Actual wall-clock observations; the production worker/process stays real."""

    started_at: float | None = None
    ready_at: float | None = None

    def assert_terminated_after_readiness(self) -> None:
        """Assert readiness and termination satisfy the configured wall-clock bounds."""
        assert self.started_at is not None and self.ready_at is not None
        assert self.ready_at - self.started_at < _STARTUP_SECONDS
        assert _PHASE_SECONDS / 2 <= time.monotonic() - self.ready_at < _TERMINATION_SECONDS


def deadline_after_worker_ready(monkeypatch, ready: Callable[[], bool]) -> WorkerDeadlineTiming:
    """Observe readiness through a test-owned marker, then advance only the parent clock.

    A real spawn has at most 30 seconds to reach the intended hostile stage.
    The worker keeps its real 60-second deadline. Once ready, the parent's
    deadline clock advances to leave 0.2 seconds for the blocked stage; normal
    process cleanup must then terminate/kill and reap it. Separate tests retain
    unmodified short absolute deadlines that include all spawn startup time.
    """
    timing = WorkerDeadlineTiming()
    real_monotonic = time.monotonic
    offset = 0.0
    absolute_deadline = None
    real_check = process.check_feed_deadline

    def clock():
        """Return the real monotonic clock plus the test-controlled offset."""
        return real_monotonic() + offset

    def check(deadline):
        """Assert deadline checks retain the first absolute deadline, then run the real check."""
        nonlocal absolute_deadline
        if absolute_deadline is None:
            absolute_deadline = deadline
        else:
            assert absolute_deadline == deadline, "A worker must keep its original deadline"
        return real_check(deadline)

    spawn_process = multiprocessing.get_context("spawn").Process
    real_start = spawn_process.start

    def start(child):
        """Start the real worker, await its marker and leave 0.2 parent-clock seconds for its
        blocked phase.
        """
        nonlocal offset
        timing.started_at = real_monotonic()
        real_start(child)
        startup_end = timing.started_at + _STARTUP_SECONDS
        while not ready():
            assert real_monotonic() < startup_end, "Spawned worker did not reach its test stage"
            assert child.is_alive(), "Spawned worker exited before reaching its test stage"
            threading.Event().wait(0.01)
        timing.ready_at = real_monotonic()
        assert absolute_deadline is not None
        offset = absolute_deadline - _PHASE_SECONDS - timing.ready_at

    parent_clock = SimpleNamespace(monotonic=clock)
    monkeypatch.setattr(process, "time", parent_clock)
    monkeypatch.setattr(cancellation, "time", parent_clock)
    monkeypatch.setattr(
        process, "check_feed_deadline", create_autospec(real_check, side_effect=check)
    )
    # A class method wrapper is not added to the Process instance's pickled state.
    monkeypatch.setattr(spawn_process, "start", create_autospec(real_start, side_effect=start))
    return timing
