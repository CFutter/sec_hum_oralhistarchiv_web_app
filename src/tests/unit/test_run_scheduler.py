"""run_scheduler.main() lifecycle wiring (TEST-048).

run_scheduler.py is the standalone scheduler process (systemd unit). It had
zero tests, so a renamed create_pool kwarg or an import error would mean no
syncs / rebuilds / cleanup / reaping ever run — and the only alarm is a
systemd restart loop. This drives main() with every external dependency
mocked and pins the start→wait→shutdown ordering: the pool is opened, the
scheduler started, and on the stop signal the scheduler is shut down and the
pool closed (no leak).
"""
import asyncio
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# run_scheduler.py lives at the PROJECT ROOT (the systemd entry point), which
# is not on the `src` pythonpath — load it by file path. PROJECT_ROOT is
# src/../.. from this test file (src/tests/unit/).
_ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    "run_scheduler", _ROOT / "run_scheduler.py"
)
run_scheduler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_scheduler)


async def test_main_starts_scheduler_and_cleans_up_on_stop():
    """main() opens the pool, builds the scheduler, starts it, waits on the
    stop event, and on shutdown calls scheduler.shutdown(wait=True) then
    closes the pool — in that order."""
    pool = MagicMock()
    pool.open = AsyncMock()
    pool.close = AsyncMock()
    scheduler = MagicMock()

    with patch.object(run_scheduler, "setup_logging"), \
         patch.object(run_scheduler, "create_pool", return_value=pool) as create_pool, \
         patch.object(run_scheduler, "FacetCache") as facet_cache, \
         patch.object(run_scheduler, "create_scheduler", return_value=scheduler) as make_sched:

        # Make the stop event fire immediately so main() proceeds to teardown
        # instead of blocking forever on stop_event.wait().
        real_event = asyncio.Event()
        real_event.set()
        with patch.object(run_scheduler.asyncio, "Event", return_value=real_event):
            await run_scheduler.main()

    # Pool opened with the dedicated application_name, then closed.
    create_pool.assert_called_once_with(application_name="oralhistarchiv-scheduler")
    pool.open.assert_awaited_once()
    pool.close.assert_awaited_once()

    # Scheduler built from (pool, facet_cache), started, and shut down cleanly.
    make_sched.assert_called_once()
    assert make_sched.call_args.args[0] is pool
    assert make_sched.call_args.args[1] is facet_cache.return_value
    scheduler.start.assert_called_once()
    scheduler.shutdown.assert_called_once_with(wait=True)


async def test_main_closes_pool_even_if_scheduler_shutdown_runs():
    """The teardown lives in a finally: block, so the pool is closed on the
    shutdown path regardless — pin that pool.close is awaited after a normal
    stop (a leak here would exhaust connections across systemd restarts)."""
    pool = MagicMock()
    pool.open = AsyncMock()
    pool.close = AsyncMock()

    with patch.object(run_scheduler, "setup_logging"), \
         patch.object(run_scheduler, "create_pool", return_value=pool), \
         patch.object(run_scheduler, "FacetCache"), \
         patch.object(run_scheduler, "create_scheduler", return_value=MagicMock()):
        event = asyncio.Event()
        event.set()
        with patch.object(run_scheduler.asyncio, "Event", return_value=event):
            await run_scheduler.main()

    pool.close.assert_awaited_once()
