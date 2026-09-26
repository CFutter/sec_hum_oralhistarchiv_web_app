"""Tests for the standalone scheduler process lifecycle (run_scheduler.py).

The scheduler process must validate its database before submitting work,
pause new submissions during shutdown, let every tracked job finish, and only
then ask APScheduler to shut down. Cache and pool resources must be released
even when preflight, draining, or APScheduler shutdown fails.

Every stand-in is autospecced from the imported production object so signature
drift fails at the call site instead of being accepted by a permissive mock.
"""

import asyncio
import importlib.util
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from psycopg_pool import AsyncConnectionPool

from config import settings

_ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("run_scheduler", _ROOT / "run_scheduler.py")
assert _spec is not None and _spec.loader is not None
run_scheduler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_scheduler)

_REAL = {
    name: getattr(run_scheduler, name)
    for name in (
        "setup_logging",
        "create_pool",
        "CatalogueStatsCache",
        "RunningJobTracker",
        "create_scheduler",
        "validate_security_settings",
        "validate_runtime_schema",
    )
}


def _patched_main(stack: ExitStack):
    """Install lifecycle stand-ins and return pool/scheduler/tracker/spies."""
    pool = create_autospec(AsyncConnectionPool, instance=True)
    scheduler = create_autospec(AsyncIOScheduler, instance=True)
    tracker = create_autospec(_REAL["RunningJobTracker"], instance=True)
    tracker.active_job_ids = ()

    spies = {
        "setup_logging": stack.enter_context(
            patch.object(
                run_scheduler,
                "setup_logging",
                new=create_autospec(_REAL["setup_logging"]),
            )
        ),
        "validate_security_settings": stack.enter_context(
            patch.object(
                run_scheduler,
                "validate_security_settings",
                new=create_autospec(_REAL["validate_security_settings"]),
            )
        ),
        "create_pool": stack.enter_context(
            patch.object(
                run_scheduler,
                "create_pool",
                new=create_autospec(_REAL["create_pool"], return_value=pool),
            )
        ),
        "CatalogueStatsCache": stack.enter_context(
            patch.object(
                run_scheduler,
                "CatalogueStatsCache",
                new=create_autospec(_REAL["CatalogueStatsCache"]),
            )
        ),
        "RunningJobTracker": stack.enter_context(
            patch.object(
                run_scheduler,
                "RunningJobTracker",
                new=create_autospec(
                    _REAL["RunningJobTracker"],
                    return_value=tracker,
                ),
            )
        ),
        "create_scheduler": stack.enter_context(
            patch.object(
                run_scheduler,
                "create_scheduler",
                new=create_autospec(
                    _REAL["create_scheduler"],
                    return_value=scheduler,
                ),
            )
        ),
        "validate_runtime_schema": stack.enter_context(
            patch.object(
                run_scheduler,
                "validate_runtime_schema",
                new=create_autospec(_REAL["validate_runtime_schema"]),
            )
        ),
    }

    stop_event = asyncio.Event()
    stop_event.set()
    stack.enter_context(patch.object(run_scheduler.asyncio, "Event", return_value=stop_event))

    loop = asyncio.get_running_loop()
    spies["add_signal_handler"] = stack.enter_context(
        patch.object(loop, "add_signal_handler", autospec=True)
    )

    return pool, scheduler, tracker, spies


class TestMainShutdownSequencing:
    """A clean shutdown is pause -> drain -> APScheduler shutdown -> release
    resources, and resource release survives failures at every stage.
    """

    async def test_clean_shutdown_pauses_drains_shuts_down_then_releases_resources(self):
        """Clean shutdown runs in the exact order: pause, drain, shutdown,
        drain again, stop the cache, then close the pool.
        """
        order: list[str] = []

        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            stats_cache = spies["CatalogueStatsCache"].return_value

            scheduler.pause.side_effect = lambda: order.append("pause")
            tracker.wait_until_empty.side_effect = lambda: order.append("wait")
            scheduler.shutdown.side_effect = lambda **_kwargs: order.append("shutdown")
            stats_cache.stop.side_effect = lambda: order.append("stats_stop")
            pool.close.side_effect = lambda: order.append("pool_close")

            await run_scheduler.main()

        spies["setup_logging"].assert_called_once_with(
            log_level=settings.log_level,
            log_format=settings.log_format,
        )
        spies["validate_security_settings"].assert_called_once_with()
        spies["create_pool"].assert_called_once_with(
            application_name="oralhistarchiv-scheduler",
            statement_timeout=settings.scheduler_statement_timeout,
        )
        pool.open.assert_awaited_once_with()
        spies["validate_runtime_schema"].assert_awaited_once_with(pool, process="scheduler")
        spies["CatalogueStatsCache"].assert_called_once_with(pool, subscribe=False)
        spies["RunningJobTracker"].assert_called_once_with()
        spies["create_scheduler"].assert_called_once_with(
            pool,
            stats_cache,
            tracker,
        )

        assert spies["add_signal_handler"].call_count == 2
        scheduler.start.assert_called_once_with()
        scheduler.pause.assert_called_once_with()
        scheduler.shutdown.assert_called_once_with(wait=False)
        assert tracker.wait_until_empty.await_count == 2

        stats_cache.stop.assert_called_once_with()
        pool.close.assert_awaited_once_with()
        assert order == [
            "pause",
            "wait",
            "shutdown",
            "wait",
            "stats_stop",
            "pool_close",
        ]

    async def test_resources_are_released_when_scheduler_shutdown_raises(self):
        """Resource cleanup happens even when APScheduler's own shutdown call
        raises, i.e. cleanup is outside the potentially failing shutdown.
        """
        order: list[str] = []

        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            stats_cache = spies["CatalogueStatsCache"].return_value

            scheduler.pause.side_effect = lambda: order.append("pause")
            tracker.wait_until_empty.side_effect = lambda: order.append("wait")

            def fail_shutdown(*, wait: bool) -> None:
                assert wait is False
                order.append("shutdown")
                raise RuntimeError("shutdown failed")

            scheduler.shutdown.side_effect = fail_shutdown
            stats_cache.stop.side_effect = lambda: order.append("stats_stop")
            pool.close.side_effect = lambda: order.append("pool_close")

            with pytest.raises(RuntimeError, match="shutdown failed"):
                await run_scheduler.main()

        scheduler.pause.assert_called_once_with()
        scheduler.shutdown.assert_called_once_with(wait=False)
        tracker.wait_until_empty.assert_awaited_once_with()
        stats_cache.stop.assert_called_once_with()
        pool.close.assert_awaited_once_with()
        assert order == ["pause", "wait", "shutdown", "stats_stop", "pool_close"]

    async def test_a_drain_timeout_forces_cancellation_then_still_cleans_up(self):
        """A normal-drain timeout enters forced cancellation, then cleans up."""
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            tracker.active_job_ids = ("full_rebuild",)
            tracker.wait_until_empty.side_effect = [
                TimeoutError("drain timed out"),
                None,
            ]

            await run_scheduler.main()

        scheduler.pause.assert_called_once_with()
        scheduler.shutdown.assert_called_once_with(wait=False)
        assert tracker.wait_until_empty.await_count == 2
        spies["CatalogueStatsCache"].return_value.stop.assert_called_once_with()
        pool.close.assert_awaited_once_with()

    async def test_resources_are_released_even_when_a_cancelled_job_never_stops(self):
        """Even expiry of both bounded waits cannot leak the cache or pool."""
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            tracker.active_job_ids = ("full_rebuild",)
            tracker.wait_until_empty.side_effect = [
                TimeoutError("normal drain timed out"),
                TimeoutError("cancellation grace timed out"),
            ]

            await run_scheduler.main()

        scheduler.shutdown.assert_called_once_with(wait=False)
        assert tracker.wait_until_empty.await_count == 2
        spies["CatalogueStatsCache"].return_value.stop.assert_called_once_with()
        pool.close.assert_awaited_once_with()


class TestMainPreflightFailures:
    """Preflight checks must stop the process before any job can be
    constructed or submitted, while still releasing what was already opened.
    """

    async def test_unsafe_security_settings_stop_the_process_before_any_pool_or_job(self):
        """Unsafe settings stop the scheduler before any DB or scheduled work."""
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            spies["validate_security_settings"].side_effect = RuntimeError(
                "unsafe scheduler configuration"
            )

            with pytest.raises(RuntimeError, match="unsafe scheduler configuration"):
                await run_scheduler.main()

        spies["setup_logging"].assert_called_once_with(
            log_level=settings.log_level,
            log_format=settings.log_format,
        )
        spies["validate_security_settings"].assert_called_once_with()
        spies["create_pool"].assert_not_called()
        pool.open.assert_not_awaited()
        spies["validate_runtime_schema"].assert_not_awaited()
        spies["CatalogueStatsCache"].assert_not_called()
        spies["RunningJobTracker"].assert_not_called()
        spies["create_scheduler"].assert_not_called()
        spies["add_signal_handler"].assert_not_called()
        scheduler.start.assert_not_called()
        scheduler.pause.assert_not_called()
        scheduler.shutdown.assert_not_called()
        tracker.wait_until_empty.assert_not_awaited()
        pool.close.assert_not_awaited()

    async def test_a_schema_mismatch_closes_the_pool_without_starting_the_scheduler(self):
        """A schema mismatch prevents construction of anything that submits
        jobs, but the already-opened pool must still be closed.
        """
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            spies["validate_runtime_schema"].side_effect = RuntimeError("schema mismatch")

            with pytest.raises(RuntimeError, match="schema mismatch"):
                await run_scheduler.main()

        spies["validate_security_settings"].assert_called_once_with()
        pool.open.assert_awaited_once_with()
        spies["validate_runtime_schema"].assert_awaited_once_with(pool, process="scheduler")
        spies["CatalogueStatsCache"].assert_not_called()
        spies["RunningJobTracker"].assert_not_called()
        spies["create_scheduler"].assert_not_called()
        spies["add_signal_handler"].assert_not_called()
        scheduler.start.assert_not_called()
        scheduler.pause.assert_not_called()
        scheduler.shutdown.assert_not_called()
        tracker.wait_until_empty.assert_not_awaited()
        pool.close.assert_awaited_once_with()


class TestUpstreamTransportPreflight:
    """The scheduler harvests from the upstream catalogue on its own, in its
    own process, so it has to apply the same transport policy the web process
    does. Over plaintext HTTP an on-path attacker could rewrite the metadata
    the archive then publishes, so a hardened deployment must not start a
    scheduler pointed at an http:// endpoint — and must stop before the
    database is even opened.
    """

    @pytest.fixture(autouse=True)
    def _hardened_deployment(self, monkeypatch):
        """Every test in this class runs under hardened (staging) policy, the
        deployment tier where the transport rule is a blocker rather than a
        recommendation."""
        monkeypatch.setattr(settings, "env_state", "staging")
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        monkeypatch.setattr(settings, "shibboleth_internal_secret", None)

    async def test_a_plaintext_upstream_url_stops_the_scheduler_before_the_database(
        self, monkeypatch
    ):
        monkeypatch.setattr(settings, "swissubase_oai_pmh_url", "http://demo.swissubase.ch/oai")

        with ExitStack() as stack:
            pool, scheduler, _tracker, spies = _patched_main(stack)
            # Run the production validator itself, not a stand-in: the point
            # of the check is that the scheduler reaches this exact policy.
            stack.enter_context(
                patch.object(
                    run_scheduler,
                    "validate_security_settings",
                    _REAL["validate_security_settings"],
                )
            )

            with pytest.raises(RuntimeError) as refusal:
                await run_scheduler.main()

        assert "SWISSUBASE_OAI_PMH_URL" in str(refusal.value)
        spies["create_pool"].assert_not_called()
        pool.open.assert_not_awaited()
        spies["create_scheduler"].assert_not_called()
        scheduler.start.assert_not_called()

    async def test_the_same_scheduler_starts_against_an_https_upstream(self, monkeypatch):
        """Positive control: only the scheme is at fault above. With an
        https:// endpoint and the same hardened settings, the scheduler
        opens its pool and starts."""
        monkeypatch.setattr(settings, "swissubase_oai_pmh_url", "https://demo.swissubase.ch/oai")

        with ExitStack() as stack:
            pool, scheduler, _tracker, spies = _patched_main(stack)
            stack.enter_context(
                patch.object(
                    run_scheduler,
                    "validate_security_settings",
                    _REAL["validate_security_settings"],
                )
            )

            await run_scheduler.main()

        spies["create_pool"].assert_called_once()
        pool.open.assert_awaited_once_with()
        scheduler.start.assert_called_once_with()


class TestMainStagingMockDataSeed:
    """On staging with mock-data seeding enabled, seeding must run after the
    schema preflight and before the scheduler is constructed.
    """

    async def test_staging_seeds_mock_data_after_its_schema_preflight(self, monkeypatch):
        monkeypatch.setattr(settings, "env_state", "staging")
        monkeypatch.setattr(settings, "seed_mock_data", True)
        order = []
        with ExitStack() as stack:
            pool, _scheduler, _tracker, spies = _patched_main(stack)
            seed = stack.enter_context(
                patch("app.services.seed_mock_data.seed_mock_data", autospec=True)
            )
            spies["validate_runtime_schema"].side_effect = lambda *_args, **_kwargs: order.append(
                "preflight"
            )
            seed.side_effect = lambda *_args: order.append("seed")
            await run_scheduler.main()
        seed.assert_awaited_once_with(pool)
        assert order == ["preflight", "seed"]
