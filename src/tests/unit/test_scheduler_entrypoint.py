"""Tests for the standalone scheduler process lifecycle (run_scheduler.py)."""

import asyncio
import importlib.util
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from psycopg_pool import AsyncConnectionPool

from app.sources import (
    FixtureAdapter,
    FixtureConfig,
    OaiPmhCmdiAdapter,
    SourceDisplay,
    configure_sources,
)
from config import settings
from tests.source_fixtures import legacy_source

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
        "ensure_source_status_rows",
        "load_runtime_sources",
        "validate_security_settings",
        "validate_runtime_schema",
    )
}


def _patched_main(stack: ExitStack):
    """Install lifecycle stand-ins and return pool/scheduler/tracker/spies."""
    stack.enter_context(patch.object(settings, "app_process_role", "scheduler"))
    stack.enter_context(patch.object(settings, "totp_encryption_keys", []))
    stack.enter_context(patch.object(run_scheduler, "validate_parser_service", autospec=True))
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
        "load_runtime_sources": stack.enter_context(
            patch.object(
                run_scheduler,
                "load_runtime_sources",
                new=create_autospec(
                    _REAL["load_runtime_sources"],
                    return_value=(legacy_source(),),
                ),
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
        "ensure_source_status_rows": stack.enter_context(
            patch.object(
                run_scheduler,
                "ensure_source_status_rows",
                new=create_autospec(_REAL["ensure_source_status_rows"]),
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

    @pytest.mark.parametrize("environment", ["dev", "staging"])
    async def test_clean_shutdown_pauses_drains_shuts_down_then_releases_resources(
        self, monkeypatch, environment
    ):
        """Startup retains sources; shutdown releases resources in order."""
        monkeypatch.setattr(settings, "env_state", environment)
        order: list[str] = []
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            fixture_fetch = stack.enter_context(
                patch.object(
                    FixtureAdapter,
                    "fetch",
                    autospec=True,
                    side_effect=AssertionError("Scheduler startup must leave ingestion to jobs"),
                )
            )

            stats_cache = spies["CatalogueStatsCache"].return_value
            selected_sources = configure_sources(
                (
                    FixtureConfig(name="archive_one", display=SourceDisplay(label="Archive one")),
                    FixtureConfig(name="archive_two", display=SourceDisplay(label="Archive two")),
                )
            )

            spies["validate_security_settings"].side_effect = lambda: order.append("security")

            def construct_source():
                """Record source construction and return the selected sources."""
                order.append("source")
                return selected_sources

            def construct_pool(**_kwargs):
                """Record pool construction and return the configured fake pool."""
                order.append("pool")
                return pool

            spies["load_runtime_sources"].side_effect = construct_source
            spies["create_pool"].side_effect = construct_pool
            pool.open.side_effect = lambda: order.append("pool_open")
            spies["validate_runtime_schema"].side_effect = lambda *_args, **_kwargs: order.append(
                "preflight"
            )
            spies["ensure_source_status_rows"].side_effect = lambda *_args: order.append(
                "provision"
            )
            scheduler.start.side_effect = lambda: order.append("start")
            scheduler.pause.side_effect = lambda: order.append("pause")
            tracker.wait_until_empty.side_effect = lambda: order.append("wait")
            scheduler.shutdown.side_effect = lambda **_kwargs: order.append("shutdown")
            stats_cache.stop.side_effect = lambda: order.append("stats_stop")
            pool.close.side_effect = lambda: order.append("pool_close")

            await run_scheduler.main()

        fixture_fetch.assert_not_called()
        pool.connection.assert_not_called()

        spies["setup_logging"].assert_called_once_with(
            log_level=settings.log_level,
            log_format=settings.log_format,
        )
        spies["validate_security_settings"].assert_called_once_with()
        spies["load_runtime_sources"].assert_called_once_with()
        spies["create_pool"].assert_called_once_with(
            application_name="oralhistarchiv-scheduler",
            statement_timeout=settings.scheduler_statement_timeout,
        )
        pool.open.assert_awaited_once_with()
        spies["validate_runtime_schema"].assert_awaited_once_with(pool, process="scheduler")
        spies["CatalogueStatsCache"].assert_called_once_with(
            pool,
            source_names=tuple(source.name for source in selected_sources),
            policy_fingerprint=run_scheduler.build_catalogue_policy(selected_sources).fingerprint,
            subscribe=False,
        )
        spies["RunningJobTracker"].assert_called_once_with()
        spies["create_scheduler"].assert_called_once_with(
            pool,
            stats_cache,
            tracker,
            selected_sources,
        )
        assert spies["create_scheduler"].call_args.args[3] is selected_sources
        spies["ensure_source_status_rows"].assert_awaited_once_with(
            pool,
            tuple(source.name for source in selected_sources),
        )

        assert spies["add_signal_handler"].call_count == 2
        scheduler.start.assert_called_once_with()
        scheduler.pause.assert_called_once_with()
        scheduler.shutdown.assert_called_once_with(wait=False)
        assert tracker.wait_until_empty.await_count == 2
        stats_cache.stop.assert_called_once_with()
        pool.close.assert_awaited_once_with()
        assert order == [
            "security",
            "source",
            "pool",
            "pool_open",
            "preflight",
            "provision",
            "start",
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
                """Require nonwaiting scheduler shutdown, record it, and raise the injected failure."""
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
        spies["load_runtime_sources"].assert_not_called()
        spies["create_pool"].assert_not_called()
        pool.open.assert_not_awaited()
        spies["validate_runtime_schema"].assert_not_awaited()
        spies["ensure_source_status_rows"].assert_not_awaited()
        spies["CatalogueStatsCache"].assert_not_called()
        spies["RunningJobTracker"].assert_not_called()
        spies["create_scheduler"].assert_not_called()
        spies["add_signal_handler"].assert_not_called()
        scheduler.start.assert_not_called()
        scheduler.pause.assert_not_called()
        scheduler.shutdown.assert_not_called()
        tracker.wait_until_empty.assert_not_awaited()
        pool.close.assert_not_awaited()

    async def test_invalid_source_configuration_stops_before_any_pool_or_job(self):
        """Source construction must finish before database resources open."""
        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            spies["load_runtime_sources"].side_effect = ValueError(
                "invalid legacy source configuration"
            )

            with pytest.raises(ValueError, match="invalid legacy source configuration"):
                await run_scheduler.main()

        spies["validate_security_settings"].assert_called_once_with()
        spies["load_runtime_sources"].assert_called_once_with()
        spies["create_pool"].assert_not_called()
        pool.open.assert_not_awaited()
        spies["validate_runtime_schema"].assert_not_awaited()
        spies["ensure_source_status_rows"].assert_not_awaited()
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

    async def test_source_provisioning_failure_closes_pool_before_jobs(self):
        """Unprovisioned durable state prevents job construction."""
        with ExitStack() as stack:
            pool, scheduler, _tracker, spies = _patched_main(stack)
            spies["ensure_source_status_rows"].side_effect = RuntimeError(
                "source provisioning failed"
            )

            with pytest.raises(RuntimeError, match="source provisioning failed"):
                await run_scheduler.main()

        spies["validate_runtime_schema"].assert_awaited_once_with(pool, process="scheduler")
        spies["ensure_source_status_rows"].assert_awaited_once_with(
            pool,
            tuple(source.name for source in spies["load_runtime_sources"].return_value),
        )
        spies["CatalogueStatsCache"].assert_not_called()
        spies["RunningJobTracker"].assert_not_called()
        spies["create_scheduler"].assert_not_called()
        scheduler.start.assert_not_called()
        pool.close.assert_awaited_once_with()


class TestUpstreamTransportPreflight:
    """The scheduler harvests from the upstream catalogue on its own, in its own process, so it has to
    apply the same transport policy the web process does.
    """

    @pytest.fixture(autouse=True)
    def _hardened_deployment(self, monkeypatch):
        """Every test in this class runs under hardened (staging) policy, the
        deployment tier where the transport rule is a blocker rather than a
        recommendation."""
        monkeypatch.setattr(settings, "env_state", "staging")
        monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
        monkeypatch.setattr(settings, "shibboleth_internal_secret", None)

    @pytest.mark.parametrize(
        ("selected_path", "endpoint", "message"),
        [
            (
                None,
                "https://archive.example.edu/oai",
                r"SOURCES_CONFIG_FILE.*required",
            ),
            (
                "/etc/oralhistarchiv-sources/sources.toml",
                "http://archive.example.edu/oai",
                r"requires.*HTTPS endpoint",
            ),
            (
                "/etc/oralhistarchiv-sources/sources.toml",
                "https://archive.example.org/oai",
                "placeholder endpoint host",
            ),
        ],
        ids=["missing-selection", "plaintext", "placeholder"],
    )
    async def test_source_refusal_stops_scheduler_before_resources(
        self, monkeypatch, selected_path, endpoint, message
    ):
        """Check source refusal stops scheduler before resources (ValueError)."""
        monkeypatch.setattr(settings, "sources_config_file", selected_path)
        document = (
            "[[sources]]\n"
            'name = "selected_archive"\n'
            'adapter = "oai_pmh_cmdi"\n'
            'label = "Selected archive"\n'
            'institution_filter = "Configured archive"\n'
            f'endpoint = "{endpoint}"\n'
        )

        with ExitStack() as stack:
            pool, scheduler, tracker, spies = _patched_main(stack)
            reader = stack.enter_context(
                patch(
                    "app.sources.startup_file._read_hardened_file",
                    autospec=True,
                    return_value=document,
                )
            )
            spies["validate_security_settings"].side_effect = _REAL["validate_security_settings"]
            spies["load_runtime_sources"].side_effect = _REAL["load_runtime_sources"]

            with pytest.raises(ValueError, match=message):
                await run_scheduler.main()

        assert reader.call_count == int(selected_path is not None)
        spies["validate_security_settings"].assert_called_once_with()
        spies["load_runtime_sources"].assert_called_once_with()
        spies["create_pool"].assert_not_called()
        pool.open.assert_not_awaited()
        spies["validate_runtime_schema"].assert_not_awaited()
        spies["ensure_source_status_rows"].assert_not_awaited()
        spies["CatalogueStatsCache"].assert_not_called()
        spies["RunningJobTracker"].assert_not_called()
        spies["create_scheduler"].assert_not_called()
        spies["add_signal_handler"].assert_not_called()
        scheduler.start.assert_not_called()
        scheduler.pause.assert_not_called()
        scheduler.shutdown.assert_not_called()
        tracker.wait_until_empty.assert_not_awaited()
        pool.close.assert_not_awaited()

    async def test_the_same_scheduler_starts_against_a_selected_https_upstream(self, monkeypatch):
        """Check the same scheduler starts against a selected https upstream."""
        monkeypatch.setattr(
            settings, "sources_config_file", "/etc/oralhistarchiv-sources/sources.toml"
        )
        document = (
            "[[sources]]\n"
            'name = "selected_archive"\n'
            'adapter = "oai_pmh_cmdi"\n'
            'label = "Selected archive"\n'
            'institution_filter = "Configured archive"\n'
            'endpoint = "https://archive.example.edu/oai"\n'
        )

        with ExitStack() as stack:
            pool, scheduler, _tracker, spies = _patched_main(stack)
            reader = stack.enter_context(
                patch(
                    "app.sources.startup_file._read_hardened_file",
                    autospec=True,
                    return_value=document,
                )
            )
            fetch = stack.enter_context(patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True))
            spies["validate_security_settings"].side_effect = _REAL["validate_security_settings"]
            spies["load_runtime_sources"].side_effect = _REAL["load_runtime_sources"]

            await run_scheduler.main()

        reader.assert_called_once()
        spies["load_runtime_sources"].assert_called_once_with()
        spies["create_pool"].assert_called_once()
        pool.open.assert_awaited_once_with()
        spies["ensure_source_status_rows"].assert_awaited_once_with(pool, ("selected_archive",))
        sources = spies["create_scheduler"].call_args.args[3]
        assert tuple(source.name for source in sources) == ("selected_archive",)
        assert isinstance(sources[0].adapter, OaiPmhCmdiAdapter)
        scheduler.start.assert_called_once_with()
        fetch.assert_not_called()
