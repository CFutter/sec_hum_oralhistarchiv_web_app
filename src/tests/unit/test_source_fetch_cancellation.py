"""Cancellation owns ingestion locks through real child termination and reaping."""

import asyncio
import base64
import hashlib
import multiprocessing
import sys
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.services import ingestion, scheduler
from app.sources import (
    JsonFeedConfig,
    configure_sources,
    json_feed_fetch,
    oai_client,
    prepare_json_feed_startup,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor
from tests.source_fetch_workers import blocked_feed_worker, blocked_oai_worker
from tests.source_fixtures import legacy_source

# Allow cold interpreter startup separately from the cancellation deadlines.
_WORKER_STARTUP_TIMEOUT_SECONDS = 30


def _source(kind, endpoint):
    """Build the selected OAI or JSON source with synthetic feed credentials when required."""
    if kind == "oai":
        return legacy_source(endpoint=endpoint)
    config = JsonFeedConfig.model_validate(
        {
            "name": "cancellation_feed",
            "display": {"label": "Cancellation feed"},
            "endpoint": endpoint,
            "credential_env": "FEED_TOKEN",
            "signing_key_env": "FEED_KEY",
        }
    )
    credentials = prepare_json_feed_startup(
        [config],
        environment="dev",
        environ={
            "FEED_TOKEN": base64.urlsafe_b64encode(hashlib.sha256(b"test bearer").digest())
            .decode()
            .rstrip("="),
            "FEED_KEY": base64.urlsafe_b64encode(hashlib.sha256(b"test signing").digest())
            .decode()
            .rstrip("="),
        },
    )
    return configure_sources([config], credentials=credentials)[0]


@pytest.mark.skipif(sys.platform != "linux", reason="SIGKILL escalation targets Linux deployment")
@pytest.mark.parametrize("kind", ["oai", "feed"])
@pytest.mark.parametrize("phase", ["waiting", "partial", "complete"])
@pytest.mark.parametrize("entry", ["incremental", "rebuild", "recovery"])
async def test_cancelled_fetch_is_reaped_before_ingestion_lock_and_tracker_release(
    monkeypatch,
    tmp_path,
    kind,
    entry,
    phase,
):
    """Check cancelled fetch is reaped before ingestion lock and tracker release."""
    marker = tmp_path / phase
    source = _source(kind, f"https://unused.example.edu{marker}")
    monkeypatch.setattr(oai_client, "_harvest_worker", blocked_oai_worker)
    monkeypatch.setattr(json_feed_fetch, "_fetch_worker", blocked_feed_worker)
    row = {
        "source_cursor": None,
        "source_fingerprint": None if entry == "recovery" else source.adapter.config_fingerprint(),
        "incremental_harvest": None,
        "incremental_started_at": None,
    }
    cursor = make_async_cursor(fetchone=row)
    monkeypatch.setattr(ingestion, "get_db_cursor", lambda _db: FakeCursorCtx(cursor))
    held = False
    released = asyncio.Event()

    @asynccontextmanager
    async def run_lock(_pool):
        """Track lock ownership until scope exit, then signal its release."""
        nonlocal held
        held = True
        try:
            yield object()
        finally:
            held = False
            released.set()

    monkeypatch.setattr(ingestion, "_cross_process_sync_lock", run_lock)
    # Each pytest case owns an event loop; preserve production's one-loop contract.
    monkeypatch.setattr(ingestion, "_sync_mutex", asyncio.Lock())
    cache = SimpleNamespace(invalidate_cache=lambda: None)

    async def job():
        """Run the selected recovery, incremental, or rebuild entry point for the configured source."""
        if entry == "recovery":
            return await scheduler.sync_and_invalidate(object(), cache, source)
        run = ingestion.run_sync if entry == "incremental" else ingestion.run_full_rebuild
        return await run(object(), configured_source=source)

    tracker = scheduler.RunningJobTracker()
    task = asyncio.create_task(tracker.run("ingestion", job))
    try:
        async with asyncio.timeout(_WORKER_STARTUP_TIMEOUT_SECONDS):
            while not marker.exists():
                if task.done():
                    await task
                    pytest.fail("fetch finished before the worker started")
                await asyncio.sleep(0.01)
        released.clear()  # Recovery releases the initial incremental lock before its rebuild.
        assert held and tracker.active_job_ids == ("ingestion",)
        started = time.monotonic()
        task.cancel()
        await asyncio.sleep(0.1)
        assert not task.done()  # The deliberately SIGTERM-resistant child still owns the run.
        assert held and not released.is_set()
        assert tracker.active_job_ids == ("ingestion",)
        with pytest.raises(asyncio.CancelledError):
            async with asyncio.timeout(4):
                await task
        assert time.monotonic() - started < 5  # The production cancellation grace.
        assert released.is_set() and not held
        assert tracker.active_job_ids == ()
        assert not any(
            child.name in {"oralhistarchiv-oai-harvest", "oralhistarchiv-json-feed-fetch"}
            for child in multiprocessing.active_children()
        )
        statements = [str(call.args[0]) for call in cursor.execute.await_args_list]
        assert not any("INSERT INTO oral_history_datasets" in statement for statement in statements)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
