"""Watermark + threadpool-offload mechanics of the sync orchestrator (unit tier).

Backlog §3.1 (watermark captured before the fetch), §3.2 (tz-correct `since=`),
§3.11a (both Source-A entry points offload the blocking harvest via
run_in_threadpool — the copy-paste-divergence seam), plus the fetch-failure
error-recording path and the empty-sync_status guard.

No DB, no network, no threads: `app.services.sync.get_db_cursor` is patched
with a factory producing FakeCursorCtx objects around ONE shared mock cursor
(so every SQL execute is captured in order), and
`app.services.sync.run_in_threadpool` is an AsyncMock, so fetch_updates never
actually runs.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

import app.services.sync as sync
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

# An aware, deliberately non-UTC watermark: 2026-03-01 14:00 at UTC+1
# (i.e. 13:00Z). Used to pin the §3.2 astimezone(utc) conversion.
NON_UTC_WATERMARK = datetime(2026, 3, 1, 14, 0, tzinfo=timezone(timedelta(hours=1)))


def _make_shared_cursor(watermark=NON_UTC_WATERMARK):
    """One cursor shared by every get_db_cursor entry; its fetchone answers
    the `SELECT last_harvest_date FROM sync_status` read."""
    fetchone = {"last_harvest_date": watermark} if watermark is not None else None
    return make_async_cursor(fetchone=fetchone)


def _patch_db(cur):
    """Patch the sync module's get_db_cursor with a FakeCursorCtx factory."""
    return patch(
        "app.services.sync.get_db_cursor",
        side_effect=lambda pool: FakeCursorCtx(cur),
    )


def _watermark_writes(cur):
    """All executes that WRITE the watermark (the _update_sync_timestamp /
    _update_full_rebuild_timestamp UPDATEs). The initial SELECT of
    last_harvest_date has no '=' and is deliberately not matched."""
    return [
        c for c in cur.execute.await_args_list
        if "last_harvest_date =" in str(c.args[0])
    ]


def _sync_error_writes(cur):
    """All executes that touch last_sync_error (_record_sync_error and
    _clear_sync_error both match; tests disambiguate via params)."""
    return [
        c for c in cur.execute.await_args_list
        if "last_sync_error" in str(c.args[0])
    ]


async def test_watermark_is_harvest_start_not_post_processing_time():
    """§3.1 — the last_harvest_date written is the harvest START.

    Regression: the sync used to stamp now() AFTER processing, so anything
    modified upstream between the server's response and end-of-run fell into
    the gap permanently (silent loss until a full rebuild). The written
    timestamp must therefore sit between our pre-call now() and the instant
    the fetch was invoked — never after processing.
    """
    cur = _make_shared_cursor()
    fetch_instants = []

    def _record_fetch_instant(*args, **kwargs):
        fetch_instants.append(datetime.now(timezone.utc))
        return []

    t0 = datetime.now(timezone.utc)
    with _patch_db(cur), patch(
        "app.services.sync.run_in_threadpool",
        new=AsyncMock(side_effect=_record_fetch_instant),
    ):
        await sync._sync_source_a(make_mock_pool())

    writes = _watermark_writes(cur)
    assert len(writes) == 1, "expected exactly one watermark UPDATE"
    written_ts = writes[0].args[1][0]
    assert len(fetch_instants) == 1
    assert t0 <= written_ts <= fetch_instants[0], (
        "watermark must be captured before the fetch, not post-processing"
    )


async def test_since_param_converts_watermark_to_true_utc_instant():
    """§3.2 — a stored watermark of 14:00+01:00 must yield since=13:00:00Z.

    Regression: strftime('...Z') on the raw datetime discarded tzinfo and
    appended a literal Z, sending an under-fetching from= (offset-wrong) to
    the OAI endpoint under any non-UTC session timezone. The fix is
    .astimezone(timezone.utc) before formatting.
    """
    cur = _make_shared_cursor(watermark=NON_UTC_WATERMARK)
    threadpool = AsyncMock(return_value=[])
    with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
        await sync._sync_source_a(make_mock_pool())

    threadpool.assert_awaited_once()
    assert threadpool.call_args.kwargs["since"] == "2026-03-01T13:00:00Z"


async def test_sync_source_a_offloads_fetch_via_run_in_threadpool():
    """§3.11a — _sync_source_a hands fetch_updates ITSELF to run_in_threadpool.

    Mechanism-not-timing guard for the offload seam: the blocking requests-
    based harvest must never run directly on the event loop. Asserting the
    first positional arg IS the module's fetch_updates pins the call path.
    """
    cur = _make_shared_cursor()
    threadpool = AsyncMock(return_value=[])
    with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
        await sync._sync_source_a(make_mock_pool())

    threadpool.assert_awaited_once()
    assert threadpool.call_args.args[0] is sync.fetch_updates


async def test_full_rebuild_offloads_fetch_via_run_in_threadpool():
    """§3.11a — _full_rebuild_source_a also wraps fetch_updates in
    run_in_threadpool (with the fixed epoch since=).

    THE copy-paste-divergence regression: the rebuild sibling once called the
    synchronous fetch_updates directly, freezing the scheduler's event loop
    for the whole harvest (missed jobs, un-runnable SIGTERM handler, hung
    deploys). An empty fetch result makes the rebuild exit early — the call
    assertion alone proves the wrapper is in place.
    """
    cur = _make_shared_cursor()
    threadpool = AsyncMock(return_value=[])
    with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
        await sync._full_rebuild_source_a(make_mock_pool())

    threadpool.assert_awaited_once()
    assert threadpool.call_args.args[0] is sync.fetch_updates
    # Full rebuild always harvests from the epoch, not the watermark.
    assert threadpool.call_args.kwargs["since"] == "1900-01-01T00:00:00Z"
    # Empty result -> early exit: no delete, no watermark write.
    assert _watermark_writes(cur) == []


async def test_fetch_failure_records_error_and_does_not_advance_watermark():
    """Fetch-failure path — swallow, record, and DO NOT advance the watermark.

    A fetch exception must not propagate out of _sync_source_a (the scheduler
    job would die); instead a sanitized message lands in
    sync_status.last_sync_error, and the last_harvest_date watermark is left
    untouched so the failed window is re-fetched next run (advancing it would
    silently skip the window forever — the §3.1 loss mode via another door).
    """
    cur = _make_shared_cursor()
    threadpool = AsyncMock(side_effect=Exception("boom"))
    with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
        # Must not raise.
        await sync._sync_source_a(make_mock_pool())

    error_writes = _sync_error_writes(cur)
    assert len(error_writes) == 1, "expected exactly one last_sync_error UPDATE"
    # _record_sync_error params: (message, error_timestamp)
    message = error_writes[0].args[1][0]
    assert message == "Incremental sync (fetch): Exception: boom"
    # Watermark must NOT advance past the failed fetch window.
    assert _watermark_writes(cur) == []


async def test_empty_sync_status_raises_runtime_error():
    """Missing sync_status row -> loud RuntimeError, not a NoneType crash.

    fetchone() returning None means migrations never seeded the singleton
    row; the sync must fail with the explicit operator-facing message instead
    of an AttributeError on row['last_harvest_date'].
    """
    cur = _make_shared_cursor(watermark=None)  # fetchone -> None
    threadpool = AsyncMock(return_value=[])
    with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
        with pytest.raises(RuntimeError, match="sync_status table is empty"):
            await sync._sync_source_a(make_mock_pool())

    # Failed before any fetch or write.
    threadpool.assert_not_awaited()
    assert _watermark_writes(cur) == []
