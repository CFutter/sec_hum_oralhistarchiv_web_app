"""Locked-connection entry points and their shared seams for app.services.sync
(unit tier).

Covers `_run_sync_on_locked_connection` / `_run_full_rebuild_on_locked_connection`
— the session that already owns the ingestion lock — surfacing every failure
as a `SyncOutcome` or as a bounded, propagated exception, and never leaving
the caller mid-write past their write-phase deadline; the threadpool-offload
seam both Source-A entry points share (`_sync_source_a` /
`_full_rebuild_source_a` hand `fetch_updates_isolated` itself to
`run_in_threadpool`); and `_sanitize_error_message`, the pure-function
scrubber that keeps internal file paths out of every message this module
writes to `sync_status.last_sync_error`.

No DB, no network, no threads: `app.services.sync.get_db_cursor` is patched
with a factory producing FakeCursorCtx objects around ONE shared mock cursor
(so every SQL execute is captured in order), and
`app.services.sync.run_in_threadpool` is autospecced against the real
starlette.concurrency.run_in_threadpool, so fetch_updates_isolated never
actually runs.

The harvest watermark, harvest application, fetch-failure handling, recovery
after an interrupted run, the rebuild-aborted exception, and the full-rebuild
success threshold are covered separately, in
`src/tests/unit/test_sync_incremental.py`.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import create_autospec, patch

import pytest
from psycopg import InterfaceError, OperationalError
from psycopg_pool import PoolTimeout

from app.services import sync
from app.services.oai_client import HarvestResult
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record

# An aware, deliberately non-UTC watermark: 2026-03-01 14:00 at UTC+1
# (i.e. 13:00Z). Pins the astimezone(utc) conversion of since=.
NON_UTC_WATERMARK = datetime(2026, 3, 1, 14, 0, tzinfo=timezone(timedelta(hours=1)))


def _harvest(
    *matching_records,
    deleted=(),
    nonmatching=(),
    uncertain=None,
) -> HarvestResult:
    """Build the real fetch_updates_isolated return type for orchestrator tests."""
    return HarvestResult(
        source_cursor=SOURCE_CURSOR,
        matching_records=list(matching_records),
        deleted_uuids=set(deleted),
        nonmatching_uuids=set(nonmatching),
        uncertain_records=dict(uncertain or {}),
    )


def _make_shared_cursor(watermark=NON_UTC_WATERMARK):
    """One cursor shared by every get_db_cursor entry; its fetchone answers
    the `SELECT last_harvest_date FROM sync_status` read."""
    fetchone = (
        {
            "source_cursor": watermark,
            "source_fingerprint": sync._source_a_fingerprint(),
            "incremental_harvest": None,
            "incremental_started_at": None,
            "incremental_position": 0,
            "incremental_affected": 0,
        }
        if watermark is not None
        else None
    )
    return make_async_cursor(fetchone=fetchone)


def _patch_db(cur):
    """Patch the sync module's get_db_cursor with a FakeCursorCtx factory."""
    return patch(
        "app.services.sync.get_db_cursor",
        autospec=True,
        side_effect=lambda _pool: FakeCursorCtx(cur),
    )


def _threadpool_double(**kwargs):
    """An autospecced stand-in for app.services.sync.run_in_threadpool.

    Signature-checked against the real starlette.concurrency.run_in_threadpool
    so a call that drops/renames an argument fails here, not silently.
    """
    return create_autospec(sync.run_in_threadpool, **kwargs)


def _watermark_writes(cur):
    """All executes that WRITE the watermark (the _update_sync_timestamp /
    _update_full_rebuild_timestamp UPDATEs). The initial SELECT of
    last_harvest_date has no '=' and is deliberately not matched."""
    return [c for c in cur.execute.await_args_list if "last_harvest_date =" in str(c.args[0])]


class TestThreadpoolOffload:
    """Both Source-A entry points offload their blocking harvest identically.

    The incremental sync and the full rebuild once diverged here: the
    rebuild sibling called the synchronous fetch_updates_isolated directly,
    freezing the scheduler's event loop for the whole harvest (missed jobs,
    an un-runnable SIGTERM handler, hung deploys). Asserting that the first
    positional argument IS the module's fetch_updates_isolated pins the call
    path for both entry points.
    """

    async def test_incremental_sync_offloads_fetch_via_run_in_threadpool(self):
        """_sync_source_a hands fetch_updates_isolated ITSELF to run_in_threadpool."""
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.args[0] is sync.fetch_updates_isolated

    async def test_full_rebuild_offloads_fetch_via_run_in_threadpool(self):
        """_full_rebuild_source_a also wraps fetch_updates_isolated in
        run_in_threadpool, harvesting from the fixed epoch rather than the
        watermark.

        An empty fetch result makes the rebuild exit early — the call
        assertion alone proves the wrapper is in place.
        """
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            await sync._full_rebuild_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.args[0] is sync.fetch_updates_isolated
        # Full rebuild always harvests from the epoch, not the watermark.
        assert threadpool.call_args.kwargs["since"] == "1900-01-01"
        # Empty result -> early exit: no delete, no watermark write.
        assert _watermark_writes(cur) == []


class TestErrorMessageSanitisation:
    """`_sanitize_error_message` strips internal file paths and caps length
    before a message reaches `sync_status.last_sync_error` or `/health/detail`."""

    def test_strips_file_paths(self):
        """Absolute .py paths are replaced with '<file>' so internal layout
        never leaks into sync_status / /health/detail."""
        msg = "ValueError: boom in /opt/app/services/sync.py while syncing"
        out = sync._sanitize_error_message(msg)
        assert "/opt/app/services/sync.py" not in out
        assert "<file>" in out
        assert out == "ValueError: boom in <file> while syncing"

    def test_truncates_long_messages(self):
        """Messages longer than 500 chars are truncated to 500 + '...'."""
        out = sync._sanitize_error_message("x" * 600)
        assert out == "x" * 500 + "..."
        assert len(out) == 503

    # The path regex — r"(?:[A-Za-z]:)?[\\/]?[\w./\\-]+\.py" — is pinned
    # against its actual behaviour across path shapes beyond the plain
    # absolute-POSIX case above, instead of trusting a prediction.

    def test_strips_windows_drive_letter_path(self):
        """A Windows-style 'C:\\...\\sync.py' path (the drive-letter branch of
        the regex) is scrubbed to '<file>' just like the POSIX case, with the
        surrounding words (positive control) left intact."""
        msg = r"Error at C:\app\services\sync.py line 10"
        out = sync._sanitize_error_message(msg)
        assert out == "Error at <file> line 10"
        assert "sync.py" not in out
        assert "line 10" in out  # positive control: non-path text is untouched

    def test_strips_relative_path_keeps_trailing_text(self):
        """A relative path with no leading slash ('src/app/services/foo.py')
        is still recognized and scrubbed; trailing words after it survive."""
        msg = "src/app/services/foo.py boom"
        out = sync._sanitize_error_message(msg)
        assert out == "<file> boom"
        assert "foo.py" not in out

    def test_strips_bare_filename(self):
        """Even a bare filename with no directory component ('sync.py') is
        scrubbed — the regex's path segment is '+' (one-or-more), so a lone
        filename alone still satisfies it. Surrounding words are a positive
        control that the sanitizer isn't just blanking the whole message."""
        msg = "bare sync.py mention"
        out = sync._sanitize_error_message(msg)
        assert out == "bare <file> mention"
        assert "sync.py" not in out

    def test_url_ending_in_py_absorbs_scheme_letter(self):
        """Pinned, not idealized: a URL ending in '.py' also matches, but the
        regex's optional '[A-Za-z]:' drive-letter branch greedily latches
        onto the 's' immediately before the '://' colon in 'https:', so the
        match starts at that 's:' — not at the 'h' of 'https'. The actual
        output is the mangled 'http<file>?x=1', not a clean 'http<file>'.
        The invariant that matters (no raw path/filename or full URL
        leaking) still holds, so this pins the real behaviour rather than a
        prediction."""
        msg = "fetch failed for https://example.com/download/report.py?x=1"
        out = sync._sanitize_error_message(msg)
        assert out == "fetch failed for http<file>?x=1"
        assert "report.py" not in out
        assert "example.com" not in out

    def test_pathless_message_is_unchanged(self):
        """A message with no '*.py'-shaped substring at all passes through
        byte-for-byte — the regex must not have false positives on ordinary
        prose. Positive control for all the stripping tests above."""
        msg = "ValueError: something went wrong, no paths here"
        out = sync._sanitize_error_message(msg)
        assert out == msg


class TestLockedConnectionEntryPoints:
    """`_run_sync_on_locked_connection` / `_run_full_rebuild_on_locked_connection`
    — the session that already owns the ingestion lock — surface every
    failure as a `SyncOutcome`, or as a bounded, propagated exception, and
    never leave the caller mid-write past their write-phase deadline.

    The advisory-lock acquisition itself (before either entry point runs) is
    exercised separately, against a real database, in
    `src/tests/integration/test_code_quality_recovery_db.py`.
    """

    @pytest.mark.parametrize(
        "error",
        [PoolTimeout, OperationalError, InterfaceError, RuntimeError],
        ids=["pool_timeout", "operational_error", "interface_error", "runtime_error"],
    )
    async def test_write_phase_failure_makes_exactly_one_bounded_failure_report_attempt(
        self, monkeypatch, error
    ):
        """Once the harvest is fetched, a failure writing it to
        `sync_status` is reported through exactly one further, best-effort
        `get_db_cursor` call (the failure-report attempt itself is allowed
        to fail silently), and the original exception still propagates to
        the caller — it must never be swallowed by the failure-reporting
        path, and no further catalogue writes are attempted."""
        status = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
                "incremental_failures": {},
            }
        )
        get_cursor = create_autospec(
            sync.get_db_cursor, side_effect=[FakeCursorCtx(status), error("unavailable")]
        )
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[parsed_record(f"record-{i}") for i in range(3)],
        )
        monkeypatch.setattr(sync, "get_db_cursor", get_cursor)
        monkeypatch.setattr(sync, "run_in_threadpool", _threadpool_double(return_value=harvest))
        locked_connection = object()

        with pytest.raises(error, match="unavailable"):
            await sync._run_sync_on_locked_connection(locked_connection)

        # One status read, one failed write, one best-effort (also failing,
        # and silently swallowed) failure-report attempt — no more.
        assert get_cursor.call_count == 3

    @pytest.mark.parametrize(
        "rebuild",
        [False, True],
        ids=["incremental_sync", "full_rebuild"],
    )
    async def test_write_phase_is_cancelled_at_its_configured_deadline(self, monkeypatch, rebuild):
        """A write that hangs past `sync_write_timeout_seconds` is cancelled
        (both entry points share the same `asyncio.timeout` write-phase
        guard) and raises `TimeoutError` rather than hanging the sync job
        forever; the blocked write observes its own cancellation."""
        cur = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
                "incremental_failures": {},
                # Full rebuild's contraction guard (`_delete_stale_source_records`)
                # also reads from this cursor; zero on both sides keeps the
                # guard from tripping before the deliberately-blocked upsert
                # is reached.
                "existing_count": 0,
                "inferred_delete_count": 0,
            }
        )
        monkeypatch.setattr(sync, "get_db_cursor", lambda _pool: FakeCursorCtx(cur))
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR, matching_records=[parsed_record("record-1")]
        )
        monkeypatch.setattr(sync, "run_in_threadpool", _threadpool_double(return_value=harvest))
        monkeypatch.setattr(sync.settings, "sync_write_timeout_seconds", 0.01)
        cancelled = asyncio.Event()

        async def blocked_write(*_args):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr(sync, "_upsert_public_catalogue_record", blocked_write)
        locked_connection = object()
        runner = (
            sync._run_full_rebuild_on_locked_connection
            if rebuild
            else sync._run_sync_on_locked_connection
        )

        with pytest.raises(TimeoutError):
            await runner(locked_connection)

        assert cancelled.is_set()

    async def test_fetch_failure_is_reported_as_a_failed_outcome_not_raised(self, monkeypatch):
        """Both entry points classify a harvest-fetch failure as a `failed`
        `SyncOutcome` with nothing applied, rather than letting the
        exception propagate out of the locked-connection session."""
        cur = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
                "incremental_failures": {},
            }
        )
        monkeypatch.setattr(sync, "get_db_cursor", lambda _pool: FakeCursorCtx(cur))
        monkeypatch.setattr(
            sync, "run_in_threadpool", _threadpool_double(side_effect=ValueError("bad harvest"))
        )
        locked_connection = object()

        for runner in (
            sync._run_sync_on_locked_connection,
            sync._run_full_rebuild_on_locked_connection,
        ):
            result = await runner(locked_connection)
            assert result.status == "failed"
            assert result.affected_count == 0


class TestLockedSyncSurfacesTheFullReharvestSignalAsATypedOutcome:
    """`_run_sync_on_locked_connection` never lets `_FullReharvestRequired`
    escape as a bare exception: it records the incremental error and returns
    a typed `SyncOutcome` the caller (the scheduler) can act on without
    string-matching a reason."""

    async def test_full_reharvest_signal_becomes_a_typed_outcome_with_no_catalogue_mutation(
        self, monkeypatch
    ):
        cur = make_async_cursor()
        monkeypatch.setattr(
            sync,
            "get_db_cursor",
            create_autospec(sync.get_db_cursor, side_effect=lambda _pool: FakeCursorCtx(cur)),
        )
        monkeypatch.setattr(
            sync,
            "_sync_source_a",
            create_autospec(
                sync._sync_source_a,
                side_effect=sync._FullReharvestRequired("committed fingerprint mismatch"),
            ),
        )

        outcome = await sync._run_sync_on_locked_connection(object())

        assert outcome == sync.SyncOutcome(
            "failed", reason="full rebuild required", requires_full_rebuild=True
        )
        error_writes = [
            c for c in cur.execute.await_args_list if "last_sync_error" in str(c.args[0])
        ]
        assert len(error_writes) == 1
        assert "requires a full rebuild" in error_writes[0].args[1][0]
        assert not any(
            "oral_history_datasets" in str(c.args[0]) for c in cur.execute.await_args_list
        )

    async def test_an_ordinary_successful_sync_passes_through_unmodified(self, monkeypatch):
        """Positive control: an ordinary success is returned as-is, with no
        error recorded and no recovery flag set."""
        success = sync.SyncOutcome("success", affected_count=3)
        monkeypatch.setattr(
            sync, "_sync_source_a", create_autospec(sync._sync_source_a, return_value=success)
        )

        outcome = await sync._run_sync_on_locked_connection(object())

        assert outcome == success
        assert outcome.requires_full_rebuild is False
