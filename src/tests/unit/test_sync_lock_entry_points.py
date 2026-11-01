"""Locked-connection entry points and their shared seams for app.services.ingestion (unit tier)."""

import asyncio
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import create_autospec, patch

import pytest
from psycopg import InterfaceError, OperationalError
from psycopg_pool import PoolTimeout

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.sources.oai_pmh_cmdi import OaiPmhCmdiAdapter
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import legacy_source

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
            "source_fingerprint": legacy_source().adapter.config_fingerprint(),
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
        "app.services.ingestion.get_db_cursor",
        autospec=True,
        side_effect=lambda _pool: FakeCursorCtx(cur),
    )


def _threadpool_double(**kwargs):
    """Return a signature-checked stand-in for ingestion source fetching."""
    return create_autospec(ingestion.run_source_fetch, **kwargs)


def _watermark_writes(cur):
    """Select watermark UPDATE calls while excluding the initial timestamp read."""
    return [c for c in cur.execute.await_args_list if "last_harvest_date =" in str(c.args[0])]


class TestThreadpoolOffload:
    """Both Source-A entry points offload their blocking harvest identically."""

    async def test_incremental_sync_offloads_fetch_via_run_source_fetch(self):
        """Incremental sync offloads the configured adapter's bound fetch method."""
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(return_value=_harvest())
        configured_source = legacy_source(max_pages=7)
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_awaited_once()
        fetch = threadpool.call_args.args[0]
        assert fetch.__func__ is OaiPmhCmdiAdapter.fetch
        assert isinstance(fetch.__self__, OaiPmhCmdiAdapter)
        assert fetch.__self__ is configured_source.adapter
        assert fetch.__self__.max_pages == 7
        assert threadpool.call_args.kwargs == {"since": datetime(2026, 2, 27, 13, tzinfo=UTC)}

    async def test_full_rebuild_offloads_fetch_via_run_source_fetch(self):
        """Full rebuild also offloads the configured adapter's bound fetch, harvesting from the fixed
        epoch rather than the watermark.
        """
        cur = _make_shared_cursor()
        cur.fetchone.return_value["failed_count"] = 0
        threadpool = _threadpool_double(return_value=_harvest())
        configured_source = legacy_source(max_pages=11)
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_awaited_once()
        fetch = threadpool.call_args.args[0]
        assert fetch.__func__ is OaiPmhCmdiAdapter.fetch
        assert isinstance(fetch.__self__, OaiPmhCmdiAdapter)
        assert fetch.__self__ is configured_source.adapter
        assert fetch.__self__.max_pages == 11
        assert threadpool.call_args.kwargs == {"since": None}
        assert _watermark_writes(cur) == []


class TestErrorMessageSanitisation:
    """Redact URLs/Python paths and bound sync diagnostics before storage or display."""

    def test_strips_file_paths(self):
        """Absolute .py paths are replaced with '<file>' so internal layout
        never leaks into sync_status / /health/detail."""
        msg = "ValueError: boom in /opt/app/services/ingestion.py while syncing"
        out = ingestion._sanitize_error_message(msg)
        assert "/opt/app/services/ingestion.py" not in out
        assert "<file>" in out
        assert out == "ValueError: boom in <file> while syncing"

    def test_truncates_long_messages(self):
        """Messages longer than 500 chars are truncated to 500 + '...'."""
        out = ingestion._sanitize_error_message("x" * 600)
        assert out == "x" * 500 + "..."
        assert len(out) == 503

    def test_strips_windows_drive_letter_path(self):
        """Check strips windows drive letter path."""
        msg = r"Error at C:\app\services\ingestion.py line 10"
        out = ingestion._sanitize_error_message(msg)
        assert out == "Error at <file> line 10"
        assert "ingestion.py" not in out
        assert "line 10" in out

    def test_strips_relative_path_keeps_trailing_text(self):
        """A relative path with no leading slash ('src/app/services/foo.py')
        is still recognized and scrubbed; trailing words after it survive."""
        msg = "src/app/services/foo.py boom"
        out = ingestion._sanitize_error_message(msg)
        assert out == "<file> boom"
        assert "foo.py" not in out

    def test_strips_bare_filename(self):
        """Check strips bare filename."""
        msg = "bare ingestion.py mention"
        out = ingestion._sanitize_error_message(msg)
        assert out == "bare <file> mention"
        assert "ingestion.py" not in out

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/feed?token=private-query#private-fragment",
            "https://user:private-password@example.com/download/report.py?token=private#secret",
            "HTTP://example.com/report.py?token=private#secret",
            "ftp://example.com/report.py?token=private#secret",
            "postgresql://user:private-password@example.com/archive?token=private#secret",
        ],
    )
    def test_redacts_complete_url_before_python_paths(self, url):
        """Remove each URL, including credentials/query/fragment, before .py path matching."""
        msg = f"fetch failed for {url}"
        out = ingestion._sanitize_error_message(msg)
        assert out == "fetch failed for <url>"

    def test_redacts_multiple_urls_and_python_paths_independently(self):
        """Keep surrounding diagnostics while removing both URL and file-path tokens."""
        msg = (
            "failed https://example.com/feed?secret=one#first and "
            "https://other.example/report.py?secret=two#second at /opt/private/worker.py"
        )
        assert ingestion._sanitize_error_message(msg) == "failed <url> and <url> at <file>"

    def test_redacts_urls_with_controls_and_escapes_remaining_controls(self):
        """Remove controls inside URL tokens and escape controls in surrounding diagnostics."""
        msg = "failed\x1b https://example.com/report.py?token=private\x00value#secret\u202e \nretry\tlater"
        assert ingestion._sanitize_error_message(msg) == r"failed\x1b <url> \nretry\tlater"

    @pytest.mark.parametrize("ending", ["\n", "\r\n", ""])
    def test_strips_traceback_paths_without_python_extension(self, ending):
        """Remove traceback file entries at a line ending or EOF without relying on .py."""
        msg = f'Error:\n  File "/opt/private/template.html", line 10, in render{ending}'
        assert ingestion._sanitize_error_message(msg) == "Error: "

    def test_redacts_before_truncation(self):
        """A long URL disappears before the output-length budget is applied."""
        msg = "failed https://example.com/feed?secret=" + "x" * 600 + "#private retry"
        assert ingestion._sanitize_error_message(msg, max_length=18) == "failed <url> retry"

    def test_pathless_message_is_unchanged(self):
        """Check pathless message is unchanged."""
        msg = "ValueError: something went wrong, no paths here"
        out = ingestion._sanitize_error_message(msg)
        assert out == msg


class TestLockedConnectionEntryPoints:
    """Cover locked connection entry points."""

    @pytest.mark.parametrize(
        "error",
        [PoolTimeout, OperationalError, InterfaceError, RuntimeError],
        ids=["pool_timeout", "operational_error", "interface_error", "runtime_error"],
    )
    async def test_write_phase_failure_makes_exactly_one_bounded_failure_report_attempt(
        self, monkeypatch, error
    ):
        """Check write phase failure makes exactly one bounded failure report attempt (error)."""
        status = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            }
        )
        get_cursor = create_autospec(
            ingestion.get_db_cursor, side_effect=[FakeCursorCtx(status), error("unavailable")]
        )
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[parsed_record(f"record-{i}") for i in range(3)],
        )
        monkeypatch.setattr(ingestion, "get_db_cursor", get_cursor)
        monkeypatch.setattr(ingestion, "run_source_fetch", _threadpool_double(return_value=harvest))
        locked_connection = object()

        with pytest.raises(error, match="unavailable"):
            await ingestion._run_sync_on_locked_connection(
                locked_connection,
                configured_source=legacy_source(),
            )

        # One status read, one failed write, one best-effort (also failing,
        # and silently swallowed) failure-report attempt — no more.
        assert get_cursor.call_count == 3

    @pytest.mark.parametrize(
        "rebuild",
        [False, True],
        ids=["incremental_sync", "full_rebuild"],
    )
    async def test_write_phase_is_cancelled_at_its_configured_deadline(self, monkeypatch, rebuild):
        """A write that exceeds the selected source's write deadline is cancelled."""
        cur = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
                # Full rebuild's contraction guard (`_delete_stale_source_records`)
                # also reads from this cursor; zero on both sides keeps the
                # guard from tripping before the deliberately-blocked upsert
                # is reached.
                "existing_count": 0,
                "inferred_delete_count": 0,
            }
        )
        monkeypatch.setattr(ingestion, "get_db_cursor", lambda _pool: FakeCursorCtx(cur))
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR, matching_records=[parsed_record("record-1")]
        )
        monkeypatch.setattr(ingestion, "run_source_fetch", _threadpool_double(return_value=harvest))
        configured_source = legacy_source(schedule={"write_timeout_seconds": 1})
        cancelled = asyncio.Event()

        async def blocked_write(*_args):
            """Block the write phase indefinitely and signal when cancellation unwinds it."""
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr(ingestion, "_upsert_public_catalogue_record", blocked_write)
        locked_connection = object()
        runner = (
            ingestion._run_full_rebuild_on_locked_connection
            if rebuild
            else ingestion._run_sync_on_locked_connection
        )

        with pytest.raises(TimeoutError):
            await runner(
                locked_connection,
                configured_source=configured_source,
            )

        assert cancelled.is_set()

    async def test_fetch_failure_is_reported_as_a_failed_outcome_not_raised(self, monkeypatch):
        """Check fetch failure is reported as a failed outcome not raised."""
        cur = make_async_cursor(
            fetchone={
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            }
        )
        monkeypatch.setattr(ingestion, "get_db_cursor", lambda _pool: FakeCursorCtx(cur))
        monkeypatch.setattr(
            ingestion,
            "run_source_fetch",
            _threadpool_double(side_effect=ValueError("bad harvest")),
        )
        locked_connection = object()
        configured_source = legacy_source()

        for runner in (
            ingestion._run_sync_on_locked_connection,
            ingestion._run_full_rebuild_on_locked_connection,
        ):
            result = await runner(
                locked_connection,
                configured_source=configured_source,
            )
            assert result.status == "failed"
            assert result.affected_count == 0


class TestLockedSyncSurfacesTheFullReharvestSignalAsATypedOutcome:
    """Cover locked sync surfaces the full reharvest signal as atyped outcome."""

    async def test_full_reharvest_signal_becomes_a_typed_outcome_with_no_catalogue_mutation(
        self, monkeypatch
    ):
        """Check full reharvest signal becomes a typed outcome with no catalogue mutation."""
        cur = make_async_cursor()
        monkeypatch.setattr(
            ingestion,
            "get_db_cursor",
            create_autospec(ingestion.get_db_cursor, side_effect=lambda _pool: FakeCursorCtx(cur)),
        )
        monkeypatch.setattr(
            ingestion,
            "_sync_source",
            create_autospec(
                ingestion._sync_source,
                side_effect=ingestion._FullReharvestRequired("committed fingerprint mismatch"),
            ),
        )

        outcome = await ingestion._run_sync_on_locked_connection(
            object(),
            configured_source=legacy_source(),
        )

        assert outcome == ingestion.SyncOutcome(
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
        """Check an ordinary successful sync passes through unmodified."""
        success = ingestion.SyncOutcome("success", affected_count=3)
        monkeypatch.setattr(
            ingestion, "_sync_source", create_autospec(ingestion._sync_source, return_value=success)
        )

        outcome = await ingestion._run_sync_on_locked_connection(
            object(),
            configured_source=legacy_source(),
        )

        assert outcome == success
        assert outcome.requires_full_rebuild is False
