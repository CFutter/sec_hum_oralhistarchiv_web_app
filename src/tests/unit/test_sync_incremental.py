"""Incremental synchronisation orchestration for app.services.sync (unit tier).

Covers the harvest watermark (captured before the fetch, converted to a true
UTC instant for `since=`), the guard that rejects a naive source_cursor,
processing of a harvest's removals and malformed records, recovery after an
interrupted run, the full-rebuild abort exception, and the full-rebuild
acceptance threshold.

No DB, no network, no threads: `app.services.sync.get_db_cursor` is patched
with a factory producing FakeCursorCtx objects around ONE shared mock cursor
(so every SQL execute is captured in order), and
`app.services.sync.run_in_threadpool` is autospecced against the real
starlette.concurrency.run_in_threadpool, so fetch_updates_isolated never
actually runs.

The threadpool-offload seam, the locked-connection entry points, and error
message sanitisation are covered separately, in
`src/tests/unit/test_sync_lock_entry_points.py`.
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import call, create_autospec, patch

import pytest

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


def _sync_error_writes(cur):
    """All executes that touch last_sync_error (_record_sync_error and
    _clear_sync_error both match; tests disambiguate via params)."""
    return [c for c in cur.execute.await_args_list if "last_sync_error" in str(c.args[0])]


class TestWatermarkCapture:
    """The durable watermark is captured before the fetch and in true UTC."""

    async def test_watermark_is_harvest_start_not_post_processing_time(self):
        """The last_harvest_date written is the harvest START, not the moment
        processing finishes.

        Stamping now() after processing would let anything modified upstream
        between the server's response and end-of-run fall into a gap that is
        never re-fetched until a full rebuild. The written timestamp must
        therefore sit between the pre-call now() and the instant the fetch
        was invoked — never after processing.
        """
        cur = _make_shared_cursor()
        fetch_instants = []

        def _record_fetch_instant(*_args, **_kwargs):
            fetch_instants.append(datetime.now(UTC))
            return _harvest()

        t0 = datetime.now(UTC)
        with (
            _patch_db(cur),
            patch(
                "app.services.sync.run_in_threadpool",
                new=_threadpool_double(side_effect=_record_fetch_instant),
            ),
        ):
            await sync._sync_source_a(make_mock_pool())

        writes = _watermark_writes(cur)
        assert len(writes) == 1, "expected exactly one watermark UPDATE"
        written_ts = writes[0].args[1][0]
        assert len(fetch_instants) == 1
        assert t0 <= written_ts <= fetch_instants[0], (
            "watermark must be captured before the fetch, not post-processing"
        )

    async def test_since_param_converts_watermark_to_true_utc_instant(self):
        """A stored watermark of 14:00+01:00 must yield since=2026-02-27.

        Formatting the raw (still tz-aware) datetime and appending a literal
        "Z" would discard tzinfo and send an offset-wrong `since=` to the OAI
        endpoint under any non-UTC session timezone. The conversion must be
        `.astimezone(timezone.utc)` before formatting.
        """
        cur = _make_shared_cursor(watermark=NON_UTC_WATERMARK)
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] == "2026-02-27"


class TestHarvestResultWatermarkGuard:
    """`HarvestResult.validate()` — the guard the incremental sync's watermark
    write relies on — refuses to hand back a naive source_cursor, since a
    naive timestamp cannot be safely converted to the UTC instant `since=`
    needs on the next run."""

    def test_naive_source_cursor_is_rejected(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=None)).validate()  # noqa: DTZ001 - rejection case

    def test_aware_source_cursor_is_accepted(self):
        """Positive control: an aware source_cursor validates cleanly."""
        HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=UTC)).validate()


class TestIncrementalHarvestApplication:
    """`_apply_incremental_harvest` processes whatever a poll returns."""

    async def test_incremental_processes_only_removals_and_advances_watermark(self):
        """Removals are processed even when no record in the poll matched.

        Pins the HarvestResult integration seam: both authoritative removal
        categories (deleted and nonmatching uuids) are processed, their
        prior ingestion failures are resolved, and a clean removal-only
        harvest still advances the cursor.
        """
        cur = make_async_cursor(
            fetchone={
                "source_cursor": NON_UTC_WATERMARK,
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            },
        )
        harvest = _harvest(
            deleted={"oai:x:deleted"},
            nonmatching={"oai:x:nonmatching"},
        )

        with (
            _patch_db(cur),
            patch(
                "app.services.sync.run_in_threadpool",
                new=_threadpool_double(return_value=harvest),
            ),
        ):
            await sync._sync_source_a(make_mock_pool())

        delete_calls = [
            call
            for call in cur.execute.await_args_list
            if "DELETE FROM oral_history_datasets" in str(call.args[0])
        ]
        assert len(delete_calls) == 2
        assert [call.args[1] for call in delete_calls] == [
            (sync._SWISSUBASE_POLICY.name, ["oai:x:deleted"]),
            (sync._SWISSUBASE_POLICY.name, ["oai:x:nonmatching"]),
        ]

        # Both uuids' prior ingestion_failures rows are resolved (deleted) as
        # a side effect of successfully processing their removal.
        failure_resolutions = {
            execute_call.args[1]
            for execute_call in cur.execute.await_args_list
            if "DELETE FROM ingestion_failures" in str(execute_call.args[0])
        }
        assert failure_resolutions == {
            (sync._SWISSUBASE_POLICY.name, "oai:x:deleted"),
            (sync._SWISSUBASE_POLICY.name, "oai:x:nonmatching"),
        }
        assert len(_watermark_writes(cur)) == 1

    async def test_sync_survives_no_uuid_record_with_none_title(self):
        """A matching record with no uuid and no title is skipped and
        recorded, and never crashes the whole incremental run.

        The parser emits `"title": None` for a record with no title
        element, and `"uuid": None` for one with no identifier. Neither
        value may reach an unguarded `[:100]` slice or an unguarded dict
        subscript: a single malformed record must not abort the entire
        incremental sync (no failure recorded, no watermark advance, and the
        scheduler job dying on every subsequent run until upstream fixes the
        record would be the failure mode here).
        """
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(return_value=_harvest({"uuid": None, "title": None}))
        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            # Correct behaviour: skip-and-record, never raise.
            await sync._sync_source_a(make_mock_pool())

        # The failure is recorded in last_sync_error as a missing-UUID skip...
        error_writes = _sync_error_writes(cur)
        assert len(error_writes) == 1, "expected exactly one last_sync_error UPDATE"
        message = error_writes[0].args[1][0]
        assert "fetch" in message and "identities" in message
        # The unresolved record pins the cursor until replay or a clean rebuild.
        assert _watermark_writes(cur) == []


class TestFetchFailureHandling:
    """A failed harvest fetch must not corrupt or advance sync state."""

    async def test_fetch_failure_records_error_and_does_not_advance_watermark(self):
        """A fetch exception is swallowed, recorded, and must not advance
        the watermark.

        A fetch exception must not propagate out of `_sync_source_a` (the
        scheduler job would die); instead a sanitized message lands in
        `sync_status.last_sync_error`, and the `last_harvest_date` watermark
        is left untouched so the failed window is re-fetched next run —
        advancing it would silently skip the window forever.
        """
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(side_effect=Exception("boom"))
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

    async def test_empty_sync_status_raises_runtime_error(self):
        """A missing sync_status row raises a loud RuntimeError, not a
        NoneType crash.

        fetchone() returning None means migrations never seeded the
        singleton row; the sync must fail with the explicit operator-facing
        message instead of an AttributeError on row['last_harvest_date'].
        """
        cur = _make_shared_cursor(watermark=None)  # fetchone -> None
        threadpool = _threadpool_double(return_value=_harvest())
        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(RuntimeError, match="sync_status table is empty"),
        ):
            await sync._sync_source_a(make_mock_pool())

        # Failed before any fetch or write.
        threadpool.assert_not_awaited()
        assert _watermark_writes(cur) == []


class TestRecoveryAfterInterruptedRun:
    """A poll that follows an earlier, unresolved poll leaves or resolves
    exactly the identity that earlier poll left behind."""

    async def test_empty_poll_preserves_unresolved_identity_and_never_writes_watermark(self):
        """An empty poll leaves a prior poll's unresolved identity alone and
        writes neither the watermark nor the incremental error channel.

        The `ingestion_failures` row from the earlier, unresolved poll is
        still listed because this empty harvest never touches its uuid;
        recording it again, or clearing it, would misreport the record as
        newly resolved.
        """
        cur = make_async_cursor(
            fetchone={
                "source_cursor": datetime(2026, 1, 1, tzinfo=UTC),
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            },
            # A record left over from an earlier, unresolved poll: still
            # listed in the ingestion_failures table because this empty
            # harvest never touches its uuid.
            fetchall=[{"uuid": "failed-id", "message": "bad record"}],
        )
        with (
            patch.object(
                sync, "get_db_cursor", autospec=True, side_effect=lambda _pool: FakeCursorCtx(cur)
            ),
            patch.object(
                sync,
                "run_in_threadpool",
                new=_threadpool_double(
                    return_value=HarvestResult(
                        source_cursor=SOURCE_CURSOR,
                    )
                ),
            ),
            patch.object(sync, "_update_sync_timestamp", autospec=True) as timestamp,
            patch.object(sync, "_clear_sync_error", autospec=True) as clear,
            patch.object(sync, "_record_record_errors", autospec=True) as record,
        ):
            await sync._sync_source_a(make_mock_pool())
        timestamp.assert_not_awaited()
        clear.assert_not_awaited()
        assert record.await_args.args[1] == [("failed-id", "bad record")]

    async def test_replayed_success_resolves_identity_and_advances_watermark(self):
        """A poll that observes the withdrawal of a previously-failed
        identity resolves that failure and advances the watermark.

        The replayed withdrawal resolves the earlier failure by deleting its
        `ingestion_failures` row, which is why the outer poll can now
        succeed.
        """
        cur = make_async_cursor(
            fetchone={
                "source_cursor": datetime(2026, 1, 1, tzinfo=UTC),
                "source_fingerprint": sync._source_a_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            },
        )
        with (
            patch.object(
                sync, "get_db_cursor", autospec=True, side_effect=lambda _pool: FakeCursorCtx(cur)
            ),
            patch.object(
                sync,
                "run_in_threadpool",
                new=_threadpool_double(
                    return_value=HarvestResult(
                        source_cursor=SOURCE_CURSOR,
                        matching_records=[],
                        deleted_uuids={"failed-id"},
                        nonmatching_uuids=set(),
                        uncertain_records={},
                    )
                ),
            ),
            patch.object(sync, "_update_sync_timestamp", autospec=True) as timestamp,
            patch.object(sync, "_clear_sync_error", autospec=True) as clear,
        ):
            await sync._sync_source_a(make_mock_pool())
        timestamp.assert_awaited_once()
        clear.assert_awaited_once_with(cur, channel="incremental")
        deletes = [
            call
            for call in cur.execute.await_args_list
            if "DELETE FROM ingestion_failures" in str(call.args[0])
        ]
        assert deletes[0].args[1] == ("swissubase", "failed-id")


class TestRebuildAbortedException:
    """`_RebuildAborted` itself, with no DB involved."""

    def test_rebuild_aborted_carries_counts_and_message(self):
        """`_full_rebuild_source_a`'s except-block report reads
        `.success_count` / `.offered` off the caught instance directly, and
        both the log line and the sync_status error text are built from the
        exception's str(). A field rename or a reworded message would
        silently break that report without any test noticing, since nothing
        else exercises the class in isolation — this pins both the
        attributes and the exact wording ops sees.
        """
        e = sync._RebuildAborted(3, 10)

        assert e.success_count == 3
        assert e.offered == 10
        assert "3/10" in str(e)
        assert "stale-delete rolled back" in str(e)
        assert str(e) == (
            "Full rebuild aborted — only 3/10 records inserted (below threshold); "
            "stale-delete rolled back, existing data kept."
        )


class TestFullRebuildSuccessThreshold:
    """A full rebuild only commits when at least half of all live records
    that were offered were written successfully."""

    @pytest.mark.parametrize(
        ("offered", "successful", "should_commit"),
        [
            pytest.param(1, 0, False, id="zero_of_one_is_below_threshold"),
            pytest.param(1, 1, True, id="one_of_one_commits"),
            pytest.param(2, 1, True, id="one_of_two_meets_half"),
            pytest.param(3, 1, False, id="one_of_three_is_below_threshold"),
            pytest.param(3, 2, True, id="two_of_three_commits"),
            pytest.param(4, 1, False, id="one_of_four_is_below_threshold"),
            pytest.param(4, 2, True, id="two_of_four_meets_half"),
            pytest.param(5, 2, False, id="two_of_five_is_below_threshold"),
            pytest.param(5, 3, True, id="three_of_five_commits"),
        ],
    )
    async def test_full_rebuild_requires_at_least_half_of_all_live_records(
        self, offered, successful, should_commit, caplog
    ):
        """Exercise the real orchestrator with explicit policy outcomes.

        Missing UUIDs count as failures even though they are absent from the
        stale-delete keep-list. The expected outcomes are independent of the
        production formula. Database rollback itself is checked in
        test_sync_db.py.
        """
        records = [parsed_record(f"good-{i}") for i in range(successful)]
        records.extend(parsed_record(f"bad-{i}") for i in range(offered - successful))

        cur = _make_shared_cursor()
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        transaction_aborts = []

        @asynccontextmanager
        async def tracked_cursor(_pool):
            try:
                yield cur
            except sync._RebuildAborted as exc:
                # The error must leave the rebuild context before the handler records it.
                transaction_aborts.append(exc)
                raise

        outcomes = [None] * successful
        outcomes.extend(ValueError("malformed record") for _ in range(offered - successful))

        with (
            patch("app.services.sync.get_db_cursor", new=tracked_cursor),
            patch(
                "app.services.sync.run_in_threadpool",
                new=_threadpool_double(return_value=_harvest(*records)),
            ),
            patch("app.services.sync._delete_stale_source_records", autospec=True) as delete,
            patch(
                "app.services.sync._upsert_public_catalogue_record",
                autospec=True,
                side_effect=outcomes,
            ) as upsert,
            patch("app.services.sync._update_full_rebuild_timestamp", autospec=True) as timestamp,
            patch("app.services.sync._record_record_errors", autospec=True) as errors,
            patch("app.services.sync._clear_sync_error", autospec=True) as clear,
        ):
            await sync._full_rebuild_source_a(make_mock_pool())

        delete.assert_awaited_once_with(
            cur,
            sync._SWISSUBASE_POLICY.name,
            sorted(r["uuid"] for r in records if r["uuid"]),
        )
        assert upsert.await_count == offered
        abort_logs = [
            record
            for record in caplog.records
            if getattr(record, "event_type", None) == "sync_rebuild_aborted"
        ]
        if should_commit:
            timestamp.assert_awaited_once()
            assert timestamp.await_args.args[0] is cur
            assert transaction_aborts == []
            assert abort_logs == []
        else:
            timestamp.assert_not_awaited()
            assert len(transaction_aborts) == 1
            assert transaction_aborts[0].success_count == successful
            assert transaction_aborts[0].offered == offered
            assert len(abort_logs) == 1
            assert abort_logs[0].success_count == successful
            assert abort_logs[0].offered == offered

        if successful == offered:
            errors.assert_not_awaited()
            # A clean rebuild clears both diagnostic channels: its own, and
            # the incremental channel a prior failed poll may have left set.
            assert clear.await_args_list == [
                call(cur, channel="rebuild"),
                call(cur, channel="incremental"),
            ]
        else:
            clear.assert_not_awaited()
            errors.assert_awaited_once()
            assert errors.await_args.kwargs == {"channel": "rebuild"}
            assert len(errors.await_args.args[1]) == offered - successful
            context = errors.await_args.args[2]
            if should_commit:
                assert context == "Full rebuild"
            else:
                assert "ABORTED" in context
                assert f"{successful}/{offered}" in context

    async def test_full_rebuild_does_not_count_tombstones_as_live_failures(self):
        """One successful live record plus tombstones remains a complete
        live harvest, so the rebuild commits."""
        cur = _make_shared_cursor()
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        live_record = parsed_record("live")
        harvest = _harvest(
            live_record,
            deleted={"deleted-a", "deleted-b"},
        )
        with (
            _patch_db(cur),
            patch(
                "app.services.sync.run_in_threadpool", new=_threadpool_double(return_value=harvest)
            ),
            patch("app.services.sync._delete_stale_source_records", autospec=True) as delete,
            patch("app.services.sync._upsert_public_catalogue_record", autospec=True) as upsert,
            patch("app.services.sync._update_full_rebuild_timestamp", autospec=True) as timestamp,
            patch("app.services.sync._record_record_errors", autospec=True) as errors,
            patch("app.services.sync._clear_sync_error", autospec=True) as clear,
        ):
            await sync._full_rebuild_source_a(make_mock_pool())

        delete.assert_awaited_once_with(cur, sync._SWISSUBASE_POLICY.name, ["live"])
        upsert.assert_awaited_once_with(cur, live_record, sync._SWISSUBASE_POLICY)
        timestamp.assert_awaited_once()
        errors.assert_not_awaited()
        # A clean rebuild clears both diagnostic channels: its own, and the
        # incremental channel a prior failed poll may have left set.
        assert clear.await_args_list == [
            call(cur, channel="rebuild"),
            call(cur, channel="incremental"),
        ]


class _ReleaseTrackingStoredHarvestParts:
    """Wrap a real `StoredHarvestParts` and report exactly when it is freed.

    `StoredHarvestParts` is a frozen, slotted dataclass with no `__weakref__`
    slot, so a plain `weakref.ref` cannot observe it. This wrapper is a
    sentinel instead: it forwards attribute access to the real parts and
    calls back the instant CPython collects it (refcount reaches zero via
    `del`, not through a GC cycle).
    """

    def __init__(self, real, on_release):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_on_release", on_release)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real"), name)

    def __del__(self):
        object.__getattribute__(self, "_on_release")()


class TestIncrementalStagingEnvelope:
    """`_sync_source_a` stages a fresh harvest as three bounded bytea
    fragments concatenated by PostgreSQL, and releases them from memory
    before record writes begin."""

    async def test_staging_update_binds_one_parameter_per_placeholder_and_round_trips_the_harvest(
        self,
    ):
        """The staging UPDATE's placeholder count matches its parameter
        count exactly, and concatenating the three bound bytea fragments
        decodes back to the exact harvest that was fetched."""
        cur = _make_shared_cursor()
        harvest = _harvest(parsed_record("staged-1"), parsed_record("staged-2"))
        threadpool = _threadpool_double(return_value=harvest)
        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            await sync._sync_source_a(make_mock_pool())

        staging_calls = [c for c in cur.execute.await_args_list if "%s::bytea" in str(c.args[0])]
        assert len(staging_calls) == 1, "expected exactly one staging UPDATE"
        sql_text, params = staging_calls[0].args
        assert str(sql_text).count("%s") == len(params), (
            "every bound placeholder must have exactly one parameter"
        )
        assert len(params) == 4  # three bytea fragments + incremental_started_at

        prefix, harvest_bytes, suffix, _started_at = params
        assert isinstance(prefix, bytes)
        assert isinstance(harvest_bytes, bytes)
        assert isinstance(suffix, bytes)

        decoded = sync.decode_stored_harvest(
            prefix + harvest_bytes + suffix,
            expected_source_fingerprint=sync._source_a_fingerprint(),
        )
        assert decoded == harvest

    async def test_staged_parts_are_released_before_the_record_write_phase_begins(self):
        """The encoded `StoredHarvestParts` fragments are freed as soon as
        the staging UPDATE commits — strictly before `_apply_incremental_harvest`
        (the record-write phase) is entered — so a large harvest's serialized
        bytes are not held in memory for the whole write phase."""
        cur = _make_shared_cursor()
        harvest = _harvest(parsed_record("staged-1"))
        threadpool = _threadpool_double(return_value=harvest)
        order = []

        real_encode = sync.encode_stored_harvest_parts

        def _tracked_encode(*args, **kwargs):
            real_parts = real_encode(*args, **kwargs)
            return _ReleaseTrackingStoredHarvestParts(
                real_parts, on_release=lambda: order.append("released")
            )

        real_apply = sync._apply_incremental_harvest

        async def _tracked_apply(*args, **kwargs):
            order.append("apply_start")
            return await real_apply(*args, **kwargs)

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync, "encode_stored_harvest_parts", autospec=True, side_effect=_tracked_encode
            ),
            patch.object(
                sync, "_apply_incremental_harvest", autospec=True, side_effect=_tracked_apply
            ),
        ):
            await sync._sync_source_a(make_mock_pool())

        assert order == ["released", "apply_start"], (
            "the staged parts must be freed before the record-write phase starts"
        )
