"""Incremental synchronisation orchestration for app.services.ingestion (unit tier)."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import call, create_autospec, patch

import pytest

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.services.ingestion_audit import DatasetWriteState
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import add_dataset_returning
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
    add_dataset_returning(cur)
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


def _sync_error_writes(cur):
    """All executes that touch last_sync_error (_record_sync_error and
    _clear_sync_error both match; tests disambiguate via params)."""
    return [c for c in cur.execute.await_args_list if "last_sync_error" in str(c.args[0])]


class TestWatermarkCapture:
    """The durable watermark is captured before the fetch and in true UTC."""

    async def test_watermark_is_harvest_start_not_post_processing_time(self):
        """The last_harvest_date written is the harvest START, not the moment processing finishes."""
        cur = _make_shared_cursor()
        fetch_instants = []

        def _record_fetch_instant(*_args, **_kwargs):
            """Record the actual fetch instant and return the scripted harvest."""
            fetch_instants.append(datetime.now(UTC))
            return _harvest()

        t0 = datetime.now(UTC)
        with (
            _patch_db(cur),
            patch(
                "app.services.ingestion.run_source_fetch",
                new=_threadpool_double(side_effect=_record_fetch_instant),
            ),
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        writes = _watermark_writes(cur)
        assert len(writes) == 1, "expected exactly one watermark UPDATE"
        written_ts = writes[0].args[1][0]
        assert len(fetch_instants) == 1
        assert t0 <= written_ts <= fetch_instants[0], (
            "watermark must be captured before the fetch, not post-processing"
        )

    async def test_since_param_converts_watermark_to_true_utc_instant(self):
        """Normalize the stored cursor to UTC before subtracting the overlap."""
        cur = _make_shared_cursor(watermark=NON_UTC_WATERMARK)
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        threadpool.assert_awaited_once()
        passed_since = threadpool.call_args.kwargs["since"]
        assert passed_since == datetime(2026, 2, 27, 13, tzinfo=UTC)
        assert passed_since.tzinfo is UTC

    async def test_naive_stored_cursor_fails_before_fetching(self):
        """Check naive stored cursor fails before fetching."""
        cur = _make_shared_cursor(watermark=NON_UTC_WATERMARK.replace(tzinfo=None))
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            outcome = await ingestion._sync_source(
                make_mock_pool(), configured_source=legacy_source()
            )

        assert outcome.status == "failed"
        threadpool.assert_not_awaited()
        assert not _watermark_writes(cur)
        assert _sync_error_writes(cur)


class TestHarvestResultWatermarkGuard:
    """Cover harvest result watermark guard."""

    def test_naive_source_cursor_is_rejected(self):
        """Check naive source cursor is rejected (ValueError)."""
        with pytest.raises(ValueError, match="timezone-aware"):
            HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=None)).validate()  # noqa: DTZ001 - rejection case

    def test_aware_source_cursor_is_accepted(self):
        """Check aware source cursor is accepted."""
        HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=UTC)).validate()


class TestIncrementalHarvestApplication:
    """`_apply_incremental_harvest` processes whatever a poll returns."""

    async def test_incremental_deletes_tombstones_and_quarantines_filter_exclusions(self):
        """Only upstream tombstones delete; local exclusions retain a withheld copy."""
        cur = make_async_cursor(
            fetchone={
                "source_cursor": NON_UTC_WATERMARK,
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
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
                "app.services.ingestion.run_source_fetch",
                new=_threadpool_double(return_value=harvest),
            ),
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        delete_calls = [
            call
            for call in cur.execute.await_args_list
            if "DELETE FROM oral_history_datasets" in str(call.args[0])
        ]
        assert len(delete_calls) == 1
        assert [call.args[1] for call in delete_calls] == [
            (legacy_source().policy.name, ["oai:x:deleted"]),
        ]

        quarantine = [
            call.args[1]
            for call in cur.execute.await_args_list
            if "INSERT INTO ingestion_quarantine" in str(call.args[0])
        ]
        assert quarantine[-1][0] == "filter_mismatch"
        assert quarantine[-1][-1] == ["oai:x:nonmatching"]
        failure_resolutions = [
            execute_call.args[1]
            for execute_call in cur.execute.await_args_list
            if "DELETE FROM ingestion_failures" in str(execute_call.args[0])
        ]
        assert failure_resolutions == [
            (
                legacy_source().policy.name,
                ["oai:x:deleted"],
            )
        ]
        assert len(_watermark_writes(cur)) == 1

    async def test_sync_survives_no_uuid_record_with_none_title(self):
        """A matching record with no uuid and no title is skipped and recorded, and never crashes the
        whole incremental run.
        """
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(return_value=_harvest({"uuid": None, "title": None}))
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        error_writes = _sync_error_writes(cur)
        assert len(error_writes) == 1, "expected exactly one last_sync_error UPDATE"
        message = error_writes[0].args[1][0]
        assert "fetch" in message and "identities" in message
        # The unresolved record pins the cursor until replay or a clean rebuild.
        assert _watermark_writes(cur) == []


class TestFetchFailureHandling:
    """A failed harvest fetch must not corrupt or advance sync state."""

    async def test_fetch_failure_records_error_and_does_not_advance_watermark(self):
        """A fetch exception is swallowed, recorded, and must not advance the watermark."""
        cur = _make_shared_cursor()
        threadpool = _threadpool_double(side_effect=Exception("boom"))
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        error_writes = _sync_error_writes(cur)
        assert len(error_writes) == 1, "expected exactly one last_sync_error UPDATE"
        # _record_sync_error params: (message, error_timestamp, source)
        message = error_writes[0].args[1][0]
        assert message == "Incremental sync (fetch): Exception: boom"
        assert _watermark_writes(cur) == []

    async def test_empty_sync_status_raises_runtime_error(self):
        """Raise a clear RuntimeError for the selected source's missing sync-status row before
        fetching.
        """
        cur = _make_shared_cursor(watermark=None)
        threadpool = _threadpool_double(return_value=_harvest())
        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(RuntimeError, match="sync_status row is missing for source"),
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        threadpool.assert_not_awaited()
        assert _watermark_writes(cur) == []


class TestRecoveryAfterInterruptedRun:
    """A poll that follows an earlier, unresolved poll leaves or resolves
    exactly the identity that earlier poll left behind."""

    async def test_empty_poll_preserves_unresolved_identity_and_never_writes_watermark(self):
        """An empty poll leaves a prior poll's unresolved identity alone and writes neither the
        watermark nor the incremental error channel.
        """
        cur = make_async_cursor(
            fetchone={
                "source_cursor": datetime(2026, 1, 1, tzinfo=UTC),
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
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
                ingestion,
                "get_db_cursor",
                autospec=True,
                side_effect=lambda _pool: FakeCursorCtx(cur),
            ),
            patch.object(
                ingestion,
                "run_source_fetch",
                new=_threadpool_double(
                    return_value=HarvestResult(
                        source_cursor=SOURCE_CURSOR,
                    )
                ),
            ),
            patch.object(ingestion, "_update_sync_timestamp", autospec=True) as timestamp,
            patch.object(ingestion, "_clear_sync_error", autospec=True) as clear,
            patch.object(ingestion, "_record_record_errors", autospec=True) as record,
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())
        timestamp.assert_not_awaited()
        clear.assert_not_awaited()
        assert record.await_args.args[1] == [("failed-id", "bad record")]

    async def test_replayed_success_resolves_identity_and_advances_watermark(self):
        """A poll that observes the withdrawal of a previously-failed identity resolves that failure
        and advances the watermark.
        """
        cur = make_async_cursor(
            fetchone={
                "source_cursor": datetime(2026, 1, 1, tzinfo=UTC),
                "source_fingerprint": legacy_source().adapter.config_fingerprint(),
                "incremental_harvest": None,
                "incremental_started_at": None,
                "incremental_position": 0,
                "incremental_affected": 0,
            },
        )
        with (
            patch.object(
                ingestion,
                "get_db_cursor",
                autospec=True,
                side_effect=lambda _pool: FakeCursorCtx(cur),
            ),
            patch.object(
                ingestion,
                "run_source_fetch",
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
            patch.object(ingestion, "_update_sync_timestamp", autospec=True) as timestamp,
            patch.object(ingestion, "_clear_sync_error", autospec=True) as clear,
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())
        timestamp.assert_awaited_once()
        clear.assert_awaited_once_with(
            cur,
            source=legacy_source().policy.name,
            channel="incremental",
        )
        deletes = [
            call
            for call in cur.execute.await_args_list
            if "DELETE FROM ingestion_failures" in str(call.args[0])
        ]
        assert deletes[0].args[1] == ("swissubase", ["failed-id"])


class TestRebuildAbortedException:
    """`_RebuildAborted` itself, with no DB involved."""

    def test_rebuild_aborted_carries_counts_and_message(self):
        """Check rebuild aborted carries counts and message."""
        e = ingestion._RebuildAborted(3, 10)

        assert e.success_count == 3
        assert e.offered == 10
        assert "3/10" in str(e)
        assert "stale-delete rolled back" in str(e)
        assert str(e) == (
            "Full rebuild aborted — only 3/10 records inserted (below threshold); "
            "stale-delete rolled back, other existing data kept. "
            "Committed authoritative withdrawals remain applied."
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
        """Exercise the real orchestrator with explicit policy outcomes."""
        records = [parsed_record(f"good-{i}") for i in range(successful)]
        records.extend(parsed_record(f"bad-{i}") for i in range(offered - successful))

        cur = _make_shared_cursor()
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        transaction_aborts = []

        @asynccontextmanager
        async def tracked_cursor(_pool):
            """Yield the rebuild cursor, retaining and propagating rebuild-abort exceptions."""
            try:
                yield cur
            except ingestion._RebuildAborted as exc:
                # The error must leave the rebuild context before the handler records it.
                transaction_aborts.append(exc)
                raise

        outcomes: list[DatasetWriteState | ValueError] = [
            DatasetWriteState(
                index + 1,
                legacy_source().name,
                records[index]["uuid"],
                "vetted",
            )
            for index in range(successful)
        ]
        outcomes.extend(ValueError("malformed record") for _ in range(offered - successful))

        with (
            patch("app.services.ingestion.get_db_cursor", new=tracked_cursor),
            patch(
                "app.services.ingestion.run_source_fetch",
                new=_threadpool_double(return_value=_harvest(*records)),
            ),
            patch("app.services.ingestion._delete_stale_source_records", autospec=True) as delete,
            patch(
                "app.services.ingestion._upsert_public_catalogue_record",
                autospec=True,
                side_effect=outcomes,
            ) as upsert,
            patch(
                "app.services.ingestion._update_full_rebuild_timestamp", autospec=True
            ) as timestamp,
            patch("app.services.ingestion._record_record_errors", autospec=True) as errors,
            patch("app.services.ingestion._clear_sync_error", autospec=True) as clear,
        ):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        delete.assert_awaited_once_with(
            cur,
            legacy_source().policy.name,
            sorted(r["uuid"] for r in records if r["uuid"]),
            max_inferred_delete_count=100,
            max_inferred_delete_ratio_percent=25,
            quarantined_uuids=[],
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
                call(cur, source=legacy_source().policy.name, channel="rebuild"),
                call(cur, source=legacy_source().policy.name, channel="incremental"),
            ]
        else:
            clear.assert_not_awaited()
            errors.assert_awaited_once()
            assert errors.await_args.kwargs == {
                "source": legacy_source().policy.name,
                "channel": "rebuild",
            }
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
                "app.services.ingestion.run_source_fetch",
                new=_threadpool_double(return_value=harvest),
            ),
            patch("app.services.ingestion._delete_stale_source_records", autospec=True) as delete,
            patch(
                "app.services.ingestion._upsert_public_catalogue_record",
                autospec=True,
                return_value=DatasetWriteState(
                    1,
                    legacy_source().name,
                    "live",
                    "vetted",
                ),
            ) as upsert,
            patch(
                "app.services.ingestion._update_full_rebuild_timestamp", autospec=True
            ) as timestamp,
            patch("app.services.ingestion._record_record_errors", autospec=True) as errors,
            patch("app.services.ingestion._clear_sync_error", autospec=True) as clear,
        ):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        delete.assert_awaited_once_with(
            cur,
            legacy_source().policy.name,
            ["live"],
            max_inferred_delete_count=100,
            max_inferred_delete_ratio_percent=25,
            quarantined_uuids=[],
        )
        upsert.assert_awaited_once_with(cur, live_record, legacy_source().policy)
        timestamp.assert_awaited_once()
        errors.assert_not_awaited()
        # A clean rebuild clears both diagnostic channels: its own, and the
        # incremental channel a prior failed poll may have left set.
        assert clear.await_args_list == [
            call(cur, source=legacy_source().policy.name, channel="rebuild"),
            call(cur, source=legacy_source().policy.name, channel="incremental"),
        ]


class _ReleaseTrackingStoredHarvestParts:
    """Wrap a real `StoredHarvestParts` and report exactly when it is freed."""

    def __init__(self, real, on_release):
        """Wrap encoded harvest parts and retain a destruction callback."""
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_on_release", on_release)

    def __getattr__(self, name):
        """Delegate unknown attributes to the wrapped harvest parts."""
        return getattr(object.__getattribute__(self, "_real"), name)

    def __del__(self):
        """Invoke the observation callback when the wrapper is destroyed."""
        object.__getattribute__(self, "_on_release")()


class TestIncrementalStagingEnvelope:
    """`_sync_source` stages a fresh harvest as three bounded bytea
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
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        staging_calls = [c for c in cur.execute.await_args_list if "%s::bytea" in str(c.args[0])]
        assert len(staging_calls) == 1, "expected exactly one staging UPDATE"
        sql_text, params = staging_calls[0].args
        assert str(sql_text).count("%s") == len(params), (
            "every bound placeholder must have exactly one parameter"
        )
        assert len(params) == 5

        prefix, harvest_bytes, suffix, _started_at, source = params
        assert source == legacy_source().policy.name

        decoded = ingestion.decode_stored_harvest(
            prefix + harvest_bytes + suffix,
            expected_source_fingerprint=legacy_source().adapter.config_fingerprint(),
        )
        assert decoded == harvest

    async def test_staged_parts_are_released_before_the_record_write_phase_begins(self):
        """Check staged parts are released before the record write phase begins."""
        cur = _make_shared_cursor()
        harvest = _harvest(parsed_record("staged-1"))
        threadpool = _threadpool_double(return_value=harvest)
        order = []

        real_encode = ingestion.encode_stored_harvest_parts

        def _tracked_encode(*args, **kwargs):
            """Wrap real encoded parts so their release is recorded in the execution order."""
            real_parts = real_encode(*args, **kwargs)
            return _ReleaseTrackingStoredHarvestParts(
                real_parts, on_release=lambda: order.append("released")
            )

        real_apply = ingestion._apply_incremental_harvest

        async def _tracked_apply(*args, **kwargs):
            """Record the write-phase start before delegating to the real apply function."""
            order.append("apply_start")
            return await real_apply(*args, **kwargs)

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion, "encode_stored_harvest_parts", autospec=True, side_effect=_tracked_encode
            ),
            patch.object(
                ingestion, "_apply_incremental_harvest", autospec=True, side_effect=_tracked_apply
            ),
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=legacy_source())

        assert order == ["released", "apply_start"], (
            "the staged parts must be freed before the record-write phase starts"
        )
