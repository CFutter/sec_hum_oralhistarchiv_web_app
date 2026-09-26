"""Source-configuration binding and progress recovery for app.services.sync
(unit tier).

Covers the cursor-fencing check in `_sync_source_a` (the committed
`sync_status.source_fingerprint` must match the currently configured
endpoint/institution filter before any incremental request or staged replay
is trusted), `_validated_incremental_progress` (the pure guard that a staged
harvest's durable position/affected counters still belong to the staged work
list), and the write-phase's distinction between the typed recovery signal
(never reported as an infrastructure failure) and a genuine write exception
(always reported).

No DB, no network, no threads: `app.services.sync.get_db_cursor` is patched
with a factory producing FakeCursorCtx objects around ONE shared mock cursor,
and `app.services.sync.run_in_threadpool` is autospecced against the real
starlette.concurrency.run_in_threadpool.

Incremental record processing, the staging envelope, and the full-rebuild
orchestrator are covered separately in `test_sync_incremental.py` and
`test_sync_rebuild.py`.
"""

from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import pytest

from app.services import sync
from app.services.oai_client import HarvestResult
from app.services.stored_harvest import encode_stored_harvest
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record


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


def _patch_db(cur):
    """Patch the sync module's get_db_cursor with a FakeCursorCtx factory."""
    return patch(
        "app.services.sync.get_db_cursor",
        autospec=True,
        side_effect=lambda _pool: FakeCursorCtx(cur),
    )


def _threadpool_double(**kwargs):
    """An autospecced stand-in for app.services.sync.run_in_threadpool."""
    return create_autospec(sync.run_in_threadpool, **kwargs)


def _status_row(**overrides):
    row = {
        "source_cursor": SOURCE_CURSOR,
        "source_fingerprint": sync._source_a_fingerprint(),
        "incremental_harvest": None,
        "incremental_started_at": None,
        "incremental_position": 0,
        "incremental_affected": 0,
    }
    row.update(overrides)
    return row


class TestCursorFencingOnCommittedSourceConfiguration:
    """`_sync_source_a` refuses to trust a stored cursor or staged harvest
    unless the committed `source_fingerprint` matches the source currently
    configured — an unbound, mismatched, or malformed commitment always
    forces a full rebuild before any incremental network request."""

    async def test_unbound_fingerprint_with_no_staged_payload_requires_a_full_reharvest(self):
        """`source_fingerprint IS NULL` (never bound) with nothing staged:
        the fetch must never happen."""
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=None))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(sync._FullReharvestRequired, match="no source configuration binding"),
        ):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()

    async def test_mismatched_fingerprint_forbids_the_incremental_request(self):
        """A fingerprint bound to a different endpoint/institution filter:
        no incremental request, no catalogue write."""
        other_fingerprint = sync.build_source_fingerprint(
            source="swissubase",
            oai_url="https://other-endpoint.example/oai",
            institution_filter="Some Other University",
        )
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=other_fingerprint))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(
                sync._FullReharvestRequired, match="differs from the committed catalogue"
            ),
        ):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()
        assert not any(
            "oral_history_datasets" in str(c.args[0]) for c in cur.execute.await_args_list
        )

    async def test_matching_fingerprint_converts_the_cursor_and_stages_the_same_fingerprint(self):
        """Positive control: a committed fingerprint matching the current
        configuration converts the stored watermark to a UTC `since=` date
        and stages a harvest carrying that same fingerprint."""
        cur = make_async_cursor(fetchone=_status_row())
        harvest = _harvest(parsed_record("live-1"))
        threadpool = _threadpool_double(return_value=harvest)

        with _patch_db(cur), patch("app.services.sync.run_in_threadpool", new=threadpool):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] == "2026-09-08"

        staging_calls = [c for c in cur.execute.await_args_list if "%s::bytea" in str(c.args[0])]
        assert len(staging_calls) == 1
        prefix, harvest_bytes, suffix, _started_at = staging_calls[0].args[1]
        decoded_envelope = sync.decode_stored_harvest(
            prefix + harvest_bytes + suffix,
            expected_source_fingerprint=sync._source_a_fingerprint(),
        )
        assert decoded_envelope == harvest

    async def test_committed_binding_to_another_configuration_forces_a_rebuild_even_with_a_matching_staged_payload(
        self,
    ):
        """The fingerprint check runs before the staged payload is even
        inspected: a staged payload that matches CURRENT settings is
        irrelevant once the row's own committed fingerprint does not."""
        current_fingerprint = sync._source_a_fingerprint()
        staged_matching_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=current_fingerprint
        )
        other_fingerprint = sync.build_source_fingerprint(
            source="swissubase",
            oai_url="https://other-endpoint.example/oai",
            institution_filter="Some Other University",
        )
        cur = make_async_cursor(
            fetchone=_status_row(
                source_fingerprint=other_fingerprint,
                incremental_harvest=staged_matching_payload,
                incremental_started_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(sync._FullReharvestRequired),
        ):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()

    async def test_matching_binding_replays_a_valid_staged_payload(self):
        """Positive control: once the committed fingerprint matches, a
        decodable staged payload with a real `incremental_started_at` is
        replayed instead of triggering a fresh fetch."""
        current_fingerprint = sync._source_a_fingerprint()
        harvest = _harvest(parsed_record("staged-1"))
        staged_payload = encode_stored_harvest(harvest, source_fingerprint=current_fingerprint)
        started_at = datetime(2026, 1, 1, tzinfo=UTC)
        cur = make_async_cursor(
            fetchone=_status_row(
                incremental_harvest=staged_payload,
                incremental_started_at=started_at,
            )
        )
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_write_incremental",
                autospec=True,
                return_value=sync.SyncOutcome("success", affected_count=1),
            ) as write_incremental,
        ):
            outcome = await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()
        write_incremental.assert_awaited_once()
        _replayed_pool, replayed_harvest, replayed_started_at = write_incremental.await_args.args
        assert replayed_harvest == harvest
        assert replayed_started_at == started_at
        assert outcome.status == "success"

    @pytest.mark.parametrize(
        "malformed_fingerprint",
        [None, "", "not-a-sha256-digest"],
        ids=["none", "empty_string", "not_a_sha256_digest"],
    )
    async def test_none_empty_and_non_sha256_committed_fingerprints_all_fail_closed(
        self, malformed_fingerprint
    ):
        """A committed fingerprint that is absent, empty, or simply not a
        SHA-256 digest is never treated as accidentally matching — every
        shape forces a full rebuild instead of an incremental request."""
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=malformed_fingerprint))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(sync._FullReharvestRequired),
        ):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()


class TestValidatedIncrementalProgress:
    """`_validated_incremental_progress` — the pure guard between a staged
    harvest's durable position/affected counters and the work list they must
    still belong to."""

    def test_position_past_the_work_list_raises_the_full_reharvest_signal(self):
        with pytest.raises(sync._FullReharvestRequired) as exc_info:
            sync._validated_incremental_progress(
                {"incremental_position": 5, "incremental_affected": 0}, work_items=3
            )
        assert type(exc_info.value) is sync._FullReharvestRequired

    @pytest.mark.parametrize(
        ("progress", "work_items"),
        [
            pytest.param(
                {"incremental_position": -1, "incremental_affected": 0}, 5, id="negative_position"
            ),
            pytest.param(
                {"incremental_position": 0, "incremental_affected": -1}, 5, id="negative_affected"
            ),
            pytest.param(
                {"incremental_position": True, "incremental_affected": 0},
                5,
                id="position_is_bool_true",
            ),
            pytest.param(
                {"incremental_position": False, "incremental_affected": 0},
                5,
                id="position_is_bool_false",
            ),
            pytest.param(
                {"incremental_position": None, "incremental_affected": 0}, 5, id="position_is_none"
            ),
            pytest.param({"incremental_affected": 0}, 5, id="position_key_missing"),
            pytest.param({"incremental_position": 0}, 5, id="affected_key_missing"),
            pytest.param(
                {"incremental_position": 2, "incremental_affected": 5},
                3,
                id="affected_over_work_items",
            ),
        ],
    )
    def test_invalid_progress_values_all_raise_the_full_reharvest_signal(
        self, progress, work_items
    ):
        with pytest.raises(sync._FullReharvestRequired):
            sync._validated_incremental_progress(progress, work_items=work_items)

    def test_position_and_affected_at_valid_boundaries_do_not_raise(self):
        """Positive control: an empty staged work list at (0, 0), and a
        fully completed one at (n, n), both validate cleanly."""
        assert sync._validated_incremental_progress(
            {"incremental_position": 0, "incremental_affected": 0}, work_items=0
        ) == (0, 0)
        assert sync._validated_incremental_progress(
            {"incremental_position": 4, "incremental_affected": 4}, work_items=4
        ) == (4, 4)


class TestProgressRecoveryDuringApplication:
    """The staged replay path (`_sync_source_a` / `_apply_incremental_harvest`)
    diagnoses a corrupt durable state before doing anything else with it."""

    async def test_missing_started_at_with_a_decodable_staged_harvest_requires_a_full_reharvest(
        self,
    ):
        fingerprint = sync._source_a_fingerprint()
        payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=_status_row(incremental_harvest=payload, incremental_started_at=None)
        )
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            pytest.raises(sync._FullReharvestRequired, match="incremental_started_at"),
        ):
            await sync._sync_source_a(make_mock_pool())

        threadpool.assert_not_awaited()

    async def test_corrupt_progress_is_diagnosed_before_the_failure_upsert_runs(self):
        """A position beyond the staged work list is caught before
        `_upsert_ingestion_failures_cur` ever runs — corruption is diagnosed
        first, so no uncertain-record failure is recorded against a cursor
        state about to be discarded for a full reharvest."""
        cur = make_async_cursor(fetchone={"incremental_position": 99, "incremental_affected": 0})
        harvest = _harvest(parsed_record("live-1"), uncertain={"bad-1": "unusable metadata"})

        with (
            _patch_db(cur),
            patch.object(sync, "_upsert_ingestion_failures_cur", autospec=True) as upsert_failures,
            pytest.raises(sync._FullReharvestRequired),
        ):
            await sync._apply_incremental_harvest(make_mock_pool(), harvest, SOURCE_CURSOR)

        upsert_failures.assert_not_awaited()

    async def test_valid_progress_still_replays_incrementally(self):
        """Positive control: valid staged progress reaches the record-write
        phase and completes normally."""
        cur = make_async_cursor(fetchone={"incremental_position": 0, "incremental_affected": 0})
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        harvest = _harvest(parsed_record("live-1"))

        with _patch_db(cur):
            outcome = await sync._apply_incremental_harvest(
                make_mock_pool(), harvest, SOURCE_CURSOR
            )

        assert outcome.status == "success"
        assert outcome.affected_count == 1


class TestWritePhaseFailureReporting:
    """`_write_incremental` reports a genuine write exception through the
    still-owned ingestion connection, but never reports the typed
    full-reharvest signal as an infrastructure failure."""

    async def test_the_full_reharvest_signal_propagates_without_a_write_failure_report(self):
        with (
            patch.object(
                sync,
                "_apply_incremental_harvest",
                autospec=True,
                side_effect=sync._FullReharvestRequired("corrupt staged progress"),
            ),
            patch.object(sync, "_report_write_failure", autospec=True) as report,
            pytest.raises(sync._FullReharvestRequired),
        ):
            await sync._write_incremental(make_mock_pool(), _harvest(), SOURCE_CURSOR)

        report.assert_not_awaited()

    async def test_a_genuine_write_exception_still_reports_a_write_failure(self):
        """Positive control: an ordinary exception during the write phase is
        still reported through `_report_write_failure` exactly once, and
        still propagates."""
        with (
            patch.object(
                sync,
                "_apply_incremental_harvest",
                autospec=True,
                side_effect=ValueError("disk full"),
            ),
            patch.object(sync, "_report_write_failure", autospec=True) as report,
            pytest.raises(ValueError, match="disk full"),
        ):
            await sync._write_incremental(make_mock_pool(), _harvest(), SOURCE_CURSOR)

        report.assert_awaited_once()
