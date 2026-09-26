"""Full-rebuild orchestration for app.services.sync (unit tier).

Covers the worker-payload discard before reconciliation, the absence-inferred
contraction guard (`_delete_stale_source_records`) both as a pure function
against a fake cursor and as a step ordered before/after its neighbours in
`_apply_full_harvest`, and the atomic publication of the rebuild's cursor and
source fingerprint — including every outcome that must leave the prior
binding untouched.

No DB, no network, no threads: `app.services.sync.get_db_cursor` is patched
with a factory producing FakeCursorCtx objects around ONE shared mock cursor,
and `app.services.sync.run_in_threadpool` is autospecced against the real
starlette.concurrency.run_in_threadpool.

Incremental staging, cursor fencing and progress recovery are covered
separately in `src/tests/unit/test_sync_incremental.py` and
`src/tests/unit/test_sync_source_binding.py`. The full-rebuild acceptance
threshold lives in
`test_sync_incremental.py::TestFullRebuildSuccessThreshold`.
"""

import logging
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import pytest
from psycopg import OperationalError

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


def _execute_texts(cur):
    return [str(c.args[0]) for c in cur.execute.await_args_list]


def _publish_calls(cur):
    """Every executed statement that would publish the rebuild's cursor and
    source fingerprint together."""
    return [c for c in cur.execute.await_args_list if "source_fingerprint = %s" in str(c.args[0])]


def _status_row(**overrides):
    """A `sync_status` row shaped for `_sync_source_a`'s cursor-fencing SELECT."""
    row = {
        "source_cursor": SOURCE_CURSOR,
        "source_fingerprint": sync._source_a_fingerprint(),
        "incremental_harvest": None,
        "incremental_started_at": None,
    }
    row.update(overrides)
    return row


def _recovery_log_records(caplog):
    return [
        record
        for record in caplog.records
        if getattr(record, "event_type", None) == "stored_harvest_full_recovery"
    ]


class TestFullRebuildDiscardsTheWorkerPayload:
    """`_full_rebuild_source_a` discards any attached worker payload before
    handing the harvest to reconciliation — the rebuild never restages worker
    bytes the way the incremental path does."""

    async def test_attached_worker_payload_is_gone_by_the_time_reconciliation_runs(self):
        """A worker payload attached to the fetched harvest is discarded
        before `_apply_full_harvest` (reconciliation) is even called."""
        cur = make_async_cursor(fetchone={"incremental_harvest": None})
        harvest = _harvest(parsed_record("live-1"))
        harvest._attach_serialized_worker_payload(b"worker-bytes")
        threadpool = _threadpool_double(return_value=harvest)
        captured = {}

        async def _spy_apply_full_harvest(_pool, harvest_arg, *_args, **_kwargs):
            captured["payload_at_reconciliation"] = harvest_arg.take_serialized_worker_payload()
            return sync.SyncOutcome("success")

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync, "_apply_full_harvest", autospec=True, side_effect=_spy_apply_full_harvest
            ),
        ):
            await sync._full_rebuild_source_a(make_mock_pool())

        assert captured["payload_at_reconciliation"] is None

    async def test_full_rebuild_without_an_attached_payload_reconciles_normally(self):
        """Positive control: a harvest with nothing attached (the ordinary
        case — full rebuilds fetch synchronously, not through the isolated
        worker) reconciles exactly the same way; the discard call does not
        require a payload to have been attached."""
        cur = make_async_cursor(fetchone={"incremental_harvest": None})
        harvest = _harvest(parsed_record("live-1"))
        threadpool = _threadpool_double(return_value=harvest)

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_apply_full_harvest",
                autospec=True,
                return_value=sync.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await sync._full_rebuild_source_a(make_mock_pool())

        apply_full_harvest.assert_awaited_once()
        assert outcome.status == "success"


class TestContractionGuardBoundaries:
    """`_delete_stale_source_records` against a fake cursor: it aborts before
    issuing the DELETE whenever the absence-inferred count crosses either
    limit, and executes exactly one DELETE otherwise."""

    async def test_1000_existing_rows_with_1_offered_aborts_before_the_delete(self):
        cur = make_async_cursor(fetchone={"existing_count": 1000, "inferred_delete_count": 999})

        with pytest.raises(sync._RebuildContractionAborted) as exc_info:
            await sync._delete_stale_source_records(cur, "swissubase", ["only-offered"])

        assert exc_info.value.existing_count == 1000
        assert exc_info.value.inferred_delete_count == 999
        assert not any(text.strip().startswith("DELETE") for text in _execute_texts(cur))

    async def test_a_small_contraction_executes_exactly_one_stale_delete(self):
        """Positive control for the abort above: a deletion count below both
        limits is not aborted and issues exactly one DELETE with the exact
        keep-list."""
        cur = make_async_cursor(fetchone={"existing_count": 10, "inferred_delete_count": 1})

        await sync._delete_stale_source_records(cur, "swissubase", ["keep-1", "keep-2"])

        delete_calls = [
            c for c in cur.execute.await_args_list if str(c.args[0]).strip().startswith("DELETE")
        ]
        assert len(delete_calls) == 1
        assert delete_calls[0].args[1] == ("swissubase", ["keep-1", "keep-2"])

    @pytest.mark.parametrize(
        ("existing_count", "inferred_delete_count", "aborts"),
        [
            pytest.param(1000, 100, False, id="count_at_the_100_row_limit_is_allowed"),
            pytest.param(1000, 101, True, id="one_row_over_the_100_row_limit_aborts"),
            pytest.param(400, 100, False, id="ratio_at_exactly_25_percent_is_allowed"),
            pytest.param(399, 100, True, id="one_delete_over_25_percent_aborts"),
        ],
    )
    async def test_contraction_limits_allow_equality_and_abort_one_over(
        self, existing_count, inferred_delete_count, aborts
    ):
        cur = make_async_cursor(
            fetchone={
                "existing_count": existing_count,
                "inferred_delete_count": inferred_delete_count,
            }
        )

        if aborts:
            with pytest.raises(sync._RebuildContractionAborted):
                await sync._delete_stale_source_records(cur, "swissubase", ["offered"])
            assert not any(text.strip().startswith("DELETE") for text in _execute_texts(cur))
        else:
            await sync._delete_stale_source_records(cur, "swissubase", ["offered"])
            delete_calls = [
                c
                for c in cur.execute.await_args_list
                if str(c.args[0]).strip().startswith("DELETE")
            ]
            assert len(delete_calls) == 1


class TestExplicitRemovalsPrecedeTheContractionGuard:
    """`_apply_full_harvest` deletes explicit upstream withdrawals before it
    ever asks `_delete_stale_source_records` to evaluate absence, so an
    explicit tombstone can never itself be miscounted as an inferred,
    absence-based deletion."""

    async def test_explicit_deletion_runs_before_the_stale_delete_call(self):
        cur = make_async_cursor()
        harvest = _harvest(
            parsed_record("live-1"),
            deleted={"tombstoned-1"},
            nonmatching={"nonmatching-1"},
        )
        order = []

        async def _track_explicit(_cur, _source, uuids):
            order.append(("explicit", tuple(uuids)))

        async def _track_stale(_cur, _source, protected_uuids):
            order.append(("stale", tuple(protected_uuids)))

        with (
            _patch_db(cur),
            patch.object(
                sync, "_delete_explicit_source_records", autospec=True, side_effect=_track_explicit
            ),
            patch.object(
                sync, "_delete_stale_source_records", autospec=True, side_effect=_track_stale
            ),
            patch.object(sync, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])),
            patch.object(sync, "_update_full_rebuild_timestamp", autospec=True),
            patch.object(sync, "_clear_sync_error", autospec=True),
        ):
            await sync._apply_full_harvest(make_mock_pool(), harvest, SOURCE_CURSOR)

        assert order == [
            ("explicit", ("nonmatching-1", "tombstoned-1")),
            ("stale", ("live-1",)),
        ]


class TestAtomicPublicationOfCursorAndFingerprint:
    """A successful full rebuild publishes its new cursor and source
    fingerprint together, in the same UPDATE as its authoritative success;
    every other outcome leaves the prior binding exactly as it was."""

    async def test_successful_rebuild_publishes_cursor_and_fingerprint_in_one_statement(self):
        cur = make_async_cursor(fetchone=[{"had_failures": False}])
        harvest = _harvest(parsed_record("live-1"))

        with (
            _patch_db(cur),
            patch.object(sync, "_delete_stale_source_records", autospec=True),
            patch.object(sync, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])),
        ):
            outcome = await sync._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                source_fingerprint=sync._source_a_fingerprint(),
            )

        assert outcome.status == "success"
        publish_calls = _publish_calls(cur)
        assert len(publish_calls) == 1
        sql_text, params = publish_calls[0].args
        assert str(sql_text).count("%s") == len(params) == 4
        harvest_started_at, full_rebuild_started_at, source_cursor, source_fingerprint = params
        assert harvest_started_at == full_rebuild_started_at == SOURCE_CURSOR
        assert source_cursor == harvest.source_cursor
        assert source_fingerprint == sync._source_a_fingerprint()

    async def test_a_partial_rebuild_with_uncertain_records_leaves_the_prior_binding(self):
        """A rebuild with unresolved records (uncertain metadata here; a
        per-record write failure takes the identical branch) never reaches
        the publish statement at all — `_update_full_rebuild_timestamp`
        returns after recording the failures."""
        cur = make_async_cursor()
        harvest = _harvest(parsed_record("live-1"), uncertain={"uncertain-1": "bad metadata"})

        with (
            _patch_db(cur),
            patch.object(sync, "_delete_stale_source_records", autospec=True),
            patch.object(sync, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])),
        ):
            outcome = await sync._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                source_fingerprint=sync._source_a_fingerprint(),
            )

        assert outcome.status == "partial"
        assert _publish_calls(cur) == []

    async def test_an_empty_rebuild_leaves_the_prior_binding(self):
        """No matching records at all: only explicit removals apply, and the
        cursor/fingerprint UPDATE is never reached."""
        cur = make_async_cursor()
        harvest = _harvest()  # no matching_records at all

        with _patch_db(cur):
            outcome = await sync._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                source_fingerprint=sync._source_a_fingerprint(),
            )

        assert outcome.status == "failed"
        assert _publish_calls(cur) == []

    async def test_a_contraction_aborted_rebuild_leaves_the_prior_binding(self):
        cur = make_async_cursor(
            fetchone={"existing_count": 1000, "inferred_delete_count": 999},
        )
        harvest = _harvest(parsed_record("live-1"))

        with _patch_db(cur):
            outcome = await sync._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                source_fingerprint=sync._source_a_fingerprint(),
            )

        assert outcome.status == "failed"
        assert _publish_calls(cur) == []

    @pytest.mark.parametrize(
        "staged",
        [False, True],
        ids=["non_staged_recovery_path", "staged_recovery_path"],
    )
    async def test_a_successful_rebuild_clears_a_stale_incremental_error(self, staged):
        """Whether or not this success came from clearing a staged payload
        that could not be replayed, a clean rebuild always clears the
        incremental error channel — not only its own rebuild channel."""
        fetchone_sequence = []
        if staged:
            fetchone_sequence.append({"id": 1})  # confirms the guarded staged clear
        fetchone_sequence.append({"had_failures": False})
        cur = make_async_cursor(fetchone=fetchone_sequence)
        harvest = _harvest(parsed_record("live-1"))

        with (
            _patch_db(cur),
            patch.object(sync, "_delete_stale_source_records", autospec=True),
            patch.object(sync, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])),
        ):
            outcome = await sync._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                staged_payload_to_clear=b"staged-bytes" if staged else None,
                source_fingerprint=sync._source_a_fingerprint(),
            )

        assert outcome.status == "success"
        incremental_clears = [
            text for text in _execute_texts(cur) if "last_sync_error" in text and "NULL" in text
        ]
        assert incremental_clears, "the incremental error channel must be cleared"


class TestFullRebuildRecoversFromAnUnreplayableStagedPayload:
    """`_full_rebuild_source_a` opportunistically replays a pending staged
    harvest before its own authoritative fetch. When that replay cannot be
    trusted (corrupt durable progress, or a staged row committed without a
    start time), the rebuild does not fail outright: it proceeds to its own
    epoch fetch and hands the exact pending bytes to `_apply_full_harvest` as
    the guarded-clear argument, so the stale staged row is only cleared if it
    is still exactly what was diagnosed as unreplayable. A genuine database
    exception while replaying is a different thing entirely — it is reported
    as an infrastructure failure and propagates, never treated as a recovery
    signal."""

    def _pending_and_status_rows(self, pending_payload, **status_overrides):
        return [
            {"incremental_harvest": pending_payload},
            _status_row(incremental_harvest=pending_payload, **status_overrides),
        ]

    async def test_corrupt_staged_progress_forces_the_epoch_fetch_and_guards_the_pending_payload_for_clearing(
        self,
    ):
        """A staged payload whose durable position no longer belongs to its
        own work list (position=99 against a 1-item list) makes the replay
        raise the full-reharvest signal from deep inside
        `_apply_incremental_harvest`; the rebuild still proceeds to fetch
        since the epoch and passes the pending bytes through for a guarded
        clear."""
        fingerprint = sync._source_a_fingerprint()
        started_at = datetime(2026, 1, 1, tzinfo=UTC)
        pending_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=[
                *self._pending_and_status_rows(pending_payload, incremental_started_at=started_at),
                {"incremental_position": 99, "incremental_affected": 0},
            ]
        )
        fresh_harvest = _harvest(parsed_record("fresh-1"))
        threadpool = _threadpool_double(return_value=fresh_harvest)

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_apply_full_harvest",
                autospec=True,
                return_value=sync.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await sync._full_rebuild_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.args[0] is sync.fetch_updates_isolated
        assert threadpool.call_args.kwargs["since"] == "1900-01-01"
        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] == pending_payload
        assert outcome.status == "success"

    async def test_missing_incremental_started_at_forces_the_epoch_fetch_and_guards_the_pending_payload_for_clearing(
        self,
    ):
        """The same orchestration as above, reached instead through a staged
        row committed without `incremental_started_at` — the signal fires
        immediately after decoding, before any work-list check runs."""
        fingerprint = sync._source_a_fingerprint()
        pending_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=self._pending_and_status_rows(pending_payload, incremental_started_at=None)
        )
        fresh_harvest = _harvest(parsed_record("fresh-1"))
        threadpool = _threadpool_double(return_value=fresh_harvest)

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_apply_full_harvest",
                autospec=True,
                return_value=sync.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await sync._full_rebuild_source_a(make_mock_pool())

        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] == "1900-01-01"
        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] == pending_payload
        assert outcome.status == "success"

    async def test_recovery_log_record_carries_the_event_type_action_and_diagnosed_reason(
        self, caplog
    ):
        """The warning logged when a pending replay is abandoned carries
        structured fields a reader can act on without parsing the message:
        the event type, the recovery action taken, and the exact diagnosed
        reason — here the missing `incremental_started_at`."""
        fingerprint = sync._source_a_fingerprint()
        pending_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=self._pending_and_status_rows(pending_payload, incremental_started_at=None)
        )
        threadpool = _threadpool_double(return_value=_harvest(parsed_record("fresh-1")))

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_apply_full_harvest",
                autospec=True,
                return_value=sync.SyncOutcome("success"),
            ),
            caplog.at_level(logging.WARNING, logger="app.services.sync"),
        ):
            await sync._full_rebuild_source_a(make_mock_pool())

        records = _recovery_log_records(caplog)
        assert len(records) == 1
        record = records[0]
        assert record.recovery_action == "full_reharvest"
        assert record.reason == "staged harvest exists without incremental_started_at"

    async def test_a_database_exception_during_the_replay_is_not_treated_as_recovery(self):
        """An exception that is not the typed full-reharvest signal (a real
        database failure here) never reaches the recovery branch: no epoch
        fetch runs, `_apply_full_harvest` is never called, the failure is
        reported through the still-owned rebuild error channel, and the
        exception still propagates to the caller."""
        pending_payload = b"opaque-pending-bytes"
        cur = make_async_cursor(fetchone={"incremental_harvest": pending_payload})
        db_error = OperationalError("connection reset by peer")
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(sync, "_sync_source_a", autospec=True, side_effect=db_error),
            patch.object(sync, "_apply_full_harvest", autospec=True) as apply_full_harvest,
            patch.object(sync, "_report_write_failure", autospec=True) as report_write_failure,
            pytest.raises(OperationalError, match="connection reset by peer"),
        ):
            await sync._full_rebuild_source_a(make_mock_pool())

        threadpool.assert_not_awaited()
        apply_full_harvest.assert_not_awaited()
        report_write_failure.assert_awaited_once()
        assert report_write_failure.await_args.args[1] == "rebuild"
        assert report_write_failure.await_args.args[2] is db_error

    async def test_a_valid_staged_replay_passes_no_guarded_payload_and_logs_no_recovery(
        self, caplog
    ):
        """Positive control: when the pending replay actually succeeds (valid
        fingerprint, start time and progress), nothing is diagnosed as
        unreplayable — `_apply_full_harvest` is told there is no staged
        payload to guard-clear, and no recovery warning is logged."""
        fingerprint = sync._source_a_fingerprint()
        started_at = datetime(2026, 1, 1, tzinfo=UTC)
        pending_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=[
                *self._pending_and_status_rows(pending_payload, incremental_started_at=started_at),
                {"incremental_position": 1, "incremental_affected": 1},
            ]
        )
        fresh_harvest = _harvest(parsed_record("fresh-1"))
        threadpool = _threadpool_double(return_value=fresh_harvest)

        with (
            _patch_db(cur),
            patch("app.services.sync.run_in_threadpool", new=threadpool),
            patch.object(
                sync,
                "_apply_full_harvest",
                autospec=True,
                return_value=sync.SyncOutcome("success"),
            ) as apply_full_harvest,
            caplog.at_level(logging.WARNING, logger="app.services.sync"),
        ):
            outcome = await sync._full_rebuild_source_a(make_mock_pool())

        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] is None
        assert _recovery_log_records(caplog) == []
        assert outcome.status == "success"
