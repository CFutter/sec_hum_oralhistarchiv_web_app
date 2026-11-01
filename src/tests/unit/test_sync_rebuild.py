"""Full-rebuild orchestration for app.services.ingestion (unit tier)."""

import logging
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import pytest
from psycopg import OperationalError

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.services.stored_harvest import encode_stored_harvest
from app.sources import oai_client
from app.sources.oai_pmh_cmdi import OaiPmhCmdiAdapter
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import add_dataset_returning
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import legacy_source


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
    add_dataset_returning(cur)
    return patch(
        "app.services.ingestion.get_db_cursor",
        autospec=True,
        side_effect=lambda _pool: FakeCursorCtx(cur),
    )


def _threadpool_double(**kwargs):
    """An autospecced stand-in for app.services.ingestion.run_source_fetch."""
    return create_autospec(ingestion.run_source_fetch, **kwargs)


def _execute_texts(cur):
    """Return SQL text from each awaited cursor execute call."""
    return [str(c.args[0]) for c in cur.execute.await_args_list]


def _publish_calls(cur):
    """Every executed statement that would publish the rebuild's cursor and
    source fingerprint together."""
    return [c for c in cur.execute.await_args_list if "source_fingerprint = %s" in str(c.args[0])]


def _status_row(**overrides):
    """A `sync_status` row shaped for `_sync_source`'s cursor-fencing SELECT."""
    row = {
        "source_cursor": SOURCE_CURSOR,
        "source_fingerprint": legacy_source().adapter.config_fingerprint(),
        "incremental_harvest": None,
        "incremental_started_at": None,
    }
    row.update(overrides)
    return row


def _recovery_log_records(caplog):
    """Select full-recovery audit records by their structured event type."""
    return [
        record
        for record in caplog.records
        if getattr(record, "event_type", None) == "stored_harvest_full_recovery"
    ]


class TestFullRebuildUsesCurrentHarvestState:
    """Rebuild reconciliation receives the validated current harvest state."""

    async def test_worker_decoded_harvest_mutation_reaches_reconciliation(self):
        """Changes after worker decoding reach the full rebuild without stale data."""
        cur = make_async_cursor(fetchone={"incremental_harvest": None})
        harvest = _harvest(parsed_record("live-1"))
        harvest = oai_client._decode_worker_harvest_result(
            oai_client.encode_harvest_result(harvest)
        )
        harvest.matching_records[0]["title"] = "Corrected before rebuild"
        threadpool = _threadpool_double(return_value=harvest)
        captured = {}

        async def _spy_apply_full_harvest(_pool, harvest_arg, *_args, **_kwargs):
            """Capture and validate the applied harvest before returning a successful sync outcome."""
            captured["harvest"] = harvest_arg
            captured["cursor"] = harvest_arg.validate()
            return ingestion.SyncOutcome("success")

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion, "_apply_full_harvest", autospec=True, side_effect=_spy_apply_full_harvest
            ),
        ):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        assert captured["harvest"] is harvest
        assert captured["cursor"] == harvest.source_cursor
        assert harvest.matching_records[0]["title"] == "Corrected before rebuild"

    async def test_directly_constructed_harvest_reconciles_normally(self):
        """Direct adapter results follow the same validation and reconciliation path."""
        cur = make_async_cursor(fetchone={"incremental_harvest": None})
        harvest = _harvest(parsed_record("live-1"))
        threadpool = _threadpool_double(return_value=harvest)

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        apply_full_harvest.assert_awaited_once()
        assert outcome.status == "success"


class TestContractionGuardBoundaries:
    """Cover contraction guard boundaries."""

    @pytest.mark.parametrize(
        "existing,deleted,count_limit,ratio_limit,allowed",
        [
            (3, 1, 1, 34, True),
            (3, 1, 1, 33, False),
            (10, 1, 0, 100, False),
            (10, 1, 1, 0, False),
            (10, 0, 0, 0, True),
            (1000, 101, 101, 11, True),
        ],
    )
    async def test_selected_limits_control_each_boundary_and_appear_in_errors(
        self, existing, deleted, count_limit, ratio_limit, allowed
    ):
        """Check selected limits control each boundary and appear in errors."""
        cur = make_async_cursor(
            fetchone={"existing_count": existing, "inferred_delete_count": deleted}
        )
        if allowed:
            await ingestion._delete_stale_source_records(
                cur,
                "swissubase",
                ["offered"],
                max_inferred_delete_count=count_limit,
                max_inferred_delete_ratio_percent=ratio_limit,
            )
            assert any(text.strip().startswith("DELETE") for text in _execute_texts(cur))
        else:
            with pytest.raises(ingestion._RebuildContractionAborted) as caught:
                await ingestion._delete_stale_source_records(
                    cur,
                    "swissubase",
                    ["offered"],
                    max_inferred_delete_count=count_limit,
                    max_inferred_delete_ratio_percent=ratio_limit,
                )
            assert f"{count_limit} records and {ratio_limit}%" in str(caught.value)
            assert not any(text.strip().startswith("DELETE") for text in _execute_texts(cur))

    async def test_1000_existing_rows_with_1_offered_aborts_before_the_delete(self):
        """Check 1000 existing rows with 1 offered aborts before the delete."""
        cur = make_async_cursor(fetchone={"existing_count": 1000, "inferred_delete_count": 999})

        with pytest.raises(ingestion._RebuildContractionAborted) as exc_info:
            await ingestion._delete_stale_source_records(
                cur,
                "swissubase",
                ["only-offered"],
                max_inferred_delete_count=100,
                max_inferred_delete_ratio_percent=25,
            )

        assert exc_info.value.existing_count == 1000
        assert exc_info.value.inferred_delete_count == 999
        assert not any(text.strip().startswith("DELETE") for text in _execute_texts(cur))

    async def test_a_small_contraction_executes_exactly_one_stale_delete(self):
        """Check a small contraction executes exactly one stale delete."""
        cur = make_async_cursor(fetchone={"existing_count": 10, "inferred_delete_count": 1})

        await ingestion._delete_stale_source_records(
            cur,
            "swissubase",
            ["keep-1", "keep-2"],
            max_inferred_delete_count=100,
            max_inferred_delete_ratio_percent=25,
        )

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
        """Check contraction limits allow equality and abort one over."""
        cur = make_async_cursor(
            fetchone={
                "existing_count": existing_count,
                "inferred_delete_count": inferred_delete_count,
            }
        )

        if aborts:
            with pytest.raises(ingestion._RebuildContractionAborted):
                await ingestion._delete_stale_source_records(
                    cur,
                    "swissubase",
                    ["offered"],
                    max_inferred_delete_count=100,
                    max_inferred_delete_ratio_percent=25,
                )
            assert not any(text.strip().startswith("DELETE") for text in _execute_texts(cur))
        else:
            await ingestion._delete_stale_source_records(
                cur,
                "swissubase",
                ["offered"],
                max_inferred_delete_count=100,
                max_inferred_delete_ratio_percent=25,
            )
            delete_calls = [
                c
                for c in cur.execute.await_args_list
                if str(c.args[0]).strip().startswith("DELETE")
            ]
            assert len(delete_calls) == 1


class TestExplicitRemovalsPrecedeTheContractionGuard:
    """Cover explicit removals precede the contraction guard."""

    async def test_explicit_deletion_runs_before_the_stale_delete_call(self):
        """Check explicit deletion runs before the stale delete call."""
        cur = make_async_cursor()
        harvest = _harvest(
            parsed_record("live-1"),
            deleted={"tombstoned-1"},
            nonmatching={"nonmatching-1"},
        )
        order = []

        async def _track_explicit(_cur, _source, uuids, *, audit=None):
            """Require no audit helper, record explicit deletions, and return their count."""
            assert audit is None
            order.append(("explicit", tuple(uuids)))
            return len(uuids)

        async def _track_stale(
            _cur,
            _source,
            protected_uuids,
            *,
            max_inferred_delete_count,
            max_inferred_delete_ratio_percent,
            quarantined_uuids,
        ):
            """Check the deletion budgets and quarantine set before recording inferred deletion inputs."""
            assert (max_inferred_delete_count, max_inferred_delete_ratio_percent) == (100, 25)
            assert quarantined_uuids == ["nonmatching-1"]
            order.append(("stale", tuple(protected_uuids)))

        with (
            _patch_db(cur),
            patch.object(
                ingestion,
                "_delete_explicit_source_records",
                autospec=True,
                side_effect=_track_explicit,
            ),
            patch.object(
                ingestion, "_delete_stale_source_records", autospec=True, side_effect=_track_stale
            ),
            patch.object(
                ingestion, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])
            ),
            patch.object(ingestion, "_update_full_rebuild_timestamp", autospec=True),
            patch.object(ingestion, "_clear_sync_error", autospec=True),
        ):
            configured_source = legacy_source()
            await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=configured_source,
                source_fingerprint=configured_source.adapter.config_fingerprint(),
            )

        assert order == [
            ("explicit", ("tombstoned-1",)),
            ("stale", ("live-1", "nonmatching-1")),
        ]


class TestAtomicPublicationOfCursorAndFingerprint:
    """Cover atomic publication of cursor and fingerprint."""

    async def test_successful_rebuild_publishes_cursor_and_fingerprint_in_one_statement(self):
        """Check successful rebuild publishes cursor and fingerprint in one statement."""
        cur = make_async_cursor(fetchone=[{"had_failures": False}])
        harvest = _harvest(parsed_record("live-1"))

        with (
            _patch_db(cur),
            patch.object(ingestion, "_delete_stale_source_records", autospec=True),
            patch.object(
                ingestion, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])
            ),
        ):
            outcome = await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
                source_fingerprint=legacy_source().adapter.config_fingerprint(),
            )

        assert outcome.status == "success"
        publish_calls = _publish_calls(cur)
        assert len(publish_calls) == 1
        sql_text, params = publish_calls[0].args
        assert str(sql_text).count("%s") == len(params) == 5
        (
            harvest_started_at,
            full_rebuild_started_at,
            source_cursor,
            source_fingerprint,
            source,
        ) = params
        assert source == legacy_source().policy.name
        assert harvest_started_at == full_rebuild_started_at == SOURCE_CURSOR
        assert source_cursor == harvest.source_cursor
        assert source_fingerprint == legacy_source().adapter.config_fingerprint()

    async def test_a_partial_rebuild_with_uncertain_records_leaves_the_prior_binding(self):
        """Check a partial rebuild with uncertain records leaves the prior binding."""
        cur = make_async_cursor()
        harvest = _harvest(parsed_record("live-1"), uncertain={"uncertain-1": "bad metadata"})

        with (
            _patch_db(cur),
            patch.object(ingestion, "_delete_stale_source_records", autospec=True),
            patch.object(
                ingestion, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])
            ),
        ):
            outcome = await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
                source_fingerprint=legacy_source().adapter.config_fingerprint(),
            )

        assert outcome.status == "partial"
        assert _publish_calls(cur) == []

    async def test_an_empty_rebuild_leaves_the_prior_binding(self):
        """No matching records at all: only explicit removals apply, and the
        cursor/fingerprint UPDATE is never reached."""
        cur = make_async_cursor(fetchone={"failed_count": 0})
        harvest = _harvest()

        with _patch_db(cur):
            outcome = await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
                source_fingerprint=legacy_source().adapter.config_fingerprint(),
            )

        assert outcome.status == "failed"
        assert _publish_calls(cur) == []

    async def test_a_contraction_aborted_rebuild_leaves_the_prior_binding(self):
        """Check a contraction aborted rebuild leaves the prior binding."""
        cur = make_async_cursor(
            fetchone={"existing_count": 1000, "inferred_delete_count": 999},
        )
        harvest = _harvest(parsed_record("live-1"))

        with _patch_db(cur):
            outcome = await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
                source_fingerprint=legacy_source().adapter.config_fingerprint(),
            )

        assert outcome.status == "failed"
        assert _publish_calls(cur) == []

    @pytest.mark.parametrize(
        "staged",
        [False, True],
        ids=["non_staged_recovery_path", "staged_recovery_path"],
    )
    async def test_a_successful_rebuild_clears_a_stale_incremental_error(self, staged):
        """Check a successful rebuild clears a stale incremental error."""
        fetchone_sequence = []
        if staged:
            fetchone_sequence.append({"source": "swissubase"})
        fetchone_sequence.append({"had_failures": False})
        cur = make_async_cursor(fetchone=fetchone_sequence)
        harvest = _harvest(parsed_record("live-1"))

        with (
            _patch_db(cur),
            patch.object(ingestion, "_delete_stale_source_records", autospec=True),
            patch.object(
                ingestion, "_reconcile_rebuild_records", autospec=True, return_value=(1, [])
            ),
        ):
            outcome = await ingestion._apply_full_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
                staged_payload_to_clear=b"staged-bytes" if staged else None,
                source_fingerprint=legacy_source().adapter.config_fingerprint(),
            )

        assert outcome.status == "success"
        incremental_clears = [
            text for text in _execute_texts(cur) if "last_sync_error" in text and "NULL" in text
        ]
        assert incremental_clears, "the incremental error channel must be cleared"


class TestFullRebuildRecoversFromAnUnreplayableStagedPayload:
    """`_full_rebuild_source` opportunistically replays a pending staged harvest before its own
    authoritative fetch.
    """

    def _pending_and_status_rows(self, pending_payload, **status_overrides):
        """Build pending-payload and status rows for staged-harvest recovery."""
        return [
            {"incremental_harvest": pending_payload},
            _status_row(incremental_harvest=pending_payload, **status_overrides),
        ]

    async def test_corrupt_staged_progress_forces_the_epoch_fetch_and_guards_the_pending_payload_for_clearing(
        self,
    ):
        """Check corrupt staged progress forces the epoch fetch and guards the pending payload for
        clearing.
        """
        configured_source = legacy_source()
        fingerprint = configured_source.adapter.config_fingerprint()
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
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_awaited_once()
        fetch = threadpool.call_args.args[0]
        assert fetch.__func__ is OaiPmhCmdiAdapter.fetch
        assert isinstance(fetch.__self__, OaiPmhCmdiAdapter)
        assert fetch.__self__ is configured_source.adapter
        assert fetch.__self__.max_pages == configured_source.config.model_dump()["max_pages"]
        assert threadpool.call_args.kwargs["since"] is None
        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["configured_source"] is configured_source
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] == pending_payload
        assert outcome.status == "success"

    async def test_missing_incremental_started_at_forces_the_epoch_fetch_and_guards_the_pending_payload_for_clearing(
        self,
    ):
        """Check missing incremental started at forces the epoch fetch and guards the pending payload
        for clearing.
        """
        fingerprint = legacy_source().adapter.config_fingerprint()
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
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ) as apply_full_harvest,
        ):
            outcome = await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] is None
        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] == pending_payload
        assert outcome.status == "success"

    async def test_recovery_log_record_carries_the_event_type_action_and_diagnosed_reason(
        self, caplog
    ):
        """Check recovery log record carries the event type action and diagnosed reason."""
        fingerprint = legacy_source().adapter.config_fingerprint()
        pending_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=self._pending_and_status_rows(pending_payload, incremental_started_at=None)
        )
        threadpool = _threadpool_double(return_value=_harvest(parsed_record("fresh-1")))

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ),
            caplog.at_level(logging.WARNING, logger="app.services.ingestion"),
        ):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        records = _recovery_log_records(caplog)
        assert len(records) == 1
        record = records[0]
        assert record.recovery_action == "full_reharvest"
        assert record.reason == "staged harvest exists without incremental_started_at"

    async def test_a_database_exception_during_the_replay_is_not_treated_as_recovery(self):
        """Check a database exception during the replay is not treated as recovery (OperationalError)."""
        pending_payload = b"opaque-pending-bytes"
        cur = make_async_cursor(fetchone={"incremental_harvest": pending_payload})
        db_error = OperationalError("connection reset by peer")
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(ingestion, "_sync_source", autospec=True, side_effect=db_error),
            patch.object(ingestion, "_apply_full_harvest", autospec=True) as apply_full_harvest,
            patch.object(ingestion, "_report_write_failure", autospec=True) as report_write_failure,
            pytest.raises(OperationalError, match="connection reset by peer"),
        ):
            await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()
        apply_full_harvest.assert_not_awaited()
        report_write_failure.assert_awaited_once()
        assert report_write_failure.await_args.args[1] == "rebuild"
        assert report_write_failure.await_args.args[2] is db_error

    async def test_a_valid_staged_replay_passes_no_guarded_payload_and_logs_no_recovery(
        self, caplog
    ):
        """Check a valid staged replay passes no guarded payload and logs no recovery."""
        fingerprint = legacy_source().adapter.config_fingerprint()
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
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ) as apply_full_harvest,
            caplog.at_level(logging.WARNING, logger="app.services.ingestion"),
        ):
            outcome = await ingestion._full_rebuild_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        apply_full_harvest.assert_awaited_once()
        assert apply_full_harvest.await_args.kwargs["staged_payload_to_clear"] is None
        assert _recovery_log_records(caplog) == []
        assert outcome.status == "success"
