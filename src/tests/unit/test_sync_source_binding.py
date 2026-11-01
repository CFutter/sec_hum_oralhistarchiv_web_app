"""Source-configuration binding and progress recovery for app.services.ingestion (unit tier)."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest
from psycopg import OperationalError

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.services.stored_harvest import encode_stored_harvest
from app.sources import AccessTier
from app.sources.oai_pmh_cmdi import OAI_ACCESS_LABELS, OAI_UNKNOWN_ACCESS_LEVEL
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import add_dataset_returning
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import fixture_source, legacy_source


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


def _status_row(**overrides):
    """Build source-binding status with the current legacy fingerprint and caller overrides."""
    row = {
        "source_cursor": SOURCE_CURSOR,
        "source_fingerprint": legacy_source().adapter.config_fingerprint(),
        "incremental_harvest": None,
        "incremental_started_at": None,
        "incremental_position": 0,
        "incremental_affected": 0,
    }
    row.update(overrides)
    return row


def _pre_title_fix_fingerprint(configured_source):
    """Reproduce the original seven-field binding without a CMDI parser version."""
    config = configured_source.config.model_dump()
    document = {
        "source": configured_source.name,
        "oai_url": config["endpoint"],
        "institution_filter": config["institution_filter"],
        "max_visibility": config["max_visibility"],
        "requires_record_tier": config["requires_record_tier"],
        "access_labels": dict(OAI_ACCESS_LABELS),
        "unknown_access_level": OAI_UNKNOWN_ACCESS_LEVEL,
    }
    return hashlib.sha256(
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


class TestCmdiTitleParserBinding:
    """Cover CMDI title parser binding."""

    @pytest.mark.parametrize("with_staged", [False, True], ids=["cursor-only", "staged-title"])
    async def test_old_parser_binding_blocks_incremental_fetch_and_replay(self, with_staged):
        """Check old parser binding blocks incremental fetch and replay."""
        configured_source = legacy_source()
        old_fingerprint = _pre_title_fix_fingerprint(configured_source)
        assert old_fingerprint != configured_source.adapter.config_fingerprint()
        row = _status_row(source_fingerprint=old_fingerprint)
        if with_staged:
            row.update(
                incremental_harvest=encode_stored_harvest(
                    _harvest(parsed_record("existing-record", title="WRONG PROJECT LABEL")),
                    source_fingerprint=old_fingerprint,
                ),
                incremental_started_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        cur = make_async_cursor(fetchone=row)
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(ingestion, "_write_incremental", autospec=True) as replay,
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._sync_source(make_mock_pool(), configured_source=configured_source)

        threadpool.assert_not_awaited()
        replay.assert_not_awaited()

    async def test_rebuild_refetches_and_guards_clearing_of_old_staged_titles(self):
        """Check rebuild refetches and guards clearing of old staged titles."""
        configured_source = legacy_source()
        old_fingerprint = _pre_title_fix_fingerprint(configured_source)
        pending = encode_stored_harvest(
            _harvest(parsed_record("existing-record", title="WRONG PROJECT LABEL")),
            source_fingerprint=old_fingerprint,
        )
        cur = make_async_cursor(
            fetchone=[
                {"incremental_harvest": pending, "source_fingerprint": old_fingerprint},
                {"acknowledged": 1},
                _status_row(
                    source_fingerprint=old_fingerprint,
                    incremental_harvest=pending,
                    incremental_started_at=datetime(2026, 1, 1, tzinfo=UTC),
                ),
                {"acknowledged": 1},
            ]
        )
        fresh = _harvest(parsed_record("existing-record", title="Correct dataset title"))
        threadpool = _threadpool_double(return_value=fresh)

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_apply_full_harvest",
                autospec=True,
                return_value=ingestion.SyncOutcome("success"),
            ) as apply_full,
            patch.object(ingestion, "_write_incremental", autospec=True) as replay,
        ):
            outcome = await ingestion._full_rebuild_source(
                make_mock_pool(), configured_source=configured_source
            )

        replay.assert_not_awaited()
        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] is None
        apply_full.assert_awaited_once()
        assert apply_full.await_args.args[1] is fresh
        assert apply_full.await_args.kwargs["staged_payload_to_clear"] == pending
        assert apply_full.await_args.kwargs["source_fingerprint"] == (
            configured_source.adapter.config_fingerprint()
        )
        assert outcome.status == "success"


class TestCursorFencingOnCommittedSourceConfiguration:
    """Cover cursor fencing on committed source configuration."""

    async def test_unbound_fingerprint_with_no_staged_payload_requires_a_full_reharvest(self):
        """`source_fingerprint IS NULL` (never bound) with nothing staged:
        the fetch must never happen."""
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=None))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(
                ingestion._FullReharvestRequired, match="no source configuration binding"
            ),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()

    async def test_mismatched_fingerprint_forbids_the_incremental_request(self):
        """A fingerprint bound to a different endpoint/institution filter:
        no incremental request, no catalogue write."""
        other_fingerprint = legacy_source(
            endpoint="https://other-endpoint.example/oai",
            institution_filter="Some Other University",
        ).adapter.config_fingerprint()
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=other_fingerprint))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(
                ingestion._FullReharvestRequired, match="operator acknowledgement required"
            ),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()
        assert not any(
            "oral_history_datasets" in str(c.args[0]) for c in cur.execute.await_args_list
        )

    async def test_matching_fingerprint_converts_the_cursor_and_stages_the_same_fingerprint(self):
        """Check matching fingerprint converts the cursor and stages the same fingerprint."""
        configured_source = legacy_source()
        cur = make_async_cursor(
            fetchone=_status_row(source_fingerprint=configured_source.adapter.config_fingerprint())
        )
        harvest = _harvest(parsed_record("live-1"))
        threadpool = _threadpool_double(return_value=harvest)

        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_awaited_once()
        assert threadpool.call_args.args[0].__self__ is configured_source.adapter
        assert threadpool.call_args.kwargs["since"] == SOURCE_CURSOR - timedelta(days=2)

        staging_calls = [c for c in cur.execute.await_args_list if "%s::bytea" in str(c.args[0])]
        assert len(staging_calls) == 1
        prefix, harvest_bytes, suffix, _started_at, source = staging_calls[0].args[1]
        assert source == configured_source.name
        decoded_envelope = ingestion.decode_stored_harvest(
            prefix + harvest_bytes + suffix,
            expected_source_fingerprint=configured_source.adapter.config_fingerprint(),
        )
        assert decoded_envelope == harvest

    async def test_committed_binding_to_another_configuration_forces_a_rebuild_even_with_a_matching_staged_payload(
        self,
    ):
        """Check committed binding to another configuration forces a rebuild even with a matching
        staged payload.
        """
        current_fingerprint = legacy_source().adapter.config_fingerprint()
        staged_matching_payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=current_fingerprint
        )
        other_fingerprint = legacy_source(
            endpoint="https://other-endpoint.example/oai",
            institution_filter="Some Other University",
        ).adapter.config_fingerprint()
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
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()

    async def test_matching_binding_without_cursor_requests_full_input(self):
        """Check matching binding without cursor requests full input."""
        cur = make_async_cursor(fetchone=_status_row(source_cursor=None))
        threadpool = _threadpool_double(return_value=_harvest())
        with _patch_db(cur), patch("app.services.ingestion.run_source_fetch", new=threadpool):
            outcome = await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_awaited_once()
        assert threadpool.call_args.kwargs["since"] is None
        assert outcome.status == "success"

    async def test_matching_binding_replays_a_valid_staged_payload(self):
        """Check matching binding replays a valid staged payload."""
        configured_source = legacy_source()
        current_fingerprint = configured_source.adapter.config_fingerprint()
        harvest = _harvest(parsed_record("staged-1"))
        staged_payload = encode_stored_harvest(harvest, source_fingerprint=current_fingerprint)
        started_at = datetime(2026, 1, 1, tzinfo=UTC)
        cur = make_async_cursor(
            fetchone=_status_row(
                source_fingerprint=current_fingerprint,
                incremental_harvest=staged_payload,
                incremental_started_at=started_at,
            )
        )
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(
                ingestion,
                "_write_incremental",
                autospec=True,
                return_value=ingestion.SyncOutcome("success", affected_count=1),
            ) as write_incremental,
        ):
            outcome = await ingestion._sync_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_not_awaited()
        write_incremental.assert_awaited_once()
        _replayed_pool, replayed_harvest, replayed_started_at = write_incremental.await_args.args
        assert replayed_harvest == harvest
        assert replayed_started_at == started_at
        assert write_incremental.await_args.kwargs["configured_source"] is configured_source
        assert outcome.status == "success"

    @pytest.mark.parametrize(
        "malformed_fingerprint",
        [None, "", "not-a-sha256-digest"],
        ids=["none", "empty_string", "not_a_sha256_digest"],
    )
    async def test_none_empty_and_non_sha256_committed_fingerprints_all_fail_closed(
        self, malformed_fingerprint
    ):
        """Check none empty and non sha256 committed fingerprints all fail closed."""
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=malformed_fingerprint))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()


class TestValidatedIncrementalProgress:
    """`_validated_incremental_progress` — the pure guard between a staged
    harvest's durable position/affected counters and the work list they must
    still belong to."""

    def test_position_past_the_work_list_raises_the_full_reharvest_signal(self):
        """Check position past the work list raises the full reharvest signal."""
        with pytest.raises(ingestion._FullReharvestRequired) as exc_info:
            ingestion._validated_incremental_progress(
                {"incremental_position": 5, "incremental_affected": 0}, work_items=3
            )
        assert type(exc_info.value) is ingestion._FullReharvestRequired

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
        """Check invalid progress values all raise the full reharvest signal."""
        with pytest.raises(ingestion._FullReharvestRequired):
            ingestion._validated_incremental_progress(progress, work_items=work_items)

    def test_position_and_affected_at_valid_boundaries_do_not_raise(self):
        """Check position and affected at valid boundaries do not raise."""
        assert ingestion._validated_incremental_progress(
            {"incremental_position": 0, "incremental_affected": 0}, work_items=0
        ) == (0, 0)
        assert ingestion._validated_incremental_progress(
            {"incremental_position": 4, "incremental_affected": 4}, work_items=4
        ) == (4, 4)


class TestProgressRecoveryDuringApplication:
    """The staged replay path (`_sync_source` / `_apply_incremental_harvest`)
    diagnoses a corrupt durable state before doing anything else with it."""

    async def test_missing_started_at_with_a_decodable_staged_harvest_requires_a_full_reharvest(
        self,
    ):
        """Check missing started at with a decodable staged harvest requires a full reharvest."""
        fingerprint = legacy_source().adapter.config_fingerprint()
        payload = encode_stored_harvest(
            _harvest(parsed_record("staged-1")), source_fingerprint=fingerprint
        )
        cur = make_async_cursor(
            fetchone=_status_row(incremental_harvest=payload, incremental_started_at=None)
        )
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(ingestion._FullReharvestRequired, match="incremental_started_at"),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=legacy_source(),
            )

        threadpool.assert_not_awaited()

    async def test_corrupt_progress_is_diagnosed_before_the_failure_upsert_runs(self):
        """Check corrupt progress is diagnosed before the failure upsert runs."""
        cur = make_async_cursor(fetchone={"incremental_position": 99, "incremental_affected": 0})
        harvest = _harvest(parsed_record("live-1"), uncertain={"bad-1": "unusable metadata"})

        with (
            _patch_db(cur),
            patch.object(
                ingestion, "_upsert_ingestion_failures_cur", autospec=True
            ) as upsert_failures,
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._apply_incremental_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
            )

        upsert_failures.assert_not_awaited()

    async def test_valid_progress_still_replays_incrementally(self):
        """Check valid progress still replays incrementally."""
        cur = make_async_cursor(fetchone={"incremental_position": 0, "incremental_affected": 0})
        cur.connection.transaction.return_value = FakeCursorCtx(cur)
        harvest = _harvest(parsed_record("live-1"))

        with _patch_db(cur):
            outcome = await ingestion._apply_incremental_harvest(
                make_mock_pool(),
                harvest,
                SOURCE_CURSOR,
                configured_source=legacy_source(),
            )

        assert outcome.status == "success"
        assert outcome.affected_count == 1


class TestWritePhaseFailureReporting:
    """`_write_incremental` reports a genuine write exception through the
    still-owned ingestion connection, but never reports the typed
    full-reharvest signal as an infrastructure failure."""

    async def test_the_full_reharvest_signal_propagates_without_a_write_failure_report(self):
        """Check the full reharvest signal propagates without a write failure report."""
        with (
            patch.object(
                ingestion,
                "_apply_incremental_harvest",
                autospec=True,
                side_effect=ingestion._FullReharvestRequired("corrupt staged progress"),
            ),
            patch.object(ingestion, "_report_write_failure", autospec=True) as report,
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._write_incremental(
                make_mock_pool(),
                _harvest(),
                SOURCE_CURSOR,
                configured_source=legacy_source(),
            )

        report.assert_not_awaited()

    async def test_a_genuine_write_exception_still_reports_a_write_failure(self):
        """Check a genuine write exception still reports a write failure (OperationalError)."""
        with (
            patch.object(
                ingestion,
                "_apply_incremental_harvest",
                autospec=True,
                side_effect=OperationalError("disk full"),
            ),
            patch.object(ingestion, "_report_write_failure", autospec=True) as report,
            pytest.raises(OperationalError, match="disk full"),
        ):
            await ingestion._write_incremental(
                make_mock_pool(),
                _harvest(),
                SOURCE_CURSOR,
                configured_source=legacy_source(),
            )

        report.assert_awaited_once()


class TestVisibilityPolicySourceBinding:
    """Cover visibility policy source binding."""

    @pytest.mark.parametrize(
        ("max_visibility", "requires_record_tier"),
        [("vetted", False), ("public", True)],
        ids=["visibility-ceiling", "mandatory-record-tier"],
    )
    @pytest.mark.parametrize("with_staged", [False, True], ids=["cursor", "staged-harvest"])
    async def test_policy_change_refuses_fetch_and_staged_replay(
        self,
        max_visibility: AccessTier,
        requires_record_tier: bool,
        with_staged: bool,
    ) -> None:
        """Check policy change refuses fetch and staged replay."""
        build = fixture_source if requires_record_tier else legacy_source
        baseline = build(max_visibility="public", requires_record_tier=False)
        old_fingerprint = baseline.adapter.config_fingerprint()
        row = _status_row(source_fingerprint=old_fingerprint)
        if with_staged:
            row.update(
                incremental_harvest=encode_stored_harvest(
                    _harvest(parsed_record("staged-before-policy-change")),
                    source_fingerprint=old_fingerprint,
                ),
                incremental_started_at=datetime(2026, 1, 1, tzinfo=UTC),
            )

        configured_source = build(
            max_visibility=max_visibility,
            requires_record_tier=requires_record_tier,
        )
        assert configured_source.adapter.config_fingerprint() != old_fingerprint
        cur = make_async_cursor(fetchone=row)
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            patch.object(ingestion, "_write_incremental", autospec=True) as replay,
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_not_awaited()
        replay.assert_not_awaited()

    def test_operational_source_config_preserves_the_source_binding(self) -> None:
        """Check operational source config preserves the source binding."""
        baseline = legacy_source()
        fingerprint = baseline.adapter.config_fingerprint()

        for changes in (
            {"max_pages": 501},
            {"schedule": {"incremental_interval_seconds": 3601}},
            {"schedule": {"rebuild_interval_seconds": 86401}},
            {"schedule": {"write_timeout_seconds": 121}},
        ):
            changed = legacy_source(**changes)
            assert changed.config.model_dump() != baseline.config.model_dump()
            assert changed.adapter.config_fingerprint() == fingerprint

    async def test_old_three_field_binding_requires_an_authoritative_rebuild(self) -> None:
        """Check old three field binding requires an authoritative rebuild."""
        configured_source = legacy_source()
        source_config = configured_source.config.model_dump()
        legacy_document = {
            "source": configured_source.name,
            "oai_url": source_config["endpoint"],
            "institution_filter": source_config["institution_filter"],
        }
        legacy_fingerprint = hashlib.sha256(
            json.dumps(
                legacy_document,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert legacy_fingerprint != configured_source.adapter.config_fingerprint()
        cur = make_async_cursor(fetchone=_status_row(source_fingerprint=legacy_fingerprint))
        threadpool = _threadpool_double()

        with (
            _patch_db(cur),
            patch("app.services.ingestion.run_source_fetch", new=threadpool),
            pytest.raises(ingestion._FullReharvestRequired),
        ):
            await ingestion._sync_source(
                make_mock_pool(),
                configured_source=configured_source,
            )

        threadpool.assert_not_awaited()
