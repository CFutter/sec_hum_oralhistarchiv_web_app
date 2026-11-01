"""Audit publication follows persisted changes and commit/savepoint boundaries."""

import asyncio
import base64
import hashlib
import logging
import re
import traceback
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import pytest
from psycopg import AsyncConnection, AsyncCursor, DataError, OperationalError

from app.services import ingestion
from app.services import ingestion_audit as audit
from app.services.harvest import HarvestResult
from app.sources import JsonFeedConfig, configure_sources, prepare_json_feed_startup
from tests.fixtures import FakeCursorCtx, make_mock_pool
from tests.oai_fixtures import parsed_record
from tests.source_fixtures import fixture_source, legacy_source

_SOURCE = "audit_archive"
_UUID = "11111111-1111-4111-8111-111111111111"
_OTHER_UUID = "22222222-2222-4222-8222-222222222222"
_CANARY = "private-metadata-and-database-error-canary"


def _cursor(*, row=None, rows=()):
    """Return a strict cursor with configured one-row and multirow read results."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchone.return_value = row
    cursor.fetchall.return_value = list(rows)
    return cursor


def _row(*, stored="public", floor=None, dataset_id=7):
    """Build a persisted dataset row with stored and administrator tiers."""
    return {
        "id": dataset_id,
        "source": _SOURCE,
        "uuid": _UUID,
        "visibility_tier": stored,
        "admin_tier": floor,
    }


def _state(*, stored="public", floor=None):
    """Build the audit before-state for the fixed source and dataset identity."""
    return audit.DatasetTierState(7, _SOURCE, _UUID, stored, floor)


def _written(
    *,
    stored="public",
    dataset_id=7,
    source=_SOURCE,
    uuid=_UUID,
):
    """Build the audit write-state using the supplied dataset identity and stored tier."""
    return audit.DatasetWriteState(
        dataset_id,
        source,
        uuid,
        stored,
    )


def _records(caplog):
    """Return captured records from the audit logger only."""
    return [record for record in caplog.records if record.name == "audit"]


def _extras(record):
    """Return nonstandard LogRecord attributes, excluding rendered message/time."""
    standard = logging.makeLogRecord({}).__dict__.keys() | {"message", "asctime"}
    return {key: value for key, value in record.__dict__.items() if key not in standard}


@pytest.mark.parametrize(
    "stored,floor,expected",
    [
        ("public", None, "public"),
        ("registered", None, "registered"),
        ("vetted", None, "vetted"),
        ("public", "registered", "registered"),
        ("public", "vetted", "vetted"),
        ("registered", "public", "registered"),
        ("registered", "vetted", "vetted"),
        ("vetted", "registered", "vetted"),
        ("vetted", "vetted", "vetted"),
    ],
)
def test_audit_uses_the_served_effective_tier(stored, floor, expected):
    """Audit uses the served effective tier."""
    assert _state(stored=stored, floor=floor).effective_tier == expected


def test_captured_identity_state_is_immutable():
    """Captured identity state is immutable."""
    state = _state()
    with pytest.raises(FrozenInstanceError):
        state.uuid = _OTHER_UUID


@pytest.mark.parametrize("present", [False, True])
async def test_tier_capture_reads_only_source_scoped_identity_and_restrictions(present):
    """Tier capture reads only source scoped identity and restrictions."""
    cursor = _cursor(row=_row(stored="registered", floor="vetted") if present else None)
    result = await audit.read_tier_state_cur(cursor, source=_SOURCE, uuid=_UUID)
    assert result == (_state(stored="registered", floor="vetted") if present else None)
    cursor.execute.assert_awaited_once()
    query, values = cursor.execute.await_args.args
    assert values == (_SOURCE, _UUID)
    text = " ".join(str(query).split())
    assert "WHERE dataset.source = %s AND dataset.uuid = %s" in text
    assert "admin.source = dataset.source AND admin.uuid = dataset.uuid" in text
    assert "FOR UPDATE OF dataset" in text
    projection = text.partition(" FROM ")[0]
    assert not re.search(r"\b(?:data|title|description|authors|keywords)\b|\*", projection)
    cursor.fetchall.assert_not_awaited()


def test_first_insert_does_not_trigger_a_transition_or_an_extra_read(caplog):
    """First insert does not trigger a transition or an extra read."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()
    buffer.record_tier_change(None, _written())
    buffer.emit()
    assert not _records(caplog)


async def test_buffer_persists_before_commit_without_emitting_or_duplicate_appends(caplog):
    """Buffer persists before commit without emitting or duplicate appends."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()
    buffer.record_tier_change(_state(), _written(stored="registered"))
    cursor = _cursor()
    await buffer.persist_cur(cursor)
    await buffer.persist_cur(cursor)
    cursor.execute.assert_awaited_once()
    query, values = cursor.execute.await_args.args
    assert "INSERT INTO public.security_audit_events" in query
    assert values[1] == "tier_changed"
    assert values[2].obj == {
        "dataset_id": 7,
        "source": _SOURCE,
        "uuid": _UUID,
        "old_tier": "public",
        "new_tier": "registered",
    }
    assert not _records(caplog)
    buffer.emit()
    assert len(_records(caplog)) == 1


@pytest.mark.parametrize(
    "before,after,expected",
    [
        (
            _state(),
            _written(stored="registered"),
            ("public", "registered"),
        ),
        (
            _state(stored="public", floor="registered"),
            _written(stored="vetted"),
            ("registered", "vetted"),
        ),
        (
            _state(stored="vetted"),
            _written(stored="vetted"),
            None,
        ),
        (
            _state(floor="vetted"),
            _written(stored="registered"),
            None,
        ),
    ],
    ids=[
        "raise",
        "raise_above_admin_floor",
        "unchanged_stored_tier",
        "unchanged_effective_tier",
    ],
)
def test_only_actual_effective_transitions_are_buffered(
    caplog,
    before,
    after,
    expected,
):
    """Only actual effective transitions are buffered."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()
    buffer.record_tier_change(before, after)

    assert not _records(caplog)
    buffer.emit()
    records = _records(caplog)

    if expected is None:
        assert not records
    else:
        assert len(records) == 1
        assert _extras(records[0]) == {
            "event_type": "tier_changed",
            "dataset_id": 7,
            "source": _SOURCE,
            "uuid": _UUID,
            "old_tier": expected[0],
            "new_tier": expected[1],
        }
        assert records[0].getMessage() == "tier_changed"
        assert records[0].exc_info is None

    buffer.emit()
    assert _records(caplog) == records


@pytest.mark.parametrize(
    "after",
    [
        replace(_written(), dataset_id=99),
        replace(_written(), source="other_archive"),
        replace(_written(), uuid=_OTHER_UUID),
    ],
    ids=["changed-id", "changed-source", "changed-uuid"],
)
def test_replaced_after_identity_fails_without_an_audit_claim(caplog, after):
    """Replaced after identity fails without an audit claim."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()

    with pytest.raises(
        RuntimeError,
        match=r"^Persisted ingestion audit state is unavailable$",
    ):
        buffer.record_tier_change(_state(), after)

    buffer.emit()
    assert not _records(caplog)


@pytest.mark.parametrize(
    "before",
    [None, _state()],
    ids=["insert", "update"],
)
@pytest.mark.parametrize("after", [None, object(), _row()])
def test_missing_or_untyped_returning_state_never_silently_disables_audit(
    caplog,
    before,
    after,
):
    """Missing or untyped returning state never silently disables audit."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()

    with pytest.raises(
        RuntimeError,
        match=r"^Catalogue upsert returned an invalid persisted state$",
    ):
        buffer.record_tier_change(before, after)

    buffer.emit()
    assert not _records(caplog)


def test_returned_write_state_is_immutable():
    """Returned write state is immutable."""
    state = _written()
    with pytest.raises(FrozenInstanceError):
        state.uuid = _OTHER_UUID


@pytest.mark.parametrize("reason", ["explicit", "inferred"])
def test_withdrawals_publish_only_returned_identities_and_fixed_reason(caplog, reason):
    """Withdrawals publish only returned identities and fixed reason."""
    caplog.set_level(logging.INFO, logger="audit")
    buffer = audit.IngestionAudit()
    returned_rows = [{"id": 8, "uuid": _OTHER_UUID, "title": _CANARY, "data": {"value": _CANARY}}]
    buffer.record_withdrawals(returned_rows, source=_SOURCE, reason=reason)
    buffer.record_withdrawals([], source=_SOURCE, reason=reason)
    assert not _records(caplog)
    buffer.emit()
    (record,) = _records(caplog)
    assert _extras(record) == {
        "event_type": "dataset_withdrawn",
        "dataset_id": 8,
        "source": _SOURCE,
        "uuid": _OTHER_UUID,
        "reason": reason,
    }
    assert record.getMessage() == "dataset_withdrawn" and record.exc_info is None
    assert _CANARY not in repr(record.__dict__)
    buffer.emit()
    assert len(_records(caplog)) == 1


def test_merging_a_successful_child_transfers_events_without_publishing(caplog):
    """Merging a successful child transfers events without publishing."""
    caplog.set_level(logging.INFO, logger="audit")
    parent, child = audit.IngestionAudit(), audit.IngestionAudit()
    child.record_tier_change(
        _state(),
        _written(stored="registered"),
    )
    child.record_withdrawals([{"id": 8, "uuid": _OTHER_UUID}], source=_SOURCE, reason="explicit")
    parent.merge(child)
    child.emit()
    assert not _records(caplog)
    parent.emit()
    assert [record.event_type for record in _records(caplog)] == [
        "tier_changed",
        "dataset_withdrawn",
    ]
    parent.emit()
    assert len(_records(caplog)) == 2


def test_successful_audit_savepoint_publishes_only_with_its_parent(caplog):
    """Successful audit savepoint publishes only with its parent."""
    caplog.set_level(logging.INFO, logger="audit")
    parent = audit.IngestionAudit()
    with audit.audit_savepoint(parent) as child:
        assert child is not None
        child.record_withdrawals([{"id": 7, "uuid": _UUID}], source=_SOURCE, reason="explicit")
        assert not _records(caplog)
    child.emit()
    assert not _records(caplog)
    parent.emit()
    assert [record.uuid for record in _records(caplog)] == [_UUID]


@pytest.mark.parametrize(
    "error", [DataError(_CANARY), RuntimeError(_CANARY), asyncio.CancelledError()]
)
def test_failed_audit_savepoints_discard_only_the_failed_child(caplog, error):
    """Failed audit savepoints discard only the failed child."""
    caplog.set_level(logging.INFO, logger="audit")
    parent = audit.IngestionAudit()
    parent.record_withdrawals([{"id": 7, "uuid": _UUID}], source=_SOURCE, reason="explicit")
    with pytest.raises(type(error)), audit.audit_savepoint(parent) as child:
        assert child is not None
        child.record_withdrawals(
            [{"id": 8, "uuid": _OTHER_UUID}], source=_SOURCE, reason="inferred"
        )
        raise error
    parent.emit()
    assert [record.uuid for record in _records(caplog)] == [_UUID]
    assert _CANARY not in repr([record.__dict__ for record in caplog.records])


def test_disabled_audit_savepoint_yields_none_and_does_not_swallow_errors():
    """Disabled audit savepoint yields None and does not swallow errors."""
    with audit.audit_savepoint(None) as child:
        assert child is None
    with pytest.raises(RuntimeError, match="test failure"), audit.audit_savepoint(None):
        raise RuntimeError("test failure")


@pytest.mark.parametrize("existing", [False, True])
async def test_real_catalogue_writer_captures_persisted_tiers_around_the_upsert(
    caplog,
    existing,
):
    """Real catalogue writer captures persisted tiers around the upsert."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor()
    cursor.fetchone.side_effect = [
        _row(floor="registered") if existing else None,
        {
            "id": 7,
            "source": _SOURCE,
            "uuid": _UUID,
            "visibility_tier": "vetted",
        },
    ]
    policy = legacy_source(
        name=_SOURCE,
        max_visibility="public",
    ).policy
    incoming = parsed_record(
        _UUID,
        visibility_tier="vetted",
        description=_CANARY,
    )
    buffer = audit.IngestionAudit()

    await ingestion._upsert_audited_record(
        cursor,
        incoming,
        policy,
        buffer,
    )

    statements = [str(call.args[0]) for call in cursor.execute.await_args_list]
    assert "FOR UPDATE OF dataset" in statements[0]
    assert "INSERT INTO oral_history_datasets" in statements[1]
    assert "RETURNING id, source, uuid, visibility_tier" in statements[1]
    assert len(statements) == cursor.fetchone.await_count == 2
    assert not _records(caplog)

    buffer.emit()
    if existing:
        (record,) = _records(caplog)
        assert (record.old_tier, record.new_tier) == (
            "registered",
            "vetted",
        )
        assert _CANARY not in repr(record.__dict__)
    else:
        assert not _records(caplog)


async def test_explicit_delete_audits_returned_rows_instead_of_requested_ids_or_rowcount(caplog):
    """Explicit delete audits returned rows instead of requested IDs or rowcount."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor(rows=[{"id": 8, "uuid": _OTHER_UUID}])
    cursor.rowcount = 999
    buffer = audit.IngestionAudit()
    deleted_count = await ingestion._delete_explicit_source_records(
        cursor, _SOURCE, [_UUID, _OTHER_UUID], audit=buffer
    )
    assert deleted_count == 1
    query, parameters = cursor.execute.await_args.args
    assert parameters == (_SOURCE, [_UUID, _OTHER_UUID])
    assert "RETURNING id, uuid" in str(query)
    assert not _records(caplog)
    buffer.emit()
    assert [(record.dataset_id, record.uuid, record.reason) for record in _records(caplog)] == [
        (8, _OTHER_UUID, "explicit")
    ]


async def test_empty_explicit_delete_has_no_query_or_audit_event(caplog):
    """Empty explicit delete has no query or audit event."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor()
    buffer = audit.IngestionAudit()
    assert await ingestion._delete_explicit_source_records(cursor, _SOURCE, [], audit=buffer) == 0
    buffer.emit()
    assert cursor.mock_calls == [] and not _records(caplog)


async def test_inferred_delete_audits_actual_returning_rows_after_the_contraction_guard(caplog):
    """Inferred delete audits actual returning rows after the contraction guard."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor(
        row={"existing_count": 20, "inferred_delete_count": 2},
        rows=[{"id": 8, "uuid": _OTHER_UUID}],
    )
    buffer = audit.IngestionAudit()
    await ingestion._delete_stale_source_records(
        cursor,
        _SOURCE,
        [_UUID],
        audit=buffer,
        max_inferred_delete_count=100,
        max_inferred_delete_ratio_percent=25,
    )
    assert cursor.execute.await_count == 2
    query, parameters = cursor.execute.await_args.args
    assert parameters == (_SOURCE, [_UUID])
    assert "RETURNING id, uuid" in str(query)
    assert not _records(caplog)
    buffer.emit()
    assert [(record.dataset_id, record.uuid, record.reason) for record in _records(caplog)] == [
        (8, _OTHER_UUID, "inferred")
    ]


async def test_aborted_contraction_does_not_delete_or_claim_a_withdrawal(caplog):
    """Aborted contraction does not delete or claim a withdrawal."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor(row={"existing_count": 10, "inferred_delete_count": 9})
    buffer = audit.IngestionAudit()
    with pytest.raises(ingestion._RebuildContractionAborted):
        await ingestion._delete_stale_source_records(
            cursor,
            _SOURCE,
            [_UUID],
            audit=buffer,
            max_inferred_delete_count=100,
            max_inferred_delete_ratio_percent=25,
        )
    buffer.emit()
    cursor.execute.assert_awaited_once()
    cursor.fetchall.assert_not_awaited()
    assert not _records(caplog)


@pytest.mark.parametrize("failure", [None, "statement", "acquisition"])
async def test_feed_write_reporting_never_logs_or_persists_the_database_exception(
    monkeypatch, caplog, failure
):
    """Feed write reporting never logs or persists the database exception."""
    caplog.set_level(logging.INFO)
    cursor = _cursor()
    if failure == "statement":
        cursor.execute.side_effect = OperationalError(_CANARY)
    original = ingestion.get_db_cursor
    database = create_autospec(
        original,
        spec_set=True,
        side_effect=OperationalError(_CANARY) if failure == "acquisition" else None,
        return_value=FakeCursorCtx(cursor),
    )
    monkeypatch.setattr(ingestion, "get_db_cursor", database)
    await ingestion._report_write_failure(
        make_mock_pool(), "incremental", DataError(_CANARY), source=_SOURCE, private_errors=True
    )
    if failure != "acquisition":
        assert cursor.execute.await_args.args[1][0] == "incremental write: feed_write_failed"
        assert _CANARY not in repr(cursor.execute.await_args_list)
    assert _CANARY not in repr([record.__dict__ for record in caplog.records])
    assert all(record.exc_info is None for record in caplog.records)
    assert not _records(caplog)


async def test_finalization_replaces_untrusted_persisted_failure_text_before_summary(
    monkeypatch, caplog, feed_source
):
    """Finalization replaces untrusted persisted failure text before summary."""
    caplog.set_level(logging.INFO)
    cursor = _cursor(
        rows=[
            {"uuid": _UUID, "message": _CANARY},
            {"uuid": _OTHER_UUID, "message": "record_metadata"},
        ]
    )
    original = ingestion.get_db_cursor
    monkeypatch.setattr(
        ingestion,
        "get_db_cursor",
        create_autospec(original, spec_set=True, return_value=FakeCursorCtx(cursor)),
    )
    cutoff = datetime(2030, 1, 2, tzinfo=UTC)
    fingerprint = feed_source.adapter.config_fingerprint()
    failed = await ingestion._finalize_incremental_harvest(
        make_mock_pool(),
        source=_SOURCE,
        harvest_started_at=datetime(2030, 1, 2, tzinfo=UTC),
        source_cursor=cutoff,
        source_fingerprint=fingerprint,
        had_work=False,
        private_errors=True,
    )
    assert failed == [(_UUID, "record_rejected"), (_OTHER_UUID, "record_metadata")]
    writes = cursor.execute.await_args_list
    consumed_writes = [call for call in writes if "SET source_fetch_cursor =" in str(call.args[0])]
    assert len(consumed_writes) == 1
    assert consumed_writes[0].args[1] == (cutoff, fingerprint, _SOURCE)
    assert _CANARY not in repr(writes)
    assert "record_rejected" in repr(writes) and "record_metadata" in repr(writes)
    assert not any("source_cursor =" in str(call.args[0]) for call in writes)
    assert _CANARY not in repr([record.__dict__ for record in caplog.records])
    assert not _records(caplog)


@pytest.fixture
def feed_source():
    """Configure a synthetic JSON feed with distinct development bearer/signing credentials."""
    config = JsonFeedConfig.model_validate(
        {
            "name": _SOURCE,
            "display": {"label": "Audit example"},
            "endpoint": "https://archive.example.edu/feed",
            "max_visibility": "public",
            "credential_env": "AUDIT_FEED_BEARER",
            "signing_key_env": "AUDIT_FEED_KEY",
        }
    )
    environ = {
        name: base64.urlsafe_b64encode(hashlib.sha256(material).digest()).decode().rstrip("=")
        for name, material in (
            ("AUDIT_FEED_BEARER", b"synthetic audit feed bearer"),
            ("AUDIT_FEED_KEY", b"separate synthetic audit feed signing material"),
        )
    }
    credentials = prepare_json_feed_startup((config,), environment="dev", environ=environ)
    return configure_sources((config,), credentials=credentials)[0]


@pytest.mark.parametrize("native_source", [False, True])
async def test_later_incremental_commit_failure_keeps_only_prior_committed_audit(
    monkeypatch, caplog, feed_source, native_source
):
    """Transaction doubles prove publication timing; real PostgreSQL proves rollback."""
    caplog.set_level(logging.INFO)
    now = datetime(2030, 1, 2, tzinfo=UTC)
    cursor = _cursor(
        row={
            "incremental_position": 0,
            "incremental_affected": 0,
            "source_cursor": now - timedelta(days=1),
        }
    )
    connection = create_autospec(AsyncConnection, instance=True, spec_set=True)
    cursor.connection = connection

    @asynccontextmanager
    async def savepoint():
        """Yield without changing transaction state."""
        yield

    connection.transaction.side_effect = savepoint
    attempts, committed = [], []

    @asynccontextmanager
    async def database(_pool):
        """Record transaction attempts and fail the third commit after checking audit publication
        order.
        """
        attempt = len(attempts) + 1
        attempts.append(attempt)
        yield cursor
        if attempt in (2, 3):
            assert len(_records(caplog)) == attempt - 2
        if attempt == 3:
            raise OperationalError(_CANARY)
        committed.append(attempt)

    state_type = audit.DatasetTierState
    write_state_type = audit.DatasetWriteState

    async def capture_change(cur, record, policy, audit):
        """Record a public-to-registered tier transition in the supplied audit buffer."""
        assert cur is cursor and audit is not None
        identity = record["uuid"]
        dataset_id = 7 if identity == _UUID else 8
        before = state_type(dataset_id, policy.name, identity, "public", None)
        after = write_state_type(
            dataset_id,
            policy.name,
            identity,
            "registered",
        )
        audit.record_tier_change(before, after)

    original_db = ingestion.get_db_cursor
    original_upsert = ingestion._upsert_audited_record
    monkeypatch.setattr(
        ingestion,
        "get_db_cursor",
        create_autospec(original_db, spec_set=True, side_effect=database),
    )
    monkeypatch.setattr(
        ingestion,
        "_upsert_audited_record",
        create_autospec(original_upsert, spec_set=True, side_effect=capture_change),
    )
    monkeypatch.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
    harvest = HarvestResult(
        source_cursor=now,
        matching_records=[
            parsed_record(identity, visibility_tier="registered", upstream_modified_at=now)
            for identity in (_UUID, _OTHER_UUID)
        ],
    )
    selected = (
        fixture_source(name=_SOURCE, max_visibility="public") if native_source else feed_source
    )
    expected_error = OperationalError if native_source else RuntimeError
    message = _CANARY if native_source else r"^JSON feed ingestion write failed$"
    with pytest.raises(expected_error, match=message) as error:
        await ingestion._write_incremental(
            make_mock_pool(), harvest, now, configured_source=selected
        )
    assert committed == [1, 2, 4]
    assert [record.uuid for record in _records(caplog)] == [_UUID]
    if not native_source:
        assert _CANARY not in "".join(traceback.format_exception(error.value))
        assert _CANARY not in repr([record.__dict__ for record in caplog.records])


@pytest.mark.parametrize("private_errors", [True, False])
@pytest.mark.parametrize("failure_stage", ["second_write", "savepoint_commit"])
async def test_failed_doi_group_discards_its_buffer_including_savepoint_commit_failure(
    monkeypatch, caplog, feed_source, failure_stage, private_errors
):
    """Failed doi group discards its buffer including savepoint commit failure."""
    caplog.set_level(logging.INFO)
    cursor = _cursor(
        rows=[
            {"uuid": _UUID, "doi": "10.1234/first"},
            {"uuid": _OTHER_UUID, "doi": "10.1234/second"},
        ]
    )
    connection = create_autospec(AsyncConnection, instance=True, spec_set=True)
    cursor.connection = connection
    rolled_back = []

    @asynccontextmanager
    async def savepoint():
        """Record rollback on DataError, optionally failing during savepoint release."""
        try:
            yield
            if failure_stage == "savepoint_commit":
                raise DataError(_CANARY)  # noqa: TRY301 - simulate rejected savepoint commit
        except DataError:
            rolled_back.append(True)
            raise

    connection.transaction.side_effect = savepoint
    state_type = audit.DatasetTierState
    write_state_type = audit.DatasetWriteState
    calls = []

    async def capture_change(cur, record, policy, audit):
        """Record a tier transition, optionally failing the second write before publication."""
        assert cur is cursor and audit is not None
        identity = record["uuid"]
        dataset_id = 7 if identity == _UUID else 8
        calls.append(identity)
        if failure_stage == "second_write" and len(calls) == 2:
            raise DataError(_CANARY)
        before = state_type(dataset_id, policy.name, identity, "public", None)
        after = write_state_type(
            dataset_id,
            policy.name,
            identity,
            "registered",
        )
        audit.record_tier_change(before, after)

    original = ingestion._upsert_audited_record
    monkeypatch.setattr(
        ingestion,
        "_upsert_audited_record",
        create_autospec(original, spec_set=True, side_effect=capture_change),
    )
    parent = audit.IngestionAudit()
    prior_uuid = "33333333-3333-4333-8333-333333333333"
    parent.record_withdrawals([{"id": 9, "uuid": prior_uuid}], source=_SOURCE, reason="explicit")
    successes, failures = await ingestion._reconcile_rebuild_records(
        cursor,
        [
            parsed_record(_UUID, doi="10.1234/second", visibility_tier="registered"),
            parsed_record(_OTHER_UUID, doi="10.1234/first", visibility_tier="registered"),
        ],
        policy=feed_source.policy,
        private_errors=private_errors,
        audit=parent,
    )
    assert calls == [_UUID, _OTHER_UUID] and rolled_back == [True]
    assert successes == 0
    reason = "record_group_failed" if private_errors else f"DataError: {_CANARY}"
    assert failures == [(_UUID, reason), (_OTHER_UUID, reason)]
    assert not _records(caplog)
    parent.emit()
    assert [record.uuid for record in _records(caplog)] == [prior_uuid]
    if private_errors:
        assert _CANARY not in repr([record.__dict__ for record in caplog.records])
        assert all(not record.exc_info for record in caplog.records)
    else:
        assert any(record.exc_info for record in caplog.records)


async def test_untrusted_incoming_uncertainty_is_fixed_before_any_diagnostic_write(
    monkeypatch, caplog, feed_source
):
    """Untrusted incoming uncertainty is fixed before any diagnostic write."""
    caplog.set_level(logging.INFO)
    now = datetime(2030, 1, 2, tzinfo=UTC)
    cursor = _cursor(
        row={"incremental_position": 0, "incremental_affected": 0, "source_cursor": now},
        rows=[{"uuid": _UUID, "message": _CANARY}],
    )
    original = ingestion.get_db_cursor
    monkeypatch.setattr(
        ingestion,
        "get_db_cursor",
        create_autospec(original, spec_set=True, return_value=FakeCursorCtx(cursor)),
    )
    harvest = HarvestResult(source_cursor=now, uncertain_records={_UUID: _CANARY})
    outcome = await ingestion._apply_incremental_harvest(
        make_mock_pool(), harvest, now, configured_source=feed_source
    )
    assert outcome.status == "partial" and outcome.failed_count == 1
    assert _CANARY not in repr(cursor.execute.await_args_list)
    assert "record_rejected" in repr(cursor.execute.await_args_list)
    assert _CANARY not in repr([record.__dict__ for record in caplog.records])
    assert not _records(caplog)


async def test_public_writer_returns_database_tier_instead_of_incoming_tier():
    """Public writer returns database tier instead of incoming tier."""
    cursor = _cursor(row=_row(stored="vetted"))
    policy = legacy_source(
        name=_SOURCE,
        max_visibility="public",
    ).policy

    result = await ingestion._upsert_public_catalogue_record(
        cursor,
        parsed_record(_UUID, visibility_tier="public"),
        policy,
    )

    assert result == _written(stored="vetted")
    cursor.execute.assert_awaited_once()
    cursor.fetchone.assert_awaited_once()


async def test_upsert_without_a_returning_row_is_a_writer_contract_failure():
    """Upsert without a returning row is a writer contract failure."""
    cursor = _cursor(row=None)
    policy = legacy_source(
        name=_SOURCE,
        max_visibility="public",
    ).policy

    with pytest.raises(
        RuntimeError,
        match=r"^Catalogue upsert returned no persisted state$",
    ):
        await ingestion._upsert_public_catalogue_record(
            cursor,
            parsed_record(_UUID),
            policy,
        )

    cursor.execute.assert_awaited_once()
    cursor.fetchone.assert_awaited_once()


@pytest.mark.parametrize(
    "missing_return",
    [False, True],
    ids=["unconfigured-mock", "missing-return"],
)
async def test_audited_insert_rejects_a_writer_without_typed_returned_state(
    monkeypatch,
    caplog,
    missing_return,
):
    """Audited insert rejects a writer without typed returned state."""
    caplog.set_level(logging.INFO, logger="audit")
    cursor = _cursor(row=None)
    writer = create_autospec(
        ingestion._upsert_public_catalogue_record,
        spec_set=True,
    )
    if missing_return:
        writer.return_value = None

    monkeypatch.setattr(
        ingestion,
        "_upsert_public_catalogue_record",
        writer,
    )
    policy = legacy_source(
        name=_SOURCE,
        max_visibility="public",
    ).policy
    buffer = audit.IngestionAudit()

    with pytest.raises(
        RuntimeError,
        match=r"^Catalogue upsert returned an invalid persisted state$",
    ):
        await ingestion._upsert_audited_record(
            cursor,
            parsed_record(_UUID),
            policy,
            buffer,
        )

    writer.assert_awaited_once()
    buffer.emit()
    assert not _records(caplog)
