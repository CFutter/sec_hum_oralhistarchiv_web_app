"""Committed sensitive-feed changes are audited without incoming metadata."""

import base64
import json
import logging
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import create_autospec

import pytest
from psycopg import sql
from psycopg.errors import CheckViolation

from app.services import ingestion
from app.sources import JsonFeedAdapter
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_STANDARD_LOG_FIELDS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
_PRIVATE = "privatefeedcanary"


@pytest.fixture
def feed(monkeypatch):
    """Install the signed-feed fixture with real authentication and in-process collection."""
    return SignedFeed(monkeypatch)


@pytest.fixture
def audit_capture(caplog):
    """Capture audit records and restore the logger's handlers and propagation on teardown."""
    logger = logging.getLogger("audit")
    handlers, propagate = logger.handlers[:], logger.propagate
    logger.handlers = [*handlers, caplog.handler] if caplog.handler not in handlers else handlers
    logger.propagate = False
    caplog.set_level(logging.INFO)
    try:
        yield caplog
    finally:
        logger.handlers, logger.propagate = handlers, propagate


def _events(capture):
    """Select tier/withdrawal audit events and assert each contains exactly its permitted fields."""
    events = [
        record
        for record in capture.records
        if record.name == "audit"
        and getattr(record, "event_type", None) in {"tier_changed", "dataset_withdrawn"}
    ]
    for event in events:
        expected = {"event_type", "dataset_id", "source", "uuid"} | (
            {"old_tier", "new_tier"} if event.event_type == "tier_changed" else {"reason"}
        )
        assert set(event.__dict__) - _STANDARD_LOG_FIELDS == expected
        assert event.getMessage() == event.event_type and event.exc_info is None
    return events


async def _seed(feed, pool, source, records):
    """Provision the source and require a successful initial snapshot rebuild."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(records)
    result = await ingestion.run_full_rebuild(pool, configured_source=source)
    assert result.status == "success"


def _rows(conn, source):
    """Read source identities, tiers and DOIs keyed by UUID; commit the observer transaction."""
    rows = conn.execute(
        "SELECT uuid, id, visibility_tier, doi FROM oral_history_datasets "
        "WHERE source = %s ORDER BY uuid",
        (source.name,),
    ).fetchall()
    conn.commit()
    return {uuid: (row_id, tier, doi) for uuid, row_id, tier, doi in rows}


def _assert_private_diagnostics_absent(capture, conn, source, *markers):
    """Check credentials and private markers are absent from logs and durable diagnostics."""
    assert isinstance(source.adapter, JsonFeedAdapter)
    credentials = source.adapter.credentials
    secrets = (
        credentials.bearer_token.get_secret_value(),
        base64.urlsafe_b64encode(credentials.signing_key.get_secret_value()).decode().rstrip("="),
    )
    logs = "\n".join(
        logging.Formatter().format(record) + json.dumps(record.__dict__, default=str)
        for record in capture.records
    )
    snapshot = snapshot_feed_source(conn, source.name)
    diagnostics = json.dumps(
        {"state": snapshot["state"], "failures": snapshot["failures"]}, default=str
    )
    for marker in (_PRIVATE, *markers, *secrets):
        assert marker not in logs and marker not in diagnostics


@contextmanager
def _reject_description(conn, uuid, marker):
    """Real PostgreSQL CHECK errors include the private failing-row DETAIL."""
    constraint = sql.Identifier("sensitive_audit_test_rejection")
    conn.execute(
        sql.SQL(
            "ALTER TABLE oral_history_datasets ADD CONSTRAINT {} "
            "CHECK (uuid <> {} OR description <> {}) NOT VALID"
        ).format(
            constraint,
            sql.Literal(uuid),
            sql.Literal(marker),
        )
    )
    conn.commit()
    try:
        yield
    finally:
        conn.rollback()
        conn.execute(
            sql.SQL("ALTER TABLE oral_history_datasets DROP CONSTRAINT {}").format(constraint)
        )
        conn.commit()


@pytest.mark.parametrize("run", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_only_effective_committed_tier_changes_emit_once_and_are_source_scoped(
    feed, db_pool, sync_conn, audit_capture, run
):
    """SB-VIS-006 / SB-VIS-007: committed corrections emit once; replay emits nothing."""
    identity = feed_uuid(1)
    source, other = feed.source(), feed.source("other_sensitive_archive")
    initial = feed.record(identity)
    await _seed(feed, db_pool, source, [initial])
    await _seed(feed, db_pool, other, [initial])
    assert _events(audit_capture) == []
    other_before = snapshot_feed_source(sync_conn, other.name)
    row_id = _rows(sync_conn, source)[identity][0]
    feed.set_snapshot([feed.record(identity, visibility_tier="registered")])
    assert (await run(db_pool, configured_source=source)).status == "success"
    assert (await run(db_pool, configured_source=source)).status == "success"
    feed.set_snapshot([initial])
    assert (await run(db_pool, configured_source=source)).status == "success"
    events = _events(audit_capture)
    assert len(events) == 2
    assert (events[0].event_type, events[0].source, events[0].uuid) == (
        "tier_changed",
        source.name,
        identity,
    )
    assert (events[0].dataset_id, events[0].old_tier, events[0].new_tier) == (
        row_id,
        "public",
        "registered",
    )
    assert (events[1].event_type, events[1].source, events[1].uuid) == (
        "tier_changed",
        source.name,
        identity,
    )
    assert (events[1].dataset_id, events[1].old_tier, events[1].new_tier) == (
        row_id,
        "registered",
        "public",
    )
    assert _rows(sync_conn, source)[identity][1] == "public"
    assert snapshot_feed_source(sync_conn, other.name) == other_before
    _assert_private_diagnostics_absent(audit_capture, sync_conn, source)


async def test_admin_floor_masks_raw_tier_upgrade_without_an_effective_change_event(
    feed, db_pool, sync_conn, audit_capture
):
    """Verify admin floor masks raw tier upgrade without an effective change event."""
    source, identity = feed.source(), feed_uuid(1)
    await _seed(feed, db_pool, source, [feed.record(identity)])
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier) VALUES (%s, %s, 'vetted')",
        (source.name, identity),
    )
    sync_conn.commit()
    feed.set_snapshot([feed.record(identity, visibility_tier="registered")])
    assert (await ingestion.run_sync(db_pool, configured_source=source)).status == "success"
    assert _rows(sync_conn, source)[identity][1] == "registered"
    assert snapshot_feed_source(sync_conn, source.name)["admin"][0]["visibility_tier"] == "vetted"
    assert _events(audit_capture) == []


@pytest.mark.parametrize("mode", ["incremental", "full", "empty-full"])
async def test_only_actual_explicit_withdrawals_emit_even_for_a_zero_match_rebuild(
    feed, db_pool, sync_conn, audit_capture, mode
):
    """SB-VIS-006: authenticated absence of an already absent UUID is not another deletion."""
    source = feed.source()
    records = [feed.record(feed_uuid(number)) for number in range(1, 5)]
    await _seed(feed, db_pool, source, records)
    row_id = _rows(sync_conn, source)[feed_uuid(1)][0]
    retained = records[1:] if mode == "full" else []
    feed.set_snapshot(retained, withdrawn=[feed_uuid(1), feed_uuid(999)])
    run = ingestion.run_sync if mode == "incremental" else ingestion.run_full_rebuild
    for _ in range(2):
        result = await run(db_pool, configured_source=source)
        assert result.status == ("failed" if mode == "empty-full" else "success")
    events = _events(audit_capture)
    assert len(events) == 1 and events[0].event_type == "dataset_withdrawn"
    assert (events[0].source, events[0].uuid, events[0].dataset_id, events[0].reason) == (
        source.name,
        feed_uuid(1),
        row_id,
        "explicit",
    )
    assert set(_rows(sync_conn, source)) == {feed_uuid(number) for number in range(2, 5)}


async def test_guarded_inferred_withdrawal_and_tier_upgrade_emit_after_the_same_rebuild_commit(
    feed, db_pool, sync_conn, audit_capture
):
    """Verify guarded inferred withdrawal and tier upgrade emit after the same rebuild commit."""
    source = feed.source()
    records = [feed.record(feed_uuid(number)) for number in range(1, 5)]
    await _seed(feed, db_pool, source, records)
    feed.set_snapshot([{**records[0], "visibility_tier": "vetted"}, *records[1:3]])
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "success"
    events = _events(audit_capture)
    assert len(events) == 2
    assert {(event.event_type, event.uuid) for event in events} == {
        ("tier_changed", feed_uuid(1)),
        ("dataset_withdrawn", feed_uuid(4)),
    }
    assert (
        next(event for event in events if event.event_type == "dataset_withdrawn").reason
        == "inferred"
    )
    assert set(_rows(sync_conn, source)) == {feed_uuid(number) for number in range(1, 4)}


async def test_zero_match_withdrawal_event_survives_a_later_health_diagnostic_failure(
    feed, db_pool, sync_conn, audit_capture, monkeypatch
):
    """Verify zero match withdrawal event survives a later health diagnostic failure."""
    source = feed.source()
    await _seed(feed, db_pool, source, [feed.record(feed_uuid(1)), feed.record(feed_uuid(2))])
    feed.set_snapshot([], withdrawn=[feed_uuid(1)])
    real_error = ingestion._record_sync_error
    failed = False

    async def fail_once(*args, **kwargs):
        """Raise on the first diagnostic write and delegate later calls."""
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("controlled diagnostic write failure")
        return await real_error(*args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(
            ingestion, "_record_sync_error", create_autospec(real_error, side_effect=fail_once)
        )
        with pytest.raises(RuntimeError):
            await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert set(_rows(sync_conn, source)) == {feed_uuid(2)}
    events = _events(audit_capture)
    assert len(events) == 1 and events[0].uuid == feed_uuid(1)
    assert events[0].event_type == "dataset_withdrawn" and events[0].reason == "explicit"
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "failed"
    assert len(_events(audit_capture)) == 1


@pytest.mark.parametrize("failure", ["contraction", "below-half"])
async def test_failed_rebuilds_preserve_only_committed_withdrawals(
    feed, db_pool, sync_conn, audit_capture, failure
):
    """Verify failed rebuilds preserve only committed withdrawals."""
    source = feed.source()
    records = [feed.record(feed_uuid(number)) for number in range(1, 5)]
    await _seed(feed, db_pool, source, records)
    before = snapshot_feed_source(sync_conn, source.name)
    if failure == "contraction":
        feed.set_snapshot(
            [{**records[0], "visibility_tier": "registered"}], withdrawn=[feed_uuid(2)]
        )
    else:
        feed.set_snapshot(
            [
                {**records[0], "visibility_tier": "registered"},
                *[{**record, "doi": "10.99999/private-collision-doi"} for record in records[1:]],
            ]
        )
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "failed"
    after = snapshot_feed_source(sync_conn, source.name)
    expected_rows = [
        row for row in before["rows"] if failure != "contraction" or row["uuid"] != feed_uuid(2)
    ]
    assert after["rows"] == expected_rows
    events = _events(audit_capture)
    assert [(event.event_type, event.uuid) for event in events] == (
        [("dataset_withdrawn", feed_uuid(2))] if failure == "contraction" else []
    )
    _assert_private_diagnostics_absent(audit_capture, sync_conn, source, "private-collision-doi")


async def test_doi_group_rollback_discards_its_events_and_database_detail_remains_private(
    feed, db_pool, sync_conn, audit_capture, monkeypatch
):
    """SB-VIS-006: a failed DOI swap does not audit its rolled-back first upsert."""
    source = feed.source()
    records = [feed.record(feed_uuid(number)) for number in range(1, 5)]
    await _seed(feed, db_pool, source, records)
    before = _rows(sync_conn, source)
    before_state = snapshot_feed_source(sync_conn, source.name)["state"]
    blocked = "private-row-detail-canary"
    real_upsert = ingestion._upsert_public_catalogue_record
    database_errors = []

    async def observe(*args, **kwargs):
        """Capture and re-raise CheckViolation from the real catalogue upsert."""
        try:
            return await real_upsert(*args, **kwargs)
        except CheckViolation as error:
            database_errors.append(str(error))
            raise

    monkeypatch.setattr(
        ingestion,
        "_upsert_public_catalogue_record",
        create_autospec(real_upsert, side_effect=observe),
    )
    feed.set_snapshot(
        [
            {**records[0], "doi": records[1]["doi"], "visibility_tier": "registered"},
            {
                **records[1],
                "doi": records[0]["doi"],
                "visibility_tier": "registered",
                "description": blocked,
            },
            *records[2:],
        ],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
    )
    with _reject_description(sync_conn, feed_uuid(2), blocked):
        result = await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert result.status == "partial" and result.failed_count == 2
    assert database_errors and blocked in database_errors[0]
    assert _rows(sync_conn, source) == before
    after_state = snapshot_feed_source(sync_conn, source.name)["state"]
    for field in (
        "source_cursor",
        "source_fingerprint",
        "last_harvest_date",
        "last_full_rebuild_date",
        "incremental_harvest",
        "incremental_position",
        "incremental_affected",
    ):
        assert after_state[field] == before_state[field]
    assert _events(audit_capture) == []
    _assert_private_diagnostics_absent(audit_capture, sync_conn, source, blocked)


async def test_incremental_batch_audit_retains_only_committed_work_and_replay_is_once(
    feed, db_pool, sync_conn, audit_capture, monkeypatch
):
    """Verify incremental batch audit retains only committed work and replay is once."""
    source = feed.source()
    records = [feed.record(feed_uuid(number)) for number in range(1, 4)]
    await _seed(feed, db_pool, source, records)
    feed.set_snapshot([{**record, "visibility_tier": "registered"} for record in records])
    monkeypatch.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
    real_cleanup = ingestion._delete_ingestion_failures_cur

    async def fail_after_second_write(cur, source_name, uuids):
        """Perform the real cleanup, then raise when the second marked record is included."""
        result = await real_cleanup(cur, source_name, uuids)
        if feed_uuid(2) in uuids:
            raise RuntimeError("controlled later batch failure: privatebatchcanary")
        return result

    with monkeypatch.context() as fault:
        fault.setattr(
            ingestion,
            "_delete_ingestion_failures_cur",
            create_autospec(
                real_cleanup,
                side_effect=fail_after_second_write,
            ),
        )
        with pytest.raises(
            RuntimeError,
            match="JSON feed ingestion write failed",
        ):
            await ingestion.run_sync(
                db_pool,
                configured_source=source,
            )
    assert [event.uuid for event in _events(audit_capture)] == [feed_uuid(1)]
    rows = _rows(sync_conn, source)
    assert [rows[feed_uuid(number)][1] for number in range(1, 4)] == [
        "registered",
        "public",
        "public",
    ]
    state = snapshot_feed_source(sync_conn, source.name)["state"]
    assert state["incremental_position"] == 1 and state["incremental_harvest"] is not None
    feed.clear_calls()
    assert (await ingestion.run_sync(db_pool, configured_source=source)).status == "success"
    assert not feed.requests and not feed.worker_calls
    assert [event.uuid for event in _events(audit_capture)] == [
        feed_uuid(number) for number in range(1, 4)
    ]
    assert (await ingestion.run_sync(db_pool, configured_source=source)).status == "success"
    assert len(_events(audit_capture)) == 3
    _assert_private_diagnostics_absent(audit_capture, sync_conn, source, "privatebatchcanary")


async def test_malformed_doi_warning_and_real_uniqueness_error_never_log_private_values(
    feed, db_pool, sync_conn, audit_capture
):
    """SB-DISC-007 / SB-VIS-006: database DETAIL and DOI warnings are not diagnostics payloads."""
    source = feed.source()
    private_doi = "10.99999/private-doi-detail-canary"
    malformed_doi = "private-malformed-doi-canary"
    await _seed(feed, db_pool, source, [feed.record(feed_uuid(1), doi=private_doi)])
    feed.set_snapshot(
        [
            feed.record(feed_uuid(2), doi=private_doi),
            feed.record(feed_uuid(3), doi=malformed_doi),
        ]
    )
    result = await ingestion.run_sync(db_pool, configured_source=source)
    assert result.status == "partial" and result.failed_count == 1
    rows = _rows(sync_conn, source)
    assert set(rows) == {feed_uuid(1), feed_uuid(3)} and rows[feed_uuid(3)][2] is None
    assert _events(audit_capture) == []
    _assert_private_diagnostics_absent(audit_capture, sync_conn, source, private_doi, malformed_doi)
