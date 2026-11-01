"""Mandatory record-tier policy enables audit independently of adapter diagnostics."""

import logging
from datetime import timedelta
from unittest.mock import create_autospec

import pytest

from app.services import ensure_source_status_rows, ingestion
from app.services.harvest import HarvestResult
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import fixture_source


@pytest.fixture
def audit_events(caplog):
    """Capture audit records and restore the logger's handlers and propagation on teardown."""
    logger = logging.getLogger("audit")
    handlers, propagate = logger.handlers[:], logger.propagate
    logger.handlers = [caplog.handler]
    logger.propagate = False
    caplog.set_level(logging.INFO)
    try:
        yield caplog
    finally:
        logger.handlers, logger.propagate = handlers, propagate


def _changes(capture):
    """Return captured tier-change and withdrawal event identities."""
    return [
        (record.event_type, record.uuid)
        for record in capture.records
        if record.name == "audit"
        and getattr(record, "event_type", None) in {"tier_changed", "dataset_withdrawn"}
    ]


async def _source_with_snapshot(db_pool, monkeypatch, *, required=True):
    """Provision a mutable fixture harvest and bind it through an initial rebuild."""
    source = fixture_source(
        name="policy_audit", max_visibility="public", requires_record_tier=required
    )
    snapshot = HarvestResult(source_cursor=SOURCE_CURSOR)

    def fetch(_adapter, *, since, cancel_event=None):
        """Return the mutable fixture snapshot after checking boundary and cancellation."""
        assert since is None or since <= SOURCE_CURSOR
        assert cancel_event is None or not cancel_event.is_set()
        return snapshot

    original = type(source.adapter).fetch
    monkeypatch.setattr(type(source.adapter), "fetch", create_autospec(original, side_effect=fetch))
    await ensure_source_status_rows(db_pool, (source.name,))
    snapshot.matching_records = [
        parsed_record(f"record-{number}", visibility_tier="public") for number in range(4)
    ]
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "success"
    return source, snapshot


@pytest.mark.parametrize("required", [True, False])
@pytest.mark.parametrize("mode", ["incremental", "full"])
async def test_native_source_audits_tier_changes_and_withdrawals_by_policy(
    db_pool, monkeypatch, audit_events, required, mode
):
    """Verify native source audits tier changes and withdrawals by policy."""
    source, snapshot = await _source_with_snapshot(db_pool, monkeypatch, required=required)
    snapshot.matching_records = snapshot.matching_records[:3]
    snapshot.matching_records[0]["visibility_tier"] = "registered"
    if mode == "incremental":
        snapshot.deleted_uuids = {"record-3"}
    run = ingestion.run_sync if mode == "incremental" else ingestion.run_full_rebuild
    assert (await run(db_pool, configured_source=source)).status == "success"
    expected = (
        {("tier_changed", "record-0"), ("dataset_withdrawn", "record-3")} if required else set()
    )
    assert set(_changes(audit_events)) == expected
    assert (await run(db_pool, configured_source=source)).status == "success"
    assert len(_changes(audit_events)) == len(expected)


@pytest.mark.parametrize("required", [True, False], ids=["audit", "no_audit"])
@pytest.mark.parametrize("withdrawals", ["empty", "nonexistent", "mixed"])
async def test_empty_rebuild_counts_only_committed_source_withdrawals(
    db_pool, sync_conn, dataset_factory, monkeypatch, audit_events, required, withdrawals
):
    """Verify empty rebuild counts only committed source withdrawals."""
    source, snapshot = await _source_with_snapshot(db_pool, monkeypatch, required=required)
    for uuid in ("record-0", "record-1", "missing", "other-source-only"):
        dataset_factory(source="other_source", uuid=uuid)
    other_before = sync_conn.execute(
        "SELECT id, uuid, title FROM oral_history_datasets WHERE source = 'other_source' ORDER BY id"
    ).fetchall()
    publication_query = """
        SELECT last_harvest_date, last_full_rebuild_date, source_cursor, source_fingerprint
        FROM sync_status WHERE source = %s
    """
    before = sync_conn.execute(publication_query, (source.name,)).fetchone()
    snapshot.matching_records = []
    snapshot.source_cursor = SOURCE_CURSOR + timedelta(days=1)
    if withdrawals != "empty":
        snapshot.deleted_uuids = {"missing", "other-source-only"}
    if withdrawals == "mixed":
        snapshot.deleted_uuids.add("record-0")
        snapshot.nonmatching_uuids = {"record-1"}
    expected_deletions = 1 if withdrawals == "mixed" else 0
    expected_events = (
        [("dataset_withdrawn", "record-0")] if required and withdrawals == "mixed" else []
    )

    # Read through an independent connection: counts and events must describe
    # committed removals, while replayed/nonexistent tombstones change nothing.
    for expected_count in (expected_deletions, 0):
        outcome = await ingestion.run_full_rebuild(db_pool, configured_source=source)
        assert outcome.status == "failed"
        assert outcome.affected_count == expected_count
        assert outcome.failed_count == int(withdrawals == "mixed")
        assert sync_conn.execute(publication_query, (source.name,)).fetchone() == before
        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
            (source.name,),
        ).fetchall() == [(f"record-{number}",) for number in range(expected_deletions, 4)]
        assert (
            sync_conn.execute(
                "SELECT id, uuid, title FROM oral_history_datasets "
                "WHERE source = 'other_source' ORDER BY id"
            ).fetchall()
            == other_before
        )
        diagnostic = sync_conn.execute(
            "SELECT last_rebuild_error FROM sync_status WHERE source = %s", (source.name,)
        ).fetchone()[0]
        assert f"{expected_count} explicit source removal(s) applied" in diagnostic
        warning = [
            record.getMessage()
            for record in audit_events.records
            if record.name == ingestion.logger.name
            and "no matching records returned" in record.getMessage()
        ][-1]
        assert f"applied {expected_count} explicit removal(s)" in warning
        assert sorted(_changes(audit_events)) == expected_events
        if withdrawals == "mixed":
            assert sync_conn.execute(
                "SELECT reason FROM ingestion_quarantine WHERE source=%s AND uuid='record-1'",
                (source.name,),
            ).fetchone() == ("filter_mismatch",)
            assert sync_conn.execute(
                "SELECT count(*) FROM catalogue_discovery WHERE source=%s AND uuid='record-1'",
                (source.name,),
            ).fetchone() == (0,)


async def test_native_source_rollback_publishes_no_tentative_audit(
    db_pool, monkeypatch, audit_events
):
    """Verify native source rollback publishes no tentative audit."""
    source, snapshot = await _source_with_snapshot(db_pool, monkeypatch)
    snapshot.matching_records = snapshot.matching_records[:1]
    snapshot.matching_records[0]["visibility_tier"] = "registered"
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "failed"
    assert _changes(audit_events) == []


async def test_native_source_incremental_replay_audits_only_committed_batches(
    db_pool, monkeypatch, audit_events
):
    """Verify native source incremental replay audits only committed batches."""
    source, snapshot = await _source_with_snapshot(db_pool, monkeypatch)
    for record in snapshot.matching_records:
        record["visibility_tier"] = "registered"
    monkeypatch.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
    original = ingestion._delete_ingestion_failures_cur

    async def fail_second_batch(cur, source, uuids):
        """Perform real cleanup, then raise for the marked second batch."""
        await original(cur, source, uuids)
        if "record-1" in uuids:
            raise RuntimeError("native-source diagnostic remains available")

    with monkeypatch.context() as fault:
        fault.setattr(
            ingestion,
            "_delete_ingestion_failures_cur",
            create_autospec(original, side_effect=fail_second_batch),
        )
        with pytest.raises(RuntimeError, match="native-source diagnostic remains available"):
            await ingestion.run_sync(db_pool, configured_source=source)
    assert _changes(audit_events) == [("tier_changed", "record-0")]
    assert (await ingestion.run_sync(db_pool, configured_source=source)).status == "success"
    assert _changes(audit_events) == [("tier_changed", f"record-{number}") for number in range(4)]
