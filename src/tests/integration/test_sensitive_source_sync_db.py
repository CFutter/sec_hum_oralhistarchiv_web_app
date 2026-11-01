"""Signed native feed input through real adapter and source-scoped persistence."""

from datetime import datetime, timedelta
from unittest.mock import create_autospec

import psycopg
import pytest

from app.services import DatasetAdminContext, change_dataset_admin_state, ingestion
from app.services.datasets import get_dataset_by_id
from app.services.stored_harvest import decode_stored_harvest
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_A, _B, _C, _D = map(feed_uuid, range(1, 5))
_LATER = DEFAULT_CUTOFF + timedelta(hours=1)
_LATEST = DEFAULT_CUTOFF + timedelta(hours=2)
_REJECTED = "rejectedconfidentialcanary"


@pytest.fixture
def feed(monkeypatch):
    """Install the signed-feed fixture with real authentication and in-process collection."""
    return SignedFeed(monkeypatch)


async def _initial_rebuild(pool, feed, source, records):
    """Provision the source, select records and require a successful authoritative rebuild."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(records)
    outcome = await ingestion.run_full_rebuild(pool, configured_source=source)
    assert outcome.status == "success"


def _row(snapshot, uuid):
    """Select the requested UUID from a source snapshot; raise StopIteration if absent."""
    return next(row for row in snapshot["rows"] if row["uuid"] == uuid)


def _progress(snapshot):
    """Extract source cursors, binding and harvest/rebuild timestamps from a snapshot."""
    state = snapshot["state"]
    return tuple(
        state[field]
        for field in (
            "source_cursor",
            "source_fingerprint",
            "last_harvest_date",
            "last_full_rebuild_date",
        )
    )


def _quarantine(conn, source):
    """Read source quarantine rows in UUID order and commit the observer transaction."""
    rows = conn.execute(
        "SELECT uuid, reason FROM ingestion_quarantine WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    conn.commit()
    return rows


def _assert_preserved_except_diagnostics(before, after, *channels):
    """Compare snapshots excluding only the named error channels."""
    assert {key: value for key, value in after.items() if key != "state"} == {
        key: value for key, value in before.items() if key != "state"
    }
    diagnostics = {
        field
        for channel in channels
        for field in (f"last_{channel}_error", f"last_{channel}_error_at")
    }
    assert {key: value for key, value in after["state"].items() if key not in diagnostics} == {
        key: value for key, value in before["state"].items() if key not in diagnostics
    }


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
@pytest.mark.parametrize(
    "invalid",
    ["missing", "null", "unknown", "duplicate_equal", "duplicate_conflict", "blank_title"],
)
async def test_identifiable_bad_records_preserve_last_good_and_quarantine_new_records(
    db_pool, sync_conn, feed, runner, invalid, bind_catalogue_policy
):
    """SB-DISC-007, SB-VIS-001, SB-VIS-002: real native rejection precedes writes."""
    source = feed.source()
    bind_catalogue_policy((source,))
    await _initial_rebuild(
        db_pool,
        feed,
        source,
        [feed.record(_A, visibility_tier="vetted"), feed.record(_B)],
    )
    before = snapshot_feed_source(sync_conn, source.name)
    rejected = []
    for uuid in (_A, _C):
        record = feed.record(uuid, marker=_REJECTED, title="Rejected incoming discovery title")
        if invalid == "missing":
            del record["visibility_tier"]
        elif invalid == "null":
            record["visibility_tier"] = None
        elif invalid == "unknown":
            record["visibility_tier"] = "unknown"
        elif invalid.startswith("duplicate"):
            record = feed.duplicate_field(
                record, "visibility_tier", "public" if invalid == "duplicate_equal" else "vetted"
            )
        else:
            record["title"] = " "
        rejected.append(record)
    feed.set_snapshot(
        [*rejected, feed.record(_B, title="Accepted neighbour update")],
        cutoff=_LATER,
        page_size=3,
    )
    outcome = await runner(db_pool, configured_source=source)
    assert (outcome.status, outcome.affected_count, outcome.failed_count) == ("partial", 1, 2)
    after = snapshot_feed_source(sync_conn, source.name)
    assert _row(after, _A) == _row(before, _A)
    assert {row["uuid"] for row in after["rows"]} == {_A, _B}
    assert _row(after, _B)["title"] == "Accepted neighbour update"
    assert _progress(after) == _progress(before)
    assert {failure["uuid"] for failure in after["failures"]} == {_A, _C}
    assert _REJECTED not in repr(after)
    reason = {
        "missing": "record_shape",
        "null": "record_tier",
        "unknown": "record_tier",
        "duplicate_equal": "duplicate_record_key",
        "duplicate_conflict": "duplicate_record_key",
        "blank_title": "record_metadata",
    }[invalid]
    assert {failure["message"] for failure in after["failures"]} == {reason}
    assert _quarantine(sync_conn, source.name) == [(_A, "record_rejected")]
    assert (
        await get_dataset_by_id(
            db_pool, _row(after, _A)["id"], "vetted", configured_sources=(source,)
        )
        is None
    )
    neighbour = await get_dataset_by_id(
        db_pool, _row(after, _B)["id"], "public", configured_sources=(source,)
    )
    assert neighbour is not None and neighbour.title == "Accepted neighbour update"

    feed.set_snapshot(
        [feed.record(_A, title="Corrected discovery title"), feed.record(_B), feed.record(_C)],
        cutoff=_LATEST,
    )
    corrected = await runner(db_pool, configured_source=source)
    assert corrected.status == "success" and corrected.failed_count == 0
    final = snapshot_feed_source(sync_conn, source.name)
    assert final["failures"] == []
    assert _quarantine(sync_conn, source.name) == []
    assert _row(final, _A)["title"] == "Corrected discovery title"
    assert _row(final, _A)["visibility_tier"] == "public"
    assert {row["uuid"] for row in final["rows"]} == {_A, _B, _C}
    assert datetime.fromisoformat(final["state"]["source_cursor"]) == _LATEST


@pytest.mark.parametrize("withdraw", [False, True], ids=["preserve-all", "explicit-withdrawal"])
async def test_all_invalid_rebuild_records_save_failures_without_losing_last_good_state(
    db_pool, sync_conn, feed, withdraw
):
    """SB-DISC-007, SB-VIS-002, SB-VIS-007: zero matches still records quarantine."""
    source = feed.source()
    other = feed.source(name="retained_archive")
    initial = [feed.record(_A), feed.record(_D)]
    await _initial_rebuild(db_pool, feed, source, initial)
    await _initial_rebuild(db_pool, feed, other, initial)
    sync_conn.execute(
        "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
        (source.name, _B, "record_timestamp"),
    )
    sync_conn.commit()
    before = snapshot_feed_source(sync_conn, source.name)
    foreign = snapshot_feed_source(sync_conn, other.name)
    existing = feed.record(_A, marker=_REJECTED)
    del existing["visibility_tier"]
    feed.set_snapshot(
        [existing, feed.record(_C, marker=_REJECTED, visibility_tier=None)],
        withdrawn=(_D,) if withdraw else (),
        cutoff=_LATER,
        page_size=1,
    )
    outcome = await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert (outcome.status, outcome.affected_count, outcome.failed_count) == (
        "failed",
        int(withdraw),
        3,
    )
    after = snapshot_feed_source(sync_conn, source.name)
    assert _row(after, _A) == _row(before, _A)
    assert {row["uuid"] for row in after["rows"]} == ({_A} if withdraw else {_A, _D})
    assert after["rows"] == [row for row in before["rows"] if not withdraw or row["uuid"] != _D]
    assert {failure["uuid"]: failure["message"] for failure in after["failures"]} == {
        _A: "record_shape",
        _B: "record_timestamp",
        _C: "record_tier",
    }
    assert next(item for item in after["failures"] if item["uuid"] == _B) == before["failures"][0]
    assert _REJECTED not in repr(after)
    assert after["admin"] == before["admin"]
    diagnostics = {"last_rebuild_error", "last_rebuild_error_at", "source_fetch_cursor"}
    assert {key: value for key, value in after["state"].items() if key not in diagnostics} == {
        key: value for key, value in before["state"].items() if key not in diagnostics
    }
    assert snapshot_feed_source(sync_conn, other.name) == foreign


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_two_page_update_applies_tier_corrections_and_withdraws_only_this_source(
    db_pool, sync_conn, feed, runner
):
    """SB-VIS-003, SB-VIS-004, SB-VIS-007, SB-VIS-008: authenticated reconciliation."""
    source = feed.source(floor="registered")
    other = feed.source(name="retained_archive")
    initial = [
        feed.record(_A),
        feed.record(_B, visibility_tier="vetted"),
        feed.record(_C),
        feed.record(_D),
    ]
    await _initial_rebuild(db_pool, feed, source, initial)
    await _initial_rebuild(db_pool, feed, other, initial)
    before = snapshot_feed_source(sync_conn, source.name)
    foreign = snapshot_feed_source(sync_conn, other.name)
    assert _row(before, _A)["visibility_tier"] == "registered"
    feed.clear_calls()
    feed.set_snapshot(
        [
            feed.record(_A, title="Updated source fields", visibility_tier="vetted"),
            feed.record(_B, title="Fresh upstream reclassification", visibility_tier="public"),
            feed.record(_D),
        ],
        withdrawn=(_C,),
        cutoff=_LATER,
        page_size=2,
    )
    outcome = await runner(db_pool, configured_source=source)
    assert outcome.status == "success"
    assert len(feed.requests) == 2 and feed.requests[1]["cursor"] == "synthetic-page-1"
    assert feed.requests[0]["nonce"] != feed.requests[1]["nonce"]
    after = snapshot_feed_source(sync_conn, source.name)
    assert {row["uuid"] for row in after["rows"]} == {_A, _B, _D}
    assert _row(after, _A)["visibility_tier"] == "vetted"
    assert _row(after, _B)["visibility_tier"] == "registered"
    assert _row(after, _D)["visibility_tier"] == "registered"
    assert _row(after, _A)["id"] == _row(before, _A)["id"]
    assert _row(after, _A)["data"]["title"] == "Updated source fields"
    assert snapshot_feed_source(sync_conn, other.name) == foreign


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_durable_hide_and_admin_floor_survive_native_withdrawal_and_reintroduction(
    bind_catalogue_policy, db_pool, sync_conn, feed, runner, admin_actor
):
    """SB-DISC-008, SB-VIS-004, SB-VIS-007: source writes cannot undo admin state."""
    source = feed.source()
    bind_catalogue_policy((source,))
    await _initial_rebuild(db_pool, feed, source, [feed.record(_A), feed.record(_B)])
    before = snapshot_feed_source(sync_conn, source.name)
    original_id = _row(before, _A)["id"]
    context = DatasetAdminContext(
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
        request_id="sensitive-feed-state-test",
        client_ip="127.0.0.1",
    )
    await change_dataset_admin_state(
        db_pool,
        original_id,
        "raise_tier",
        context=context,
        new_tier="vetted",
        configured_sources=(source,),
    )
    await change_dataset_admin_state(
        db_pool, original_id, "hide", context=context, configured_sources=(source,)
    )
    admin = snapshot_feed_source(sync_conn, source.name)["admin"]
    feed.set_snapshot([feed.record(_B)], withdrawn=(_A,), cutoff=_LATER)
    assert (await runner(db_pool, configured_source=source)).status == "success"
    deleted = snapshot_feed_source(sync_conn, source.name)
    assert {row["uuid"] for row in deleted["rows"]} == {_B}
    assert deleted["admin"] == admin
    feed.set_snapshot([feed.record(_A, title="Returned record"), feed.record(_B)], cutoff=_LATEST)
    assert (await runner(db_pool, configured_source=source)).status == "success"
    returned = snapshot_feed_source(sync_conn, source.name)
    returned_id = _row(returned, _A)["id"]
    assert returned_id != original_id and returned["admin"] == admin
    assert (
        await get_dataset_by_id(db_pool, returned_id, "vetted", configured_sources=(source,))
        is None
    )
    await change_dataset_admin_state(
        db_pool, returned_id, "restore", context=context, configured_sources=(source,)
    )
    public = await get_dataset_by_id(db_pool, returned_id, "public", configured_sources=(source,))
    vetted = await get_dataset_by_id(db_pool, returned_id, "vetted", configured_sources=(source,))
    assert public is not None and public.visibility_tier == "vetted" and public.description is None
    assert vetted is not None and vetted.description == "privatefeedcanary description"


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
@pytest.mark.parametrize("older", [False, True], ids=["equal-cutoff", "older-cutoff"])
async def test_authenticated_cutoff_cannot_roll_back_committed_state(
    db_pool, sync_conn, feed, runner, older
):
    """SB-VIS-005, SB-TRANS-004: a fresh signed response cannot roll back progress."""
    source = feed.source()
    await _initial_rebuild(db_pool, feed, source, [feed.record(_A), feed.record(_B)])
    before = snapshot_feed_source(sync_conn, source.name)
    cutoff = DEFAULT_CUTOFF - timedelta(hours=1) if older else DEFAULT_CUTOFF
    feed.set_snapshot(
        [feed.record(_A, title="Authenticated replacement"), feed.record(_B)], cutoff=cutoff
    )
    if older and runner is ingestion.run_full_rebuild:
        with pytest.raises(ValueError, match="snapshot predates"):
            await runner(db_pool, configured_source=source)
        outcome = None
    else:
        outcome = await runner(db_pool, configured_source=source)
    after = snapshot_feed_source(sync_conn, source.name)
    assert after["state"]["source_cursor"] == before["state"]["source_cursor"]
    assert after["state"]["incremental_harvest"] is None
    if older:
        assert outcome is None or outcome.status == "failed"
        _assert_preserved_except_diagnostics(
            before, after, "sync" if runner is ingestion.run_sync else "rebuild"
        )
    else:
        assert outcome.status == "success"
        assert _row(after, _A)["title"] == "Authenticated replacement"


async def _interrupt_native_incremental(pool, monkeypatch, source):
    """Interrupt the second incremental write after one committed item."""
    real = ingestion._upsert_public_catalogue_record
    calls = 0

    async def interrupt_second(cur, record, policy):
        """Raise OperationalError on the second write and delegate the first."""
        nonlocal calls
        calls += 1
        if calls == 2:
            raise psycopg.OperationalError("injected interruption after committed progress")
        return await real(cur, record, policy)

    with monkeypatch.context() as crash:
        crash.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
        crash.setattr(
            ingestion,
            "_upsert_public_catalogue_record",
            create_autospec(real, spec_set=True, side_effect=interrupt_second),
        )
        with pytest.raises(RuntimeError, match="JSON feed ingestion write failed"):
            await ingestion.run_sync(pool, configured_source=source)


async def test_authenticated_staged_payload_replays_without_another_network_request(
    db_pool, sync_conn, feed, monkeypatch
):
    """SB-TRANS-004, SB-VIS-007: durable replay uses the authenticated complete chain."""
    source = feed.source()
    await _initial_rebuild(db_pool, feed, source, [feed.record(_A)])
    feed.set_snapshot(
        [feed.record(_A, title="Committed first item"), feed.record(_B)], cutoff=_LATER
    )
    await _interrupt_native_incremental(db_pool, monkeypatch, source)
    staged = sync_conn.execute(
        "SELECT incremental_harvest, incremental_position, incremental_affected FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone()
    sync_conn.commit()
    assert staged[1:] == (1, 1)
    decoded = decode_stored_harvest(
        bytes(staged[0]), expected_source_fingerprint=source.adapter.config_fingerprint()
    )
    assert [record["uuid"] for record in decoded.matching_records] == [_A, _B]
    assert decoded.source_cursor == _LATER
    feed.clear_calls()
    feed.status_code = 503
    outcome = await ingestion.run_sync(db_pool, configured_source=source)
    assert (outcome.status, outcome.affected_count) == ("success", 2)
    assert feed.requests == feed.worker_calls == []
    after = snapshot_feed_source(sync_conn, source.name)
    assert {row["uuid"] for row in after["rows"]} == {_A, _B}
    assert after["state"]["incremental_harvest"] is None
    assert datetime.fromisoformat(after["state"]["source_cursor"]) == _LATER


async def test_staged_cutoff_older_than_committed_state_requires_authoritative_recovery(
    db_pool, sync_conn, feed, monkeypatch
):
    """SB-VIS-005, SB-TRANS-004: replay cannot bypass the committed cutoff fence."""
    source = feed.source()
    await _initial_rebuild(db_pool, feed, source, [feed.record(_A)])
    feed.set_snapshot([feed.record(_A), feed.record(_B)], cutoff=_LATER)
    await _interrupt_native_incremental(db_pool, monkeypatch, source)
    sync_conn.execute(
        "UPDATE sync_status SET source_cursor = %s WHERE source = %s", (_LATEST, source.name)
    )
    sync_conn.commit()
    before = snapshot_feed_source(sync_conn, source.name)
    feed.clear_calls()
    outcome = await ingestion.run_sync(db_pool, configured_source=source)
    assert outcome.status == "failed" and outcome.requires_full_rebuild
    after = snapshot_feed_source(sync_conn, source.name)
    _assert_preserved_except_diagnostics(before, after, "sync")
    assert feed.requests == feed.worker_calls == []
    feed.set_snapshot([feed.record(_A), feed.record(_B)], cutoff=_LATEST)
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "success"
    assert snapshot_feed_source(sync_conn, source.name)["state"]["incremental_harvest"] is None


@pytest.mark.parametrize(
    "failed_rebuild", [False, True], ids=["successful-rebind", "failed-rebind"]
)
async def test_new_feed_binding_fences_staged_work_until_a_successful_real_rebuild(
    db_pool, sync_conn, feed, monkeypatch, failed_rebuild, approve_source_rebinding
):
    """SB-VIS-007, SB-TRANS-004: incompatible binding cannot replay or advance state."""
    source = feed.source()
    await _initial_rebuild(db_pool, feed, source, [feed.record(_A)])
    feed.set_snapshot([feed.record(_A), feed.record(_B)], cutoff=_LATER)
    await _interrupt_native_incremental(db_pool, monkeypatch, source)
    before = snapshot_feed_source(sync_conn, source.name)
    changed = feed.source(floor="registered", signing_key_env="ROTATED_KEY_REFERENCE")
    feed.clear_calls()
    fenced = await ingestion.run_sync(db_pool, configured_source=changed)
    assert fenced.status == "failed" and fenced.requires_source_acknowledgement
    assert feed.requests == feed.worker_calls == []
    feed.set_snapshot([feed.record(_A), feed.record(_B)], cutoff=_LATEST)
    approve_source_rebinding(changed)
    if failed_rebuild:
        feed.signature_mode = "wrong"
    outcome = await ingestion.run_full_rebuild(db_pool, configured_source=changed)
    after = snapshot_feed_source(sync_conn, changed.name)
    if failed_rebuild:
        assert outcome.status == "failed"
        _assert_preserved_except_diagnostics(before, after, "sync", "rebuild")
    else:
        assert outcome.status == "success"
        assert after["state"]["source_fingerprint"] == changed.adapter.config_fingerprint()
        assert after["state"]["incremental_harvest"] is None
        assert {row["visibility_tier"] for row in after["rows"]} == {"registered"}
