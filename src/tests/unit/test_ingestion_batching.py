"""Resolved failures are cleared with their batch, before durable progress."""

from unittest.mock import create_autospec

import pytest
from psycopg import DataError, OperationalError

from app.services import ingestion
from app.services.harvest import HarvestResult
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import add_dataset_returning
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import legacy_source


@pytest.mark.parametrize("uuids", [[], ()])
async def test_empty_resolved_identity_batch_issues_no_delete(uuids):
    """Empty resolved identity batch issues no delete."""
    cursor = make_async_cursor()
    await ingestion._delete_ingestion_failures_cur(
        cursor,
        "selected_archive",
        uuids,
    )
    cursor.execute.assert_not_awaited()


async def test_resolved_identity_batch_uses_one_source_scoped_delete():
    """Resolved identity batch uses one source scoped delete."""
    cursor = make_async_cursor()
    await ingestion._delete_ingestion_failures_cur(
        cursor,
        "selected_archive",
        ("first", "second"),
    )

    cursor.execute.assert_awaited_once()
    query, params = cursor.execute.await_args.args
    assert "WHERE source = %s AND uuid = ANY(%s::text[])" in " ".join(query.split())
    assert params == ("selected_archive", ["first", "second"])


@pytest.fixture
def batch_scope(monkeypatch):
    """Patch ingestion to use the fake cursor and two-record commit batches."""
    cursor = add_dataset_returning(
        make_async_cursor(
            fetchone={
                "incremental_position": 0,
                "incremental_affected": 0,
            }
        )
    )
    cursor.connection.transaction.return_value = FakeCursorCtx(cursor)

    monkeypatch.setattr(
        ingestion,
        "get_db_cursor",
        create_autospec(
            ingestion.get_db_cursor,
            spec_set=True,
            side_effect=lambda _pool: FakeCursorCtx(cursor),
        ),
    )
    monkeypatch.setattr(
        ingestion,
        "_INCREMENTAL_COMMIT_BATCH_SIZE",
        2,
    )
    monkeypatch.setattr(
        ingestion,
        "_INCREMENTAL_COMMIT_BATCH_MAX_SECONDS",
        60,
    )
    return cursor, legacy_source()


async def test_only_successful_identities_are_cleared_once_per_batch(
    batch_scope,
    monkeypatch,
):
    """Only successful identities are cleared once per batch."""
    cursor, source = batch_scope
    real_upsert = ingestion._upsert_public_catalogue_record

    async def reject_bad(cur, record, policy):
        """Reject UUID "bad" with DataError and delegate all other writes."""
        if record["uuid"] == "bad":
            raise DataError("controlled record rejection")
        return await real_upsert(cur, record, policy)

    monkeypatch.setattr(
        ingestion,
        "_upsert_public_catalogue_record",
        create_autospec(
            real_upsert,
            spec_set=True,
            side_effect=reject_bad,
        ),
    )
    finalize = create_autospec(
        ingestion._finalize_incremental_harvest,
        spec_set=True,
        return_value=[("bad", "controlled record rejection")],
    )
    monkeypatch.setattr(
        ingestion,
        "_finalize_incremental_harvest",
        finalize,
    )

    harvest = HarvestResult(
        source_cursor=SOURCE_CURSOR,
        deleted_uuids={"already-absent"},
        matching_records=[parsed_record(uuid) for uuid in ("first", "bad", "last")],
    )
    harvest.validate()

    await ingestion._apply_incremental_harvest(
        make_mock_pool(),
        harvest,
        SOURCE_CURSOR,
        configured_source=source,
    )

    calls = cursor.execute.await_args_list
    cleanups = [call for call in calls if "DELETE FROM ingestion_failures" in str(call.args[0])]
    assert [call.args[1] for call in cleanups] == [
        (source.name, ["already-absent", "first"]),
        (source.name, ["last"]),
    ]

    progress = [call for call in calls if "SET incremental_position =" in str(call.args[0])]
    assert [call.args[1] for call in progress] == [
        (2, 1, source.name),
        (4, 2, source.name),
    ]
    assert all(
        calls.index(cleanup) < calls.index(stamp)
        for cleanup, stamp in zip(
            cleanups,
            progress,
            strict=True,
        )
    )

    diagnostics = [call for call in calls if "INSERT INTO ingestion_failures" in str(call.args[0])]
    assert len(diagnostics) == 1
    assert diagnostics[0].args[1][:2] == (source.name, "bad")
    finalize.assert_awaited_once()


async def test_cleanup_failure_prevents_current_batch_progress(
    batch_scope,
    monkeypatch,
):
    """Cleanup failure prevents current batch progress."""
    cursor, source = batch_scope
    real_cleanup = ingestion._delete_ingestion_failures_cur
    batches = []

    async def fail_second_batch(cur, source_name, uuids):
        """Perform real cleanup and record UUIDs, then fail the second batch."""
        await real_cleanup(cur, source_name, uuids)
        batches.append(list(uuids))
        if len(batches) == 2:
            raise OperationalError("controlled cleanup failure")

    monkeypatch.setattr(
        ingestion,
        "_delete_ingestion_failures_cur",
        create_autospec(
            real_cleanup,
            spec_set=True,
            side_effect=fail_second_batch,
        ),
    )
    finalize = create_autospec(
        ingestion._finalize_incremental_harvest,
        spec_set=True,
    )
    monkeypatch.setattr(
        ingestion,
        "_finalize_incremental_harvest",
        finalize,
    )

    harvest = HarvestResult(
        source_cursor=SOURCE_CURSOR,
        matching_records=[parsed_record(uuid) for uuid in ("first", "second", "third", "fourth")],
    )
    harvest.validate()

    with pytest.raises(
        OperationalError,
        match="controlled cleanup failure",
    ):
        await ingestion._apply_incremental_harvest(
            make_mock_pool(),
            harvest,
            SOURCE_CURSOR,
            configured_source=source,
        )

    assert batches == [
        ["first", "second"],
        ["third", "fourth"],
    ]
    progress = [
        call.args[1]
        for call in cursor.execute.await_args_list
        if "SET incremental_position =" in str(call.args[0])
    ]
    assert progress == [(2, 2, source.name)]
    finalize.assert_not_awaited()
