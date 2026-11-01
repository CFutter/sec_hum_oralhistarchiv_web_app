"""Serving restrictions outlive failed catalogue transactions and stale replay."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import create_autospec

import pytest
from psycopg import DataError, OperationalError

from app.services import ingestion
from app.services.harvest import HarvestResult
from tests.fixtures import make_async_cursor, make_mock_pool
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import legacy_source


async def test_incremental_write_failure_is_quarantined_after_later_batch_rollback(monkeypatch):
    """Incremental write failure is quarantined after later batch rollback."""
    source = legacy_source()
    cursor = make_async_cursor(fetchone={"incremental_position": 0, "incremental_affected": 0})
    transactions = []
    statements = []
    current = 0

    @asynccontextmanager
    async def transaction(_pool):
        """Number transaction scopes and record commit/rollback while propagating failures."""
        nonlocal current
        current += 1
        identity = current
        try:
            yield cursor
        except BaseException:
            transactions.append((identity, "rollback"))
            raise
        else:
            transactions.append((identity, "commit"))

    async def execute(statement, params=None):
        """Capture each statement and parameters with its transaction number."""
        statements.append((current, str(statement), params))

    async def apply_item(_cur, uuid, _record, _policy, _audit):
        """Raise DataError for "rejected" and OperationalError for the later item."""
        if uuid == "rejected":
            raise DataError("invalid accepted-record value")
        raise OperationalError("later batch failed")

    cursor.execute.side_effect = execute
    monkeypatch.setattr(ingestion, "get_db_cursor", transaction)
    monkeypatch.setattr(ingestion, "_apply_incremental_item_cur", apply_item)
    harvest = HarvestResult(
        matching_records=[parsed_record("rejected"), parsed_record("later")],
        source_cursor=SOURCE_CURSOR,
    )
    with pytest.raises(OperationalError, match="later batch failed"):
        await ingestion._apply_incremental_harvest(
            make_mock_pool(), harvest, SOURCE_CURSOR, configured_source=source
        )

    assert transactions == [(1, "commit"), (2, "rollback"), (3, "commit")]
    final = [
        params
        for tx, query, params in statements
        if tx == 3 and "INSERT INTO ingestion_quarantine" in query
    ]
    assert final == [
        ("record_write_failed", SOURCE_CURSOR, SOURCE_CURSOR, source.name, ["rejected"])
    ]


async def test_full_rebuild_failure_collector_is_persisted_after_worker_rollback(monkeypatch):
    """Full rebuild failure collector is persisted after worker rollback."""
    source = legacy_source()
    events = []

    async def failed_work(*_args, write_failures, **_kwargs):
        """Collect the rejected identity and raise after recording catalogue rollback."""
        write_failures.add("rejected")
        events.append("catalogue rolled back")
        raise OperationalError("rebuild transaction failed")

    async def persisted(_pool, source_name, uuids, started, source_cursor):
        """Require the source cursor and capture a copy of persisted quarantine identities."""
        assert source_cursor == SOURCE_CURSOR
        events.append((source_name, uuids.copy(), started))

    monkeypatch.setattr(ingestion, "_apply_full_harvest_work", failed_work)
    monkeypatch.setattr(ingestion, "_persist_write_quarantine", persisted)
    with pytest.raises(OperationalError, match="rebuild transaction failed"):
        await ingestion._apply_full_harvest(
            make_mock_pool(),
            HarvestResult(source_cursor=SOURCE_CURSOR),
            SOURCE_CURSOR,
            configured_source=source,
            source_fingerprint=source.adapter.config_fingerprint(),
        )
    assert events == ["catalogue rolled back", (source.name, {"rejected"}, SOURCE_CURSOR)]


async def test_quarantine_final_transaction_is_drained_despite_repeated_cancellation(monkeypatch):
    """Quarantine final transaction is drained despite repeated cancellation."""
    entered, finish = asyncio.Event(), asyncio.Event()
    committed = []
    cursor = make_async_cursor()

    @asynccontextmanager
    async def transaction(_pool):
        """Block until released, then yield the cursor and record successful commit."""
        entered.set()
        await finish.wait()
        yield cursor
        committed.append(True)

    monkeypatch.setattr(ingestion, "get_db_cursor", transaction)
    task = asyncio.create_task(
        ingestion._persist_write_quarantine(
            make_mock_pool(), "archive_alpha", {"known"}, SOURCE_CURSOR, SOURCE_CURSOR
        )
    )
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert committed == [True]
    assert any(
        "INSERT INTO ingestion_quarantine" in str(call.args[0])
        for call in cursor.execute.await_args_list
    )


async def test_restoration_requires_later_harvest_and_never_clears_administrator_state():
    """Restoration requires later harvest and never clears administrator state."""
    cursor = make_async_cursor()
    await ingestion._restore_valid_record_cur(
        cursor, "archive_alpha", "known", SOURCE_CURSOR, SOURCE_CURSOR
    )
    cursor.execute.assert_awaited_once_with(
        "DELETE FROM ingestion_quarantine WHERE source = %s AND uuid = %s "
        "AND failed_harvest_at < %s AND failed_source_cursor <= %s",
        ("archive_alpha", "known", SOURCE_CURSOR, SOURCE_CURSOR),
    )


async def test_successful_rebuild_group_restores_within_its_savepoint(monkeypatch):
    """Successful rebuild group restores within its savepoint."""
    source = legacy_source()
    cursor = make_async_cursor()
    events = []

    @asynccontextmanager
    async def transaction():
        """Record savepoint entry and release around the write group."""
        events.append("savepoint")
        yield
        events.append("release")

    async def accepted(*_args):
        """Record a validated upsert in the event sequence."""
        events.append("validated upsert")

    async def restored(*_args):
        """Record serving-quarantine restoration in the event sequence."""
        events.append("restore")

    cursor.connection.transaction.side_effect = transaction
    monkeypatch.setattr(
        ingestion,
        "_upsert_audited_record",
        create_autospec(ingestion._upsert_audited_record, side_effect=accepted),
    )
    monkeypatch.setattr(
        ingestion,
        "_restore_valid_record_cur",
        create_autospec(ingestion._restore_valid_record_cur, side_effect=restored),
    )
    await ingestion._write_rebuild_group_cur(
        cursor, [parsed_record("known")], source.policy, None, SOURCE_CURSOR, SOURCE_CURSOR
    )
    assert events == ["savepoint", "validated upsert", "restore", "release"]
