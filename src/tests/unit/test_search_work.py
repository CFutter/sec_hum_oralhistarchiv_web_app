"""Search admission owns its connection until cancellation and cleanup finish."""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, create_autospec

import pytest
from psycopg import AsyncConnection, OperationalError
from psycopg.errors import QueryCanceled
from psycopg_pool import AsyncConnectionPool, PoolTimeout

from app.services import search_work
from app.services.search_work import SearchUnavailable, SearchWork
from config import settings


def _resources(*, lock_available=True):
    """Build search work with signature-checked pool/connection doubles and scripted lock availability."""
    connection = create_autospec(AsyncConnection, instance=True, spec_set=True)
    cursor = AsyncMock()
    cursor.fetchone.return_value = (lock_available,)

    @asynccontextmanager
    async def cursor_scope(**_kwargs):
        """Yield the scripted cursor without a real database connection."""
        yield cursor

    connection.cursor.side_effect = cursor_scope
    pool = create_autospec(AsyncConnectionPool, instance=True, spec_set=True)
    pool.getconn.return_value = connection
    return SearchWork(pool), pool, connection, cursor


async def test_local_capacity_refuses_without_pool_checkout_and_recovers():
    """Check local capacity refuses without pool checkout and recovers (SearchUnavailable)."""
    work, pool, connection, _ = _resources()
    async with work.connection() as first:
        assert first is connection
        with pytest.raises(SearchUnavailable):
            async with work.connection():
                pytest.fail("A second local search must not enter")
        assert pool.getconn.await_count == 1
        connection.rollback.assert_not_awaited()
    connection.rollback.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)
    async with work.connection():
        pass
    assert pool.getconn.await_count == 2


async def test_global_lock_refusal_rolls_back_and_returns_the_search_connection():
    """Check global lock refusal rolls back and returns the search connection (SearchUnavailable)."""
    work, pool, connection, _ = _resources(lock_available=False)
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            pytest.fail("A competing database search must not enter")
    connection.rollback.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)


@pytest.mark.parametrize("error", [PoolTimeout("private"), OperationalError("private")])
async def test_checkout_failure_is_sanitized_and_does_not_consume_local_capacity(error):
    """Check checkout failure is sanitized and does not consume local capacity (SearchUnavailable)."""
    work, pool, _, _ = _resources()
    pool.getconn.side_effect = error
    for _ in range(2):
        with pytest.raises(SearchUnavailable) as raised:
            async with work.connection():
                pytest.fail("Failed checkout must not enter")
        assert "private" not in str(raised.value)
    assert pool.getconn.await_count == 2
    pool.putconn.assert_not_awaited()


async def test_statement_failure_cleans_up_before_becoming_a_search_refusal():
    """Check statement failure cleans up before becoming a search refusal (SearchUnavailable)."""
    work, pool, connection, _ = _resources()
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            raise QueryCanceled("private query text")
    connection.rollback.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)


async def test_operation_deadline_includes_all_reads_and_returns_the_connection(monkeypatch):
    """Check operation deadline includes all reads and returns the connection (SearchUnavailable)."""
    monkeypatch.setattr(settings, "search_operation_timeout_seconds", 0.02)
    work, pool, connection, _ = _resources()
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            await asyncio.Event().wait()
    connection.rollback.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)


async def test_repeated_cancellation_does_not_release_capacity_during_rollback():
    """Check repeated cancellation does not release capacity during rollback (SearchUnavailable)."""
    work, pool, connection, _ = _resources()
    entered = asyncio.Event()
    rollback_started = asyncio.Event()
    release_rollback = asyncio.Event()

    async def rollback():
        """Signal rollback entry and wait for the test to release it."""
        rollback_started.set()
        await release_rollback.wait()

    connection.rollback.side_effect = rollback

    async def search():
        """Hold a search connection until the task is cancelled."""
        async with work.connection():
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(search())
    await entered.wait()
    task.cancel()
    await rollback_started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            pytest.fail("Cancellation must not free an unfinished transaction")
    pool.putconn.assert_not_awaited()
    release_rollback.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    pool.putconn.assert_awaited_once_with(connection)
    connection.rollback.side_effect = None
    async with work.connection():
        pass


async def test_failed_rollback_discards_connection_before_releasing_capacity():
    """Check failed rollback discards connection before releasing capacity (SearchUnavailable)."""
    work, pool, connection, _ = _resources()
    connection.rollback.side_effect = OperationalError("connection lost")
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            pass
    connection.close.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)


async def test_stalled_rollback_closes_connection_and_returns_capacity(monkeypatch):
    """Check stalled rollback closes connection and returns capacity (SearchUnavailable)."""
    monkeypatch.setattr(search_work, "_CLEANUP_TIMEOUT_SECONDS", 0.01)
    work, pool, connection, _ = _resources()

    async def stalled_rollback():
        """Block rollback indefinitely until cancellation."""
        await asyncio.Event().wait()

    connection.rollback.side_effect = stalled_rollback
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            pass
    connection.close.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)
    connection.rollback.side_effect = None
    async with work.connection():
        pass


async def test_cancellation_waits_for_pool_return_before_releasing_capacity():
    """Check cancellation waits for pool return before releasing capacity (SearchUnavailable)."""
    work, pool, connection, _ = _resources()
    returning = asyncio.Event()
    returned = asyncio.Event()

    async def putconn(actual):
        """Require the selected connection and delay pool return until released."""
        assert actual is connection
        returning.set()
        await returned.wait()

    pool.putconn.side_effect = putconn

    async def search():
        """Enter and leave one search-work connection scope."""
        async with work.connection():
            pass

    task = asyncio.create_task(search())
    await returning.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    with pytest.raises(SearchUnavailable):
        async with work.connection():
            pytest.fail("A pending pool return must still own local capacity")
    returned.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    pool.putconn.side_effect = None
    async with work.connection():
        pass


async def test_programming_errors_propagate_after_cleanup():
    """Check programming errors propagate after cleanup (ValueError)."""
    work, pool, connection, _ = _resources()
    with pytest.raises(ValueError, match="programming error"):
        async with work.connection():
            raise ValueError("programming error")
    connection.rollback.assert_awaited_once()
    pool.putconn.assert_awaited_once_with(connection)
