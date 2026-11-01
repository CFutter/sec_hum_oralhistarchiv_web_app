"""Bound catalogue search work without borrowing account database capacity."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from psycopg import AsyncConnection, OperationalError
from psycopg.errors import QueryCanceled
from psycopg.rows import tuple_row
from psycopg_pool import AsyncConnectionPool, PoolTimeout, TooManyRequests

from config import settings

# A separate namespace from ingestion/catalogue mutation locks. Every worker
# sharing the database uses this one key, irrespective of client or search text.
_SEARCH_WORK_LOCK_KEY = 0x4F484151  # "OHAQ"
_CLEANUP_TIMEOUT_SECONDS = 1.0


class SearchUnavailable(RuntimeError):
    """A search cannot proceed within its independent admission/work budget."""

    def __init__(self) -> None:
        """Set the user-facing temporary-unavailability message."""
        super().__init__("Search is temporarily unavailable. Please try again shortly.")


class SearchWork:
    """One application event loop owns a pool and immediate local admission.

    The nonblocking database lock supplies the deployment-wide concurrency
    bound; the early global start-rate gate separately limits sustained work.
    Page retrieval and facets share the yielded connection and outer read-only
    transaction. Context helpers can open savepoints without releasing its lock.
    """

    def __init__(self, pool: AsyncConnectionPool) -> None:
        """Retain the pool and mark this event-loop-owned worker idle."""
        self._pool = pool
        self._busy = False

    async def _return_connection(self, connection: AsyncConnection) -> None:
        """End the outer transaction before returning its connection or permit.

        Roll back even successful reads. If rollback cannot finish promptly,
        close the connection so the pool cannot lend an uncertain transaction.
        """
        try:
            async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                await connection.rollback()
        except BaseException:
            await connection.close()
            raise
        finally:
            await self._pool.putconn(connection)

    async def _finish(self, connection: AsyncConnection) -> None:
        """Drain cleanup despite repeated request cancellation, then propagate it."""
        cleanup = asyncio.create_task(self._return_connection(connection))
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                cancelled = True
        # Retrieve failures before propagating cancellation so no background
        # task or connection-return exception is silently abandoned.
        cleanup.result()
        if cancelled:
            raise asyncio.CancelledError

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        """Yield one bounded search transaction or reject without a local queue.

        No await occurs between checking and taking the event-loop-owned permit.
        Keep it until rollback/close and pool return have actually completed.
        Never fall back to the account pool or leave a detached query running.
        """
        if self._busy:
            raise SearchUnavailable
        self._busy = True
        connection: AsyncConnection | None = None
        try:
            try:
                async with asyncio.timeout(settings.search_operation_timeout_seconds):
                    connection = await self._pool.getconn(
                        timeout=settings.search_pool_timeout_seconds
                    )
                    # The first command opens the outer transaction. The pool
                    # configures short statement deadlines and read-only work.
                    async with connection.cursor(row_factory=tuple_row) as cursor:
                        await cursor.execute(
                            "SELECT pg_try_advisory_xact_lock(%s)", (_SEARCH_WORK_LOCK_KEY,)
                        )
                        row = await cursor.fetchone()
                        if row is None or row[0] is not True:
                            raise SearchUnavailable
                    yield connection
            finally:
                if connection is not None:
                    await self._finish(connection)
        except (TimeoutError, QueryCanceled, PoolTimeout, TooManyRequests, OperationalError):
            raise SearchUnavailable from None
        finally:
            self._busy = False
