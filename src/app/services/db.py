"""Async PostgreSQL pools and transactional cursors.

Callers open and close pools in their event loop. Database errors propagate.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from psycopg import AsyncConnection, AsyncCursor, sql
from psycopg.rows import AsyncRowFactory, dict_row, tuple_row
from psycopg_pool import AsyncConnectionPool, PoolTimeout, TooManyRequests

from config import settings

logger = logging.getLogger(__name__)

_POOL_ACQUIRE_TIMEOUT = 10.0
Database = AsyncConnectionPool | AsyncConnection


def create_pool(
    application_name: str = "oralhistarchiv-web", statement_timeout: str | None = None
) -> AsyncConnectionPool:
    """Create an unopened pool from DATABASE_URL and DATABASE_POOL_* settings.

    The caller must await open() and close(). Acquisition times out after
    10 seconds. application_name labels sessions in pg_stat_activity;
    statement_timeout is a PostgreSQL duration string, or None to use
    DB_STATEMENT_TIMEOUT. Each connection receives both settings.
    """
    timeout = statement_timeout if statement_timeout is not None else settings.db_statement_timeout
    logger.info(
        "Creating database connection pool "
        "(max_size=%d, max_waiting=%d, statement_timeout=%s, app=%s).",
        settings.database_pool_size,
        settings.database_pool_max_waiting,
        timeout,
        application_name,
    )

    async def configure(conn: AsyncConnection) -> None:
        """Apply connection-level settings to every pooled connection."""
        await conn.set_autocommit(True)
        try:
            await conn.execute(
                sql.SQL("SET application_name = {}").format(sql.Literal(application_name))
            )
            await conn.execute(sql.SQL("SET statement_timeout = {}").format(sql.Literal(timeout)))
        finally:
            await conn.set_autocommit(False)

    return AsyncConnectionPool(
        conninfo=settings.database_url.get_secret_value(),
        min_size=min(2, settings.database_pool_size),
        max_size=settings.database_pool_size,
        max_waiting=settings.database_pool_max_waiting,
        timeout=_POOL_ACQUIRE_TIMEOUT,
        configure=configure,
        open=False,  # opened by the lifespan via `await pool.open()`
    )


@asynccontextmanager
async def get_db_cursor(
    pool: Database, row_factory: AsyncRowFactory[Any] | None = dict_row
) -> AsyncIterator[AsyncCursor[Any]]:
    """Yield a cursor in a transaction; commit on success and roll back on error.

    Accepts a pool or an existing connection; the latter uses a transaction
    or nested savepoint without acquiring another session. None selects
    tuple rows; the default selects dictionaries. Pool admission failures
    are logged and re-raised; other database errors also propagate.
    """
    factory = row_factory if row_factory is not None else tuple_row
    if isinstance(pool, AsyncConnection):
        # Sync uses its advisory-lock-owning session for every transaction.
        # Losing that session fences writes: never acquire a replacement here.
        async with pool.transaction(), pool.cursor(row_factory=factory) as cur:
            yield cur
        return
    try:
        async with pool.connection() as conn, conn.cursor(row_factory=factory) as cur:
            yield cur
    except (PoolTimeout, TooManyRequests) as error:
        logger.warning(
            "Database pool admission rejected "
            "(max_size=%d, max_waiting=%d, timeout=%.0fs, reason=%s)",
            settings.database_pool_size,
            settings.database_pool_max_waiting,
            _POOL_ACQUIRE_TIMEOUT,
            type(error).__name__,
        )
        raise
