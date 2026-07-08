"""Database connection management with connection pooling.

Uses psycopg_pool.AsyncConnectionPool to reuse connections instead of opening
a new connection per request. The pool is created (unopened) via create_pool
and opened/closed by the application lifespan with `await pool.open()` /
`await pool.close()`.
"""

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from psycopg import AsyncConnection, AsyncCursor, sql
from psycopg.rows import dict_row, tuple_row
from psycopg_pool import AsyncConnectionPool, PoolTimeout
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


def create_pool(application_name: str = "oralhistarchiv-web") -> AsyncConnectionPool:
    """Create (but do not open) the async connection pool.

    The caller opens it with `await pool.open()` inside the event loop
    (the web/scheduler lifespan) and closes it with `await pool.close()`.

    Args:
        application_name: Identifier shown in pg_stat_activity, to distinguish
            web from scheduler connections. The scheduler passes
            "oralhistarchiv-scheduler" explicitly.
    """
    logger.info(
        "Creating database connection pool "
        "(max_size=%d, statement_timeout=%s, app=%s).",
        settings.database_pool_size,
        settings.db_statement_timeout,
        application_name,
    )

    async def configure(conn: AsyncConnection) -> None:
        """Apply connection-level settings to every pooled connection."""
        await conn.set_autocommit(True)
        try:
            await conn.execute(
                sql.SQL("SET application_name = {}").format(sql.Literal(application_name))
            )
            await conn.execute(
                sql.SQL("SET statement_timeout = {}").format(
                    sql.Literal(settings.db_statement_timeout)
                )
            )
        finally:
            await conn.set_autocommit(False)

    return AsyncConnectionPool(
        conninfo=settings.database_url.get_secret_value(),
        min_size=2,
        max_size=settings.database_pool_size,
        timeout=10.0,
        configure=configure,
        open=False,   # opened by the lifespan via `await pool.open()`
    )


@asynccontextmanager
async def get_db_cursor(
    pool: AsyncConnectionPool, row_factory: Any = dict_row
) -> AsyncIterator[AsyncCursor[Any]]:
    """Yield an async cursor from the pool.

    row_factory defaults to dict_row (rows as dicts). Pass tuple_row for
    positional tuple rows. row_factory=None is normalized to tuple_row, so
    the row shape never depends on any connection-level default set in
    create_pool.
    """
    factory = row_factory if row_factory is not None else tuple_row
    try:
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=factory) as cur:
                yield cur
    except PoolTimeout as e:
        logger.warning(
            "DB pool exhausted (max_size=%d, timeout=10s): %s",
            settings.database_pool_size, e,
        )
        raise