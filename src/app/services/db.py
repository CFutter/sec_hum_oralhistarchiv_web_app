"""Async PostgreSQL pools and transactional cursors.

Callers open and close pools in their event loop. Database errors propagate.
"""

import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any, TypeGuard, get_args

from psycopg import AsyncConnection, AsyncCursor, sql
from psycopg.rows import AsyncRowFactory, dict_row, tuple_row
from psycopg_pool import AsyncConnectionPool, PoolTimeout, TooManyRequests

from app.duration_contract import validate_statement_timeout
from app.sources import AccessTier
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
    DB_STATEMENT_TIMEOUT. Invalid durations raise ValueError before constructing
    the pool. Each connection receives both settings.
    """
    timeout = validate_statement_timeout(
        settings.db_statement_timeout if statement_timeout is None else statement_timeout
    )
    return _create_pool(
        application_name=application_name,
        statement_timeout=timeout,
        size=settings.database_pool_size,
        max_waiting=settings.database_pool_max_waiting,
        acquire_timeout=_POOL_ACQUIRE_TIMEOUT,
    )


def create_search_pool() -> AsyncConnectionPool:
    """Create one dedicated search connection with short, independent deadlines.

    SearchWork admits one local borrower without waiting before this pool is
    touched. max_waiting=1 defensively bounds reconnection admission; zero would
    mean an unbounded queue in psycopg_pool. No account work uses this pool.
    """
    return _create_pool(
        application_name="oralhistarchiv-search",
        statement_timeout=f"{settings.search_statement_timeout_ms}ms",
        size=1,
        max_waiting=1,
        acquire_timeout=settings.search_pool_timeout_seconds,
        search_only=True,
    )


def _create_pool(
    *,
    application_name: str,
    statement_timeout: str,
    size: int,
    max_waiting: int,
    acquire_timeout: float,
    search_only: bool = False,
) -> AsyncConnectionPool:
    """Construct an unopened pool without sharing either admission queue."""
    timeout = validate_statement_timeout(statement_timeout)
    logger.info(
        "Creating database connection pool "
        "(max_size=%d, max_waiting=%d, statement_timeout=%s, app=%s).",
        size,
        max_waiting,
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
            if search_only:
                await conn.execute("SET max_parallel_workers_per_gather = 0")
                await conn.execute("SET default_transaction_read_only = on")
        finally:
            await conn.set_autocommit(False)

    return AsyncConnectionPool(
        conninfo=settings.database_url.get_secret_value(),
        min_size=min(2, size),
        max_size=size,
        max_waiting=max_waiting,
        timeout=acquire_timeout,
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


def _is_catalogue_tier(value: object) -> TypeGuard[AccessTier]:
    """Require a canonical viewer tier before a catalogue connection is acquired."""
    return type(value) is str and value in get_args(AccessTier)


@asynccontextmanager
async def get_catalogue_cursor(
    pool: Database,
    viewer_tier: AccessTier,
    row_factory: AsyncRowFactory[Any] | None = dict_row,
) -> AsyncIterator[AsyncCursor[Any]]:
    """Yield a transactional catalogue cursor with a local, nestable viewer tier.

    Restore the previous setting before a successful nested savepoint releases;
    SET LOCAL alone would otherwise persist into its outer transaction. Errors
    propagate through get_db_cursor, whose rollback restores the prior setting.
    The separate settings cursor preserves the caller's requested row factory.
    """
    if not _is_catalogue_tier(viewer_tier):
        raise ValueError("Unknown catalogue viewer tier")
    async with (
        get_db_cursor(pool, row_factory=row_factory) as cur,
        cur.connection.cursor(row_factory=tuple_row) as scope,
    ):
        await scope.execute("SELECT current_setting('app.viewer_tier', true)")
        previous = await scope.fetchone()
        if previous is None:
            raise RuntimeError("Catalogue viewer setting query returned no row")
        await scope.execute("SELECT set_config('app.viewer_tier', %s, true)", (viewer_tier,))
        yield cur
        # Exceptional exits skip this statement and roll back the underlying
        # transaction/savepoint, including its local configuration changes.
        await scope.execute("SELECT set_config('app.viewer_tier', %s, true)", (previous[0] or "",))


_SEARCH_CONTEXT_KEYS = (
    "app.search_term",
    "app.search_pattern",
    "app.search_mode",
    "app.search_field_masks",
)


@asynccontextmanager
async def get_catalogue_search_cursor(
    pool: Database,
    viewer_tier: AccessTier,
    search_context: Mapping[str, str],
    row_factory: AsyncRowFactory[Any] | None = dict_row,
) -> AsyncIterator[AsyncCursor[Any]]:
    """Scope bound search context to one nestable catalogue transaction.

    The candidate view receives only the four declared settings. Successful
    nested scopes restore every previous value; errors roll back the underlying
    transaction/savepoint, including viewer and search settings. No query text
    is interpolated into SQL or persisted on a pooled connection.
    """
    if set(search_context) != set(_SEARCH_CONTEXT_KEYS) or any(
        type(search_context[key]) is not str for key in _SEARCH_CONTEXT_KEYS
    ):
        raise ValueError("Invalid catalogue search context")
    if search_context["app.search_mode"] not in {"auto", "web", "literal"}:
        raise ValueError("Invalid catalogue search mode")
    async with (
        get_catalogue_cursor(pool, viewer_tier, row_factory=row_factory) as cur,
        cur.connection.cursor(row_factory=tuple_row) as scope,
    ):
        await scope.execute(
            "SELECT current_setting(%s, true), current_setting(%s, true), "
            "current_setting(%s, true), current_setting(%s, true)",
            _SEARCH_CONTEXT_KEYS,
        )
        previous = await scope.fetchone()
        if previous is None or len(previous) != len(_SEARCH_CONTEXT_KEYS):
            raise RuntimeError("Catalogue search settings query returned an invalid row")
        setting_sql = (
            "SELECT set_config(%s, %s, true), set_config(%s, %s, true), "
            "set_config(%s, %s, true), set_config(%s, %s, true)"
        )
        values = tuple(
            value for key in _SEARCH_CONTEXT_KEYS for value in (key, search_context[key])
        )
        await scope.execute(setting_sql, values)
        yield cur
        restored = tuple(
            value
            for key, prior in zip(_SEARCH_CONTEXT_KEYS, previous, strict=True)
            for value in (key, prior or "")
        )
        await scope.execute(setting_sql, restored)
