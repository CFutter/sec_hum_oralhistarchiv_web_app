"""Real PostgreSQL viewer scopes restore settings across pooled and nested use."""

import asyncio

import pytest
from psycopg.errors import DivisionByZero
from psycopg.rows import dict_row, tuple_row
from psycopg_pool import AsyncConnectionPool

from app.services import get_catalogue_cursor, get_db_cursor


async def _setting(connection):
    """Read the connection's transaction-local viewer tier."""
    async with connection.cursor(row_factory=tuple_row) as cur:
        await cur.execute("SELECT current_setting('app.viewer_tier', true)")
        return (await cur.fetchone())[0]


@pytest.mark.parametrize("row_factory", (dict_row, tuple_row, None))
async def test_catalogue_context_preserves_requested_row_factory(db_pool, row_factory):
    """Verify catalogue context preserves requested row factory."""
    async with get_catalogue_cursor(db_pool, "registered", row_factory=row_factory) as cur:
        await cur.execute("SELECT current_setting('app.viewer_tier') AS viewer_tier")
        row = await cur.fetchone()
        assert row == (
            {"viewer_tier": "registered"} if row_factory is dict_row else ("registered",)
        )


async def test_catalogue_context_does_not_leak_between_reused_pooled_sessions(db_pool):
    """Verify catalogue context does not leak between reused pooled sessions."""
    pool = AsyncConnectionPool(db_pool.conninfo, min_size=1, max_size=1, open=False)
    await pool.open()
    try:
        session_ids = set()
        for tier in ("vetted", "public", "registered", "public"):
            async with get_catalogue_cursor(pool, tier) as cur:
                await cur.execute(
                    "SELECT pg_backend_pid() AS pid, current_setting('app.viewer_tier') AS tier"
                )
                row = await cur.fetchone()
                session_ids.add(row["pid"])
                assert row["tier"] == tier
            async with get_db_cursor(pool) as cur:
                await cur.execute(
                    "SELECT pg_backend_pid() AS pid, "
                    "current_setting('app.viewer_tier', true) AS tier"
                )
                row = await cur.fetchone()
                session_ids.add(row["pid"])
                assert row["tier"] in (None, "")
        assert len(session_ids) == 1
    finally:
        await pool.close()


@pytest.mark.parametrize("invalid", (None, "unknown", "Public", True, 1, [], {}))
async def test_catalogue_context_validates_tier_before_attempting_pool_access(db_pool, invalid):
    """Verify catalogue context validates tier before attempting pool access."""
    unopened_pool = AsyncConnectionPool(db_pool.conninfo, open=False)
    with pytest.raises(ValueError, match="Unknown catalogue viewer tier"):
        async with get_catalogue_cursor(unopened_pool, invalid):
            pytest.fail("An invalid tier reached a catalogue cursor")


async def test_nested_catalogue_context_restores_the_outer_local_tier_on_success(db_pool):
    """Verify nested catalogue context restores the outer local tier on success."""
    async with db_pool.connection() as connection:
        async with connection.transaction():
            await connection.execute("SELECT set_config('app.viewer_tier', 'registered', true)")
            async with get_catalogue_cursor(connection, "vetted"):
                assert await _setting(connection) == "vetted"
                async with get_catalogue_cursor(connection, "public"):
                    assert await _setting(connection) == "public"
                assert await _setting(connection) == "vetted"
            assert await _setting(connection) == "registered"
        assert await _setting(connection) in (None, "")


@pytest.mark.parametrize("sql_error", (False, True))
async def test_nested_catalogue_context_rollback_restores_a_usable_outer_transaction(
    db_pool, sql_error
):
    """Verify nested catalogue context rollback restores a usable outer transaction."""
    async with db_pool.connection() as connection:
        async with get_catalogue_cursor(connection, "vetted"):
            expected = DivisionByZero if sql_error else RuntimeError
            with pytest.raises(expected):
                async with get_catalogue_cursor(connection, "public") as cur:
                    assert await _setting(connection) == "public"
                    if sql_error:
                        await cur.execute("SELECT 1 / 0")
                    else:
                        raise RuntimeError("Synthetic caller refusal")
            assert await _setting(connection) == "vetted"
            await connection.execute("SELECT 1")
        assert await _setting(connection) in (None, "")


async def test_cancelled_catalogue_context_rolls_back_its_local_tier(db_pool):
    """Verify cancelled catalogue context rolls back its local tier."""
    async with db_pool.connection() as connection:

        async def cancel_inside_scope():
            """Cancel the current task while a catalogue context is active."""
            async with get_catalogue_cursor(connection, "vetted"):
                assert await _setting(connection) == "vetted"
                asyncio.current_task().cancel()
                await asyncio.sleep(0)

        task = asyncio.create_task(cancel_inside_scope())
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await _setting(connection) in (None, "")
        await connection.execute("SELECT 1")
