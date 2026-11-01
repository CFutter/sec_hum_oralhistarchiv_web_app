"""Real PostgreSQL search/viewer scopes restore nested state and reused sessions."""

import asyncio

import pytest
from psycopg.errors import DivisionByZero
from psycopg.rows import dict_row, tuple_row
from psycopg_pool import AsyncConnectionPool

from app.services.db import get_catalogue_search_cursor, get_db_cursor

READ_SETTINGS = """
SELECT current_setting('app.viewer_tier', true) AS viewer_tier,
       current_setting('app.search_term', true) AS search_term,
       current_setting('app.search_pattern', true) AS search_pattern,
       current_setting('app.search_mode', true) AS search_mode,
       current_setting('app.search_field_masks', true) AS search_field_masks
"""
OUTER = {
    "app.search_term": "outer oral history",
    "app.search_pattern": "%outer oral history%",
    "app.search_mode": "auto",
    "app.search_field_masks": '{"title":"public"}',
}
INNER = {
    "app.search_term": "inner interview",
    "app.search_pattern": "%inner interview%",
    "app.search_mode": "literal",
    "app.search_field_masks": '{"description":"registered"}',
}


async def read_settings(connection):
    """Read all catalogue search settings from the supplied connection."""
    async with connection.cursor(row_factory=tuple_row) as cursor:
        await cursor.execute(READ_SETTINGS)
        return await cursor.fetchone()


async def test_nested_search_success_restores_viewer_and_all_four_settings(db_pool):
    """Verify nested search success restores viewer and all four settings."""
    async with db_pool.connection() as connection:
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('app.viewer_tier', 'registered', true), "
                "set_config('app.search_term', 'previous term', true), "
                "set_config('app.search_pattern', 'previous pattern', true), "
                "set_config('app.search_mode', 'web', true), "
                "set_config('app.search_field_masks', 'previous masks', true)"
            )
            previous = await read_settings(connection)
            async with get_catalogue_search_cursor(
                connection, "vetted", OUTER, row_factory=None
            ) as outer:
                await outer.execute(READ_SETTINGS)
                assert await outer.fetchone() == ("vetted", *OUTER.values())
                async with get_catalogue_search_cursor(
                    connection, "public", INNER, row_factory=dict_row
                ) as inner:
                    await inner.execute(READ_SETTINGS)
                    assert await inner.fetchone() == {
                        "viewer_tier": "public",
                        "search_term": INNER["app.search_term"],
                        "search_pattern": INNER["app.search_pattern"],
                        "search_mode": "literal",
                        "search_field_masks": INNER["app.search_field_masks"],
                    }
                assert await read_settings(connection) == ("vetted", *OUTER.values())
            assert await read_settings(connection) == previous
        assert all(value in (None, "") for value in await read_settings(connection))


async def test_nested_sql_error_restores_every_setting_and_keeps_outer_transaction_usable(db_pool):
    """Verify nested SQL error restores every setting and keeps outer transaction usable."""
    async with db_pool.connection() as connection:
        async with get_catalogue_search_cursor(connection, "vetted", OUTER) as outer:
            with pytest.raises(DivisionByZero):
                async with get_catalogue_search_cursor(connection, "public", INNER) as inner:
                    assert await read_settings(connection) == ("public", *INNER.values())
                    await inner.execute("SELECT 1 / 0")
            assert await read_settings(connection) == ("vetted", *OUTER.values())
            await outer.execute("SELECT 1 AS usable")
            assert await outer.fetchone() == {"usable": 1}
        assert all(value in (None, "") for value in await read_settings(connection))


async def test_cancelled_search_scope_does_not_leak_viewer_or_search_into_reused_connection(
    db_pool,
):
    """Verify cancelled search scope does not leak viewer or search into reused connection."""
    pool = AsyncConnectionPool(db_pool.conninfo, min_size=1, max_size=1, open=False)
    await pool.open()
    try:
        async with get_db_cursor(pool, row_factory=None) as cursor:
            await cursor.execute("SELECT pg_backend_pid()")
            previous_pid = (await cursor.fetchone())[0]

        async def cancel_inside_scope():
            """Cancel the current task while a catalogue context is active."""
            async with get_catalogue_search_cursor(pool, "vetted", OUTER) as cursor:
                assert await read_settings(cursor.connection) == ("vetted", *OUTER.values())
                task = asyncio.current_task()
                assert task is not None
                task.cancel()
                await asyncio.sleep(0)

        task = asyncio.create_task(cancel_inside_scope())
        with pytest.raises(asyncio.CancelledError):
            await task

        async with get_db_cursor(pool, row_factory=None) as cursor:
            await cursor.execute("SELECT pg_backend_pid()")
            assert (await cursor.fetchone())[0] == previous_pid
            assert all(value in (None, "") for value in await read_settings(cursor.connection))
            await cursor.execute("SELECT 1")
            assert await cursor.fetchone() == (1,)
    finally:
        await pool.close()
