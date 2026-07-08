"""§7.2 — get_db_cursor row-factory normalization (real pool).

Guards: `row_factory=None` is normalized to tuple_row inside get_db_cursor,
severing the hidden dependency on create_pool setting no connection-level
factory. The dict_row-pool test is the real regression guard: it simulates
the "default connections to dict rows in create_pool" refactor the finding
feared, and pins that explicit `row_factory=None` still yields tuples.
"""
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app.services.db import get_db_cursor

from .conftest import TEST_DATABASE_URL


async def test_default_yields_dict_rows(db_pool):
    async with get_db_cursor(db_pool) as cur:
        await cur.execute("SELECT 1 AS one")
        row = await cur.fetchone()
    assert row == {"one": 1}
    assert row["one"] == 1


async def test_row_factory_none_yields_tuples(db_pool):
    async with get_db_cursor(db_pool, row_factory=None) as cur:
        await cur.execute("SELECT 1, 'two'")
        row = await cur.fetchone()
    assert row == (1, "two")
    assert row[0] == 1  # positional indexing works


async def test_row_factory_none_still_tuples_with_dict_row_connection_default():
    """Even if the pool's connections default to dict_row (a plausible future
    create_pool refactor), row_factory=None must STILL yield tuples — the
    normalization is per-cursor, not inherited from the connection."""
    async def configure(conn):
        conn.row_factory = dict_row

    pool = AsyncConnectionPool(
        conninfo=TEST_DATABASE_URL, min_size=1, max_size=2,
        configure=configure, open=False,
    )
    await pool.open()
    try:
        async with get_db_cursor(pool, row_factory=None) as cur:
            await cur.execute("SELECT 1, 'two'")
            row = await cur.fetchone()
        assert row == (1, "two")

        # And the connection-level default is really dict_row (the premise).
        async with pool.connection() as conn:
            cur = await conn.execute("SELECT 1 AS one")
            assert await cur.fetchone() == {"one": 1}
    finally:
        await pool.close()
