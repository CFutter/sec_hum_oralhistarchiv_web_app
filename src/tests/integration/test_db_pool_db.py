"""app.services.db: pool-backed cursor row shape and transaction boundary (real pool).

get_db_cursor's row_factory defaults to dict_row and normalizes an explicit
row_factory=None to tuple_row, independent of any connection-level default
set by create_pool's configure callback. Separately, the cursor's async
context manager commits on clean exit and rolls back on exception, which is
what lets a per-record sync loop leave no partial row behind for a failed
record.
"""

import pytest
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app.services.db import get_db_cursor

from .conftest import TEST_DATABASE_URL


class TestCursorRowFactory:
    """get_db_cursor's row shape is controlled per-call, not by the pool."""

    async def test_default_yields_dict_rows(self, db_pool):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute("SELECT 1 AS one")
            row = await cur.fetchone()
        assert row == {"one": 1}
        assert row["one"] == 1

    async def test_row_factory_none_yields_tuples(self, db_pool):
        async with get_db_cursor(db_pool, row_factory=None) as cur:
            await cur.execute("SELECT 1, 'two'")
            row = await cur.fetchone()
        assert row == (1, "two")
        assert row[0] == 1  # positional indexing works

    async def test_row_factory_none_still_tuples_with_dict_row_connection_default(self):
        """Even if the pool's connections default to dict_row (a plausible
        future create_pool refactor), row_factory=None must STILL yield
        tuples — the normalization is per-cursor, not inherited from the
        connection."""

        async def configure(conn):
            conn.row_factory = dict_row

        pool = AsyncConnectionPool(
            conninfo=TEST_DATABASE_URL,
            min_size=1,
            max_size=2,
            configure=configure,
            open=False,
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


class TestCursorTransactionBoundary:
    """get_db_cursor commits a clean block and rolls back a raising one."""

    async def test_cursor_commits_on_clean_exit(self, db_pool, sync_conn):
        """Writes inside get_db_cursor persist without an explicit commit —
        the per-record sync loop relies on each cursor block committing its
        record."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "INSERT INTO oral_history_datasets (uuid, title) VALUES (%s, %s)",
                ("oai:test:commit-check", "Committed"),
            )
        row = sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE uuid = %s",
            ("oai:test:commit-check",),
        ).fetchone()
        assert row == ("Committed",)

    async def test_cursor_rolls_back_on_exception(self, db_pool, sync_conn):
        """An exception inside the block must roll the write back — this is
        what makes a failed record in the sync loop leave no partial row
        behind."""
        with pytest.raises(RuntimeError):
            async with get_db_cursor(db_pool) as cur:
                await cur.execute(
                    "INSERT INTO oral_history_datasets (uuid, title) VALUES (%s, %s)",
                    ("oai:test:rollback-check", "Doomed"),
                )
                raise RuntimeError("boom")
        row = sync_conn.execute(
            "SELECT 1 FROM oral_history_datasets WHERE uuid = %s",
            ("oai:test:rollback-check",),
        ).fetchone()
        assert row is None
