"""Real transactions isolate search capacity and release global admission safely."""

import asyncio
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import pytest
from psycopg.pq import TransactionStatus

from app.services.datasets import get_facets, get_recent_datasets, search_catalogue_page
from app.services.db import create_search_pool, get_catalogue_cursor
from app.services.search_work import SearchUnavailable, SearchWork
from app.services.sessions import get_session_user
from config import settings
from tests.source_fixtures import legacy_source

_SOURCE_ROOT = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def _search_pool():
    """Open the configured search pool and close it after the test."""
    pool = create_search_pool()
    await pool.open(wait=True)
    try:
        yield pool
    finally:
        await pool.close()


async def test_search_holds_global_admission_across_nested_catalogue_reads(db_pool):
    """Verify search holds global admission across nested catalogue reads."""
    async with _search_pool() as first, _search_pool() as second:
        first_work, second_work = SearchWork(first), SearchWork(second)
        async with first_work.connection() as connection:
            async with get_catalogue_cursor(connection, "vetted") as cursor:
                await cursor.execute("SELECT current_setting('app.viewer_tier') AS tier")
                assert (await cursor.fetchone())["tier"] == "vetted"
            # Exiting the nested catalogue savepoint must not release the
            # outer admission lock before the next (facet) read.
            with pytest.raises(SearchUnavailable):
                async with second_work.connection():
                    pytest.fail("A concurrent search acquired the global slot")
            async with get_catalogue_cursor(connection, "public") as cursor:
                await cursor.execute("SELECT current_setting('app.viewer_tier') AS tier")
                assert (await cursor.fetchone())["tier"] == "public"
            async with db_pool.connection() as ordinary:
                row = await (await ordinary.execute("SELECT 1")).fetchone()
                assert row == (1,)
                assert ordinary.info.backend_pid != connection.info.backend_pid
        async with second_work.connection():
            pass
        async with first.connection() as clean:
            assert clean.info.transaction_status is TransactionStatus.IDLE
            assert (await (await clean.execute("SHOW transaction_read_only")).fetchone()) == ("on",)
            row = await (
                await clean.execute("SELECT current_setting('app.viewer_tier', true)")
            ).fetchone()
            assert row[0] in (None, "")


@pytest.mark.usefixtures("db_pool")
async def test_search_statement_timeout_returns_clean_capacity(monkeypatch):
    """Verify search statement timeout returns clean capacity."""
    monkeypatch.setattr(settings, "search_statement_timeout_ms", 30)
    async with _search_pool() as pool:
        work = SearchWork(pool)
        with pytest.raises(SearchUnavailable):
            async with work.connection() as connection:
                await connection.execute("SELECT pg_sleep(1)")
        async with work.connection() as connection:
            assert (await (await connection.execute("SELECT 1")).fetchone()) == (1,)


async def test_cancelled_search_query_stops_before_capacity_is_reused(db_pool, monkeypatch):
    """Verify cancelled search query stops before capacity is reused."""
    monkeypatch.setattr(settings, "search_statement_timeout_ms", 5000)
    monkeypatch.setattr(settings, "search_operation_timeout_seconds", 10.0)
    async with _search_pool() as pool:
        work = SearchWork(pool)
        started = asyncio.Event()
        backend_pid = 0

        async def running():
            """Hold an admitted search connection in a ten-second PostgreSQL sleep."""
            nonlocal backend_pid
            async with work.connection() as connection:
                backend_pid = connection.info.backend_pid
                started.set()
                await connection.execute("SELECT pg_sleep(10)")

        task = asyncio.create_task(running())
        try:
            async with asyncio.timeout(2.0):
                await started.wait()
                async with db_pool.connection() as observer:
                    # A fresh snapshot on every poll is necessary: PostgreSQL
                    # caches activity information within an observer transaction.
                    await observer.set_autocommit(True)
                    try:
                        while True:
                            row = await (
                                await observer.execute(
                                    "SELECT state, wait_event FROM pg_stat_activity WHERE pid = %s",
                                    (backend_pid,),
                                )
                            ).fetchone()
                            if row == ("active", "PgSleep"):
                                break
                            await asyncio.sleep(0.01)
                    finally:
                        await observer.set_autocommit(False)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        async with db_pool.connection() as observer:
            row = await (
                await observer.execute(
                    "SELECT state, xact_start FROM pg_stat_activity WHERE pid = %s", (backend_pid,)
                )
            ).fetchone()
            assert row is None or (row[0] == "idle" and row[1] is None)
        async with work.connection():
            pass


@pytest.mark.usefixtures("db_pool")
async def test_an_independent_process_cannot_take_a_live_search_slot(monkeypatch):
    """Separate interpreter state cannot reset the database-wide search budget."""
    monkeypatch.setattr(settings, "search_operation_timeout_seconds", 5.0)
    script = """
'''Report whether this process can acquire a shared search slot.'''
import asyncio
from app.services.db import create_search_pool
from app.services.search_work import SearchUnavailable, SearchWork

async def main():
    '''Print ACQUIRED/REFUSED for shared admission, then close the local pool.'''
    pool = create_search_pool()
    await pool.open(wait=True)
    try:
        try:
            async with SearchWork(pool).connection():
                print('ACQUIRED', flush=True)
        except SearchUnavailable:
            print('REFUSED', flush=True)
    finally:
        await pool.close()

asyncio.run(main())
"""
    environment = dict(os.environ, PYTHONPATH=str(_SOURCE_ROOT))
    async with _search_pool() as pool, SearchWork(pool).connection():
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=4.0)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == 0, stderr.decode()
        assert stdout.decode().strip().endswith("REFUSED")


async def test_four_search_pools_leave_session_and_home_queries_responsive(
    bind_catalogue_policy, db_pool, sync_conn, user_factory, session_factory
):
    """Exercise broad queries through independent pools while ordinary work runs.

    This is a deterministic integration regression, not a production load/SLO
    qualification; the latter must also include the deployed early admission.
    """
    source = legacy_source()
    bind_catalogue_policy((source,))
    sync_conn.execute(
        """INSERT INTO oral_history_datasets
               (source, uuid, title, description, keywords, languages, visibility_tier)
           SELECT %s, 'capacity-' || number::text,
                  'Common interview', repeat('Common oral history transcript ', 30),
                  ARRAY['common'], ARRAY['German'],
                  CASE WHEN number %% 2 = 0 THEN 'vetted' ELSE 'public' END
           FROM generate_series(1, 1200) AS number""",
        (source.name,),
    )
    sync_conn.commit()
    user = user_factory(email="search-budget@example.org")
    session = session_factory(user.id, purpose="full")
    active = 0
    maximum_active = 0
    admitted = 0
    refused = 0
    started = asyncio.Event()

    async def search_requests(work):
        """Run mixed searches while counting admitted, refused and concurrently active work."""
        nonlocal active, maximum_active, admitted, refused
        for query in ("-zzzz", "%", "!", "common OR -absent"):
            try:
                async with work.connection() as connection:
                    active += 1
                    maximum_active = max(maximum_active, active)
                    admitted += 1
                    started.set()
                    try:
                        await search_catalogue_page(
                            connection, "public", query, configured_sources=(source,)
                        )
                        await get_facets(connection, "public", configured_sources=(source,))
                    finally:
                        active -= 1
            except SearchUnavailable:
                refused += 1
            await asyncio.sleep(0)

    async with AsyncExitStack() as stack:
        pools = [await stack.enter_async_context(_search_pool()) for _ in range(4)]
        tasks = [asyncio.create_task(search_requests(SearchWork(pool))) for pool in pools]
        try:
            await asyncio.wait_for(started.wait(), timeout=2.0)
            for _ in range(4):
                async with asyncio.timeout(1.0):
                    principal = await get_session_user(db_pool, session)
                    assert principal.user is not None and principal.user.id == user.id
                    home_rows = await get_recent_datasets(
                        db_pool, "public", configured_sources=(source,)
                    )
                    assert home_rows
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    assert maximum_active == 1
    assert admitted > 0 and refused > 0
