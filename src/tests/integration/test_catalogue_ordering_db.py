"""Owner-boundary ordering, exact filtering and separate count budgets on PostgreSQL."""

from contextlib import asynccontextmanager
from unittest.mock import create_autospec

import pytest
from psycopg import errors

from app.services import datasets
from app.services.access_tiers import tier_rank
from app.services.search_query import parse_search_query
from app.sources import FixtureConfig, configure_sources


def _sources():
    """Build the ordering source with distinct field-visibility minima."""
    return configure_sources(
        (
            FixtureConfig.model_validate(
                {
                    "name": "ordered_archive",
                    "display": {"label": "Ordering proof"},
                    "max_visibility": "public",
                    "field_visibility": {
                        "description": "vetted",
                        "keywords": "registered",
                        "languages": "vetted",
                    },
                }
            ),
        )
    )


def _context(viewer="public", term="", **filters):
    """Build an audience query context using empty defaults for unspecified filters."""
    return datasets._page_query_context(
        parse_search_query(term),
        tier_rank(viewer),
        {"keyword": "", "language": "", "access_level": "", **filters},
        _sources(),
    )


def _ids(connection, *, anchor=None, ceiling=None, backward=False, limit=2, offset=0, context=None):
    """Return matching dataset IDs in page order."""
    return [
        row[0]
        for row in connection.execute(
            "SELECT selected.id FROM public.catalogue_page_ids("
            "%s, COALESCE(%s::integer, public.catalogue_scan_ceiling()), "
            "%s, %s, %s, %s) AS selected(id)",
            (
                anchor,
                ceiling,
                backward,
                limit,
                offset,
                context if context is not None else _context(),
            ),
        ).fetchall()
    ]


@pytest.fixture(autouse=True)
def _bound_catalogue_policy(bind_catalogue_policy):
    """Bind the test's selected source policy before querying."""
    bind_catalogue_policy(_sources())


def test_null_and_nonnull_seek_ranges_are_disjoint_in_both_directions(sync_conn, dataset_factory):
    """Verify null and nonnull seek ranges are disjoint in both directions."""
    newest = dataset_factory(source="ordered_archive", upstream_modified_at="2026-01-02T00:00:00Z")
    older = dataset_factory(source="ordered_archive", upstream_modified_at="2026-01-01T00:00:00Z")
    null_lower = dataset_factory(source="ordered_archive", upstream_modified_at=None)
    null_higher = dataset_factory(source="ordered_archive", upstream_modified_at=None)
    ordered = [newest, older, null_higher, null_lower]
    assert _ids(sync_conn, limit=4) == ordered
    assert _ids(sync_conn, anchor=newest) == [older, null_higher]
    assert _ids(sync_conn, anchor=older) == [null_higher, null_lower]
    assert _ids(sync_conn, anchor=null_higher) == [null_lower]
    assert _ids(sync_conn, anchor=null_lower) == []
    assert _ids(sync_conn, anchor=null_lower, backward=True, limit=3) == [
        null_higher,
        older,
        newest,
    ]
    assert _ids(sync_conn, anchor=null_higher, backward=True) == [older, newest]
    assert _ids(sync_conn, anchor=older, backward=True) == [newest]
    assert _ids(sync_conn, offset=2) == ordered[2:]


def test_filters_and_current_eligibility_apply_before_each_branch_limit(sync_conn, dataset_factory):
    """Verify filters and current eligibility apply before each branch limit."""
    expected = dataset_factory(source="ordered_archive", title="Needle discovery")
    dataset_factory(source="ordered_archive", title="Unrelated", description="Needle")
    hidden = dataset_factory(source="ordered_archive", title="Needle hidden")
    # Bookmarks retain the ceiling from before an anchor becomes ineligible.
    ceiling = sync_conn.execute("SELECT public.catalogue_scan_ceiling()").fetchone()[0]
    assert ceiling == hidden
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) "
        "SELECT source, uuid, clock_timestamp() FROM oral_history_datasets WHERE id = %s",
        (hidden,),
    )
    assert _ids(sync_conn, limit=1, context=_context(term="Needle")) == [expected]
    assert sync_conn.execute("SELECT public.catalogue_scan_ceiling()").fetchone()[0] < hidden
    assert _ids(sync_conn, anchor=hidden, ceiling=ceiling, context=_context(term="Needle")) == []
    assert _ids(sync_conn, anchor=expected, context=_context(term="Needle")) == []


@pytest.mark.parametrize("viewer", ["public", "registered", "vetted"])
@pytest.mark.parametrize(
    ("term", "filters"),
    [
        ("", {}),
        ("oral", {}),
        ('"oral history"', {}),
        ('"oral" -hidden', {}),
        ("50%", {}),
        ("oral", {"keyword": "shared"}),
        ("oral", {"language": "English"}),
        ("", {"access_level": "restricted"}),
    ],
)
async def test_private_page_matching_agrees_with_the_separate_exact_counter(
    db_pool, sync_conn, dataset_factory, viewer, term, filters
):
    """Verify private page matching agrees with the separate exact counter."""
    for index, tier in enumerate(("public", "registered", "vetted")):
        dataset_factory(
            source="ordered_archive",
            title="oral history" if index != 1 else "50% oral",
            description="hidden oral history",
            keywords=["shared"],
            languages=["English"],
            access_level="public" if index == 0 else "restricted",
            visibility_tier=tier,
        )
    sync_conn.execute("SELECT set_config('app.viewer_tier', %s, true)", (viewer,))
    found = _ids(sync_conn, limit=100, context=_context(viewer, term, **filters))
    expected = await datasets.count_search_datasets(
        db_pool, viewer, term, configured_sources=_sources(), **filters
    )
    assert len(found) == expected


@pytest.mark.parametrize(("prior", "expected"), [("0", "2s"), ("100ms", "100ms"), ("5s", "2s")])
async def test_exact_counter_enforces_budget_and_restores_nested_settings(
    db_pool, dataset_factory, monkeypatch, prior, expected
):
    """Verify exact counter enforces budget and restores nested settings."""
    dataset_factory(source="ordered_archive")
    observed = []
    real_scope = datasets.get_catalogue_cursor

    class RecordingCursor:
        """Delegate cursor operations while recording SQL for plan assertions."""

        def __init__(self, cursor):
            """Store cursor on this test double."""
            self.cursor = cursor

        def __getattr__(self, name):
            """Delegate missing attributes to the wrapped cursor."""
            return getattr(self.cursor, name)

        async def execute(self, statement, params=None):
            """Forward SQL execution with this test's observation or injected failure."""
            if not isinstance(statement, str) and "SELECT COUNT(*)" in statement.as_string():
                async with self.cursor.connection.cursor() as observer:
                    await observer.execute("SHOW statement_timeout")
                    observed.append((await observer.fetchone())[0])
            return await self.cursor.execute(statement, params)

    @asynccontextmanager
    async def record(*args, **kwargs):
        """Yield a real cursor wrapped to record executed SQL for plan assertions."""
        async with real_scope(*args, **kwargs) as cursor:
            yield RecordingCursor(cursor)

    monkeypatch.setattr(
        datasets,
        "get_catalogue_cursor",
        create_autospec(real_scope, spec_set=True, side_effect=record),
    )
    async with db_pool.connection() as connection:
        await connection.execute("SELECT set_config('statement_timeout', %s, true)", (prior,))
        assert (
            await datasets.count_search_datasets(
                connection, "public", configured_sources=_sources()
            )
            == 1
        )
        actual = await (await connection.execute("SHOW statement_timeout")).fetchone()
        assert actual == (prior,)
    assert observed == [expected]


async def test_failed_exact_counter_rolls_back_nested_timeout_and_keeps_outer_transaction(
    db_pool, dataset_factory, monkeypatch
):
    """Verify failed exact counter rolls back nested timeout and keeps outer transaction."""
    dataset_factory(source="ordered_archive")
    real_scope = datasets.get_catalogue_cursor
    delayed = []

    class SlowCounterCursor:
        """Delegate cursor operations while delaying catalogue count queries."""

        def __init__(self, cursor):
            """Store cursor on this test double."""
            self.cursor = cursor

        def __getattr__(self, name):
            """Delegate missing attributes to the wrapped cursor."""
            return getattr(self.cursor, name)

        async def execute(self, statement, params=None):
            """Forward SQL execution with this test's observation or injected failure."""
            rendered = statement if isinstance(statement, str) else statement.as_string()
            if "SELECT COUNT(*) FROM public.catalogue_match_ids" in rendered:
                delayed.append(True)
                await self.cursor.execute("SELECT pg_catalog.pg_sleep(0.2)")
            return await self.cursor.execute(statement, params)

    @asynccontextmanager
    async def slow_count(*args, **kwargs):
        """Yield a real cursor whose count query is deliberately delayed in PostgreSQL."""
        async with real_scope(*args, **kwargs) as cursor:
            yield SlowCounterCursor(cursor)

    monkeypatch.setattr(datasets, "get_catalogue_cursor", slow_count)
    async with db_pool.connection() as connection:
        await connection.execute("SELECT set_config('statement_timeout', '5s', true)")
        with pytest.raises(errors.QueryCanceled):
            await datasets.count_search_datasets(
                connection, "public", configured_sources=_sources(), timeout_ms=10
            )
        actual = await (await connection.execute("SHOW statement_timeout")).fetchone()
        assert actual == ("5s",)
        assert await (await connection.execute("SELECT 42")).fetchone() == (42,)
    assert delayed == [True]
