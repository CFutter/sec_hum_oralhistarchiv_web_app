"""Deep catalogue bookmarks retain identity boundaries and current disclosure rules."""

import re
from contextlib import asynccontextmanager

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from app.services import datasets
from app.services.db import get_catalogue_cursor, get_catalogue_search_cursor
from app.services.search_cursor import SearchCursorInvalid
from app.sources import FixtureConfig, configure_sources
from tests.integration import test_deployed_preflight_db

deployed_database = test_deployed_preflight_db.deployed_database


def source():
    """Build the public-floor cursor-test source with vetted-only descriptions."""
    return configure_sources(
        [
            FixtureConfig.model_validate(
                {
                    "name": "cursor_archive",
                    "display": {"label": "Cursor archive"},
                    "max_visibility": "public",
                    "field_visibility": {"description": "vetted"},
                }
            )
        ]
    )[0]


def seed_deep_tail(connection, *, tail_size=8, null_tail=False, visibility="public"):
    """Put page 100 at a tied timestamp or NULL boundary with two rows per page."""
    connection.execute(
        "INSERT INTO public.oral_history_datasets "
        "(source, uuid, title, description, keywords, languages, access_level, "
        "visibility_tier, upstream_modified_at) "
        "SELECT 'cursor_archive', 'head-' || n, 'anchor head ' || n, 'safe', "
        "ARRAY['keep'], ARRAY['English'], 'public', %s, "
        "TIMESTAMPTZ '2025-01-02 00:00:00+00' + n * INTERVAL '1 second' "
        "FROM generate_series(1, 198) AS fixture(n)",
        (visibility,),
    )
    connection.execute(
        "INSERT INTO public.oral_history_datasets "
        "(source, uuid, title, description, keywords, languages, access_level, "
        "visibility_tier, upstream_modified_at) "
        "SELECT 'cursor_archive', 'tail-' || n, 'anchor tail ' || n, 'safe', "
        "ARRAY['keep'], ARRAY['English'], 'public', %s, "
        "CASE WHEN %s THEN NULL ELSE TIMESTAMPTZ '2025-01-01 00:00:00+00' END "
        "FROM generate_series(1, %s) AS fixture(n)",
        (visibility, null_tail, tail_size),
    )
    ordered = [
        row[0]
        for row in connection.execute(
            "SELECT id FROM public.oral_history_datasets WHERE source = 'cursor_archive' "
            "ORDER BY upstream_modified_at DESC NULLS LAST, id DESC"
        ).fetchall()
    ]
    connection.commit()
    return ordered


def identifiers(page):
    """Return dataset IDs from the search page in response order."""
    return [record.id for record in page.datasets]


@pytest.mark.parametrize("number", [1, 2, 99, 100])
async def test_numbered_pages_share_the_bounded_no_count_api(
    bind_catalogue_policy, db_pool, sync_conn, number
):
    """Verify numbered pages share the bounded no count api."""
    bind_catalogue_policy((source(),))
    ordered = seed_deep_tail(sync_conn)
    result = await datasets.search_catalogue_page(
        db_pool, "public", page=number, page_size=2, configured_sources=(source(),)
    )
    assert identifiers(result) == ordered[(number - 1) * 2 : number * 2]
    assert result.page == number and result.total_count is None and result.has_next
    assert (result.next_cursor is not None) is (number == 100)
    assert result.previous_cursor is None


@pytest.mark.parametrize("null_tail", [False, True], ids=["timestamp-ties", "null-ties"])
async def test_forward_and_backward_seek_excludes_new_ids_without_duplicate_rows(
    bind_catalogue_policy, db_pool, sync_conn, null_tail
):
    """Verify forward and backward seek excludes new IDs without duplicate rows."""
    ordered = seed_deep_tail(sync_conn, null_tail=null_tail)
    selected = (source(),)
    bind_catalogue_policy(selected)
    first = await datasets.search_catalogue_page(
        db_pool, "public", page=100, page_size=2, configured_sources=selected
    )
    assert first.page == 100 and identifiers(first) == ordered[198:200]
    assert first.total_count is None and first.next_cursor
    assert first.previous_cursor is None

    # One new ID sorts before the anchor; another sorts after the non-NULL
    # anchor. NULL/tie inserts also exercise the descending-ID tiebreaker.
    inserted = sync_conn.execute(
        "INSERT INTO public.oral_history_datasets "
        "(source, uuid, title, description, access_level, visibility_tier, upstream_modified_at) "
        "VALUES ('cursor_archive', 'new-before', 'anchor new before', 'safe', 'public', "
        "'public', TIMESTAMPTZ '2030-01-01 00:00:00+00'), "
        "('cursor_archive', 'new-after', 'anchor new after', 'safe', 'public', "
        "'public', TIMESTAMPTZ '2020-01-01 00:00:00+00'), "
        "('cursor_archive', 'new-null', 'anchor new null', 'safe', 'public', 'public', NULL) "
        "RETURNING id"
    ).fetchall()
    sync_conn.commit()
    new_ids = {row[0] for row in inserted}
    second = await datasets.search_catalogue_page(
        db_pool, "public", cursor=first.next_cursor, page_size=2, configured_sources=selected
    )
    third = await datasets.search_catalogue_page(
        db_pool, "public", cursor=second.next_cursor, page_size=2, configured_sources=selected
    )
    assert second.page == 101 and identifiers(second) == ordered[200:202]
    assert third.page == 102 and identifiers(third) == ordered[202:204]
    assert second.total_count is third.total_count is None
    seen = identifiers(first) + identifiers(second) + identifiers(third)
    assert len(seen) == len(set(seen)) == 6
    assert not new_ids.intersection(seen)

    previous = await datasets.search_catalogue_page(
        db_pool, "public", cursor=third.previous_cursor, page_size=2, configured_sources=selected
    )
    boundary = await datasets.search_catalogue_page(
        db_pool, "public", cursor=previous.previous_cursor, page_size=2, configured_sources=selected
    )
    assert previous.page == 101 and identifiers(previous) == identifiers(second)
    assert boundary.page == 100 and identifiers(boundary) == identifiers(first)
    assert boundary.previous_cursor is None
    final = await datasets.search_catalogue_page(
        db_pool, "public", cursor=third.next_cursor, page_size=2, configured_sources=selected
    )
    assert final.page == 103 and identifiers(final) == ordered[204:206]
    assert final.next_cursor is None


@pytest.mark.parametrize("search_text", ["", '"anchor"'], ids=["unfiltered", "fulltext"])
async def test_only_numbered_entry_uses_bounded_offset_and_every_seek_uses_no_offset(
    bind_catalogue_policy, db_pool, sync_conn, monkeypatch, search_text
):
    """Verify only numbered entry uses bounded offset and every seek uses no offset."""
    seed_deep_tail(sync_conn)
    captured = []

    class RecordingCursor:
        """Delegate cursor operations while recording SQL for plan assertions."""

        def __init__(self, cursor):
            """Store cursor on this test double."""
            self.cursor = cursor

        def __getattr__(self, name):
            """Delegate missing attributes to the wrapped cursor."""
            return getattr(self.cursor, name)

        async def execute(self, query, params=None, **kwargs):
            """Forward SQL execution with this test's observation or injected failure."""
            statement = query if isinstance(query, str) else query.as_string(self.cursor.connection)
            if "catalogue_guard_search_policy" not in statement:
                captured.append((statement, params))
            return await self.cursor.execute(query, params, **kwargs)

    def recorder(real_scope):
        """Return the cursor-scope wrapper that records executed queries."""

        @asynccontextmanager
        async def record(*args, **kwargs):
            """Yield a real cursor wrapped to record executed SQL for plan assertions."""
            async with real_scope(*args, **kwargs) as cursor:
                yield RecordingCursor(cursor)

        return record

    monkeypatch.setattr(datasets, "get_catalogue_cursor", recorder(get_catalogue_cursor))
    monkeypatch.setattr(
        datasets, "get_catalogue_search_cursor", recorder(get_catalogue_search_cursor)
    )
    selected = (source(),)
    bind_catalogue_policy(selected)
    initial = await datasets.search_catalogue_page(
        db_pool,
        "public",
        search_text=search_text,
        page=100,
        page_size=2,
        configured_sources=selected,
    )
    assert initial.next_cursor and len(captured) == 1
    statement, parameters = captured[0]
    assert "public.catalogue_page_ids" in statement and "%(offset)s" in statement
    offset_values = [value for name, value in parameters.items() if "offset" in name.lower()]
    assert offset_values == [198]
    captured.clear()
    following = await datasets.search_catalogue_page(
        db_pool,
        "public",
        search_text=search_text,
        page_size=2,
        cursor=initial.next_cursor,
        configured_sources=selected,
    )
    assert following.previous_cursor and captured
    assert all("offset" not in parameters for _, parameters in captured)
    assert all(not re.search(r"\bOFFSET\b", statement, re.IGNORECASE) for statement, _ in captured)
    captured.clear()
    await datasets.search_catalogue_page(
        db_pool,
        "public",
        search_text=search_text,
        page_size=2,
        cursor=following.previous_cursor,
        configured_sources=selected,
    )
    assert captured
    assert all("offset" not in parameters for _, parameters in captured)
    assert all(not re.search(r"\bOFFSET\b", statement, re.IGNORECASE) for statement, _ in captured)


async def test_legacy_numbered_page_999_is_rejected_before_acquiring_database_cursor(
    db_pool, monkeypatch
):
    """Verify legacy numbered page 999 is rejected before acquiring database cursor."""

    def forbidden_cursor(*_args, **_kwargs):
        """Fail if an out-of-window page attempts to acquire a database cursor."""
        pytest.fail("an out-of-window numbered page acquired a database cursor")

    monkeypatch.setattr(datasets, "get_catalogue_cursor", forbidden_cursor)
    monkeypatch.setattr(datasets, "get_catalogue_search_cursor", forbidden_cursor)
    with pytest.raises(ValueError):
        await datasets.search_datasets(db_pool, "public", page=999, configured_sources=(source(),))


@pytest.mark.parametrize("change", ["hide", "delete", "query-ineligible"])
async def test_a_currently_ineligible_anchor_invalidates_its_bookmark(
    bind_catalogue_policy, db_pool, sync_conn, change
):
    """Verify a currently ineligible anchor invalidates its bookmark."""
    seed_deep_tail(sync_conn)
    selected = (source(),)
    bind_catalogue_policy(selected)
    initial = await datasets.search_catalogue_page(
        db_pool,
        "public",
        search_text='"anchor"',
        page=100,
        page_size=2,
        configured_sources=selected,
    )
    assert initial.next_cursor
    anchor_id = initial.datasets[-1].id
    if change == "hide":
        sync_conn.execute(
            "INSERT INTO public.dataset_admin_state (source, uuid, hidden_at) "
            "SELECT source, uuid, clock_timestamp() FROM public.oral_history_datasets WHERE id = %s",
            (anchor_id,),
        )
    elif change == "delete":
        sync_conn.execute("DELETE FROM public.oral_history_datasets WHERE id = %s", (anchor_id,))
    else:
        sync_conn.execute(
            "UPDATE public.oral_history_datasets SET title = 'unrelated', description = '' WHERE id = %s",
            (anchor_id,),
        )
    sync_conn.commit()
    with pytest.raises(SearchCursorInvalid):
        await datasets.search_catalogue_page(
            db_pool,
            "public",
            search_text='"anchor"',
            cursor=initial.next_cursor,
            page_size=2,
            configured_sources=selected,
        )


async def test_an_eligible_anchor_with_an_empty_current_tail_is_a_valid_bookmark(
    bind_catalogue_policy, db_pool, sync_conn
):
    """Verify an eligible anchor with an empty current tail is a valid bookmark."""
    ordered = seed_deep_tail(sync_conn)
    selected = (source(),)
    bind_catalogue_policy(selected)
    initial = await datasets.search_catalogue_page(
        db_pool, "public", page=100, page_size=2, configured_sources=selected
    )
    assert initial.next_cursor
    sync_conn.execute(
        "DELETE FROM public.oral_history_datasets WHERE id = ANY(%s)", (ordered[200:],)
    )
    sync_conn.commit()
    empty = await datasets.search_catalogue_page(
        db_pool, "public", cursor=initial.next_cursor, page_size=2, configured_sources=selected
    )
    assert empty.page == 101 and empty.datasets == []
    assert empty.total_count is None and empty.next_cursor is None


@pytest.mark.parametrize("viewer", ["public", "vetted"])
async def test_each_seek_rechecks_masked_negation_filters_and_hidden_rows(
    bind_catalogue_policy, db_pool, sync_conn, viewer
):
    """Verify each seek rechecks masked negation filters and hidden rows."""
    ordered = seed_deep_tail(sync_conn, tail_size=14)
    selected = (source(),)
    bind_catalogue_policy(selected)
    arguments = {
        "search_text": '"anchor" -privatecanary',
        "keyword": "keep",
        "language": "English",
        "access_level": "public",
        "page_size": 2,
        "configured_sources": selected,
    }
    initial = await datasets.search_catalogue_page(db_pool, viewer, page=100, **arguments)
    assert initial.next_cursor and identifiers(initial) == ordered[198:200]
    sync_conn.execute(
        "UPDATE public.oral_history_datasets SET description = 'privatecanary' WHERE id = %s",
        (ordered[200],),
    )
    sync_conn.execute(
        "UPDATE public.oral_history_datasets SET keywords = '{}' WHERE id = %s", (ordered[201],)
    )
    sync_conn.execute(
        "UPDATE public.oral_history_datasets SET languages = ARRAY['French'] WHERE id = %s",
        (ordered[202],),
    )
    sync_conn.execute(
        "UPDATE public.oral_history_datasets SET access_level = 'restricted' WHERE id = %s",
        (ordered[203],),
    )
    sync_conn.execute(
        "INSERT INTO public.dataset_admin_state (source, uuid, hidden_at) "
        "SELECT source, uuid, clock_timestamp() FROM public.oral_history_datasets WHERE id = %s",
        (ordered[204],),
    )
    sync_conn.commit()
    following = await datasets.search_catalogue_page(
        db_pool, viewer, cursor=initial.next_cursor, **arguments
    )
    excluded = set(ordered[201:205])
    if viewer == "vetted":
        excluded.add(ordered[200])
    remaining = [identifier for identifier in ordered[200:] if identifier not in excluded]
    assert following.page == 101 and identifiers(following) == remaining[:2]
    assert following.total_count is None
    if viewer == "public":
        assert following.datasets[0].description is None


async def test_lower_id_late_commit_can_appear_within_the_original_identity_ceiling(
    bind_catalogue_policy, db_pool, sync_conn
):
    """Verify lower ID late commit can appear within the original identity ceiling."""
    seed_deep_tail(sync_conn, tail_size=2, null_tail=True)
    selected = (source(),)
    bind_catalogue_policy(selected)
    # The display DSN omits credentials; retain authentication for this session.
    with psycopg.connect(sync_conn.info.dsn, password=sync_conn.info.password) as late:
        late_id = late.execute(
            "SELECT nextval(pg_get_serial_sequence('public.oral_history_datasets', 'id'))"
        ).fetchone()[0]
        later_ids = [
            row[0]
            for row in sync_conn.execute(
                "INSERT INTO public.oral_history_datasets "
                "(source, uuid, title, description, access_level, visibility_tier) "
                "SELECT 'cursor_archive', 'later-' || n, 'anchor later ' || n, 'safe', 'public', 'public' "
                "FROM generate_series(1, 3) AS fixture(n) RETURNING id"
            ).fetchall()
        ]
        sync_conn.commit()
        assert (
            sync_conn.execute(
                "SELECT id FROM public.oral_history_datasets WHERE id = %s", (late_id,)
            ).fetchall()
            == []
        )
        initial = await datasets.search_catalogue_page(
            db_pool, "public", page=100, page_size=2, configured_sources=selected
        )
        assert identifiers(initial) == list(reversed(later_ids[1:]))
        assert initial.total_count is None and initial.next_cursor
        # Writers serialize policy-sensitive DML. An allocated identity may
        # still be inserted later without being covered by an MVCC bookmark.
        late.execute(
            "INSERT INTO public.oral_history_datasets "
            "(id, source, uuid, title, description, access_level, visibility_tier) "
            "OVERRIDING SYSTEM VALUE "
            "VALUES (%s, 'cursor_archive', 'late-commit', 'anchor late', 'safe', 'public', 'public')",
            (late_id,),
        )
        late.commit()
        assert sync_conn.execute(
            "SELECT id FROM public.oral_history_datasets WHERE id = %s", (late_id,)
        ).fetchone() == (late_id,)
        following = await datasets.search_catalogue_page(
            db_pool, "public", cursor=initial.next_cursor, page_size=2, configured_sources=selected
        )
    assert identifiers(following) == [later_ids[0], late_id]
    assert following.total_count is None
    assert late_id < max(later_ids)
    assert not set(identifiers(initial)).intersection(identifiers(following))


@pytest.mark.parametrize("viewer", ["public", "vetted"])
async def test_actual_web_role_seeks_preserve_above_tier_discovery_and_redaction(
    bind_catalogue_policy, deployed_database, viewer
):
    """Verify actual web role seeks preserve above tier discovery and redaction."""
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        ordered = seed_deep_tail(owner, visibility="vetted")
    selected = (source(),)
    bind_catalogue_policy(selected, database_url=deployed_database["oralhistarchiv"])
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        async with pool.connection() as connection:
            assert await (
                await connection.execute(
                    "SELECT current_user, rolsuper, rolbypassrls, "
                    "pg_catalog.row_security_active('public.oral_history_datasets'::regclass) "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            ).fetchone() == ("oralhistarchiv_web", False, False, True)
        initial = await datasets.search_catalogue_page(
            pool,
            viewer,
            search_text='"anchor"',
            page=100,
            page_size=2,
            configured_sources=selected,
        )
        following = await datasets.search_catalogue_page(
            pool,
            viewer,
            search_text='"anchor"',
            cursor=initial.next_cursor,
            page_size=2,
            configured_sources=selected,
        )
    assert identifiers(initial) == ordered[198:200]
    assert identifiers(following) == ordered[200:202] and following.page == 101
    assert initial.total_count is following.total_count is None
    assert all(
        record.description == ("safe" if viewer == "vetted" else None)
        for record in following.datasets
    )
