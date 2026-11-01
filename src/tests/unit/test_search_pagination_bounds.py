"""Public pagination APIs reject invalid bounds and bookmarks before acquiring SQL."""

import re
from contextlib import asynccontextmanager
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from app.services import datasets
from app.services.search_cursor import SearchCursorInvalid
from tests.fixtures import make_async_cursor, make_mock_pool
from tests.source_fixtures import legacy_source

_SOURCES = (legacy_source(name="test_source", max_visibility="public"),)


@pytest.fixture
def catalogue_scope(monkeypatch):
    """Install scripted plain/search catalogue scopes for pagination and return their observations."""
    state = SimpleNamespace(
        pool=make_mock_pool(),
        cursor=make_async_cursor(
            fetchall=[{"id": None, "ceiling_id": 0, "anchor_valid": True}],
            fetchone=[("0",), (0,)],
        ),
    )

    @asynccontextmanager
    async def plain(pool, _viewer_tier, **_kwargs):
        """Require the configured pool and yield the scripted pagination cursor."""
        assert pool is state.pool
        yield state.cursor

    @asynccontextmanager
    async def search(pool, _viewer_tier, _search_context, **_kwargs):
        """Require the configured pool and yield the scripted pagination cursor."""
        assert pool is state.pool
        yield state.cursor

    state.plain = create_autospec(datasets.get_catalogue_cursor, side_effect=plain)
    state.search = create_autospec(datasets.get_catalogue_search_cursor, side_effect=search)
    monkeypatch.setattr(datasets, "get_catalogue_cursor", state.plain)
    monkeypatch.setattr(datasets, "get_catalogue_search_cursor", state.search)
    return state


def page_rows(*identifiers):
    """Build public dataset rows with a ceiling of 100 and a valid anchor flag."""
    rows = []
    for dataset_id in identifiers:
        row = asdict(
            datasets.Dataset(
                id=dataset_id,
                uuid=f"bookmark-{dataset_id}",
                title="Interview",
                source="test_source",
                visibility_tier="public",
            )
        )
        row.update(ceiling_id=100, anchor_valid=True)
        rows.append(row)
    return rows


@pytest.mark.parametrize("page", [-1, 0, 101, 10000, True, False, 1.0, "1", None])
async def test_numbered_search_rejects_invalid_page_before_sql(catalogue_scope, page):
    """Check numbered search rejects invalid page before SQL (ValueError)."""
    with pytest.raises(ValueError, match="Numbered search page"):
        await datasets.search_datasets(
            catalogue_scope.pool, "public", page=page, configured_sources=_SOURCES
        )
    catalogue_scope.plain.assert_not_called()
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("page", [1, 100])
async def test_numbered_search_accepts_both_window_boundaries(catalogue_scope, page):
    """Check numbered search accepts both window boundaries."""
    catalogue_scope.cursor.fetchall.return_value = []
    assert await datasets.search_datasets(
        catalogue_scope.pool, "public", page=page, configured_sources=_SOURCES
    ) == ([], 0)
    assert catalogue_scope.plain.called
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("page", [-1, 0, 101, True, 100.0, "100", None])
async def test_page_api_rejects_out_of_window_numbered_page_before_sql(catalogue_scope, page):
    """Check page API rejects out of window numbered page before SQL (ValueError)."""
    with pytest.raises(ValueError, match="Numbered search page"):
        await datasets.search_catalogue_page(
            catalogue_scope.pool, "public", page=page, configured_sources=_SOURCES
        )
    catalogue_scope.plain.assert_not_called()
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("page_size", [-1, 0, 101, True, False, 1.0, "20", None])
async def test_bookmark_search_rejects_invalid_page_size_before_sql(catalogue_scope, page_size):
    """Check bookmark search rejects invalid page size before SQL (ValueError)."""
    with pytest.raises(ValueError, match="Search page size"):
        await datasets.search_catalogue_page(
            catalogue_scope.pool, "public", page_size=page_size, configured_sources=_SOURCES
        )
    catalogue_scope.plain.assert_not_called()
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("page_size", [1, 100])
async def test_bookmark_entry_accepts_both_page_size_boundaries(catalogue_scope, page_size):
    """Check bookmark entry accepts both page size boundaries."""
    result = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        page=100,
        page_size=page_size,
        configured_sources=_SOURCES,
    )
    assert isinstance(result, datasets.SearchPage)
    assert result.page == 100
    assert result.datasets == []
    assert result.total_count is None
    assert result.next_cursor is None
    assert result.previous_cursor is None
    catalogue_scope.plain.assert_called_once_with(catalogue_scope.pool, "public")
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("cursor", ["", "not-a-bookmark", "x" * 2049])
async def test_invalid_bookmark_is_rejected_before_sql(catalogue_scope, cursor):
    """Check invalid bookmark is rejected before SQL (SearchCursorInvalid)."""
    with pytest.raises(SearchCursorInvalid, match="Search bookmark is no longer valid"):
        await datasets.search_catalogue_page(
            catalogue_scope.pool, "public", cursor=cursor, configured_sources=_SOURCES
        )
    catalogue_scope.plain.assert_not_called()
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize(
    "changed",
    [
        {"search_text": "history"},
        {"keyword": "interview"},
        {"language": "English"},
        {"access_level": "restricted"},
        {"user_tier": "registered"},
        {"audience": "another-session"},
        {"page_size": 2},
        {"configured_sources": ()},
    ],
)
async def test_bookmark_context_changes_are_rejected_before_another_sql_scope(
    catalogue_scope, changed
):
    """Check bookmark context changes are rejected before another SQL scope (SearchCursorInvalid)."""
    rows = []
    for dataset_id in (40, 39):
        row = asdict(
            datasets.Dataset(
                id=dataset_id,
                uuid=f"bookmark-{dataset_id}",
                title="Interview",
                source="test_source",
                visibility_tier="public",
            )
        )
        row.update(ceiling_id=100, anchor_valid=True)
        rows.append(row)
    catalogue_scope.cursor.fetchall.return_value = rows
    first = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        page=100,
        page_size=1,
        audience="original-session",
        configured_sources=_SOURCES,
    )
    assert first.next_cursor is not None
    catalogue_scope.plain.assert_called_once_with(catalogue_scope.pool, "public")
    options = {
        "user_tier": "public",
        "page_size": 1,
        "audience": "original-session",
        "configured_sources": _SOURCES,
        **changed,
    }
    with pytest.raises(SearchCursorInvalid, match="Search bookmark is no longer valid"):
        await datasets.search_catalogue_page(
            catalogue_scope.pool, cursor=first.next_cursor, **options
        )
    catalogue_scope.plain.assert_called_once_with(catalogue_scope.pool, "public")
    catalogue_scope.search.assert_not_called()


@pytest.mark.parametrize("search_text", ["history", '"oral history"'])
async def test_bookmark_nonempty_search_uses_the_bound_search_scope(catalogue_scope, search_text):
    """Check bookmark nonempty search uses the bound search scope."""
    result = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        search_text=search_text,
        configured_sources=_SOURCES,
    )
    assert result.datasets == []
    catalogue_scope.plain.assert_not_called()
    catalogue_scope.search.assert_called_once()
    args = catalogue_scope.search.call_args.args
    assert args[:2] == (catalogue_scope.pool, "public")
    assert args[2]["app.search_term"] == search_text
    assert set(args[2]) == {
        "app.search_term",
        "app.search_pattern",
        "app.search_mode",
        "app.search_field_masks",
    }


@pytest.mark.parametrize("page", [1, 2, 99, 100])
async def test_page_api_binds_complete_sql_context_and_uses_bounded_numbered_offsets(
    catalogue_scope, monkeypatch, page
):
    """Check page API binds complete SQL context and uses bounded numbered offsets."""

    def no_count(*_args, **_kwargs):
        """Fail if ordinary pagination requests an exact result count."""
        pytest.fail("ordinary page navigation requested an exact count")

    monkeypatch.setattr(datasets, "count_search_datasets", no_count)
    catalogue_scope.cursor.fetchall.return_value = page_rows(40, 39, 38)
    result = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        keyword="interview",
        page=page,
        page_size=2,
        configured_sources=_SOURCES,
    )
    statement, parameters = catalogue_scope.cursor.execute.call_args.args
    rendered = statement.as_string()
    placeholders = set(re.findall(r"%\((\w+)\)s", rendered))
    assert placeholders <= parameters.keys()
    assert parameters["offset"] == (page - 1) * 2
    assert parameters["limit"] == 3
    assert parameters["page_query"].obj == {
        "fingerprint": datasets.build_catalogue_policy(_SOURCES).fingerprint,
        "mode": "empty",
        "term": "",
        "pattern": "%%",
        "keyword": "interview",
        "language": "",
        "access_level": "",
        "masks": {"*": 0, "test_source": 63},
    }
    assert "row_number" not in rendered.lower()
    assert "count(*)" not in rendered.lower()
    assert result.page == page
    assert [record.id for record in result.datasets] == [40, 39]
    assert result.total_count is None and result.has_next
    assert (result.next_cursor is not None) is (page == 100)
    assert result.previous_cursor is None


async def test_forward_and_reverse_bookmarks_use_current_rows_and_zero_seek_offset(
    catalogue_scope,
):
    """Check forward and reverse bookmarks use current rows and zero seek offset."""
    catalogue_scope.cursor.fetchall.return_value = page_rows(40, 39, 38)
    initial = await datasets.search_catalogue_page(
        catalogue_scope.pool, "public", page=100, page_size=2, configured_sources=_SOURCES
    )
    catalogue_scope.cursor.fetchall.return_value = page_rows(38, 37, 36)
    following = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        cursor=initial.next_cursor,
        page_size=2,
        configured_sources=_SOURCES,
    )
    statement, parameters = catalogue_scope.cursor.execute.call_args.args
    assert parameters["anchor_id"] == 39
    assert parameters["ceiling_id"] == 100
    assert "offset" not in parameters
    assert not re.search(r"\bOFFSET\b", statement.as_string(), re.IGNORECASE)
    assert following.page == 101
    assert [record.id for record in following.datasets] == [38, 37]
    assert following.previous_cursor is not None
    catalogue_scope.cursor.fetchall.return_value = page_rows(39, 40, 41)
    previous = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        cursor=following.previous_cursor,
        page_size=2,
        configured_sources=_SOURCES,
    )
    assert previous.page == 100
    assert [record.id for record in previous.datasets] == [40, 39]
    assert previous.next_cursor is not None
    assert previous.previous_cursor is None
    assert previous.has_next


async def test_page_api_refuses_a_missing_bounds_carrier(catalogue_scope):
    """Check page API refuses a missing bounds carrier (RuntimeError)."""
    catalogue_scope.cursor.fetchall.return_value = []
    with pytest.raises(RuntimeError, match="returned no bounds row"):
        await datasets.search_catalogue_page(
            catalogue_scope.pool, "public", configured_sources=_SOURCES
        )


async def test_currently_ineligible_bookmark_is_refused_and_eligible_empty_tail_is_valid(
    catalogue_scope,
):
    """Check currently ineligible bookmark is refused and eligible empty tail is valid
    (SearchCursorInvalid).
    """
    catalogue_scope.cursor.fetchall.return_value = page_rows(40, 39)
    initial = await datasets.search_catalogue_page(
        catalogue_scope.pool, "public", page=100, page_size=1, configured_sources=_SOURCES
    )
    catalogue_scope.cursor.fetchall.return_value = [
        {"id": None, "ceiling_id": 100, "anchor_valid": False}
    ]
    with pytest.raises(SearchCursorInvalid):
        await datasets.search_catalogue_page(
            catalogue_scope.pool,
            "public",
            cursor=initial.next_cursor,
            page_size=1,
            configured_sources=_SOURCES,
        )
    catalogue_scope.cursor.fetchall.return_value[0]["anchor_valid"] = True
    tail = await datasets.search_catalogue_page(
        catalogue_scope.pool,
        "public",
        cursor=initial.next_cursor,
        page_size=1,
        configured_sources=_SOURCES,
    )
    assert tail.page == 101 and tail.datasets == [] and tail.total_count is None
    assert not tail.has_next and tail.next_cursor is None


@pytest.mark.parametrize("identifiers", [(40,), (40, 39)])
async def test_full_or_short_terminal_page_has_no_forward_link(catalogue_scope, identifiers):
    """Check full or short terminal page has no forward link."""
    catalogue_scope.cursor.fetchall.return_value = page_rows(*identifiers)
    result = await datasets.search_catalogue_page(
        catalogue_scope.pool, "public", page=100, page_size=2, configured_sources=_SOURCES
    )
    assert not result.has_next and result.next_cursor is None
