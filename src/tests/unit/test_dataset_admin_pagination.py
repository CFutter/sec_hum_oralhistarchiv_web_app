"""Administrator browsing must never reintroduce full counts or growing offsets."""

from unittest.mock import create_autospec

import pytest

from app.services import dataset_admin_queries as queries
from tests.fixtures import FakeCursorCtx, make_async_cursor


@pytest.mark.parametrize(
    ("filters", "boundary", "order"),
    [({}, None, "DESC"), ({"after_id": 27}, 27, "DESC"), ({"before_id": 7}, 7, "ASC")],
)
async def test_each_navigation_direction_uses_one_bounded_identity_query(
    monkeypatch, filters, boundary, order
):
    """Each navigation direction uses one bounded identity query."""
    cur = make_async_cursor(fetchall=[])
    get_cursor = create_autospec(queries.get_db_cursor, return_value=FakeCursorCtx(cur))
    monkeypatch.setattr(queries, "get_db_cursor", get_cursor)
    result = await queries.search_admin_datasets(
        object(), **filters, page_size=20, configured_sources=()
    )
    assert result == queries.DatasetAdminPage([])
    cur.execute.assert_awaited_once()
    statement, params = cur.execute.await_args.args
    rendered = statement.as_string(None)
    assert "LEFT JOIN catalogue_discovery AS discovery ON discovery.id = stored.id" in rendered
    assert "discovery.title AS public_title" in rendered
    assert "oral_history_datasets" not in rendered
    assert "COUNT(" not in rendered.upper() and "OFFSET" not in rendered.upper()
    assert f"ORDER BY stored.id {order} LIMIT %(limit)s" in rendered
    assert params["limit"] == 21 and params["boundary"] == boundary
    cur.fetchall.assert_awaited_once()
    cur.fetchone.assert_not_awaited()
