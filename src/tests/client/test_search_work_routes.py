"""Every rendered search keeps page and facet reads inside one owned budget."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from starlette.responses import Response

from app.services.datasets import SearchPage
from app.services.search_work import SearchUnavailable


@pytest.mark.parametrize(
    "query",
    ("", "?q=-missing", "?q=%25", "?keyword=topic", "?page=100", "?cursor=opaque"),
)
def test_all_search_modes_share_one_guarded_connection(guest_client, monkeypatch, query):
    """Check all search modes share one guarded connection (HTTP 200)."""
    connection = object()
    state = {"active": False, "entries": 0, "exits": 0}

    @asynccontextmanager
    async def scope():
        """Track entry and exit while yielding the shared search connection."""
        state["entries"] += 1
        state["active"] = True
        try:
            yield connection
        finally:
            state["active"] = False
            state["exits"] += 1

    async def page(actual_connection, *_args, **_kwargs):
        """Require the active shared connection and return one search result."""
        assert actual_connection is connection and state["active"]
        # Keep the numbered-page case rendering, so both reads are exercised.
        return SearchPage([SimpleNamespace(id=1)], None, 1)

    async def facets(actual_connection, *_args, **_kwargs):
        """Require the active shared connection and return no facets."""
        assert actual_connection is connection and state["active"]
        return {}

    monkeypatch.setattr(guest_client.app.state, "search_work", SimpleNamespace(connection=scope))
    with (
        patch("app.routes.pages.search_catalogue_page", autospec=True, side_effect=page),
        patch("app.routes.pages.get_facets", autospec=True, side_effect=facets),
        patch("app.routes.pages.templates.TemplateResponse", autospec=True) as render,
    ):

        def response(*_args, **_kwargs):
            """Require search scope exit before returning the rendered response."""
            assert not state["active"]
            return Response("search")

        render.side_effect = response
        result = guest_client.get(f"/search{query}")
    assert result.status_code == 200
    assert state == {"active": False, "entries": 1, "exits": 1}


def test_search_refusal_does_not_fall_back_to_normal_pool(guest_client, monkeypatch):
    """Check search refusal does not fall back to normal pool (HTTP 503)."""

    @asynccontextmanager
    async def refused():
        """Raise SearchUnavailable before yielding any connection."""
        raise SearchUnavailable
        yield  # pragma: no cover - context entry always refuses

    monkeypatch.setattr(guest_client.app.state, "search_work", SimpleNamespace(connection=refused))
    with (
        patch("app.routes.pages.search_catalogue_page", autospec=True) as page,
        patch("app.routes.pages.get_facets", autospec=True) as facets,
    ):
        result = guest_client.get("/search")
    assert result.status_code == 503
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["retry-after"]
    page.assert_not_awaited()
    facets.assert_not_awaited()
