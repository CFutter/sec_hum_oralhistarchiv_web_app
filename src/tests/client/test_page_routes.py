"""Catalogue and account page routes (`app.routes.pages`, `app.routes.auth.account`), as seen through the TestClient."""

from typing import Any, cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from lxml import html

from app.routes.pages import MAX_SEARCH_PAGE
from app.services.datasets import Dataset
from config import settings


def _make_dataset(**overrides: Any) -> Dataset:
    """A minimal Dataset with the fields these tests need overridden; every
    other field keeps its production default (see `app.services.datasets.Dataset`)."""
    values: dict[str, Any] = {"id": 1, "uuid": "uuid-0001", "title": "Interview"}
    values.update(overrides)
    return Dataset(**cast("Any", values))


class TestTrailingSlashHandling:
    """Routes are registered without a trailing slash, so an extra slash must 404 rather than redirect."""

    @pytest.mark.parametrize(
        "method,path",
        [("get", "/search/"), ("post", "/account/change-name/")],
        ids=["search_get_with_trailing_slash", "change_name_post_with_trailing_slash"],
    )
    def test_trailing_slash_404s_without_a_redirect(self, guest_client, method, path):
        """A path with an unregistered trailing slash 404s directly, never redirecting (and so never downgrading a request to plain HTTP)."""
        response = getattr(guest_client, method)(path, follow_redirects=False)
        assert response.status_code == 404
        assert "location" not in response.headers


class TestAccountFormSessionExpiry:
    """A form POST from a session that has expired must return the visitor to a fresh copy of the form, not to an error page."""

    def test_change_name_post_without_session_redirects_to_login_with_resubmit(self, guest_client):
        """`/account/change-name` requires a full local session; without one it redirects to the login page and flags that the form should be resubmitted after re-authentication."""
        response = guest_client.post(
            "/account/change-name",
            data={"display_name": "Changed", "csrf_token": guest_client.csrf_token},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?next=%2Faccount&resubmit=1"


class TestSearchPageBounds:
    """The search page caps how far pagination can go, regardless of how many results actually match."""

    def test_last_search_page_discloses_window_and_has_no_unservable_next(self, guest_client):
        """At the capped last page, the template is told the result window is limited and is given no further page to link to."""
        with (
            patch(
                "app.routes.pages.search_datasets",
                autospec=True,
                return_value=([object()], MAX_SEARCH_PAGE * settings.pagination_size + 1),
            ),
            patch("app.routes.pages.templates.TemplateResponse", autospec=True) as render,
            patch("app.routes.pages.get_facets", autospec=True, return_value={}),
        ):
            from fastapi import Response  # noqa: PLC0415

            render.return_value = Response()
            assert guest_client.get(f"/search?page={MAX_SEARCH_PAGE}").status_code == 200
        context = render.call_args.args[2]
        assert context["total_pages"] == MAX_SEARCH_PAGE
        assert context["result_window_limited"] is True


class TestDatasetKeywordLinks:
    """A keyword shown on the dataset detail page becomes a working link back
    into search, unless the keyword itself is too long to be a plausible
    search filter — in which case it stays visible but unlinked rather than
    producing a broken or truncated link."""

    @pytest.mark.parametrize(
        "length",
        [101, 256],
        ids=["moderately_long_keyword", "keyword_at_the_facet_label_limit"],
    )
    def test_generated_long_keyword_link_round_trips_through_router(self, guest_client, length):
        """A keyword up to and including the facet label length limit (256
        characters) is still rendered as a `?keyword=` link, and following
        that link sends the exact same keyword string to `search_datasets`."""
        keyword = "ü" * (length - 2) + "/&"
        dataset = _make_dataset(visibility_tier="public", keywords=[keyword])
        with patch(
            "app.routes.pages.get_dataset_by_id",
            autospec=True,
            return_value=dataset,
        ):
            response = guest_client.get("/dataset/1")
        assert response.status_code == 200
        links = html.fromstring(response.text).xpath('//a[contains(@href, "?keyword=")]/@href')
        link = next(
            value for value in links if parse_qs(urlsplit(value).query)["keyword"] == [keyword]
        )
        with (
            patch(
                "app.routes.pages.search_datasets",
                autospec=True,
                return_value=([], 0),
            ) as search,
            patch("app.routes.pages.get_facets", autospec=True, return_value={}),
        ):
            response = guest_client.get(link)
        assert response.status_code == 200
        assert search.await_args.args[3] == keyword

    def test_oversized_legacy_keyword_remains_visible_without_broken_link(self, guest_client):
        """A keyword beyond the facet label length limit (data ingested
        before the limit existed) still renders in the page text, but is not
        turned into a `?keyword=` link, since the router would reject that
        query and it could never resolve — this is the counterpart of the
        round-trip case above for keywords too long to route."""
        keyword = "x" * 257
        dataset = _make_dataset(visibility_tier="public", keywords=[keyword])
        with patch(
            "app.routes.pages.get_dataset_by_id",
            autospec=True,
            return_value=dataset,
        ):
            response = guest_client.get("/dataset/1")
        assert response.status_code == 200
        tree = html.fromstring(response.text)
        assert keyword in tree.text_content()
        assert not tree.xpath('//a[contains(@href, "?keyword=")]')
