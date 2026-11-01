"""Server-rendered numbered handoff, opaque navigation and stale-bookmark recovery."""

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from lxml import html

from app.routes.pages import MAX_SEARCH_PAGE
from app.services.datasets import Dataset, SearchPage
from app.services.search_cursor import SEARCH_CURSOR_MAX_LENGTH, SearchCursorInvalid
from tests.source_fixtures import TEST_SOURCE_NAME


def dataset(identifier=1):
    """Build a sample dataset with a deterministic pagination identity."""
    return Dataset(
        id=identifier, uuid=f"pagination-{identifier}", title="Interview", source=TEST_SOURCE_NAME
    )


def query_values(url):
    """Parse URL query values, retaining repeated keys as lists."""
    return parse_qs(urlsplit(url).query)


def navigation(document, kind):
    """Extract pagination links of the requested kind from rendered HTML."""
    return html.fromstring(document).xpath(f'//a[contains(@class, "pagination-{kind}")]/@href')


@pytest.mark.parametrize("page", (1, 2, 99))
def test_numbered_links_use_the_shared_no_count_page_service(guest_client, page):
    """Check numbered links use the shared no count page service (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([dataset()], None, page, has_next=True),
        ) as seek,
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get(f"/search?q=oral&page={page}&pagination=restart")
    assert response.status_code == 200
    assert seek.await_args.kwargs["page"] == page
    assert seek.await_args.kwargs["configured_sources"] is guest_client.app.state.catalogue_policy
    assert (
        guest_client.app.state.catalogue_policy.sources is guest_client.app.state.configured_sources
    )
    assert response.context["result_count"] is None
    assert response.context["total_pages"] is None
    assert "Search results" in response.text
    assert f"Page {page} of" not in response.text
    following = query_values(navigation(response.text, "next")[0])
    assert following == {"q": ["oral"], "page": [str(page + 1)]}
    if page > 1:
        assert query_values(navigation(response.text, "prev")[0])["page"] == [str(page - 1)]


def test_page_100_hands_off_to_an_opaque_url_and_keeps_numbered_previous(guest_client):
    """Check page 100 hands off to an opaque URL and keeps numbered previous (HTTP 200)."""
    result = SearchPage([dataset()], None, MAX_SEARCH_PAGE, "encrypted-next", has_next=True)
    with (
        patch("app.routes.pages.search_catalogue_page", autospec=True, return_value=result) as seek,
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get(
            "/search?q=oral&keyword=topic&language=German&access_level=public&page=100"
        )
    assert response.status_code == 200
    assert seek.await_args.kwargs["page"] == 100
    assert seek.await_args.kwargs["cursor"] is None
    assert seek.await_args.kwargs["audience"] == "anonymous"
    assert query_values(navigation(response.text, "next")[0]) == {
        "q": ["oral"],
        "keyword": ["topic"],
        "language": ["German"],
        "access_level": ["public"],
        "cursor": ["encrypted-next"],
    }
    assert query_values(navigation(response.text, "prev")[0])["page"] == ["99"]
    assert "Only the first" not in response.text


@pytest.mark.parametrize("page", (1, 99, 100))
def test_numbered_page_without_lookahead_has_no_next_link(guest_client, page):
    """Check numbered page without lookahead has no next link (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([dataset()], None, page, has_next=False),
        ),
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get("/search", params={"q": "oral", "page": page})
    assert response.status_code == 200
    assert response.context["result_count"] is None
    assert response.context["total_pages"] is None
    assert navigation(response.text, "next") == []


@pytest.mark.parametrize("page", (2, 99, 100))
def test_empty_numbered_page_restarts_without_counting_or_loading_facets(guest_client, page):
    """Check empty numbered page restarts without counting or loading facets (HTTP 303)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([], None, page),
        ),
        patch("app.routes.pages.get_facets", autospec=True) as facets,
    ):
        response = guest_client.get(
            "/search",
            params={
                "q": "oral",
                "keyword": "topic",
                "language": "German",
                "access_level": "public",
                "page": page,
            },
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert query_values(response.headers["location"]) == {
        "q": ["oral"],
        "keyword": ["topic"],
        "language": ["German"],
        "access_level": ["public"],
        "page": ["1"],
        "pagination": ["empty"],
    }
    facets.assert_not_awaited()


@pytest.mark.parametrize("page", (101, 10000, 10001))
def test_unsigned_deep_page_numbers_are_rejected_before_search(guest_client, page):
    """Check unsigned deep page numbers are rejected before search (HTTP 422)."""
    with (
        patch("app.routes.pages.search_catalogue_page", autospec=True) as seek,
    ):
        response = guest_client.get(f"/search?page={page}")
    assert response.status_code == 422
    seek.assert_not_awaited()


def test_cursor_navigation_never_turns_the_display_counter_into_a_page_parameter(guest_client):
    """Check cursor navigation never turns the display counter into a page parameter (HTTP 200)."""
    result = SearchPage([dataset()], None, 501, "next-opaque", "previous-opaque", has_next=True)
    with (
        patch("app.routes.pages.search_catalogue_page", autospec=True, return_value=result) as seek,
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get("/search?q=oral&cursor=current-opaque&pagination=restart")
    assert response.status_code == 200
    assert seek.await_args.kwargs["cursor"] == "current-opaque"
    assert query_values(navigation(response.text, "next")[0]) == {
        "q": ["oral"],
        "cursor": ["next-opaque"],
    }
    assert query_values(navigation(response.text, "prev")[0]) == {
        "q": ["oral"],
        "cursor": ["previous-opaque"],
    }
    assert "Page 501" in response.text
    assert "Start again" in response.text


def test_previous_cursor_back_to_page_100_can_return_to_numbered_page_99(guest_client):
    """Check previous cursor back to page 100 can return to numbered page 99 (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([dataset()], None, 100, "next-opaque", has_next=True),
        ),
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get("/search?q=oral&cursor=back-to-handoff")
    assert response.status_code == 200
    assert query_values(navigation(response.text, "prev")[0]) == {"q": ["oral"], "page": ["99"]}


@pytest.mark.parametrize("reason", ("expired", "changed policy", "deleted anchor", "bad signature"))
def test_invalid_or_stale_bookmark_redirects_once_with_fixed_notice(guest_client, reason):
    """Check invalid or stale bookmark redirects once with fixed notice (HTTP 303)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            side_effect=SearchCursorInvalid(reason),
        ),
        patch("app.routes.pages.get_facets", autospec=True) as facets,
    ):
        response = guest_client.get(
            "/search?q=oral&keyword=topic&language=German&access_level=public&cursor=secretbookmark&page=99",
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert query_values(response.headers["location"]) == {
        "q": ["oral"],
        "keyword": ["topic"],
        "language": ["German"],
        "access_level": ["public"],
        "page": ["1"],
        "pagination": ["restart"],
    }
    assert "secretbookmark" not in response.headers["location"]
    facets.assert_not_awaited()


def test_page_one_renders_generic_restart_notice_and_drops_it_from_links(guest_client):
    """Check page one renders generic restart notice and drops it from links (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([dataset()], None, 1, has_next=True),
        ),
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get("/search?q=oral&page=1&pagination=restart")
    assert response.status_code == 200
    notices = html.fromstring(response.text).xpath('//p[@role="status"]/text()')
    assert notices == ["This search bookmark has expired or no longer matches. Showing page 1."]
    assert "pagination" not in query_values(navigation(response.text, "next")[0])


def test_empty_eligible_cursor_tail_keeps_a_start_again_link(guest_client):
    """Check empty eligible cursor tail keeps a start again link (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([], None, 102),
        ),
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get("/search?q=oral&cursor=valid-empty-tail")
    assert response.status_code == 200
    assert response.context["result_count"] is None
    assert "No datasets found." in response.text
    assert navigation(response.text, "next") == []
    starts = html.fromstring(response.text).xpath('//a[normalize-space()="Start again"]/@href')
    assert len(starts) == 1
    assert query_values(starts[0]) == {"q": ["oral"], "page": ["1"]}
    assert "expired" not in response.text


def test_clear_filters_and_new_search_forms_do_not_reuse_a_bookmark(guest_client):
    """Check clear filters and new search forms do not reuse a bookmark (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage(
                [dataset()], None, 101, "next-opaque", "prev-opaque", has_next=True
            ),
        ),
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = guest_client.get(
            "/search?q=oral&keyword=topic&cursor=old-bookmark&pagination=restart"
        )
    assert response.status_code == 200
    doc = html.fromstring(response.text)
    clear = doc.xpath('//a[@class="filter-clear"]/@href')
    assert len(clear) == 1 and query_values(clear[0]) == {"q": ["oral"]}
    assert doc.xpath('//form//input[@name="cursor" or @name="page" or @name="pagination"]') == []


def test_oversized_cursor_is_rejected_before_the_service(guest_client):
    """Check oversized cursor is rejected before the service (HTTP 422)."""
    with patch("app.routes.pages.search_catalogue_page", autospec=True) as seek:
        response = guest_client.get(
            "/search", params={"cursor": "x" * (SEARCH_CURSOR_MAX_LENGTH + 1)}
        )
    assert response.status_code == 422
    seek.assert_not_awaited()


def test_authenticated_bookmark_audience_contains_no_raw_account_or_session_identifier(
    authenticated_client,
):
    """Check authenticated bookmark audience contains no raw account or session identifier (HTTP 200)."""
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([dataset()], None, 100),
        ) as seek,
        patch("app.routes.pages.get_facets", autospec=True, return_value={}),
    ):
        response = authenticated_client.get("/search?page=100")
    assert response.status_code == 200
    audience = seek.await_args.kwargs["audience"]
    assert len(audience) == 64
    assert all(char in "0123456789abcdef" for char in audience)
    assert audience != "anonymous"
