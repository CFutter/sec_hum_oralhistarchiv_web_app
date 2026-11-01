"""Early search refusals use the shared layout without spending session/database work."""

from unittest.mock import patch

import pytest
from lxml import html

from app.main import app
from app.middleware import rate_limiting
from app.middleware.bounded_rate_limit_storage import SearchStartGate
from app.services.datasets import SearchPage
from config import settings
from tests.fixtures import make_sample_user


def _assert_styled_busy_page(response, root_path):
    """Require the complete public 503 search page and return its root-prefixed search link."""
    assert response.status_code == 503
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-store"
    assert int(response.headers["retry-after"]) > 0
    assert response.headers["x-request-id"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers.get_list("set-cookie") == []
    document = html.fromstring(response.text)
    assert document.xpath('//header[@class="site-header"]')
    assert document.xpath('//footer[@class="site-footer"]')
    assert document.xpath('//link[@rel="stylesheet"]/@href') == [
        f"{root_path}/static/css/style.css"
    ]
    section = document.xpath('//section[@class="container error-page"]')[0]
    assert section.xpath("./h1/text()") == ["Search temporarily busy"]
    assert section.xpath('./p[@class="error-message"]/text()') == [
        "Search is temporarily busy. Please wait briefly and try again."
    ]
    button = section.xpath('./a[@class="btn btn-primary"]')[0]
    assert button.text_content() == "← Back to search"
    assert button.get("href") == f"{root_path}/search"
    assert not document.xpath('//nav//a[@class="nav-link nav-auth"]')
    assert not document.xpath('//form[contains(@action, "/logout")]')
    return button.get("href")


@pytest.mark.parametrize("authenticated", [False, True])
@pytest.mark.parametrize("limits_enabled", [False, True])
@pytest.mark.parametrize("root_path", ["", "/archive"])
def test_search_busy_page_is_styled_without_resolving_identity_and_its_button_retries(
    client_builder, monkeypatch, authenticated, limits_enabled, root_path
):
    """Check search busy page is styled without resolving identity and its button retries (HTTP 200)."""
    client = client_builder(
        session_user=make_sample_user(display_name="PRIVATE-ACCOUNT-CANARY")
        if authenticated
        else None
    )
    monkeypatch.setattr(app, "root_path", root_path)
    monkeypatch.setattr(app.state.limiter, "enabled", limits_enabled)
    gate = SearchStartGate(None, rate=0.0001, burst=1)
    monkeypatch.setattr(rate_limiting, "get_search_start_gate", lambda: gate)
    assert gate.acquire()
    before = dict(client.cookies)
    client.session_spy.reset_mock()
    with (
        patch(
            "app.routes.pages.search_catalogue_page",
            autospec=True,
            return_value=SearchPage([], None, 1),
        ) as page,
        patch("app.routes.pages.get_facets", autospec=True, return_value={}) as facets,
    ):
        response = client.get(
            f"{root_path}/search?q=PRIVATE-SEARCH-CANARY&cursor=PRIVATE-BOOKMARK-CANARY"
        )
        href = _assert_styled_busy_page(response, root_path)
        for private_value in (
            "PRIVATE-ACCOUNT-CANARY",
            "PRIVATE-SEARCH-CANARY",
            "PRIVATE-BOOKMARK-CANARY",
        ):
            assert private_value not in response.text
        assert dict(client.cookies) == before
        client.session_spy.assert_not_awaited()
        page.assert_not_awaited()
        facets.assert_not_awaited()

        # Static styling remains available while search admission is exhausted.
        if not root_path:
            css = client.get("/static/css/style.css")
            assert css.status_code == 200
            assert ".error-page" in css.text
        gate.reset()
        retried = client.get(href)
        assert retried.status_code == 200
        page.assert_awaited_once()
        facets.assert_awaited_once()


def test_other_error_pages_keep_the_home_button_and_resolved_account_navigation(
    authenticated_client,
):
    """Check other error pages keep the home button and resolved account navigation (HTTP 422)."""
    response = authenticated_client.get("/dataset/not-an-integer")
    assert response.status_code == 422
    document = html.fromstring(response.text)
    button = document.xpath('//section[@class="container error-page"]/a')[0]
    assert button.get("href") == "/"
    assert button.text_content() == "← Back to home"
    assert document.xpath('//form[@action="/logout"]')
    assert settings.session_cookie_name in authenticated_client.cookies
