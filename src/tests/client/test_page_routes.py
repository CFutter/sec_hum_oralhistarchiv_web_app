"""Catalogue and account page routes (`app.routes.pages`, `app.routes.auth.account`), as seen through the TestClient."""

from typing import Any, cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from lxml import html
from psycopg_pool import PoolTimeout, TooManyRequests

from app.routes.pages import MAX_SEARCH_PAGE
from app.services import SourceStatus
from app.services.datasets import Dataset, SearchPage
from app.sources import ConfiguredSource, FixtureConfig, SourceDisplay, configure_sources
from config import settings
from tests.fixtures import make_sample_user, replace_test_catalogue_sources
from tests.source_fixtures import TEST_SOURCE_NAME


def _make_dataset(**overrides: Any) -> Dataset:
    """Build a dataset with explicit test ownership and optional overrides."""
    values: dict[str, Any] = {
        "id": 1,
        "uuid": "uuid-0001",
        "title": "Interview",
        "source": TEST_SOURCE_NAME,
    }
    values.update(overrides)
    if "resource_proxies" not in values:
        values["resource_proxies"] = [
            {"type": kind, "ref": values[key]}
            for kind, key in (
                ("Resource", "resource_access_url"),
                ("LandingPage", "landing_page_url"),
            )
            if values.get(key) is not None
        ]
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
    """The last numbered page offers a bounded cursor continuation."""

    def test_last_search_page_discloses_window_and_has_no_unservable_next(self, guest_client):
        """Page 100 can continue without linking to an unsigned deeper page."""
        with (
            patch(
                "app.routes.pages.search_catalogue_page",
                autospec=True,
                return_value=SearchPage(
                    [_make_dataset()],
                    None,
                    MAX_SEARCH_PAGE,
                    "opaque-next",
                ),
            ),
            patch("app.routes.pages.templates.TemplateResponse", autospec=True) as render,
            patch("app.routes.pages.get_facets", autospec=True, return_value={}),
        ):
            from fastapi import Response  # noqa: PLC0415

            render.return_value = Response()
            assert guest_client.get(f"/search?page={MAX_SEARCH_PAGE}").status_code == 200
        context = render.call_args.args[2]
        assert context["total_pages"] is None
        assert context["result_count"] is None
        assert context["next_page_url"] == "/search?cursor=opaque-next"
        assert context["previous_page_url"] == "/search?page=99"


@pytest.mark.parametrize("is_admin", [False, True])
def test_catalogue_detail_links_to_visibility_controls_only_for_admins(client_builder, is_admin):
    """Check catalogue detail links to visibility controls only for admins (HTTP 200)."""
    client = client_builder(session_user=make_sample_user(is_admin=is_admin, access_tier="public"))
    with patch(
        "app.routes.pages.get_dataset_by_id",
        autospec=True,
        return_value=_make_dataset(visibility_tier="vetted"),
    ) as lookup:
        response = client.get("/dataset/1")
    assert response.status_code == 200
    assert lookup.await_args.args[2] == "public"
    links = html.fromstring(response.text).xpath(
        '//a[@href="/admin/datasets/1" and normalize-space(.)="Manage visibility"]'
    )
    assert bool(links) is is_admin


class TestDatasetKeywordLinks:
    """Link routeable keywords; retain oversized labels as plain text."""

    @pytest.mark.parametrize(
        "length",
        [101, 256],
        ids=["moderately_long_keyword", "keyword_at_the_facet_label_limit"],
    )
    def test_generated_long_keyword_link_round_trips_through_router(self, guest_client, length):
        """Require a 256-character keyword link to preserve its exact value through search routing."""
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
                "app.routes.pages.search_catalogue_page",
                autospec=True,
                return_value=SearchPage([], None, 1),
            ) as search,
            patch("app.routes.pages.get_facets", autospec=True, return_value={}),
        ):
            response = guest_client.get(link)
        assert response.status_code == 200
        assert search.await_args.args[3] == keyword

    def test_oversized_legacy_keyword_remains_visible_without_broken_link(self, guest_client):
        """Render an oversized legacy keyword without a search link the router would reject."""
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


class TestDatasetSourceDisplay:
    """Source presentation follows configuration without changing metadata tiers."""

    @staticmethod
    def _source(display: SourceDisplay | None = None) -> ConfiguredSource:
        """Build a public offline source with optional display-label overrides."""
        return configure_sources(
            (
                FixtureConfig(
                    name="offline_archive",
                    max_visibility="public",
                    log_resource_access=False,
                    display=display
                    or SourceDisplay(
                        label="Community archive",
                        resource_link_label="Request interview access",
                        landing_link_label="Read catalogue entry",
                    ),
                ),
            )
        )[0]

    @pytest.mark.parametrize(
        ("resource_url", "expected_url", "expected_label"),
        [
            (
                "https://records.example.edu/resource",
                "https://records.example.edu/resource",
                "Request interview access",
            ),
            (None, "https://records.example.edu/record", "Read catalogue entry"),
        ],
        ids=["resource-precedes-landing", "landing-fallback"],
    )
    def test_configured_fixture_source_uses_its_labels_and_link_precedence(
        self, guest_client, monkeypatch, resource_url, expected_url, expected_label
    ):
        """Check configured fixture source uses its labels and link precedence (HTTP 200)."""
        source = self._source()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, (source,))
        dataset = _make_dataset(
            source=source.name,
            visibility_tier="public",
            resource_access_url=resource_url,
            landing_page_url="https://records.example.edu/record",
        )
        with patch("app.routes.pages.get_dataset_by_id", autospec=True, return_value=dataset):
            response = guest_client.get("/dataset/1")

        assert response.status_code == 200
        tree = html.fromstring(response.text)
        source_text = tree.xpath(
            "string(//dt[normalize-space()='Source']/following-sibling::dd[1])"
        )
        assert source_text.strip() == source.display.label
        links = tree.xpath("//a[@href=$href]", href=expected_url)
        assert len(links) == 1
        assert links[0].text_content().strip() == expected_label
        assert links[0].get("target") == "_blank"
        assert "noopener" in links[0].get("rel", "").split()
        if resource_url is not None:
            assert "https://records.example.edu/record" not in tree.xpath("//a/@href")

    @pytest.mark.parametrize(
        ("resource_url", "expected_url", "expected_label"),
        [
            (
                "https://retained.example.edu/resource",
                "https://retained.example.edu/resource",
                "Open resource",
            ),
            (None, "https://retained.example.edu/record", "View source record"),
        ],
        ids=["retained-resource", "retained-landing"],
    )
    def test_unconfigured_retained_source_uses_its_identity_and_audited_links(
        self, client_builder, resource_url, expected_url, expected_label
    ):
        """Check unconfigured retained source uses its identity and audited links (HTTP 200)."""
        source = self._source()
        client = client_builder(
            session_user=make_sample_user(access_tier="vetted"),
            configured_sources=(source,),
        )
        dataset = _make_dataset(
            source="retained_archive",
            visibility_tier="public",
            resource_access_url=resource_url,
            landing_page_url="https://retained.example.edu/record",
        )
        with patch("app.routes.pages.get_dataset_by_id", autospec=True, return_value=dataset):
            response = client.get("/dataset/1")

        assert response.status_code == 200
        tree = html.fromstring(response.text)
        source_text = tree.xpath(
            "string(//dt[normalize-space()='Source']/following-sibling::dd[1])"
        )
        assert source_text.strip() == "retained_archive"
        links = tree.xpath("//a[@href='/dataset/1/resource/0']")
        assert len(links) == 1
        assert links[0].text_content().strip() == expected_label
        assert expected_url not in response.text
        assert source.display.label not in tree.text_content()
        assert "SWISSUbase" not in tree.text_content()

    def test_source_and_action_labels_are_escaped_as_text(self, guest_client, monkeypatch):
        """Check source and action labels are escaped as text (HTTP 200)."""
        display = SourceDisplay(
            label="Archive <script>injected-source</script> & Voices",
            resource_link_label="<img data-display-injection='yes'> Open collection",
        )
        source = self._source(display)
        replace_test_catalogue_sources(monkeypatch, guest_client.app, (source,))
        resource_url = "https://records.example.edu/resource"
        dataset = _make_dataset(
            source=source.name,
            visibility_tier="public",
            resource_access_url=resource_url,
        )
        with patch("app.routes.pages.get_dataset_by_id", autospec=True, return_value=dataset):
            response = guest_client.get("/dataset/1")

        assert response.status_code == 200
        tree = html.fromstring(response.text)
        source_text = tree.xpath(
            "string(//dt[normalize-space()='Source']/following-sibling::dd[1])"
        )
        assert source_text.strip() == display.label
        assert tree.xpath("//a[@href=$href]", href=resource_url)[0].text_content().strip() == (
            display.resource_link_label
        )
        assert display.label not in response.text
        assert display.resource_link_label not in response.text
        assert not tree.xpath(
            "//script[normalize-space()='injected-source'] | //img[@data-display-injection]"
        )

    @pytest.mark.parametrize("visibility_tier", ["registered", "vetted"])
    def test_source_links_remain_hidden_below_the_metadata_tier(
        self, guest_client, monkeypatch, visibility_tier
    ):
        """Check source links remain hidden below the metadata tier (HTTP 200)."""
        source = self._source()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, (source,))
        dataset = _make_dataset(
            source=source.name,
            visibility_tier=visibility_tier,
            description="Full-only metadata",
            resource_access_url="https://records.example.edu/resource",
            landing_page_url="https://records.example.edu/record",
        )
        with patch("app.routes.pages.get_dataset_by_id", autospec=True, return_value=dataset):
            response = guest_client.get("/dataset/1")

        assert response.status_code == 200
        tree = html.fromstring(response.text)
        assert "Interview" in tree.text_content()
        assert "Restricted Dataset" in tree.text_content()
        assert "Full-only metadata" not in tree.text_content()
        assert "https://records.example.edu/resource" not in response.text
        assert "https://records.example.edu/record" not in response.text
        assert source.display.resource_link_label not in tree.text_content()
        assert source.display.landing_link_label not in tree.text_content()
        assert not tree.xpath("//dt[normalize-space()='Source']")

    def test_no_resource_urls_preserves_the_contact_fallback(self, guest_client, monkeypatch):
        """Check no resource URLs preserves the contact fallback (HTTP 200)."""
        source = self._source()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, (source,))
        dataset = _make_dataset(source=source.name, visibility_tier="public")
        with patch("app.routes.pages.get_dataset_by_id", autospec=True, return_value=dataset):
            response = guest_client.get("/dataset/1")

        assert response.status_code == 200
        tree = html.fromstring(response.text)
        assert "No online resource link is available." in tree.text_content()
        assert tree.xpath("//p[@class='download-contact']/a/@href") == [
            f"mailto:{settings.contact_email}"
        ]
        assert source.display.resource_link_label not in tree.text_content()
        assert source.display.landing_link_label not in tree.text_content()


class TestAboutConfiguredSources:
    """About projects configured display text and safe operational states."""

    @staticmethod
    def _sources() -> tuple[ConfiguredSource, ...]:
        """Build three offline sources with distinct labels and visibility policies."""
        return configure_sources(
            (
                FixtureConfig(
                    name="community_archive",
                    max_visibility="vetted",
                    display=SourceDisplay(label="Community archive"),
                ),
                FixtureConfig(
                    name="regional_archive",
                    display=SourceDisplay(
                        label="Regional interviews",
                        sensitivity_badge="Restricted collection",
                    ),
                ),
                FixtureConfig(
                    name="local_archive",
                    display=SourceDisplay(label="Local voices"),
                ),
            )
        )

    def test_configured_order_labels_and_safe_statuses_use_the_retained_selection(
        self, guest_client, monkeypatch
    ):
        """Check configured order labels and safe statuses use the retained selection (HTTP 200)."""
        sources = self._sources()
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        guest_client.source_status_spy.side_effect = None
        guest_client.source_status_spy.return_value = (
            SourceStatus(
                name=sources[0].name,
                label=sources[0].display.label,
                sensitivity_badge=sources[0].display.sensitivity_badge,
                status="active",
            ),
            SourceStatus(
                name=sources[1].name,
                label=sources[1].display.label,
                sensitivity_badge=sources[1].display.sensitivity_badge,
                status="pending",
            ),
            SourceStatus(
                name=sources[2].name,
                label=sources[2].display.label,
                sensitivity_badge=sources[2].display.sensitivity_badge,
                status="degraded",
            ),
        )

        response = guest_client.get("/about")

        assert response.status_code == 200
        document = html.fromstring(response.text)
        rows = document.xpath("//table[@class='about-table']/tbody/tr")
        assert [[cell.text_content().strip() for cell in row.xpath("./td")] for row in rows] == [
            ["Community archive", "Not specified", "Active"],
            ["Regional interviews", "Restricted collection", "Awaiting sync"],
            ["Local voices", "Not specified", "Needs attention"],
        ]
        # A source's write policy is not a sensitivity description.
        assert sources[0].policy.max_visibility == "vetted"
        assert rows[0].xpath("./td")[1].text_content().strip() == "Not specified"
        metadata = guest_client.app.state.configured_sources
        assert tuple(source.config for source in metadata) == tuple(
            source.config for source in sources
        )
        assert all(not hasattr(source, "adapter") for source in metadata)
        guest_client.source_status_spy.assert_awaited_once_with(
            guest_client.mock_pool,
            configured_sources=metadata,
        )
        assert guest_client.source_status_spy.await_args.kwargs["configured_sources"] is metadata
        guest_client.mock_pool.connection.assert_not_called()

    def test_source_labels_and_sensitivity_badges_are_escaped(self, guest_client, monkeypatch):
        """Check source labels and sensitivity badges are escaped (HTTP 200)."""
        label = "Archive <script>about-source-injection</script> & Voices"
        badge = "<img data-about-injection='yes'> Collection description"
        sources = configure_sources(
            (
                FixtureConfig(
                    name="escaped_archive",
                    display=SourceDisplay(label=label, sensitivity_badge=badge),
                ),
            )
        )
        replace_test_catalogue_sources(monkeypatch, guest_client.app, sources)
        guest_client.source_status_spy.side_effect = None
        guest_client.source_status_spy.return_value = (
            SourceStatus(
                name=sources[0].name,
                label=label,
                sensitivity_badge=badge,
                status="pending",
            ),
        )

        response = guest_client.get("/about")

        assert response.status_code == 200
        document = html.fromstring(response.text)
        cells = document.xpath("//table[@class='about-table']/tbody/tr/td")
        assert [cell.text_content().strip() for cell in cells] == [label, badge, "Awaiting sync"]
        assert label not in response.text
        assert badge not in response.text
        assert not document.xpath(
            "//script[normalize-space()='about-source-injection'] | //img[@data-about-injection]"
        )

    @pytest.mark.parametrize(
        "exception_type",
        [PoolTimeout, TooManyRequests],
        ids=["pool-timeout", "pool-queue-full"],
    )
    def test_source_status_capacity_failure_keeps_the_controlled_503(
        self, guest_client, exception_type
    ):
        """Check source status capacity failure keeps the controlled 503."""
        marker = "private-upstream-source-error-92ec"
        guest_client.source_status_spy.side_effect = exception_type(marker)

        response = guest_client.get("/about")

        assert response.status_code == 503
        assert response.text == "Service temporarily unavailable. Please try again shortly."
        assert response.headers["Retry-After"] == "5"
        assert response.headers["Cache-Control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert marker not in response.text
        guest_client.source_status_spy.assert_awaited_once_with(
            guest_client.mock_pool,
            configured_sources=guest_client.app.state.configured_sources,
        )
