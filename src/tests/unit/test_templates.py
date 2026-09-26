"""Unit contracts for the template layer: page-route rendering wired through
`app.routes.pages`, and the Jinja environment configured by
`app.template_setup`."""

import re
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, call, create_autospec, sentinel

import pytest
from fastapi import Request

from app.main import app as application
from app.routes import pages
from app.services.cache import CatalogueStatsCache, GlobalStats
from app.template_setup import doi_url_filter, templates, utc_datetime_filter
from config import settings
from tests.fixtures import make_sample_user

_TOTAL_DATASETS = 12
_TWO = 2

_DISPLAY_RE = re.compile(r"\d{2} \w+ \d{4}, \d{2}:\d{2} UTC")


def _stats_cache() -> MagicMock:
    """A global-only cache double: pages.home awaits get_global_stats() once
    for both figures together. Autospecced against the real class so a call
    to a method the class doesn't have (e.g. a reintroduced per-tier facet
    cache) fails here instead of silently succeeding on a bare MagicMock."""
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    cache.get_global_stats.return_value = GlobalStats(
        total_datasets=_TOTAL_DATASETS, last_full_rebuild=None
    )
    return cache


def _request(
    *,
    pool: object,
    stats_cache: MagicMock,
    user: object | None,
) -> Request:
    """Build the minimal request shape consumed by the page handlers."""
    return cast(
        Request,
        SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db_pool=pool,
                    catalogue_stats_cache=stats_cache,
                )
            ),
            state=SimpleNamespace(user=user),
        ),
    )


class TestPageRendering:
    """Home and search pages resolve the effective request tier and never
    leak another tier's data through the shared global cache."""

    def test_get_user_tier_defaults_to_public_for_guests(self) -> None:
        request = _request(pool=object(), stats_cache=_stats_cache(), user=None)

        assert pages._get_user_tier(request) == "public"

    def test_get_user_tier_uses_the_authenticated_tier(self) -> None:
        request = _request(
            pool=object(),
            stats_cache=_stats_cache(),
            user=SimpleNamespace(access_tier="vetted"),
        )

        assert pages._get_user_tier(request) == "vetted"

    async def test_home_queries_tier_statistics_on_every_request(self, monkeypatch) -> None:
        """A shared global cache must never retain authorization-sensitive data."""
        pool = object()
        stats_cache = _stats_cache()
        public_request = _request(pool=pool, stats_cache=stats_cache, user=None)
        registered_request = _request(
            pool=pool,
            stats_cache=stats_cache,
            user=SimpleNamespace(access_tier="registered"),
        )

        recent = create_autospec(pages.get_recent_datasets, spec_set=True)
        recent.side_effect = [[], []]
        facets = create_autospec(pages.get_facets, spec_set=True)
        facets.side_effect = [
            {
                "access_levels": ["public"],
                "keywords": ["public-keyword"],
                "languages": ["German"],
            },
            {
                "access_levels": ["public", "restricted"],
                "keywords": ["public-keyword", "registered-keyword"],
                "languages": ["German", "French"],
            },
        ]
        metadata_counts = create_autospec(pages.get_home_metadata_counts, spec_set=True)
        metadata_counts.side_effect = [(1, 1), (2, 2)]
        template_response = create_autospec(templates.TemplateResponse, spec_set=True)
        template_response.side_effect = [sentinel.public_response, sentinel.registered_response]

        monkeypatch.setattr(pages, "get_recent_datasets", recent)
        monkeypatch.setattr(pages, "get_facets", facets)
        monkeypatch.setattr(pages, "get_home_metadata_counts", metadata_counts)
        monkeypatch.setattr(templates, "TemplateResponse", template_response)

        public_response = await pages.home(public_request)
        registered_response = await pages.home(registered_request)

        assert public_response is sentinel.public_response
        assert registered_response is sentinel.registered_response
        assert recent.await_args_list == [
            call(pool, "public"),
            call(pool, "registered"),
        ]
        facets.assert_not_awaited()
        assert metadata_counts.await_args_list == [
            call(pool, "public"),
            call(pool, "registered"),
        ]

        public_context = template_response.call_args_list[0].args[2]
        registered_context = template_response.call_args_list[1].args[2]
        assert public_context["total_datasets"] == _TOTAL_DATASETS
        assert public_context["total_languages"] == 1
        assert public_context["total_keywords"] == 1
        assert public_context["user_tier"] == "public"
        assert registered_context["total_datasets"] == _TOTAL_DATASETS
        assert registered_context["total_languages"] == _TWO
        assert registered_context["total_keywords"] == _TWO
        assert registered_context["user_tier"] == "registered"

        assert stats_cache.get_global_stats.await_count == _TWO

    async def test_search_queries_facets_for_every_request_tier(self, monkeypatch) -> None:
        """Search facets must be read directly for the effective request tier."""
        pool = object()
        stats_cache = _stats_cache()
        public_request = _request(pool=pool, stats_cache=stats_cache, user=None)
        vetted_request = _request(
            pool=pool,
            stats_cache=stats_cache,
            user=SimpleNamespace(access_tier="vetted"),
        )

        search = create_autospec(pages.search_datasets, spec_set=True)
        search.side_effect = [([], 0), ([], 0)]
        facets = create_autospec(pages.get_facets, spec_set=True)
        facets.side_effect = [
            {
                "access_levels": ["public"],
                "keywords": ["public-keyword"],
                "languages": ["German"],
            },
            {
                "access_levels": ["public", "restricted"],
                "keywords": ["public-keyword", "vetted-keyword"],
                "languages": ["German", "Romansh"],
            },
        ]
        template_response = create_autospec(templates.TemplateResponse, spec_set=True)
        template_response.side_effect = [sentinel.public_response, sentinel.vetted_response]

        monkeypatch.setattr(pages, "search_datasets", search)
        monkeypatch.setattr(pages, "get_facets", facets)
        monkeypatch.setattr(templates, "TemplateResponse", template_response)

        public_response = await pages.search_page(
            public_request,
            query="",
            keyword="",
            language="",
            access_level="",
            page=1,
        )
        vetted_response = await pages.search_page(
            vetted_request,
            query="",
            keyword="",
            language="",
            access_level="",
            page=1,
        )

        assert public_response is sentinel.public_response
        assert vetted_response is sentinel.vetted_response
        assert search.await_args_list == [
            call(
                pool,
                "public",
                "",
                "",
                "",
                "",
                page=1,
                page_size=settings.pagination_size,
            ),
            call(
                pool,
                "vetted",
                "",
                "",
                "",
                "",
                page=1,
                page_size=settings.pagination_size,
            ),
        ]
        assert facets.await_args_list == [call(pool, "public"), call(pool, "vetted")]

        public_context = template_response.call_args_list[0].args[2]
        vetted_context = template_response.call_args_list[1].args[2]
        assert public_context["all_keywords"] == ["public-keyword"]
        assert public_context["all_languages"] == ["German"]
        assert public_context["user_tier"] == "public"
        assert vetted_context["all_keywords"] == ["public-keyword", "vetted-keyword"]
        assert vetted_context["all_languages"] == ["German", "Romansh"]
        assert vetted_context["user_tier"] == "vetted"

        stats_cache.get_global_stats.assert_not_awaited()


class TestAccountPageRendering:
    """`account.html` renders every stored instant in UTC, never the
    session's original wall-clock offset — the same `utc_datetime` filter
    pinned directly in `TestJinjaFilters`, exercised here through a real
    template render so a filter mis-registration on this specific template
    would also be caught."""

    def test_account_displays_actual_utc_instants(self) -> None:
        local = datetime(2026, 3, 10, 0, 5, tzinfo=timezone(timedelta(hours=2)))
        user = make_sample_user(created_at=local, last_login=local)
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/account",
                "headers": [],
                "app": application,
            }
        )
        request.state.user = user
        rendered = templates.get_template("account.html").render(request=request, user=user)
        assert "09 March 2026, 22:05 UTC" in rendered
        assert "00:05 UTC" not in rendered
        assert local.astimezone(UTC).day == 9


class TestJinjaFilters:
    """The `utc_datetime` Jinja filter registered by `app.template_setup`:
    render-time formatting of the last-rebuild timestamp.

    Pins the presentation contract that moved out of
    datasets.get_last_full_rebuild_date: the service now returns an aware
    datetime and this filter owns the display string. Complements the
    integration test, which pins only that the value is a non-None aware
    datetime.

    Locale note: %B is LC_TIME-dependent, so the month name is matched by
    shape (\\w+), never by literal text. Everything locale-independent —
    day, year, time, and the UTC conversion — is asserted exactly.
    """

    def test_none_renders_em_dash(self) -> None:
        """No full rebuild has completed yet — the home page must not print
        the word 'None'.

        Pin: the template's `| default('—')` does NOT cover this, because
        Jinja's default() substitutes only for *undefined*, not None. Every
        fresh install hits this until the first rebuild finishes.
        """
        assert utc_datetime_filter(None) == "—"

    def test_utc_value_matches_display_shape(self) -> None:
        out = utc_datetime_filter(datetime(2026, 3, 9, 14, 5, tzinfo=UTC))
        assert _DISPLAY_RE.fullmatch(out)
        assert out.startswith("09 ")
        assert out.endswith(" 2026, 14:05 UTC")

    def test_non_utc_value_is_converted_not_relabelled(self) -> None:
        """A +02:00 timestamp must render its UTC equivalent, not its wall
        clock with 'UTC' appended. psycopg returns TIMESTAMPTZ values in the
        session timezone, so the conversion is load-bearing, not
        decorative."""
        aware = datetime(2026, 3, 9, 16, 5, tzinfo=timezone(timedelta(hours=2)))
        assert utc_datetime_filter(aware).endswith(" 2026, 14:05 UTC")

    def test_registered_as_jinja_filter(self) -> None:
        """The template calls it by name; a rename here must not silently
        un-register it and fall back to Jinja's undefined-filter error at
        render."""
        assert templates.env.filters["utc_datetime"] is utc_datetime_filter

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # doi:-prefixed → prefix stripped THEN resolver added: closes the
            # doubled-prefix 404 https://doi.org/doi:10.1/x.
            ("doi:10.1/x", "https://doi.org/10.1/x"),
            # 'DOI:' uppercase — code lowercases before the startswith check.
            ("DOI:10.1/x", "https://doi.org/10.1/x"),
            # Bare DOI → resolver prefix added.
            ("10.1/x", "https://doi.org/10.1/x"),
            # Existing http(s) URL passes through unchanged.
            ("https://doi.org/10.1/x", "https://doi.org/10.1/x"),
            # XSS guard: non-http(s) scheme → empty string, never an href.
            ("javascript:alert(1)", ""),
            # Empty input → empty output.
            ("", ""),
        ],
        ids=[
            "doi-prefix-lowercase-gets-resolver",
            "doi-prefix-uppercase-gets-resolver",
            "bare-doi-gets-resolver",
            "existing-http-url-unchanged",
            "non-http-scheme-becomes-empty",
            "empty-input-becomes-empty",
        ],
    )
    def test_doi_url_filter_always_yields_an_http_href_or_empty_string(
        self, value, expected
    ) -> None:
        """`doi_url_filter` (the render-side DOI canonicalization) always
        yields an http(s) href or ''. Complements the ingest-side
        canonicalization pinned in test_record_parsing.py."""
        assert doi_url_filter(value) == expected
