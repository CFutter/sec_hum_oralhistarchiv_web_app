"""Unit contracts for the template layer: page-route rendering wired through `app.routes.pages`, and
the Jinja environment configured by `app.template_setup`.
"""

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, call, create_autospec, sentinel

import pytest
from fastapi import Request

from app.catalogue_runtime import replace_catalogue_sources
from app.main import app as application
from app.routes import pages
from app.services import cache as cache_module
from app.services import datasets
from app.services.cache import CatalogueStatsCache, GlobalStats
from app.services.datasets import (
    SearchPage,
    get_facets,
    get_recent_datasets,
    search_catalogue_page,
)
from app.services.db import get_db_cursor
from app.template_setup import doi_url_filter, templates, utc_datetime_filter
from config import settings
from tests.fixtures import make_async_cursor, make_sample_user
from tests.source_fixtures import fixture_source

_TOTAL_DATASETS = 12
_TWO = 2

_DISPLAY_RE = re.compile(r"\d{2} \w+ \d{4}, \d{2}:\d{2} UTC")


def _stats_cache() -> MagicMock:
    """Return a strict global-statistics cache double that rejects unsupported methods."""
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
    search_connection: object | None = None,
) -> Request:
    """Build the minimal request shape consumed by the page handlers."""

    @asynccontextmanager
    async def search_scope() -> AsyncIterator[object]:
        """Yield the selected search connection or a fresh inert stand-in."""
        yield search_connection if search_connection is not None else object()

    request = cast(
        Request,
        SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db_pool=pool,
                    search_work=SimpleNamespace(connection=search_scope),
                    catalogue_stats_cache=stats_cache,
                    configured_sources=(),
                )
            ),
            state=SimpleNamespace(user=user),
        ),
    )
    replace_catalogue_sources(
        request.app, (fixture_source(name="archive", max_visibility="public"),)
    )
    return request


class TestPageRendering:
    """Home and search pages resolve the effective request tier and never
    leak another tier's data through the shared global cache."""

    def test_get_user_tier_defaults_to_public_for_guests(self) -> None:
        """Check GET user tier defaults to public for guests."""
        request = _request(pool=object(), stats_cache=_stats_cache(), user=None)

        assert pages._get_user_tier(request) == "public"

    def test_get_user_tier_uses_the_authenticated_tier(self) -> None:
        """Check GET user tier uses the authenticated tier."""
        request = _request(
            pool=object(),
            stats_cache=_stats_cache(),
            user=SimpleNamespace(id=7, access_tier="vetted"),
        )

        assert pages._get_user_tier(request) == "vetted"

    def test_home_renders_only_the_dataset_total(self) -> None:
        """Check home renders only the dataset total."""
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "app": application,
            }
        )
        request.state.user = None
        rendered = templates.get_template("home.html").render(
            request=request,
            user_tier="public",
            recent=[],
            total_datasets=_TOTAL_DATASETS,
            last_full_rebuild=None,
        )
        assert re.findall(r'<span class="stat-label">(.*?)</span>', rendered) == ["Datasets"]
        assert re.findall(r'<span class="stat-number">(.*?)</span>', rendered) == [
            str(_TOTAL_DATASETS)
        ]
        assert "Recent Additions" in rendered

    async def test_home_reads_live_total_and_tier_scoped_recent_records(self, monkeypatch) -> None:
        """A shared global cache must never retain authorization-sensitive data."""
        pool = object()
        stats_cache = _stats_cache()
        public_request = _request(pool=pool, stats_cache=stats_cache, user=None)
        registered_request = _request(
            pool=pool,
            stats_cache=stats_cache,
            user=SimpleNamespace(access_tier="registered"),
        )

        recent = create_autospec(get_recent_datasets, spec_set=True)
        recent.side_effect = [[], []]
        facets = create_autospec(get_facets, spec_set=True)
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
        template_response = create_autospec(templates.TemplateResponse, spec_set=True)
        template_response.side_effect = [sentinel.public_response, sentinel.registered_response]

        monkeypatch.setattr(pages, "get_recent_datasets", recent)
        monkeypatch.setattr(pages, "get_facets", facets)
        monkeypatch.setattr(templates, "TemplateResponse", template_response)

        public_response = await pages.home(public_request)
        registered_response = await pages.home(registered_request)

        public_policy = public_request.app.state.catalogue_policy
        registered_policy = registered_request.app.state.catalogue_policy
        assert public_response is sentinel.public_response
        assert registered_response is sentinel.registered_response
        assert recent.await_args_list == [
            call(pool, "public", configured_sources=public_policy),
            call(pool, "registered", configured_sources=registered_policy),
        ]
        facets.assert_not_awaited()

        public_context = template_response.call_args_list[0].args[2]
        registered_context = template_response.call_args_list[1].args[2]
        assert public_context["configured_sources"] is public_policy
        assert registered_context["configured_sources"] is registered_policy
        assert public_context["total_datasets"] == _TOTAL_DATASETS
        assert "total_languages" not in public_context
        assert "total_keywords" not in public_context
        assert public_context["user_tier"] == "public"
        assert registered_context["total_datasets"] == _TOTAL_DATASETS
        assert "total_languages" not in registered_context
        assert "total_keywords" not in registered_context
        assert registered_context["user_tier"] == "registered"

        assert stats_cache.get_global_stats.await_count == _TWO

    @pytest.mark.parametrize("viewer", ("public", "registered", "vetted"))
    async def test_home_query_budget_keeps_recent_rows_bounded_and_totals_live(
        self, monkeypatch, viewer
    ) -> None:
        """Run real home services: only bounded cards, freshness, and live totals."""
        pool = object()
        cache = CatalogueStatsCache(
            cast("Any", pool),
            source_names=("archive",),
            policy_fingerprint="a" * 64,
            subscribe=False,
        )
        request = _request(
            pool=pool,
            stats_cache=cast("MagicMock", cache),
            user=SimpleNamespace(access_tier=viewer),
        )
        cursor = make_async_cursor(fetchone=[(None,), (12,), (11,)])
        scopes = []
        databases = []

        @asynccontextmanager
        async def cursor_scope(_pool, user_tier, **_kwargs):
            """Record the viewer tier and pool before yielding the home-page cursor."""
            scopes.append(user_tier)
            databases.append(_pool)
            yield cursor

        @asynccontextmanager
        async def cache_scope(observed_pool):
            """Require the home-page pool before yielding the cache cursor."""
            assert observed_pool is pool
            yield cursor

        monkeypatch.setattr(
            cache_module,
            "get_db_cursor",
            create_autospec(get_db_cursor, side_effect=cache_scope),
        )

        monkeypatch.setattr(datasets, "get_catalogue_cursor", cursor_scope)
        render = create_autospec(templates.TemplateResponse, spec_set=True)
        monkeypatch.setattr(templates, "TemplateResponse", render)
        try:
            await pages.home(request)
            await pages.home(request)
        finally:
            cache.stop()

        guarded = [
            call
            for call in cursor.execute.await_args_list
            if call.args[0] == "SELECT public.catalogue_guard_search_policy(%s)"
        ]
        assert len(guarded) == 4
        assert all(
            call.args[1] == (request.app.state.catalogue_policy.fingerprint,) for call in guarded
        )
        calls = [call for call in cursor.execute.await_args_list if call not in guarded]
        assert len(calls) == 5
        assert scopes == [viewer, "public", "public", viewer, "public"]
        assert databases == [pool, cursor.connection, cursor.connection, pool, cursor.connection]
        for index in (0, 3):
            statement, params = calls[index].args
            assert "public.catalogue_page_ids(" in statement.as_string()
            assert params["limit"] == 3
            assert params["offset"] == 0
        assert "sync_status" in calls[1].args[0].as_string()
        assert calls[1].args[1] == (["archive"],)
        for index in (2, 4):
            assert calls[index].args[0].as_string().lstrip().startswith("SELECT COUNT(*) FROM")
        assert [call.args[2]["total_datasets"] for call in render.call_args_list] == [12, 11]
        for rendered in render.call_args_list:
            assert "total_languages" not in rendered.args[2]
            assert "total_keywords" not in rendered.args[2]

    async def test_search_queries_facets_for_the_current_request_tier(self, monkeypatch) -> None:
        """Suggestions and results retain the same authorized viewer tier."""
        pool = object()
        search_connection = object()
        stats_cache = _stats_cache()
        public_request = _request(
            pool=pool, stats_cache=stats_cache, user=None, search_connection=search_connection
        )
        vetted_request = _request(
            pool=pool,
            stats_cache=stats_cache,
            user=SimpleNamespace(id=7, access_tier="vetted"),
            search_connection=search_connection,
        )

        search = create_autospec(search_catalogue_page, spec_set=True)
        search.side_effect = [SearchPage([], None, 1), SearchPage([], None, 1)]
        facets = create_autospec(get_facets, spec_set=True)
        facets.side_effect = [
            {
                "access_levels": ["public"],
                "keywords": ["public-keyword"],
                "languages": ["German"],
            },
            {
                "access_levels": ["public"],
                "keywords": ["public-keyword"],
                "languages": ["German"],
            },
        ]
        template_response = create_autospec(templates.TemplateResponse, spec_set=True)
        template_response.side_effect = [sentinel.public_response, sentinel.vetted_response]

        monkeypatch.setattr(pages, "search_catalogue_page", search)
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

        public_policy = public_request.app.state.catalogue_policy
        vetted_policy = vetted_request.app.state.catalogue_policy
        assert public_response is sentinel.public_response
        assert vetted_response is sentinel.vetted_response
        assert search.await_args_list == [
            call(
                search_connection,
                "public",
                "",
                "",
                "",
                "",
                page=1,
                page_size=settings.pagination_size,
                configured_sources=public_policy,
                cursor=None,
                audience="anonymous",
            ),
            call(
                search_connection,
                "vetted",
                "",
                "",
                "",
                "",
                page=1,
                page_size=settings.pagination_size,
                configured_sources=vetted_policy,
                cursor=None,
                audience=pages._search_audience(vetted_request),
            ),
        ]
        assert facets.await_args_list == [
            call(search_connection, "public", configured_sources=public_policy, disclosures=[]),
            call(search_connection, "vetted", configured_sources=vetted_policy, disclosures=[]),
        ]

        public_context = template_response.call_args_list[0].args[2]
        vetted_context = template_response.call_args_list[1].args[2]
        assert public_context["configured_sources"] is public_policy
        assert vetted_context["configured_sources"] is vetted_policy
        assert public_context["all_keywords"] == ["public-keyword"]
        assert public_context["all_languages"] == ["German"]
        assert public_context["user_tier"] == "public"
        assert vetted_context["all_keywords"] == ["public-keyword"]
        assert vetted_context["all_languages"] == ["German"]
        assert vetted_context["user_tier"] == "vetted"

        stats_cache.get_global_stats.assert_not_awaited()


class TestAccountPageRendering:
    """Cover account page rendering."""

    def test_account_displays_actual_utc_instants(self) -> None:
        """Check account displays actual UTC instants."""
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
    """The `utc_datetime` Jinja filter registered by `app.template_setup`: render-time formatting of
    the last-rebuild timestamp.
    """

    def test_none_renders_em_dash(self) -> None:
        """No full rebuild has completed yet — the home page must not print the word 'None'."""
        assert utc_datetime_filter(None) == "—"

    def test_utc_value_matches_display_shape(self) -> None:
        """Check UTC value matches display shape."""
        out = utc_datetime_filter(datetime(2026, 3, 9, 14, 5, tzinfo=UTC))
        assert _DISPLAY_RE.fullmatch(out)
        assert out.startswith("09 ")
        assert out.endswith(" 2026, 14:05 UTC")

    def test_non_utc_value_is_converted_not_relabelled(self) -> None:
        """Check non UTC value is converted not relabelled."""
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
            ("doi:10.1/x", "https://doi.org/10.1/x"),
            ("DOI:10.1/x", "https://doi.org/10.1/x"),
            ("10.1/x", "https://doi.org/10.1/x"),
            ("https://doi.org/10.1/x", "https://doi.org/10.1/x"),
            ("javascript:alert(1)", ""),
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
