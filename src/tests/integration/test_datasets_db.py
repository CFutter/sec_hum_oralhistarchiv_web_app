"""Tier-scoping and ordering of `app.services.datasets` queries."""

from datetime import UTC, datetime

import pytest

from app.services.datasets import (
    FACET_OPTION_LIMIT,
    get_facets,
    get_global_catalogue_stats,
    get_last_full_rebuild_date,
    get_recent_datasets,
    get_total_dataset_count,
    search_datasets,
)
from tests.source_fixtures import legacy_source

_SOURCES = (legacy_source(max_visibility="public"),)


def _seed_three_tiers(dataset_factory):
    """Insert two datasets per tier with distinct facet markers."""
    dataset_factory(
        visibility_tier="public",
        keywords=["pub-kw"],
        languages=["German"],
        access_level="public",
    )
    dataset_factory(visibility_tier="public", keywords=["pub-kw"], access_level="public")
    dataset_factory(
        visibility_tier="registered",
        keywords=["reg-kw"],
        languages=["Italian"],
        access_level="public",
    )
    dataset_factory(visibility_tier="registered", keywords=["reg-kw"], access_level="public")
    dataset_factory(
        visibility_tier="vetted",
        keywords=["secret-kw"],
        languages=["Rumantsch"],
        access_level="restricted",
    )
    dataset_factory(visibility_tier="vetted", keywords=["secret-kw"], access_level="restricted")


@pytest.fixture(autouse=True)
def _bound_catalogue_policy(bind_catalogue_policy):
    """Bind the test's selected source policy before querying."""
    bind_catalogue_policy(_SOURCES)


class TestFacetTierScoping:
    """Facet content (keywords/languages/access levels) is tier-scoped on
    every channel `get_facets` exposes."""

    async def test_get_facets_is_tier_scoped_for_public(self, db_pool, dataset_factory):
        """The leak assertion: a public/guest actor's facets must not
        enumerate keyword or language values that exist only in
        registered- or vetted-tier datasets."""
        _seed_three_tiers(dataset_factory)

        public = await get_facets(db_pool, "public", configured_sources=_SOURCES)

        assert "secret-kw" not in public["keywords"]
        assert "reg-kw" not in public["keywords"]
        assert "Rumantsch" not in public["languages"]
        assert "Italian" not in public["languages"]
        assert "restricted" in public["access_levels"]
        # Positive control: the public tier's own values still surface.
        assert "pub-kw" in public["keywords"]
        assert "German" in public["languages"]
        assert "public" in public["access_levels"]

    async def test_get_facets_registered_sees_middle_but_not_vetted(self, db_pool, dataset_factory):
        """The middle tier: a registered actor gains the registered-tier
        values (positive control on the `WHEN 'registered' THEN 1` copy)
        while vetted-only values stay hidden."""
        _seed_three_tiers(dataset_factory)

        registered = await get_facets(db_pool, "registered", configured_sources=_SOURCES)

        assert "reg-kw" in registered["keywords"]
        assert "Italian" in registered["languages"]
        assert "pub-kw" in registered["keywords"]
        assert "secret-kw" not in registered["keywords"]
        assert "Rumantsch" not in registered["languages"]
        assert "restricted" in registered["access_levels"]

    async def test_get_facets_vetted_sees_everything(self, db_pool, dataset_factory):
        """Positive control for the whole ladder: the top tier enumerates all
        three tiers' values — proves the hidden values were really present in
        the data and the public/registered tests weren't passing vacuously."""
        _seed_three_tiers(dataset_factory)

        vetted = await get_facets(db_pool, "vetted", configured_sources=_SOURCES)

        assert {"pub-kw", "reg-kw", "secret-kw"} <= set(vetted["keywords"])
        assert {"German", "Italian", "Rumantsch"} <= set(vetted["languages"])
        assert {"public", "restricted"} <= set(vetted["access_levels"])

    async def test_facet_keyword_min_share_gate(self, db_pool, dataset_factory):
        """Characterises the HAVING COUNT(*) >= 2 keyword gate: a keyword on a
        single dataset never surfaces (even at the top tier), while languages
        keep singletons. Guards the gate against accidental removal — it is
        the reason every keyword in this module needs two sharers."""
        dataset_factory(visibility_tier="public", keywords=["lonely-kw"], languages=["Vulcan"])

        facets = await get_facets(db_pool, "vetted", configured_sources=_SOURCES)

        assert "lonely-kw" not in facets["keywords"]
        assert "Vulcan" in facets["languages"]

    async def test_facet_suggestions_are_bounded_and_remain_tier_scoped(
        self, db_pool, dataset_factory
    ):
        """Keyword facet suggestions are capped at FACET_OPTION_LIMIT even
        when far more qualifying keywords exist, and the cap does not leak
        above-tier-only keywords into the guest result to fill out the
        count."""
        keywords = [f"keyword-{i:03}" for i in range(80)]
        for i in range(2):
            dataset_factory(uuid=f"public:{i}", keywords=keywords)
            dataset_factory(uuid=f"hidden:{i}", keywords=["secret-facet"], visibility_tier="vetted")
        guest = await get_facets(db_pool, "public", configured_sources=_SOURCES)
        assert len(guest["keywords"]) == FACET_OPTION_LIMIT
        assert "secret-facet" not in guest["keywords"]


class TestLanguageFilterTierGating:
    """The `?language=` exact-match filter in `search_datasets` is gated
    behind the visibility predicate, separately from the keyword filter."""

    async def test_language_filter_is_tier_gated(self, db_pool, dataset_factory):
        """Verify language filter is tier gated."""
        dataset_factory(visibility_tier="vetted", title="Hidden DS", languages=["Rumantsch"])

        results, total = await search_datasets(
            db_pool, "public", language="Rumantsch", configured_sources=_SOURCES
        )
        assert results == [] and total == 0

        # Positive control: the vetted actor gets the hit through the same filter.
        results, total = await search_datasets(
            db_pool, "vetted", language="Rumantsch", configured_sources=_SOURCES
        )
        assert total == 1
        assert results[0].title == "Hidden DS"

    async def test_language_filter_still_matches_public_data_for_guest(
        self, db_pool, dataset_factory
    ):
        """Positive control for the guest direction: the tier gate must not
        swallow legitimately visible matches (an over-broad 'fix' that hides
        public data would pass the leak test above but fail here)."""
        dataset_factory(visibility_tier="public", title="Open DS", languages=["German"])

        results, total = await search_datasets(
            db_pool, "public", language="German", configured_sources=_SOURCES
        )
        assert total == 1
        assert results[0].title == "Open DS"


class TestPublicDiscoverySearchBoundary:
    """The public-discovery search boundary in `search_datasets` is
    intentional and exact: title and access level remain searchable on an
    above-tier row while every full-only field stays unmatchable below
    tier."""

    async def test_public_search_fields_match_above_tier_rows(self, db_pool, dataset_factory):
        """Title and access_level are intentionally searchable by an
        anonymous/below-tier viewer. The returned record is still redacted,
        proving searchability does not unlock full metadata."""
        dataset_factory(
            visibility_tier="vetted",
            title="CURATED-PUBLIC-DISCOVERY-TITLE",
            access_level="restricted",
            description="FULL-ONLY-DESCRIPTION",
        )

        for search_text in ("CURATED-PUBLIC-DISCOVERY-TITLE", "restricted"):
            results, total = await search_datasets(
                db_pool, "public", search_text=search_text, configured_sources=_SOURCES
            )
            assert total == 1
            assert len(results) == 1
            assert results[0].title == "CURATED-PUBLIC-DISCOVERY-TITLE"
            assert results[0].description is None

    async def test_full_search_fields_do_not_match_above_tier_rows_for_public(
        self, db_pool, dataset_factory
    ):
        """Every non-public field included in search_text_full is gated by
        visibility. Each marker is a positive match for a vetted viewer and a
        zero-result probe for an anonymous/public viewer."""
        full_only_markers = {
            "description": "PRIVATE-DESCRIPTION-MARKER",
            "project_title": "PRIVATE-PROJECT-TITLE-MARKER",
            "project_description": "PRIVATE-PROJECT-DESCRIPTION-MARKER",
            "keyword": "PRIVATE-KEYWORD-MARKER",
            "author": "PRIVATE-AUTHOR-MARKER",
        }
        dataset_factory(
            visibility_tier="vetted",
            title="Safe Public Title",
            description=full_only_markers["description"],
            project_title=full_only_markers["project_title"],
            project_description=full_only_markers["project_description"],
            keywords=[full_only_markers["keyword"]],
            authors=[full_only_markers["author"]],
        )

        for field_name, marker in full_only_markers.items():
            public_results, public_total = await search_datasets(
                db_pool,
                "public",
                search_text=marker,
                configured_sources=_SOURCES,
            )
            assert public_results == [], field_name
            assert public_total == 0, field_name

            vetted_results, vetted_total = await search_datasets(
                db_pool,
                "vetted",
                search_text=marker,
                configured_sources=_SOURCES,
            )
            assert vetted_total == 1, field_name
            assert vetted_results[0].title == "Safe Public Title", field_name


class TestRecentDatasetsTierRedaction:
    """The home page's recent list (`get_recent_datasets`) redacts
    below-tier metadata while still listing the row."""

    async def test_get_recent_datasets_redacts_below_tier(self, db_pool, dataset_factory):
        """Verify get recent datasets redacts below tier."""
        dataset_factory(
            visibility_tier="vetted",
            title="Vetted Title",
            description="SECRET-DESC",
            keywords=["secret-kw"],
            languages=["Rumantsch"],
            authors=["Secret Author"],
        )

        recent = await get_recent_datasets(db_pool, "public", configured_sources=_SOURCES)
        total = await get_total_dataset_count(db_pool)

        assert total == 1  # the row IS listed — catalogue browsable
        ds = recent[0]
        assert ds.title == "Vetted Title"  # PUBLIC_DISCOVERY_FIELDS kept
        assert ds.description is None  # THE leak assertion
        assert ds.keywords == []
        assert ds.languages == []
        assert ds.authors == []

        # POSITIVE CONTROL: an over-broad "redact everything" fix fails here.
        recent_v = await get_recent_datasets(db_pool, "vetted", configured_sources=_SOURCES)
        assert recent_v[0].description == "SECRET-DESC"
        assert recent_v[0].keywords == ["secret-kw"]

    async def test_get_recent_datasets_registered_actor_sees_middle_tier_only(
        self, db_pool, dataset_factory
    ):
        """The middle tier on this channel: a registered actor gets the
        registered dataset in full and the vetted one redacted. Pins that
        the recent list uses the tier LATTICE, not a boolean authenticated
        check."""
        dataset_factory(visibility_tier="registered", title="Reg", description="REG-DESC")
        dataset_factory(visibility_tier="vetted", title="Vet", description="VET-DESC")

        recent = await get_recent_datasets(db_pool, "registered", configured_sources=_SOURCES)
        by_title = {d.title: d for d in recent}

        assert by_title["Reg"].description == "REG-DESC"  # at tier -> full
        assert by_title["Vet"].description is None  # above tier -> redacted


class TestSearchExactCountTierScoping:
    """The compatibility API's separate count keeps the page's exact field gates."""

    async def test_search_exact_count_is_tier_scoped(self, db_pool, dataset_factory):
        """Empty pages retain the exact count of current, permitted matches.

        The compatibility API fetches its page and count separately. A private
        description must not affect the public count, even on an empty page.
        """
        for i in range(3):
            dataset_factory(
                visibility_tier="vetted", title=f"Hidden {i}", description="SECRET-DESC"
            )
        dataset_factory(visibility_tier="public", title="Open 1")

        # Guest probes a protected field on an empty second page.
        results, total = await search_datasets(
            db_pool,
            "public",
            search_text="SECRET-DESC",
            page=2,
            page_size=20,
            configured_sources=_SOURCES,
        )
        assert results == []
        assert total == 0, f"exact count leaked cross-tier rows: total={total}"

        # POSITIVE CONTROL 1: the vetted actor's exact count sees the 3
        # hits — proves the rows exist and the guest assertion is not
        # vacuous.
        results_v, total_v = await search_datasets(
            db_pool,
            "vetted",
            search_text="SECRET-DESC",
            page=2,
            page_size=20,
            configured_sources=_SOURCES,
        )
        assert results_v == []
        assert total_v == 3

        # POSITIVE CONTROL 2: page 1 returns the same three permitted matches.
        page1, t1 = await search_datasets(
            db_pool, "vetted", search_text="SECRET-DESC", page=1, configured_sources=_SOURCES
        )
        assert len(page1) == 3
        assert t1 == 3

    async def test_search_exact_count_is_tier_scoped_on_keyword_channel(
        self, db_pool, dataset_factory
    ):
        """Same property on the ?keyword= channel — the keyword and
        full-blob gates are separate SQL lines and separately deletable."""
        for i in range(3):
            dataset_factory(visibility_tier="vetted", title=f"H{i}", keywords=["secret-kw"])

        results, total = await search_datasets(
            db_pool,
            "public",
            keyword="secret-kw",
            page=2,
            page_size=20,
            configured_sources=_SOURCES,
        )
        assert results == [] and total == 0

        results_v, total_v = await search_datasets(
            db_pool,
            "vetted",
            keyword="secret-kw",
            page=2,
            page_size=20,
            configured_sources=_SOURCES,
        )
        assert results_v == [] and total_v == 3  # positive control


class TestDatasetOrdering:
    """Search and recent listings use the same stable, nulls-last order."""

    @pytest.mark.parametrize("tier", ["public", "registered", "vetted"])
    async def test_search_recent_and_pagination_agree_on_missing_dates(
        self, db_pool, dataset_factory, tier
    ):
        """Verify search recent and pagination agree on missing dates."""
        undated_first = dataset_factory(upstream_modified_at=None, keywords=["history"])
        older = dataset_factory(
            upstream_modified_at=datetime(2025, 1, 1, tzinfo=UTC),
            keywords=["history"],
        )
        newer_first = dataset_factory(
            upstream_modified_at=datetime(2026, 1, 1, tzinfo=UTC),
            keywords=["history"],
        )
        undated_last = dataset_factory(upstream_modified_at=None, keywords=["history"])
        newer_last = dataset_factory(
            upstream_modified_at=datetime(2026, 1, 1, tzinfo=UTC),
            keywords=["history"],
        )
        expected = [newer_last, newer_first, older, undated_last, undated_first]
        recent = await get_recent_datasets(db_pool, tier, limit=5, configured_sources=_SOURCES)
        assert [row.id for row in recent] == expected
        pages = []
        for page in (1, 2, 3):
            rows, count = await search_datasets(
                db_pool,
                tier,
                keyword="history",
                page=page,
                page_size=2,
                configured_sources=_SOURCES,
            )
            assert count == 5
            pages.extend(row.id for row in rows)
        assert pages == expected
        rows, count = await search_datasets(
            db_pool, tier, page=4, page_size=2, configured_sources=_SOURCES
        )
        assert rows == []
        assert count == 5


class TestConfiguredSourceRebuildFreshness:
    """Global counts retain all rows; freshness covers every selected source."""

    @pytest.mark.parametrize(
        ("first_state", "second_state", "expected_state"),
        [
            ("older", "newer", "older"),
            ("newer", "older", "older"),
            ("missing", "newer", None),
            ("newer", "missing", None),
            ("never", "newer", None),
            ("newer", "never", None),
        ],
        ids=[
            "first-source-is-oldest",
            "second-source-is-oldest",
            "first-source-is-missing",
            "second-source-is-missing",
            "first-source-never-rebuilt",
            "second-source-never-rebuilt",
        ],
    )
    async def test_freshness_requires_all_selected_sources_and_ignores_unselected_state(
        self, db_pool, sync_conn, dataset_factory, first_state, second_state, expected_state
    ):
        """Verify freshness requires all selected sources and ignores unselected state."""
        source_names = ("archive_alpha", "archive_beta")
        timestamps = {
            "older": datetime(2026, 1, 2, tzinfo=UTC),
            "newer": datetime(2026, 1, 3, tzinfo=UTC),
            "never": None,
        }
        for name, state in zip(source_names, (first_state, second_state), strict=True):
            if state != "missing":
                sync_conn.execute(
                    "INSERT INTO sync_status (source, last_full_rebuild_date) VALUES (%s, %s)",
                    (name, timestamps[state]),
                )
        sync_conn.execute(
            "INSERT INTO sync_status (source, last_full_rebuild_date) VALUES (%s, %s)",
            ("unselected_archive", datetime(2020, 1, 1, tzinfo=UTC)),
        )
        sync_conn.commit()

        # The default legacy row also remains unselected and never rebuilt.
        # Retained dataset rows count even when their source is not selected.
        for name in (*source_names, "unselected_archive"):
            dataset_factory(source=name)

        expected = None if expected_state is None else timestamps[expected_state]
        for selected in (source_names, source_names[::-1]):
            assert await get_global_catalogue_stats(db_pool, source_names=selected) == (
                3,
                expected,
            )
            assert await get_last_full_rebuild_date(db_pool, source_names=selected) == expected
