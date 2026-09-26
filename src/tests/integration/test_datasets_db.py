"""Tier-scoping and ordering of `app.services.datasets` queries.

`get_facets` is the function that stops a below-tier user's search sidebar
from enumerating keyword/language/access-level values that occur only in
above-tier datasets. Before this module existed, it was only ever
monkeypatched away (unit cache tests) or executed without content assertions
(e2e page loads) — neutralising its tier filter shipped a fully green suite.

Also pins the sibling oracles: `get_keyword_count` (the home-page stat
carries its own copy of the tier CASE), the `?language=` exact-match filter
in `search_datasets` (gated behind the visibility predicate on its own SQL
line, separately deletable from the tested keyword twin), the public
discovery search boundary (title and access level stay searchable on an
above-tier row while the returned record stays redacted), the tier-redaction
of the home page's recent list, the tier-scoping of the empty-page fallback
COUNT(*), and the stable nulls-last ordering shared by search and recent
listings.

Every negative assertion ("below tier must NOT see X") is paired with a
positive control ("at/above tier DOES see X") so a broken fixture or an
over-eager filter cannot pass as a leak-free result.

The three-tier data layout used throughout (keyword facets need TWO sharers
to survive the HAVING COUNT(*) >= 2 gate; languages/access_levels keep
singletons):

    tier        keywords (x2 sharers)   language     access_level
    public      pub-kw                  German       public
    registered  reg-kw                  Italian      public
    vetted      secret-kw               Rumantsch    restricted
"""

from datetime import UTC, datetime

import pytest

from app.services.datasets import (
    FACET_OPTION_LIMIT,
    get_facets,
    get_keyword_count,
    get_recent_datasets,
    get_total_dataset_count,
    search_datasets,
)


def _seed_three_tiers(dataset_factory):
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


class TestFacetTierScoping:
    """Facet content (keywords/languages/access levels) is tier-scoped on
    every channel `get_facets` exposes."""

    async def test_get_facets_is_tier_scoped_for_public(self, db_pool, dataset_factory):
        """The leak assertion: a public/guest actor's facets must not
        enumerate keyword or language values that exist only in
        registered- or vetted-tier datasets."""
        _seed_three_tiers(dataset_factory)

        public = await get_facets(db_pool, "public")

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

        registered = await get_facets(db_pool, "registered")

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

        vetted = await get_facets(db_pool, "vetted")

        assert {"pub-kw", "reg-kw", "secret-kw"} <= set(vetted["keywords"])
        assert {"German", "Italian", "Rumantsch"} <= set(vetted["languages"])
        assert {"public", "restricted"} <= set(vetted["access_levels"])

    async def test_facet_keyword_min_share_gate(self, db_pool, dataset_factory):
        """Characterises the HAVING COUNT(*) >= 2 keyword gate: a keyword on a
        single dataset never surfaces (even at the top tier), while languages
        keep singletons. Guards the gate against accidental removal — it is
        the reason every keyword in this module needs two sharers."""
        dataset_factory(visibility_tier="public", keywords=["lonely-kw"], languages=["Vulcan"])

        facets = await get_facets(db_pool, "vetted")

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
        guest = await get_facets(db_pool, "public")
        assert len(guest["keywords"]) == FACET_OPTION_LIMIT
        assert "secret-facet" not in guest["keywords"]


class TestKeywordCountTierScoping:
    """The home-page keyword stat (`get_keyword_count`) is tier-scoped and
    diverges deliberately from the facet keyword list."""

    async def test_get_keyword_count_is_tier_scoped(self, db_pool, dataset_factory):
        """get_keyword_count carries its own copy of the tier CASE; dropping
        its WHERE clause makes a public user's home page count keywords
        across ALL tiers — an aggregate oracle. Singletons count here (no
        >=2 gate), so one dataset per tier suffices."""
        dataset_factory(visibility_tier="public", keywords=["pub-kw"])
        dataset_factory(visibility_tier="registered", keywords=["reg-kw"])
        dataset_factory(visibility_tier="vetted", keywords=["hidden-1", "hidden-2"])

        assert await get_keyword_count(db_pool, "public") == 1
        assert await get_keyword_count(db_pool, "registered") == 2
        assert await get_keyword_count(db_pool, "vetted") == 4  # positive control

    async def test_singleton_keyword_counted_but_absent_from_facets(self, db_pool, dataset_factory):
        """The keyword count is NOT derivable from the facet lists —
        get_facets drops singletons (the HAVING COUNT(*) >= 2 de-noise gate)
        while get_keyword_count counts every distinct keyword. The
        shared-payload cache design rests on carrying BOTH per tier; a
        'simplification' that recomputes the count as
        len(facets['keywords']) silently undercounts, and this pins the
        divergence at the service layer where it originates."""
        dataset_factory(visibility_tier="public", keywords=["once-kw"])

        facets = await get_facets(db_pool, "public")
        assert "once-kw" not in facets["keywords"]

        # POSITIVE CONTROL: the same tier's count DOES include the
        # singleton — its absence above is the >=2 gate, not tier gating or
        # a broken seed.
        assert await get_keyword_count(db_pool, "public") == 1


class TestLanguageFilterTierGating:
    """The `?language=` exact-match filter in `search_datasets` is gated
    behind the visibility predicate, separately from the keyword filter."""

    async def test_language_filter_is_tier_gated(self, db_pool, dataset_factory):
        """The language filter line in search_datasets is gated behind the
        visibility predicate SEPARATELY from the (already-tested) keyword
        line. Deleting `AND {visible}` from the language line alone lets a
        guest confirm a hidden dataset carries a guessed language — a
        presence oracle this test closes in both directions."""
        dataset_factory(visibility_tier="vetted", title="Hidden DS", languages=["Rumantsch"])

        results, total = await search_datasets(db_pool, "public", language="Rumantsch")
        assert results == [] and total == 0

        # Positive control: the vetted actor gets the hit through the same filter.
        results, total = await search_datasets(db_pool, "vetted", language="Rumantsch")
        assert total == 1
        assert results[0].title == "Hidden DS"

    async def test_language_filter_still_matches_public_data_for_guest(
        self, db_pool, dataset_factory
    ):
        """Positive control for the guest direction: the tier gate must not
        swallow legitimately visible matches (an over-broad 'fix' that hides
        public data would pass the leak test above but fail here)."""
        dataset_factory(visibility_tier="public", title="Open DS", languages=["German"])

        results, total = await search_datasets(db_pool, "public", language="German")
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
            results, total = await search_datasets(db_pool, "public", search_text=search_text)
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
                db_pool, "public", search_text=marker
            )
            assert public_results == [], field_name
            assert public_total == 0, field_name

            vetted_results, vetted_total = await search_datasets(
                db_pool, "vetted", search_text=marker
            )
            assert vetted_total == 1, field_name
            assert vetted_results[0].title == "Safe Public Title", field_name


class TestRecentDatasetsTierRedaction:
    """The home page's recent list (`get_recent_datasets`) redacts
    below-tier metadata while still listing the row."""

    async def test_get_recent_datasets_redacts_below_tier(self, db_pool, dataset_factory):
        """search_datasets and get_dataset_by_id have redaction pins;
        get_recent_datasets is the only remaining filter_for_tier call site
        without one. home.html renders description, authors, keywords and
        languages directly, so dropping the call leaks restricted metadata
        to anonymous visitors on the landing page. The existing e2e witness
        asserts only a COUNT ('<span class="stat-number">3</span>'), which
        is present whether or not redaction runs."""
        dataset_factory(
            visibility_tier="vetted",
            title="Vetted Title",
            description="SECRET-DESC",
            keywords=["secret-kw"],
            languages=["Rumantsch"],
            authors=["Secret Author"],
        )

        recent = await get_recent_datasets(db_pool, "public")
        total = await get_total_dataset_count(db_pool)

        assert total == 1  # the row IS listed — catalogue browsable
        ds = recent[0]
        assert ds.title == "Vetted Title"  # PUBLIC_DISCOVERY_FIELDS kept
        assert ds.description is None  # THE leak assertion
        assert ds.keywords == []
        assert ds.languages == []
        assert ds.authors == []

        # POSITIVE CONTROL: an over-broad "redact everything" fix fails here.
        recent_v = await get_recent_datasets(db_pool, "vetted")
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

        recent = await get_recent_datasets(db_pool, "registered")
        by_title = {d.title: d for d in recent}

        assert by_title["Reg"].description == "REG-DESC"  # at tier -> full
        assert by_title["Vet"].description is None  # above tier -> redacted


class TestSearchFallbackCountTierScoping:
    """The empty-page fallback COUNT(*) query in `search_datasets` carries
    the same tier WHERE as the main query."""

    async def test_search_fallback_count_is_tier_scoped(self, db_pool, dataset_factory):
        """search_datasets issues a SECOND count query when a page past the
        end returns no rows (COUNT(*) OVER() has no carrier). It must re-use
        the same tier-gated WHERE; dropping it turns total_count into a
        cross-tier counting oracle that reconstructs exactly the presence
        oracle the main query's gating closes.

        A FILTERED query is REQUIRED: with no filter the WHERE collapses to
        TRUE and the catalogue is browsable by design, so the mutation is
        invisible. page>=2 is required too: offset==0 short-circuits to
        ([], 0) before the fallback."""
        for i in range(3):
            dataset_factory(
                visibility_tier="vetted", title=f"Hidden {i}", description="SECRET-DESC"
            )
        dataset_factory(visibility_tier="public", title="Open 1")

        # Guest probes the tier-gated full blob on page 2 -> 0 rows -> fallback.
        results, total = await search_datasets(
            db_pool, "public", search_text="SECRET-DESC", page=2, page_size=20
        )
        assert results == []
        assert total == 0, f"fallback count leaked cross-tier rows: total={total}"

        # POSITIVE CONTROL 1: the vetted actor's fallback count sees the 3
        # hits — proves the rows exist and the guest assertion is not
        # vacuous.
        results_v, total_v = await search_datasets(
            db_pool, "vetted", search_text="SECRET-DESC", page=2, page_size=20
        )
        assert results_v == []
        assert total_v == 3

        # POSITIVE CONTROL 2: page 1 really returns them — the fallback is
        # the only thing under test; the main query must still work.
        page1, t1 = await search_datasets(db_pool, "vetted", search_text="SECRET-DESC", page=1)
        assert len(page1) == 3
        assert t1 == 3

    async def test_search_fallback_count_is_tier_scoped_on_keyword_channel(
        self, db_pool, dataset_factory
    ):
        """Same property on the ?keyword= channel — the keyword and
        full-blob gates are separate SQL lines and separately deletable."""
        for i in range(3):
            dataset_factory(visibility_tier="vetted", title=f"H{i}", keywords=["secret-kw"])

        results, total = await search_datasets(
            db_pool, "public", keyword="secret-kw", page=2, page_size=20
        )
        assert results == [] and total == 0

        results_v, total_v = await search_datasets(
            db_pool, "vetted", keyword="secret-kw", page=2, page_size=20
        )
        assert results_v == [] and total_v == 3  # positive control


class TestDatasetOrdering:
    """Search and recent listings use the same stable, nulls-last order."""

    @pytest.mark.parametrize("tier", ["public", "registered", "vetted"])
    async def test_search_recent_and_pagination_agree_on_missing_dates(
        self, db_pool, dataset_factory, tier
    ):
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
        recent = await get_recent_datasets(db_pool, tier, limit=5)
        assert [row.id for row in recent] == expected
        pages = []
        for page in (1, 2, 3):
            rows, count = await search_datasets(
                db_pool,
                tier,
                keyword="history",
                page=page,
                page_size=2,
            )
            assert count == 5
            pages.extend(row.id for row in rows)
        assert pages == expected
        rows, count = await search_datasets(db_pool, tier, page=4, page_size=2)
        assert rows == []
        assert count == 5
