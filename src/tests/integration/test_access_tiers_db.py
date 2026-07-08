"""Tier-scoping of the aggregate/oracle channels — facets, counts, filters.

Closes the audit's headline finding (TEST-001, mutation probe P12): `get_facets`
is the function that stops a below-tier user's search sidebar from enumerating
keyword/language/access-level values that occur only in above-tier datasets.
Before this file, it was only ever monkeypatched away (unit cache tests) or
executed without content assertions (e2e page loads) — neutralising its tier
filter shipped `542 passed, 0 failed`.

Also pins the sibling oracles: `get_keyword_count` (TEST-030 — the home-page
stat carries its own copy of the tier CASE) and the `?language=` exact-match
filter in `search_datasets` (TEST-031 — gated behind the visibility predicate
on its own SQL line, separately deletable from the tested keyword twin).

Every negative assertion ("below tier must NOT see X") is paired with a
positive control ("at/above tier DOES see X") so a broken fixture or an
over-eager filter cannot pass as a leak-free result.

The three-tier data layout used throughout (keyword facets need TWO sharers to
survive the HAVING COUNT(*) >= 2 gate; languages/access_levels keep
singletons):

    tier        keywords (x2 sharers)   language     access_level
    public      pub-kw                  German       public
    registered  reg-kw                  Italian      public
    vetted      secret-kw               Rumantsch    restricted
"""
from app.services.datasets import get_facets, get_keyword_count, search_datasets


def _seed_three_tiers(dataset_factory):
    dataset_factory(visibility_tier="public", keywords=["pub-kw"],
                    languages=["German"], access_level="public")
    dataset_factory(visibility_tier="public", keywords=["pub-kw"],
                    access_level="public")
    dataset_factory(visibility_tier="registered", keywords=["reg-kw"],
                    languages=["Italian"], access_level="public")
    dataset_factory(visibility_tier="registered", keywords=["reg-kw"],
                    access_level="public")
    dataset_factory(visibility_tier="vetted", keywords=["secret-kw"],
                    languages=["Rumantsch"], access_level="restricted")
    dataset_factory(visibility_tier="vetted", keywords=["secret-kw"],
                    access_level="restricted")


# ---------------------------------------------------------------------------
# TEST-001 / P12 — facet content is tier-scoped on every facet channel
# ---------------------------------------------------------------------------

async def test_get_facets_is_tier_scoped_for_public(db_pool, dataset_factory):
    """THE leak assertion (probe P12): a public/guest actor's facets must not
    enumerate keyword, language, or access-level values that exist only in
    registered- or vetted-tier datasets."""
    _seed_three_tiers(dataset_factory)

    public = await get_facets(db_pool, "public")

    assert "secret-kw" not in public["keywords"]
    assert "reg-kw" not in public["keywords"]
    assert "Rumantsch" not in public["languages"]
    assert "Italian" not in public["languages"]
    assert "restricted" not in public["access_levels"]
    # Positive control: the public tier's own values still surface.
    assert "pub-kw" in public["keywords"]
    assert "German" in public["languages"]
    assert "public" in public["access_levels"]


async def test_get_facets_registered_sees_middle_but_not_vetted(
    db_pool, dataset_factory
):
    """The middle tier (TEST-007's dead CASE branch, facet channel): a
    registered actor gains the registered-tier values (positive control on
    the `WHEN 'registered' THEN 1` copy) while vetted-only values stay
    hidden."""
    _seed_three_tiers(dataset_factory)

    registered = await get_facets(db_pool, "registered")

    assert "reg-kw" in registered["keywords"]
    assert "Italian" in registered["languages"]
    assert "pub-kw" in registered["keywords"]
    assert "secret-kw" not in registered["keywords"]
    assert "Rumantsch" not in registered["languages"]
    assert "restricted" not in registered["access_levels"]


async def test_get_facets_vetted_sees_everything(db_pool, dataset_factory):
    """Positive control for the whole ladder: the top tier enumerates all
    three tiers' values — proves the hidden values were really present in the
    data and the public/registered tests weren't passing vacuously."""
    _seed_three_tiers(dataset_factory)

    vetted = await get_facets(db_pool, "vetted")

    assert {"pub-kw", "reg-kw", "secret-kw"} <= set(vetted["keywords"])
    assert {"German", "Italian", "Rumantsch"} <= set(vetted["languages"])
    assert {"public", "restricted"} <= set(vetted["access_levels"])


async def test_facet_keyword_min_share_gate(db_pool, dataset_factory):
    """Characterises the HAVING COUNT(*) >= 2 keyword gate: a keyword on a
    single dataset never surfaces (even at the top tier), while languages
    keep singletons. Guards the gate against accidental removal — it is the
    reason every keyword in these tests needs two sharers."""
    dataset_factory(visibility_tier="public", keywords=["lonely-kw"],
                    languages=["Vulcan"])

    facets = await get_facets(db_pool, "vetted")

    assert "lonely-kw" not in facets["keywords"]
    assert "Vulcan" in facets["languages"]


# ---------------------------------------------------------------------------
# TEST-030 — the home-page keyword stat is tier-scoped (counting oracle)
# ---------------------------------------------------------------------------

async def test_get_keyword_count_is_tier_scoped(db_pool, dataset_factory):
    """get_keyword_count carries its own copy of the tier CASE; dropping its
    WHERE clause makes a public user's home page count keywords across ALL
    tiers — an aggregate oracle. Singletons count here (no >=2 gate), so one
    dataset per tier suffices."""
    dataset_factory(visibility_tier="public", keywords=["pub-kw"])
    dataset_factory(visibility_tier="registered", keywords=["reg-kw"])
    dataset_factory(visibility_tier="vetted", keywords=["hidden-1", "hidden-2"])

    assert await get_keyword_count(db_pool, "public") == 1
    assert await get_keyword_count(db_pool, "registered") == 2
    assert await get_keyword_count(db_pool, "vetted") == 4  # positive control


# ---------------------------------------------------------------------------
# TEST-031 — the ?language= exact-match filter is tier-gated
# ---------------------------------------------------------------------------

async def test_language_filter_is_tier_gated(db_pool, dataset_factory):
    """The language filter line in search_datasets is gated behind the
    visibility predicate SEPARATELY from the (already-tested) keyword line.
    Deleting `AND {visible}` from the language line alone lets a guest
    confirm a hidden dataset carries a guessed language — a presence oracle
    this test closes in both directions."""
    dataset_factory(visibility_tier="vetted", title="Hidden DS",
                    languages=["Rumantsch"])

    results, total = await search_datasets(db_pool, "public", language="Rumantsch")
    assert results == [] and total == 0

    # Positive control: the vetted actor gets the hit through the same filter.
    results, total = await search_datasets(db_pool, "vetted", language="Rumantsch")
    assert total == 1
    assert results[0].title == "Hidden DS"


async def test_language_filter_still_matches_public_data_for_guest(
    db_pool, dataset_factory
):
    """Positive control for the guest direction: the tier gate must not
    swallow legitimately visible matches (an over-broad 'fix' that hides
    public data would pass the leak test above but fail here)."""
    dataset_factory(visibility_tier="public", title="Open DS",
                    languages=["German"])

    results, total = await search_datasets(db_pool, "public", language="German")
    assert total == 1
    assert results[0].title == "Open DS"
