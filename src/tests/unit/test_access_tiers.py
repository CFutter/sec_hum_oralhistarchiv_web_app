"""Tier lattice + redaction totality (pure unit tier — no DB, no client).

Pins the access-tier hierarchy in app/services/access_tiers.py
(can_access / tier_rank / resolve_tier / SourcePolicy) and the
redaction machinery in app/services/datasets.py (filter_for_tier,
_redacted_values, assert_redaction_total, _TIER_VISIBLE_FIELDS).

The tier lattice is the single authorization primitive for metadata
visibility; filter_for_tier is the single redaction chokepoint every
dataset read funnels through. Regressions here are silent data leaks,
so each edge of the lattice and both failure modes of the totality
check are pinned explicitly.
"""
import dataclasses
from dataclasses import fields as dataclass_fields

import pytest

from app.services import datasets
from app.services.access_tiers import (
    SourcePolicy,
    can_access,
    resolve_tier,
    tier_rank,
)
from app.services.datasets import Author, Dataset, filter_for_tier


def make_full_dataset(**overrides) -> Dataset:
    """A Dataset with EVERY field populated with a distinctive non-default
    value, so redaction tests can tell 'kept' from 'redacted' for each field."""
    values = dict(
        id=7,
        uuid="uuid-0007",
        title="Zurich interviews",
        project_title="Project X",
        description="Long description",
        resource_description="Resource description",
        languages=["German", "French"],
        project_description="Project description",
        authors=[Author(name="A. Author")],
        keywords=["oral-history", "zurich"],
        resource_proxies=[{"type": "Resource", "ref": "http://dl.example"}],
        download_url="http://dl.example",
        landing_page_url="http://lp.example",
        license_val="CC-BY",
        license_url="http://license.example",
        access_level="restricted",
        version="1.2",
        doi="10.1234/abc",
        resource_type="Sound",
        bibliographical_citation="Cite me (2026)",
        source="swissubase",
        visibility_tier="vetted",
    )
    values.update(overrides)
    return Dataset(**values)


# ---------------------------------------------------------------------------
# can_access — the full 3x3 lattice
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("user_tier", "required_tier", "expected"),
    [
        # public user: sees only public
        ("public", "public", True),
        ("public", "registered", False),
        ("public", "vetted", False),
        # registered user: public + registered
        ("registered", "public", True),
        ("registered", "registered", True),
        ("registered", "vetted", False),
        # vetted user: sees everything
        ("vetted", "public", True),
        ("vetted", "registered", True),
        ("vetted", "vetted", True),
    ],
)
def test_can_access_full_matrix(user_tier, required_tier, expected):
    """Pins every cell of the 3x3 tier matrix: vetted > registered > public,
    strict and total. Guards against any reordering/off-by-one in _TIER_RANK
    (e.g. a swapped comparison letting public viewers see vetted metadata)."""
    assert can_access(user_tier, required_tier) is expected


@pytest.mark.parametrize(
    ("user_tier", "required_tier"),
    [
        ("garbage", "public"),      # unknown user tier
        ("vetted", "garbage"),      # unknown required tier
    ],
)
def test_can_access_unknown_tier_raises_value_error(user_tier, required_tier):
    """Unknown tier strings on EITHER side raise ValueError (fail closed),
    never a silent True/False. Guards the KeyError -> ValueError translation."""
    with pytest.raises(ValueError, match="Unknown access tier"):
        can_access(user_tier, required_tier)


# ---------------------------------------------------------------------------
# tier_rank — numeric ranks used in SQL tier gating
# ---------------------------------------------------------------------------

def test_tier_rank_values():
    """public=0, registered=1, vetted=2. These exact numbers are baked into
    the SQL CASE expressions in datasets.py (visibility gating); changing
    them without touching the SQL would desynchronize Python and DB gating."""
    assert tier_rank("public") == 0
    assert tier_rank("registered") == 1
    assert tier_rank("vetted") == 2


def test_tier_rank_unknown_raises_value_error():
    """tier_rank fails closed on unknown tiers instead of returning a rank."""
    with pytest.raises(ValueError, match="Unknown access tier"):
        tier_rank("garbage")


# ---------------------------------------------------------------------------
# resolve_tier — record tier vs source ceiling (more restrictive wins)
# ---------------------------------------------------------------------------

def test_resolve_tier_none_returns_ceiling():
    """A record with no tier of its own gets the source ceiling ('vetted'
    here) — absence of a per-record decision never widens visibility."""
    policy = SourcePolicy(name="source-b", max_visibility="vetted")
    assert resolve_tier(None, policy) == "vetted"


def test_resolve_tier_garbage_returns_ceiling():
    """An unrecognized record tier string falls back to the ceiling instead
    of raising or (worse) being trusted as-is."""
    policy = SourcePolicy(name="source-b", max_visibility="registered")
    assert resolve_tier("garbage", policy) == "registered"


def test_resolve_tier_clamps_record_more_permissive_than_ceiling():
    """A record claiming 'public' under a 'vetted' ceiling is clamped to
    'vetted': a source can never publish MORE permissively than its policy
    allows. This is the core clamp guarding sensitive-source leaks."""
    policy = SourcePolicy(name="sensitive-source", max_visibility="vetted")
    assert resolve_tier("public", policy) == "vetted"


def test_resolve_tier_keeps_record_more_restrictive_than_ceiling():
    """A record claiming 'vetted' under a 'registered' ceiling KEEPS 'vetted':
    being more restrictive than the ceiling is always allowed. Also pins the
    equal case (record at ceiling keeps its own tier)."""
    policy = SourcePolicy(name="open-source", max_visibility="registered")
    assert resolve_tier("vetted", policy) == "vetted"
    # Record exactly at the ceiling keeps its own tier too (>= comparison).
    assert resolve_tier("registered", policy) == "registered"


# ---------------------------------------------------------------------------
# SourcePolicy — frozen dataclass
# ---------------------------------------------------------------------------

def test_source_policy_is_frozen():
    """SourcePolicy(frozen=True): assigning to a field raises. Guards against
    the dataclass losing frozen=True, which would let ingest code silently
    widen a source's visibility ceiling at runtime."""
    policy = SourcePolicy(name="swissubase", max_visibility="registered")
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.max_visibility = "public"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# filter_for_tier — redaction behavior
# ---------------------------------------------------------------------------

def test_filter_for_tier_at_or_above_returns_same_object():
    """A user at or above the dataset's visibility_tier gets the IDENTICAL
    object back (no copy, no redaction). Pins the identity fast-path with
    `is`, both for tier == visibility_tier and tier above it."""
    ds_registered = make_full_dataset(visibility_tier="registered")
    assert filter_for_tier(ds_registered, "registered") is ds_registered  # equal
    assert filter_for_tier(ds_registered, "vetted") is ds_registered      # above


def test_filter_for_tier_below_returns_new_redacted_dataset():
    """A below-tier viewer gets a NEW Dataset keeping exactly the
    _TIER_VISIBLE_FIELDS (id/uuid/title/access_level/version/source/
    visibility_tier) and every other field reset to its redacted value
    (None or fresh []). Checked field-by-field over dataclass_fields so a
    newly added field can't slip through this test unclassified."""
    ds = make_full_dataset(visibility_tier="vetted")
    redacted = filter_for_tier(ds, "public")

    assert redacted is not ds
    assert isinstance(redacted, Dataset)

    expected_visible = {
        "id", "uuid", "title", "access_level", "version", "source",
        "visibility_tier",
    }
    assert datasets._TIER_VISIBLE_FIELDS == frozenset(expected_visible)

    expected_redacted = datasets._redacted_values()
    for f in dataclass_fields(Dataset):
        if f.name in expected_visible:
            # kept verbatim from the original
            assert getattr(redacted, f.name) == getattr(ds, f.name), f.name
        else:
            # reset to the redacted value, never the original
            assert getattr(redacted, f.name) == expected_redacted[f.name], f.name

    # Spot-check the fields the spec names explicitly.
    assert redacted.authors == []
    assert redacted.keywords == []
    assert redacted.languages == []
    assert redacted.description is None
    assert redacted.doi is None
    # The original is untouched by redaction.
    assert ds.description == "Long description"
    assert ds.authors == [Author(name="A. Author")]


def test_filter_for_tier_redacted_lists_are_not_shared():
    """MUTATION-ISOLATION pin: redact two datasets, mutate one's .languages
    in place -> the other's stays []. This is exactly the aliasing bug
    _redacted_values() (a function returning fresh lists per call, rather
    than a shared module-level constant) exists to prevent."""
    ds_a = make_full_dataset(id=1, uuid="uuid-a", visibility_tier="vetted")
    ds_b = make_full_dataset(id=2, uuid="uuid-b", visibility_tier="vetted")

    red_a = filter_for_tier(ds_a, "public")
    red_b = filter_for_tier(ds_b, "public")

    red_a.languages.append("Klingon")

    assert red_a.languages == ["Klingon"]
    assert red_b.languages == []  # would be ["Klingon"] if lists were aliased
    # Same guarantee for the other list-typed redacted fields.
    red_a.keywords.append("leak")
    red_a.authors.append(Author(name="Mallory"))
    assert red_b.keywords == []
    assert red_b.authors == []


# ---------------------------------------------------------------------------
# assert_redaction_total — startup totality check
# ---------------------------------------------------------------------------

def test_assert_redaction_total_passes_today():
    """The current classification is total and disjoint: every Dataset field
    is in exactly one of _TIER_VISIBLE_FIELDS / _redacted_values(). If this
    fails, a Dataset field was added without a redaction decision."""
    datasets.assert_redaction_total()  # must not raise


def test_assert_redaction_total_detects_overlap(monkeypatch):
    """A field in BOTH sets ('description' added to _TIER_VISIBLE_FIELDS
    while still in _redacted_values) is an erroneous classification;
    assert_redaction_total raises AssertionError naming the field."""
    monkeypatch.setattr(
        datasets,
        "_TIER_VISIBLE_FIELDS",
        datasets._TIER_VISIBLE_FIELDS | {"description"},
    )
    with pytest.raises(AssertionError, match="in both sets.*description"):
        datasets.assert_redaction_total()


def test_assert_redaction_total_detects_unclassified_field(monkeypatch):
    """A Dataset field in NEITHER set (drop 'doi' from _redacted_values) is
    an unclassified field — the exact 'new field silently leaks or vanishes'
    failure the startup check exists for. AssertionError says 'unclassified'
    and names the field."""
    original = datasets._redacted_values

    def redacted_minus_doi():
        values = original()
        del values["doi"]
        return values

    monkeypatch.setattr(datasets, "_redacted_values", redacted_minus_doi)
    with pytest.raises(AssertionError, match="unclassified fields.*doi"):
        datasets.assert_redaction_total()
