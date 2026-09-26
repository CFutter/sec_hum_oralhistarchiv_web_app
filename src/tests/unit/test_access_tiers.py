"""Tier lattice + redaction totality (pure unit tier — no DB, no client).

Pins the access-tier hierarchy in app/services/access_tiers.py
(can_access / tier_rank / resolve_tier / resolve_required_source_tier /
SourcePolicy) and the
redaction machinery in app/services/datasets.py (filter_for_tier,
_redacted_values, assert_redaction_total, PUBLIC_DISCOVERY_FIELDS,
PUBLIC_SEARCH_FIELDS).

The tier lattice is the single authorization primitive for metadata
visibility; filter_for_tier is the single redaction chokepoint every
dataset read funnels through. A failure here is a silent data leak,
so each edge of the lattice and both failure modes of the totality
check are pinned explicitly.
"""

import ast
import dataclasses
import inspect
import re
from dataclasses import fields as dataclass_fields
from typing import Any, cast
from unittest.mock import create_autospec

import pytest

from app.services import access_tiers, datasets
from app.services.access_tiers import (
    SourcePolicy,
    SourceVisibilityTierError,
    can_access,
    resolve_required_source_tier,
    resolve_tier,
    tier_rank,
)
from app.services.datasets import Author, Dataset, filter_for_tier
from app.services.db_schema_contract import FUNCTION_CONTRACTS
from app.services.sync import _classify_swissubase_access


def _noop_classifier(_license_val: str | None) -> str:
    """Placeholder for tests that exercise tier resolution, not classification.

    resolve_tier never calls classify_access; SourcePolicy just requires one.
    """
    return "public"


def make_full_dataset(**overrides) -> Dataset:
    """A Dataset with EVERY field populated with a distinctive non-default
    value, so redaction tests can tell 'kept' from 'redacted' for each field."""
    values = {
        "id": 7,
        "uuid": "uuid-0007",
        "title": "Zurich interviews",
        "project_title": "Project X",
        "description": "Long description",
        "resource_description": "Resource description",
        "languages": ["German", "French"],
        "project_description": "Project description",
        "authors": [Author(name="A. Author")],
        "keywords": ["oral-history", "zurich"],
        "resource_proxies": [{"type": "Resource", "ref": "http://dl.example"}],
        "resource_access_url": "http://dl.example",
        "landing_page_url": "http://lp.example",
        "license_val": "CC-BY",
        "license_url": "http://license.example",
        "access_level": "restricted",
        "version": "1.2",
        "doi": "10.1234/abc",
        "resource_type": "Sound",
        "bibliographical_citation": "Cite me (2026)",
        "source": "swissubase",
        "visibility_tier": "vetted",
    }
    values.update(overrides)
    return Dataset(**cast("Any", values))


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
        ("garbage", "public"),  # unknown user tier
        ("vetted", "garbage"),  # unknown required tier
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


def test_resolve_optional_tier_none_returns_ceiling():
    """An optional-tier source gets its ceiling when the record has no tier.

    Source A uses this model because its public OAI stream does not carry an
    application visibility classification. Sensitive Source B records use the
    strict primitive tested below instead.
    """
    policy = SourcePolicy(
        name="optional-tier-source",
        max_visibility="vetted",
        classify_access=_noop_classifier,
    )
    assert resolve_tier(None, policy) == "vetted"


def test_resolve_optional_tier_garbage_returns_ceiling():
    """The legacy optional-tier resolver does not trust an unknown value."""
    policy = SourcePolicy(
        name="optional-tier-source",
        max_visibility="registered",
        classify_access=_noop_classifier,
    )
    assert resolve_tier("garbage", policy) == "registered"


def test_resolve_optional_tier_clamps_record_more_permissive_than_ceiling():
    """The optional resolver clamps a valid tier to a stricter ceiling."""
    policy = SourcePolicy(
        name="optional-tier-source",
        max_visibility="vetted",
        classify_access=_noop_classifier,
    )
    assert resolve_tier("public", policy) == "vetted"


def test_resolve_optional_tier_keeps_record_more_restrictive_than_ceiling():
    """A record claiming 'vetted' under a 'registered' ceiling KEEPS 'vetted':
    being more restrictive than the ceiling is always allowed. Also pins the
    equal case (record at ceiling keeps its own tier)."""
    policy = SourcePolicy(
        name="open-source", max_visibility="registered", classify_access=_noop_classifier
    )
    assert resolve_tier("vetted", policy) == "vetted"
    # Record exactly at the ceiling keeps its own tier too (>= comparison).
    assert resolve_tier("registered", policy) == "registered"


# ---------------------------------------------------------------------------
# resolve_required_source_tier — mandatory Source B tier contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "record_tier",
    [
        None,
        "",
        "garbage",
        "PUBLIC",
        " public ",
        "untrusted-tier-canary-7f62",
        0,
        ["vetted"],
    ],
    ids=[
        "missing",
        "empty",
        "unknown",
        "case-variant",
        "whitespace",
        "non-reflection-canary",
        "integer",
        "list",
    ],
)
def test_required_source_tier_rejects_missing_or_unknown(record_tier):
    """SB-VIS-001/002: invalid classifications raise before persistence.

    The future Source B adapter must turn this failure into record rejection or
    quarantine, never a potentially more permissive default.
    """
    policy = SourcePolicy(
        name="source-b",
        max_visibility="registered",
        classify_access=_noop_classifier,
    )

    with pytest.raises(SourceVisibilityTierError, match=r"^source-b record") as exc:
        resolve_required_source_tier(record_tier, policy)

    # Raw upstream input must not be reflected into an error that callers log.
    raw_canary = record_tier if isinstance(record_tier, str) and record_tier else repr(record_tier)
    assert raw_canary not in str(exc.value)


@pytest.mark.parametrize(
    ("record_tier", "ceiling", "expected"),
    [
        ("public", "public", "public"),
        ("public", "registered", "registered"),
        ("public", "vetted", "vetted"),
        ("registered", "public", "registered"),
        ("registered", "registered", "registered"),
        ("registered", "vetted", "vetted"),
        ("vetted", "public", "vetted"),
        ("vetted", "registered", "vetted"),
        ("vetted", "vetted", "vetted"),
    ],
)
def test_required_source_tier_full_record_ceiling_matrix(record_tier, ceiling, expected):
    """SB-VIS-003: policy may only keep or tighten a valid source tier."""
    policy = SourcePolicy(
        name="source-b",
        max_visibility=ceiling,
        classify_access=_noop_classifier,
    )
    assert resolve_required_source_tier(record_tier, policy) == expected


# ---------------------------------------------------------------------------
# SourcePolicy — frozen dataclass
# ---------------------------------------------------------------------------


def test_source_policy_is_frozen():
    """SourcePolicy(frozen=True): assigning to a field raises. Guards against
    the dataclass losing frozen=True, which would let ingest code silently
    widen a source's visibility ceiling at runtime."""
    policy = SourcePolicy(
        name="swissubase", max_visibility="registered", classify_access=_noop_classifier
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.max_visibility = "public"


class TestSwissubaseAccessClassification:
    """`_classify_swissubase_access` (the SWISSUbase source's
    `classify_access` implementation) and the SourcePolicy contract that
    requires every source to supply one explicitly."""

    @pytest.mark.parametrize(
        ("license_val", "expected"),
        [
            # Case-insensitive prefix match on "restricted access".
            ("Restricted access — ethics approval", "restricted"),
            ("RESTRICTED ACCESS: contact the depositor", "restricted"),
            # Anything else is public (fail-open by choice for SWISSUbase).
            ("License CC BY", "public"),
            (None, "public"),
        ],
        ids=[
            "restricted-access-prefix-mixed-case",
            "restricted-access-prefix-upper-case",
            "any-other-license-is-public",
            "missing-license-is-public",
        ],
    )
    def test_classifies_by_restricted_access_prefix(self, license_val, expected):
        """'restricted access*' (any case) → restricted; everything else
        (incl. None) → public for source='swissubase'."""
        assert _classify_swissubase_access(license_val) == expected

    def test_source_policy_requires_explicit_classifier(self):
        """A new source cannot inherit SWISSUbase's fail-open classifier
        by accident — omitting classify_access fails at construction, not per
        record inside the sync loop."""
        with pytest.raises(TypeError):
            SourcePolicy(name="source-b", max_visibility="vetted")


# ---------------------------------------------------------------------------
# Public discovery policy + filter_for_tier redaction behavior
# ---------------------------------------------------------------------------


def test_public_discovery_fields_are_explicit_and_stable():
    """SB-DISC-001/002: this exact set is disclosed below tier.

    A source or fork with a different disclosure policy must make a reviewed
    code-and-test change instead of acquiring a new public field implicitly.
    """
    assert (
        frozenset(
            {
                "id",
                "uuid",
                "title",
                "access_level",
                "version",
                "source",
                "visibility_tier",
            }
        )
        == datasets.PUBLIC_DISCOVERY_FIELDS
    )


def test_public_search_fields_are_explicit_and_inside_discovery_envelope():
    """SB-DISC-006: only title and access level are searchable below tier."""
    assert frozenset({"title", "access_level"}) == datasets.PUBLIC_SEARCH_FIELDS
    assert datasets.PUBLIC_SEARCH_FIELDS <= datasets.PUBLIC_DISCOVERY_FIELDS


def test_schema_contract_public_search_assignment_matches_policy():
    """SB-DISC-006: runtime-preflight's PostgreSQL function contract builds
    search_text_public from exactly PUBLIC_SEARCH_FIELDS—no full-only field.

    The live-schema integration suite separately proves that a changed function
    body is rejected, so this comparison ties that guarded body to field policy.
    """
    function_source = FUNCTION_CONTRACTS["update_search_text()"].source
    _, separator, after_assignment = function_source.partition("NEW.search_text_public :=")
    assert separator, "schema contract no longer assigns search_text_public"
    public_assignment, terminator, _ = after_assignment.partition(";")
    assert terminator, "search_text_public assignment is not terminated"

    referenced_fields = frozenset(re.findall(r"NEW\.([a-z_]+)", public_assignment))
    assert referenced_fields == datasets.PUBLIC_SEARCH_FIELDS


def test_filter_for_tier_at_or_above_returns_same_object():
    """A user at or above the dataset's visibility_tier gets the IDENTICAL
    object back (no copy, no redaction). Pins the identity fast-path with
    `is`, both for tier == visibility_tier and tier above it."""
    ds_registered = make_full_dataset(visibility_tier="registered")
    assert filter_for_tier(ds_registered, "registered") is ds_registered  # equal
    assert filter_for_tier(ds_registered, "vetted") is ds_registered  # above


def test_filter_for_tier_below_returns_new_redacted_dataset():
    """SB-DISC-001/002: a below-tier viewer gets a NEW Dataset keeping
    exactly PUBLIC_DISCOVERY_FIELDS and every other field reset to its
    redacted value (None or fresh []). Checked field-by-field over
    dataclass_fields so a newly added field cannot slip through unclassified.
    """
    ds = make_full_dataset(visibility_tier="vetted")
    redacted = filter_for_tier(ds, "public")

    assert redacted is not ds
    assert isinstance(redacted, Dataset)

    expected_visible = datasets.PUBLIC_DISCOVERY_FIELDS

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
    in place -> the other's stays []."""
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
    is in exactly one of PUBLIC_DISCOVERY_FIELDS / _redacted_values(). If this
    fails, a Dataset field was added without a disclosure decision."""
    datasets.assert_redaction_total()  # must not raise


def test_assert_redaction_total_detects_overlap(monkeypatch):
    """A field in BOTH sets ('description' added to PUBLIC_DISCOVERY_FIELDS
    while still in _redacted_values) is an erroneous classification;
    assert_redaction_total raises AssertionError naming the field."""
    monkeypatch.setattr(
        datasets,
        "PUBLIC_DISCOVERY_FIELDS",
        datasets.PUBLIC_DISCOVERY_FIELDS | {"description"},
    )
    with pytest.raises(
        AssertionError,
        match=r"in both sets.*description",
    ):
        datasets.assert_redaction_total()


def test_assert_redaction_total_detects_unapproved_public_search_field(monkeypatch):
    """SB-DISC-006 fail-fast: an ungated search field outside the public
    discovery envelope is an authorization oracle and blocks startup."""
    monkeypatch.setattr(
        datasets,
        "PUBLIC_SEARCH_FIELDS",
        datasets.PUBLIC_SEARCH_FIELDS | {"description"},
    )
    with pytest.raises(
        AssertionError,
        match=r"publicly searchable but not public-discovery fields.*description",
    ):
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

    spy = create_autospec(datasets._redacted_values, spec_set=True)
    spy.side_effect = redacted_minus_doi
    monkeypatch.setattr(datasets, "_redacted_values", spy)
    with pytest.raises(
        AssertionError,
        match=r"unclassified fields.*doi",
    ):
        datasets.assert_redaction_total()


def test_assert_redaction_total_detects_stale_classified_name(monkeypatch):
    """A classified name that is NOT a Dataset field (a typo, or a rename applied
    to the dataclass but not to _redacted_values) would pass the coverage check
    and then raise TypeError inside filter_for_tier on the first below-tier
    render. Caught at startup instead."""
    original = datasets._redacted_values

    def redacted_with_typo():
        values = original()
        values["licence_val"] = values.pop("license_val")  # British spelling typo
        return values

    spy = create_autospec(datasets._redacted_values, spec_set=True)
    spy.side_effect = redacted_with_typo
    monkeypatch.setattr(datasets, "_redacted_values", spy)
    with pytest.raises(
        AssertionError,
        match=r"not Dataset fields.*licence_val",
    ):
        datasets.assert_redaction_total()


# ---------------------------------------------------------------------------
# assert_tier_rank_complete (the untested twin of
# assert_redaction_total; both are lifespan fail-fast guards)
# ---------------------------------------------------------------------------


def test_assert_tier_rank_complete_passes_today():
    """The shipped lattice is complete and total. If this fails, an
    AccessTier member was added without a rank."""
    access_tiers.assert_tier_rank_complete()  # must not raise


def test_assert_tier_rank_complete_detects_unranked_tier(monkeypatch):
    """A tier declared in the AccessTier Literal but absent from _TIER_RANK
    falls to the fail-closed `ELSE 99` in TIER_CASE_SQL and vanishes from
    EVERY visibility query — rows become invisible to everyone, including
    admins. The guard must name it at startup."""
    monkeypatch.setattr(
        access_tiers,
        "_TIER_RANK",
        {"public": 0, "registered": 1},  # 'vetted' dropped
    )
    with pytest.raises(AssertionError, match=r"unranked.*vetted"):
        access_tiers.assert_tier_rank_complete()


def test_assert_tier_rank_complete_detects_ranked_but_undeclared(monkeypatch):
    """The other direction: a rank for a tier the Literal no longer declares
    (a rename applied to AccessTier but not to _TIER_RANK). Mirrors
    test_assert_redaction_total_detects_stale_classified_name."""
    monkeypatch.setattr(
        access_tiers,
        "_TIER_RANK",
        {"public": 0, "registered": 1, "vetted": 2, "superuser": 3},
    )
    with pytest.raises(AssertionError, match=r"ranked but not declared.*superuser"):
        access_tiers.assert_tier_rank_complete()


# ---------------------------------------------------------------------------
# structural canary — every tier-aware read path must redact
# ---------------------------------------------------------------------------


def test_every_dataset_read_path_funnels_through_filter_for_tier():
    """The get_recent_datasets hole existed because nobody
    ENUMERATED it as a redaction channel. This makes the enumeration
    self-enforcing — a new public async read taking user_tier that never
    calls filter_for_tier fails HERE, not in production.

    Exemptions are aggregate channels that return scalars/value-lists rather
    than Dataset rows: they are tier-scoped in SQL, with nothing to redact.
    Adding to this set must be a reviewed decision with a reason."""
    AGGREGATE_CHANNELS = {
        "get_home_metadata_counts",  # two counts, tier-scoped in one SQL query
        "get_facets",  # returns value lists; tier-scoped via TIER_CASE_SQL
        "get_keyword_count",  # returns an int; tier-scoped via TIER_CASE_SQL
    }

    tree = ast.parse(inspect.getsource(datasets))
    offenders = []
    checked = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef) or node.name.startswith("_"):
            continue
        if "user_tier" not in {a.arg for a in node.args.args}:
            continue
        if node.name in AGGREGATE_CHANNELS:
            continue
        checked.append(node.name)
        calls = {
            n.func.id
            for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        if "filter_for_tier" not in calls:
            offenders.append(node.name)

    assert not offenders, (
        f"tier-aware read paths that never redact: {offenders} — every "
        f"function taking user_tier and returning Dataset rows must funnel "
        f"through filter_for_tier"
    )
    # ANTI-VACUITY CONTROL (mirrors test_route_guards.test_route_table_is_populated):
    # if the walk finds nothing, the assertion above passes meaninglessly.
    assert set(checked) >= {
        "search_datasets",
        "get_recent_datasets",
        "get_dataset_by_id",
    }, f"canary only inspected {checked} — the AST walk does not reach the read paths"
