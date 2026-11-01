"""Tier ordering, source ceilings and total dataset-field redaction."""

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
    SourceVisibilityTierError,
    can_access,
    resolve_required_source_tier,
    resolve_tier,
    tier_rank,
)
from app.services.datasets import Author, Dataset, filter_for_tier
from app.services.db_schema_contract import FUNCTION_CONTRACTS
from app.sources import SourcePolicy
from app.sources.oai_pmh_cmdi import classify_oai_access
from tests.source_fixtures import legacy_source

_SOURCES = (legacy_source(max_visibility="public"),)


def _noop_classifier(_license_val: str | None) -> str:
    """Return public as an unused classifier for tier-policy tests."""
    return "public"


def make_full_dataset(**overrides) -> Dataset:
    """Populate every Dataset field with a distinctive value, applying explicit overrides."""
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


@pytest.mark.parametrize(
    ("user_tier", "required_tier", "expected"),
    [
        ("public", "public", True),
        ("public", "registered", False),
        ("public", "vetted", False),
        ("registered", "public", True),
        ("registered", "registered", True),
        ("registered", "vetted", False),
        ("vetted", "public", True),
        ("vetted", "registered", True),
        ("vetted", "vetted", True),
    ],
)
def test_can_access_full_matrix(user_tier, required_tier, expected):
    """Check all nine viewer/required-tier combinations."""
    assert can_access(user_tier, required_tier) is expected


@pytest.mark.parametrize(
    ("user_tier", "required_tier"),
    [
        ("garbage", "public"),
        ("vetted", "garbage"),
    ],
)
def test_can_access_unknown_tier_raises_value_error(user_tier, required_tier):
    """Raise ValueError for an unknown viewer or required tier."""
    with pytest.raises(ValueError, match="Unknown access tier"):
        can_access(user_tier, required_tier)


def test_tier_rank_values():
    """Keep public=0, registered=1 and vetted=2 aligned with SQL ranks."""
    assert tier_rank("public") == 0
    assert tier_rank("registered") == 1
    assert tier_rank("vetted") == 2


def test_tier_rank_unknown_raises_value_error():
    """tier_rank fails closed on unknown tiers instead of returning a rank."""
    with pytest.raises(ValueError, match="Unknown access tier"):
        tier_rank("garbage")


def test_resolve_optional_tier_none_returns_ceiling():
    """An optional-tier source gets its ceiling when the record has no tier."""
    policy = SourcePolicy(
        name="optional-tier-source",
        max_visibility="vetted",
        classify_access=_noop_classifier,
    )
    assert resolve_tier(None, policy) == "vetted"


def test_resolve_optional_tier_garbage_returns_ceiling():
    """Use the source ceiling when an optional record tier is unknown."""
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
    """Preserve a record tier equal to or stricter than its source ceiling."""
    policy = SourcePolicy(
        name="open-source", max_visibility="registered", classify_access=_noop_classifier
    )
    assert resolve_tier("vetted", policy) == "vetted"
    assert resolve_tier("registered", policy) == "registered"


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
    """Reject missing or unknown mandatory tiers without echoing their values."""
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
    """Keep or tighten valid source tiers against their ceiling."""
    policy = SourcePolicy(
        name="source-b",
        max_visibility=ceiling,
        classify_access=_noop_classifier,
    )
    assert resolve_required_source_tier(record_tier, policy) == expected


def test_source_policy_is_frozen():
    """Reject SourcePolicy mutation with FrozenInstanceError."""
    policy = SourcePolicy(
        name="swissubase", max_visibility="registered", classify_access=_noop_classifier
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.max_visibility = "public"


class TestSwissubaseAccessClassification:
    """OAI access labels use an explicit local mapping and conservative fallback."""

    @pytest.mark.parametrize(
        ("license_val", "expected"),
        [
            ("Restricted access", "restricted"),
            ("RESTRICTED ACCESS: contact the depositor", "restricted"),
            ("License CC BY", "public"),
            (None, "restricted"),
        ],
        ids=[
            "exact-restricted-access",
            "unknown-label-is-restricted",
            "explicit-local-public-label",
            "missing-license-is-restricted",
        ],
    )
    def test_classifies_by_explicit_mapping(self, license_val, expected):
        """Only exact public labels map to public; unknown/missing stays restricted."""
        assert classify_oai_access(license_val) == expected

    def test_source_policy_requires_explicit_classifier(self):
        """Every source must supply its own resource-access classifier."""
        with pytest.raises(TypeError):
            SourcePolicy(name="source-b", max_visibility="vetted")


def test_public_discovery_fields_are_explicit_and_stable():
    """Keep the exact reviewed set of below-tier discovery fields."""
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
    """Limit below-tier search to discovery title and access level."""
    assert frozenset({"title", "access_level"}) == datasets.PUBLIC_SEARCH_FIELDS
    assert datasets.PUBLIC_SEARCH_FIELDS <= datasets.PUBLIC_DISCOVERY_FIELDS


def test_schema_contract_public_search_assignment_matches_policy():
    """Build public search text from exactly PUBLIC_SEARCH_FIELDS."""
    function_source = FUNCTION_CONTRACTS["update_search_text()"].source
    _, separator, after_assignment = function_source.partition("NEW.search_text_public :=")
    assert separator, "schema contract no longer assigns search_text_public"
    public_assignment, terminator, _ = after_assignment.partition(";")
    assert terminator, "search_text_public assignment is not terminated"

    referenced_fields = frozenset(re.findall(r"NEW\.([a-z_]+)", public_assignment))
    assert referenced_fields == datasets.PUBLIC_SEARCH_FIELDS


def test_filter_for_tier_at_or_above_returns_same_object():
    """Return the original dataset when no field requires redaction."""
    ds_registered = make_full_dataset(visibility_tier="registered")
    assert (
        filter_for_tier(ds_registered, "registered", configured_sources=_SOURCES) is ds_registered
    )
    assert filter_for_tier(ds_registered, "vetted", configured_sources=_SOURCES) is ds_registered


def test_filter_for_tier_below_returns_new_redacted_dataset():
    """Copy below-tier datasets, preserving discovery fields and clearing private fields."""
    ds = make_full_dataset(visibility_tier="vetted")
    redacted = filter_for_tier(ds, "public", configured_sources=_SOURCES)

    assert redacted is not ds
    assert isinstance(redacted, Dataset)

    expected_visible = datasets.PUBLIC_DISCOVERY_FIELDS

    expected_redacted = datasets._redacted_values()
    for f in dataclass_fields(Dataset):
        if f.name in expected_visible:
            assert getattr(redacted, f.name) == getattr(ds, f.name), f.name
        else:
            assert getattr(redacted, f.name) == expected_redacted[f.name], f.name

    assert redacted.authors == []
    assert redacted.keywords == []
    assert redacted.languages == []
    assert redacted.description is None
    assert redacted.doi is None
    assert ds.description == "Long description"
    assert ds.authors == [Author(name="A. Author")]


def test_filter_for_tier_redacted_lists_are_not_shared():
    """Allocate independent empty lists for each redacted dataset."""
    ds_a = make_full_dataset(id=1, uuid="uuid-a", visibility_tier="vetted")
    ds_b = make_full_dataset(id=2, uuid="uuid-b", visibility_tier="vetted")

    red_a = filter_for_tier(ds_a, "public", configured_sources=_SOURCES)
    red_b = filter_for_tier(ds_b, "public", configured_sources=_SOURCES)

    red_a.languages.append("Klingon")

    assert red_a.languages == ["Klingon"]
    assert red_b.languages == []
    red_a.keywords.append("leak")
    red_a.authors.append(Author(name="Mallory"))
    assert red_b.keywords == []
    assert red_b.authors == []


def test_assert_field_visibility_total_passes_today():
    """Classify every Dataset field in exactly one disclosure set."""
    datasets.assert_field_visibility_total()


def test_assert_field_visibility_total_detects_overlap(monkeypatch):
    """Name fields present in both disclosure sets."""
    monkeypatch.setattr(
        datasets,
        "PUBLIC_DISCOVERY_FIELDS",
        datasets.PUBLIC_DISCOVERY_FIELDS | {"description"},
    )
    with pytest.raises(
        AssertionError,
        match=r"in both sets.*description",
    ):
        datasets.assert_field_visibility_total()


def test_assert_field_visibility_total_detects_unapproved_public_search_field(monkeypatch):
    """Reject public-search fields outside the discovery set."""
    monkeypatch.setattr(
        datasets,
        "PUBLIC_SEARCH_FIELDS",
        datasets.PUBLIC_SEARCH_FIELDS | {"description"},
    )
    with pytest.raises(
        AssertionError,
        match=r"publicly searchable but not public-discovery fields.*description",
    ):
        datasets.assert_field_visibility_total()


def test_assert_field_visibility_total_detects_unclassified_field(monkeypatch):
    """Name Dataset fields missing from both disclosure sets."""
    original = datasets._redacted_values

    def redacted_minus_doi():
        """Return the redaction map without DOI classification."""
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
        datasets.assert_field_visibility_total()


def test_assert_field_visibility_total_detects_stale_classified_name(monkeypatch):
    """Reject classification names absent from Dataset."""
    original = datasets._redacted_values

    def redacted_with_typo():
        """Return a redaction map with a misspelled license field."""
        values = original()
        values["licence_val"] = values.pop("license_val")
        return values

    spy = create_autospec(datasets._redacted_values, spec_set=True)
    spy.side_effect = redacted_with_typo
    monkeypatch.setattr(datasets, "_redacted_values", spy)
    with pytest.raises(
        AssertionError,
        match=r"not Dataset fields.*licence_val",
    ):
        datasets.assert_field_visibility_total()


def test_assert_tier_rank_complete_passes_today():
    """Assign a rank to every declared access tier."""
    access_tiers.assert_tier_rank_complete()


def test_assert_tier_rank_complete_detects_unranked_tier(monkeypatch):
    """Reject a declared tier missing from the rank map."""
    monkeypatch.setattr(
        access_tiers,
        "_TIER_RANK",
        {"public": 0, "registered": 1},
    )
    with pytest.raises(AssertionError, match=r"unranked.*vetted"):
        access_tiers.assert_tier_rank_complete()


def test_assert_tier_rank_complete_detects_ranked_but_undeclared(monkeypatch):
    """Reject a ranked tier absent from the declared tier type."""
    monkeypatch.setattr(
        access_tiers,
        "_TIER_RANK",
        {"public": 0, "registered": 1, "vetted": 2, "superuser": 3},
    )
    with pytest.raises(AssertionError, match=r"ranked but not declared.*superuser"):
        access_tiers.assert_tier_rank_complete()


def test_every_dataset_read_path_funnels_through_filter_for_tier():
    """Require every tier-aware dataset read to invoke field redaction."""
    AGGREGATE_CHANNELS = {
        "count_search_datasets",  # exact scalar count; field gates are applied in SQL
        "get_facets",  # returns value lists; tier-scoped via TIER_CASE_SQL
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
