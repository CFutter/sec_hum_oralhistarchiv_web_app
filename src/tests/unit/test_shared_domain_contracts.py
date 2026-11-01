"""Shared facts must stay consistent across lexical, service and SQL boundaries."""

import importlib.util
from types import MappingProxyType

import pytest

from app import SEARCH_FUNCTION_SOURCES
from app.ingestion_contracts import ACCESS_TIER_RANK
from app.paths import PROJECT_ROOT
from app.services import access_tiers
from app.source_contract import SOURCE_NAME_PATTERN
from app.sources import SourceConfig, json_feed_pages, json_feed_records
from app.sources.json_feed_lexical import FEED_UTC_SECOND_PATTERN, FEED_UUID_PATTERN


def _checker():
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location(
        "shared_domain_check", PROJECT_ROOT / "scripts/check_domain_contracts.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_ranks_and_feed_lexicals_have_one_immutable_definition():
    """Check shared ranks and feed lexicals have one immutable definition."""
    assert access_tiers._TIER_RANK is ACCESS_TIER_RANK
    assert isinstance(ACCESS_TIER_RANK, MappingProxyType)
    assert json_feed_pages.FEED_UUID_PATTERN is FEED_UUID_PATTERN
    assert json_feed_records.FEED_UUID_PATTERN is FEED_UUID_PATTERN
    assert json_feed_pages.FEED_UTC_SECOND_PATTERN is FEED_UTC_SECOND_PATTERN
    assert json_feed_records.FEED_UTC_SECOND_PATTERN is FEED_UTC_SECOND_PATTERN


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("x", True),
        ("valid_name1", True),
        ("a" * 32, True),
        ("", False),
        ("a" * 33, False),
        ("A", False),
        ("a\n", False),
        ("a-b", False),
    ],
    ids=["x", "valid_name1", "a" * 32, "", "a" * 33, "A", "a\n", "a-b"],
)
def test_source_model_uses_the_same_lexical_boundary(name, valid):
    """Explicit boundary outcomes catch a shared regex/model defect, not just disagreement."""
    values = {"name": name, "adapter": "fixture", "display": {"label": "Example"}}
    assert bool(SOURCE_NAME_PATTERN.fullmatch(name)) is valid
    if valid:
        assert SourceConfig.model_validate(values).name == name
    else:
        with pytest.raises(ValueError):
            SourceConfig.model_validate(values)


def _sql_sources():
    """Return the three canonical catalogue-search function bodies used by the contract checks."""
    return (
        SEARCH_FUNCTION_SOURCES["catalogue_refresh_search_record(p_id integer)"],
        SEARCH_FUNCTION_SOURCES[
            "catalogue_replace_search_policy(p_expected text, p_fingerprint text, p_masks jsonb)"
        ],
        SEARCH_FUNCTION_SOURCES["catalogue_search_relation(p_query jsonb)"],
    )


def test_current_sql_matches_shared_rank_and_source_facts():
    """Check current SQL matches shared rank and source facts."""
    _checker().verify_domain_sql(*_sql_sources())


@pytest.mark.parametrize(
    "change", ["rank", "tier", "source", "audience_order", "audience_allowlist"]
)
def test_authoring_gate_rejects_independently_changed_sql(change):
    """Check authoring gate rejects independently changed SQL (ValueError)."""
    projection, policy, relation = _sql_sources()
    if change == "rank":
        projection = projection.replace("WHEN 'registered' THEN 1", "WHEN 'registered' THEN 9")
    elif change == "tier":
        projection = projection.replace("WHEN 'vetted' THEN 2", "WHEN 'retired' THEN 2")
    elif change == "source":
        policy = policy.replace("^[a-z0-9_]{1,32}$", "^[a-z]{1,32}$")
    elif change == "audience_order":
        projection = projection.replace(
            "ARRAY['public', 'registered', 'vetted']", "ARRAY['public', 'vetted', 'registered']"
        )
    else:
        relation = relation.replace(
            "audience NOT IN ('public', 'registered', 'vetted')",
            "audience NOT IN ('public', 'registered')",
        )
    assert (projection, policy, relation) != _sql_sources()
    with pytest.raises(ValueError):
        _checker().verify_domain_sql(projection, policy, relation)
