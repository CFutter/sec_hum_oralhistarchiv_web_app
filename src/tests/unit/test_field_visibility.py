"""The field matrix adds minimum tiers without relaxing record restrictions."""

import inspect
from dataclasses import asdict, fields
from types import MappingProxyType
from typing import Any, cast

import pytest

from app import services
from app.services import datasets
from app.services.datasets import Author, Dataset
from tests.source_fixtures import legacy_source

_TIERS = ("public", "registered", "vetted")
_SOURCES = (legacy_source(name="matrix_archive", max_visibility="public"),)
_LINK_FIELDS = ("resource_proxies", "resource_access_url", "landing_page_url")


def _dataset(**changes):
    """Return a public sample carrying private canaries and explicit field overrides."""
    values: dict[str, Any] = {
        "id": 7,
        "uuid": "field-matrix-record",
        "title": "Approved public discovery title",
        "source": "matrix_archive",
        "visibility_tier": "public",
        "description": "DESCRIPTION-PRIVATE-MARKER",
        "languages": ["LANGUAGE-PRIVATE-MARKER"],
        "keywords": ["KEYWORD-PRIVATE-MARKER"],
        "authors": [Author(name="AUTHOR-PRIVATE-MARKER")],
        "resource_proxies": [
            {"type": "Resource", "ref": "https://archive.example.org/private/resource"}
        ],
        "resource_access_url": "https://archive.example.org/private/resource",
        "landing_page_url": "https://archive.example.org/private/landing",
    }
    return Dataset(**(values | changes))


def _matrix(monkeypatch, **changes):
    """Patch an immutable field-visibility map and return the merged policy."""
    policy = dict(datasets.FIELD_VISIBILITY) | changes
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", MappingProxyType(policy))
    return policy


def _raised_matrix(monkeypatch):
    """Require registered description/languages and vetted keywords/resource links."""
    return _matrix(
        monkeypatch,
        description="registered",
        languages="registered",
        keywords="vetted",
        **dict.fromkeys(_LINK_FIELDS, "vetted"),
    )


def test_shipped_field_matrix_is_total_immutable_and_preserves_existing_disclosures():
    """The foundation introduces no newly public or newly hidden default field."""
    names = {field.name for field in fields(Dataset)}
    assert dict(datasets.FIELD_VISIBILITY) == dict.fromkeys(names, "public")
    assert datasets.PUBLIC_SEARCH_FIELDS <= datasets.PUBLIC_DISCOVERY_FIELDS
    assert all(
        datasets.FIELD_VISIBILITY[name] == "public" for name in datasets.PUBLIC_SEARCH_FIELDS
    )
    with pytest.raises(TypeError):
        cast("dict[str, str]", datasets.FIELD_VISIBILITY)["description"] = "vetted"
    datasets.assert_field_visibility_total()


def test_field_visibility_api_uses_the_public_service_boundary_without_an_old_alias():
    """Field visibility API uses the public service boundary without an old alias."""
    for name in (
        "FIELD_VISIBILITY",
        "assert_field_visibility_total",
        "can_view_field",
        "field_required_tier",
    ):
        assert services.__all__.count(name) == 1
        assert getattr(services, name) is getattr(datasets, name)
    assert not hasattr(services, "assert_redaction_total")
    assert not hasattr(datasets, "assert_redaction_total")


@pytest.mark.parametrize(
    "api_name",
    [
        "can_view_field",
        "can_view_full",
        "count_search_datasets",
        "field_required_tier",
        "filter_for_tier",
        "full_required_tier",
        "get_dataset_by_id",
        "get_facets",
        "get_recent_datasets",
        "search_catalogue_page",
        "search_datasets",
    ],
)
def test_catalogue_policy_apis_require_an_explicit_source_snapshot(api_name):
    """Catalogue policy APIs require an explicit source snapshot."""
    parameter = inspect.signature(getattr(datasets, api_name)).parameters["configured_sources"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


@pytest.mark.parametrize("user_tier", _TIERS)
def test_raised_field_minima_redact_scalars_lists_and_every_link_representation(
    monkeypatch, user_tier
):
    """Raised field minima redact scalars lists and every link representation."""
    _raised_matrix(monkeypatch)
    original = _dataset()
    before = asdict(original)

    released = datasets.filter_for_tier(original, user_tier, configured_sources=_SOURCES)

    registered = _TIERS.index(user_tier) >= _TIERS.index("registered")
    vetted = user_tier == "vetted"
    assert released.description == (original.description if registered else None)
    assert released.languages == (original.languages if registered else [])
    assert released.keywords == (original.keywords if vetted else [])
    assert released.resource_proxies == (original.resource_proxies if vetted else [])
    assert released.resource_access_url == (original.resource_access_url if vetted else None)
    assert released.landing_page_url == (original.landing_page_url if vetted else None)
    assert released.authors == original.authors
    assert released.title == original.title
    assert datasets.can_view_full(original, user_tier, configured_sources=_SOURCES) is vetted
    assert (released is original) is vetted
    assert asdict(original) == before


@pytest.mark.parametrize("record_tier", _TIERS)
def test_record_or_effective_admin_tier_remains_a_floor_for_every_private_field(
    monkeypatch, record_tier
):
    """Dataset.visibility_tier already includes a committed administrator floor."""
    policy = _raised_matrix(monkeypatch)
    dataset = _dataset(visibility_tier=record_tier)
    for field in fields(Dataset):
        minimum = policy[field.name]
        required = (
            "public"
            if field.name in datasets.PUBLIC_DISCOVERY_FIELDS
            else max((record_tier, minimum), key=_TIERS.index)
        )
        assert (
            datasets.field_required_tier(dataset, field.name, configured_sources=_SOURCES)
            == required
        )
        for viewer in _TIERS:
            assert datasets.can_view_field(
                dataset, viewer, field.name, configured_sources=_SOURCES
            ) is (_TIERS.index(viewer) >= _TIERS.index(required))


def test_repeated_partial_redaction_has_fresh_hidden_lists(monkeypatch):
    """Repeated partial redaction has fresh hidden lists."""
    _raised_matrix(monkeypatch)
    original = _dataset()
    first = datasets.filter_for_tier(original, "public", configured_sources=_SOURCES)
    second = datasets.filter_for_tier(original, "public", configured_sources=_SOURCES)
    first.languages.append("LOCAL-MUTATION")
    first.keywords.append("LOCAL-MUTATION")
    first.resource_proxies.append({"ref": "LOCAL-MUTATION"})
    assert second.languages == second.keywords == second.resource_proxies == []
    assert original.languages == ["LANGUAGE-PRIVATE-MARKER"]
    assert original.keywords == ["KEYWORD-PRIVATE-MARKER"]
    assert len(original.resource_proxies) == 1


@pytest.mark.parametrize("field_name", ("unknown_field", "", None, 1, [], {}))
def test_field_helpers_reject_unknown_field_names(field_name):
    """Field helpers reject unknown field names."""
    dataset = _dataset()
    with pytest.raises(ValueError):
        datasets.field_required_tier(dataset, field_name, configured_sources=_SOURCES)
    with pytest.raises(ValueError):
        datasets.can_view_field(dataset, "vetted", field_name, configured_sources=_SOURCES)


@pytest.mark.parametrize("invalid", (None, "unknown", 0, True))
def test_field_helpers_fail_closed_on_invalid_minimum_tiers(monkeypatch, invalid):
    """Field helpers fail closed on invalid minimum tiers."""
    _matrix(monkeypatch, description=invalid)
    dataset = _dataset()
    with pytest.raises(ValueError):
        datasets.field_required_tier(dataset, "description", configured_sources=_SOURCES)
    with pytest.raises(ValueError):
        datasets.can_view_field(dataset, "vetted", "description", configured_sources=_SOURCES)
    with pytest.raises(ValueError):
        datasets.filter_for_tier(dataset, "vetted", configured_sources=_SOURCES)


def test_field_helpers_fail_closed_when_a_matrix_entry_is_missing(monkeypatch):
    """Field helpers fail closed when a matrix entry is missing."""
    policy = dict(datasets.FIELD_VISIBILITY)
    del policy["description"]
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", MappingProxyType(policy))
    with pytest.raises(ValueError):
        datasets.field_required_tier(_dataset(), "description", configured_sources=_SOURCES)
    with pytest.raises(ValueError):
        datasets.filter_for_tier(_dataset(), "vetted", configured_sources=_SOURCES)


@pytest.mark.parametrize("invalid", (None, "unknown", 0, True))
def test_field_helpers_reject_invalid_record_or_viewer_tiers(invalid):
    """Field helpers reject invalid record or viewer tiers."""
    with pytest.raises(ValueError):
        datasets.field_required_tier(
            _dataset(visibility_tier=invalid), "description", configured_sources=_SOURCES
        )
    with pytest.raises(ValueError):
        datasets.can_view_field(_dataset(), invalid, "description", configured_sources=_SOURCES)


@pytest.mark.parametrize("field_name", ("description", "title", "resource_proxies"))
def test_startup_rejects_missing_matrix_entries(monkeypatch, field_name):
    """Startup rejects missing matrix entries."""
    policy = dict(datasets.FIELD_VISIBILITY)
    del policy[field_name]
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", MappingProxyType(policy))
    with pytest.raises(AssertionError, match=field_name):
        datasets.assert_field_visibility_total()


def test_startup_rejects_unknown_matrix_fields(monkeypatch):
    """Startup rejects unknown matrix fields."""
    _matrix(monkeypatch, unexpected_field="vetted")
    with pytest.raises(AssertionError, match="unexpected_field"):
        datasets.assert_field_visibility_total()


@pytest.mark.parametrize("invalid", (None, [], "invalid", 1))
def test_startup_rejects_a_matrix_that_is_not_a_mapping(monkeypatch, invalid):
    """Startup rejects a matrix that is not a mapping."""
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", invalid)
    with pytest.raises(AssertionError, match="mapping"):
        datasets.assert_field_visibility_total()


@pytest.mark.parametrize("invalid_name", (None, 0, True, ("description",)))
def test_startup_rejects_nonstring_matrix_keys(monkeypatch, invalid_name):
    """Startup rejects nonstring matrix keys."""
    policy = dict(datasets.FIELD_VISIBILITY)
    policy[invalid_name] = "public"
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", MappingProxyType(policy))
    with pytest.raises(AssertionError, match="invalid matrix field names"):
        datasets.assert_field_visibility_total()


@pytest.mark.parametrize("invalid", (None, "unknown", 0, True))
def test_startup_rejects_invalid_matrix_tiers(monkeypatch, invalid):
    """Startup rejects invalid matrix tiers."""
    _matrix(monkeypatch, description=invalid)
    with pytest.raises(AssertionError, match="description"):
        datasets.assert_field_visibility_total()


@pytest.mark.parametrize("field_name", ("title", "access_level", "uuid"))
def test_startup_and_field_helpers_refuse_nonpublic_discovery_minima(monkeypatch, field_name):
    """Startup and field helpers refuse nonpublic discovery minima."""
    _matrix(monkeypatch, **{field_name: "registered"})
    with pytest.raises(AssertionError, match=field_name):
        datasets.assert_field_visibility_total()
    with pytest.raises(ValueError):
        datasets.field_required_tier(_dataset(), field_name, configured_sources=_SOURCES)


@pytest.mark.parametrize("field_name", _LINK_FIELDS)
def test_startup_rejects_inconsistent_resource_url_group_minima(monkeypatch, field_name):
    """Startup rejects inconsistent resource URL group minima."""
    _matrix(monkeypatch, **{field_name: "vetted"})
    with pytest.raises(AssertionError, match="resource"):
        datasets.assert_field_visibility_total()


def test_startup_accepts_stricter_private_minima_with_an_aligned_resource_group(monkeypatch):
    """Startup accepts stricter private minima with an aligned resource group."""
    _raised_matrix(monkeypatch)
    datasets.assert_field_visibility_total()
