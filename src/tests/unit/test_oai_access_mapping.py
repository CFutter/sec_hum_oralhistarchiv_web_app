"""Exact local OAI label mapping, independent of metadata visibility."""

import operator
from types import MappingProxyType

import pytest

from app.sources import OaiPmhCmdiConfig, configure_sources
from app.sources import oai_pmh_cmdi as oai
from app.sources.fixture import classify_fixture_access
from app.sources.json_feed import classify_json_feed_access
from app.sources.static_json import classify_static_json_access


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Public access", "public"),
        ("License CC BY", "public"),
        ("CC BY 4.0", "public"),
        ("Restricted access", "restricted"),
    ],
)
def test_exact_local_oai_labels(raw, expected):
    """Check exact local OAI labels."""
    assert oai.classify_oai_access(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        " ",
        "public access",
        "PUBLIC ACCESS",
        " Public access",
        "Public access ",
        "Public access extra",
        "License CC BY 4.0",
        "cc by 4.0",
        "CC BY 4.0; private agreement",
        "Open Access",
        "Restricted access (special agreement)",
        "UNREVIEWED-CANARY",
    ],
)
def test_unknown_and_missing_oai_labels_are_restricted(raw):
    """Check unknown and missing OAI labels are restricted."""
    assert oai.classify_oai_access(raw) == "restricted"


@pytest.mark.parametrize(
    "raw", [False, 0, b"Public access", ["Public access"], {"label": "PRIVATE-CANARY"}]
)
def test_wrong_oai_label_type_has_fixed_metadata_free_error(raw):
    """Check wrong OAI label type has fixed metadata free error (TypeError)."""
    with pytest.raises(TypeError) as error:
        oai.classify_oai_access(raw)
    assert str(error.value) == "OAI access label must be text or None"
    assert "PRIVATE-CANARY" not in str(error.value)


def test_oai_access_mapping_cannot_be_mutated_in_place():
    """Check OAI access mapping cannot be mutated in place (TypeError)."""
    assert isinstance(oai.OAI_ACCESS_LABELS, MappingProxyType)
    with pytest.raises(TypeError):
        operator.setitem(oai.OAI_ACCESS_LABELS, "Public access", "restricted")
    assert oai.classify_oai_access("Public access") == "public"


def configured_source(**overrides):
    """Validate and configure a sample OAI source with caller overrides."""
    values = {
        "name": "mapping_archive",
        "display": {"label": "Mapping archive"},
        "endpoint": "https://archive.example.org/oai",
        "institution_filter": "Example institution",
        "max_visibility": "registered",
    }
    values.update(overrides)
    return configure_sources([OaiPmhCmdiConfig.model_validate(values)])[0]


@pytest.mark.parametrize("binding", ["mapping", "fallback"])
def test_mapping_and_fallback_are_interpretation_bindings(monkeypatch, binding):
    """Check mapping and fallback are interpretation bindings."""
    source = configured_source()
    before = source.adapter.config_fingerprint()
    if binding == "mapping":
        monkeypatch.setattr(
            oai,
            "OAI_ACCESS_LABELS",
            MappingProxyType(dict(oai.OAI_ACCESS_LABELS) | {"New local label": "restricted"}),
        )
    else:
        monkeypatch.setattr(oai, "OAI_UNKNOWN_ACCESS_LEVEL", "public")
    assert source.adapter.config_fingerprint() != before


def test_configured_oai_classifier_preserves_the_source_visibility_floor():
    """Check configured OAI classifier preserves the source visibility floor."""
    source = configured_source(requires_record_tier=False)
    assert source.policy.max_visibility == "registered"
    assert source.policy.requires_record_tier is False
    assert source.policy.classify_access("Public access") == "public"
    assert source.policy.classify_access(None) == "restricted"
    assert source.policy.max_visibility == "registered" and not source.policy.requires_record_tier


@pytest.mark.parametrize("classifier", [classify_fixture_access, classify_static_json_access])
def test_bundled_adapter_contracts_remain_exact_and_conservative(classifier):
    """Check bundled adapter contracts remain exact and conservative."""
    assert classifier("Public access") == "public"
    assert classifier("Restricted access") == "restricted"
    assert classifier("CC BY 4.0") == "restricted"
    assert classifier(None) == "restricted"


def test_json_feed_contract_remains_strict_and_does_not_inherit_oai_aliases():
    """Check JSON feed contract remains strict and does not inherit OAI aliases."""
    assert classify_json_feed_access("Public access") == "public"
    assert classify_json_feed_access("Restricted access") == "restricted"
    for raw in ("License CC BY", "CC BY 4.0", "Public access "):
        with pytest.raises(ValueError, match="outside the reviewed mapping"):
            classify_json_feed_access(raw)
    with pytest.raises(TypeError, match="access label must be text"):
        classify_json_feed_access(None)
