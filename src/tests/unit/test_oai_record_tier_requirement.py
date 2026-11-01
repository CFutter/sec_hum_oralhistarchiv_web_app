"""Reject unsupported OAI tier requirements before constructing or fetching a source."""

from dataclasses import replace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.sources import OaiPmhCmdiAdapter, OaiPmhCmdiConfig, load_sources_for_startup
from app.sources.configuration import configure_sources_from_toml
from tests.source_fixtures import fixture_source, legacy_source

_DOCUMENT = """[[sources]]
name = "valid_archive"
adapter = "oai_pmh_cmdi"
label = "Valid archive"
endpoint = "https://archive.example.org/oai"
institution_filter = "Example University"

[[sources]]
name = "invalid_archive"
adapter = "oai_pmh_cmdi"
label = "Invalid archive"
endpoint = "https://archive.example.org/oai"
institution_filter = "Example University"
requires_record_tier = true
"""


def test_default_and_explicit_false_construct_the_same_oai_policy():
    """Check default and explicit false construct the same OAI policy."""
    default = legacy_source()
    explicit = legacy_source(requires_record_tier=False)
    assert default.policy.requires_record_tier is False
    assert explicit.policy.requires_record_tier is False
    assert default.adapter.config_fingerprint() == explicit.adapter.config_fingerprint()


def test_true_is_rejected_with_an_adapter_specific_explanation():
    """Check true is rejected with an adapter specific explanation (ValidationError)."""
    with pytest.raises(ValidationError, match="requires_record_tier must be false"):
        legacy_source(requires_record_tier=True)


@pytest.mark.parametrize("invalid", [None, 0, 1, "false", "true", []])
def test_record_tier_requirement_remains_a_strict_boolean(invalid):
    """Check record tier requirement remains a strict boolean (ValidationError)."""
    with pytest.raises(ValidationError) as failure:
        legacy_source(requires_record_tier=invalid)
    assert any(error["loc"] == ("requires_record_tier",) for error in failure.value.errors())


@pytest.mark.parametrize("invalid", [True, None, 0, ""])
def test_direct_adapter_construction_rejects_unsupported_or_falsey_requirements(invalid):
    """Check direct adapter construction rejects unsupported or falsey requirements (ValueError)."""
    adapter = legacy_source().adapter
    policy = replace(adapter.policy, requires_record_tier=invalid)
    with pytest.raises(ValueError, match="requires_record_tier must be false"):
        OaiPmhCmdiAdapter(
            policy=policy,
            oai_url="https://archive.example.org/oai",
            institution_filter="Example University",
            max_pages=7,
        )


def test_unvalidated_model_copy_cannot_bypass_the_adapter_guard():
    """Check unvalidated model copy cannot bypass the adapter guard (ValueError)."""
    config = legacy_source().config
    assert isinstance(config, OaiPmhCmdiConfig)
    invalid = config.model_copy(update={"requires_record_tier": True})
    with pytest.raises(ValueError, match="requires_record_tier must be false"):
        OaiPmhCmdiAdapter.from_config(invalid)


@pytest.mark.parametrize("startup", [False, True], ids=["toml", "runtime-startup"])
def test_invalid_selection_fails_before_any_factory_or_transport(startup, tmp_path):
    """Check invalid selection fails before any factory or transport (ValidationError)."""
    path = tmp_path / "sources.toml"
    path.write_text(_DOCUMENT, encoding="utf-8")
    with (
        patch.object(OaiPmhCmdiAdapter, "from_config", autospec=True) as factory,
        patch("app.sources.oai_client.fetch_updates_isolated", autospec=True) as fetch,
        pytest.raises(ValidationError, match="requires_record_tier must be false"),
    ):
        if startup:
            load_sources_for_startup(path, environment="dev")
        else:
            configure_sources_from_toml(_DOCUMENT)
    factory.assert_not_called()
    fetch.assert_not_called()


def test_native_tier_capable_fixture_still_supports_a_mandatory_tier():
    """Check native tier capable fixture still supports a mandatory tier."""
    assert fixture_source(requires_record_tier=True).policy.requires_record_tier is True
