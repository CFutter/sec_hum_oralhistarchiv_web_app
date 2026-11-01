"""Resource redirect auditing is explicit source configuration, separate from ingestion."""

import base64
import hashlib

import pytest
from pydantic import ValidationError

from app.sources import (
    JsonFeedConfig,
    configure_sources,
    load_sources_for_startup,
    parse_source_config,
    prepare_json_feed_startup,
)

_ADAPTERS = ("oai_pmh_cmdi", "fixture", "static_json", "json_feed")
_ENVIRONMENT = {
    "RESOURCE_FEED_BEARER": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
    "RESOURCE_FEED_SIGNING_KEY": base64.urlsafe_b64encode(
        hashlib.sha256(b"synthetic resource logging configuration key").digest()
    )
    .decode("ascii")
    .rstrip("="),
}


def _values(adapter):
    """Build adapter-specific source settings with the required endpoint and credential names."""
    values = {
        "name": "resource_archive",
        "adapter": adapter,
        "display": {"label": "Resource archive"},
    }
    if adapter == "oai_pmh_cmdi":
        values.update(
            endpoint="https://archive.example.edu/oai", institution_filter="Example University"
        )
    elif adapter == "json_feed":
        values.update(
            endpoint="https://archive.example.edu/feed",
            credential_env="RESOURCE_FEED_BEARER",
            signing_key_env="RESOURCE_FEED_SIGNING_KEY",
        )
    return values


def _source(config):
    """Prepare feed credentials if needed and configure the selected source."""
    credentials = prepare_json_feed_startup(
        (config,) if isinstance(config, JsonFeedConfig) else (),
        environment="dev",
        environ=_ENVIRONMENT,
    )
    return configure_sources((config,), credentials=credentials)[0]


@pytest.mark.parametrize(
    ("adapter", "required"),
    [
        ("oai_pmh_cmdi", False),
        ("fixture", False),
        ("fixture", True),
        ("static_json", False),
        ("static_json", True),
        ("json_feed", True),
    ],
)
def test_resource_logging_default_uses_the_resolved_record_tier_policy(adapter, required):
    """Check resource logging default uses the resolved record tier policy."""
    values = _values(adapter)
    # The true fixture/static/JSON and false OAI cases exercise adapter defaults.
    if required != (adapter != "oai_pmh_cmdi"):
        values["requires_record_tier"] = required
    config = parse_source_config(values)
    assert config.requires_record_tier is required
    assert config.log_resource_access is required
    assert config.model_dump()["log_resource_access"] is required
    source = _source(config)
    assert source.config.log_resource_access is source.log_resource_access is required


@pytest.mark.parametrize("adapter", _ADAPTERS)
@pytest.mark.parametrize("enabled", [False, True])
def test_explicit_resource_logging_override_survives_construction_without_rebinding(
    adapter, enabled
):
    """Check explicit resource logging override survives construction without rebinding."""
    source = _source(parse_source_config({**_values(adapter), "log_resource_access": enabled}))
    other = _source(parse_source_config({**_values(adapter), "log_resource_access": not enabled}))
    assert source.log_resource_access is enabled
    assert source.config.model_dump()["log_resource_access"] is enabled
    assert other.log_resource_access is not enabled
    assert source.adapter.config_fingerprint() == other.adapter.config_fingerprint()


@pytest.mark.parametrize("adapter", _ADAPTERS)
@pytest.mark.parametrize("invalid", [None, 0, 1, "true", "false"])
def test_resource_logging_accepts_only_explicit_booleans(adapter, invalid):
    """Check resource logging accepts only explicit booleans (ValidationError)."""
    with pytest.raises(ValidationError):
        parse_source_config({**_values(adapter), "log_resource_access": invalid})


@pytest.mark.parametrize("adapter", _ADAPTERS)
@pytest.mark.parametrize("enabled", [False, True])
def test_flat_startup_file_preserves_the_resource_logging_override(tmp_path, adapter, enabled):
    """Check flat startup file preserves the resource logging override."""
    values = _values(adapter)
    values.pop("display")
    document = "[[sources]]\nlabel = 'Resource archive'\n"
    document += "".join(f"{name} = {value!r}\n" for name, value in values.items())
    document += f"log_resource_access = {str(enabled).lower()}\n"
    path = tmp_path / "sources.toml"
    path.write_text(document, encoding="utf-8")
    source = load_sources_for_startup(path, environment="dev", environ=_ENVIRONMENT)[0]
    assert source.log_resource_access is enabled
    assert source.config.model_dump()["log_resource_access"] is enabled
