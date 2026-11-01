"""Source field restrictions are immutable, validated and independent of ingestion."""

import base64
import hashlib
import pickle
from types import MappingProxyType
from typing import Any, cast

import pytest
from pydantic import ValidationError

from app.field_visibility import PUBLIC_DISCOVERY_FIELDS, RESOURCE_URL_FIELDS
from app.sources import (
    JsonFeedConfig,
    configure_sources,
    load_sources_for_startup,
    parse_source_config,
    prepare_json_feed_startup,
)
from app.sources import base as source_base

_ADAPTERS = ("oai_pmh_cmdi", "fixture", "static_json", "json_feed")
_ENVIRONMENT = {
    "FIELD_FEED_BEARER": "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
    "FIELD_FEED_SIGNING_KEY": base64.urlsafe_b64encode(
        hashlib.sha256(b"synthetic source field visibility configuration key").digest()
    )
    .decode("ascii")
    .rstrip("="),
}


def _values(adapter):
    """Build adapter-specific source settings with the required endpoint and credential names."""
    values: dict[str, Any] = {
        "name": "field_archive",
        "adapter": adapter,
        "display": {"label": "Field archive"},
    }
    if adapter == "oai_pmh_cmdi":
        values.update(
            endpoint="https://archive.example.edu/oai", institution_filter="Example University"
        )
    elif adapter == "json_feed":
        values.update(
            endpoint="https://archive.example.edu/feed",
            credential_env="FIELD_FEED_BEARER",
            signing_key_env="FIELD_FEED_SIGNING_KEY",
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


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_source_field_visibility_defaults_to_an_immutable_empty_override(adapter):
    """Check source field visibility defaults to an immutable empty override (TypeError)."""
    config = parse_source_config(_values(adapter))
    assert config.field_visibility == {}
    assert config.model_dump()["field_visibility"] == {}
    with pytest.raises(TypeError):
        cast("dict[str, str]", config.field_visibility)["description"] = "vetted"
    assert _source(config).field_visibility == {}


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_source_overrides_survive_snapshots_without_changing_ingestion_binding(adapter):
    """Check source overrides survive snapshots without changing ingestion binding (TypeError)."""
    requested = {"description": "registered", "keywords": "vetted"}
    config = parse_source_config({**_values(adapter), "field_visibility": requested})
    requested["description"] = "public"
    source = _source(config)
    baseline = _source(parse_source_config(_values(adapter)))

    assert dict(config.field_visibility) == {"description": "registered", "keywords": "vetted"}
    assert dict(source.field_visibility) == dict(config.field_visibility)
    assert source.config is not config
    assert source.field_visibility is source.config.field_visibility
    assert source.adapter.config_fingerprint() == baseline.adapter.config_fingerprint()
    with pytest.raises(TypeError):
        cast("dict[str, str]", source.field_visibility)["description"] = "public"
    dumped = config.model_dump()
    assert dumped["field_visibility"] == dict(config.field_visibility)
    assert type(config).model_validate(dumped) == config
    assert type(config).model_validate_json(config.model_dump_json()) == config
    restored = pickle.loads(pickle.dumps(config))
    assert restored == config
    assert dict(restored.field_visibility) == dict(config.field_visibility)
    with pytest.raises(TypeError):
        restored.field_visibility["description"] = "public"


@pytest.mark.parametrize("adapter", _ADAPTERS)
def test_flat_startup_file_retains_field_visibility_overrides(tmp_path, adapter):
    """Check flat startup file retains field visibility overrides."""
    values = _values(adapter)
    values.pop("display")
    document = "[[sources]]\nlabel = 'Field archive'\n"
    document += "".join(f"{name} = {value!r}\n" for name, value in values.items())
    document += "field_visibility = { description = 'registered', languages = 'vetted' }\n"
    path = tmp_path / "sources.toml"
    path.write_text(document, encoding="utf-8")

    source = load_sources_for_startup(path, environment="dev", environ=_ENVIRONMENT)[0]

    assert dict(source.field_visibility) == {"description": "registered", "languages": "vetted"}


@pytest.mark.parametrize(
    "invalid",
    (
        None,
        True,
        0,
        [],
        "description=vetted",
        {"description": None},
        {"description": 1},
        {"description": True},
        {"description": "VETTED"},
        {"description": "vetted "},
        {"description": "unknown"},
        {1: "vetted"},
        {True: "vetted"},
    ),
)
def test_source_field_visibility_rejects_nonmapping_or_noncanonical_input(invalid):
    """Check source field visibility rejects nonmapping or noncanonical input (ValidationError)."""
    with pytest.raises(ValidationError):
        parse_source_config({**_values("fixture"), "field_visibility": invalid})


@pytest.mark.parametrize("field_name", ("unknown_field", "description ", "Description", ""))
def test_source_field_visibility_rejects_unknown_field_names(field_name):
    """Check source field visibility rejects unknown field names (ValidationError)."""
    with pytest.raises(ValidationError, match="Unknown field visibility overrides"):
        parse_source_config({**_values("fixture"), "field_visibility": {field_name: "vetted"}})


@pytest.mark.parametrize("field_name", sorted(PUBLIC_DISCOVERY_FIELDS))
@pytest.mark.parametrize("minimum", ("registered", "vetted"))
def test_source_field_visibility_cannot_restrict_the_approved_public_envelope(field_name, minimum):
    """Check source field visibility cannot restrict the approved public envelope (ValidationError)."""
    with pytest.raises(ValidationError, match="Public discovery field"):
        parse_source_config({**_values("fixture"), "field_visibility": {field_name: minimum}})


def test_equal_public_envelope_overrides_are_valid_noops():
    """Check equal public envelope overrides are valid noops."""
    overrides = dict.fromkeys(PUBLIC_DISCOVERY_FIELDS, "public")
    config = parse_source_config({**_values("fixture"), "field_visibility": overrides})
    assert dict(config.field_visibility) == overrides


@pytest.mark.parametrize("field_name", sorted(RESOURCE_URL_FIELDS))
@pytest.mark.parametrize("minimum", ("registered", "vetted"))
def test_source_resource_overrides_cannot_leave_a_less_restricted_url_copy(field_name, minimum):
    """Check source resource overrides cannot leave a less restricted URL copy (ValidationError)."""
    with pytest.raises(ValidationError, match="Resource URL fields require equal"):
        parse_source_config({**_values("fixture"), "field_visibility": {field_name: minimum}})


@pytest.mark.parametrize("minimum", ("public", "registered", "vetted"))
def test_source_resource_overrides_can_raise_all_url_representations_together(minimum):
    """Check source resource overrides can raise all URL representations together."""
    overrides = dict.fromkeys(RESOURCE_URL_FIELDS, minimum)
    config = parse_source_config({**_values("fixture"), "field_visibility": overrides})
    assert dict(_source(config).field_visibility) == overrides


@pytest.mark.parametrize("code_minimum", ("registered", "vetted"))
@pytest.mark.parametrize("override", ("public", "registered", "vetted"))
def test_source_field_visibility_can_only_equal_or_raise_the_code_minimum(
    monkeypatch, code_minimum, override
):
    """Check source field visibility can only equal or raise the code minimum (ValidationError)."""
    matrix = dict(source_base.FIELD_VISIBILITY) | {"description": code_minimum}
    monkeypatch.setattr(source_base, "FIELD_VISIBILITY", MappingProxyType(matrix))
    values = {**_values("fixture"), "field_visibility": {"description": override}}
    ranks = {"public": 0, "registered": 1, "vetted": 2}
    if ranks[override] < ranks[code_minimum]:
        with pytest.raises(ValidationError, match="loosens the code minimum"):
            parse_source_config(values)
    else:
        assert parse_source_config(values).field_visibility["description"] == override


def test_source_construction_revalidates_a_bypassed_model_copy():
    """Check source construction revalidates a bypassed model copy (ValidationError)."""
    original = parse_source_config(_values("fixture"))
    changed = original.model_copy(update={"field_visibility": {"unknown_field": "vetted"}})
    with pytest.raises(ValidationError, match="Unknown field visibility overrides"):
        _source(changed)
