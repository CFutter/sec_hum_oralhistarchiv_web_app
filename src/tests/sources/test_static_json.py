"""Native-format and activation checks for the isolated static JSON proof."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.sources import (
    StaticJsonAdapter,
    StaticJsonConfig,
    configure_sources,
    validate_source_startup,
)


def _config(**overrides: object) -> StaticJsonConfig:
    """Validate a public-floor static JSON source configuration with supplied overrides."""
    values: dict[str, object] = {
        "name": "native_json_archive",
        "display": {"label": "Native JSON archive"},
        "max_visibility": "public",
    }
    values.update(overrides)
    return StaticJsonConfig.model_validate(values)


def _adapter(**overrides: object) -> StaticJsonAdapter:
    """Build the static JSON adapter from validated configuration overrides."""
    return StaticJsonAdapter.from_config(_config(**overrides))


def _document() -> dict[str, Any]:
    """Decode the packaged static JSON snapshot and require an object."""
    document = json.loads(_adapter().payload.decode("utf-8"))
    assert isinstance(document, dict)
    return document


def _document_adapter(document: object, *, requires_record_tier: bool = True) -> StaticJsonAdapter:
    """Replace the static adapter's payload with UTF-8 JSON for this test."""
    return replace(
        _adapter(requires_record_tier=requires_record_tier),
        payload=json.dumps(document, ensure_ascii=False).encode("utf-8"),
    )


def test_native_snapshot_translates_cursor_and_items() -> None:
    """Verify native snapshot translates cursor and items."""
    adapter = _adapter()
    document = json.loads(adapter.payload.decode("utf-8"))
    assert set(document) == {"cursor", "items"}
    assert "matching_records" not in document
    assert adapter.policy.requires_record_tier is True

    result = adapter.fetch(since=None)
    assert result.validate() == datetime(2020, 1, 4, tzinfo=UTC)
    assert result.matching_records[0]["uuid"] == document["items"][0]["uuid"]
    assert result.matching_records[0]["upstream_modified_at"] == datetime(
        2020, 1, 1, 12, tzinfo=UTC
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"dataset": "../outside"},
        {"endpoint": "https://archive.example.org/input.json"},
        {"max_bytes": True},
        {"max_bytes": 0},
        {"max_bytes": 1048577},
    ],
)
def test_config_rejects_unbounded_or_unrecognized_input(changes: dict[str, object]) -> None:
    """Verify config rejects unbounded or unrecognized input."""
    with pytest.raises(ValidationError):
        _config(**changes)


def test_factory_accepts_exact_byte_budget_and_rejects_one_byte_less() -> None:
    """Verify factory accepts exact byte budget and rejects one byte less."""
    payload = _adapter().payload
    assert len(payload) > 1
    assert _adapter(max_bytes=len(payload)).payload == payload
    with pytest.raises(ValueError, match="exceeds max_bytes"):
        _adapter(max_bytes=len(payload) - 1)


def test_direct_construction_rejects_mutable_payload() -> None:
    """Verify direct construction rejects mutable payload."""
    payload: Any = bytearray(_adapter().payload)
    with pytest.raises(TypeError, match="immutable bytes"):
        replace(_adapter(), payload=payload)


def test_direct_construction_retains_the_hard_byte_limit() -> None:
    """Verify direct construction retains the hard byte limit."""
    with pytest.raises(ValueError, match="1 MiB hard limit"):
        replace(_adapter(), payload=b" " * 1048577)


@pytest.mark.parametrize(
    "change", ["missing_cursor", "missing_items", "extra_field", "not_an_object"]
)
def test_native_envelope_requires_exact_fields(change: str) -> None:
    """Verify native envelope requires exact fields."""
    document = _document()
    native: object = document
    if change == "missing_cursor":
        del document["cursor"]
    elif change == "missing_items":
        del document["items"]
    elif change == "extra_field":
        document["unrecognized"] = True
    else:
        native = [document]
    with pytest.raises(ValueError, match="exactly cursor and items"):
        _document_adapter(native).fetch(since=None)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [("cursor", None, "cursor must be a string"), ("items", {}, "items must be a list")],
)
def test_native_envelope_rejects_wrong_types(field: str, value: object, message: str) -> None:
    """Verify native envelope rejects wrong types."""
    document = _document()
    document[field] = value
    with pytest.raises(TypeError, match=message):
        _document_adapter(document).fetch(since=None)


@pytest.mark.parametrize("cursor", ["not-a-timestamp", "2020-01-04", "2020-01-04T00:00:00"])
def test_native_cursor_requires_a_valid_aware_timestamp(cursor: str) -> None:
    """Verify native cursor requires a valid aware timestamp."""
    document = _document()
    document["cursor"] = cursor
    with pytest.raises(ValueError):
        _document_adapter(document).fetch(since=None)


@pytest.mark.parametrize(
    "modified", ["omitted", None, "2020-01-01T12:00:00", "2020-01-05T00:00:00Z"]
)
def test_native_records_require_aware_modification_times_within_the_cursor(
    modified: object,
) -> None:
    """Verify native records require aware modification times within the cursor."""
    document = _document()
    first = document["items"][0]
    if modified == "omitted":
        del first["upstream_modified_at"]
    else:
        first["upstream_modified_at"] = modified
    with pytest.raises(ValueError):
        _document_adapter(document).fetch(since=None)


@pytest.mark.parametrize("omitted", [False, True], ids=["null", "omitted"])
def test_native_mandatory_tiers_cannot_be_missing(omitted: bool) -> None:
    """Verify native mandatory tiers cannot be missing."""
    document = _document()
    first = document["items"][0]
    if omitted:
        del first["visibility_tier"]
    else:
        first["visibility_tier"] = None
    with pytest.raises(ValueError, match="missing required visibility_tier"):
        _document_adapter(document).fetch(since=None)


def test_native_optional_tier_remains_absent_for_shared_policy_resolution() -> None:
    """Verify native optional tier remains absent for shared policy resolution."""
    document = _document()
    del document["items"][0]["visibility_tier"]
    result = _document_adapter(document, requires_record_tier=False).fetch(since=None)
    assert result.matching_records[0].get("visibility_tier") is None
    assert result.validate() == datetime(2020, 1, 4, tzinfo=UTC)


def test_native_invalid_tier_is_rejected_even_when_optional() -> None:
    """Verify native invalid tier is rejected even when optional."""
    document = _document()
    document["items"][0]["visibility_tier"] = "unsupported"
    with pytest.raises(ValidationError):
        _document_adapter(document, requires_record_tier=False).fetch(since=None)


@pytest.mark.parametrize("damage", ["blank_title", "duplicate_identity"])
def test_entire_native_snapshot_is_validated_before_date_filtering(damage: str) -> None:
    """Verify entire native snapshot is validated before date filtering."""
    document = _document()
    if damage == "blank_title":
        document["items"][0]["title"] = " "
    else:
        document["items"][0]["uuid"] = document["items"][-1]["uuid"]
    with pytest.raises(ValueError):
        _document_adapter(document).fetch(since=datetime(2020, 1, 3, tzinfo=UTC))


def test_duplicate_json_object_fields_are_rejected() -> None:
    """Verify duplicate JSON object fields are rejected."""
    payload = b'{"cursor":"2020-01-04T00:00:00Z","items":[],"items":[]}'
    with pytest.raises(ValueError, match="duplicate object fields"):
        replace(_adapter(), payload=payload).fetch(since=None)


@pytest.mark.parametrize(
    ("payload", "error"), [(b"{", json.JSONDecodeError), (b"\xff", UnicodeDecodeError)]
)
def test_invalid_json_or_utf8_is_not_a_successful_empty_harvest(
    payload: bytes, error: type[Exception]
) -> None:
    """Verify invalid JSON or UTF-8 is not a successful empty harvest."""
    with pytest.raises(error):
        replace(_adapter(), payload=payload).fetch(since=None)


def test_cursor_day_is_empty_and_later_days_are_rejected() -> None:
    """Verify cursor day is empty and later days are rejected."""
    adapter = _adapter()
    result = adapter.fetch(since=datetime(2020, 1, 4, tzinfo=UTC))
    assert not result.matching_records
    assert result.validate() == datetime(2020, 1, 4, tzinfo=UTC)
    with pytest.raises(ValueError, match="later than its fixed source cursor"):
        adapter.fetch(since=datetime(2020, 1, 5, tzinfo=UTC))


def test_fingerprint_binds_exact_native_bytes_even_when_decoded_content_matches() -> None:
    """Verify fingerprint binds exact native bytes even when decoded content matches."""
    adapter = _adapter()
    changed = replace(adapter, payload=adapter.payload + b" ")
    assert changed.fetch(since=None) == adapter.fetch(since=None)
    assert changed.config_fingerprint() != adapter.config_fingerprint()


@pytest.mark.parametrize(
    ("environment", "allow_fixture"),
    [("dev", False), ("staging", False), ("production", True)],
)
def test_synthetic_activation_uses_explicit_environment_policy(
    environment: str, allow_fixture: bool
) -> None:
    """Verify synthetic activation uses explicit environment policy."""
    source = configure_sources((_config(),))[0]
    with patch.object(StaticJsonAdapter, "fetch", autospec=True) as fetch:
        validate_source_startup((source,), environment=environment, allow_fixture=allow_fixture)
    fetch.assert_not_called()


def test_production_requires_explicit_synthetic_permission() -> None:
    """Verify production requires explicit synthetic permission."""
    source = configure_sources((_config(),))[0]
    with pytest.raises(ValueError, match=source.name):
        validate_source_startup((source,), environment="production")
