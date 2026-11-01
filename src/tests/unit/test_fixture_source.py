"""Deterministic offline source behavior before runtime activation."""

import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.sources import (
    FixtureAdapter,
    FixtureConfig,
    OaiPmhCmdiAdapter,
    SourceAdapter,
    SourceConfig,
    SourceDisplay,
    SourceSchedule,
    classify_fixture_access,
    configure_sources,
)
from app.sources.configuration import configure_sources_from_toml


def _config(**overrides: object) -> FixtureConfig:
    """Validate an offline source with explicit configuration overrides."""
    values: dict[str, object] = {
        "name": "offline_archive",
        "display": {"label": "Offline archive"},
        "max_visibility": "public",
    }
    values.update(overrides)
    return FixtureConfig.model_validate(values)


def _adapter(**overrides: object) -> FixtureAdapter:
    """Construct an offline adapter from the overridden fixture configuration."""
    return FixtureAdapter.from_config(_config(**overrides))


def test_fixture_full_harvest_has_fixed_cursor_and_explicit_tiers() -> None:
    """Fixture full harvest has fixed cursor and explicit tiers."""
    source = configure_sources([_config()])[0]
    adapter: SourceAdapter = source.adapter
    result = adapter.fetch(since=None)
    assert result.validate() == datetime(2020, 1, 4, tzinfo=UTC)
    assert [record["visibility_tier"] for record in result.matching_records] == [
        "public",
        "registered",
        "vetted",
    ]
    assert source.policy.max_visibility == "public"
    assert source.policy.requires_record_tier is True
    assert not result.deleted_uuids
    assert not result.nonmatching_uuids
    assert not result.uncertain_records
    assert isinstance(adapter, FixtureAdapter)
    with pytest.raises(FrozenInstanceError):
        adapter.dataset = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("since", "identifiers"),
    [
        (None, ["fixture:public", "fixture:registered", "fixture:vetted"]),
        (datetime(2020, 1, 2, tzinfo=UTC), ["fixture:registered", "fixture:vetted"]),
        (datetime(2020, 1, 3, tzinfo=UTC), ["fixture:vetted"]),
        (datetime(2020, 1, 4, tzinfo=UTC), []),
        (
            datetime.fromisoformat("2020-01-02T00:30:00+01:00"),
            ["fixture:public", "fixture:registered", "fixture:vetted"],
        ),
        (
            datetime(2020, 1, 2, 23, 59, tzinfo=UTC),
            ["fixture:registered", "fixture:vetted"],
        ),
    ],
)
def test_fixture_since_is_inclusive(since: datetime | None, identifiers: list[str]) -> None:
    """Fixture since is inclusive."""
    result = _adapter().fetch(since=since)
    assert [record["uuid"] for record in result.matching_records] == identifiers
    assert result.source_cursor == datetime(2020, 1, 4, tzinfo=UTC)


@pytest.mark.parametrize(
    ("since", "error"),
    [
        ("2020-01-01", TypeError),
        (123, TypeError),
        (datetime(2020, 1, 1, tzinfo=UTC).replace(tzinfo=None), ValueError),
        (datetime(2020, 1, 5, tzinfo=UTC), ValueError),
    ],
)
def test_fixture_rejects_invalid_since(since: object, error: type[Exception]) -> None:
    """Fixture rejects invalid since."""
    with pytest.raises(error):
        _adapter().fetch(since=since)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Public access", "public"),
        ("Restricted access", "restricted"),
        (None, "restricted"),
        ("unknown", "restricted"),
        (" Public access", "restricted"),
        ("Public access extra", "restricted"),
    ],
)
def test_fixture_classifies_access_conservatively(raw: str | None, expected: str) -> None:
    """Fixture classifies access conservatively."""
    assert classify_fixture_access(raw) == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"dataset": "../outside"},
        {"adapter": "unknown"},
        {"max_bytes": True},
        {"max_bytes": 0},
        {"max_bytes": "65536"},
    ],
)
def test_fixture_config_is_strict(changes: dict[str, object]) -> None:
    """Fixture config is strict."""
    with pytest.raises(ValidationError):
        _config(**changes)


def test_fixture_factory_requires_its_config_model() -> None:
    """Fixture factory requires its config model."""
    config = SourceConfig(
        name="offline_archive", adapter="fixture", display=SourceDisplay(label="Offline archive")
    )
    with pytest.raises(TypeError, match="requires FixtureConfig"):
        configure_sources([config])


def test_fixture_factory_enforces_payload_budget() -> None:
    """Fixture factory enforces payload budget."""
    with pytest.raises(ValueError, match="max_bytes"):
        _adapter(max_bytes=1)


def test_fixture_returns_independent_results() -> None:
    """Fixture returns independent results."""
    adapter = _adapter()
    first = adapter.fetch(since=None)
    first.matching_records[0]["keywords"].append("changed")
    first.matching_records[0]["resource_proxies"][0]["ref"] = "https://changed.example.org/"
    first.deleted_uuids.add("fixture:changed")
    second = adapter.fetch(since=None)
    other = _adapter(name="other_fixture").fetch(since=None)
    assert "changed" not in second.matching_records[0]["keywords"]
    assert second.matching_records[0]["resource_proxies"][0]["ref"] == (
        "https://archive.example.org/resources/public"
    )
    assert not second.deleted_uuids
    assert second == other


@pytest.mark.parametrize(
    "changes",
    [{"name": "other_fixture"}, {"max_visibility": "registered"}, {"requires_record_tier": False}],
)
def test_fixture_fingerprint_tracks_interpretation(changes: dict[str, object]) -> None:
    """Fixture fingerprint tracks interpretation."""
    assert _adapter().config_fingerprint() != _adapter(**changes).config_fingerprint()


def test_fixture_operational_metadata_is_not_binding() -> None:
    """Fixture operational metadata is not binding."""
    changed = _adapter(
        display=SourceDisplay(label="Renamed archive", sensitivity_badge="Synthetic examples"),
        schedule=SourceSchedule(
            incremental_interval_seconds=900,
            rebuild_interval_seconds=43200,
            write_timeout_seconds=240,
        ),
        max_bytes=128000,
    )
    assert changed.config_fingerprint() == _adapter().config_fingerprint()


def test_fixture_payload_snapshot_survives_resource_changes(tmp_path: Path) -> None:
    """Fixture payload snapshot survives resource changes."""
    original_payload = _adapter().payload
    resource = tmp_path / "fixture_data" / "catalogue_v1.json"
    resource.parent.mkdir()
    resource.write_bytes(original_payload)
    with patch("app.sources.fixture.files", autospec=True, return_value=tmp_path):
        first = _adapter()
        fingerprint = first.config_fingerprint()
        resource.write_bytes(
            original_payload.replace(b"Public sample interview", b"Revised public sample interview")
        )
        assert first.config_fingerprint() == fingerprint
        assert first.fetch(since=None).matching_records[0]["title"] == ("Public sample interview")
        second = _adapter()
    assert second.config_fingerprint() != fingerprint
    assert second.fetch(since=None).matching_records[0]["title"] == (
        "Revised public sample interview"
    )


@pytest.mark.parametrize(
    "case",
    ["duplicate", "blank-title", "missing-time", "future-time", "missing-tier", "withdrawal"],
)
def test_fixture_rejects_invalid_payload_before_filtering(case: str) -> None:
    """Fixture rejects invalid payload before filtering."""
    adapter = _adapter()
    document = json.loads(adapter.payload)
    record = document["matching_records"][0]
    if case == "duplicate":
        document["matching_records"].append(dict(record))
    elif case == "blank-title":
        record["title"] = " "
    elif case == "missing-time":
        record["upstream_modified_at"] = None
    elif case == "future-time":
        record["upstream_modified_at"] = "2020-01-05T00:00:00+00:00"
    elif case == "missing-tier":
        record["visibility_tier"] = None
    else:
        document["deleted_uuids"] = ["fixture:withdrawn"]
    altered = replace(adapter, payload=json.dumps(document).encode("utf-8"))
    with pytest.raises(ValueError):
        altered.fetch(since=datetime(2020, 1, 3, tzinfo=UTC))


def test_mixed_adapter_toml_constructs_in_order_without_fetching() -> None:
    """Mixed adapter toml constructs in order without fetching."""
    document = """[[sources]]
name = "remote_archive"
adapter = "oai_pmh_cmdi"
label = "Remote archive"
endpoint = "https://repository.example.org/oai"
institution_filter = "Example University"

[[sources]]
name = "offline_archive"
adapter = "fixture"
label = "Offline archive"
max_visibility = "public"
"""
    with (
        patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as oai_fetch,
        patch.object(FixtureAdapter, "fetch", autospec=True) as fixture_fetch,
    ):
        sources = configure_sources_from_toml(document)
    oai_fetch.assert_not_called()
    fixture_fetch.assert_not_called()
    assert tuple(source.name for source in sources) == ("remote_archive", "offline_archive")
    assert isinstance(sources[0].adapter, OaiPmhCmdiAdapter)
    assert isinstance(sources[1].adapter, FixtureAdapter)
    assert sources[0].policy is not sources[1].policy


@pytest.mark.parametrize(
    ("payload", "error"),
    [(bytearray(b"{}"), TypeError), (b"x" * 1048577, ValueError)],
)
def test_fixture_rejects_unsafe_direct_snapshots(payload: object, error: type[Exception]) -> None:
    """Fixture rejects unsafe direct snapshots."""
    with pytest.raises(error):
        replace(_adapter(), payload=payload)  # type: ignore[arg-type]
