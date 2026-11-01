"""Validated source construction, independent of runtime activation."""

from dataclasses import FrozenInstanceError, replace
from typing import Any
from unittest.mock import create_autospec, patch

import pytest
from pydantic import ValidationError

import app.sources as source_api
from app.sources import configure_sources
from app.sources.base import (
    AccessTier,
    ConfiguredSource,
    SourceAdapter,
    SourceConfig,
    SourceDisplay,
    SourcePolicy,
    SourceSchedule,
)
from app.sources.oai_pmh_cmdi import OaiPmhCmdiAdapter, OaiPmhCmdiConfig


def _config(**overrides: object) -> OaiPmhCmdiConfig:
    """Validate a public OAI source configuration with caller overrides."""
    values: dict[str, object] = {
        "name": "example_archive",
        "display": {"label": "Example archive"},
        "endpoint": "https://archive.example.org/oai",
        "institution_filter": "Example University",
        "max_visibility": "public",
    }
    values.update(overrides)
    return OaiPmhCmdiConfig.model_validate(values)


@pytest.mark.parametrize(
    "changes",
    [
        {"name": ""},
        {"name": "Bad-name"},
        {"name": "name\n"},
        {"name": "x" * 33},
        {"unexpected": True},
        {"max_pages": True},
        {"max_pages": 0},
        {"institution_filter": " "},
        {"endpoint": "https://user:secret@example.org/oai"},
        {"max_visibility": "unknown"},
        {"requires_record_tier": True},
        {"requires_record_tier": 1},
    ],
)
def test_invalid_source_configuration_is_rejected(changes: dict[str, object]) -> None:
    """Check invalid source configuration is rejected (ValidationError)."""
    with pytest.raises(ValidationError):
        _config(**changes)


@pytest.mark.parametrize("label", [" ", "First\nSecond"])
def test_display_text_must_be_nonblank_and_single_line(label: str) -> None:
    """Check display text must be nonblank and single line (ValidationError)."""
    with pytest.raises(ValidationError):
        SourceDisplay(label=label)


@pytest.mark.parametrize(
    "changes",
    [
        {"incremental_interval_seconds": 0},
        {"rebuild_interval_seconds": 0},
        {"write_timeout_seconds": 0},
        {"write_timeout_seconds": 3601},
        {"incremental_interval_seconds": True},
        {"rebuild_max_inferred_delete_count": -1},
        {"rebuild_max_inferred_delete_count": True},
        {"rebuild_max_inferred_delete_count": "1"},
        {"rebuild_max_inferred_delete_count": 1.0},
        {"rebuild_max_inferred_delete_ratio_percent": -1},
        {"rebuild_max_inferred_delete_ratio_percent": 101},
        {"rebuild_max_inferred_delete_ratio_percent": False},
        {"rebuild_max_inferred_delete_ratio_percent": "34"},
        {"rebuild_max_inferred_delete_ratio_percent": 34.0},
    ],
)
def test_schedule_rejects_invalid_budgets(changes: dict[str, object]) -> None:
    """Check schedule rejects invalid budgets (ValidationError)."""
    with pytest.raises(ValidationError):
        SourceSchedule.model_validate(changes)


def test_contraction_budgets_keep_conservative_defaults() -> None:
    """Check contraction budgets keep conservative defaults."""
    schedule = SourceSchedule()
    assert schedule.rebuild_max_inferred_delete_count == 100
    assert schedule.rebuild_max_inferred_delete_ratio_percent == 25


@pytest.mark.parametrize("count,ratio", [(0, 0), (1, 34), (1000, 100)])
def test_contraction_budget_boundaries_are_accepted(count: int, ratio: int) -> None:
    """Check contraction budget boundaries are accepted."""
    schedule = SourceSchedule(
        rebuild_max_inferred_delete_count=count,
        rebuild_max_inferred_delete_ratio_percent=ratio,
    )
    assert schedule.rebuild_max_inferred_delete_count == count
    assert schedule.rebuild_max_inferred_delete_ratio_percent == ratio


@pytest.mark.parametrize("case", ["empty", "duplicate", "unknown"])
def test_registry_rejects_ambiguous_source_sets(case: str) -> None:
    """Check registry rejects ambiguous source sets (ValueError)."""
    configs: list[SourceConfig] = []
    if case == "duplicate":
        configs = [_config(), _config()]
    elif case == "unknown":
        configs = [
            SourceConfig(
                name="example_archive",
                adapter="unknown",
                display=SourceDisplay(label="Example archive"),
            )
        ]
    with pytest.raises(ValueError):
        configure_sources(configs)


def test_source_facade_publishes_the_owning_types() -> None:
    """Check source facade publishes the owning types."""
    assert source_api.AccessTier is AccessTier
    assert source_api.SourcePolicy is SourcePolicy
    assert {"AccessTier", "SourcePolicy"} <= set(source_api.__all__)


def test_registered_adapter_requires_its_own_configuration_model() -> None:
    """Check registered adapter requires its own configuration model (TypeError)."""
    config = SourceConfig(
        name="example_archive",
        adapter="oai_pmh_cmdi",
        display=SourceDisplay(label="Example archive"),
    )
    with pytest.raises(TypeError, match="requires OaiPmhCmdiConfig"):
        configure_sources([config])


def test_descriptions_and_configured_sources_are_frozen() -> None:
    """Check descriptions and configured sources are frozen."""
    config = _config()
    for model, field, value in (
        (config, "name", "changed"),
        (config.display, "label", "Changed"),
        (config.schedule, "write_timeout_seconds", 1),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)
    source = configure_sources([config])[0]
    with pytest.raises(FrozenInstanceError):
        source.adapter = source.adapter  # type: ignore[misc]


def test_registry_builds_independent_sources_in_order_without_fetching() -> None:
    """Check registry builds independent sources in order without fetching."""
    first = _config(max_pages=7)
    second = _config(
        name="second_archive",
        endpoint="https://second.example.org/oai",
        schedule=SourceSchedule(incremental_interval_seconds=900),
        max_visibility="registered",
        requires_record_tier=False,
    )
    with patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as fetch:
        sources = configure_sources([first, second])
    fetch.assert_not_called()
    assert tuple(source.name for source in sources) == ("example_archive", "second_archive")
    assert sources[0].policy is not sources[1].policy
    assert sources[0].display == first.display
    assert sources[1].schedule.incremental_interval_seconds == 900
    assert sources[1].policy.max_visibility == "registered"
    assert sources[1].policy.requires_record_tier is False
    assert isinstance(sources[0].adapter, OaiPmhCmdiAdapter)
    assert sources[0].adapter.oai_url == first.endpoint
    assert sources[0].adapter.institution_filter == first.institution_filter
    assert sources[0].adapter.max_pages == 7


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "other_archive"},
        {"endpoint": "https://other.example.org/oai"},
        {"institution_filter": "Other University"},
        {"max_visibility": "registered"},
    ],
)
def test_interpretation_changes_alter_the_binding(changes: dict[str, object]) -> None:
    """Check interpretation changes alter the binding."""
    original = configure_sources([_config()])[0]
    changed = configure_sources([_config(**changes)])[0]
    assert changed.adapter.config_fingerprint() != original.adapter.config_fingerprint()


def test_presentation_and_operational_changes_preserve_the_binding() -> None:
    """Check presentation and operational changes preserve the binding."""
    original = configure_sources([_config()])[0]
    changed = configure_sources(
        [
            _config(
                display=SourceDisplay(
                    label="Renamed archive",
                    resource_link_label="Download",
                    landing_link_label="Catalogue",
                    sensitivity_badge="Restricted collection",
                ),
                schedule=SourceSchedule(
                    incremental_interval_seconds=900,
                    rebuild_interval_seconds=43200,
                    write_timeout_seconds=240,
                    rebuild_max_inferred_delete_count=1,
                    rebuild_max_inferred_delete_ratio_percent=34,
                ),
                max_pages=11,
            )
        ]
    )[0]
    assert changed.adapter.config_fingerprint() == original.adapter.config_fingerprint()


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "other_archive"},
        {"max_visibility": "registered"},
        {"requires_record_tier": True},
    ],
)
def test_wrapper_rejects_a_divergent_write_policy(changes: dict[str, Any]) -> None:
    """Check wrapper rejects a divergent write policy (ValueError)."""
    source = configure_sources([_config()])[0]
    adapter = create_autospec(SourceAdapter, instance=True, spec_set=True)
    adapter.name = source.name
    adapter.policy = replace(source.policy, **changes)
    with pytest.raises(ValueError, match="policy disagree"):
        ConfiguredSource(config=source.config, adapter=adapter)


def test_wrapper_rejects_a_divergent_adapter_name() -> None:
    """Check wrapper rejects a divergent adapter name (ValueError)."""
    source = configure_sources([_config()])[0]
    adapter = create_autospec(SourceAdapter, instance=True, spec_set=True)
    adapter.name = "other_archive"
    adapter.policy = source.policy
    with pytest.raises(ValueError, match="policy disagree"):
        ConfiguredSource(config=source.config, adapter=adapter)


def test_institution_filter_preserves_exact_nonblank_binding_input():
    """Check institution filter preserves exact nonblank binding input."""
    assert _config(institution_filter=" X ").institution_filter == " X "
