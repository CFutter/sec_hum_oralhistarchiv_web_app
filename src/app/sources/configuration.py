"""Parse explicit source TOML without global settings or fetching."""

import tomllib
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from . import configure_sources, parse_source_config
from .base import ConfiguredSource, SourceConfig, SourceDisplay, SourceSchedule
from .json_feed_config import JsonFeedCredentials


class _SourcesDocument(BaseModel):
    """Require a nonempty sources array and reject unknown top-level fields."""

    model_config = ConfigDict(extra="forbid", strict=True)

    sources: list[dict[str, object]] = Field(min_length=1)


def _source_config_from_entry(entry: dict[str, object]) -> SourceConfig:
    """Translate the flat file format into the nested construction models."""
    values = dict(entry)
    if "display" in values or "schedule" in values:
        raise ValueError("Source TOML requires flat display and schedule fields")

    display = SourceDisplay.model_validate(
        {name: values.pop(name) for name in SourceDisplay.model_fields if name in values}
    )
    schedule = SourceSchedule.model_validate(
        {name: values.pop(name) for name in SourceSchedule.model_fields if name in values}
    )
    return parse_source_config({**values, "display": display, "schedule": schedule})


def parse_source_configs_from_toml(document: str) -> tuple[SourceConfig, ...]:
    """Validate descriptions in order without constructing adapters or reading secrets.

    Runtime callers must still prepare credentials, construct sources and apply
    the existing startup/file policies.
    """
    parsed = _SourcesDocument.model_validate(tomllib.loads(document))
    configs = tuple(_source_config_from_entry(entry) for entry in parsed.sources)
    if len({config.name for config in configs}) != len(configs):
        raise ValueError("Duplicate source name in source configuration")
    return configs


def configure_sources_from_toml(
    document: str, *, credentials: Sequence[JsonFeedCredentials] = ()
) -> tuple[ConfiguredSource, ...]:
    """Validate a complete TOML document and construct runnable sources without fetching."""
    return configure_sources(parse_source_configs_from_toml(document), credentials=credentials)


def load_sources_file(
    path: str | Path, *, credentials: Sequence[JsonFeedCredentials] = ()
) -> tuple[ConfiguredSource, ...]:
    """Read an explicit UTF-8 file; syntax, validation and I/O errors propagate.

    This is a construction API, not the staging/production startup gate.
    It performs no environment, ownership or permission-policy checks.
    """
    return configure_sources_from_toml(
        Path(path).read_text(encoding="utf-8"), credentials=credentials
    )
