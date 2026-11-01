"""Initial adapter boundary for source identity, binding and blocking harvests."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.duration_contract import MAX_SOURCE_INTERVAL_SECONDS
from app.field_visibility import (
    FIELD_VISIBILITY,
    PUBLIC_DISCOVERY_FIELDS,
    RESOURCE_URL_FIELDS,
    FrozenFieldVisibility,
)
from app.ingestion_contracts import ACCESS_TIER_RANK, HarvestResult
from app.ingestion_contracts import (
    AccessTier as AccessTier,  # noqa: PLC0414 - public re-export.
)
from app.source_contract import SOURCE_NAME_MAX_CHARS, SOURCE_NAME_SQL_PATTERN


@dataclass(frozen=True)
class SourcePolicy:
    """Source restriction and classifier for raw access labels.

    max_visibility is the least restrictive permitted tier; classify_access
    maps a raw label or None to an access classification. When
    requires_record_tier is true, ingestion must reject a missing or unknown
    record tier before building persistence parameters.
    """

    name: str
    max_visibility: AccessTier
    classify_access: Callable[[str | None], str]
    requires_record_tier: bool = False


class SourceDisplay(BaseModel):
    """Plain display text; templates remain responsible for HTML escaping."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    label: str
    resource_link_label: str = "Open resource"
    landing_link_label: str = "View source record"
    sensitivity_badge: str | None = None

    @field_validator("label", "resource_link_label", "landing_link_label", "sensitivity_badge")
    @classmethod
    def validate_display_text(cls, value: str | None) -> str | None:
        """Require nonblank printable text when a value is supplied."""
        if value is None:
            return None
        value = value.strip()
        if not value or not value.isprintable():
            raise ValueError("Source display text must be nonblank and single-line")
        return value


class SourceSchedule(BaseModel):
    """Operational budgets, separate from interpretation fingerprints."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    incremental_interval_seconds: int = Field(default=3600, ge=1, le=MAX_SOURCE_INTERVAL_SECONDS)
    rebuild_interval_seconds: int = Field(default=86400, ge=1, le=MAX_SOURCE_INTERVAL_SECONDS)
    write_timeout_seconds: int = Field(default=120, ge=1, le=3600)
    rebuild_max_inferred_delete_count: int = Field(default=100, ge=0)
    rebuild_max_inferred_delete_ratio_percent: int = Field(default=25, ge=0, le=100)


class SourceConfig(BaseModel):
    """Common construction model; this is not a runtime TOML loader."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(
        min_length=1, max_length=SOURCE_NAME_MAX_CHARS, pattern=SOURCE_NAME_SQL_PATTERN
    )
    adapter: str = Field(min_length=1)
    display: SourceDisplay
    schedule: SourceSchedule = Field(default_factory=SourceSchedule)
    max_visibility: AccessTier = "vetted"
    requires_record_tier: bool = False
    log_resource_access: bool = Field(default_factory=lambda data: data["requires_record_tier"])
    field_visibility: Mapping[str, AccessTier] = Field(default_factory=FrozenFieldVisibility)

    @field_validator("field_visibility")
    @classmethod
    def validate_field_visibility(cls, value: Mapping[str, AccessTier]) -> Mapping[str, AccessTier]:
        """Snapshot stricter field minima without changing the discovery contract."""
        unknown = value.keys() - FIELD_VISIBILITY.keys()
        if unknown:
            raise ValueError(f"Unknown field visibility overrides: {sorted(unknown)}")
        for name, minimum in value.items():
            if ACCESS_TIER_RANK[minimum] < ACCESS_TIER_RANK[FIELD_VISIBILITY[name]]:
                raise ValueError(f"Field visibility override loosens the code minimum: {name}")
            if name in PUBLIC_DISCOVERY_FIELDS and minimum != "public":
                raise ValueError(f"Public discovery field requires a public minimum: {name}")
        resolved = dict(FIELD_VISIBILITY) | dict(value)
        if len({resolved[name] for name in RESOURCE_URL_FIELDS}) != 1:
            raise ValueError("Resource URL fields require equal visibility minima")
        return FrozenFieldVisibility(tuple(value.items()))

    @field_serializer("field_visibility")
    def serialize_field_visibility(self, value: Mapping[str, AccessTier]) -> dict[str, AccessTier]:
        """Keep immutable configuration snapshots serializable and revalidatable."""
        return dict(value)


def normalize_harvest_since(since: object) -> datetime | None:
    """Return no boundary or an aware lower boundary normalized to UTC.

    Wrong types raise TypeError; naive timestamps raise ValueError.
    Values are never interpreted using the machine's local timezone.
    """
    if since is None:
        return None
    if not isinstance(since, datetime):
        raise TypeError("Harvest since must be a datetime or None")
    if since.utcoffset() is None:
        raise ValueError("Harvest since must be timezone-aware")
    return since.astimezone(UTC)


class SourceAdapter(Protocol):
    """A configured harvest and its source-interpretation fingerprint.

    Fetch is synchronous and must enforce a terminating resource budget.
    The caller offloads it from the event loop and supplies an already-
    computed aware lower boundary, or None for full input. Adapters may
    widen the boundary to their native granularity, never narrow it.
    """

    @property
    def name(self) -> str:
        """Return the persistent source identity."""
        ...

    @property
    def policy(self) -> SourcePolicy:
        """Return the source's record-visibility and access policy."""
        ...

    def config_fingerprint(self) -> str:
        """Return the binding required for cursor and staged-harvest reuse."""
        ...

    def fetch(self, *, since: datetime | None, cancel_event: Event | None = None) -> HarvestResult:
        """Return complete requested input; None selects full-harvest mode.

        Runtime callers always supply cancel_event. Network supervisors must
        observe it promptly and reap their workers before raising. None is for
        direct synchronous callers without an asynchronous owner.
        """
        ...


@dataclass(frozen=True, slots=True)
class ConfiguredSource:
    """Pair a validated description with an adapter using the same policy."""

    config: SourceConfig
    adapter: SourceAdapter

    def __post_init__(self) -> None:
        """Reject a description that disagrees with the actual write policy."""
        if (
            self.adapter.name != self.config.name
            or self.adapter.policy.name != self.config.name
            or self.adapter.policy.max_visibility != self.config.max_visibility
            or self.adapter.policy.requires_record_tier != self.config.requires_record_tier
        ):
            raise ValueError("Source configuration and adapter policy disagree")

    @property
    def name(self) -> str:
        """Return the persistent source identity."""
        return self.config.name

    @property
    def display(self) -> SourceDisplay:
        """Return presentation metadata, which does not affect binding."""
        return self.config.display

    @property
    def schedule(self) -> SourceSchedule:
        """Return operational settings, which do not affect binding."""
        return self.config.schedule

    @property
    def log_resource_access(self) -> bool:
        """Return the redirect audit setting, which does not affect ingestion binding."""
        return self.config.log_resource_access

    @property
    def field_visibility(self) -> Mapping[str, AccessTier]:
        """Return immutable disclosure overrides, separate from ingestion binding."""
        return self.config.field_visibility

    @property
    def policy(self) -> SourcePolicy:
        """Return the adapter's actual write policy."""
        return self.adapter.policy


@dataclass(frozen=True, slots=True)
class CatalogueSource:
    """Nonsecret source metadata for serving an already-ingested catalogue.

    This snapshot deliberately has no adapter or fetch operation. Construct it
    through catalogue_sources so its classifier is a reviewed pure function,
    never a bound method retaining a credential-bearing adapter.
    """

    config: SourceConfig
    policy: SourcePolicy

    @property
    def name(self) -> str:
        """Return the persistent source identity."""
        return self.config.name

    @property
    def display(self) -> SourceDisplay:
        """Return display labels; these do not affect ingestion binding."""
        return self.config.display

    @property
    def schedule(self) -> SourceSchedule:
        """Return operational budgets; these do not affect ingestion binding."""
        return self.config.schedule

    @property
    def log_resource_access(self) -> bool:
        """Return whether successful resource redirects require audit logging."""
        return self.config.log_resource_access

    @property
    def field_visibility(self) -> Mapping[str, AccessTier]:
        """Return immutable field disclosure overrides, separate from ingestion binding."""
        return self.config.field_visibility


SourceMetadata = ConfiguredSource | CatalogueSource
