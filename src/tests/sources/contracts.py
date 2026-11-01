"""Shared adapter cases for source construction and harvest conformance."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from app.sources import (
    AccessTier,
    ConfiguredSource,
    JsonFeedConfig,
    SourceAdapter,
    configure_sources,
    parse_source_config,
    prepare_json_feed_startup,
)


@dataclass(frozen=True, slots=True)
class Case:
    """Adapter configuration, expected harvests and transport observations for conformance checks."""

    adapter_id: str
    adapter_type: type[SourceAdapter]
    values: dict[str, object]
    document: str
    cursor: datetime
    boundary: datetime
    full_ids: tuple[str, ...]
    boundary_ids: tuple[str, ...]
    raw_tiers: tuple[AccessTier | None, ...]
    expected_registered_tiers: tuple[AccessTier, ...]
    operational_overrides: dict[str, object]
    insufficient_budget: dict[str, object]
    budget_error: type[Exception]
    budget_match: str
    io_calls: list[dict[str, object]]
    environ: Mapping[str, str] | None = None
    mandatory_record_tier: bool = False
    supports_required_record_tier: bool = True

    def build(self, **overrides: object) -> ConfiguredSource:
        """Parse case overrides, prepare feed credentials if needed, and build the configured
        source.
        """
        config = parse_source_config({**self.values, **overrides})
        credentials = (
            prepare_json_feed_startup((config,), environment="dev", environ=self.environ or {})
            if isinstance(config, JsonFeedConfig)
            else ()
        )
        return configure_sources((config,), credentials=credentials)[0]
