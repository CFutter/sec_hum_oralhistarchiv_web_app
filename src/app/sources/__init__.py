"""Source construction without settings or runtime activation."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from .base import (
    AccessTier,
    CatalogueSource,
    ConfiguredSource,
    SourceAdapter,
    SourceConfig,
    SourceDisplay,
    SourceMetadata,
    SourcePolicy,
    SourceSchedule,
    normalize_harvest_since,
)
from .fixture import FixtureAdapter, FixtureConfig, classify_fixture_access
from .json_feed import JsonFeedAdapter, classify_json_feed_access
from .json_feed_config import (
    JsonFeedConfig,
    JsonFeedCredentials,
    prepare_json_feed_startup,
    snapshot_json_feed_selection,
)
from .json_feed_harvest import JsonFeedHarvestBuilder
from .json_feed_http import FeedRequest, FeedTransportError
from .json_feed_pages import JsonFeedPageValidator
from .json_feed_protocol import (
    FeedProtocolError,
    FeedRecordInput,
    FeedRecordRejection,
    ValidatedFeedPage,
)
from .json_feed_transport import AuthenticatedFeedPage, JsonFeedTransport
from .oai_pmh_cmdi import OaiPmhCmdiAdapter, OaiPmhCmdiConfig, classify_oai_access
from .parser_transport import validate_parser_service
from .startup import validate_source_startup
from .static_json import StaticJsonAdapter, StaticJsonConfig, classify_static_json_access

__all__ = [
    "AccessTier",
    "AuthenticatedFeedPage",
    "CatalogueSource",
    "ConfiguredSource",
    "FeedProtocolError",
    "FeedRecordInput",
    "FeedRecordRejection",
    "FeedRequest",
    "FeedTransportError",
    "FixtureAdapter",
    "FixtureConfig",
    "JsonFeedAdapter",
    "JsonFeedConfig",
    "JsonFeedCredentials",
    "JsonFeedHarvestBuilder",
    "JsonFeedPageValidator",
    "JsonFeedTransport",
    "OaiPmhCmdiAdapter",
    "OaiPmhCmdiConfig",
    "SourceAdapter",
    "SourceConfig",
    "SourceDisplay",
    "SourceMetadata",
    "SourcePolicy",
    "SourceSchedule",
    "StaticJsonAdapter",
    "StaticJsonConfig",
    "ValidatedFeedPage",
    "catalogue_sources",
    "classify_fixture_access",
    "classify_json_feed_access",
    "classify_oai_access",
    "classify_static_json_access",
    "configure_sources",
    "load_catalogue_sources_for_startup",
    "load_sources_for_startup",
    "normalize_harvest_since",
    "parse_source_config",
    "parse_source_configs_from_toml",
    "prepare_json_feed_startup",
    "registered_adapter_names",
    "run_parser_service",
    "validate_parser_service",
    "validate_source_startup",
]


def run_parser_service() -> None:
    """Activate the parser broker only in its dedicated entry point."""
    from .parser_service import main  # noqa: PLC0415 - broker activation is entry-point-only.

    main()


@dataclass(frozen=True, slots=True)
class _AdapterRegistration:
    """Pair an adapter configuration model with its explicit-credential factory."""

    config_model: type[SourceConfig]
    factory: Callable[[SourceConfig, JsonFeedCredentials | None], SourceAdapter]


_ADAPTER_REGISTRATIONS: Mapping[str, _AdapterRegistration] = MappingProxyType(
    {
        "oai_pmh_cmdi": _AdapterRegistration(
            config_model=OaiPmhCmdiConfig,
            factory=lambda config, _credentials: OaiPmhCmdiAdapter.from_config(config),
        ),
        "fixture": _AdapterRegistration(
            config_model=FixtureConfig,
            factory=lambda config, _credentials: FixtureAdapter.from_config(config),
        ),
        "static_json": _AdapterRegistration(
            config_model=StaticJsonConfig,
            factory=lambda config, _credentials: StaticJsonAdapter.from_config(config),
        ),
        "json_feed": _AdapterRegistration(
            config_model=JsonFeedConfig,
            factory=JsonFeedAdapter.from_config,
        ),
    }
)


_CONFIG_MODELS: Mapping[str, type[SourceConfig]] = MappingProxyType(
    {name: registration.config_model for name, registration in _ADAPTER_REGISTRATIONS.items()}
)


def registered_adapter_names() -> tuple[str, ...]:
    """Return runnable adapter identifiers in declaration order."""
    return tuple(_ADAPTER_REGISTRATIONS)


def parse_source_config(values: Mapping[str, object]) -> SourceConfig:
    """Validate a registered description without constructing its adapter."""
    adapter = values.get("adapter")
    if not isinstance(adapter, str) or adapter not in _CONFIG_MODELS:
        raise ValueError("Unknown or missing source adapter")
    return _CONFIG_MODELS[adapter].model_validate(dict(values))


def catalogue_sources(configs: Sequence[SourceConfig]) -> tuple[CatalogueSource, ...]:
    """Snapshot registered nonsecret descriptions without constructing any adapter.

    Policy and catalogue fingerprints use the same validated fields as ingestion.
    Credential reference names are configuration; their values are never read.
    Bundled fixture payloads and network clients are not opened or retained.
    """
    classifiers = {
        "oai_pmh_cmdi": classify_oai_access,
        "fixture": classify_fixture_access,
        "static_json": classify_static_json_access,
        "json_feed": classify_json_feed_access,
    }
    if not configs:
        raise ValueError("At least one source must be configured")
    sources: list[CatalogueSource] = []
    names: set[str] = set()
    for config in configs:
        if not isinstance(config, SourceConfig):
            raise TypeError("Catalogue sources require SourceConfig descriptions")
        snapshot = parse_source_config(config.model_dump())
        if snapshot.name in names:
            raise ValueError(f"Duplicate source name: {snapshot.name}")
        names.add(snapshot.name)
        sources.append(
            CatalogueSource(
                config=snapshot,
                policy=SourcePolicy(
                    name=snapshot.name,
                    max_visibility=snapshot.max_visibility,
                    classify_access=classifiers[snapshot.adapter],
                    requires_record_tier=snapshot.requires_record_tier,
                ),
            )
        )
    return tuple(sources)


def configure_sources(
    configs: Sequence[SourceConfig], *, credentials: Sequence[JsonFeedCredentials] = ()
) -> tuple[ConfiguredSource, ...]:
    """Construct sources in configuration order; reject empty or ambiguous sets.

    This function reads no deployment config files, global settings or
    environment variables and performs no harvest. Validate all descriptions
    and exact prepared credential snapshots before any adapter factory runs.
    Fixture factories read bounded bundled resources. Runtime callers choose
    which constructed sources to activate.
    """
    configs = tuple(configs)
    if not configs:
        raise ValueError("At least one source must be configured")

    snapshots: list[SourceConfig] = []
    names: set[str] = set()
    for config in configs:
        if not isinstance(config, SourceConfig):
            raise TypeError("Source construction requires SourceConfig descriptions")
        if config.name in names:
            raise ValueError(f"Duplicate source name: {config.name}")
        names.add(config.name)
        if config.adapter not in _ADAPTER_REGISTRATIONS:
            raise ValueError(f"Unknown source adapter: {config.adapter}")
        registration = _ADAPTER_REGISTRATIONS[config.adapter]
        if not isinstance(config, registration.config_model):
            raise TypeError(f"{config.adapter} requires {registration.config_model.__name__}")
        snapshots.append(registration.config_model.model_validate(config.model_dump()))

    prepared = snapshot_json_feed_selection(
        [config for config in snapshots if isinstance(config, JsonFeedConfig)], credentials
    )

    return tuple(
        ConfiguredSource(
            config=config,
            adapter=_ADAPTER_REGISTRATIONS[config.adapter].factory(
                config, prepared.get(config.name)
            ),
        )
        for config in snapshots
    )


# Configuration imports the construction functions defined above.
from .configuration import parse_source_configs_from_toml  # noqa: E402
from .startup_file import load_catalogue_sources_for_startup, load_sources_for_startup  # noqa: E402
