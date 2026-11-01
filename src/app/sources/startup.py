"""Pure deployment policy for the sources selected by a startup caller."""

from collections.abc import Sequence

from app.url_safety import parse_http_url

from .base import ConfiguredSource, SourceConfig
from .fixture import FixtureAdapter, FixtureConfig
from .oai_pmh_cmdi import OaiPmhCmdiAdapter, OaiPmhCmdiConfig
from .static_json import StaticJsonAdapter, StaticJsonConfig

_PLACEHOLDER_HOSTS = (
    "example.com",
    "example.net",
    "example.org",
    "example",
    "invalid",
    "test",
    "localhost",
)


def _validate_source_endpoint(source: str, endpoint: str, *, hardened: bool) -> None:
    """Validate credential-free HTTP(S); hardened requires HTTPS and rejects placeholder hosts.

    Raise ValueError for invalid structure/hosts; perform no DNS or network lookup.
    """
    try:
        parsed = parse_http_url(endpoint, require_https=hardened)
    except ValueError as exc:
        requirement = "HTTPS" if hardened else "HTTP(S)"
        raise ValueError(
            f"Source {source!r} requires an absolute, credential-free {requirement} endpoint"
        ) from exc

    try:
        hostname = (parsed.hostname or "").encode("idna").decode("ascii").casefold().rstrip(".")
    except UnicodeError:
        raise ValueError(f"Source {source!r} has an invalid endpoint host") from None
    if hardened and any(
        hostname == placeholder or hostname.endswith(f".{placeholder}")
        for placeholder in _PLACEHOLDER_HOSTS
    ):
        raise ValueError(f"Source {source!r} uses a placeholder endpoint host")


def _validate_startup_options(*, environment: str, allow_fixture: bool) -> None:
    """Require dev/staging/production and a boolean fixture permission; raise
    ValueError/TypeError.
    """
    if environment not in {"dev", "staging", "production"}:
        raise ValueError("Unsupported source environment")
    if not isinstance(allow_fixture, bool):
        raise TypeError("allow_fixture must be a boolean")


def validate_source_configs_startup(
    configs: Sequence[SourceConfig], *, environment: str, allow_fixture: bool = False
) -> None:
    """Apply the common nonsecret deployment policy before either runtime starts."""
    from .json_feed_config import JsonFeedConfig, validate_json_feed_configs  # noqa: PLC0415

    _validate_startup_options(environment=environment, allow_fixture=allow_fixture)
    if not configs:
        raise ValueError("At least one source must be configured")
    if len({config.name for config in configs}) != len(configs):
        raise ValueError("Duplicate source name in source configuration")
    validate_json_feed_configs(
        [config for config in configs if isinstance(config, JsonFeedConfig)],
        environment=environment,
    )
    for config in configs:
        if isinstance(config, JsonFeedConfig):
            continue  # Includes endpoint and cross-source credential-reference policy above.
        if isinstance(config, OaiPmhCmdiConfig):
            _validate_source_endpoint(
                config.name, config.endpoint, hardened=environment in {"staging", "production"}
            )
        elif isinstance(config, (FixtureConfig, StaticJsonConfig)):
            if environment == "production" and not allow_fixture:
                raise ValueError(
                    f"Source {config.name!r} requires explicit production fixture permission"
                )
        else:
            raise TypeError(f"Source {config.name!r} has no startup policy")


def validate_source_startup(
    sources: Sequence[ConfiguredSource],
    *,
    environment: str,
    allow_fixture: bool = False,
) -> None:
    """Check actual adapters without fetching, reading settings or mutating them.

    Staging and production require HTTPS and reject placeholder endpoint hosts.
    Production fixtures require explicit permission. This is an endpoint and
    adapter policy only; file and credential gates belong to their runtime
    boundaries. New adapter implementations must add an explicit startup policy.
    """
    _validate_startup_options(environment=environment, allow_fixture=allow_fixture)
    from .json_feed import JsonFeedAdapter  # noqa: PLC0415

    selected_sources = tuple(sources)
    if not selected_sources:
        raise ValueError("At least one source must be configured")

    names: set[str] = set()
    for source in selected_sources:
        if source.name in names:
            raise ValueError(f"Duplicate source name: {source.name}")
        names.add(source.name)

        adapter = source.adapter
        if isinstance(adapter, JsonFeedAdapter):
            _validate_source_endpoint(
                source.name,
                adapter.config.endpoint,
                hardened=environment in {"staging", "production"},
            )
        elif isinstance(adapter, OaiPmhCmdiAdapter):
            _validate_source_endpoint(
                source.name,
                adapter.oai_url,
                hardened=environment in {"staging", "production"},
            )
        elif isinstance(adapter, (FixtureAdapter, StaticJsonAdapter)):
            if environment == "production" and not allow_fixture:
                raise ValueError(
                    f"Source {source.name!r} requires explicit production fixture permission"
                )
        else:
            raise TypeError(f"Source {source.name!r} has no startup policy")
