"""Load the explicitly selected runtime source configuration."""

import os

from app.sources import (
    CatalogueSource,
    ConfiguredSource,
    JsonFeedConfig,
    load_catalogue_sources_for_startup,
    load_sources_for_startup,
)
from config import settings


def load_runtime_sources() -> tuple[ConfiguredSource, ...]:
    """Return scheduler fetch adapters with explicitly prepared credential snapshots."""
    path = settings.sources_config_file
    if not path:
        raise ValueError("SOURCES_CONFIG_FILE is required to start the web and scheduler processes")

    return load_sources_for_startup(
        path,
        environment=settings.env_state,
        allow_fixture=settings.allow_fixture_source,
        environ=os.environ,
    )


def load_runtime_catalogue_sources() -> tuple[CatalogueSource, ...]:
    """Return detached web policy and refuse selected feed secrets in its environment.

    Reject even empty credential variables: removing values from app state
    cannot remove secrets inherited through a deployment environment file.
    Names are read solely to enforce the role boundary; values are never read.
    """
    path = settings.sources_config_file
    if not path:
        raise ValueError("SOURCES_CONFIG_FILE is required to start the web and scheduler processes")
    sources = load_catalogue_sources_for_startup(
        path, environment=settings.env_state, allow_fixture=settings.allow_fixture_source
    )
    environment_names = frozenset(os.environ)
    if any(
        reference in environment_names
        for source in sources
        if isinstance(source.config, JsonFeedConfig)
        for reference in (source.config.credential_env, source.config.signing_key_env)
    ):
        raise ValueError("Feed credentials must be supplied only to the scheduler environment")
    return sources
