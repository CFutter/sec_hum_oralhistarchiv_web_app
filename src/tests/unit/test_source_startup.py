"""Explicit environment policy for already constructed source snapshots."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from app.sources import (
    ConfiguredSource,
    FixtureAdapter,
    FixtureConfig,
    OaiPmhCmdiAdapter,
    OaiPmhCmdiConfig,
    SourceDisplay,
    configure_sources,
    validate_source_startup,
)


def _oai(endpoint: str = "https://archive.example.edu/oai") -> ConfiguredSource:
    """Configure the sample online OAI source with the selected endpoint."""
    return configure_sources(
        (
            OaiPmhCmdiConfig(
                name="online_archive",
                display=SourceDisplay(label="Online archive"),
                endpoint=endpoint,
                institution_filter="Configured archive",
            ),
        )
    )[0]


def _fixture() -> ConfiguredSource:
    """Configure a single offline fixture source."""
    return configure_sources(
        (FixtureConfig(name="offline_archive", display=SourceDisplay(label="Offline archive")),)
    )[0]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_hardened_environments_require_https(environment: str) -> None:
    """Check hardened environments require https (ValueError)."""
    with pytest.raises(ValueError, match="online_archive"):
        validate_source_startup((_oai("http://archive.example.edu/oai"),), environment=environment)


@pytest.mark.parametrize(
    "host",
    [
        "archive.example.org",
        "EXAMPLE.COM.",
        "example.net",
        "archive.example",
        "archive.invalid",
        "archive.test",
        "archive.localhost",
    ],
)
def test_hardened_environments_reject_placeholder_hosts(host: str) -> None:
    """Check hardened environments reject placeholder hosts (ValueError)."""
    source = _oai(f"https://{host}/oai")
    for environment in ("staging", "production"):
        with pytest.raises(ValueError, match="online_archive"):
            validate_source_startup((source,), environment=environment)


def test_hardened_environments_accept_a_configured_https_endpoint() -> None:
    """Check hardened environments accept a configured https endpoint."""
    for environment in ("staging", "production"):
        validate_source_startup((_oai(),), environment=environment)


def test_startup_checks_the_actual_adapter_endpoint() -> None:
    """Check startup checks the actual adapter endpoint (ValueError)."""
    source = _oai()
    assert isinstance(source.adapter, OaiPmhCmdiAdapter)
    source = replace(
        source,
        adapter=replace(source.adapter, oai_url="http://archive.example.edu/oai"),
    )
    assert isinstance(source.config, OaiPmhCmdiConfig)
    assert source.config.endpoint == "https://archive.example.edu/oai"
    with pytest.raises(ValueError, match="online_archive"):
        validate_source_startup((source,), environment="production")


def test_development_allows_http_and_placeholder_endpoints() -> None:
    """Check development allows HTTP and placeholder endpoints."""
    validate_source_startup((_oai("http://archive.example.org/oai"),), environment="dev")


@pytest.mark.parametrize(
    ("environment", "allow_fixture"),
    [("dev", False), ("staging", False), ("production", True)],
)
def test_fixture_activation_obeys_the_explicit_environment_policy(
    environment: str, allow_fixture: bool
) -> None:
    """Check fixture activation obeys the explicit environment policy."""
    validate_source_startup((_fixture(),), environment=environment, allow_fixture=allow_fixture)


def test_production_refuses_fixtures_by_default() -> None:
    """Check production refuses fixtures by default (ValueError)."""
    with pytest.raises(ValueError, match="offline_archive"):
        validate_source_startup((_fixture(),), environment="production")


@pytest.mark.parametrize("duplicate", [False, True], ids=["empty", "duplicate-name"])
def test_startup_requires_a_nonempty_unambiguous_source_set(duplicate: bool) -> None:
    """Check startup requires a nonempty unambiguous source set (ValueError)."""
    sources = (_oai(), _oai()) if duplicate else ()
    with pytest.raises(ValueError):
        validate_source_startup(sources, environment="dev")


def test_unknown_environment_is_rejected() -> None:
    """Check unknown environment is rejected (ValueError)."""
    with pytest.raises(ValueError):
        validate_source_startup((_oai(),), environment="unknown")


def test_fixture_override_must_be_an_explicit_boolean() -> None:
    """Check fixture override must be an explicit boolean (TypeError)."""
    with pytest.raises(TypeError):
        validate_source_startup(
            (_fixture(),),
            environment="production",
            allow_fixture="false",  # type: ignore[arg-type]
        )


def test_validation_does_not_fetch_fingerprint_or_resolve_hosts() -> None:
    """Check validation does not fetch fingerprint or resolve hosts."""
    sources = (_oai(), _fixture())
    before = tuple(source.config.model_dump() for source in sources)
    with (
        patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as oai_fetch,
        patch.object(FixtureAdapter, "fetch", autospec=True) as fixture_fetch,
        patch.object(OaiPmhCmdiAdapter, "config_fingerprint", autospec=True) as oai_binding,
        patch.object(FixtureAdapter, "config_fingerprint", autospec=True) as fixture_binding,
        patch("socket.getaddrinfo", autospec=True) as resolve,
    ):
        validate_source_startup(sources, environment="staging")

    oai_fetch.assert_not_called()
    fixture_fetch.assert_not_called()
    oai_binding.assert_not_called()
    fixture_binding.assert_not_called()
    resolve.assert_not_called()
    assert tuple(source.name for source in sources) == ("online_archive", "offline_archive")
    assert tuple(source.config.model_dump() for source in sources) == before
