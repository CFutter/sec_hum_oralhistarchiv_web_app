"""Runtime feed activation requires a complete explicit credential snapshot."""

import base64
import hashlib
from dataclasses import replace
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest

import app.sources as source_api
from app.sources import (
    FixtureConfig,
    JsonFeedAdapter,
    JsonFeedConfig,
    JsonFeedCredentials,
    configure_sources,
    load_sources_for_startup,
    parse_source_config,
    parse_source_configs_from_toml,
    prepare_json_feed_startup,
    registered_adapter_names,
)
from app.sources.configuration import configure_sources_from_toml, load_sources_file

_FEED = """[[sources]]
name = "private_archive"
adapter = "json_feed"
label = "Private archive"
endpoint = "https://archive.example.edu/feed"
credential_env = "ARCHIVE_FEED_BEARER"
signing_key_env = "ARCHIVE_FEED_SIGNING_KEY"
max_visibility = "registered"
requires_record_tier = true
incremental_interval_seconds = 900
max_page_bytes = 524288
max_project_title_chars = 8192
"""
_FIXTURE = """[[sources]]
name = "fixture_demo"
adapter = "fixture"
label = "Demonstration archive"
"""
_BEARER = "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"
_KEY = (
    base64.urlsafe_b64encode(hashlib.sha256(b"first feed source signing key").digest())
    .decode()
    .rstrip("=")
)


def _environment():
    """Return the synthetic archive bearer and signing-key variables."""
    return {"ARCHIVE_FEED_BEARER": _BEARER, "ARCHIVE_FEED_SIGNING_KEY": _KEY}


def _credentials(configs):
    """Prepare credentials for JSON-feed configurations only."""
    return prepare_json_feed_startup(
        [config for config in configs if isinstance(config, JsonFeedConfig)],
        environment="dev",
        environ=_environment(),
    )


def test_feed_description_preparation_and_real_adapter_are_public():
    """Feed description preparation and real adapter are public."""
    assert {
        "JsonFeedConfig",
        "JsonFeedCredentials",
        "JsonFeedAdapter",
        "classify_json_feed_access",
        "parse_source_configs_from_toml",
        "prepare_json_feed_startup",
    } <= set(source_api.__all__)
    assert registered_adapter_names() == ("oai_pmh_cmdi", "fixture", "static_json", "json_feed")
    config = parse_source_config(
        {
            "adapter": "json_feed",
            "name": "private_archive",
            "display": {"label": "Private archive"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "ARCHIVE_FEED_BEARER",
            "signing_key_env": "ARCHIVE_FEED_SIGNING_KEY",
        }
    )
    assert isinstance(config, JsonFeedConfig)


def test_parse_only_toml_keeps_order_and_policy_without_constructing_or_resolving(monkeypatch):
    """Parse only toml keeps order and policy without constructing or resolving."""
    monkeypatch.setenv("ARCHIVE_FEED_BEARER", "deliberately-invalid")
    monkeypatch.setenv("ARCHIVE_FEED_SIGNING_KEY", "deliberately-invalid")
    with (
        patch("app.sources.fixture.files", autospec=True) as bundled_resource,
        patch("socket.getaddrinfo", autospec=True) as resolve,
    ):
        configs = parse_source_configs_from_toml(_FIXTURE + "\n" + _FEED)
    bundled_resource.assert_not_called()
    resolve.assert_not_called()
    assert tuple(config.name for config in configs) == ("fixture_demo", "private_archive")
    assert isinstance(configs[0], FixtureConfig)
    feed = configs[1]
    assert isinstance(feed, JsonFeedConfig)
    assert feed.display.label == "Private archive"
    assert feed.schedule.incremental_interval_seconds == 900
    assert feed.max_visibility == "registered" and feed.requires_record_tier is True
    assert feed.max_page_bytes == 524288
    assert feed.max_project_title_chars == 8192
    assert "deliberately-invalid" not in repr(feed.model_dump())


@pytest.mark.parametrize(
    "document",
    [
        "",
        "sources = []",
        _FEED + "\n" + _FEED,
        _FEED.replace('adapter = "json_feed"', 'adapter = "unknown"'),
        _FEED + '\n[sources.display]\nlabel = "Nested"\n',
        _FEED + '\nmax_pages = "7"\n',
    ],
)
def test_parse_only_does_not_bypass_document_or_model_validation(document):
    """Parse only does not bypass document or model validation."""
    with pytest.raises(ValueError):
        parse_source_configs_from_toml(document)


@pytest.mark.parametrize("feed_first", [False, True])
@pytest.mark.parametrize("boundary", ["construction", "toml", "file", "startup"])
def test_missing_credentials_reject_the_whole_selection_before_bundled_resource_io(
    tmp_path: Path, feed_first, boundary
):
    """Missing credentials reject the whole selection before bundled resource I/O."""
    document = "\n".join((_FEED, _FIXTURE) if feed_first else (_FIXTURE, _FEED))
    path = tmp_path / "sources.toml"
    path.write_text(document, encoding="utf-8")
    with (
        patch("app.sources.fixture.files", autospec=True) as bundled_resource,
        pytest.raises(ValueError, match=r"(?:prepared credentials|bearer credential)"),
    ):
        if boundary == "construction":
            configure_sources(parse_source_configs_from_toml(document))
        elif boundary == "toml":
            configure_sources_from_toml(document)
        elif boundary == "file":
            load_sources_file(path)
        else:
            load_sources_for_startup(path, environment="dev")
    bundled_resource.assert_not_called()


@pytest.mark.parametrize("boundary", ["construction", "toml", "file", "startup"])
def test_explicit_prepared_credentials_activate_the_real_adapter_without_fetching(
    tmp_path: Path, monkeypatch, boundary
):
    """Explicit prepared credentials activate the real adapter without fetching."""
    configs = parse_source_configs_from_toml(_FEED)
    credentials = _credentials(configs)
    path = tmp_path / "sources.toml"
    path.write_text(_FEED)
    monkeypatch.setenv("ARCHIVE_FEED_BEARER", "ambient values must not be read")
    with (
        patch.object(JsonFeedAdapter, "fetch", autospec=True) as fetch,
        patch("socket.getaddrinfo", autospec=True) as resolve,
    ):
        if boundary == "construction":
            sources = configure_sources(configs, credentials=credentials)
        elif boundary == "toml":
            sources = configure_sources_from_toml(_FEED, credentials=credentials)
        elif boundary == "file":
            sources = load_sources_file(path, credentials=credentials)
        else:
            sources = load_sources_for_startup(path, environment="dev", environ=_environment())
    assert len(sources) == 1 and isinstance(sources[0].adapter, JsonFeedAdapter)
    assert sources[0].policy.requires_record_tier
    assert sources[0].policy.max_visibility == "registered"
    assert sources[0].adapter.credentials.bearer_token.get_secret_value() == _BEARER
    fetch.assert_not_called()
    resolve.assert_not_called()


@pytest.mark.parametrize("failure", ["missing", "extra", "duplicate", "mismatched", "wrong_type"])
def test_invalid_credential_sets_fail_before_any_factory(failure):
    """Invalid credential sets fail before any factory."""
    configs = parse_source_configs_from_toml(_FIXTURE + "\n" + _FEED)
    credentials = _credentials(configs)
    credential = credentials[0]
    invalid = JsonFeedCredentials("another_source", credential.bearer_token, credential.signing_key)
    candidates = {
        "missing": (),
        "extra": (*credentials, invalid),
        "duplicate": (*credentials, credential),
        "mismatched": (invalid,),
        "wrong_type": (object(),),
    }[failure]
    registrations = source_api._ADAPTER_REGISTRATIONS
    factories = {
        name: create_autospec(item.factory, spec_set=True, side_effect=item.factory)
        for name, item in registrations.items()
    }
    with (
        patch.object(
            source_api,
            "_ADAPTER_REGISTRATIONS",
            {name: replace(item, factory=factories[name]) for name, item in registrations.items()},
        ),
        pytest.raises((TypeError, ValueError)),
    ):
        configure_sources(configs, credentials=candidates)
    for factory in factories.values():
        factory.assert_not_called()


def test_explicit_startup_mapping_is_required_even_if_ambient_secrets_exist(tmp_path, monkeypatch):
    """Explicit startup mapping is required even if ambient secrets exist."""
    path = tmp_path / "sources.toml"
    path.write_text(_FEED)
    for key, value in _environment().items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match="bearer credential"):
        load_sources_for_startup(path, environment="dev")


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_feed_actual_adapter_is_subject_to_hardened_endpoint_policy(environment):
    """Feed actual adapter is subject to hardened endpoint policy."""
    from app.sources import validate_source_startup  # noqa: PLC0415

    config = parse_source_configs_from_toml(
        _FEED.replace("archive.example.edu", "archive.example.org")
    )[0]
    sources = configure_sources((config,), credentials=_credentials((config,)))
    with pytest.raises(ValueError, match="placeholder endpoint"):
        validate_source_startup(sources, environment=environment)
