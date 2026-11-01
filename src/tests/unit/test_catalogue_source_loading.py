"""Serving catalogue policy never needs scheduler fetch capabilities or secrets."""

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest

from app import sources as source_api
from app.catalogue_runtime import publish_catalogue_sources, replace_catalogue_sources
from app.services import build_catalogue_policy, runtime_sources, synchronize_search_policy
from app.sources import (
    CatalogueSource,
    FixtureConfig,
    JsonFeedConfig,
    SourceDisplay,
    StaticJsonConfig,
    catalogue_sources,
    configure_sources,
    load_catalogue_sources_for_startup,
    load_sources_for_startup,
    prepare_json_feed_startup,
)
from tests.source_fixtures import legacy_source

_DOCUMENT = """[[sources]]
name = "selected_feed"
adapter = "json_feed"
label = "Selected feed"
endpoint = "https://feed.archive.edu/catalogue"
credential_env = "SELECTED_FEED_BEARER"
signing_key_env = "SELECTED_FEED_KEY"
max_visibility = "registered"
"""


def _feed_config():
    """Return a registered-tier feed configuration with named credential variables."""
    return JsonFeedConfig(
        name="selected_feed",
        display=SourceDisplay(label="Selected feed"),
        endpoint="https://feed.archive.edu/catalogue",
        credential_env="SELECTED_FEED_BEARER",
        signing_key_env="SELECTED_FEED_KEY",
        max_visibility="registered",
    )


def _credentials(config):
    """Prepare synthetic credentials for the selected feed in development mode."""
    return prepare_json_feed_startup(
        (config,),
        environment="dev",
        environ={
            config.credential_env: "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8",
            config.signing_key_env: base64.urlsafe_b64encode(
                hashlib.sha256(b"catalogue loader synthetic signing material").digest()
            )
            .decode()
            .rstrip("="),
        },
    )


def test_web_loads_feed_metadata_without_resolving_credentials_or_constructing_adapters(tmp_path):
    """Web loads feed metadata without resolving credentials or constructing adapters."""
    path = tmp_path / "sources.toml"
    path.write_text(_DOCUMENT)
    with (
        patch(
            "app.sources.startup_file.prepare_json_feed_startup",
            autospec=True,
            side_effect=AssertionError,
        ),
        patch(
            "app.sources.startup_file.configure_sources", autospec=True, side_effect=AssertionError
        ),
        patch("socket.getaddrinfo", autospec=True, side_effect=AssertionError),
    ):
        sources = load_catalogue_sources_for_startup(path, environment="dev")
    assert sources[0].name == "selected_feed"
    assert isinstance(sources[0], CatalogueSource)
    assert not hasattr(sources[0], "adapter")
    assert not hasattr(sources[0], "fetch")
    assert not hasattr(sources[0], "credentials")
    with pytest.raises(FrozenInstanceError):
        sources[0].policy = None
    with pytest.raises(ValueError, match="bearer credential is missing or invalid"):
        load_sources_for_startup(path, environment="dev", environ={})


def test_all_registered_adapters_have_identical_nonsecret_policy_and_fingerprints():
    """All registered adapters have identical nonsecret policy and fingerprints."""
    feed = _feed_config()
    configs = (
        legacy_source().config,
        FixtureConfig(name="fixture", display=SourceDisplay(label="Fixture")),
        StaticJsonConfig(name="static", display=SourceDisplay(label="Static")),
        feed,
    )
    configured = configure_sources(configs, credentials=_credentials(feed))
    # Even bundled payloads must not be read when compiling serving metadata.
    with (
        patch("app.sources.fixture.files", autospec=True, side_effect=AssertionError),
        patch("app.sources.static_json.files", autospec=True, side_effect=AssertionError),
    ):
        metadata = catalogue_sources(configs)
    assert {source.config.adapter for source in metadata} == set(
        source_api.registered_adapter_names()
    )
    assert tuple(source.policy for source in metadata) == tuple(
        source.policy for source in configured
    )
    web = build_catalogue_policy(metadata)
    scheduler = build_catalogue_policy(configured)
    assert web.fingerprint == scheduler.fingerprint
    assert web.page_masks == scheduler.page_masks
    assert web.document_masks_json == scheduler.document_masks_json


@pytest.mark.parametrize("reference", ("SELECTED_FEED_BEARER", "SELECTED_FEED_KEY"))
@pytest.mark.parametrize("value", ("", "synthetic-secret-value"))
def test_web_refuses_selected_feed_environment_even_when_empty(
    monkeypatch, tmp_path, reference, value
):
    """Web refuses selected feed environment even when empty."""
    path = tmp_path / "sources.toml"
    path.write_text(_DOCUMENT)
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file=str(path),
            env_state="dev",
            allow_fixture_source=False,
        ),
    )
    monkeypatch.delenv("SELECTED_FEED_BEARER", raising=False)
    monkeypatch.delenv("SELECTED_FEED_KEY", raising=False)
    assert runtime_sources.load_runtime_catalogue_sources()[0].name == "selected_feed"
    monkeypatch.setenv(reference, value)
    with pytest.raises(ValueError, match="only to the scheduler environment") as error:
        runtime_sources.load_runtime_catalogue_sources()
    assert "synthetic-secret-value" not in str(error.value)


def test_web_environment_refusal_reads_only_variable_names(monkeypatch, tmp_path):
    """Web environment refusal reads only variable names."""

    class NamesOnly(Mapping[str, str]):
        """Expose one environment name and fail if its value is read."""

        def __iter__(self):
            """Iterate the single feed credential variable name."""
            return iter(("SELECTED_FEED_BEARER",))

        def __len__(self):
            """Report one exposed environment variable."""
            return 1

        def __getitem__(self, _name):
            """Fail if web source loading reads an environment value."""
            raise AssertionError("Web source loading accessed an environment value")

    path = tmp_path / "sources.toml"
    path.write_text(_DOCUMENT)
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file=str(path),
            env_state="dev",
            allow_fixture_source=False,
        ),
    )
    with monkeypatch.context() as isolated_environment:
        isolated_environment.setattr(runtime_sources.os, "environ", NamesOnly())
        with pytest.raises(ValueError, match="only to the scheduler environment"):
            runtime_sources.load_runtime_catalogue_sources()


@pytest.mark.parametrize("loader", (load_catalogue_sources_for_startup, load_sources_for_startup))
@pytest.mark.parametrize(
    "change,message",
    (
        ("https://feed.example.org/catalogue", "placeholder endpoint host"),
        ("https://feed.archive.edu/catalogue", "signing-key references must be unique"),
    ),
)
def test_both_runtime_roles_reject_nonsecret_feed_policy_before_secrets(loader, change, message):
    """Both runtime roles reject nonsecret feed policy before secrets."""
    document = _DOCUMENT.replace("https://feed.archive.edu/catalogue", change)
    if "unique" in message:
        document += _DOCUMENT.replace('name = "selected_feed"', 'name = "second_feed"')
    with (
        patch("app.sources.startup_file._read_hardened_file", autospec=True, return_value=document),
        pytest.raises(ValueError, match=message),
    ):
        loader("/etc/oralhistarchiv-sources/sources.toml", environment="staging")


async def test_publication_drops_adapter_and_waits_for_durable_binding(monkeypatch):
    """Publication drops adapter and waits for durable binding."""
    previous = (legacy_source(name="previous"),)
    app = SimpleNamespace(state=SimpleNamespace())
    old = replace_catalogue_sources(app, previous)
    feed = _feed_config()
    selected = configure_sources((feed,), credentials=_credentials(feed))
    pool = object()

    async def verify(observed_pool, policy):
        """Require adapter-free policy verification while the previous policy remains published."""
        assert observed_pool is pool
        assert app.state.catalogue_policy is old
        assert all(isinstance(source, CatalogueSource) for source in policy.sources)
        assert policy.fingerprint == build_catalogue_policy(selected).fingerprint

    probe = create_autospec(synchronize_search_policy, side_effect=verify)
    monkeypatch.setattr("app.services.synchronize_search_policy", probe)
    published = await publish_catalogue_sources(app, pool, selected)
    probe.assert_awaited_once()
    assert app.state.catalogue_policy is published
    assert app.state.configured_sources is published.sources
    assert not hasattr(published.sources[0], "adapter")

    probe.side_effect = RuntimeError("Durable policy binding differs")
    with pytest.raises(RuntimeError, match="binding differs"):
        await publish_catalogue_sources(app, pool, previous)
    assert app.state.catalogue_policy is published
    assert app.state.configured_sources is published.sources


async def test_empty_offline_snapshot_does_not_allow_an_empty_runtime_selection(tmp_path):
    """Empty offline snapshot does not allow an empty runtime selection."""
    app = SimpleNamespace(state=SimpleNamespace())
    offline = replace_catalogue_sources(app, ())
    assert offline.sources == ()
    with pytest.raises(ValueError, match="At least one source"):
        await publish_catalogue_sources(app, object(), ())
    path = tmp_path / "empty.toml"
    path.write_text("sources = []\n")
    with pytest.raises(ValueError, match="at least 1 item"):
        load_catalogue_sources_for_startup(path, environment="dev")
    assert app.state.catalogue_policy is offline
