"""Runtime startup requires one explicit, validated source-file selection."""

import os
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest
from dotenv import dotenv_values

from app.paths import PROJECT_ROOT
from app.services import runtime_sources
from app.sources import (
    FixtureAdapter,
    FixtureConfig,
    OaiPmhCmdiAdapter,
    SourceDisplay,
    configure_sources,
    load_sources_for_startup,
)


@pytest.mark.parametrize("environment", ["dev", "staging", "production"])
@pytest.mark.parametrize("selected_path", [None, ""], ids=["unset", "empty"])
def test_runtime_requires_explicit_source_selection_before_file_loading(
    monkeypatch, environment, selected_path
):
    """Check runtime requires explicit source selection before file loading (ValueError)."""
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file=selected_path,
            env_state=environment,
            allow_fixture_source=False,
        ),
    )
    loader = create_autospec(load_sources_for_startup)
    monkeypatch.setattr(runtime_sources, "load_sources_for_startup", loader)

    with pytest.raises(ValueError, match=r"SOURCES_CONFIG_FILE.*required"):
        runtime_sources.load_runtime_sources()

    loader.assert_not_called()


@pytest.mark.parametrize(
    ("environment", "allow_fixture"),
    [("dev", False), ("staging", False), ("production", True)],
)
def test_runtime_returns_the_exact_validated_tuple(monkeypatch, environment, allow_fixture):
    """Check runtime returns the exact validated tuple."""
    monkeypatch.setenv("RUNTIME_SOURCE_ENV_PROBE", "synthetic-runtime-value")
    sources = configure_sources(
        (
            FixtureConfig(name="archive_one", display=SourceDisplay(label="Archive one")),
            FixtureConfig(name="archive_two", display=SourceDisplay(label="Archive two")),
        )
    )
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file="/etc/oralhistarchiv-sources/sources.toml",
            env_state=environment,
            allow_fixture_source=allow_fixture,
        ),
    )
    loader = create_autospec(load_sources_for_startup, return_value=sources)
    monkeypatch.setattr(runtime_sources, "load_sources_for_startup", loader)

    selected = runtime_sources.load_runtime_sources()

    assert selected is sources
    assert loader.call_args.kwargs["environ"] is os.environ
    assert (
        loader.call_args.kwargs["environ"]["RUNTIME_SOURCE_ENV_PROBE"] == "synthetic-runtime-value"
    )
    loader.assert_called_once_with(
        "/etc/oralhistarchiv-sources/sources.toml",
        environment=environment,
        allow_fixture=allow_fixture,
        environ=os.environ,
    )


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("source file missing"),
        PermissionError("source file unreadable"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid source text"),
        ValueError("invalid source policy"),
    ],
    ids=["missing", "unreadable", "invalid-utf8", "invalid-policy"],
)
def test_runtime_file_failure_propagates_without_fallback(monkeypatch, failure):
    """Check runtime file failure propagates without fallback."""
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file="selected-sources.toml",
            env_state="dev",
            allow_fixture_source=False,
        ),
    )
    loader = create_autospec(load_sources_for_startup, side_effect=failure)
    monkeypatch.setattr(runtime_sources, "load_sources_for_startup", loader)

    with pytest.raises(type(failure)) as raised:
        runtime_sources.load_runtime_sources()

    assert raised.value is failure
    loader.assert_called_once_with(
        "selected-sources.toml", environment="dev", allow_fixture=False, environ=os.environ
    )


def test_development_example_selects_the_offline_source_without_fetching(monkeypatch):
    """Check development example selects the offline source without fetching."""
    values = dotenv_values(PROJECT_ROOT / ".env.example", interpolate=False)
    assert values["ENV_STATE"] == "dev"
    assert values["SOURCES_CONFIG_FILE"] == "deploy/environment/sources.dev.toml"
    assert values["ALLOW_FIXTURE_SOURCE"] == "false"

    monkeypatch.chdir(PROJECT_ROOT)
    monkeypatch.setattr(
        runtime_sources,
        "settings",
        SimpleNamespace(
            sources_config_file=values["SOURCES_CONFIG_FILE"],
            env_state="dev",
            allow_fixture_source=False,
        ),
    )

    with (
        patch.object(FixtureAdapter, "fetch", autospec=True) as fixture_fetch,
        patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as oai_fetch,
    ):
        sources = runtime_sources.load_runtime_sources()

    assert tuple(source.name for source in sources) == ("fixture_demo",)
    assert isinstance(sources[0].adapter, FixtureAdapter)
    fixture_fetch.assert_not_called()
    oai_fetch.assert_not_called()
