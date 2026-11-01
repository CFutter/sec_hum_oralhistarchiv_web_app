"""The shared OAI test source is independent of runtime source settings."""

import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from app.ingestion_contracts import HarvestResult
from app.services import runtime_sources
from app.sources import OaiPmhCmdiAdapter, OaiPmhCmdiConfig, load_sources_for_startup, oai_client
from app.sources.oai_client import fetch_updates_isolated
from tests.oai_fixtures import SOURCE_CURSOR, fetch_updates_in_process
from tests.source_fixtures import (
    TEST_INSTITUTION_FILTER,
    TEST_OAI_ENDPOINT,
    TEST_SOURCE_NAME,
    legacy_source,
)


def test_in_process_oai_boundary_preserves_the_isolated_signature():
    """Check in process OAI boundary preserves the isolated signature."""
    assert inspect.signature(fetch_updates_in_process, eval_str=True) == inspect.signature(
        fetch_updates_isolated, eval_str=True
    )


@pytest.mark.parametrize("max_pages", (None, 7))
def test_in_process_oai_boundary_forwards_only_parser_arguments(monkeypatch, max_pages):
    """Check in process OAI boundary forwards only parser arguments."""
    expected = HarvestResult(source_cursor=SOURCE_CURSOR)
    direct = create_autospec(oai_client.fetch_updates, spec_set=True, return_value=expected)
    monkeypatch.setattr(oai_client, "fetch_updates", direct)
    isolated = create_autospec(
        fetch_updates_isolated, spec_set=True, side_effect=fetch_updates_in_process
    )
    overrides = {} if max_pages is None else {"max_pages": max_pages}

    result = isolated(
        TEST_OAI_ENDPOINT,
        "2020-01-02",
        TEST_INSTITUTION_FILTER,
        source=TEST_SOURCE_NAME,
        log_level="INFO",
        log_format="json",
        **overrides,
    )

    assert result is expected
    direct.assert_called_once_with(
        oai_url=TEST_OAI_ENDPOINT,
        since="2020-01-02",
        institution_filter=TEST_INSTITUTION_FILTER,
        max_pages=oai_client.OAI_DEFAULT_MAX_PAGES if max_pages is None else max_pages,
    )


def test_test_source_uses_explicit_configuration_without_fetching(monkeypatch):
    """Check test source uses explicit configuration without fetching."""
    monkeypatch.setattr(runtime_sources, "settings", SimpleNamespace())

    adapter_fetch = create_autospec(
        OaiPmhCmdiAdapter.fetch,
        side_effect=AssertionError("source construction fetched records"),
    )
    transport = create_autospec(
        fetch_updates_isolated,
        side_effect=AssertionError("source construction invoked transport"),
    )
    monkeypatch.setattr(OaiPmhCmdiAdapter, "fetch", adapter_fetch)
    monkeypatch.setattr("app.sources.oai_client.fetch_updates_isolated", transport)

    source = legacy_source()

    assert isinstance(source.config, OaiPmhCmdiConfig)
    assert isinstance(source.adapter, OaiPmhCmdiAdapter)
    assert source.name == TEST_SOURCE_NAME
    assert source.adapter.oai_url == TEST_OAI_ENDPOINT
    assert source.adapter.institution_filter == TEST_INSTITUTION_FILTER
    assert source.adapter.max_pages == 500
    assert source.policy.max_visibility == "vetted"
    assert source.policy.requires_record_tier is False
    assert source.schedule.incremental_interval_seconds == 3600
    assert source.schedule.rebuild_interval_seconds == 86400
    assert source.schedule.write_timeout_seconds == 120
    adapter_fetch.assert_not_called()
    transport.assert_not_called()


def test_test_source_overrides_do_not_mutate_subsequent_sources():
    """Check test source overrides do not mutate subsequent sources."""
    baseline = legacy_source()
    changed = legacy_source(
        name="other_archive",
        endpoint="https://other.example.org/oai",
        institution_filter="Other archive",
        max_pages=7,
        max_visibility="registered",
        requires_record_tier=False,
        schedule={
            "incremental_interval_seconds": 17,
            "rebuild_interval_seconds": 41,
            "write_timeout_seconds": 119,
        },
    )

    assert isinstance(changed.adapter, OaiPmhCmdiAdapter)
    assert changed.name == changed.adapter.name == "other_archive"
    assert changed.adapter.oai_url == "https://other.example.org/oai"
    assert changed.adapter.institution_filter == "Other archive"
    assert changed.adapter.max_pages == 7
    assert changed.policy.max_visibility == "registered"
    assert changed.policy.requires_record_tier is False
    assert changed.schedule.incremental_interval_seconds == 17
    assert changed.schedule.rebuild_interval_seconds == 41
    assert changed.schedule.write_timeout_seconds == 119

    ordinary = legacy_source()
    assert ordinary.config == baseline.config
    assert ordinary is not baseline
    assert ordinary.adapter is not baseline.adapter


def test_bootstrap_source_file_matches_the_explicit_test_source():
    """Check bootstrap source file matches the explicit test source."""
    path = Path(__file__).resolve().parents[1] / "sources.toml"
    sources = load_sources_for_startup(path, environment="dev")

    assert len(sources) == 1
    assert (
        sources[0].config.model_dump() == legacy_source(max_visibility="public").config.model_dump()
    )
