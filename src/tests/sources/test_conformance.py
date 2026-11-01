"""Shared contracts for every registered source, using recorded native input."""

import importlib
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest.mock import create_autospec

import pytest

from app.ingestion_contracts.cancellation import HarvestCancelled
from app.services import get_db_cursor, ingestion
from app.services.access_tiers import SourceVisibilityTierError
from app.services.schema import DATASET_INSERT_COLUMNS
from app.services.source_fetch import run_source_fetch
from app.services.stored_harvest import encode_stored_harvest
from app.sources import (
    load_sources_for_startup,
    registered_adapter_names,
    validate_source_startup,
)
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.ingestion_doubles import dataset_write_state_from_params
from tests.sources.contracts import Case


def test_every_registered_adapter_has_a_case_provider():
    """Verify every registered adapter has a case provider."""
    names = registered_adapter_names()
    assert names, "The adapter registry must not be empty"
    for name in names:
        provider = importlib.import_module(f"tests.sources.cases.{name}")
        assert callable(provider.make_case), f"Missing make_case() for {name}"


def test_construction_and_fingerprinting_do_not_harvest(source_case: Case, monkeypatch):
    """Verify construction and fingerprinting do not harvest."""
    original_fetch = source_case.adapter_type.fetch
    fetch = create_autospec(
        original_fetch, side_effect=AssertionError("Construction must not harvest")
    )
    monkeypatch.setattr(source_case.adapter_type, "fetch", fetch)

    source = source_case.build()
    assert source.config.adapter == source_case.adapter_id
    assert isinstance(source.adapter, source_case.adapter_type)
    assert source.name == source.adapter.name == source.policy.name == source.config.name
    assert source.policy.max_visibility == source.config.max_visibility
    assert source.policy.requires_record_tier == source.config.requires_record_tier
    fingerprint = source.adapter.config_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint)
    assert source_case.build().adapter.config_fingerprint() == fingerprint
    fetch.assert_not_called()
    assert not source_case.io_calls


@pytest.mark.parametrize("environment", ["dev", "staging", "production"])
def test_flat_file_and_explicit_startup_policy(
    source_case: Case, tmp_path: Path, environment: str, monkeypatch
):
    """Verify flat file and explicit startup policy."""
    original_fetch = source_case.adapter_type.fetch
    fetch = create_autospec(original_fetch, side_effect=AssertionError("Startup must not harvest"))
    monkeypatch.setattr(source_case.adapter_type, "fetch", fetch)
    path = tmp_path / "sources.toml"
    path.write_text(source_case.document, encoding="utf-8")

    # Trusted-path traversal has its own suite. Exercise actual construction
    # here in dev, then the real adapter activation policy in each environment.
    loaded = load_sources_for_startup(str(path), environment="dev", environ=source_case.environ)
    expected = source_case.build()
    assert len(loaded) == 1
    assert loaded[0].config == expected.config
    assert isinstance(loaded[0].adapter, source_case.adapter_type)
    assert loaded[0].adapter.config_fingerprint() == expected.adapter.config_fingerprint()
    validate_source_startup(loaded, environment=environment, allow_fixture=True)
    fetch.assert_not_called()
    assert not source_case.io_calls


def test_complete_native_harvest(source_case: Case):
    """Verify complete native harvest."""
    harvest = source_case.build().adapter.fetch(since=None)
    assert harvest.validate() == source_case.cursor
    assert tuple(record["uuid"] for record in harvest.matching_records) == source_case.full_ids
    assert tuple(record.get("visibility_tier") for record in harvest.matching_records) == (
        source_case.raw_tiers
    )
    assert not harvest.deleted_uuids
    assert not harvest.nonmatching_uuids
    assert not harvest.uncertain_records


@pytest.mark.parametrize("offset", [0, -13, 13])
def test_inclusive_boundary_uses_the_utc_instant(source_case: Case, offset: int):
    """Verify inclusive boundary uses the utc instant."""
    adapter = source_case.build().adapter
    full = adapter.fetch(since=None)
    assert any(
        record["upstream_modified_at"] == source_case.boundary for record in full.matching_records
    )
    boundary = source_case.boundary.astimezone(timezone(timedelta(hours=offset)))
    if offset:
        assert boundary.date() != source_case.boundary.date()

    harvest = adapter.fetch(since=boundary)
    assert harvest.validate() == source_case.cursor
    assert tuple(record["uuid"] for record in harvest.matching_records) == (
        source_case.boundary_ids
    )


@pytest.mark.parametrize(
    ("since", "error"),
    [("2020-01-02", TypeError), (123, TypeError), (datetime(2020, 1, 2), ValueError)],  # noqa: DTZ001
)
def test_invalid_boundary_fails_before_io(source_case: Case, since, error):
    """Verify invalid boundary fails before io."""
    adapter = source_case.build().adapter
    before = len(source_case.io_calls)
    with pytest.raises(error):
        adapter.fetch(since=since)
    assert len(source_case.io_calls) == before


def test_fetch_returns_independent_mutable_results(source_case: Case):
    """Verify fetch returns independent mutable results."""
    adapter = source_case.build().adapter
    fingerprint = adapter.config_fingerprint()
    first = adapter.fetch(since=None)
    baseline = deepcopy(first)
    assert first.matching_records[0]["keywords"]
    assert first.matching_records[0]["resource_proxies"]
    first.matching_records[0]["keywords"].append("local mutation")
    first.matching_records[0]["resource_proxies"][0]["ref"] = "https://changed.example.org/"
    first.matching_records.clear()
    first.deleted_uuids.add("local:deleted")
    first.nonmatching_uuids.add("local:nonmatching")
    first.uncertain_records["local:uncertain"] = "local mutation"

    later = adapter.fetch(since=None)
    assert later == baseline
    assert later.validate() == source_case.cursor
    assert adapter.config_fingerprint() == fingerprint


@pytest.mark.parametrize("change", ["identity", "visibility", "required_tier"])
def test_interpretation_changes_invalidate_the_fingerprint(source_case: Case, change: str):
    """Verify interpretation changes invalidate the fingerprint."""
    original = source_case.build()
    overrides: dict[str, object]
    if change == "identity":
        overrides = {"name": "other_archive"}
    elif change == "visibility":
        overrides = {"max_visibility": "registered"}
    else:
        if not source_case.supports_required_record_tier:
            with pytest.raises(ValueError, match="requires_record_tier must be false"):
                source_case.build(requires_record_tier=True)
            return
        if source_case.mandatory_record_tier:
            with pytest.raises(ValueError, match="requires explicit record tiers"):
                source_case.build(requires_record_tier=False)
            return
        overrides = {"requires_record_tier": not original.policy.requires_record_tier}
    changed = source_case.build(**overrides)
    assert changed.config != original.config
    assert changed.adapter.config_fingerprint() != original.adapter.config_fingerprint()


def test_operational_changes_preserve_the_fingerprint(source_case: Case):
    """Verify operational changes preserve the fingerprint."""
    original = source_case.build()
    changed = source_case.build(**source_case.operational_overrides)
    assert changed.config != original.config
    assert changed.adapter.config_fingerprint() == original.adapter.config_fingerprint()


def test_native_input_budget_is_enforced(source_case: Case):
    # A fixture bounds its snapshot at construction; OAI bounds pages at fetch.
    """Verify native input budget is enforced."""
    with pytest.raises(source_case.budget_error, match=source_case.budget_match):
        source_case.build(**source_case.insufficient_budget).adapter.fetch(since=None)


@pytest.mark.parametrize("with_staged", [False, True])
async def test_changed_binding_fences_cursor_and_staged_replay(
    source_case: Case, with_staged: bool, monkeypatch
):
    """Verify changed binding fences cursor and staged replay."""
    original = source_case.build()
    fingerprint = original.adapter.config_fingerprint()
    harvest = original.adapter.fetch(since=None)
    changed = source_case.build(max_visibility="registered")
    assert changed.adapter.config_fingerprint() != fingerprint
    payload = (
        encode_stored_harvest(harvest, source_fingerprint=fingerprint) if with_staged else None
    )
    cur = make_async_cursor(
        fetchone={
            "source_cursor": source_case.cursor,
            "source_fingerprint": fingerprint,
            "incremental_harvest": payload,
            "incremental_started_at": datetime(2020, 1, 5, tzinfo=UTC) if with_staged else None,
            "incremental_position": 0,
            "incremental_affected": 0,
        }
    )
    original_cursor = get_db_cursor
    threadpool = create_autospec(run_source_fetch)
    replay = create_autospec(ingestion._write_incremental)
    monkeypatch.setattr(
        ingestion,
        "get_db_cursor",
        create_autospec(original_cursor, return_value=FakeCursorCtx(cur)),
    )
    monkeypatch.setattr(ingestion, "run_source_fetch", threadpool)
    monkeypatch.setattr(ingestion, "_write_incremental", replay)
    before = len(source_case.io_calls)

    with pytest.raises(ingestion._FullReharvestRequired, match="operator acknowledgement required"):
        await ingestion._sync_source(make_mock_pool(), configured_source=changed)

    threadpool.assert_not_awaited()
    replay.assert_not_awaited()
    assert len(source_case.io_calls) == before
    assert cur.execute.await_count == 2
    assert cur.execute.await_args_list[0].args[1] == (changed.name,)
    assert cur.execute.await_args_list[1].args[1] == (
        changed.name,
        fingerprint,
        changed.adapter.config_fingerprint(),
    )


async def test_native_records_use_the_selected_source_and_tier_policy(
    source_case: Case, monkeypatch
):
    """Verify native records use the selected source and tier policy."""
    source = source_case.build(max_visibility="registered")
    harvest = source.adapter.fetch(since=None)
    write = create_autospec(
        ingestion.upsert_dataset,
        spec_set=True,
        side_effect=dataset_write_state_from_params,
    )
    monkeypatch.setattr(ingestion, "upsert_dataset", write)
    cur = make_async_cursor()

    for record in harvest.matching_records:
        await ingestion._upsert_public_catalogue_record(cur, record, source.policy)

    rows = [
        dict(zip(DATASET_INSERT_COLUMNS, call.args[1], strict=True))
        for call in write.await_args_list
    ]
    assert tuple(row["uuid"] for row in rows) == source_case.full_ids
    assert all(row["source"] == source.name for row in rows)
    assert tuple(row["visibility_tier"] for row in rows) == source_case.expected_registered_tiers
    cur.execute.assert_not_awaited()


async def test_shared_write_boundary_rejects_a_missing_mandatory_tier(
    source_case: Case, monkeypatch
):
    """Verify shared write boundary rejects a missing mandatory tier."""
    if not source_case.supports_required_record_tier:
        with pytest.raises(ValueError, match="requires_record_tier must be false"):
            source_case.build(requires_record_tier=True)
        assert not source_case.io_calls
        return
    harvest = source_case.build().adapter.fetch(since=None)
    record = deepcopy(harvest.matching_records[0])
    record["visibility_tier"] = None
    source = source_case.build(requires_record_tier=True)
    write = create_autospec(
        ingestion.upsert_dataset,
        spec_set=True,
        side_effect=dataset_write_state_from_params,
    )
    monkeypatch.setattr(ingestion, "upsert_dataset", write)
    cur = make_async_cursor()

    with pytest.raises(SourceVisibilityTierError, match="missing required visibility_tier"):
        await ingestion._upsert_public_catalogue_record(cur, record, source.policy)

    write.assert_not_awaited()
    cur.execute.assert_not_awaited()


def test_cancelled_fetch_fails_before_io_for_every_adapter(source_case: Case):
    """Verify cancelled fetch fails before io for every adapter."""
    adapter = source_case.build().adapter
    before = len(source_case.io_calls)
    cancel_event = Event()
    cancel_event.set()
    with pytest.raises(HarvestCancelled):
        adapter.fetch(since=None, cancel_event=cancel_event)
    assert len(source_case.io_calls) == before
