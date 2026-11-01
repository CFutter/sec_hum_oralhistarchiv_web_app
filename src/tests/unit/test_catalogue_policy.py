"""Compiled catalogue policy is reused without caching live record decisions."""

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import MappingProxyType, SimpleNamespace
from typing import cast
from unittest.mock import create_autospec

import pytest
from fastapi import Request

from app import search_mask_contract as masks
from app.catalogue_runtime import replace_catalogue_sources
from app.routes import pages
from app.services import cache as cache_module
from app.services import datasets
from app.services.cache import CatalogueStatsCache
from app.services.datasets import Dataset
from app.services.schema import DATASET_SELECT_COLUMNS
from app.services.search_query import parse_search_query
from tests.fixtures import make_async_cursor, make_mock_pool, replace_test_catalogue_sources
from tests.source_fixtures import legacy_source

_TIERS = ("public", "registered", "vetted")
_FILTERS = {"keyword": "", "language": "", "access_level": ""}


def _sources(**changes):
    """Return a source with protected description/keywords and explicit policy overrides."""
    values = {
        "name": "compiled_archive",
        "max_visibility": "public",
        "field_visibility": {"description": "registered", "keywords": "vetted"},
    }
    return (legacy_source(**(values | changes)),)


def _dataset(**changes):
    """Return a public sample dataset with protected metadata and explicit overrides."""
    return Dataset(
        **(
            {
                "id": 1,
                "uuid": "compiled-record",
                "title": "Public discovery",
                "source": "compiled_archive",
                "visibility_tier": "public",
                "description": "Protected description",
                "keywords": ["Protected keyword"],
            }
            | changes
        )
    )


def _forbid_recompilation(monkeypatch):
    """Fail if a compiled-policy consumer rebuilds source or dataclass policy."""

    def unexpected(*_args, **_kwargs):
        """Fail immediately when a compiled policy is rebuilt."""
        pytest.fail("A compiled policy consumer rebuilt source/model policy")

    monkeypatch.setattr(datasets, "compile_catalogue_policy", unexpected)
    monkeypatch.setattr(datasets, "dataclass_fields", unexpected)


@pytest.mark.parametrize("source_name", ("compiled_archive", "retained_archive"))
@pytest.mark.parametrize("record_tier", _TIERS)
@pytest.mark.parametrize("viewer", _TIERS)
def test_compiled_rules_preserve_unknown_sources_and_live_record_floors(
    source_name, record_tier, viewer
):
    """Compiled rules preserve unknown sources and live record floors."""
    policy = datasets.build_catalogue_policy(_sources())
    dataset = _dataset(source=source_name, visibility_tier=record_tier)
    redacted = datasets.filter_for_tier(dataset, viewer, configured_sources=policy)

    description_minimum = "registered" if source_name == "compiled_archive" else "vetted"
    required = max((record_tier, description_minimum), key=_TIERS.index)
    allowed = _TIERS.index(viewer) >= _TIERS.index(required)
    assert (
        datasets.field_required_tier(dataset, "description", configured_sources=policy) == required
    )
    assert redacted.description == (dataset.description if allowed else None)
    assert redacted.keywords == (dataset.keywords if viewer == "vetted" else [])
    assert redacted.title == dataset.title
    assert datasets.full_required_tier(dataset, configured_sources=policy) == "vetted"
    assert datasets.can_view_full(dataset, viewer, configured_sources=policy) is (
        viewer == "vetted"
    )


def test_record_tier_changes_take_effect_without_recompilation(monkeypatch):
    """Record tier changes take effect without recompilation."""
    policy = datasets.build_catalogue_policy(_sources(field_visibility={}))
    dataset = _dataset()
    _forbid_recompilation(monkeypatch)
    assert datasets.can_view_field(dataset, "public", "description", configured_sources=policy)
    dataset.visibility_tier = "vetted"
    assert not datasets.can_view_field(dataset, "public", "description", configured_sources=policy)
    assert datasets.full_required_tier(dataset, configured_sources=policy) == "vetted"
    assert (
        datasets.filter_for_tier(dataset, "public", configured_sources=policy).description is None
    )
    dataset.visibility_tier = "public"
    assert datasets.can_view_full(dataset, "public", configured_sources=policy)


def test_policy_and_nested_derived_mappings_are_immutable():
    """Policy and nested derived mappings are immutable."""
    policy = datasets.build_catalogue_policy(_sources())
    with pytest.raises(FrozenInstanceError):
        policy.fingerprint = "changed"
    for mapping, key in (
        (policy.source_by_name, "compiled_archive"),
        (policy.code_minima, "description"),
        (policy.source_minima, "compiled_archive"),
        (policy.source_minima["compiled_archive"], "description"),
        (policy.full_minima, "compiled_archive"),
        (policy.field_sql, "description"),
        (policy.document_masks_json, 0),
        (policy.page_masks, 0),
        (policy.page_masks[0], "compiled_archive"),
    ):
        with pytest.raises(TypeError):
            mapping[key] = None


def test_query_payload_mutation_cannot_change_cached_masks():
    """Query payload mutation cannot change cached masks."""
    policy = datasets.build_catalogue_policy(_sources())
    query = parse_search_query("interview")
    first = datasets._page_query_context(query, 0, _FILTERS, policy).obj
    first["masks"]["compiled_archive"] = 63
    second = datasets._page_query_context(query, 0, _FILTERS, policy).obj
    assert second["masks"]["compiled_archive"] == 54
    assert json.loads(
        datasets._search_policy_context(query, 0, policy)["app.search_field_masks"]
    ) == {
        "*": 0,
        "compiled_archive": 22,
    }


def test_policy_reuse_and_source_replacement_are_scoped_to_each_app():
    """Policy reuse and source replacement are scoped to each app."""
    sources = _sources()
    state = SimpleNamespace(configured_sources=sources)
    request = cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))
    first = replace_catalogue_sources(request.app, sources)
    assert tuple(source.config for source in first.sources) == tuple(
        source.config for source in sources
    )
    assert all(not hasattr(source, "adapter") for source in first.sources)
    assert pages._get_catalogue_policy(request) is first

    other_state = SimpleNamespace(configured_sources=sources)
    other_request = cast(Request, SimpleNamespace(app=SimpleNamespace(state=other_state)))
    other = replace_catalogue_sources(other_request.app, sources)
    assert other is not first
    assert other.fingerprint == first.fingerprint

    replaced = replace_catalogue_sources(request.app, _sources(field_visibility={}))
    assert pages._get_catalogue_policy(request) is replaced
    assert replaced is not first
    assert replaced.minimum("description", "compiled_archive") == "public"
    assert first.minimum("description", "compiled_archive") == "registered"
    assert pages._get_catalogue_policy(other_request) is other


def test_code_matrix_replacement_rebuilds_the_snapshot_without_mutating_the_old_one(monkeypatch):
    """Code matrix replacement rebuilds the snapshot without mutating the old one."""
    sources = _sources(field_visibility={})
    first = datasets.build_catalogue_policy(sources)
    assert datasets.build_catalogue_policy(sources, previous=first) is first
    matrix = dict(datasets.FIELD_VISIBILITY) | {"description": "vetted"}
    monkeypatch.setattr(datasets, "FIELD_VISIBILITY", MappingProxyType(matrix))
    replaced = datasets.build_catalogue_policy(sources, previous=first)
    assert replaced is not first
    assert replaced.fingerprint != first.fingerprint
    assert replaced.minimum("description", "compiled_archive") == "vetted"
    assert first.minimum("description", "compiled_archive") == "public"


@pytest.mark.parametrize("change", ("override", "selection", "write_policy", "protocol"))
def test_policy_fingerprint_covers_all_static_bookmark_inputs(monkeypatch, change):
    """Policy fingerprint covers all static bookmark inputs."""
    sources = _sources()
    before = datasets.build_catalogue_policy(sources)
    if change == "override":
        sources = _sources(field_visibility={})
    elif change == "selection":
        sources = _sources(name="other_archive")
    elif change == "write_policy":
        sources = _sources(max_visibility="vetted")
    else:
        monkeypatch.setattr(masks, "SEARCH_MASK_PROTOCOL_TAG", "synthetic-future-protocol")
    after = datasets.build_catalogue_policy(sources)
    assert after.fingerprint != before.fingerprint


def test_duplicate_source_names_cannot_overwrite_a_compiled_policy_entry():
    """Duplicate source names cannot overwrite a compiled policy entry."""
    source = _sources()[0]
    with pytest.raises(ValueError, match="Duplicate source name"):
        datasets.build_catalogue_policy((source, source))


@pytest.mark.parametrize("rank", (-1, 3, True, False, "0", None))
def test_cached_masks_reject_noncanonical_ranks(rank):
    """Cached masks reject noncanonical ranks."""
    policy = datasets.build_catalogue_policy(_sources())
    query = parse_search_query("interview")
    with pytest.raises(ValueError, match="viewer rank"):
        datasets._page_query_context(query, rank, _FILTERS, policy)
    with pytest.raises(ValueError, match="viewer rank"):
        datasets._search_policy_context(query, rank, policy)


def test_source_order_does_not_change_bookmark_policy_identity():
    """Source order does not change bookmark policy identity."""
    first = _sources(name="first_archive")[0]
    second = _sources(name="second_archive", field_visibility={})[0]
    assert datasets.build_catalogue_policy((first, second)).fingerprint == (
        datasets.build_catalogue_policy((second, first)).fingerprint
    )


def test_nested_helpers_use_precompiled_sql_masks_and_bookmark_policy(monkeypatch):
    """Nested helpers use precompiled SQL masks and bookmark policy."""
    policy = datasets.build_catalogue_policy(_sources())
    query = parse_search_query("interview")
    _forbid_recompilation(monkeypatch)
    for rank, tier in enumerate(_TIERS):
        assert datasets._field_visible_sql("description", policy) is policy.field_sql["description"]
        assert "catalogue_match_ids" in datasets._search_where_clause(query, policy).as_string()
        assert (
            datasets._page_query_context(query, rank, _FILTERS, policy).obj["fingerprint"]
            == policy.fingerprint
        )
        assert datasets._page_query_context(query, rank, _FILTERS, policy).obj["masks"] == dict(
            policy.page_masks[rank]
        )
        assert (
            datasets._search_policy_context(query, rank, policy)["app.search_field_masks"]
            == (policy.document_masks_json[rank])
        )
        first = datasets._search_bookmark_context(query, tier, _FILTERS, 20, "guest", policy)
        second = datasets._search_bookmark_context(query, tier, _FILTERS, 20, "other", policy)
        assert first != second
        datasets.filter_for_tier(_dataset(), tier, configured_sources=policy)


@pytest.mark.parametrize(
    "api_name",
    (
        "count_search_datasets",
        "search_datasets",
        "search_catalogue_page",
        "get_recent_datasets",
        "get_facets",
        "get_dataset_by_id",
    ),
)
async def test_every_database_service_preserves_the_compiled_context(monkeypatch, api_name):
    """Every database service preserves the compiled context."""
    policy = datasets.build_catalogue_policy(_sources())
    _forbid_recompilation(monkeypatch)
    row = dict.fromkeys(DATASET_SELECT_COLUMNS)
    row.update(id=1, uuid="compiled-record", title="Interview", source="compiled_archive")
    cursor = make_async_cursor(fetchall=[row])
    if api_name in {"count_search_datasets", "search_datasets"}:
        cursor.fetchone.side_effect = [("0",), (1,)]
    elif api_name == "get_dataset_by_id":
        cursor.fetchone.return_value = row
    elif api_name == "get_facets":
        cursor.fetchall.return_value = [("keyword", "interview", None, None, None, None)]
    elif api_name == "search_catalogue_page":
        cursor.fetchall.return_value = [row | {"anchor_valid": True, "ceiling_id": 1}]

    @asynccontextmanager
    async def scope(*_args, **_kwargs):
        """Yield the configured cursor without opening a database connection."""
        yield cursor

    for name in ("get_catalogue_cursor", "get_catalogue_search_cursor"):
        monkeypatch.setattr(
            datasets, name, create_autospec(getattr(datasets, name), side_effect=scope)
        )
    args = [make_mock_pool()]
    if api_name == "get_dataset_by_id":
        args.append(1)
    args.append("public")
    if api_name.startswith(("search_", "count_search")):
        args.append("interview")
    result = await getattr(datasets, api_name)(*args, configured_sources=policy)
    assert result is not None
    cursor.execute.assert_awaited()


def test_invalid_policy_replacement_leaves_the_published_snapshot_intact():
    """Invalid policy replacement leaves the published snapshot intact."""
    sources = _sources()
    state = SimpleNamespace()
    request = cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))
    first = replace_catalogue_sources(request.app, sources)
    with pytest.raises(ValueError, match="Duplicate source"):
        replace_catalogue_sources(request.app, (sources[0], sources[0]))
    assert state.catalogue_policy is first
    assert state.configured_sources is first.sources


def _isolate_cache_policy_guard(monkeypatch):
    """These tests isolate snapshot publication from the separately tested DB fence."""
    cursor = SimpleNamespace(connection=object())

    @asynccontextmanager
    async def scope(_pool):
        """Yield the configured cursor without opening a database connection."""
        yield cursor

    monkeypatch.setattr(
        cache_module,
        "get_db_cursor",
        create_autospec(cache_module.get_db_cursor, side_effect=scope),
    )
    monkeypatch.setattr(
        cache_module,
        "guard_catalogue_policy_cur",
        create_autospec(cache_module.guard_catalogue_policy_cur, return_value=None),
    )


async def test_source_replacement_rebinds_statistics_and_rejects_old_inflight_cache(monkeypatch):
    """Source replacement rebinds statistics and rejects old inflight cache."""
    _isolate_cache_policy_guard(monkeypatch)
    sources = _sources()
    cache = CatalogueStatsCache(
        object(),
        source_names=[sources[0].name],
        policy_fingerprint=datasets.build_catalogue_policy(sources).fingerprint,
        subscribe=False,
    )
    state = SimpleNamespace(catalogue_stats_cache=cache)
    request = cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))
    replace_catalogue_sources(request.app, sources)
    started = asyncio.Event()
    release = asyncio.Event()
    old_date = datetime(2026, 1, 1, tzinfo=UTC)
    new_date = datetime(2026, 2, 1, tzinfo=UTC)
    scopes = []

    async def freshness(_pool, *, source_names):
        """Record source scope and block the old fill before returning old/new timestamps."""
        scopes.append(source_names)
        if len(scopes) == 1:
            started.set()
            await release.wait()
            return old_date
        return new_date

    fetch = create_autospec(cache_module.get_last_full_rebuild_date, side_effect=freshness)
    monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch)
    pending = asyncio.create_task(cache.get_last_full_rebuild())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        replacement = _sources(name="replacement_archive")
        replace_catalogue_sources(request.app, replacement)
        release.set()
        assert await asyncio.wait_for(pending, timeout=1) == old_date
        assert await cache.get_last_full_rebuild() == new_date
        assert await cache.get_last_full_rebuild() == new_date
        assert scopes == [(sources[0].name,), (replacement[0].name,)]
        with pytest.raises(ValueError, match="Duplicate source"):
            replace_catalogue_sources(request.app, (sources[0], sources[0]))
        assert await cache.get_last_full_rebuild() == new_date
        assert len(scopes) == 2
    finally:
        release.set()
        await pending
        cache.stop()


async def test_test_scope_restoration_rebinds_cache_and_restores_the_exact_old_policy(monkeypatch):
    """Test scope restoration rebinds cache and restores the exact old policy."""
    _isolate_cache_policy_guard(monkeypatch)
    sources = _sources()
    cache = CatalogueStatsCache(
        object(),
        source_names=[sources[0].name],
        policy_fingerprint=datasets.build_catalogue_policy(sources).fingerprint,
        subscribe=False,
    )
    state = SimpleNamespace(catalogue_stats_cache=cache)
    request = cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))
    original = replace_catalogue_sources(request.app, sources)
    fetch = create_autospec(cache_module.get_last_full_rebuild_date, return_value=None)
    monkeypatch.setattr(cache_module, "get_last_full_rebuild_date", fetch)
    with monkeypatch.context() as replacement:
        replace_test_catalogue_sources(replacement, request.app, _sources(name="temporary_archive"))
        await cache.get_last_full_rebuild()
        assert fetch.await_args.kwargs["source_names"] == ("temporary_archive",)
    assert state.catalogue_policy is original
    assert state.configured_sources is original.sources
    await cache.get_last_full_rebuild()
    assert fetch.await_args.kwargs["source_names"] == (sources[0].name,)
    assert fetch.await_count == 2
    cache.stop()
