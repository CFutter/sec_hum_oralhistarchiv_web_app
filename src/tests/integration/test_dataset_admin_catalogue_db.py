"""Catalogue reads enforce durable administrator state without runtime writers."""

from dataclasses import asdict
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from lxml import html

from app.services import build_catalogue_policy, ingestion
from app.services.access_tiers import tier_rank
from app.services.cache import CatalogueStatsCache
from app.services.datasets import (
    FACET_SAMPLE_SIZE,
    PUBLIC_DISCOVERY_FIELDS,
    get_dataset_by_id,
    get_facets,
    get_global_catalogue_stats,
    get_recent_datasets,
    get_total_dataset_count,
    search_datasets,
)
from app.services.totp_crypto import encrypt_value
from app.sources import AccessTier
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.sync_doubles import FETCH, harvest_result, make_record
from tests.source_fixtures import legacy_source

_TIERS: tuple[AccessTier, ...] = ("public", "registered", "vetted")
_HIDDEN_AT = datetime(2026, 10, 17, tzinfo=UTC)
_CONTROLLED_SOURCES = tuple(
    legacy_source(name=name, max_visibility="public") for name in ("archive_alpha", "archive_beta")
)


@pytest.fixture(autouse=True)
def _bound_catalogue_policy(bind_catalogue_policy, request):
    """Bind the test's selected source policy before querying."""
    if "e2e_client" not in request.fixturenames:
        bind_catalogue_policy(_CONTROLLED_SOURCES)


def _set_state(conn, source, uuid, tier=None, hidden_at=None):
    """Publish test-owned state so independent catalogue connections can read it."""
    conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) "
        "VALUES (%s, %s, %s, %s) ON CONFLICT (source, uuid) DO UPDATE "
        "SET visibility_tier = EXCLUDED.visibility_tier, hidden_at = EXCLUDED.hidden_at",
        (source, uuid, tier, hidden_at),
    )
    conn.commit()


@pytest.mark.parametrize(
    ("raw_tier", "admin_tier", "effective_tier"),
    [
        ("public", None, "public"),
        ("public", "public", "public"),
        ("public", "registered", "registered"),
        ("public", "vetted", "vetted"),
        ("registered", None, "registered"),
        ("registered", "public", "registered"),
        ("registered", "registered", "registered"),
        ("registered", "vetted", "vetted"),
        ("vetted", None, "vetted"),
        ("vetted", "public", "vetted"),
        ("vetted", "registered", "vetted"),
        ("vetted", "vetted", "vetted"),
    ],
)
async def test_effective_tier_controls_redaction_and_all_metadata_gates(
    db_pool, sync_conn, dataset_factory, raw_tier, admin_tier, effective_tier
):
    """Verify effective tier controls redaction and all metadata gates."""
    dataset_id = dataset_factory(
        source="archive_alpha",
        uuid="controlled",
        visibility_tier=raw_tier,
        title="Public discovery title",
        description="privatedescriptionmarker",
        keywords=["privatekeyword", "privatekeyword"],
        languages=["PrivateLanguage"],
    )
    _set_state(sync_conn, "archive_alpha", "controlled", admin_tier)
    for viewer in _TIERS:
        allowed = tier_rank(viewer) >= tier_rank(effective_tier)
        detail = await get_dataset_by_id(
            db_pool, dataset_id, viewer, configured_sources=_CONTROLLED_SOURCES
        )
        rows, total = await search_datasets(
            db_pool,
            viewer,
            search_text="Public discovery title",
            configured_sources=_CONTROLLED_SOURCES,
        )
        recent = await get_recent_datasets(db_pool, viewer, configured_sources=_CONTROLLED_SOURCES)
        assert detail is not None
        assert total == 1 and [row.id for row in rows] == [dataset_id]
        assert [row.id for row in recent] == [dataset_id]
        for result in (detail, rows[0], recent[0]):
            assert result.visibility_tier == effective_tier
            assert result.title == "Public discovery title"
            if allowed:
                assert result.description == "privatedescriptionmarker"
                assert result.languages == ["PrivateLanguage"]
            else:
                private = set(asdict(result)) - PUBLIC_DISCOVERY_FIELDS
                assert all(asdict(result)[name] in (None, []) for name in private)
        for filters in (
            {"search_text": "privatedescriptionmarker"},
            {"keyword": "privatekeyword"},
            {"language": "PrivateLanguage"},
        ):
            matches, count = await search_datasets(
                db_pool, viewer, **filters, configured_sources=_CONTROLLED_SOURCES
            )
            assert [row.id for row in matches] == ([dataset_id] if allowed else [])
            assert count == int(allowed)
        facets = await get_facets(db_pool, viewer, configured_sources=_CONTROLLED_SOURCES)
        assert facets == {
            "keywords": ["privatekeyword"] if allowed else [],
            "languages": ["PrivateLanguage"] if allowed else [],
            "access_levels": ["public"],
        }
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE id = %s", (dataset_id,)
    ).fetchone() == (raw_tier,)


@pytest.mark.parametrize("viewer", _TIERS)
async def test_hidden_identity_disappears_from_every_catalogue_surface(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    dataset_factory,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    viewer,
):
    """Verify hidden identity disappears from every catalogue surface."""
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, _CONTROLLED_SOURCES)
    hidden_id = dataset_factory(
        source="archive_alpha",
        uuid="shared",
        title="Hidden catalogue record",
        keywords=["hiddenkeyword", "hiddenkeyword"],
        languages=["HiddenLanguage"],
        access_level="hiddenaccess",
        upstream_modified_at=_HIDDEN_AT,
    )
    visible_id = dataset_factory(
        source="archive_beta",
        uuid="shared",
        title="Visible catalogue record",
        keywords=["visiblekeyword", "visiblekeyword"],
        languages=["VisibleLanguage"],
        access_level="visibleaccess",
        upstream_modified_at=None,
    )
    _set_state(sync_conn, "archive_alpha", "shared", hidden_at=_HIDDEN_AT)
    assert (
        await get_dataset_by_id(db_pool, hidden_id, viewer, configured_sources=_CONTROLLED_SOURCES)
        is None
    )
    visible = await get_dataset_by_id(
        db_pool, visible_id, viewer, configured_sources=_CONTROLLED_SOURCES
    )
    assert visible is not None and visible.id == visible_id
    rows, total = await search_datasets(db_pool, viewer, configured_sources=_CONTROLLED_SOURCES)
    assert [row.id for row in rows] == [visible_id] and total == 1
    assert await search_datasets(
        db_pool, viewer, page=2, configured_sources=_CONTROLLED_SOURCES
    ) == ([], 1)
    for filters in (
        {"search_text": "Hidden catalogue record"},
        {"keyword": "hiddenkeyword"},
        {"language": "HiddenLanguage"},
        {"access_level": "hiddenaccess"},
    ):
        assert await search_datasets(
            db_pool, viewer, **filters, configured_sources=_CONTROLLED_SOURCES
        ) == ([], 0)
        assert await search_datasets(
            db_pool, viewer, page=2, **filters, configured_sources=_CONTROLLED_SOURCES
        ) == ([], 0)
    assert [
        row.id
        for row in await get_recent_datasets(
            db_pool, viewer, limit=1, configured_sources=_CONTROLLED_SOURCES
        )
    ] == [visible_id]
    assert await get_total_dataset_count(db_pool) == 1
    assert await get_global_catalogue_stats(db_pool, source_names=("archive_alpha",)) == (1, None)
    assert await get_facets(db_pool, viewer, configured_sources=_CONTROLLED_SOURCES) == {
        "keywords": ["visiblekeyword"],
        "languages": ["VisibleLanguage"],
        "access_levels": ["visibleaccess"],
    }
    if viewer != "public":
        user = user_factory(access_tier=viewer, totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
        session = session_factory(user.id)
        e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(session))
    assert e2e_client.get(f"/dataset/{hidden_id}", follow_redirects=False).status_code == 404
    assert e2e_client.get(f"/dataset/{visible_id}", follow_redirects=False).status_code == 200
    response = e2e_client.get("/search", follow_redirects=False)
    assert response.status_code == 200
    assert response.context["user_tier"] == viewer
    assert response.context["result_count"] is None
    assert [row.id for row in response.context["results"]] == [visible_id]
    assert "Hidden catalogue record" not in response.text
    home = e2e_client.get("/", follow_redirects=False)
    assert home.status_code == 200 and "Hidden catalogue record" not in home.text
    assert home.context["user_tier"] == viewer
    assert html.fromstring(home.text).xpath('//span[@class="stat-number"]/text()') == ["1"]


async def test_hidden_rows_do_not_consume_the_recent_facet_sample(
    db_pool, sync_conn, dataset_factory
):
    """Verify hidden rows do not consume the recent facet sample."""
    visible_id = dataset_factory(
        source="archive_beta",
        keywords=["survivingkeyword", "survivingkeyword"],
        languages=["SurvivingLanguage"],
        upstream_modified_at=None,
    )
    sync_conn.execute(
        "INSERT INTO oral_history_datasets "
        "(source, uuid, title, visibility_tier, access_level, upstream_modified_at) "
        "SELECT 'archive_alpha', 'hidden-' || n, 'Hidden ' || n, 'public', 'hiddenaccess', %s "
        "FROM generate_series(1, %s) AS n",
        (_HIDDEN_AT, FACET_SAMPLE_SIZE),
    )
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) "
        "SELECT source, uuid, %s FROM oral_history_datasets WHERE source = 'archive_alpha'",
        (_HIDDEN_AT,),
    )
    sync_conn.commit()
    assert [
        row.id
        for row in await get_recent_datasets(
            db_pool, "vetted", limit=1, configured_sources=_CONTROLLED_SOURCES
        )
    ] == [visible_id]
    assert await get_facets(db_pool, "vetted", configured_sources=_CONTROLLED_SOURCES) == {
        "keywords": ["survivingkeyword"],
        "languages": ["SurvivingLanguage"],
        "access_levels": ["public"],
    }


async def test_restore_and_raw_reintroduction_reuse_the_identity_floor(
    db_pool, sync_conn, dataset_factory
):
    """Verify restore and raw reintroduction reuse the identity floor."""
    original = dataset_factory(source="archive_alpha", uuid="restored", description="Private text")
    _set_state(sync_conn, "archive_alpha", "restored", "vetted", _HIDDEN_AT)
    assert (
        await get_dataset_by_id(db_pool, original, "vetted", configured_sources=_CONTROLLED_SOURCES)
        is None
    )
    _set_state(sync_conn, "archive_alpha", "restored", "vetted")
    public = await get_dataset_by_id(
        db_pool, original, "public", configured_sources=_CONTROLLED_SOURCES
    )
    full = await get_dataset_by_id(
        db_pool, original, "vetted", configured_sources=_CONTROLLED_SOURCES
    )
    assert public is not None and public.visibility_tier == "vetted" and public.description is None
    assert full is not None and full.description == "Private text"
    sync_conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (original,))
    sync_conn.commit()
    replacement = dataset_factory(source="archive_alpha", uuid="restored", visibility_tier="public")
    assert replacement != original
    reintroduced = await get_dataset_by_id(
        db_pool, replacement, "public", configured_sources=_CONTROLLED_SOURCES
    )
    assert reintroduced is not None
    assert reintroduced.visibility_tier == "vetted" and reintroduced.description is None


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_normal_ingestion_preserves_state_through_updates_withdrawal_and_return(
    bind_catalogue_policy, db_pool, sync_conn, sync_source, runner
):
    """Verify normal ingestion preserves state through updates withdrawal and return."""
    source = legacy_source(name=sync_source.name, max_visibility="public")
    bind_catalogue_policy((source,))
    sync_conn.execute(
        "UPDATE sync_status SET source_fingerprint = %s WHERE source = %s",
        (source.adapter.config_fingerprint(), source.name),
    )
    uuid = "ingested-admin-control"
    _set_state(sync_conn, source.name, uuid, "vetted", _HIDDEN_AT)
    state_query = (
        "SELECT visibility_tier, hidden_at FROM dataset_admin_state WHERE source = %s AND uuid = %s"
    )
    row_query = "SELECT id, title, visibility_tier FROM oral_history_datasets WHERE source = %s AND uuid = %s"
    neighbour = make_record("uncontrolled-neighbour")
    previous_id = None
    for title in ("Initial title", "Updated title"):
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record(uuid, title), neighbour])
        ):
            outcome = await runner(db_pool, configured_source=source)
        assert outcome.status == "success"
        row = sync_conn.execute(row_query, (source.name, uuid)).fetchone()
        assert row is not None and row[1:] == (title, "public")
        assert previous_id is None or row[0] == previous_id
        previous_id = row[0]
        assert (
            await get_dataset_by_id(db_pool, row[0], "vetted", configured_sources=(source,)) is None
        )
        assert sync_conn.execute(state_query, (source.name, uuid)).fetchone() == (
            "vetted",
            _HIDDEN_AT,
        )
    with patch(
        FETCH, autospec=True, return_value=harvest_result([neighbour], deleted_uuids=(uuid,))
    ):
        outcome = await runner(db_pool, configured_source=source)
    assert outcome.status == "success"
    assert sync_conn.execute(row_query, (source.name, uuid)).fetchone() is None
    assert sync_conn.execute(state_query, (source.name, uuid)).fetchone() == ("vetted", _HIDDEN_AT)
    with patch(
        FETCH,
        autospec=True,
        return_value=harvest_result([make_record(uuid, "Returned"), neighbour]),
    ):
        outcome = await runner(db_pool, configured_source=source)
    assert outcome.status == "success"
    returned = sync_conn.execute(row_query, (source.name, uuid)).fetchone()
    assert (
        returned is not None
        and returned[0] != previous_id
        and returned[1:] == ("Returned", "public")
    )
    assert (
        await get_dataset_by_id(db_pool, returned[0], "vetted", configured_sources=(source,))
        is None
    )
    _set_state(sync_conn, source.name, uuid, "vetted")
    restored = await get_dataset_by_id(db_pool, returned[0], "public", configured_sources=(source,))
    assert (
        restored is not None
        and restored.visibility_tier == "vetted"
        and restored.description is None
    )
    visible = await get_dataset_by_id(db_pool, returned[0], "vetted", configured_sources=(source,))
    assert visible is not None and visible.description == make_record(uuid)["description"]


async def test_two_warm_stats_caches_observe_hide_and_restore_without_invalidation(
    db_pool, sync_conn, dataset_factory, monkeypatch
):
    """Verify two warm stats caches observe hide and restore without invalidation."""
    monkeypatch.setattr(settings, "redis_enabled", False)
    dataset_factory(source="archive_alpha", uuid="live-count")
    caches = [
        CatalogueStatsCache(
            db_pool,
            source_names=("archive_alpha",),
            policy_fingerprint=build_catalogue_policy(_CONTROLLED_SOURCES).fingerprint,
            subscribe=False,
        )
        for _ in range(2)
    ]
    try:
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 1
            assert await cache.get_total_datasets() == 1
        _set_state(sync_conn, "archive_alpha", "live-count", hidden_at=_HIDDEN_AT)
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 0
            assert await cache.get_total_datasets() == 0
        _set_state(sync_conn, "archive_alpha", "live-count")
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 1
            assert await cache.get_total_datasets() == 1
    finally:
        for cache in caches:
            cache.stop()
