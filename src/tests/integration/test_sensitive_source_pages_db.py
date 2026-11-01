"""Real signed feed metadata reaches every catalogue surface through tier gates."""

import copy
from dataclasses import asdict
from datetime import datetime, timedelta

import pytest

from app.services import DatasetAdminContext, change_dataset_admin_state, ingestion
from app.services.cache import CatalogueStatsCache
from app.services.datasets import (
    PUBLIC_DISCOVERY_FIELDS,
    PUBLIC_SEARCH_FIELDS,
    get_dataset_by_id,
    get_facets,
    get_recent_datasets,
    get_total_dataset_count,
    search_datasets,
)
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.fixtures import sign_session_id
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_TIERS = ("public", "registered", "vetted")
_PUBLIC = frozenset({"id", "uuid", "title", "access_level", "version", "source", "visibility_tier"})
_VIEWERS = ("public", "registered", "vetted", "public_admin")
_A, _B, _C = map(feed_uuid, range(1, 4))


@pytest.fixture
def feed(monkeypatch):
    """Install the signed-feed fixture with real authentication and in-process collection."""
    return SignedFeed(monkeypatch)


def _record(feed, uuid, *, marker="matrixprivate", **changes):
    """Build a synthetic source record with the requested identity and overrides."""
    return feed.record(uuid, marker=marker, keywords=[f"{marker}keyword"] * 2, **changes)


def _tier(viewer):
    """Map the public administrator test identity to the public metadata tier."""
    return "public" if viewer == "public_admin" else viewer


def _allowed(viewer, required):
    """Check whether the viewer metadata tier meets the required tier."""
    return _TIERS.index(_tier(viewer)) >= _TIERS.index(required)


def _sign_in(client, viewer, user_factory, session_factory):
    """Install the requested viewer's session cookie; leave public viewers unauthenticated."""
    if viewer == "public":
        return
    user = user_factory(
        access_tier=_tier(viewer),
        is_admin=viewer == "public_admin",
        totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"),
    )
    session = session_factory(user.id, purpose="full")
    client.cookies.set(settings.session_cookie_name, sign_session_id(session))


async def _populate(pool, feed, source, records):
    """Provision the source and require a successful rebuild of the supplied records."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(records)
    assert (await ingestion.run_full_rebuild(pool, configured_source=source)).status == "success"


def _ids(conn, source):
    """Return source catalogue IDs keyed by native UUID."""
    return {row["uuid"]: row["id"] for row in snapshot_feed_source(conn, source.name)["rows"]}


def _expected(wire, dataset_id, source):
    """Build the expected service-row shape from native wire metadata."""
    result = {
        key: copy.deepcopy(value)
        for key, value in wire.items()
        if key not in {"institutions", "main_disciplines", "modified_at"}
    }
    result.update(
        id=dataset_id,
        source=source,
        access_level="public" if wire["license_val"] == "Public access" else "restricted",
        authors=[{"name": value} for value in wire["authors"]],
        resource_access_url=next(
            item["ref"] for item in wire["resource_proxies"] if item["type"] == "Resource"
        ),
        landing_page_url=next(
            item["ref"] for item in wire["resource_proxies"] if item["type"] == "LandingPage"
        ),
    )
    return result


def _assert_release(dataset, wire, dataset_id, source, viewer):
    """Compare released metadata with the viewer's expected redaction."""
    assert PUBLIC_DISCOVERY_FIELDS == _PUBLIC
    assert {"title", "access_level"} == PUBLIC_SEARCH_FIELDS
    expected = _expected(wire, dataset_id, source)
    assert all(value for field, value in expected.items() if field not in _PUBLIC)
    if not _allowed(viewer, wire["visibility_tier"]):
        expected = {
            field: value if field in _PUBLIC else [] if isinstance(value, list) else None
            for field, value in expected.items()
        }
    assert asdict(dataset) == expected


async def _assert_metadata_stats(pool, viewer, visible, *, configured_sources):
    """Compare tier-scoped facets and counts with the permitted fixture records."""
    permitted = [record for record in visible if _allowed(viewer, record["visibility_tier"])]
    keywords = sorted({value for record in permitted for value in record["keywords"]})
    languages = sorted({value for record in permitted for value in record["languages"]})
    access = sorted(
        {
            "public" if record["license_val"] == "Public access" else "restricted"
            for record in visible
        }
    )
    assert await get_total_dataset_count(pool) == len(visible)
    assert await get_facets(pool, _tier(viewer), configured_sources=configured_sources) == {
        "keywords": keywords,
        "languages": languages,
        "access_levels": access,
    }
    return keywords, languages


@pytest.mark.parametrize("viewer", _VIEWERS)
@pytest.mark.parametrize("required", _TIERS)
async def test_native_records_release_exact_public_fields_or_all_full_fields(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    viewer,
    required,
):
    """SB-DISC-001, SB-DISC-002, SB-DISC-003, SB-DISC-004, SB-DISC-005,
    SB-DISC-006, SB-VIS-008: exact structural release at every tier.

    Human-language public suitability still requires source-owner approval.
    """
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    wire = _record(
        feed,
        _A,
        visibility_tier=required,
        license_val="Public access" if required == "vetted" else "Restricted access",
    )
    await _populate(db_pool, feed, source, [wire])
    dataset_id = _ids(sync_conn, source)[_A]
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    detail = await get_dataset_by_id(
        db_pool, dataset_id, _tier(viewer), configured_sources=(source,)
    )
    results, count = await search_datasets(
        db_pool, _tier(viewer), search_text=wire["title"], configured_sources=(source,)
    )
    recent = await get_recent_datasets(db_pool, _tier(viewer), configured_sources=(source,))
    assert detail is not None and count == 1 and len(results) == len(recent) == 1
    for dataset in (detail, results[0], recent[0]):
        _assert_release(dataset, wire, dataset_id, source.name, viewer)
    responses = (
        e2e_client.get(f"/dataset/{dataset_id}"),
        e2e_client.get("/search", params={"q": wire["title"]}),
        e2e_client.get("/"),
    )
    for response in responses:
        assert response.status_code == 200 and response.context["user_tier"] == _tier(viewer)
        assert wire["title"] in response.text
        if _allowed(viewer, required):
            assert "matrixprivate" in response.text
        else:
            assert "matrixprivate" not in response.text
    rendered = (
        responses[0].context["dataset"],
        responses[1].context["results"][0],
        responses[2].context["recent"][0],
    )
    for dataset in rendered:
        _assert_release(dataset, wire, dataset_id, source.name, viewer)
    if _allowed(viewer, required):
        assert f'href="/dataset/{dataset_id}/resource/0"' in responses[0].text
    else:
        assert f'href="/dataset/{dataset_id}/resource/0"' not in responses[0].text
    for proxy in wire["resource_proxies"]:
        assert proxy["ref"] not in responses[0].text
    resource = e2e_client.get(f"/dataset/{dataset_id}/resource/0", follow_redirects=False)
    assert resource.status_code == (303 if _allowed(viewer, required) else 404)
    if _allowed(viewer, required):
        assert resource.headers["location"] == wire["resource_proxies"][0]["ref"]
    else:
        assert "location" not in resource.headers
    assert responses[1].context["result_count"] is None
    assert responses[2].context["total_datasets"] == 1
    assert "total_keywords" not in responses[2].context
    assert "total_languages" not in responses[2].context


@pytest.mark.parametrize("viewer", _TIERS)
async def test_public_discovery_and_private_full_text_search(
    db_pool, tiered_catalogue, e2e_client, user_factory, session_factory, viewer
):
    """SB-DISC-002, SB-DISC-003, SB-DISC-005, SB-DISC-006: tier-gated search text."""
    records, ids = tiered_catalogue
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    for record in records:
        allowed = _allowed(viewer, record["visibility_tier"])
        expected_ids = [ids[record["uuid"]]] if allowed else []
        title = e2e_client.get("/search", params={"q": record["title"]})
        assert title.status_code == 200 and title.context["result_count"] is None
        assert [row.id for row in title.context["results"]] == [ids[record["uuid"]]]
        for field in ("description", "project_title", "project_description", "authors"):
            term = record[field][0] if field == "authors" else record[field]
            rows, total = await search_datasets(
                db_pool,
                viewer,
                search_text=term,
                configured_sources=e2e_client.app.state.configured_sources,
            )
            assert [row.id for row in rows] == expected_ids and total == int(allowed)
            page = e2e_client.get("/search", params={"q": term})
            assert page.status_code == 200 and page.context["result_count"] is None
            assert [row.id for row in page.context["results"]] == expected_ids
    for parameter in ("q", "access_level"):
        response = e2e_client.get("/search", params={parameter: "restricted"})
        assert response.status_code == 200 and response.context["result_count"] is None
        assert len(response.context["results"]) == 2


@pytest.fixture
async def tiered_catalogue(
    replace_bound_catalogue_sources, db_pool, sync_conn, feed, e2e_client, monkeypatch
):
    """Populate complete native records with one distinct marker per source tier."""
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    records = [
        _record(
            feed,
            uuid,
            marker=f"{tier}needle",
            title=f"Discovery {tier}",
            visibility_tier=tier,
            license_val="Public access" if tier == "public" else "Restricted access",
        )
        for uuid, tier in zip((_A, _B, _C), _TIERS, strict=True)
    ]
    await _populate(db_pool, feed, source, records)
    return records, _ids(sync_conn, source)


@pytest.mark.parametrize("viewer", _TIERS)
async def test_private_filters_facets_counts_and_pagination(
    db_pool, tiered_catalogue, e2e_client, user_factory, session_factory, monkeypatch, viewer
):
    """SB-DISC-002, SB-DISC-005, SB-DISC-006: filters, aggregates and page tiers."""
    monkeypatch.setattr(settings, "pagination_size", 1)
    records, ids = tiered_catalogue
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    for record in records:
        allowed = _allowed(viewer, record["visibility_tier"])
        expected_ids = [ids[record["uuid"]]] if allowed else []
        for parameter, values in (
            ("keyword", record["keywords"]),
            ("language", record["languages"]),
        ):
            rows, total = await search_datasets(
                db_pool,
                viewer,
                **{parameter: values[0]},
                configured_sources=e2e_client.app.state.configured_sources,
            )
            assert [row.id for row in rows] == expected_ids and total == int(allowed)
            page = e2e_client.get("/search", params={parameter: values[0]})
            assert page.context["result_count"] is None
            assert [row.id for row in page.context["results"]] == expected_ids
    keywords, languages = await _assert_metadata_stats(
        db_pool, viewer, records, configured_sources=e2e_client.app.state.configured_sources
    )
    blank = e2e_client.get("/search")
    assert blank.context["all_keywords"] == keywords and blank.context["all_languages"] == languages
    assert blank.context["all_access_levels"] == ["public", "restricted"]
    for record in records:
        marker = f"{record['visibility_tier']}needle"
        assert (marker in blank.text) == _allowed(viewer, record["visibility_tier"])
    home = e2e_client.get("/")
    assert home.context["total_datasets"] == 3
    assert "total_languages" not in home.context and "total_keywords" not in home.context
    expected_order = sorted(ids.values(), reverse=True)
    for number, expected_id in enumerate(expected_order, start=1):
        rows, total = await search_datasets(
            db_pool,
            viewer,
            page=number,
            page_size=1,
            configured_sources=e2e_client.app.state.configured_sources,
        )
        assert [row.id for row in rows] == [expected_id] and total == 3
        page = e2e_client.get("/search", params={"page": number})
        assert page.status_code == 200 and page.context["result_count"] is None
        assert [row.id for row in page.context["results"]] == [expected_id]
        assert page.context["total_pages"] is None
        assert (page.context["next_page_url"] is not None) is (number < len(expected_order))
    beyond = e2e_client.get("/search", params={"page": 4}, follow_redirects=False)
    assert beyond.status_code == 303
    assert beyond.headers["location"] == "/search?page=1&pagination=empty"


@pytest.mark.parametrize("viewer", _TIERS)
async def test_real_admin_hide_removes_every_surface_and_preserves_another_source(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    admin_actor,
    monkeypatch,
    viewer,
):
    """SB-DISC-008, SB-VIS-004, SB-VIS-007: a durable hide overrides every tier."""
    source, other = feed.source(), feed.source(name="retained_archive")
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source, other))
    hidden = _record(
        feed,
        _A,
        marker="concealedprivate",
        title="Concealed discovery",
        license_val="Public access",
        modified_at="2030-01-03T13:00:00Z",
    )
    neighbour = _record(feed, _B, marker="visibleprivate", title="Visible discovery")
    retained = _record(feed, _A, marker="retainedprivate", title="Retained discovery")
    await _populate(db_pool, feed, source, [hidden, neighbour])
    await _populate(db_pool, feed, other, [retained])
    dataset_id, retained_id = _ids(sync_conn, source)[_A], _ids(sync_conn, other)[_A]
    foreign = snapshot_feed_source(sync_conn, other.name)
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    assert e2e_client.get("/").context["total_datasets"] == 3
    context = DatasetAdminContext(actor_id=admin_actor.id, actor_session_id=admin_actor.session_id)
    await change_dataset_admin_state(
        db_pool, dataset_id, "hide", context=context, configured_sources=(source, other)
    )
    assert (
        await get_dataset_by_id(db_pool, dataset_id, viewer, configured_sources=(source, other))
        is None
    )
    assert (
        await get_dataset_by_id(db_pool, retained_id, viewer, configured_sources=(source, other))
        is not None
    )
    for filters in (
        {"search_text": hidden["title"]},
        {"keyword": hidden["keywords"][0]},
        {"language": hidden["languages"][0]},
    ):
        assert await search_datasets(
            db_pool, viewer, **filters, configured_sources=(source, other)
        ) == ([], 0)
    assert e2e_client.get(f"/dataset/{dataset_id}").status_code == 404
    assert e2e_client.get(f"/dataset/{retained_id}").status_code == 200
    for path in ("/", "/search"):
        page = e2e_client.get(path)
        assert page.status_code == 200 and "Concealed discovery" not in page.text
        assert "concealedprivate" not in page.text and "Retained discovery" in page.text
    assert await search_datasets(
        db_pool, viewer, access_level="public", configured_sources=(source, other)
    ) == ([], 0)
    visible_ids = sorted((retained_id, _ids(sync_conn, source)[_B]), reverse=True)
    for page_number, expected_id in enumerate(visible_ids, start=1):
        rows, total = await search_datasets(
            db_pool, viewer, page=page_number, page_size=1, configured_sources=(source, other)
        )
        assert [row.id for row in rows] == [expected_id] and total == 2
    assert await search_datasets(
        db_pool, viewer, page=3, page_size=1, configured_sources=(source, other)
    ) == ([], 2)
    await _assert_metadata_stats(
        db_pool, viewer, [neighbour, retained], configured_sources=(source, other)
    )
    assert len(await get_recent_datasets(db_pool, viewer, configured_sources=(source, other))) == 2
    assert [
        row.id
        for row in await get_recent_datasets(
            db_pool, viewer, limit=1, configured_sources=(source, other)
        )
    ] == visible_ids[:1]
    assert e2e_client.get("/").context["total_datasets"] == 2
    assert snapshot_feed_source(sync_conn, other.name) == foreign
    await change_dataset_admin_state(
        db_pool, dataset_id, "restore", context=context, configured_sources=(source, other)
    )
    assert e2e_client.get(f"/dataset/{dataset_id}").status_code == 200
    assert e2e_client.get("/").context["total_datasets"] == 3
    await _assert_metadata_stats(
        db_pool, viewer, [hidden, neighbour, retained], configured_sources=(source, other)
    )


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
@pytest.mark.parametrize("viewer", _TIERS)
async def test_native_corrections_and_withdrawals_refresh_raw_search_and_warm_caches(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    runner,
    viewer,
):
    """SB-DISC-008, SB-VIS-003, SB-VIS-004, SB-VIS-006: no stale serving metadata."""
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    original = [
        _record(
            feed,
            uuid,
            marker=f"obsolete{suffix}",
            title=f"Obsolete discovery {suffix}",
            license_val="Public access",
        )
        for uuid, suffix in ((_A, "a"), (_B, "b"))
    ]
    await _populate(db_pool, feed, source, original)
    ids = _ids(sync_conn, source)
    _sign_in(e2e_client, viewer, user_factory, session_factory)
    assert "obsoletea" in e2e_client.get("/search").text
    assert e2e_client.get("/").context["total_datasets"] == 2
    caches = [
        CatalogueStatsCache(
            db_pool,
            source_names=(source.name,),
            policy_fingerprint=e2e_client.app.state.catalogue_policy.fingerprint,
            subscribe=False,
        )
        for _ in range(2)
    ]
    try:
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 2
        current = [
            _record(
                feed,
                uuid,
                marker=f"current{suffix}",
                title=f"Current discovery {suffix}",
                visibility_tier="vetted",
                modified_at="2030-01-04T00:30:00Z",
                version="2.0",
            )
            for uuid, suffix in ((_A, "a"), (_B, "b"))
        ]
        feed.set_snapshot(current, cutoff=DEFAULT_CUTOFF + timedelta(hours=1))
        assert (await runner(db_pool, configured_source=source)).status == "success"
        stored = snapshot_feed_source(sync_conn, source.name)["rows"]
        assert "obsolete" not in repr(stored)
        for row in stored:
            wire = next(record for record in current if record["uuid"] == row["uuid"])
            assert row["id"] == ids[row["uuid"]]
            assert row["title"] == row["data"]["title"] == wire["title"]
            assert row["visibility_tier"] == "vetted" and row["access_level"] == "restricted"
            assert row["search_text_public"] == f"{wire['title']} restricted"
            assert wire["description"] in row["search_text_full"]
            assert row["version"] == "2.0"
            assert row["data"]["version"] == "2.0" and "modified_at" not in row["data"]
            assert row["data"]["upstream_modified_at"] == "2030-01-04T00:30:00+00:00"
            assert datetime.fromisoformat(row["upstream_modified_at"]) == datetime.fromisoformat(
                row["data"]["upstream_modified_at"]
            )
            detail = await get_dataset_by_id(
                db_pool, row["id"], viewer, configured_sources=(source,)
            )
            assert detail is not None
            _assert_release(detail, wire, row["id"], source.name, viewer)
        for term in ("obsoletea", "obsoleteb", "Obsolete discovery", "public"):
            assert await search_datasets(
                db_pool, viewer, search_text=term, configured_sources=(source,)
            ) == ([], 0)
        for path in ("/", "/search", f"/dataset/{ids[_A]}"):
            page = e2e_client.get(path)
            assert page.status_code == 200 and "obsolete" not in page.text
            assert ("currenta" in page.text) == (viewer == "vetted")
        await _assert_metadata_stats(db_pool, viewer, current, configured_sources=(source,))
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 2
        feed.set_snapshot([current[0]], withdrawn=(_B,), cutoff=DEFAULT_CUTOFF + timedelta(hours=2))
        assert (await runner(db_pool, configured_source=source)).status == "success"
        assert (
            await get_dataset_by_id(db_pool, ids[_B], "vetted", configured_sources=(source,))
            is None
        )
        assert e2e_client.get(f"/dataset/{ids[_B]}").status_code == 404
        assert (
            await search_datasets(
                db_pool, viewer, search_text=current[1]["title"], configured_sources=(source,)
            )
        ) == ([], 0)
        for path in ("/", "/search"):
            page = e2e_client.get(path)
            assert page.status_code == 200 and current[1]["title"] not in page.text
            assert "currentb" not in page.text
        await _assert_metadata_stats(db_pool, viewer, current[:1], configured_sources=(source,))
        for cache in caches:
            assert (await cache.get_global_stats()).total_datasets == 1
            assert await cache.get_total_datasets() == 1
        assert e2e_client.get("/").context["total_datasets"] == 1
    finally:
        for cache in caches:
            cache.stop()
