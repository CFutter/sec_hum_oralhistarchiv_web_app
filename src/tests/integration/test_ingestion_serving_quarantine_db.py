"""Authenticated rejected corrections withhold retained catalogue copies."""

from datetime import timedelta

import pytest

from app.services import get_db_cursor, ingestion
from app.services.dataset_admin_queries import get_admin_dataset_by_id
from app.services.datasets import get_dataset_by_id, get_facets, search_datasets
from tests.json_feed_fixtures import DEFAULT_CUTOFF, SignedFeed, feed_uuid, provision_feed_source

_A, _B, _C = map(feed_uuid, range(1, 4))


def _neighbours(feed):
    """Build two neighbouring records with distinct private facet markers."""
    return [
        feed.record(
            _B,
            title="Neighbour",
            keywords=["neighbourkeyword"] * 2,
            languages=["neighbourlanguage"],
        ),
        feed.record(
            _C,
            title="Third neighbour",
            keywords=["thirdkeyword"] * 2,
            languages=["thirdlanguage"],
        ),
    ]


def _quarantine(conn, source):
    """Read source quarantine rows in UUID order and commit the observer transaction."""
    rows = conn.execute(
        "SELECT uuid, reason, failed_harvest_at FROM ingestion_quarantine "
        "WHERE source = %s ORDER BY uuid",
        (source,),
    ).fetchall()
    conn.commit()
    return rows


async def _seed(pool, feed, source):
    """Provision the source and require a successful initial snapshot rebuild."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(
        [
            feed.record(_A, title="RetainedCanary", keywords=["withheldkeyword"] * 2),
            *_neighbours(feed),
        ]
    )
    assert (await ingestion.run_full_rebuild(pool, configured_source=source)).status == "success"


@pytest.mark.parametrize("runner", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_invalid_tightening_withholds_every_tier_until_valid_fresh_correction(
    replace_bound_catalogue_sources, db_pool, sync_conn, monkeypatch, e2e_client, runner
):
    """Verify invalid tightening withholds every tier until valid fresh correction."""
    feed = SignedFeed(monkeypatch)
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    await _seed(db_pool, feed, source)
    ids = dict(
        sync_conn.execute(
            "SELECT uuid, id FROM oral_history_datasets WHERE source = %s", (source.name,)
        ).fetchall()
    )
    assert set(ids) == {_A, _B, _C}
    dataset_id = ids[_A]
    sync_conn.commit()
    rejected = feed.record(_A, visibility_tier="vetted", title=" ")
    feed.set_snapshot(
        [rejected, *_neighbours(feed)],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
    )
    assert (await runner(db_pool, configured_source=source)).status == "partial"
    assert [(uuid, reason) for uuid, reason, _at in _quarantine(sync_conn, source.name)] == [
        (_A, "record_rejected")
    ]
    assert sync_conn.execute(
        "SELECT title, visibility_tier FROM oral_history_datasets WHERE id = %s", (dataset_id,)
    ).fetchone() == ("RetainedCanary", "public")
    sync_conn.commit()
    for viewer in ("public", "registered", "vetted"):
        assert (
            await get_dataset_by_id(db_pool, dataset_id, viewer, configured_sources=(source,))
            is None
        )
        assert await search_datasets(
            db_pool, viewer, search_text="RetainedCanary", configured_sources=(source,)
        ) == ([], 0)
        neighbours, count = await search_datasets(db_pool, viewer, configured_sources=(source,))
        assert count == 2 and {row.id for row in neighbours} == {ids[_B], ids[_C]}
        assert (
            await get_dataset_by_id(db_pool, ids[_B], viewer, configured_sources=(source,))
            is not None
        )
        assert await get_facets(db_pool, viewer, configured_sources=(source,)) == {
            "keywords": ["neighbourkeyword", "thirdkeyword"],
            "languages": ["neighbourlanguage", "thirdlanguage"],
            "access_levels": ["restricted"],
        }
    admin = await get_admin_dataset_by_id(db_pool, dataset_id, configured_sources=(source,))
    assert admin is not None and admin.quarantined_at is not None and admin.public_title is None
    assert admin.quarantine_reason == "record_rejected"
    assert e2e_client.get(f"/dataset/{dataset_id}").status_code == 404
    resource = e2e_client.get(f"/dataset/{dataset_id}/resource/0", follow_redirects=False)
    assert resource.status_code == 404 and "location" not in resource.headers

    feed.set_snapshot(
        [
            feed.record(_A, visibility_tier="vetted", title="Corrected"),
            *_neighbours(feed),
        ],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=2),
    )
    assert (await runner(db_pool, configured_source=source)).status == "success"
    assert _quarantine(sync_conn, source.name) == []
    public = await get_dataset_by_id(db_pool, dataset_id, "public", configured_sources=(source,))
    vetted = await get_dataset_by_id(db_pool, dataset_id, "vetted", configured_sources=(source,))
    assert public is not None and public.visibility_tier == "vetted" and public.description is None
    assert vetted is not None and vetted.title == "Corrected" and vetted.description


async def test_rejected_known_record_stays_quarantined_when_contraction_aborts_rebuild(
    db_pool, sync_conn, monkeypatch
):
    """Verify rejected known record stays quarantined when contraction aborts rebuild."""
    feed = SignedFeed(monkeypatch)
    source = feed.source(schedule={"rebuild_max_inferred_delete_count": 0})
    await _seed(db_pool, feed, source)
    feed.set_snapshot(
        [feed.record(_A, title=""), feed.record(_B)],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
    )
    result = await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert result.status == "failed"
    assert [row[0] for row in _quarantine(sync_conn, source.name)] == [_A]
    assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone() == (3,)
    sync_conn.commit()


async def test_failed_rebuild_write_group_keeps_restriction_after_outer_rollback(
    db_pool, sync_conn, monkeypatch
):
    """Verify failed rebuild write group keeps restriction after outer rollback."""
    feed = SignedFeed(monkeypatch)
    source = feed.source()
    await _seed(db_pool, feed, source)
    before = sync_conn.execute(
        "SELECT uuid, title FROM oral_history_datasets ORDER BY uuid"
    ).fetchall()
    sync_conn.commit()
    feed.set_snapshot(
        [
            feed.record(_A, doi="10.1234/conflict"),
            feed.record(_B, doi="10.1234/conflict"),
            feed.record(_C, title="Rolled back neighbour"),
        ],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
    )
    result = await ingestion.run_full_rebuild(db_pool, configured_source=source)
    assert result.status == "failed" and result.failed_count == 2
    assert [(uuid, reason) for uuid, reason, _at in _quarantine(sync_conn, source.name)] == [
        (_A, "record_write_failed"),
        (_B, "record_write_failed"),
    ]
    assert (
        sync_conn.execute("SELECT uuid, title FROM oral_history_datasets ORDER BY uuid").fetchall()
        == before
    )
    sync_conn.commit()


async def test_delete_reintroduction_and_stale_replay_cannot_clear_quarantine(
    db_pool, sync_conn, dataset_factory, bind_catalogue_policy, monkeypatch
):
    """Verify delete reintroduction and stale replay cannot clear quarantine."""
    source, uuid = "archive_alpha", "retained-identity"
    feed = SignedFeed(monkeypatch)
    sources = (feed.source(name=source), feed.source(name="archive_beta"))
    bind_catalogue_policy(sources)
    dataset_id = dataset_factory(source=source, uuid=uuid, title="Quarantined identity")
    foreign = dataset_factory(source="archive_beta", uuid=uuid, title="Foreign allowed identity")
    async with get_db_cursor(db_pool) as cur:
        await ingestion._quarantine_known_records_cur(
            cur, source, [uuid, "unknown"], DEFAULT_CUTOFF, DEFAULT_CUTOFF
        )
    assert len(_quarantine(sync_conn, source)) == 1
    assert _quarantine(sync_conn, "archive_beta") == []
    sync_conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (dataset_id,))
    sync_conn.commit()
    reintroduced = dataset_factory(source=source, uuid=uuid, title="Quarantined identity")
    assert len(_quarantine(sync_conn, source)) == 1
    assert (
        await get_dataset_by_id(db_pool, reintroduced, "public", configured_sources=sources) is None
    )
    allowed = await get_dataset_by_id(db_pool, foreign, "public", configured_sources=sources)
    assert allowed is not None and allowed.title == "Foreign allowed identity"
    found, count = await search_datasets(db_pool, "public", configured_sources=sources)
    assert count == 1 and [row.id for row in found] == [foreign]
    assert await search_datasets(
        db_pool, "public", search_text="Quarantined identity", configured_sources=sources
    ) == ([], 0)
    for started in (DEFAULT_CUTOFF - timedelta(seconds=1), DEFAULT_CUTOFF):
        async with get_db_cursor(db_pool) as cur:
            await ingestion._restore_valid_record_cur(cur, source, uuid, started, DEFAULT_CUTOFF)
        assert len(_quarantine(sync_conn, source)) == 1
    async with get_db_cursor(db_pool) as cur:
        await ingestion._restore_valid_record_cur(
            cur,
            source,
            uuid,
            DEFAULT_CUTOFF + timedelta(seconds=1),
            DEFAULT_CUTOFF - timedelta(seconds=1),
        )
    assert len(_quarantine(sync_conn, source)) == 1
    sync_conn.execute(
        "INSERT INTO dataset_admin_state(source, uuid, visibility_tier, hidden_at) "
        "VALUES (%s, %s, 'vetted', CURRENT_TIMESTAMP)",
        (source, uuid),
    )
    sync_conn.commit()
    async with get_db_cursor(db_pool) as cur:
        await ingestion._restore_valid_record_cur(
            cur, source, uuid, DEFAULT_CUTOFF + timedelta(seconds=1), DEFAULT_CUTOFF
        )
    assert _quarantine(sync_conn, source) == []
    assert sync_conn.execute(
        "SELECT visibility_tier, hidden_at IS NOT NULL FROM dataset_admin_state "
        "WHERE source = %s AND uuid = %s",
        (source, uuid),
    ).fetchone() == ("vetted", True)
    assert sync_conn.execute(
        "SELECT id FROM oral_history_datasets WHERE id = %s", (foreign,)
    ).fetchone()
    sync_conn.commit()
    assert (
        await get_dataset_by_id(db_pool, foreign, "public", configured_sources=sources) is not None
    )
