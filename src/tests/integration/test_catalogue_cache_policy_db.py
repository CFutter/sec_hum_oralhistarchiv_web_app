"""Warm public statistics refuse a superseded durable catalogue policy."""

from datetime import UTC, datetime

import pytest
from psycopg_pool import AsyncConnectionPool

from app.services import CatalogueStatsCache, SearchUnavailable
from tests.source_fixtures import legacy_source


@pytest.mark.parametrize(
    "method", ("get_global_stats", "get_total_datasets", "get_last_full_rebuild")
)
async def test_every_warm_cache_read_refuses_replaced_policy(
    bind_catalogue_policy, db_pool, sync_conn, dataset_factory, method
):
    """Verify every warm cache read refuses replaced policy."""
    source = legacy_source(max_visibility="public")
    policy = bind_catalogue_policy((source,))
    dataset_factory(title="Public discovery")
    sync_conn.execute(
        "UPDATE sync_status SET last_full_rebuild_date = last_harvest_date WHERE source = %s",
        (source.name,),
    )
    sync_conn.commit()
    cache = CatalogueStatsCache(
        db_pool,
        source_names=(source.name,),
        policy_fingerprint=policy.fingerprint,
        subscribe=False,
    )
    try:
        warmed = await cache.get_global_stats()
        assert warmed.total_datasets == 1
        assert warmed.last_full_rebuild == datetime(2026, 1, 1, tzinfo=UTC)
        tightened = bind_catalogue_policy((legacy_source(max_visibility="vetted"),))
        assert tightened.fingerprint != policy.fingerprint
        with pytest.raises(SearchUnavailable):
            await getattr(cache, method)()

        cache.replace_source_names((source.name,), policy_fingerprint=tightened.fingerprint)
        current = await cache.get_global_stats()
        assert current == warmed
    finally:
        cache.stop()


async def test_guard_and_statistics_share_one_pool_connection(
    bind_catalogue_policy, db_pool, dataset_factory
):
    """Verify guard and statistics share one pool connection."""
    source = legacy_source(max_visibility="public")
    policy = bind_catalogue_policy((source,))
    dataset_factory()
    async with AsyncConnectionPool(
        db_pool.conninfo, min_size=1, max_size=1, timeout=0.2, open=False
    ) as single:
        await single.wait(timeout=10)
        cache = CatalogueStatsCache(
            single,
            source_names=(source.name,),
            policy_fingerprint=policy.fingerprint,
            subscribe=False,
        )
        try:
            assert (await cache.get_global_stats()).total_datasets == 1
            assert await cache.get_total_datasets() == 1
            assert await cache.get_last_full_rebuild() is None
        finally:
            cache.stop()
