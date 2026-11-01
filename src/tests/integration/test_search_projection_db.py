"""Audience projections track the complete disclosure policy in the same commit."""

import pytest
from psycopg.errors import LockNotAvailable, ObjectNotInPrerequisiteState
from psycopg.types.json import Jsonb

from app.services import (
    SearchUnavailable,
    build_catalogue_policy,
    get_dataset_by_id,
    guard_catalogue_policy_cur,
    replace_search_policy,
    search_catalogue_page,
    synchronize_search_policy,
)
from tests.source_fixtures import legacy_source


async def _policy(pool, **minima):
    """Build and durably synchronize a source policy with the supplied field minima."""
    sources = (legacy_source(max_visibility="public", field_visibility=minima),)
    policy = build_catalogue_policy(sources)
    await synchronize_search_policy(pool, policy)
    return policy


async def _ids(pool, policy, viewer="public", term=""):
    """Return matching dataset IDs in page order."""
    page = await search_catalogue_page(pool, viewer, term, configured_sources=policy)
    return [row.id for row in page.datasets]


async def test_each_projection_contains_only_its_permitted_document_and_filters(
    db_pool, sync_conn, dataset_factory
):
    """Verify each projection contains only its permitted document and filters."""
    policy = await _policy(db_pool, description="vetted", keywords="registered", languages="vetted")
    identifier = dataset_factory(
        title="discoveryword",
        description="descriptionsecret",
        keywords=["keywordsecret"],
        languages=["languagesecret"],
        visibility_tier="public",
    )
    public, registered, vetted = (
        sync_conn.execute(
            f"SELECT literal_document, keywords, languages FROM catalogue_search_{audience} WHERE id = %s",
            (identifier,),
        ).fetchone()
        for audience in ("public", "registered", "vetted")
    )
    assert "descriptionsecret" not in public[0] and "keywordsecret" not in public[0]
    assert public[1:] == ([], [])
    assert "descriptionsecret" not in registered[0] and registered[1:] == (["keywordsecret"], [])
    assert "descriptionsecret" in vetted[0] and vetted[2] == ["languagesecret"]
    assert await _ids(db_pool, policy, term="discoveryword -descriptionsecret") == [identifier]
    assert (
        await _ids(db_pool, policy, viewer="vetted", term="discoveryword -descriptionsecret") == []
    )


async def test_above_tier_discovery_survives_but_hidden_and_quarantined_rows_do_not(
    db_pool, sync_conn, dataset_factory
):
    """Verify above tier discovery survives but hidden and quarantined rows do not."""
    policy = await _policy(db_pool)
    identifier = dataset_factory(
        title="discoverable", description="restrictedword", visibility_tier="vetted"
    )
    assert await _ids(db_pool, policy, term="discoverable") == [identifier]
    assert await _ids(db_pool, policy, term="restrictedword") == []
    row = sync_conn.execute(
        "SELECT source, uuid FROM oral_history_datasets WHERE id = %s", (identifier,)
    ).fetchone()
    sync_conn.execute(
        "INSERT INTO dataset_admin_state(source, uuid, hidden_at) VALUES (%s, %s, clock_timestamp())",
        row,
    )
    sync_conn.commit()
    assert await _ids(db_pool, policy, viewer="vetted", term="discoverable") == []
    sync_conn.execute("DELETE FROM dataset_admin_state WHERE source = %s AND uuid = %s", row)
    sync_conn.execute(
        "INSERT INTO ingestion_quarantine(source, uuid, reason, failed_harvest_at, failed_source_cursor) VALUES (%s, %s, 'record_rejected', clock_timestamp(), clock_timestamp())",
        row,
    )
    sync_conn.commit()
    assert await _ids(db_pool, policy, viewer="vetted", term="discoverable") == []
    assert sync_conn.execute(
        "SELECT count(*) FROM catalogue_discovery WHERE id = %s", (identifier,)
    ).fetchone() == (0,)
    sync_conn.execute("DELETE FROM ingestion_quarantine WHERE source = %s AND uuid = %s", row)
    sync_conn.commit()
    assert await _ids(db_pool, policy, term="discoverable") == [identifier]
    assert await _ids(db_pool, policy, term="restrictedword") == []


async def test_admin_floor_and_projection_change_share_commit_and_rollback(
    db_pool, sync_conn, dataset_factory
):
    """Verify admin floor and projection change share commit and rollback."""
    policy = await _policy(db_pool)
    identifier = dataset_factory(description="originalword", visibility_tier="public")
    source, uuid = sync_conn.execute(
        "SELECT source, uuid FROM oral_history_datasets WHERE id = %s", (identifier,)
    ).fetchone()
    sync_conn.commit()
    sync_conn.execute(
        "INSERT INTO dataset_admin_state(source, uuid, visibility_tier) VALUES (%s, %s, 'vetted')",
        (source, uuid),
    )
    # Serving readers refuse while a policy-affecting write owns the lock.
    with pytest.raises(SearchUnavailable):
        await _ids(db_pool, policy, term="originalword")
    sync_conn.rollback()
    assert await _ids(db_pool, policy, term="originalword") == [identifier]
    sync_conn.execute(
        "INSERT INTO dataset_admin_state(source, uuid, visibility_tier) VALUES (%s, %s, 'vetted')",
        (source, uuid),
    )
    sync_conn.commit()
    assert await _ids(db_pool, policy, term="originalword") == []
    assert await _ids(db_pool, policy, viewer="vetted", term="originalword") == [identifier]


async def test_policy_replacement_is_compare_and_swap_and_stale_startup_cannot_undo_it(
    db_pool, sync_conn, dataset_factory
):
    """Verify policy replacement is compare and swap and stale startup cannot undo it."""
    before = await _policy(db_pool)
    identifier = dataset_factory(description="changedpolicyword", visibility_tier="public")
    after = build_catalogue_policy(
        (legacy_source(max_visibility="public", field_visibility={"description": "vetted"}),)
    )
    assert await _ids(db_pool, before, term="changedpolicyword") == [identifier]
    with pytest.raises(ObjectNotInPrerequisiteState):
        await replace_search_policy(db_pool, after, expected_fingerprint="0" * 64)
    assert await _ids(db_pool, before, term="changedpolicyword") == [identifier]
    await replace_search_policy(db_pool, after, expected_fingerprint=before.fingerprint)
    assert await _ids(db_pool, after, term="changedpolicyword") == []
    with pytest.raises(SearchUnavailable):
        await _ids(db_pool, before, term="changedpolicyword")
    with pytest.raises(ObjectNotInPrerequisiteState):
        await synchronize_search_policy(db_pool, before)
    assert sync_conn.execute("SELECT fingerprint FROM catalogue_search_policy").fetchone() == (
        after.fingerprint,
    )
    assert await _ids(db_pool, after, viewer="vetted", term="changedpolicyword") == [identifier]


async def test_raw_mutation_takes_the_projection_policy_lock_before_commit(
    db_pool, sync_conn, dataset_factory
):
    """Verify raw mutation takes the projection policy lock before commit."""
    policy = await _policy(db_pool)
    identifier = dataset_factory(description="beforeword", visibility_tier="public")
    sync_conn.execute(
        "UPDATE oral_history_datasets SET description = 'afterword' WHERE id = %s", (identifier,)
    )
    async with db_pool.connection() as observer:
        row = await (
            await observer.execute("SELECT pg_try_advisory_xact_lock(1330135379)")
        ).fetchone()
        assert row == (False,)
    for word in ("beforeword", "afterword"):
        with pytest.raises(SearchUnavailable):
            await _ids(db_pool, policy, term=word)
    sync_conn.commit()
    assert await _ids(db_pool, policy, term="beforeword") == []
    assert await _ids(db_pool, policy, term="afterword") == [identifier]


async def test_explicit_same_policy_rebuild_repairs_projection_only_with_current_comparison(
    db_pool, sync_conn, dataset_factory
):
    """Verify explicit same policy rebuild repairs projection only with current comparison."""
    policy = await _policy(db_pool)
    identifier = dataset_factory(title="repairable", visibility_tier="public")
    # Only the owner can alter private projection storage; simulate a repair
    # requirement without changing authoritative catalogue content or policy.
    sync_conn.execute("DELETE FROM catalogue_search_public WHERE id = %s", (identifier,))
    sync_conn.commit()
    await synchronize_search_policy(db_pool, policy)
    assert await _ids(db_pool, policy, term="repairable") == []
    with pytest.raises(ObjectNotInPrerequisiteState):
        await replace_search_policy(db_pool, policy, expected_fingerprint="0" * 64)
    await replace_search_policy(db_pool, policy, expected_fingerprint=policy.fingerprint)
    assert await _ids(db_pool, policy, term="repairable") == [identifier]


async def test_detail_and_resource_metadata_refuse_stale_worker_policy(db_pool, dataset_factory):
    """Verify detail and resource metadata refuse stale worker policy."""
    before = await _policy(db_pool)
    identifier = dataset_factory(
        visibility_tier="public",
        description="laterrestricted",
        resource_proxies=[{"type": "Resource", "ref": "https://archive.example.test/record"}],
    )
    visible = await get_dataset_by_id(db_pool, identifier, "public", configured_sources=before)
    assert visible is not None and visible.description == "laterrestricted"
    after = build_catalogue_policy((legacy_source(max_visibility="vetted"),))
    await replace_search_policy(db_pool, after, expected_fingerprint=before.fingerprint)
    with pytest.raises(SearchUnavailable):
        await get_dataset_by_id(db_pool, identifier, "public", configured_sources=before)
    hidden = await get_dataset_by_id(db_pool, identifier, "public", configured_sources=after)
    assert hidden is not None and hidden.description is None and hidden.resource_access_url is None


async def test_policy_replacement_cannot_commit_during_a_guarded_serving_transaction(
    db_pool, sync_conn
):
    """Verify policy replacement cannot commit during a guarded serving transaction."""
    before = await _policy(db_pool)
    after = build_catalogue_policy((legacy_source(max_visibility="vetted"),))
    async with (
        db_pool.connection() as connection,
        connection.transaction(),
        connection.cursor() as cursor,
    ):
        await guard_catalogue_policy_cur(cursor, before)
        sync_conn.execute("SET LOCAL lock_timeout = '50ms'")
        with pytest.raises(LockNotAvailable):
            sync_conn.execute(
                "SELECT public.catalogue_replace_search_policy(%s, %s, %s)",
                (
                    before.fingerprint,
                    after.fingerprint,
                    Jsonb({str(rank): dict(masks) for rank, masks in after.page_masks.items()}),
                ),
            )
        sync_conn.rollback()
        assert sync_conn.execute("SELECT fingerprint FROM catalogue_search_policy").fetchone() == (
            before.fingerprint,
        )
        sync_conn.rollback()
    await replace_search_policy(db_pool, after, expected_fingerprint=before.fingerprint)
