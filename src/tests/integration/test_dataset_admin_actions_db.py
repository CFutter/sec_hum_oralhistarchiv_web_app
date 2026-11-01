"""Authorized dataset actions commit durable state and audit only successful changes."""

import asyncio
import logging

import pytest
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from app.services import (
    AdminActionRejected,
    DatasetAdminContext,
    DatasetAdminRejected,
)
from app.services import (
    change_dataset_admin_state as change_state,
)
from app.services.catalogue_lock import CATALOGUE_WRITE_LOCK_KEY
from app.services.datasets import get_dataset_by_id
from app.services.session_ids import hash_session_id
from tests.source_fixtures import fixture_source, legacy_source


@pytest.fixture
def action_context(admin_actor):
    """Build the dataset-admin context from the fixture actor and session."""
    return DatasetAdminContext(
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
        request_id="dataset-admin-test",
        client_ip="127.0.0.1",
    )


@pytest.fixture
def action_audit(caplog):
    """Capture audit even when application setup disables propagation."""
    logger = logging.getLogger("audit")
    handlers, propagate = logger.handlers[:], logger.propagate
    logger.handlers = [*handlers, caplog.handler] if caplog.handler not in handlers else handlers
    logger.propagate = False
    try:
        with caplog.at_level(logging.INFO, logger="audit"):
            yield caplog
    finally:
        logger.handlers, logger.propagate = handlers, propagate


def _events(capture):
    """Select the relevant captured audit events for this scenario."""
    return [r for r in capture.records if getattr(r, "event_type", "").startswith("admin_dataset_")]


def _state(conn, source="archive_alpha", uuid="controlled"):
    """Read the admin tier and hidden timestamp, or None; commit the observer transaction."""
    row = conn.execute(
        "SELECT visibility_tier, hidden_at FROM dataset_admin_state WHERE source = %s AND uuid = %s",
        (source, uuid),
    ).fetchone()
    conn.commit()
    return row


async def test_raise_hide_restore_are_durable_source_scoped_and_audited_once(
    bind_catalogue_policy,
    db_pool,
    sync_conn,
    dataset_factory,
    admin_actor,
    action_context,
    action_audit,
):
    """Verify raise hide restore are durable source scoped and audited once."""
    target = dataset_factory(
        source="archive_alpha",
        uuid="controlled",
        data=Jsonb({}),
        title="metadata-never-audit",
        description="private-never-audit",
    )
    foreign = dataset_factory(source="archive_beta", uuid="controlled")
    source = legacy_source(name="archive_alpha", max_visibility="public")
    bind_catalogue_policy((source,))
    assert admin_actor.session_id not in repr(action_context)
    raised = await change_state(
        db_pool,
        target,
        "raise_tier",
        context=action_context,
        new_tier="registered",
        configured_sources=(source,),
    )
    assert raised.changed and raised.dataset_id == target
    assert (raised.source, raised.uuid, raised.action) == (
        "archive_alpha",
        "controlled",
        "raise_tier",
    )
    assert raised.before.admin_tier is None and raised.after.admin_tier == "registered"
    assert raised.before.stored_tier == raised.after.stored_tier == "public"
    assert raised.after.effective_tier == "registered"
    repeated = await change_state(
        db_pool,
        target,
        "raise_tier",
        context=action_context,
        new_tier="registered",
        configured_sources=(source,),
    )
    assert not repeated.changed
    hidden = await change_state(
        db_pool, target, "hide", context=action_context, configured_sources=(source,)
    )
    assert hidden.changed and hidden.after.hidden_at is not None
    assert hidden.after.hidden_at.utcoffset() is not None
    repeated = await change_state(
        db_pool, target, "hide", context=action_context, configured_sources=(source,)
    )
    assert not repeated.changed and repeated.after.hidden_at == hidden.after.hidden_at
    assert await get_dataset_by_id(db_pool, target, "vetted", configured_sources=(source,)) is None
    restored = await change_state(
        db_pool, target, "restore", context=action_context, configured_sources=(source,)
    )
    assert restored.changed and restored.after.hidden_at is None
    assert restored.after.admin_tier == "registered"
    repeated = await change_state(
        db_pool, target, "restore", context=action_context, configured_sources=(source,)
    )
    assert not repeated.changed
    assert _state(sync_conn) == ("registered", None)
    assert _state(sync_conn, "archive_beta") is None
    visible_foreign = await get_dataset_by_id(
        db_pool, foreign, "public", configured_sources=(source,)
    )
    assert visible_foreign is not None and visible_foreign.visibility_tier == "public"
    visible = await get_dataset_by_id(db_pool, target, "public", configured_sources=(source,))
    assert visible is not None and visible.description is None
    assert sync_conn.execute(
        "SELECT visibility_tier FROM oral_history_datasets WHERE id = %s", (target,)
    ).fetchone() == ("public",)
    events = _events(action_audit)
    assert [r.event_type for r in events] == [
        "admin_dataset_tier_raised",
        "admin_dataset_hidden",
        "admin_dataset_restored",
    ]
    for record, result in zip(events, (raised, hidden, restored), strict=True):
        assert (record.actor_admin_id, record.dataset_id) == (admin_actor.id, target)
        assert (record.dataset_source, record.dataset_uuid) == ("archive_alpha", "controlled")
        assert (record.request_id, record.client_ip) == ("dataset-admin-test", "127.0.0.1")
        for name in ("before", "after"):
            state = getattr(result, name)
            assert getattr(record, name) == {
                "stored_tier": state.stored_tier,
                "admin_tier": state.admin_tier,
                "effective_tier": state.effective_tier,
                "hidden_at": state.hidden_at.isoformat() if state.hidden_at else None,
            }
        assert "never-audit" not in repr(vars(record))
        assert admin_actor.session_id not in repr(vars(record))


@pytest.mark.parametrize(
    ("stored", "policy", "record_tier", "admin_floor"),
    [
        ("vetted", "public", None, None),
        ("public", "vetted", None, None),
        ("public", "public", "vetted", None),
        ("public", "public", None, "vetted"),
    ],
)
async def test_raise_rejects_below_any_effective_or_current_source_floor(
    db_pool,
    sync_conn,
    dataset_factory,
    action_context,
    action_audit,
    stored,
    policy,
    record_tier,
    admin_floor,
):
    """Verify raise rejects below any effective or current source floor."""
    target = dataset_factory(
        source="archive_alpha",
        uuid="controlled",
        visibility_tier=stored,
        data=Jsonb({"visibility_tier": record_tier}),
    )
    if admin_floor:
        sync_conn.execute(
            "INSERT INTO dataset_admin_state (source, uuid, visibility_tier) VALUES ('archive_alpha', 'controlled', %s)",
            (admin_floor,),
        )
        sync_conn.commit()
    before = _state(sync_conn)
    source = legacy_source(name="archive_alpha", max_visibility=policy)
    with pytest.raises(DatasetAdminRejected) as rejected:
        await change_state(
            db_pool,
            target,
            "raise_tier",
            context=action_context,
            new_tier="registered",
            configured_sources=(source,),
        )
    assert rejected.value.reason == "tier_below_floor"
    assert _state(sync_conn) == before and _events(action_audit) == []


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {"visibility_tier": None},
        {"visibility_tier": "unknown"},
        {"visibility_tier": 3},
    ],
)
async def test_mandatory_source_tier_failures_do_not_prevent_hide_or_restore(
    db_pool, sync_conn, dataset_factory, action_context, action_audit, raw
):
    """Verify mandatory source tier failures do not prevent hide or restore."""
    target = dataset_factory(source="archive_alpha", uuid="controlled", data=Jsonb(raw))
    source = fixture_source(
        name="archive_alpha", max_visibility="public", requires_record_tier=True
    )
    with pytest.raises(DatasetAdminRejected) as rejected:
        await change_state(
            db_pool,
            target,
            "raise_tier",
            context=action_context,
            new_tier="vetted",
            configured_sources=(source,),
        )
    assert rejected.value.reason == "invalid_source_tier"
    assert _state(sync_conn) is None and _events(action_audit) == []
    assert (
        await change_state(
            db_pool, target, "hide", context=action_context, configured_sources=(source,)
        )
    ).changed
    assert (
        await change_state(
            db_pool, target, "restore", context=action_context, configured_sources=(source,)
        )
    ).changed


@pytest.mark.parametrize("mandatory", [False, True])
async def test_equal_effective_tier_can_pin_a_new_durable_floor_without_parsing_other_json(
    db_pool, sync_conn, dataset_factory, action_context, mandatory
):
    """Verify equal effective tier can pin a new durable floor without parsing other JSON."""
    target = dataset_factory(
        source="archive_alpha",
        uuid="controlled",
        visibility_tier="registered",
        data=Jsonb(
            {"visibility_tier": "registered", "upstream_modified_at": "2026-10-17T00:00:00+00:00"}
        ),
    )
    source = fixture_source(
        name="archive_alpha", max_visibility="public", requires_record_tier=mandatory
    )
    result = await change_state(
        db_pool,
        target,
        "raise_tier",
        context=action_context,
        new_tier="registered",
        configured_sources=(source,),
    )
    assert result.changed and result.before.admin_tier is None
    assert result.before.effective_tier == result.after.effective_tier == "registered"
    assert _state(sync_conn) == ("registered", None)


async def test_retained_unselected_source_can_hide_restore_but_not_raise(
    db_pool, sync_conn, dataset_factory, action_context, action_audit
):
    """Verify retained unselected source can hide restore but not raise."""
    target = dataset_factory(source="archive_alpha", uuid="controlled")
    untouched = await change_state(
        db_pool, target, "restore", context=action_context, configured_sources=()
    )
    assert not untouched.changed and _state(sync_conn) is None
    with pytest.raises(DatasetAdminRejected) as rejected:
        await change_state(
            db_pool,
            target,
            "raise_tier",
            context=action_context,
            new_tier="vetted",
            configured_sources=(),
        )
    assert rejected.value.reason == "source_unavailable"
    assert _events(action_audit) == []
    assert (
        await change_state(db_pool, target, "hide", context=action_context, configured_sources=())
    ).changed
    assert (
        await change_state(
            db_pool, target, "restore", context=action_context, configured_sources=()
        )
    ).changed


@pytest.mark.parametrize(
    "authority",
    [
        "non-admin",
        "inactive",
        "missing-totp",
        "missing-recovery",
        "revoked",
        "expired",
        "wrong-purpose",
        "wrong-user",
    ],
)
async def test_current_actor_and_session_authority_are_required(
    db_pool,
    sync_conn,
    dataset_factory,
    user_factory,
    admin_actor,
    action_context,
    action_audit,
    authority,
):
    """Verify current actor and session authority are required."""
    target = dataset_factory(source="archive_alpha", uuid="controlled")
    actor_changes = {
        "non-admin": "is_admin = false",
        "inactive": "is_active = false",
        "missing-totp": "totp_secret = NULL",
        "missing-recovery": "totp_recovery_code_generation = 0",
    }
    if authority in actor_changes:
        sync_conn.execute(
            f"UPDATE users SET {actor_changes[authority]} WHERE id = %s", (admin_actor.id,)
        )
    else:
        session_hash = hash_session_id(admin_actor.session_id)
        if authority == "revoked":
            sync_conn.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
        elif authority == "wrong-user":
            other = user_factory()
            sync_conn.execute(
                "UPDATE sessions SET user_id = %s WHERE id = %s", (other.id, session_hash)
            )
        else:
            change = (
                "expires_at = clock_timestamp() - INTERVAL '1 second'"
                if authority == "expired"
                else "purpose = 'totp_setup'"
            )
            sync_conn.execute(f"UPDATE sessions SET {change} WHERE id = %s", (session_hash,))
    sync_conn.commit()
    with pytest.raises(AdminActionRejected):
        await change_state(db_pool, target, "hide", context=action_context, configured_sources=())
    assert _state(sync_conn) is None and _events(action_audit) == []


async def test_commit_failure_rolls_back_state_and_emits_no_success_audit(
    db_pool, sync_conn, dataset_factory, action_context, action_audit
):
    """Verify commit failure rolls back state and emits no success audit."""
    target = dataset_factory(source="archive_alpha", uuid="controlled")
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid) VALUES ('archive_alpha', 'canary')"
    )
    sync_conn.execute(
        "ALTER TABLE dataset_admin_state ADD CONSTRAINT test_admin_commit_failure UNIQUE (source) DEFERRABLE INITIALLY DEFERRED"
    )
    sync_conn.commit()
    try:
        with pytest.raises(UniqueViolation):
            await change_state(
                db_pool, target, "hide", context=action_context, configured_sources=()
            )
        assert _state(sync_conn) is None and _events(action_audit) == []
        assert _state(sync_conn, uuid="canary") == (None, None)
    finally:
        sync_conn.execute(
            "ALTER TABLE dataset_admin_state DROP CONSTRAINT test_admin_commit_failure"
        )
        sync_conn.commit()


async def _wait_for_catalogue_block(observer, follower, leader_pid):
    """Require PostgreSQL-observed lock blocking, with a bounded polling deadline."""
    deadline = asyncio.get_running_loop().time() + 20
    while True:
        if follower.done():
            follower.result()
            pytest.fail("Dataset action did not wait for the catalogue write lock")
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("Catalogue lock wait was not observed")
        row = await (
            await observer.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() "
                "AND pid <> %s AND %s = ANY(pg_blocking_pids(pid)))",
                (leader_pid, leader_pid),
            )
        ).fetchone()
        if row is not None and row[0]:
            return
        await asyncio.sleep(0.01)


async def test_session_revocation_while_waiting_for_ingestion_lock_prevents_action(
    db_pool, sync_conn, dataset_factory, admin_actor, action_context, action_audit
):
    """Verify session revocation while waiting for ingestion lock prevents action."""
    assert db_pool.max_size >= 3
    target = dataset_factory(source="archive_alpha", uuid="controlled")
    follower = None
    async with db_pool.connection() as leader, db_pool.connection() as observer:
        await observer.set_autocommit(True)
        try:
            await leader.execute("SELECT pg_advisory_xact_lock(%s)", (CATALOGUE_WRITE_LOCK_KEY,))
            follower = asyncio.create_task(
                change_state(db_pool, target, "hide", context=action_context, configured_sources=())
            )
            await _wait_for_catalogue_block(observer, follower, leader.info.backend_pid)
            await leader.execute(
                "DELETE FROM sessions WHERE id = %s", (hash_session_id(admin_actor.session_id),)
            )
            await leader.commit()
            with pytest.raises(AdminActionRejected):
                await asyncio.wait_for(follower, timeout=5)
        finally:
            if follower is not None and not follower.done():
                follower.cancel()
                await asyncio.wait_for(asyncio.gather(follower, return_exceptions=True), timeout=5)
            await leader.rollback()
            await observer.set_autocommit(False)
    assert _state(sync_conn) is None and _events(action_audit) == []
