"""Administrator authority is revalidated at durable write boundaries."""

import asyncio
import contextlib
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import create_autospec

import psycopg
import pytest
from pydantic import SecretStr

from app.services import email_change, federated_session_policy, session_revocation, sessions, users
from app.services.admin_promotion import request_admin_promotion
from app.services.db import get_db_cursor
from app.services.session_ids import hash_session_id
from tests.integration.conftest import TEST_DATABASE_URL

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_RACE_TIMEOUT = 20
_CLEANUP_TIMEOUT = 5
_POLL_INTERVAL = 0.01
_FEDERATED_ISSUER = "https://idp.test.example/idp/shibboleth"
_FEDERATED_SECRET = "kPQ9mV2xL7sN4cB8fH1jD5gR0aY3eU6iO9wQ2tM7zX4vC8b"


@pytest.fixture
async def admin_race_observer(db_pool):
    assert db_pool.max_size >= 2, "authorization races need at least two pooled connections"
    async with await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL,
        autocommit=True,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    ) as conn:
        yield conn


def _track_connections(monkeypatch):
    active: dict[asyncio.Task[Any], int] = {}

    @asynccontextmanager
    async def tracked_cursor(pool, *args, **kwargs) -> AsyncIterator[Any]:
        async with get_db_cursor(pool, *args, **kwargs) as cur:
            task = asyncio.current_task()
            assert task is not None
            active[task] = cur.connection.info.backend_pid
            try:
                yield cur
            finally:
                active.pop(task, None)

    for module in (email_change, session_revocation, sessions, users):
        monkeypatch.setattr(module, "get_db_cursor", tracked_cursor)
    return active


async def _wait_for_database_block(observer, active, follower, leader_pid):
    """Poll until the follower is observed blocked on the leader's pid.

    Bounded by its own deadline, not only by the caller's outer
    ``asyncio.timeout``: that cancellation can land inside the psycopg call
    instead of the sleep and be swallowed there, leaving the loop spinning
    after the timeout already expired.
    """
    deadline = asyncio.get_running_loop().time() + _RACE_TIMEOUT
    while True:
        if follower.done():
            follower.result()
            pytest.fail("Competing operation finished before the leading transaction committed")
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(
                f"no backend blocked on leader pid {leader_pid} within {_RACE_TIMEOUT}s"
            )
        follower_pid = active.get(follower)
        if follower_pid is not None:
            cur = await observer.execute(
                "SELECT %s = ANY(pg_blocking_pids(%s))",
                (leader_pid, follower_pid),
            )
            row = await cur.fetchone()
            if row is not None and row[0]:
                assert follower_pid != leader_pid
                return
        # Poll a database-observed lock condition; elapsed time is not proof.
        await asyncio.sleep(_POLL_INTERVAL)


def _user_state(sync_conn, user_id):
    row = sync_conn.execute(
        """SELECT is_active, is_admin, access_tier, pending_email,
                  pending_email_token_hash, pending_email_created_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row


def _outbox_count(sync_conn, user_id):
    row = sync_conn.execute(
        "SELECT count(*) FROM email_outbox WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row[0]


def _federated_approval_state(sync_conn, user_id):
    row = sync_conn.execute(
        """SELECT federated_status, is_active, access_tier, is_admin,
                  email_verified, federated_approved_at, federated_approved_by,
                  auth_revision
             FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row


async def _enable_federation_policy(db_pool, monkeypatch):
    monkeypatch.setattr(users.settings, "shibboleth_enabled", True)
    monkeypatch.setattr(
        users.settings,
        "shibboleth_trusted_issuers",
        [_FEDERATED_ISSUER],
    )
    monkeypatch.setattr(
        users.settings,
        "shibboleth_internal_secret",
        SecretStr(_FEDERATED_SECRET),
    )
    await federated_session_policy.reconcile_federated_session_policy(db_pool)


@pytest.mark.parametrize(
    "session_state",
    ["deleted", "wrong-user", "totp-setup", "expired", "unknown"],
)
async def test_tier_write_requires_the_exact_current_full_session(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    session_state,
):
    actor = user_factory(is_admin=True)
    target = user_factory(access_tier="public")
    # A different valid session must not rescue the exact credential supplied
    # by the already-resolved request.
    session_factory(actor.id, purpose="full")

    if session_state == "deleted":
        actor_session_id = session_factory(actor.id, purpose="full")
        sync_conn.execute(
            "DELETE FROM sessions WHERE id = %s",
            (hash_session_id(actor_session_id),),
        )
        sync_conn.commit()
    elif session_state == "wrong-user":
        other = user_factory()
        actor_session_id = session_factory(other.id, purpose="full")
    elif session_state == "totp-setup":
        actor_session_id = session_factory(actor.id, purpose="totp_setup")
    elif session_state == "expired":
        actor_session_id = session_factory(actor.id, purpose="full", expires_in_seconds=-1)
    else:
        actor_session_id = secrets.token_urlsafe(32)

    with pytest.raises(users.AdminActionRejected, match="session is no longer valid"):
        await users.update_access_tier(
            db_pool,
            target.id,
            "vetted",
            actor_id=actor.id,
            actor_session_id=actor_session_id,
        )

    assert _user_state(sync_conn, target.id)[2] == "public"


@pytest.mark.parametrize(
    "operation",
    ["tier", "active", "admin", "email", "federated-approval"],
)
async def test_revoked_session_blocks_every_privileged_mutation_sink(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    operation,
    monkeypatch,
):
    actor = user_factory(is_admin=True)
    revoked_session_id = session_factory(actor.id, purpose="full")
    session_factory(actor.id, purpose="full")  # another session remains valid
    if operation == "federated-approval":
        await _enable_federation_policy(db_pool, monkeypatch)
        target = user_factory(
            auth_method="shibboleth",
            shibboleth_issuer=_FEDERATED_ISSUER,
            shibboleth_subject_id="urn:test:subject:revoked-admin",
            federated_status="pending",
            is_active=False,
            access_tier="public",
        )
        federated_before = _federated_approval_state(sync_conn, target.id)
    else:
        target = user_factory(is_active=True, is_admin=False, access_tier="public")
        federated_before = None
    before = _user_state(sync_conn, target.id)

    await sessions.delete_session(db_pool, revoked_session_id)

    with pytest.raises(users.AdminActionRejected, match="session is no longer valid"):
        if operation == "tier":
            await users.update_access_tier(
                db_pool,
                target.id,
                "vetted",
                actor_id=actor.id,
                actor_session_id=revoked_session_id,
            )
        elif operation == "active":
            await users.set_user_active(
                db_pool,
                target.id,
                False,
                actor_id=actor.id,
                actor_session_id=revoked_session_id,
            )
        elif operation == "admin":
            # Granting is a two-party, target-accepted invitation (users.py:889-891
            # rejects a direct grant outright); the actor-side sink under test is
            # the invitation request itself.
            await request_admin_promotion(
                db_pool,
                actor_id=actor.id,
                actor_session_id=revoked_session_id,
                target_user_id=target.id,
            )
        elif operation == "email":
            await email_change.stage_admin_email_change(
                db_pool,
                actor_id=actor.id,
                actor_session_id=revoked_session_id,
                target_user_id=target.id,
                new_email="revoked-admin-change@uzh.ch",
            )
        else:
            await users.approve_federated_user(
                db_pool,
                target.id,
                expected_issuer=_FEDERATED_ISSUER,
                expected_subject_id="urn:test:subject:revoked-admin",
                access_tier="vetted",
                actor_id=actor.id,
                actor_session_id=revoked_session_id,
            )

    assert _user_state(sync_conn, target.id) == before
    assert _outbox_count(sync_conn, target.id) == 0
    if federated_before is not None:
        assert _federated_approval_state(sync_conn, target.id) == federated_before


async def test_credential_revocation_blocks_a_queued_tier_grant(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
):
    actor = user_factory(is_admin=True)
    actor_session_id = session_factory(actor.id)
    target = user_factory(access_tier="public")

    await session_revocation.delete_user_sessions(db_pool, actor.id)

    with pytest.raises(users.AdminActionRejected, match="session is no longer valid"):
        await users.update_access_tier(
            db_pool,
            target.id,
            "vetted",
            actor_id=actor.id,
            actor_session_id=actor_session_id,
        )
    assert _user_state(sync_conn, target.id)[2] == "public"


@pytest.mark.parametrize("revocation", ["demote", "deactivate", "delete-session"])
async def test_revocation_committing_first_rejects_waiting_federated_approval(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    admin_race_observer,
    revocation,
):
    await _enable_federation_policy(db_pool, monkeypatch)
    actor = user_factory(is_admin=True)
    actor_session_id = session_factory(actor.id)
    subject = f"urn:test:subject:revocation-first:{revocation}"
    target = user_factory(
        auth_method="shibboleth",
        shibboleth_issuer=_FEDERATED_ISSUER,
        shibboleth_subject_id=subject,
        federated_status="pending",
        is_active=False,
        access_tier="public",
    )
    before = _federated_approval_state(sync_conn, target.id)
    active = _track_connections(monkeypatch)
    leader = await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    )
    follower = None

    try:
        if revocation in {"demote", "deactivate"}:
            statement = (
                "UPDATE users SET is_admin = false WHERE id = %s"
                if revocation == "demote"
                else "UPDATE users SET is_active = false WHERE id = %s"
            )
            await leader.execute(statement, (actor.id,))
        else:
            await leader.execute(
                "DELETE FROM sessions WHERE id = %s",
                (hash_session_id(actor_session_id),),
            )

        leader_pid = leader.info.backend_pid
        async with asyncio.timeout(_RACE_TIMEOUT):
            follower = asyncio.create_task(
                users.approve_federated_user(
                    db_pool,
                    target.id,
                    expected_issuer=_FEDERATED_ISSUER,
                    expected_subject_id=subject,
                    access_tier="vetted",
                    actor_id=actor.id,
                    actor_session_id=actor_session_id,
                )
            )
            await _wait_for_database_block(
                admin_race_observer,
                active,
                follower,
                leader_pid,
            )
            await leader.commit()
            with pytest.raises(users.AdminActionRejected):
                await follower
    finally:
        with contextlib.suppress(Exception):
            await leader.rollback()
        await leader.close()
        if follower is not None and not follower.done():
            follower.cancel()
            async with asyncio.timeout(_CLEANUP_TIMEOUT):
                await asyncio.gather(follower, return_exceptions=True)

    assert _federated_approval_state(sync_conn, target.id) == before


@pytest.mark.parametrize("revocation", ["demote", "deactivate", "delete-session"])
async def test_revocation_committing_first_rejects_waiting_tier_grant(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    admin_race_observer,
    revocation,
):
    actor = user_factory(is_admin=True)
    actor_session_id = session_factory(actor.id)
    target = user_factory(access_tier="public")
    active = _track_connections(monkeypatch)
    leader = await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    )
    follower = None

    try:
        if revocation in {"demote", "deactivate"}:
            statement = (
                "UPDATE users SET is_admin = false WHERE id = %s"
                if revocation == "demote"
                else "UPDATE users SET is_active = false WHERE id = %s"
            )
            await leader.execute(
                statement,
                (actor.id,),
            )
        else:
            await leader.execute(
                "DELETE FROM sessions WHERE id = %s",
                (hash_session_id(actor_session_id),),
            )

        leader_pid = leader.info.backend_pid
        async with asyncio.timeout(_RACE_TIMEOUT):
            follower = asyncio.create_task(
                users.update_access_tier(
                    db_pool,
                    target.id,
                    "vetted",
                    actor_id=actor.id,
                    actor_session_id=actor_session_id,
                )
            )
            await _wait_for_database_block(
                admin_race_observer,
                active,
                follower,
                leader_pid,
            )
            await leader.commit()
            with pytest.raises(users.AdminActionRejected):
                await follower
    finally:
        with contextlib.suppress(Exception):
            await leader.rollback()
        await leader.close()
        if follower is not None and not follower.done():
            follower.cancel()
            async with asyncio.timeout(_CLEANUP_TIMEOUT):
                await asyncio.gather(follower, return_exceptions=True)

    assert _user_state(sync_conn, target.id)[2] == "public"


@dataclass
class _GuardGate:
    actor_id: int
    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    pid: int | None = None


@pytest.mark.parametrize("revocation", ["demote", "deactivate", "delete-session"])
async def test_guarded_grant_commits_before_waiting_revocation(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    admin_race_observer,
    revocation,
):
    actor = user_factory(is_admin=True)
    actor_session_id = session_factory(actor.id)
    revoker = user_factory(is_admin=True)
    revoker_session_id = session_factory(revoker.id)
    target = user_factory(access_tier="public")
    active = _track_connections(monkeypatch)
    gate = _GuardGate(actor.id)
    real_guard = users.guard_current_admin_session_cur

    async def paused_guard(cur, *, actor_id, actor_session_id):
        await real_guard(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        if actor_id == gate.actor_id:
            gate.pid = cur.connection.info.backend_pid
            gate.reached.set()
            await gate.release.wait()

    monkeypatch.setattr(
        users,
        "guard_current_admin_session_cur",
        create_autospec(users.guard_current_admin_session_cur, side_effect=paused_guard),
    )
    tasks: list[asyncio.Task[Any]] = []

    async def revoke():
        if revocation == "demote":
            return await users.set_user_admin(
                db_pool,
                actor.id,
                False,
                actor_id=revoker.id,
                actor_session_id=revoker_session_id,
            )
        if revocation == "deactivate":
            return await users.set_user_active(
                db_pool,
                actor.id,
                False,
                actor_id=revoker.id,
                actor_session_id=revoker_session_id,
            )
        return await sessions.delete_session(db_pool, actor_session_id)

    try:
        async with asyncio.timeout(_RACE_TIMEOUT):
            grant = asyncio.create_task(
                users.update_access_tier(
                    db_pool,
                    target.id,
                    "vetted",
                    actor_id=actor.id,
                    actor_session_id=actor_session_id,
                )
            )
            tasks.append(grant)
            await gate.reached.wait()
            assert gate.pid is not None

            revocation_task = asyncio.create_task(revoke())
            tasks.append(revocation_task)
            await _wait_for_database_block(
                admin_race_observer,
                active,
                revocation_task,
                gate.pid,
            )
            gate.release.set()
            grant_result, _ = await asyncio.gather(grant, revocation_task)
    finally:
        gate.release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        async with asyncio.timeout(_CLEANUP_TIMEOUT):
            await asyncio.gather(*tasks, return_exceptions=True)

    assert grant_result == ("public", "vetted")
    assert _user_state(sync_conn, target.id)[2] == "vetted"


@pytest.mark.parametrize("revocation", ["demote", "deactivate", "delete-session"])
async def test_guarded_federated_approval_commits_before_waiting_revocation(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    admin_race_observer,
    revocation,
):
    await _enable_federation_policy(db_pool, monkeypatch)
    actor = user_factory(is_admin=True)
    actor_session_id = session_factory(actor.id)
    revoker = user_factory(is_admin=True)
    revoker_session_id = session_factory(revoker.id)
    subject = f"urn:test:subject:approval-first:{revocation}"
    target = user_factory(
        auth_method="shibboleth",
        shibboleth_issuer=_FEDERATED_ISSUER,
        shibboleth_subject_id=subject,
        federated_status="pending",
        is_active=False,
        access_tier="public",
    )
    before_revision = _federated_approval_state(sync_conn, target.id)[7]
    active = _track_connections(monkeypatch)
    gate = _GuardGate(actor.id)
    real_guard = users.guard_current_admin_session_cur

    async def paused_guard(cur, *, actor_id, actor_session_id):
        await real_guard(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        if actor_id == gate.actor_id:
            gate.pid = cur.connection.info.backend_pid
            gate.reached.set()
            await gate.release.wait()

    monkeypatch.setattr(
        users,
        "guard_current_admin_session_cur",
        create_autospec(users.guard_current_admin_session_cur, side_effect=paused_guard),
    )
    tasks: list[asyncio.Task[Any]] = []

    async def revoke():
        if revocation == "demote":
            return await users.set_user_admin(
                db_pool,
                actor.id,
                False,
                actor_id=revoker.id,
                actor_session_id=revoker_session_id,
            )
        if revocation == "deactivate":
            return await users.set_user_active(
                db_pool,
                actor.id,
                False,
                actor_id=revoker.id,
                actor_session_id=revoker_session_id,
            )
        return await sessions.delete_session(db_pool, actor_session_id)

    try:
        async with asyncio.timeout(_RACE_TIMEOUT):
            approval = asyncio.create_task(
                users.approve_federated_user(
                    db_pool,
                    target.id,
                    expected_issuer=_FEDERATED_ISSUER,
                    expected_subject_id=subject,
                    access_tier="vetted",
                    actor_id=actor.id,
                    actor_session_id=actor_session_id,
                )
            )
            tasks.append(approval)
            await gate.reached.wait()
            assert gate.pid is not None

            revocation_task = asyncio.create_task(revoke())
            tasks.append(revocation_task)
            await _wait_for_database_block(
                admin_race_observer,
                active,
                revocation_task,
                gate.pid,
            )
            gate.release.set()
            approved, _ = await asyncio.gather(approval, revocation_task)
    finally:
        gate.release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        async with asyncio.timeout(_CLEANUP_TIMEOUT):
            await asyncio.gather(*tasks, return_exceptions=True)

    assert approved.federated_status == "approved"
    assert _federated_approval_state(sync_conn, target.id) == (
        "approved",
        True,
        "vetted",
        False,
        False,
        approved.federated_approved_at,
        actor.id,
        before_revision + 1,
    )
