import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import create_autospec

import psycopg
import pyotp
import pytest
from psycopg.errors import DivisionByZero
from psycopg.rows import dict_row

from app.services import authentication, sessions, totp, users
from app.services.crypto import encrypt_value
from app.services.db import get_db_cursor
from tests.integration.conftest import TEST_DATABASE_URL

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_RACE_TIMEOUT = 20
_CLEANUP_TIMEOUT = 5
_POLL_INTERVAL = 0.01
_TOTP_TIME = 1_800_000_000
_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # Fixed test credential; never used outside this module.
_IP = "127.0.0.1"


@pytest.fixture(autouse=True)
def _fixed_totp_clock(monkeypatch):
    # Scope the fixed clock to TOTP verification, not the database or asyncio.
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))


@pytest.fixture
async def deactivation_observer(db_pool):
    assert db_pool.max_size >= 2, "Races need at least two pooled connections"
    async with await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL,
        autocommit=True,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    ) as conn:
        yield conn


def _state(sync_conn, user_id):
    with sync_conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """SELECT is_active, auth_revision, failed_login_count, locked_until,
                      last_login, last_totp_step, email, password_hash, totp_secret
               FROM users WHERE id = %s""",
            (user_id,),
        )
        row = cur.fetchone()
    sync_conn.commit()
    assert row is not None
    return row


def _session_rows(sync_conn, user_id):
    rows = sync_conn.execute(
        """SELECT id, user_id, expires_at, ip_address, purpose
           FROM sessions WHERE user_id = %s ORDER BY id""",
        (user_id,),
    ).fetchall()
    sync_conn.commit()
    return rows


def _login_case(user_factory, *, with_totp):
    return SimpleNamespace(
        user=user_factory(
            auth_revision=0,
            failed_login_count=1,
            totp_secret=encrypt_value(_TOTP_SECRET) if with_totp else None,
            last_totp_step=None,
        ),
        code=pyotp.TOTP(_TOTP_SECRET).at(_TOTP_TIME) if with_totp else "",
    )


async def _password_proof(db_pool, case, *, expected_revision):
    check = await authentication.verify_password(db_pool, case.user.email, case.user.password)
    assert check.password_ok is True
    assert check.user is not None and check.user.id == case.user.id
    assert check.auth_revision == expected_revision
    return check


async def _finalize(db_pool, case, check):
    assert check.auth_revision is not None
    return await authentication.finalize_local_login(
        db_pool,
        user_id=case.user.id,
        expected_auth_revision=check.auth_revision,
        totp_code=case.code,
        ip_address=_IP,
    )


@pytest.mark.parametrize("initially_active", [True, False], ids=["active", "already-inactive"])
@pytest.mark.parametrize("auth_method", ["local", "shibboleth"])
async def test_deactivation_revokes_both_session_purposes_and_only_the_target_user(
    db_pool, user_factory, session_factory, sync_conn, initially_active, auth_method, admin_actor
):
    """Even a repeated deactivation cleans up sessions and advances the revision."""
    user = user_factory(
        auth_method=auth_method,
        is_active=initially_active,
        auth_revision=7,
        failed_login_count=4,
        locked_until=datetime.now(UTC) + timedelta(hours=1),
    )
    session_factory(user.id, purpose="full")
    session_factory(user.id, purpose="totp_setup")
    other = user_factory()
    other_token = session_factory(other.id)
    before = _state(sync_conn, user.id)
    other_before = _state(sync_conn, other.id)
    other_sessions = _session_rows(sync_conn, other.id)
    assert len(_session_rows(sync_conn, user.id)) == 2

    result = await users.set_user_active(
        db_pool,
        user.id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )

    assert result == users.SetActiveResult(initially_active, False, False)
    assert _state(sync_conn, user.id) == {**before, "is_active": False, "auth_revision": 8}
    assert _session_rows(sync_conn, user.id) == []
    assert _state(sync_conn, other.id) == other_before
    assert _session_rows(sync_conn, other.id) == other_sessions
    lookup = await sessions.get_session_user(db_pool, other_token)
    assert lookup.user is not None and lookup.user.id == other.id


async def test_repeated_deactivation_advances_revision_even_without_session_rows(
    db_pool, user_factory, sync_conn, admin_actor
):
    """Zero deleted rows must not bypass invalidation of in-flight password checks."""
    user = user_factory(is_active=False, auth_revision=0)
    assert _session_rows(sync_conn, user.id) == []

    for expected_revision in (1, 2):
        result = await users.set_user_active(
            db_pool,
            user.id,
            False,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )
        assert result == users.SetActiveResult(False, False, False)
        assert _state(sync_conn, user.id)["auth_revision"] == expected_revision
        assert _session_rows(sync_conn, user.id) == []


@pytest.mark.parametrize("initially_active", [True, False], ids=["active", "already-inactive"])
@pytest.mark.parametrize("failure_point", ["during-delete", "after-delete"])
async def test_deactivation_sql_failure_rolls_back_flag_revision_and_sessions_then_retry_works(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    initially_active,
    failure_point,
    admin_actor,
):
    """Fault injection uses the caller's cursor and real PostgreSQL exceptions."""
    user = user_factory(
        is_active=initially_active,
        auth_revision=11,
        failed_login_count=2,
        locked_until=datetime.now(UTC) + timedelta(hours=1),
    )
    old_tokens = [
        session_factory(user.id, purpose="full"),
        session_factory(user.id, purpose="totp_setup"),
    ]
    before = _state(sync_conn, user.id)
    before_sessions = _session_rows(sync_conn, user.id)
    assert len(before_sessions) == 2
    real_delete = users.delete_user_sessions_cur

    async def fail_deletion(cur, user_id):
        assert user_id == user.id
        await cur.execute("SELECT is_active, auth_revision FROM users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
        # Prove the UPDATE happened before the injected failure in this transaction.
        assert row is not None and row["is_active"] is False
        assert row["auth_revision"] == before["auth_revision"] + 1
        if failure_point == "during-delete":
            await cur.execute(
                "DELETE FROM sessions WHERE user_id = %s AND 1 / %s = 0", (user_id, 0)
            )
        else:
            await real_delete(cur, user_id)
            await cur.execute(
                "SELECT COUNT(*) AS remaining FROM sessions WHERE user_id = %s", (user_id,)
            )
            remaining = await cur.fetchone()
            assert remaining is not None and remaining["remaining"] == 0
            await cur.execute("SELECT 1 / 0")

    # Patch where the direct import is LOOKED UP, not session_revocation's attribute.
    with monkeypatch.context() as patcher:
        patcher.setattr(users, "delete_user_sessions_cur", fail_deletion)
        with pytest.raises(DivisionByZero):
            await users.set_user_active(
                db_pool,
                user.id,
                False,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )

    # Independent connection sees all original committed data, including deleted rows.
    assert _state(sync_conn, user.id) == before
    assert _session_rows(sync_conn, user.id) == before_sessions

    result = await users.set_user_active(
        db_pool,
        user.id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    assert result == users.SetActiveResult(initially_active, False, False)
    assert _state(sync_conn, user.id) == {**before, "is_active": False, "auth_revision": 12}
    assert _session_rows(sync_conn, user.id) == []

    await users.set_user_active(
        db_pool,
        user.id,
        True,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    for token in old_tokens:
        assert (await sessions.get_session_user(db_pool, token)).user is None


@pytest.mark.parametrize("with_totp", [True, False], ids=["full", "setup"])
async def test_reactivation_cannot_resurrect_sessions_or_an_old_password_proof(
    db_pool, user_factory, session_factory, sync_conn, with_totp, admin_actor
):
    """After reactivation, revision checks still reject a pre-deactivation proof."""
    case = _login_case(user_factory, with_totp=with_totp)
    old_token = session_factory(case.user.id)
    check = await _password_proof(db_pool, case, expected_revision=0)

    assert await users.set_user_active(
        db_pool,
        case.user.id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    ) == users.SetActiveResult(True, False, False)
    assert await users.set_user_active(
        db_pool,
        case.user.id,
        True,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    ) == users.SetActiveResult(
        False,
        True,
        True,  # The fixture's failed-login count was one.
    )
    before_rejected_login = _state(sync_conn, case.user.id)
    assert before_rejected_login["is_active"] is True
    assert before_rejected_login["auth_revision"] == 2
    assert (await sessions.get_session_user(db_pool, old_token)).user is None

    rejected = await _finalize(db_pool, case, check)
    assert isinstance(rejected, authentication.LocalLoginFailure)
    assert rejected.reason == "auth_state_changed"
    assert _state(sync_conn, case.user.id) == before_rejected_login
    assert _session_rows(sync_conn, case.user.id) == []

    # Positive control: a fresh password proof succeeds with the same valid TOTP code.
    fresh = await _password_proof(db_pool, case, expected_revision=2)
    result = await _finalize(db_pool, case, fresh)
    assert isinstance(result, authentication.LocalLoginSuccess)
    assert result.purpose == ("full" if with_totp else "totp_setup")
    lookup = await sessions.get_session_user(db_pool, result.session_id)
    assert lookup.user is not None and lookup.user.id == case.user.id
    assert lookup.purpose == result.purpose
    assert (await sessions.get_session_user(db_pool, old_token)).user is None
    assert len(_session_rows(sync_conn, case.user.id)) == 1


@pytest.mark.parametrize("lock_state", ["future", "expired", "none"])
async def test_unlocking_an_active_account_advances_revision_and_preserves_sessions(
    db_pool, user_factory, session_factory, sync_conn, lock_state, admin_actor
):
    """The activation/unlock branch must not become an accidental logout-everywhere."""
    locked_until = {
        "future": datetime.now(UTC) + timedelta(hours=1),
        "expired": datetime.now(UTC) - timedelta(hours=1),
        "none": None,
    }[lock_state]
    user = user_factory(
        is_active=True,
        auth_revision=7,
        failed_login_count=3 if lock_state == "future" else 0,
        locked_until=locked_until,
    )
    token = session_factory(user.id)
    before = _state(sync_conn, user.id)
    before_sessions = _session_rows(sync_conn, user.id)

    result = await users.set_user_active(
        db_pool,
        user.id,
        True,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )

    assert result == users.SetActiveResult(True, True, lock_state != "none")
    assert _state(sync_conn, user.id) == {
        **before,
        "auth_revision": before["auth_revision"] + 1,
        "failed_login_count": 0,
        "locked_until": None,
    }
    assert _session_rows(sync_conn, user.id) == before_sessions
    lookup = await sessions.get_session_user(db_pool, token)
    assert lookup.user is not None and lookup.user.id == user.id


@dataclass
class _Gate:
    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    pid: int | None = None

    async def hold(self, cur):
        self.pid = cur.connection.info.backend_pid
        self.reached.set()
        await self.release.wait()


def _pause_deactivation(monkeypatch, gate):
    real_delete = users.delete_user_sessions_cur

    async def paused_delete(cur, user_id):
        await real_delete(cur, user_id)
        await gate.hold(cur)

    monkeypatch.setattr(
        users,
        "delete_user_sessions_cur",
        create_autospec(users.delete_user_sessions_cur, side_effect=paused_delete),
    )


def _pause_login(monkeypatch, gate):
    real_create = authentication.create_session_cur

    async def paused_create(cur, *, user_id, ip_address, purpose, max_age_seconds):
        token = await real_create(
            cur,
            user_id=user_id,
            ip_address=ip_address,
            purpose=purpose,
            max_age_seconds=max_age_seconds,
        )
        await gate.hold(cur)
        return token

    monkeypatch.setattr(
        authentication,
        "create_session_cur",
        create_autospec(authentication.create_session_cur, side_effect=paused_create),
    )


def _track_connections(monkeypatch):
    active = {}

    @asynccontextmanager
    async def tracked_cursor(pool, *args, **kwargs) -> AsyncIterator[Any]:
        async with get_db_cursor(pool, *args, **kwargs) as cur:
            task = asyncio.current_task()
            active[task] = cur.connection.info.backend_pid
            try:
                yield cur
            finally:
                active.pop(task, None)

    for module in (authentication, users):
        monkeypatch.setattr(module, "get_db_cursor", tracked_cursor)
    return active


async def _wait_for_gate(gate, leader):
    waiter = asyncio.create_task(gate.reached.wait())
    try:
        await asyncio.wait((waiter, leader), return_when=asyncio.FIRST_COMPLETED)
        if leader.done():
            leader.result()
            pytest.fail("Leading operation completed without holding the transaction gate")
    finally:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


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
                "SELECT %s = ANY(pg_blocking_pids(%s))", (leader_pid, follower_pid)
            )
            row = await cur.fetchone()
            if row is not None and row[0]:
                assert follower_pid != leader_pid
                return
        # Poll a real database condition; sleeping by itself never establishes ordering.
        await asyncio.sleep(_POLL_INTERVAL)


async def _ordered_race(observer, active, gate, leading_call, following_call):
    tasks = []
    try:
        async with asyncio.timeout(_RACE_TIMEOUT):
            leader = asyncio.create_task(leading_call())
            tasks.append(leader)
            await _wait_for_gate(gate, leader)
            assert gate.pid is not None
            follower = asyncio.create_task(following_call())
            tasks.append(follower)
            await _wait_for_database_block(observer, active, follower, gate.pid)
            gate.release.set()
            return await asyncio.gather(leader, follower)
    finally:
        gate.release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        async with asyncio.timeout(_CLEANUP_TIMEOUT):
            await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("with_totp", [True, False], ids=["full", "setup"])
async def test_deactivation_first_blocks_login_and_preserves_unused_totp_step(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    deactivation_observer,
    with_totp,
    admin_actor,
):
    case = _login_case(user_factory, with_totp=with_totp)
    session_factory(case.user.id)
    check = await _password_proof(db_pool, case, expected_revision=0)
    before = _state(sync_conn, case.user.id)
    active = _track_connections(monkeypatch)
    gate = _Gate()
    _pause_deactivation(monkeypatch, gate)

    deactivated, result = await _ordered_race(
        deactivation_observer,
        active,
        gate,
        lambda: users.set_user_active(
            db_pool,
            case.user.id,
            False,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        ),
        lambda: _finalize(db_pool, case, check),
    )

    assert deactivated == users.SetActiveResult(True, False, False)
    assert isinstance(result, authentication.LocalLoginFailure)
    assert result.reason == "inactive_account"
    assert _state(sync_conn, case.user.id) == {**before, "is_active": False, "auth_revision": 1}
    assert _session_rows(sync_conn, case.user.id) == []


@pytest.mark.parametrize("with_totp", [True, False], ids=["full", "setup"])
async def test_login_first_has_its_new_session_deleted_by_waiting_deactivation(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    deactivation_observer,
    with_totp,
    admin_actor,
):
    case = _login_case(user_factory, with_totp=with_totp)
    old_token = session_factory(case.user.id)
    check = await _password_proof(db_pool, case, expected_revision=0)
    active = _track_connections(monkeypatch)
    gate = _Gate()
    _pause_login(monkeypatch, gate)

    result, deactivated = await _ordered_race(
        deactivation_observer,
        active,
        gate,
        lambda: _finalize(db_pool, case, check),
        lambda: users.set_user_active(
            db_pool,
            case.user.id,
            False,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        ),
    )

    assert isinstance(result, authentication.LocalLoginSuccess)
    assert result.purpose == ("full" if with_totp else "totp_setup")
    assert deactivated == users.SetActiveResult(True, False, False)
    state = _state(sync_conn, case.user.id)
    assert state["is_active"] is False
    assert state["auth_revision"] == 1
    assert state["failed_login_count"] == 0
    assert state["last_login"] is not None
    assert state["last_totp_step"] == (_TOTP_TIME // 30 if with_totp else None)
    assert _session_rows(sync_conn, case.user.id) == []

    # Reactivation rules out the inactive-user lookup filter as the reason for rejection.
    await users.set_user_active(
        db_pool,
        case.user.id,
        True,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    assert (await sessions.get_session_user(db_pool, old_token)).user is None
    assert (await sessions.get_session_user(db_pool, result.session_id)).user is None
