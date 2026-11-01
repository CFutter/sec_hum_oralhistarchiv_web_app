"""The ``auth_revision`` fence and its token nonces under real concurrency."""

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
from itsdangerous import TimestampSigner
from psycopg.errors import DivisionByZero, ForeignKeyViolation
from psycopg.rows import dict_row

from app.services import (
    authentication,
    begin_local_registration,
    complete_local_registration,
    email_change,
    email_outbox,
    inspect_local_registration,
    password_reset,
    resend_local_registration,
    session_revocation,
    sessions,
    totp,
    users,
)
from app.services.crypto import decrypt_outbox_body
from app.services.db import get_db_cursor
from app.services.tokens import hash_token
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.action_links import token_from_action_email
from tests.integration.conftest import DEFAULT_PASSWORD, TEST_DATABASE_URL

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_OPERATIONS = ("password_reset", "email_change", "revoke_all")
_LOGIN_REVOCATION_CASES = [
    pytest.param(operation, with_totp, id=f"{operation}-{'full' if with_totp else 'setup'}")
    for operation in _OPERATIONS
    for with_totp in (True, False)
    if operation != "password_reset" or with_totp
]
_RACE_TIMEOUT = 20
_CLEANUP_TIMEOUT = 5
_POLL_INTERVAL = 0.01
_TOTP_TIME = 1_800_000_000
_NEW_PASSWORD = "M4ple!Orbit#7319_Cobalt"
_IP = "127.0.0.1"


@dataclass
class _Case:
    """Credentials and pending capability for one authentication-revision race."""

    operation: str
    user: Any
    code: str
    token: str
    new_email: str
    reset_code: str

    @property
    def module(self):
        """Select the service module implementing this case's revocation operation."""
        return {
            "password_reset": password_reset,
            "email_change": email_change,
            "revoke_all": session_revocation,
        }[self.operation]


@pytest.fixture(autouse=True)
def _fixed_totp_clock(monkeypatch):
    # Replace this module reference, not time.time globally.
    """Freeze the TOTP service's wall clock at the test instant."""
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))


@pytest.fixture
async def race_observer(db_pool):
    """Yield an independent autocommit observer with a five-second statement timeout."""
    assert db_pool.max_size >= 2, "Races need at least two pooled connections"
    async with await psycopg.AsyncConnection.connect(
        TEST_DATABASE_URL,
        autocommit=True,
        connect_timeout=3,
        options="-c statement_timeout=5000",
    ) as conn:
        yield conn


async def _make_case(db_pool, user_factory, operation, *, with_totp=True):
    """Create the credentials and pending capability for the requested race operation."""
    secret = pyotp.random_base32() if with_totp else None
    new_email = "changed-pending@example.org"
    user = user_factory(
        auth_revision=0,
        display_name="Alice Example",
        failed_login_count=1,
        totp_secret=encrypt_value(secret) if secret is not None else None,
        last_totp_step=None,
    )
    token = ""
    if operation == "password_reset":
        token = password_reset.generate_reset_token(user.id, user.email)
        await password_reset.store_reset_token_hash(
            db_pool, user.id, hash_token(token), expected_email=user.email
        )
    elif operation == "email_change":
        token = email_change.generate_email_change_token(user.id, new_email, auth_revision=0)
        await email_change.store_pending_email(
            db_pool, user.id, new_email, hash_token(token), expected_auth_revision=0
        )
    return _Case(
        operation=operation,
        user=user,
        code=pyotp.TOTP(secret).at(_TOTP_TIME) if secret is not None else "",
        token=token,
        new_email=new_email,
        # A login in the same race consumes the current step. Reset proves a
        # distinct step within the configured clock-skew window.
        reset_code=pyotp.TOTP(secret).at(_TOTP_TIME + 30) if secret is not None else "",
    )


def _state(sync_conn, user_id):
    """Read required user credentials and pending actions as a dictionary; commit the observer
    transaction.
    """
    with sync_conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """SELECT email, password_hash, auth_revision, totp_secret,
                      last_totp_step, failed_login_count, locked_until, last_login,
                      password_reset_token_hash, password_reset_created_at,
                      pending_email, pending_email_token_hash,
                      pending_email_created_at
               FROM users WHERE id = %s""",
            (user_id,),
        )
        row = cur.fetchone()
    sync_conn.commit()
    assert row is not None
    return row


def _session_count(sync_conn, user_id):
    """Count stored sessions for the user, including expired rows."""
    row = sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row[0]


async def _password_proof(db_pool, case):
    """Verify the case password and assert its identity and expected revision."""
    check = await authentication.verify_password(db_pool, case.user.email, case.user.password)
    assert check.password_ok is True
    assert check.user is not None and check.user.id == case.user.id
    assert check.auth_revision == 0, "Exercise zero as a valid initial revision"
    return check


async def _finalize(db_pool, case, check):
    """Finalize login using the verified revision and case's TOTP proof."""
    assert check.auth_revision is not None
    return await authentication.finalize_local_login(
        db_pool,
        user_id=case.user.id,
        expected_auth_revision=check.auth_revision,
        totp_code=case.code,
        ip_address=_IP,
    )


async def _revoke(db_pool, case):
    """Apply the case's password reset, email confirmation or session-revocation operation."""
    if case.operation == "password_reset":
        await password_reset.update_password_with_token(
            db_pool,
            case.user.id,
            case.token,
            _NEW_PASSWORD,
            expected_email=case.user.email,
            totp_code=case.reset_code,
        )
    elif case.operation == "email_change":
        assert (
            await email_change.confirm_email_change(
                db_pool,
                case.user.id,
                case.new_email,
                case.token,
                expected_auth_revision=0,
            )
            is True
        )
    else:
        assert case.operation == "revoke_all"
        await session_revocation.delete_user_sessions(db_pool, case.user.id)


@dataclass
class _Gate:
    """Transaction gate carrying readiness/release events and the lock-owner backend PID."""

    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    pid: int | None = None

    async def hold(self, cur):
        """Record the backend PID, signal the gate and hold the transaction until released."""
        self.pid = cur.connection.info.backend_pid
        self.reached.set()
        await self.release.wait()


def _pause_revocation(monkeypatch, case, gate):
    """Patch session deletion to pause its transaction after the real deletion."""
    real_delete = case.module.delete_user_sessions_cur

    async def paused_delete(cur, user_id):
        """Delete sessions with the real helper, then hold the transaction at the gate."""
        await real_delete(cur, user_id)
        await gate.hold(cur)

    monkeypatch.setattr(
        case.module,
        "delete_user_sessions_cur",
        create_autospec(case.module.delete_user_sessions_cur, side_effect=paused_delete),
    )


def _pause_login(monkeypatch, gate):
    """Patch session creation to pause its transaction after the real insert."""
    real_create = authentication.create_session_cur

    async def paused_create(cur, *, user_id, ip_address, purpose, max_age_seconds):
        """Create the real session, hold its transaction at the gate and return the token."""
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
    """Patch cursor scopes to track each active task's PostgreSQL backend PID."""
    active = {}

    @asynccontextmanager
    async def tracked_cursor(pool, *args, **kwargs) -> AsyncIterator[Any]:
        """Yield a real cursor while tracking the current task's backend PID; remove it on exit."""
        async with get_db_cursor(pool, *args, **kwargs) as cur:
            task = asyncio.current_task()
            active[task] = cur.connection.info.backend_pid
            try:
                yield cur
            finally:
                active.pop(task, None)

    for module in (authentication, password_reset, email_change, sessions, session_revocation):
        monkeypatch.setattr(module, "get_db_cursor", tracked_cursor)
    return active


async def _wait_for_gate(gate, leader):
    """Require the leader to reach its gate before finishing; clean up the waiter task."""
    waiter = asyncio.create_task(gate.reached.wait())
    try:
        await asyncio.wait((waiter, leader), return_when=asyncio.FIRST_COMPLETED)
        if leader.done():
            leader.result()  # Surface the original exception, if any.
            pytest.fail("Leading operation completed without holding the transaction gate")
    finally:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


async def _wait_for_database_block(observer, active, follower, leader_pid):
    """Poll until the follower connection is blocked behind the leader's lock.

    The caller wraps this in ``asyncio.timeout``, but that cancellation can
    land inside the psycopg call instead of the sleep and be swallowed there,
    leaving the loop spinning after the timeout already expired. The
    deadline check below is what actually terminates the loop, matching the
    shape used by ``_wait_for_blocker`` in ``test_federated_authentication_db.py``.
    """
    deadline = asyncio.get_running_loop().time() + _RACE_TIMEOUT
    while True:
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("follower connection never blocked behind the leader's lock")
        if follower.done():
            follower.result()
            pytest.fail("Competing operation finished before the leading transaction committed")
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
        # Poll an observed database condition; elapsed time is not evidence.
        await asyncio.sleep(_POLL_INTERVAL)


async def _ordered_race(observer, active, gate, leading_call, following_call):
    """Run a gated leader and blocked follower; release and cancel outstanding tasks on exit."""
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


class TestConcurrentRevocationAndLogin:
    """A revocation (password reset, email change, or explicit revoke-all)
    racing a waiting login must leave the fence consistent regardless of
    which transaction the database serializes first."""

    @pytest.mark.parametrize(("operation", "with_totp"), _LOGIN_REVOCATION_CASES)
    async def test_revocation_first_rejects_old_password_proof(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
        race_observer,
        operation,
        with_totp,
    ):
        """Revocation holds the user lock; waiting login must see the new revision."""
        case = await _make_case(db_pool, user_factory, operation, with_totp=with_totp)
        session_factory(case.user.id)
        check = await _password_proof(db_pool, case)
        before = _state(sync_conn, case.user.id)
        active = _track_connections(monkeypatch)
        gate = _Gate()
        _pause_revocation(monkeypatch, case, gate)

        _, result = await _ordered_race(
            race_observer,
            active,
            gate,
            lambda: _revoke(db_pool, case),
            lambda: _finalize(db_pool, case, check),
        )

        assert isinstance(result, authentication.LocalLoginFailure)
        assert result.reason == "auth_state_changed"
        assert result.failed_count is None and result.just_locked is False
        after = _state(sync_conn, case.user.id)
        assert after["auth_revision"] == check.auth_revision + 1
        expected_step = before["last_totp_step"]
        if operation == "password_reset":
            expected_step = _TOTP_TIME // 30 + 1
        assert after["last_totp_step"] == expected_step
        assert after["last_login"] == before["last_login"]
        expected_failures = 0 if operation == "password_reset" else before["failed_login_count"]
        assert after["failed_login_count"] == expected_failures
        assert _session_count(sync_conn, case.user.id) == 0

    @pytest.mark.parametrize(("operation", "with_totp"), _LOGIN_REVOCATION_CASES)
    async def test_login_first_session_is_removed_by_waiting_revocation(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
        race_observer,
        operation,
        with_totp,
    ):
        """Login inserts under the lock; subsequent revocation must delete that row."""
        case = await _make_case(db_pool, user_factory, operation, with_totp=with_totp)
        session_factory(case.user.id)
        check = await _password_proof(db_pool, case)
        active = _track_connections(monkeypatch)
        gate = _Gate()
        _pause_login(monkeypatch, gate)

        result, _ = await _ordered_race(
            race_observer,
            active,
            gate,
            lambda: _finalize(db_pool, case, check),
            lambda: _revoke(db_pool, case),
        )

        assert isinstance(result, authentication.LocalLoginSuccess)
        assert result.purpose == ("full" if with_totp else "totp_setup")
        assert _session_count(sync_conn, case.user.id) == 0
        lookup = await sessions.get_session_user(db_pool, result.session_id)
        assert lookup.user is None
        after = _state(sync_conn, case.user.id)
        assert after["auth_revision"] == check.auth_revision + 1
        assert after["last_login"] is not None
        expected_step = _TOTP_TIME // 30 if with_totp else None
        if operation == "password_reset":
            expected_step = _TOTP_TIME // 30 + 1
        assert after["last_totp_step"] == expected_step


class TestTransactionalRollbackOnFailure:
    """A real SQL error partway through a fenced transaction must undo every
    write the transaction made, including the ``auth_revision`` bump."""

    @pytest.mark.parametrize("operation", _OPERATIONS)
    async def test_failed_session_deletion_rolls_back_revision_and_credentials(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
        operation,
    ):
        """A real SQL error in DELETE must undo the preceding user UPDATE."""
        case = await _make_case(db_pool, user_factory, operation)
        session_factory(case.user.id)
        before = _state(sync_conn, case.user.id)

        async def failing_delete(cur, user_id):
            # Prove we reached deletion AFTER an uncommitted revision increment.
            """Check the incremented revision, then cause session deletion to fail in PostgreSQL."""
            await cur.execute("SELECT auth_revision FROM users WHERE id = %s", (user_id,))
            row = await cur.fetchone()
            assert row["auth_revision"] == before["auth_revision"] + 1
            await cur.execute(
                "DELETE FROM sessions WHERE user_id = %s AND 1 / %s = 0",
                (user_id, 0),
            )

        with monkeypatch.context() as local_patch:
            local_patch.setattr(case.module, "delete_user_sessions_cur", failing_delete)
            with pytest.raises(DivisionByZero):
                await _revoke(db_pool, case)

        assert _state(sync_conn, case.user.id) == before
        assert _session_count(sync_conn, case.user.id) == 1

        # Positive control: the original token/state still permits the real action.
        await _revoke(db_pool, case)
        assert _state(sync_conn, case.user.id)["auth_revision"] == before["auth_revision"] + 1
        assert _session_count(sync_conn, case.user.id) == 0

    async def test_failed_session_insert_rolls_back_totp_and_login_state(
        self,
        db_pool,
        user_factory,
        sync_conn,
        monkeypatch,
    ):
        """A real FK failure during INSERT must not consume the valid TOTP code."""
        case = await _make_case(db_pool, user_factory, "revoke_all")
        check = await _password_proof(db_pool, case)
        before = _state(sync_conn, case.user.id)
        real_create = authentication.create_session_cur

        async def invalid_insert(cur, *, user_id, ip_address, purpose, max_age_seconds):
            """Attempt the real session insert with a nonexistent user to force a foreign-key
            error.
            """
            assert user_id == case.user.id
            return await real_create(
                cur,
                user_id=-1,  # No such user in the clean integration-test database.
                ip_address=ip_address,
                purpose=purpose,
                max_age_seconds=max_age_seconds,
            )

        with monkeypatch.context() as local_patch:
            local_patch.setattr(authentication, "create_session_cur", invalid_insert)
            with pytest.raises(ForeignKeyViolation):
                await _finalize(db_pool, case, check)

        assert _state(sync_conn, case.user.id) == before
        assert _session_count(sync_conn, case.user.id) == 0
        result = await _finalize(db_pool, case, check)
        assert isinstance(result, authentication.LocalLoginSuccess)
        assert result.purpose == "full"
        assert _session_count(sync_conn, case.user.id) == 1


class TestLockoutAndRevocationEdgeCases:
    """Boundary states around the fence: a lockout applied after the password
    snapshot was taken, and a revocation with nothing left to delete."""

    async def test_lockout_after_password_check_is_not_cleared_by_finalizer(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """A valid password snapshot does not override a subsequently applied lockout."""
        case = await _make_case(db_pool, user_factory, "revoke_all")
        check = await _password_proof(db_pool, case)
        for _ in range(settings.login_failure_threshold):
            count, _ = await authentication.record_login_failure(
                db_pool, case.user.id, expected_auth_revision=0
            )
            if count >= settings.login_failure_threshold:
                break
        locked_state = _state(sync_conn, case.user.id)
        assert locked_state["locked_until"] > datetime.now(UTC)

        result = await _finalize(db_pool, case, check)

        assert isinstance(result, authentication.LocalLoginFailure)
        assert result.reason == "account_locked"
        assert _state(sync_conn, case.user.id) == locked_state
        assert _session_count(sync_conn, case.user.id) == 0

    async def test_revocation_without_existing_sessions_still_invalidates_password_proof(
        self,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """DELETE affecting zero rows still commits the revision increment."""
        case = await _make_case(db_pool, user_factory, "revoke_all")
        check = await _password_proof(db_pool, case)
        assert _session_count(sync_conn, case.user.id) == 0
        await _revoke(db_pool, case)

        result = await _finalize(db_pool, case, check)

        assert isinstance(result, authentication.LocalLoginFailure)
        assert result.reason == "auth_state_changed"
        assert _state(sync_conn, case.user.id)["auth_revision"] == check.auth_revision + 1
        fresh_check = await authentication.verify_password(
            db_pool, case.user.email, case.user.password
        )
        assert fresh_check.password_ok is True
        assert fresh_check.auth_revision == check.auth_revision + 1
        fresh_result = await _finalize(db_pool, case, fresh_check)
        assert isinstance(fresh_result, authentication.LocalLoginSuccess)


@pytest.fixture
def _frozen_token_clock(monkeypatch):
    """Freeze token-signer timestamps at the current whole second."""
    instant = int(datetime.now(UTC).timestamp())
    monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda _self: instant)


def _registration_mail_token(sync_conn, email):
    """Decrypt the newest registration email and extract its capability token."""
    row = sync_conn.execute(
        """SELECT body_ciphertext FROM email_outbox
           WHERE recipient = %s AND message_type = 'email_verification'
           ORDER BY id DESC LIMIT 1""",
        (email,),
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    body = decrypt_outbox_body(row[0])
    assert body is not None
    prefix = settings.public_base_url + "/verify-email/"
    return token_from_action_email(
        body, next(line.strip() for line in body.splitlines() if prefix in line)
    )


class TestTokenNonceReplacement:
    """Issuing a fresh token for the same purpose invalidates the previously
    stored token hash immediately, even when both are signed in the same
    clock second and would otherwise carry an identical timestamp."""

    async def test_same_second_registration_resend_preserves_the_live_single_use_link(
        self, db_pool, sync_conn, _frozen_token_clock
    ):
        """Verify same second registration resend preserves the live single use link."""
        email = "nonce-mailbox@example.org"
        await begin_local_registration(db_pool, email=email)
        first = _registration_mail_token(sync_conn, email)
        assert await inspect_local_registration(db_pool, first) is not None
        await resend_local_registration(db_pool, email=email)
        second = _registration_mail_token(sync_conn, email)
        assert first == second
        assert await inspect_local_registration(db_pool, first) is not None
        assert await inspect_local_registration(db_pool, second) is not None
        owner = await complete_local_registration(
            db_pool, token=second, display_name="Mailbox Owner", password=_NEW_PASSWORD
        )
        assert owner is not None and owner.email_verified and owner.is_active
        assert (await authentication.verify_password(db_pool, email, _NEW_PASSWORD)).password_ok
        assert (
            await complete_local_registration(
                db_pool,
                token=second,
                display_name="Different Owner",
                password="Cobalt-Forests-739!Rain",
            )
            is None
        )

    async def test_cancelled_registration_cannot_be_revived_by_same_second_resend(
        self, db_pool, sync_conn, _frozen_token_clock
    ):
        """Verify cancelled registration cannot be revived by same second resend."""
        email = "cancelled-mailbox@example.org"
        await begin_local_registration(db_pool, email=email)
        token = _registration_mail_token(sync_conn, email)
        reference = await inspect_local_registration(db_pool, token)
        assert reference is not None
        await session_revocation.delete_user_sessions(db_pool, reference.user_id)
        await resend_local_registration(db_pool, email=email)
        assert await inspect_local_registration(db_pool, token) is None
        assert (
            await complete_local_registration(
                db_pool, token=token, display_name="Mailbox Owner", password=_NEW_PASSWORD
            )
            is None
        )
        state = sync_conn.execute(
            """SELECT password_hash, is_active, email_verified, auth_revision,
                      email_verification_token_hash, email_verification_created_at
               FROM users WHERE id = %s""",
            (reference.user_id,),
        ).fetchone()
        assert state == (None, False, False, 1, None, None)
        assert sync_conn.execute(
            "SELECT status, terminal_outcome FROM email_outbox WHERE user_id = %s",
            (reference.user_id,),
        ).fetchall() == [("dead", "cancelled")]
        sync_conn.commit()

    async def test_same_second_email_change_replacement_rejects_previous_link(
        self, db_pool, user_factory, _frozen_token_clock
    ):
        """Verify same second email change replacement rejects previous link."""
        user = user_factory()
        revision = 0  # user_factory's explicit/default initial revision
        address = "new@example.org"
        first = email_change.generate_email_change_token(
            user.id,
            address,
            auth_revision=revision,
            acting_admin_id=99,
        )
        await email_change.store_pending_email(
            db_pool,
            user.id,
            address,
            hash_token(first),
            expected_auth_revision=revision,
        )
        second = email_change.generate_email_change_token(
            user.id,
            address,
            auth_revision=revision,
            acting_admin_id=99,
        )
        await email_change.store_pending_email(
            db_pool,
            user.id,
            address,
            hash_token(second),
            expected_auth_revision=revision,
        )
        assert not await email_change.confirm_email_change(
            db_pool,
            user.id,
            address,
            first,
            expected_auth_revision=revision,
        )
        assert await email_change.confirm_email_change(
            db_pool,
            user.id,
            address,
            second,
            expected_auth_revision=revision,
        )
        assert not await email_change.confirm_email_change(
            db_pool,
            user.id,
            address,
            second,
            expected_auth_revision=revision,
        )

    async def test_consumed_reset_token_cannot_reactivate_on_same_second_reissue(
        self, db_pool, user_factory, _frozen_token_clock, monkeypatch
    ):
        """Verify consumed reset token cannot reactivate on same second reissue."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        first = password_reset.generate_reset_token(user.id, user.email)
        await password_reset.store_reset_token_hash(
            db_pool, user.id, hash_token(first), expected_email=user.email
        )
        await password_reset.update_password_with_token(
            db_pool,
            user.id,
            first,
            "Cobalt-Forests-739!Rain",
            expected_email=user.email,
            totp_code=pyotp.TOTP(secret).at(_TOTP_TIME),
        )
        second = password_reset.generate_reset_token(user.id, user.email)
        await password_reset.store_reset_token_hash(
            db_pool, user.id, hash_token(second), expected_email=user.email
        )
        assert not await password_reset.verify_reset_token_hash(
            db_pool, user.id, hash_token(first), expected_email=user.email
        )
        assert await password_reset.verify_reset_token_hash(
            db_pool, user.id, hash_token(second), expected_email=user.email
        )
        monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME + 30))
        with pytest.raises(ValueError, match="reset token"):
            await password_reset.update_password_with_token(
                db_pool,
                user.id,
                first,
                "Violet-Mountains-827!Snow",
                expected_email=user.email,
                totp_code=pyotp.TOTP(secret).at(_TOTP_TIME + 30),
            )
        await password_reset.update_password_with_token(
            db_pool,
            user.id,
            second,
            "Violet-Mountains-827!Snow",
            expected_email=user.email,
            totp_code=pyotp.TOTP(secret).at(_TOTP_TIME + 30),
        )
        assert not await password_reset.verify_reset_token_hash(
            db_pool, user.id, hash_token(second), expected_email=user.email
        )


class TestRevisionChangeFencesPendingEmail:
    """Any operation that bumps ``auth_revision`` (an admin unlock, a TOTP
    enrollment, or a TOTP rotation) must cancel a pending admin-initiated
    email change and fence delivery of its verification email, whether that
    email is still queued or was already claimed by a delivery worker before
    the revision changed."""

    @pytest.mark.parametrize("transition", ["unlock", "enroll", "rotate"])
    @pytest.mark.parametrize(
        "claimed",
        [pytest.param(True, id="claimed-by-worker"), pytest.param(False, id="still-queued")],
    )
    async def test_revision_change_cancels_pending_email_and_fences_claimed_delivery(
        self,
        db_pool,
        sync_conn,
        user_factory,
        session_factory,
        admin_actor,
        transition,
        claimed,
    ):
        """Verify revision change cancels pending email and fences claimed delivery."""
        old_secret = pyotp.random_base32()

        user = user_factory(
            totp_secret=encrypt_value(old_secret) if transition == "rotate" else None
        )
        await email_change.stage_admin_email_change(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=user.id,
            new_email="new-address@example.org",
        )
        messages = (
            await email_outbox.claim_due_emails(
                db_pool, limit=10, lease_timeout=timedelta(minutes=5)
            )
            if claimed
            else []
        )
        if transition == "unlock":
            await users.set_user_active(
                db_pool,
                user.id,
                True,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )
        elif transition == "enroll":
            session = session_factory(user.id, purpose="totp_setup")
            pending = await totp.get_or_create_pending_totp_secret(
                db_pool,
                user.id,
                purpose=totp.PendingTotpPurpose.ENROLLMENT,
                session_id=session,
            )
            assert pending.outcome is totp.PendingTotpOutcome.READY
            assert pending.secret is not None
            new_secret = pending.secret
            recovery_code = pending.recovery_codes[0]
            # This module's autouse `_fixed_totp_clock` freezes the
            # production step clock at `_TOTP_TIME`, so the code proved
            # here must be generated `.at()` that same instant, not
            # `.now()` (real wall-clock time), or the codes fall in
            # different steps and every fresh-auth call below rejects
            # them as invalid credentials.
            assert (
                await totp.verify_and_enroll_totp(
                    db_pool,
                    user.id,
                    pyotp.TOTP(new_secret).at(_TOTP_TIME),
                    recovery_code,
                    session_id=session,
                )
                is totp.TotpEnrollmentOutcome.ENROLLED
            )
        else:
            # Rotation is a fresh-auth two-step challenge on the target
            # user's OWN full session (not the admin actor's session,
            # which only authorized the pending email change above).
            rotation_session = session_factory(user.id, purpose="full")
            start = await totp.begin_totp_rotation(
                db_pool,
                user.id,
                DEFAULT_PASSWORD,
                pyotp.TOTP(old_secret).at(_TOTP_TIME),
                session_id=rotation_session,
            )
            assert start.outcome is totp.TotpRotationStartOutcome.READY
            assert (
                await totp.confirm_totp_rotation(
                    db_pool,
                    user.id,
                    pyotp.TOTP(start.secret).at(_TOTP_TIME),
                    session_id=rotation_session,
                )
                is totp.TotpRotationOutcome.ROTATED
            )
        assert sync_conn.execute(
            "SELECT pending_email, pending_email_token_hash, pending_email_created_at "
            "FROM users WHERE id=%s",
            (user.id,),
        ).fetchone() == (None, None, None)
        if claimed:
            for message in messages:
                if message.message_type == "email_change_verification":
                    assert not await email_outbox.prepare_email_delivery(
                        db_pool,
                        message,
                        lease_timeout=timedelta(minutes=5),
                        min_remaining_lifetime=timedelta(0),
                    )
        else:
            assert sync_conn.execute(
                "SELECT status FROM email_outbox WHERE message_type='email_change_verification'"
            ).fetchone() == ("dead",)


async def _complete_expiring_case(db_pool, case):
    """Attempt the case's action; return False for an invalid reset token."""
    if case.operation == "password_reset":
        try:
            await password_reset.update_password_with_token(
                db_pool,
                case.user.id,
                case.token,
                _NEW_PASSWORD,
                expected_email=case.user.email,
                totp_code=case.reset_code,
            )
        except password_reset.InvalidResetToken:
            return False
        return True
    return await email_change.confirm_email_change(
        db_pool,
        case.user.id,
        case.new_email,
        case.token,
        expected_auth_revision=0,
    )


async def _wait_for_expiry(observer, expires_at):
    """Poll database wall time until capability expiry; raise TimeoutError at the race deadline."""
    deadline = asyncio.get_running_loop().time() + _RACE_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        cur = await observer.execute("SELECT clock_timestamp() >= %s", (expires_at,))
        row = await cur.fetchone()
        if row is not None and row[0]:
            return
        await asyncio.sleep(_POLL_INTERVAL)
    raise TimeoutError("Database capability did not expire before the test deadline")


@pytest.mark.parametrize("operation", ["password_reset", "email_change"])
@pytest.mark.parametrize("expiry", ["signature", "persisted"])
async def test_action_expiry_is_rechecked_after_waiting_for_user_lock(
    db_pool,
    user_factory,
    session_factory,
    sync_conn,
    monkeypatch,
    race_observer,
    operation,
    expiry,
):
    """A valid capability becomes expired while the mutation waits behind a real row lock."""
    clock = [int(datetime.now(UTC).timestamp())]
    monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda _self: clock[0])
    case = await _make_case(db_pool, user_factory, operation)
    session_factory(case.user.id)
    expires_at = None
    if expiry == "persisted":
        column = (
            "password_reset_created_at"
            if operation == "password_reset"
            else "pending_email_created_at"
        )
        age = case.module._ACTION_TOKEN.max_age
        # The capability is valid when B starts; only wall-clock passage expires it.
        row = sync_conn.execute(
            psycopg.sql.SQL(
                "UPDATE users SET {column} = clock_timestamp() - %s * INTERVAL '1 second' "
                "+ INTERVAL '2 seconds' WHERE id = %s "
                "RETURNING {column} + %s * INTERVAL '1 second'"
            ).format(column=psycopg.sql.Identifier(column)),
            (age, case.user.id, age),
        ).fetchone()
        assert row is not None
        expires_at = row[0]
        sync_conn.commit()
    before = _state(sync_conn, case.user.id)
    active = _track_connections(monkeypatch)
    follower = None
    try:
        async with asyncio.timeout(_RACE_TIMEOUT):
            async with db_pool.connection() as blocker:
                await blocker.execute(
                    "SELECT id FROM users WHERE id = %s FOR UPDATE", (case.user.id,)
                )
                follower = asyncio.create_task(_complete_expiring_case(db_pool, case))
                await _wait_for_database_block(
                    race_observer, active, follower, blocker.info.backend_pid
                )
                if expiry == "signature":
                    clock[0] += case.module._ACTION_TOKEN.max_age + 1
                else:
                    assert expires_at is not None
                    await _wait_for_expiry(race_observer, expires_at)
            assert await follower is False
    finally:
        if follower is not None:
            if not follower.done():
                follower.cancel()
            async with asyncio.timeout(_CLEANUP_TIMEOUT):
                await asyncio.gather(follower, return_exceptions=True)
    assert _state(sync_conn, case.user.id) == before
    assert _session_count(sync_conn, case.user.id) == 1
