"""Persisted account deadlines use PostgreSQL wall time after actual lock waits."""

import asyncio
from datetime import datetime, timedelta

import psycopg
import pyotp
import pytest

from app.services import authentication, totp
from app.services.db import get_db_cursor
from app.services.email import build_account_locked_notice
from app.services.session_ids import hash_session_id
from tests.integration.conftest import TEST_DATABASE_URL


async def _wait_for_blocked_task(observer, task, blocker_pid):
    """Prove the service reached a row lock before allowing the deadline to pass."""
    async with asyncio.timeout(5):
        while True:
            if task.done():
                task.result()
                pytest.fail("operation completed before the row lock was released")
            cur = await observer.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                "WHERE %s = ANY(pg_blocking_pids(pid)))",
                (blocker_pid,),
            )
            if (await cur.fetchone())[0]:
                return
            await asyncio.sleep(0.01)


async def _pending_operation(operation, pool, user_id, session_id, pending):
    """Display, issue or verify the session-bound enrollment challenge for this case."""
    if operation == "display":
        return await totp.get_pending_totp_secret(
            pool, user_id, session_id=session_id, purpose=totp.PendingTotpPurpose.ENROLLMENT
        )
    if operation == "issue":
        return await totp.get_or_create_pending_totp_secret(
            pool, user_id, session_id=session_id, purpose=totp.PendingTotpPurpose.ENROLLMENT
        )
    return await totp.verify_and_enroll_totp(
        pool,
        user_id,
        pyotp.TOTP(pending.secret).now(),
        pending.recovery_codes[0],
        session_id=session_id,
    )


@pytest.mark.parametrize("lock_target", ["user", "session"])
@pytest.mark.parametrize("operation", ["display", "issue", "enroll"])
async def test_pending_deadline_is_checked_after_row_lock_wait(
    db_pool, sync_conn, user_factory, session_factory, monkeypatch, lock_target, operation
):
    """Verify pending deadline is checked after row lock wait."""
    user = user_factory()
    session_id = session_factory(user.id, purpose="totp_setup")
    pending = await _pending_operation("issue", db_pool, user.id, session_id, None)
    monkeypatch.setattr(totp, "_PENDING_TOTP_MAX_AGE_SECONDS", 1)
    sync_conn.execute(
        "UPDATE users SET pending_totp_created_at = clock_timestamp() WHERE id = %s",
        (user.id,),
    )
    sync_conn.commit()
    async with (
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as blocker,
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, autocommit=True) as observer,
    ):
        if lock_target == "user":
            await blocker.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user.id,))
        else:
            await blocker.execute(
                "SELECT id FROM sessions WHERE id = %s FOR UPDATE", (hash_session_id(session_id),)
            )
        task = asyncio.create_task(
            _pending_operation(operation, db_pool, user.id, session_id, pending)
        )
        try:
            await _wait_for_blocked_task(observer, task, blocker.info.backend_pid)
            # Database elapsed time, independent of Python's wall clock.
            await observer.execute(
                "SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM "
                "(pending_totp_created_at + INTERVAL '1 second' - clock_timestamp())), 0) + 0.05) "
                "FROM users WHERE id = %s",
                (user.id,),
            )
            released_at = (await (await observer.execute("SELECT clock_timestamp()")).fetchone())[0]
            await blocker.commit()
            async with asyncio.timeout(5):
                result = await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    if operation == "display":
        assert result is None
    elif operation == "enroll":
        assert result is totp.TotpEnrollmentOutcome.PENDING_SECRET_MISSING
    else:
        assert result.outcome is totp.PendingTotpOutcome.READY
        assert result.secret != pending.secret
        issued_at = sync_conn.execute(
            "SELECT pending_totp_created_at FROM users WHERE id = %s", (user.id,)
        ).fetchone()[0]
        assert issued_at >= released_at, "the full TTL must start after the lock wait"
        assert (
            await _pending_operation("display", db_pool, user.id, session_id, result)
            == result.secret
        )


async def test_session_expiry_is_checked_after_its_lock_wait(
    db_pool, sync_conn, user_factory, session_factory
):
    """Verify session expiry is checked after its lock wait."""
    user = user_factory()
    session_id = session_factory(user.id, purpose="totp_setup")
    pending = await _pending_operation("issue", db_pool, user.id, session_id, None)
    sync_conn.execute(
        "UPDATE sessions SET expires_at = clock_timestamp() + INTERVAL '1 second' WHERE id = %s",
        (hash_session_id(session_id),),
    )
    sync_conn.commit()
    async with (
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as blocker,
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, autocommit=True) as observer,
    ):
        await blocker.execute(
            "SELECT id FROM sessions WHERE id = %s FOR UPDATE", (hash_session_id(session_id),)
        )
        task = asyncio.create_task(
            _pending_operation("issue", db_pool, user.id, session_id, pending)
        )
        try:
            await _wait_for_blocked_task(observer, task, blocker.info.backend_pid)
            await observer.execute(
                "SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM (expires_at - clock_timestamp())), 0) + 0.05) "
                "FROM sessions WHERE id = %s",
                (hash_session_id(session_id),),
            )
            await blocker.commit()
            async with asyncio.timeout(5):
                result = await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert result.outcome is totp.PendingTotpOutcome.SESSION_EXPIRED


@pytest.mark.parametrize("offset_days", [-2, 2])
async def test_pending_and_lockout_deadlines_ignore_python_wall_clock_skew(
    db_pool, sync_conn, user_factory, session_factory, monkeypatch, offset_days
):
    """Verify pending and lockout deadlines ignore python wall clock skew."""
    user = user_factory()
    session_id = session_factory(user.id, purpose="totp_setup")
    pending = await _pending_operation("issue", db_pool, user.id, session_id, None)

    class SkewedDatetime(datetime):
        """Clock double shifted by the parametrized day offset."""

        @classmethod
        def now(cls, tz=None):
            """Return current wall time shifted by the parametrized number of days."""
            return datetime.now(tz) + timedelta(days=offset_days)

    monkeypatch.setattr(totp, "datetime", SkewedDatetime)
    monkeypatch.setattr(authentication, "datetime", SkewedDatetime)
    assert (
        await _pending_operation("enroll", db_pool, user.id, session_id, pending)
        is totp.TotpEnrollmentOutcome.ENROLLED
    )

    sync_conn.execute(
        "UPDATE users SET locked_until = clock_timestamp() + INTERVAL '1 hour' WHERE id = %s",
        (user.id,),
    )
    sync_conn.commit()
    check = await authentication.verify_password(db_pool, user.email, user.password)
    assert check.failure_reason == "account_locked"
    revision = sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s", (user.id,)
    ).fetchone()[0]
    result = await authentication.finalize_local_login(
        db_pool,
        user_id=user.id,
        expected_auth_revision=revision,
        totp_code="",
        ip_address="127.0.0.1",
    )
    assert result.reason == "account_locked"

    # A lock that has already expired must not be extended by a slow application clock.
    sync_conn.execute(
        "UPDATE users SET locked_until = clock_timestamp() - INTERVAL '1 hour' WHERE id = %s",
        (user.id,),
    )
    sync_conn.commit()
    check = await authentication.verify_password(db_pool, user.email, user.password)
    assert check.password_ok
    assert check.locked_until is None


async def test_login_lockout_expiry_is_checked_after_user_lock_wait(
    db_pool, sync_conn, user_factory
):
    """Verify login lockout expiry is checked after user lock wait."""
    user = user_factory()
    sync_conn.execute(
        "UPDATE users SET locked_until = clock_timestamp() + INTERVAL '1 second' WHERE id = %s",
        (user.id,),
    )
    revision = sync_conn.execute(
        "SELECT auth_revision FROM users WHERE id = %s", (user.id,)
    ).fetchone()[0]
    sync_conn.commit()
    async with (
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as blocker,
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, autocommit=True) as observer,
    ):
        await blocker.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user.id,))
        task = asyncio.create_task(
            authentication.finalize_local_login(
                db_pool,
                user_id=user.id,
                expected_auth_revision=revision,
                totp_code="",
                ip_address="127.0.0.1",
            )
        )
        try:
            await _wait_for_blocked_task(observer, task, blocker.info.backend_pid)
            await observer.execute(
                "SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM (locked_until - clock_timestamp())), 0) + 0.05) "
                "FROM users WHERE id = %s",
                (user.id,),
            )
            await blocker.commit()
            async with asyncio.timeout(5):
                result = await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert isinstance(result, authentication.LocalLoginSuccess)


async def test_notice_claim_uses_wall_time_within_an_older_transaction(db_pool, user_factory):
    """Verify notice claim uses wall time within an older transaction."""
    user = user_factory()
    async with get_db_cursor(db_pool) as cur:
        await cur.execute("SELECT auth_revision FROM users WHERE id = %s FOR UPDATE", (user.id,))
        revision = (await cur.fetchone())["auth_revision"]
        # Expired according to wall time, but still in the future relative to
        # transaction start: CURRENT_TIMESTAMP would incorrectly claim it.
        await cur.execute("SELECT pg_sleep(0.03)")
        await cur.execute(
            "UPDATE users SET locked_until = clock_timestamp() - INTERVAL '0.01 second' WHERE id = %s",
            (user.id,),
        )
        assert not await authentication.queue_lockout_notice_cur(
            cur,
            user_id=user.id,
            expected_auth_revision=revision,
            email=build_account_locked_notice(user.email),
        )
        await cur.execute(
            "SELECT count(*) AS notices FROM email_outbox WHERE user_id = %s", (user.id,)
        )
        assert (await cur.fetchone())["notices"] == 0
