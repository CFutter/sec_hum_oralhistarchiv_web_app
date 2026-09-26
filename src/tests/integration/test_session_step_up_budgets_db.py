"""``app.services.credential_attempts`` against the real PostgreSQL schema.

``reserve_session_step_up_attempt`` binds a small, shared attempt budget to
the exact full session that is proving a password, TOTP code, or other
sensitive credential during a step-up flow (admin promotion, email change,
TOTP setup and recovery all reserve through it). These tests pin the durable
serialization point which cannot be proved with mock cursors: one quota per
exact active full session, and the deliberate lock order — session row
before challenge/session cascade deletes — that keeps exhaustion and
account-wide revocation from deadlocking each other. The integration
conftest applies the application's Alembic migration and skips this module
when the configured test database is unavailable.
"""

import asyncio
from unittest.mock import create_autospec

import psycopg
import pyotp
import pytest

from app.services import session_revocation
from app.services.admin_promotion import AdminPromotionRejected, prepare_admin_promotion
from app.services.credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from app.services.crypto import encrypt_value
from app.services.db import get_db_cursor
from app.services.email_change import SelfEmailChangeRejected, stage_self_email_change
from app.services.session_ids import hash_session_id
from app.services.session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from app.services.totp import TotpRotationStartOutcome, begin_totp_rotation
from app.services.totp_recover import TotpRecoveryRejected, authorize_totp_recovery
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def _session_state(sync_conn, raw_session_id: str) -> tuple[int, bool] | None:
    return sync_conn.execute(
        """
        SELECT step_up_attempt_count,
               expires_at > clock_timestamp() AS active
        FROM sessions
        WHERE id = %s
        """,
        (hash_session_id(raw_session_id),),
    ).fetchone()


def _credential_snapshot(sync_conn, user_id: int):
    """Every column a step-up reservation must never touch, win or lose."""
    row = sync_conn.execute(
        """
        SELECT password_hash, totp_secret, auth_revision,
               failed_login_count, locked_until
        FROM users
        WHERE id = %s
        """,
        (user_id,),
    ).fetchone()
    assert row is not None
    return row


def _user_login_lock_state(sync_conn, user_id: int):
    return sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()


async def _backend_pid(conn: psycopg.AsyncConnection) -> int:
    cursor = await conn.execute("SELECT pg_backend_pid()")
    row = await cursor.fetchone()
    await conn.commit()
    assert row is not None
    return row[0]


async def _reserve_session_on_independent_connection(
    *,
    user_id: int,
    session_id: str,
    barrier: asyncio.Barrier,
):
    async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn:
        backend_pid = await _backend_pid(conn)
        await barrier.wait()
        outcome = await reserve_session_step_up_attempt(
            conn,  # type: ignore[arg-type] - exercises the supported direct-connection path
            user_id=user_id,
            session_id=session_id,
        )
        return outcome, backend_pid


class TestSessionStepUpReservation:
    """One shared budget per exact active full session, serialized on its row."""

    async def test_exhausting_the_session_budget_expires_only_that_session(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """N reservations succeed; N+1 revokes no account or sibling session."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 2)
        user = user_factory(failed_login_count=4, locked_until=None)
        exhausted_session = session_factory(user.id, purpose="full")
        sibling_session = session_factory(user.id, purpose="full")
        before_lock_state = _user_login_lock_state(sync_conn, user.id)

        first = await reserve_session_step_up_attempt(
            db_pool,
            user_id=user.id,
            session_id=exhausted_session,
        )
        second = await reserve_session_step_up_attempt(
            db_pool,
            user_id=user.id,
            session_id=exhausted_session,
        )
        exhausted = await reserve_session_step_up_attempt(
            db_pool,
            user_id=user.id,
            session_id=exhausted_session,
        )

        assert first is SessionStepUpAttemptOutcome.RESERVED
        assert second is SessionStepUpAttemptOutcome.RESERVED
        assert exhausted is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED
        assert _session_state(sync_conn, exhausted_session) == (2, False)
        assert _session_state(sync_conn, sibling_session) == (0, True)
        assert _user_login_lock_state(sync_conn, user.id) == before_lock_state

    async def test_concurrent_reservations_cannot_cross_the_limit(
        self,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """The session row serializes reservations across workers and requests."""
        limit = 3
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", limit)
        user = user_factory(failed_login_count=2, locked_until=None)
        raw_session = session_factory(user.id, purpose="full")
        sibling_session = session_factory(user.id, purpose="full")
        before_lock_state = _user_login_lock_state(sync_conn, user.id)

        caller_count = limit + 5
        barrier = asyncio.Barrier(caller_count)
        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    _reserve_session_on_independent_connection(
                        user_id=user.id,
                        session_id=raw_session,
                        barrier=barrier,
                    )
                    for _ in range(caller_count)
                )
            ),
            timeout=10,
        )
        outcomes = [outcome for outcome, _backend in results]
        backend_pids = [backend for _outcome, backend in results]

        assert len(set(backend_pids)) == caller_count
        assert outcomes.count(SessionStepUpAttemptOutcome.RESERVED) == limit
        assert outcomes.count(SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED) == 1
        assert outcomes.count(SessionStepUpAttemptOutcome.INVALID_SESSION) == 4
        assert _session_state(sync_conn, raw_session) == (limit, False)
        assert _session_state(sync_conn, sibling_session) == (0, True)
        assert _user_login_lock_state(sync_conn, user.id) == before_lock_state


class TestSessionStepUpRevocationLockOrder:
    """Exhaustion and account-wide revocation never invert the session-first lock order.

    ``pending_totp_rotations`` and ``sessions`` both carry an ON DELETE
    CASCADE-linked challenge row to the session; locking the session before
    deleting or invalidating that challenge (never the reverse) is what keeps
    a concurrent exhaustion and a concurrent revocation from deadlocking.
    """

    async def test_session_budget_expiry_does_not_invert_revocation_lock_order(
        self,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Exhaustion and user-wide revocation complete without a challenge/FK deadlock."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 1)
        user = user_factory(totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
        raw_session = session_factory(user.id, purpose="full")
        session_hash = hash_session_id(raw_session)
        sync_conn.execute(
            "UPDATE sessions SET step_up_attempt_count = 1 WHERE id = %s",
            (session_hash,),
        )
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations (
                user_id, session_id, auth_revision, encrypted_secret, expires_at
            )
            VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')
            """,
            (user.id, session_hash, encrypt_value("KRSXG5DSNFXGOIDB")),
        )
        sync_conn.commit()

        session_locked = asyncio.Event()
        challenge_deleted = asyncio.Event()

        async def exhaust_exact_session():
            async with (
                await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn,
                conn.transaction(),
            ):
                cursor = await conn.execute(
                    "SELECT 1 FROM sessions WHERE id = %s FOR UPDATE",
                    (session_hash,),
                )
                assert await cursor.fetchone() is not None
                session_locked.set()
                await challenge_deleted.wait()
                return await reserve_session_step_up_attempt(
                    conn,  # type: ignore[arg-type] - supported direct-connection path
                    user_id=user.id,
                    session_id=raw_session,
                )

        async def revoke_user_state():
            await session_locked.wait()
            async with (
                await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn,
                get_db_cursor(conn) as cur,
            ):
                await invalidate_pending_authentication_state_cur(cur, user.id)
                challenge_deleted.set()
                await delete_user_sessions_cur(cur, user.id)

        outcome, _ = await asyncio.wait_for(
            asyncio.gather(exhaust_exact_session(), revoke_user_state()),
            timeout=10,
        )

        assert outcome is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED
        assert _session_state(sync_conn, raw_session) is None
        assert (
            sync_conn.execute(
                "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s",
                (user.id,),
            ).fetchone()
            is None
        )

    async def test_user_revocation_uses_session_first_order_against_logout(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
    ):
        """Logout cascade and revoke-all serialize without a session/challenge cycle."""
        user = user_factory(totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
        raw_session = session_factory(user.id, purpose="full")
        session_hash = hash_session_id(raw_session)
        sync_conn.execute(
            """
            INSERT INTO pending_totp_rotations (
                user_id, session_id, auth_revision, encrypted_secret, expires_at
            )
            VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')
            """,
            (user.id, session_hash, encrypt_value("KRSXG5DSNFXGOIDB")),
        )
        sync_conn.commit()

        logout_locked_session = asyncio.Event()
        revocation_reached_session_delete = asyncio.Event()
        real_delete = session_revocation.delete_user_sessions_cur

        async def observed_delete(cur, user_id):
            revocation_reached_session_delete.set()
            await real_delete(cur, user_id)

        # autospecced against delete_user_sessions_cur's real signature so a
        # future parameter it gains would raise here rather than silently
        # stop being exercised by this spy.
        autospecced_delete = create_autospec(
            session_revocation.delete_user_sessions_cur,
            spec_set=True,
            side_effect=observed_delete,
        )
        monkeypatch.setattr(session_revocation, "delete_user_sessions_cur", autospecced_delete)

        async def logout_exact_session():
            async with (
                await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as conn,
                conn.transaction(),
            ):
                cursor = await conn.execute(
                    "SELECT 1 FROM sessions WHERE id = %s FOR UPDATE",
                    (session_hash,),
                )
                assert await cursor.fetchone() is not None
                logout_locked_session.set()
                await revocation_reached_session_delete.wait()
                await conn.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))

        async def revoke_every_session():
            await logout_locked_session.wait()
            await session_revocation.delete_user_sessions(db_pool, user.id)

        await asyncio.wait_for(
            asyncio.gather(logout_exact_session(), revoke_every_session()),
            timeout=10,
        )

        assert _session_state(sync_conn, raw_session) is None
        assert (
            sync_conn.execute(
                "SELECT 1 FROM pending_totp_rotations WHERE user_id = %s",
                (user.id,),
            ).fetchone()
            is None
        )


class TestSessionStepUpExhaustionIsolatesCredentialState:
    """A reservation, win or lose, never touches a credential or lockout column."""

    async def test_exhaustion_leaves_credential_and_lockout_state_untouched(
        self, db_pool, user_factory, session_factory, sync_conn, monkeypatch
    ):
        """Exhausting a session's budget expires only that session row."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 1)
        user = user_factory(
            totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"),
            failed_login_count=2,
            locked_until=None,
        )
        exhausted_session = session_factory(user.id, purpose="full")
        before = _credential_snapshot(sync_conn, user.id)

        reserved = await reserve_session_step_up_attempt(
            db_pool, user_id=user.id, session_id=exhausted_session
        )
        exhausted = await reserve_session_step_up_attempt(
            db_pool, user_id=user.id, session_id=exhausted_session
        )

        assert reserved is SessionStepUpAttemptOutcome.RESERVED
        assert exhausted is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED
        assert _credential_snapshot(sync_conn, user.id) == before

    async def test_reservation_within_the_limit_also_leaves_credential_state_untouched(
        self, db_pool, user_factory, session_factory, sync_conn, monkeypatch
    ):
        """POSITIVE CONTROL: an ordinary, successful reservation is equally
        inert on every credential and lockout column."""
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", 2)
        user = user_factory(totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
        raw_session = session_factory(user.id, purpose="full")
        before = _credential_snapshot(sync_conn, user.id)

        reserved = await reserve_session_step_up_attempt(
            db_pool, user_id=user.id, session_id=raw_session
        )

        assert reserved is SessionStepUpAttemptOutcome.RESERVED
        assert _credential_snapshot(sync_conn, user.id) == before


class TestSharedBudgetAcrossProtectedStepUpServices:
    """Every protected step-up entry point draws from the same session counter.

    Rotation start, self-service email change, admin-promotion preparation
    and admin-authorized recovery all call
    ``reserve_session_step_up_attempt`` before any of their own domain
    checks (each reads its own production module to confirm this ordering).
    Alternating submissions among them must still share one counter and one
    exhaustion point for the exact session making them.
    """

    async def test_alternating_submissions_across_services_share_one_counter(
        self,
        db_pool,
        user_factory,
        session_factory,
        sync_conn,
        monkeypatch,
        admin_actor,
    ):
        limit = 4
        monkeypatch.setattr(settings, "session_step_up_attempt_limit", limit)
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        raw_session = session_factory(user.id, purpose="full")
        sibling_session = session_factory(user.id, purpose="full")

        async def submit_rotation_start():
            result = await begin_totp_rotation(
                db_pool,
                user.id,
                "wrong-password",
                "000000",
                session_id=raw_session,
            )
            assert result.outcome is TotpRotationStartOutcome.INVALID_CREDENTIALS

        async def submit_email_change():
            with pytest.raises(SelfEmailChangeRejected):
                await stage_self_email_change(
                    db_pool,
                    user_id=user.id,
                    session_id=raw_session,
                    current_password="wrong-password",
                    new_email="someone-else@example.org",
                )

        async def submit_promotion_prepare():
            with pytest.raises(AdminPromotionRejected) as excinfo:
                await prepare_admin_promotion(
                    db_pool,
                    user_id=user.id,
                    session_id=raw_session,
                    password="wrong-password",
                    totp_code="not-a-code",
                )
            assert excinfo.value.args[0] == "invalid_totp"

        async def submit_admin_recovery_authorization():
            with pytest.raises(TotpRecoveryRejected):
                await authorize_totp_recovery(
                    db_pool,
                    actor_id=user.id,
                    actor_session_id=raw_session,
                    target_user_id=admin_actor.id,
                    admin_totp_code="not-a-code",
                )

        submissions = [
            submit_rotation_start,
            submit_email_change,
            submit_promotion_prepare,
            submit_admin_recovery_authorization,
        ]
        for index in range(limit):
            await submissions[index % len(submissions)]()
            assert _session_state(sync_conn, raw_session) == (index + 1, True)

        # The first excess submission, from any of the services, expires only
        # the exact session making it.
        with pytest.raises(AdminPromotionRejected) as excess:
            await prepare_admin_promotion(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                password="wrong-password",
                totp_code="not-a-code",
            )
        assert excess.value.args[0] == "step_up_exhausted"
        assert _session_state(sync_conn, raw_session) == (limit, False)
        assert _session_state(sync_conn, sibling_session) == (0, True)
