"""Integration tests: user CRUD + TOTP persistence against real PostgreSQL.

Pins the database behaviors the unit tier mocks away: the LOWER(email)
unique index, UPDATE ... RETURNING existence checks, the asymmetric
set_user_active counter handling, the SQL-side lockout threshold CASE,
the last_totp_step replay guard, pending-TOTP TTL/promotion, and the
fail-closed handling of undecryptable TOTP secrets. It also exercises the
row-locked concurrent-write behavior of update_access_tier.

The session-bound TOTP rotation protocol (begin_totp_rotation /
confirm_totp_rotation) has its own module: test_totp_rotation_db.py.
"""

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from unittest.mock import patch

import psycopg
import pyotp
import pytest
import time_machine

from app.services import registration
from app.services.authentication import (
    record_login_failure,
)
from app.services.crypto import decrypt_value, encrypt_value
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    TotpDecryptionError,
    TotpEnrollmentOutcome,
    get_or_create_pending_totp_secret,
    get_pending_totp_secret,
    get_totp_secret,
    matched_step,
    verify_and_consume_totp,
    verify_and_enroll_totp,
)
from app.services.users import (
    SetActiveResult,
    UserAlreadyExistsError,
    get_user_by_email,
    get_user_by_id,
    reap_unverified_accounts,
    set_user_active,
    update_access_tier,
    update_display_name,
)
from tests.account_setup import create_local_user, store_pending_totp_secret
from tests.integration.conftest import TEST_DATABASE_URL


def _fetch_user_row(sync_conn, user_id, columns):
    """Read raw column values for asserts (bypasses the app's SELECT builder)."""
    row = sync_conn.execute(
        f"SELECT {', '.join(columns)} FROM users WHERE id = %s", (user_id,)
    ).fetchone()
    assert row is not None, f"user {user_id} missing"
    return dict(zip(columns, row, strict=False))


async def _wait_until_blocked_by(observer, leader_pid):
    """Poll ``pg_blocking_pids`` instead of sleeping: proves the wait, not the delay."""
    while True:
        cur = await observer.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE %s = ANY(pg_blocking_pids(pid)))",
            (leader_pid,),
        )
        row = await cur.fetchone()
        if row and row[0]:
            return
        await asyncio.sleep(0.02)


class TestLocalUserCreation:
    """create_local_user inserts a public-tier, authenticator-free account."""

    async def test_create_local_user_normalizes_email_and_defaults(self, db_pool, sync_conn):
        """create_local_user strips/lowercases the email before INSERT and the
        returned User starts with totp_configured=False and tier 'public'
        (creation can never elevate — the INSERT hardcodes 'public')."""
        user = await create_local_user(
            db_pool, email=" Alice@UZH.ch ", display_name="Alice", password="s3cret-Pw!"
        )
        assert user.email == "alice@uzh.ch"
        assert user.totp_configured is False
        assert user.access_tier == "public"
        assert user.auth_method == "local"

        stored = _fetch_user_row(sync_conn, user.id, ["email", "access_tier"])
        assert stored["email"] == "alice@uzh.ch"
        assert stored["access_tier"] == "public"

    async def test_create_local_user_duplicate_email_case_insensitive(self, db_pool, user_factory):
        """The LOWER(email) unique index rejects a duplicate that differs only in
        case: the UniqueViolation is translated to UserAlreadyExistsError
        end-to-end (not a raw psycopg error leaking to the route)."""
        user_factory(email="alice@uzh.ch")
        with pytest.raises(UserAlreadyExistsError) as exc_info:
            await create_local_user(
                db_pool, email="ALICE@uzh.ch", display_name="Impostor", password="s3cret-Pw!"
            )
        # The error carries the normalized (lowercased) email.
        assert exc_info.value.email == "alice@uzh.ch"

    async def test_new_local_account_has_no_active_pending_or_consumed_totp(
        self, db_pool, sync_conn
    ):
        """POSITIVE CONTROL for the pending/active TOTP columns exercised
        elsewhere: the raw INSERT that create_local_user issues leaves every
        authenticator column unset, so a fresh account starts with no second
        factor configured, staged, or replayed."""
        user = await create_local_user(
            db_pool,
            email="new-person@example.org",
            display_name="New Person",
            password="Unrelated-CorrectHorse-4829!",
        )
        assert user.totp_configured is False
        assert sync_conn.execute(
            "SELECT totp_secret, pending_totp_secret, pending_totp_created_at, last_totp_step "
            "FROM users WHERE id = %s",
            (user.id,),
        ).fetchone() == (None, None, None, None)


class TestRegistrationTransaction:
    """register_local_user commits the account row and its verification email
    enqueue as one transaction: either both land, or neither does."""

    async def test_registration_enqueue_failure_rolls_back_account_and_can_retry(
        self, db_pool, sync_conn
    ):
        """If enqueueing the verification email raises, the transaction rolls
        back the whole INSERT with it — no orphaned account survives with no
        way to receive a verification link. A retry with the same email then
        succeeds normally, proving the failed attempt left nothing behind to
        collide with it."""
        kwargs = {
            "email": "  AUDIT@UZH.CH  ",
            "display_name": "New Person",
            "password": "Vm8!qZ2#rL7@pX9$",
        }
        with (
            patch.object(
                registration,
                "enqueue_outbound_email_cur",
                autospec=True,
                side_effect=RuntimeError("queue failed"),
            ),
            pytest.raises(RuntimeError, match="queue failed"),
        ):
            await registration.register_local_user(db_pool, **kwargs)
        assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
        sync_conn.commit()
        user = await registration.register_local_user(db_pool, **kwargs)
        assert user.email == "audit@uzh.ch"
        assert sync_conn.execute(
            "SELECT email_verification_token_hash IS NOT NULL FROM users WHERE id=%s", (user.id,)
        ).fetchone()[0]
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM email_outbox WHERE user_id=%s", (user.id,)
            ).fetchone()[0]
            == 1
        )


class TestDisplayNameAndAccessTierUpdates:
    """update_display_name / update_access_tier: existence checks and the
    row-locked concurrent-write ordering of the returned (old, new) pair."""

    async def test_update_display_name_persists(self, db_pool, user_factory, sync_conn):
        """update_display_name writes the normalized name to the real row."""
        handle = user_factory()
        await update_display_name(db_pool, handle.id, "  New Name  ")
        stored = _fetch_user_row(sync_conn, handle.id, ["display_name"])
        assert stored["display_name"] == "New Name"

    async def test_update_display_name_unknown_user_raises(self, db_pool):
        """UPDATE ... RETURNING id on a missing user yields no row -> ValueError
        (guards the existence check the unit tier only mocks)."""
        with pytest.raises(ValueError, match="not found"):
            await update_display_name(db_pool, 999_999, "Ghost")

    async def test_update_access_tier_persists(self, db_pool, user_factory, sync_conn, admin_actor):
        """update_access_tier persists the new tier on the real row and returns
        the atomically captured (old_value, new_value) pair."""
        handle = user_factory()  # default tier: public
        result = await update_access_tier(
            db_pool,
            handle.id,
            "vetted",
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )
        assert result == ("public", "vetted")
        stored = _fetch_user_row(sync_conn, handle.id, ["access_tier"])
        assert stored["access_tier"] == "vetted"

    async def test_update_access_tier_unknown_user_raises(self, db_pool, admin_actor):
        """Missing user -> ValueError via the RETURNING existence check."""
        with pytest.raises(ValueError, match="not found"):
            await update_access_tier(
                db_pool,
                999_999,
                "registered",
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )

    async def test_concurrent_tier_writes_capture_committed_old_value(
        self, db_pool, user_factory, admin_actor
    ):
        """A concurrent admin's write blocks on the`before` CTE's row lock
        (users.py:353-355, `SELECT access_tier FROMusers WHERE id = %(user_id)s FOR UPDATE`)
        and its returned old_value iswhat the row held at WRITE time — the first
        writer's COMMITTED value — never a stale pre-lock snapshot.

        conn1 opens a transaction that rewrites access_tier to 'vetted' but does
        NOT commit yet; the second writer's update_access_tier(..., 'public')
        call must block on FOR UPDATE until conn1 commits, then report
        old_value='vetted' (conn1's committed value), never 'registered' (the
        seed value a stale read taken before conn1's write would return).
        """
        handle = user_factory(access_tier="registered")

        conn1 = await psycopg.AsyncConnection.connect(TEST_DATABASE_URL)
        leader_pid, task = conn1.info.backend_pid, None
        try:
            async with conn1.cursor() as cur:  # transaction open, deliberately not committed
                await cur.execute(
                    "WITH before AS (SELECT access_tier FROM users "
                    "WHERE id = %(u)s FOR UPDATE) "
                    "UPDATE users SET access_tier = 'vetted' FROM before "
                    "WHERE users.id = %(u)s RETURNING before.access_tier",
                    {"u": handle.id},
                )
            task = asyncio.create_task(
                update_access_tier(
                    db_pool,
                    handle.id,
                    "public",
                    actor_id=admin_actor.id,
                    actor_session_id=admin_actor.session_id,
                )
            )
            async with await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as observer:
                await asyncio.wait_for(_wait_until_blocked_by(observer, leader_pid), 5)

            await conn1.commit()
            old_value, new_value = await asyncio.wait_for(task, timeout=5)
        finally:
            # On any failure above (e.g. the blocking-proof assert): close conn1
            # (releases its FOR UPDATE lock via implicit rollback) and drain the
            # second-writer task so it can't outlive the test's event loop / pool
            # (matches the drain pattern in test_sync_mutex_race.py's finally
            # blocks; a bare task.cancel() without awaiting risks a "Task was
            # destroyed but it is pending" warning bleeding into later tests).
            await conn1.close()
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        assert old_value == "vetted"  # conn1's COMMITTED value — the CTE re-read
        assert new_value == "public"  # NOT "registered": a stale snapshot would say that


def _plant_lockout(sync_conn, user_id):
    """SQL-set a mid-lockout state: 5 failures, locked into the future."""
    sync_conn.execute(
        """UPDATE users
              SET failed_login_count = 5,
                  locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes',
                  is_active = false
            WHERE id = %s""",
        (user_id,),
    )
    sync_conn.commit()


class TestSetUserActiveAsymmetry:
    """set_user_active(True) clears lockout state; set_user_active(False) preserves it."""

    async def test_set_user_active_true_clears_lockout_counters(
        self, db_pool, user_factory, sync_conn, admin_actor
    ):
        """Reactivation is a fresh start: set_user_active(True) clears
        failed_login_count and locked_until so the user is not still locked
        out from before deactivation, and returns SetActiveResult with
        lock_cleared=True (users.py:436-451: before.failed_login_count=5 > 0
        makes the OR-clause true). _plant_lockout also sets is_active=false,
        so old_value=False here (deactivated -> reactivated)."""
        handle = user_factory()
        _plant_lockout(sync_conn, handle.id)

        result = await set_user_active(
            db_pool,
            handle.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert result == SetActiveResult(old_value=False, new_value=True, lock_cleared=True)
        stored = _fetch_user_row(
            sync_conn, handle.id, ["is_active", "failed_login_count", "locked_until"]
        )
        assert stored["is_active"] is True
        assert stored["failed_login_count"] == 0
        assert stored["locked_until"] is None

    async def test_set_user_active_true_on_already_active_locked_user_clears_lockout(
        self, db_pool, user_factory, sync_conn, admin_actor
    ):
        """Reactivating an ALREADY-ACTIVE, locked-out user still clears
        the lockout — the write is no longer guarded by a pre-read.
        old_value=True (not False, unlike the deactivated-then-reactivated case above)
        pins that the branch fires unconditionally on is_active=True, not only on
        an is_active flip."""
        handle = user_factory(is_active=True)
        sync_conn.execute(
            """UPDATE users
                  SET failed_login_count = 3,
                      locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
                WHERE id = %s""",
            (handle.id,),
        )
        sync_conn.commit()

        result = await set_user_active(
            db_pool,
            handle.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert result == SetActiveResult(old_value=True, new_value=True, lock_cleared=True)
        stored = _fetch_user_row(
            sync_conn, handle.id, ["is_active", "failed_login_count", "locked_until"]
        )
        assert stored["is_active"] is True
        assert stored["failed_login_count"] == 0
        assert stored["locked_until"] is None

    async def test_set_user_active_true_on_expired_lock_still_reports_cleared(
        self, db_pool, user_factory, sync_conn, admin_actor
    ):
        """Pins the OR in the lock_cleared expression (users.py:449-450:
        `before.failed_login_count > 0 OR before.locked_until IS NOT NULL`):
        locked_until IS NOT NULL is true even when the timestamp is already in
        the PAST (an expired lock no longer actually blocking anyone) —
        lock_cleared reports "the write reset stale lockout state", not "the
        user was actively blocked at read time"."""
        handle = user_factory(is_active=True)
        sync_conn.execute(
            """UPDATE users
                  SET failed_login_count = 0,
                      locked_until = CURRENT_TIMESTAMP - INTERVAL '1 hour'
                WHERE id = %s""",
            (handle.id,),
        )
        sync_conn.commit()

        result = await set_user_active(
            db_pool,
            handle.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert result == SetActiveResult(old_value=True, new_value=True, lock_cleared=True)
        stored = _fetch_user_row(sync_conn, handle.id, ["locked_until"])
        assert stored["locked_until"] is None

    async def test_set_user_active_true_on_clean_active_user_reports_not_cleared(
        self, db_pool, user_factory, admin_actor
    ):
        """POSITIVE CONTROL for the lock_cleared=True pins above: reactivating an
        already-active user with NO lockout state (failed_login_count=0,
        locked_until=NULL, the user_factory defaults) returns lock_cleared=False
        — proves the OR only fires when there was something to clear, not
        unconditionally on every reactivation call."""
        handle = user_factory(is_active=True)

        result = await set_user_active(
            db_pool,
            handle.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert result == SetActiveResult(old_value=True, new_value=True, lock_cleared=False)

    async def test_set_user_active_false_preserves_lockout_counters(
        self, db_pool, user_factory, sync_conn, admin_actor
    ):
        """Deactivation keeps the audit signal: counters and locked_until are
        NOT cleared when an admin disables the account, and lock_cleared is
        hard-coded False on the deactivate branch (users.py:452-464) regardless
        of the prior lockout state — the companion pin to the
        reactivation-clears-lockout tests above."""
        handle = user_factory()  # is_active=True by default
        sync_conn.execute(
            """UPDATE users
                  SET failed_login_count = 5,
                      locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
                WHERE id = %s""",
            (handle.id,),
        )
        sync_conn.commit()

        result = await set_user_active(
            db_pool,
            handle.id,
            False,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )

        assert result == SetActiveResult(old_value=True, new_value=False, lock_cleared=False)
        stored = _fetch_user_row(
            sync_conn, handle.id, ["is_active", "failed_login_count", "locked_until"]
        )
        assert stored["is_active"] is False
        assert stored["failed_login_count"] == 5
        assert stored["locked_until"] is not None

    async def test_set_user_active_unknown_user_raises(self, db_pool, admin_actor):
        """Missing user -> ValueError for both directions of the flag."""
        with pytest.raises(ValueError, match="not found"):
            await set_user_active(
                db_pool,
                999_999,
                True,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )
        with pytest.raises(ValueError, match="not found"):
            await set_user_active(
                db_pool,
                999_999,
                False,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )


class TestUserLookups:
    """get_user_by_email / get_user_by_id."""

    async def test_get_user_by_email_case_insensitive(self, db_pool, user_factory):
        """get_user_by_email matches via LOWER(email) = LOWER(%s) against the
        real index, regardless of the caller's casing."""
        handle = user_factory(email="alice@uzh.ch")
        user = await get_user_by_email(db_pool, "ALICE@UZH.CH")
        assert user is not None
        assert user.id == handle.id
        assert user.email == "alice@uzh.ch"

    async def test_get_user_by_id_missing_returns_none(self, db_pool):
        """Unknown id -> None (not an exception)."""
        assert await get_user_by_id(db_pool, 999_999) is None


class TestUnverifiedAccountReaper:
    """``reap_unverified_accounts`` deletes unverified local accounts past
    the retention window in bounded batches, skipping any account another
    transaction currently holds locked, without blocking on it."""

    async def test_reaper_commits_bounded_progress_and_skips_busy_accounts(
        self, db_pool, sync_conn, user_factory
    ):
        """A single run deletes at most its batch cap (10 batches x 100 =
        1000 rows), skipping a concurrently locked row via SKIP LOCKED
        rather than waiting on it; once the lock is released, a second run
        reaps what remains."""
        busy = user_factory(email_verified=False, created_at=datetime(2020, 1, 1, tzinfo=UTC))
        sync_conn.execute(
            "INSERT INTO users (email, display_name, password_hash, auth_method, "
            "email_verified, created_at) SELECT 'reap' || i || '@uzh.ch', 'Old', "
            "'unused', 'local', false, '2020-01-01'::timestamptz FROM generate_series(1, 1005) i"
        )
        sync_conn.commit()
        sync_conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (busy.id,))
        try:
            async with asyncio.timeout(10):
                assert await reap_unverified_accounts(db_pool) == 1000
        finally:
            sync_conn.rollback()
        assert sync_conn.execute("SELECT COUNT(*) FROM users").fetchone() == (6,)
        sync_conn.commit()
        assert await reap_unverified_accounts(db_pool) == 6


class TestLoginFailureLockout:
    """record_login_failure / clear_login_failures (threshold = 3 in test env)."""

    async def test_login_failure_lockout_crossing_and_clear(
        self, db_pool, user_factory, sync_conn, admin_actor
    ):
        """The SQL CASE locks exactly at the threshold: two failures leave the
        account unlocked; the third sets locked_until AND reports
        was_locked_this_call=True only on that crossing call. A fourth
        failure arrives while the lock is live, so it neither raises the
        counter nor reports a second crossing. Administrator reactivation
        resets both columns."""
        handle = user_factory()

        count, locked = await record_login_failure(db_pool, handle.id, expected_auth_revision=0)
        assert (count, locked) == (1, False)

        count, locked = await record_login_failure(db_pool, handle.id, expected_auth_revision=0)
        assert (count, locked) == (2, False)
        stored = _fetch_user_row(sync_conn, handle.id, ["locked_until"])
        assert stored["locked_until"] is None  # below threshold: not locked

        # Third failure crosses the threshold (LOGIN_FAILURE_THRESHOLD=3).
        count, locked = await record_login_failure(db_pool, handle.id, expected_auth_revision=0)
        assert (count, locked) == (3, True)
        stored = _fetch_user_row(sync_conn, handle.id, ["locked_until"])
        assert stored["locked_until"] is not None
        assert stored["locked_until"] > datetime.now(UTC)

        # Fourth failure: already locked — the counter and the flag hold still.
        count, locked = await record_login_failure(db_pool, handle.id, expected_auth_revision=0)
        assert (count, locked) == (3, False)

        await set_user_active(
            db_pool,
            handle.id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )
        stored = _fetch_user_row(sync_conn, handle.id, ["failed_login_count", "locked_until"])
        assert stored["failed_login_count"] == 0
        assert stored["locked_until"] is None


class TestTotpReplayGuard:
    """verify_and_consume_totp: a valid current code verifies once; replay and garbage are rejected."""

    async def test_totp_code_verifies_once_then_replay_rejected(self, db_pool, user_factory):
        """A valid current code returns True exactly once.

        Verification reads the current encrypted secret and replay floor under
        one row lock. The first call advances last_totp_step; replaying that code
        is rejected. A future-step code inside valid_window=1 still verifies,
        proving the guard is monotonic rather than a blanket block.
        """
        secret = pyotp.random_base32()
        handle = user_factory(totp_secret=encrypt_value(secret))
        totp = pyotp.TOTP(secret)

        with time_machine.travel(datetime.now(UTC), tick=False):
            instant = int(time.time())
            code = totp.at(instant)
            assert await verify_and_consume_totp(db_pool, handle.id, code) is True
            # Replay of the exact same code: step already consumed.
            assert await verify_and_consume_totp(db_pool, handle.id, code) is False

            # Next-step code (offset +1 within valid_window=1) still verifies.
            future_code = totp.at(instant + 30)
            assert await verify_and_consume_totp(db_pool, handle.id, future_code) is True

    async def test_totp_garbage_code_rejected_without_consuming(self, db_pool, user_factory):
        """An invalid code returns False and leaves last_totp_step untouched,
        so the genuine current code still works afterwards."""
        secret = pyotp.random_base32()
        handle = user_factory(totp_secret=encrypt_value(secret))

        assert await verify_and_consume_totp(db_pool, handle.id, "not-a-code") is False
        assert await verify_and_consume_totp(db_pool, handle.id, pyotp.TOTP(secret).now()) is True


class TestPendingTotpEnrollment:
    """The staged (pending) secret store, its TTL and promotion through verify_and_enroll_totp."""

    async def test_pending_totp_roundtrip_encrypted_at_rest(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """store_pending_totp_secret encrypts before writing: the raw column
        value is ciphertext (!= the secret) but decrypt_value recovers it, and
        get_pending_totp_secret returns the plaintext within the TTL, to the
        exact session authorizing the enrollment."""
        secret = pyotp.random_base32()
        handle = user_factory()
        raw_session = session_factory(handle.id, purpose="totp_setup")

        await store_pending_totp_secret(db_pool, handle.id, secret)

        stored = _fetch_user_row(
            sync_conn, handle.id, ["pending_totp_secret", "pending_totp_created_at"]
        )
        assert stored["pending_totp_secret"] is not None
        assert stored["pending_totp_secret"] != secret  # encrypted at rest
        assert decrypt_value(stored["pending_totp_secret"]) == secret
        assert stored["pending_totp_created_at"] is not None

        assert (
            await get_pending_totp_secret(
                db_pool,
                handle.id,
                session_id=raw_session,
                purpose=PendingTotpPurpose.ENROLLMENT,
            )
            == secret
        )

    async def test_pending_totp_expires_after_ttl(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """A pending secret aged past the 10-minute TTL is treated as absent:
        the SELECT's created_at window excludes it -> None."""
        secret = pyotp.random_base32()
        handle = user_factory()
        raw_session = session_factory(handle.id, purpose="totp_setup")
        await store_pending_totp_secret(db_pool, handle.id, secret)

        sync_conn.execute(
            """UPDATE users
                  SET pending_totp_created_at = CURRENT_TIMESTAMP - INTERVAL '11 minutes'
                WHERE id = %s""",
            (handle.id,),
        )
        sync_conn.commit()

        assert (
            await get_pending_totp_secret(
                db_pool,
                handle.id,
                session_id=raw_session,
                purpose=PendingTotpPurpose.ENROLLMENT,
            )
            is None
        )

    async def test_enrollment_promotes_and_clears_pending(
        self, db_pool, user_factory, session_factory, sync_conn
    ):
        """Enrollment promotes the pending secret and consumes its verified step."""
        handle = user_factory(
            email_verified=True,
            is_active=True,
            auth_method="local",
            totp_secret=None,
            last_totp_step=None,
        )
        session_id = session_factory(handle.id, purpose="totp_setup")
        # get_or_create_pending_totp_secret is the real production entry point
        # (routes/auth/totp.py:131): it atomically stages the pending secret AND
        # its recovery-code set, which verify_and_enroll_totp now requires the
        # caller to confirm one of (totp.py:511-518).
        pending = await get_or_create_pending_totp_secret(
            db_pool, handle.id, purpose=PendingTotpPurpose.ENROLLMENT, session_id=session_id
        )
        assert pending.outcome is PendingTotpOutcome.READY
        secret = pending.secret
        recovery_code = pending.recovery_codes[0]

        verified_at = 1_800_000_000
        consumed_step = verified_at // 30
        code = pyotp.TOTP(secret).at(verified_at)

        with patch("app.services.totp.time.time", return_value=verified_at):
            outcome = await verify_and_enroll_totp(
                db_pool, handle.id, code, recovery_code, session_id=session_id
            )

            assert outcome is TotpEnrollmentOutcome.ENROLLED

            # The enrollment code has already been consumed.
            assert await verify_and_consume_totp(db_pool, handle.id, code) is False

        stored = _fetch_user_row(
            sync_conn,
            handle.id,
            [
                "totp_secret",
                "pending_totp_secret",
                "pending_totp_created_at",
                "last_totp_step",
            ],
        )
        assert stored["pending_totp_secret"] is None
        assert stored["pending_totp_created_at"] is None
        assert stored["last_totp_step"] == consumed_step
        assert stored["totp_secret"] != secret
        assert decrypt_value(stored["totp_secret"]) == secret

        assert await get_totp_secret(db_pool, handle.id) == secret
        # Already cleared by promotion, so the read short-circuits before the
        # authorizing-session check; the session/purpose args are required by
        # the signature but irrelevant to this negative result.
        assert (
            await get_pending_totp_secret(
                db_pool,
                handle.id,
                session_id=session_id,
                purpose=PendingTotpPurpose.ENROLLMENT,
            )
            is None
        )

    async def test_enrollment_cannot_replace_existing_authenticator(
        self, db_pool, user_factory, sync_conn
    ):
        """POSITIVE CONTROL companion: an already-configured authenticator
        short-circuits enrollment entirely — nothing about the active secret,
        replay step, or a co-staged pending secret is disturbed."""
        active_secret = pyotp.random_base32()
        pending_secret = pyotp.random_base32()

        handle = user_factory(
            email_verified=True,
            is_active=True,
            auth_method="local",
            totp_secret=encrypt_value(active_secret),
            last_totp_step=999999,
        )
        await store_pending_totp_secret(db_pool, handle.id, pending_secret)

        outcome = await verify_and_enroll_totp(
            db_pool,
            handle.id,
            pyotp.TOTP(pending_secret).now(),
            "unused-because-already-configured-short-circuits-first",
            session_id="unused-because-enrollment-is-already-complete",
        )

        assert outcome is TotpEnrollmentOutcome.ALREADY_CONFIGURED

        row = _fetch_user_row(
            sync_conn,
            handle.id,
            ["last_totp_step", "totp_secret", "pending_totp_secret"],
        )
        assert row["last_totp_step"] == 999999
        assert decrypt_value(row["totp_secret"]) == active_secret
        assert decrypt_value(row["pending_totp_secret"]) == pending_secret


class TestGetTotpSecretFailClosed:
    """get_totp_secret / verify_and_consume_totp fail closed on corrupt ciphertext."""

    async def test_get_totp_secret_none_when_absent(self, db_pool, user_factory):
        """No totp_secret configured (and unknown user) -> None, not an error."""
        handle = user_factory()  # no totp_secret
        assert await get_totp_secret(db_pool, handle.id) is None
        assert await get_totp_secret(db_pool, 999_999) is None

    async def test_get_totp_secret_undecryptable_raises(self, db_pool, user_factory, sync_conn):
        """An existing but undecryptable secret (key rotation gone wrong /
        corruption) raises TotpDecryptionError — fail closed, NEVER 'no second
        factor configured'."""
        handle = user_factory()
        sync_conn.execute(
            "UPDATE users SET totp_secret = 'garbage-not-fernet' WHERE id = %s",
            (handle.id,),
        )
        sync_conn.commit()

        with pytest.raises(TotpDecryptionError) as exc_info:
            await get_totp_secret(db_pool, handle.id)
        assert exc_info.value.user_id == handle.id

    async def test_totp_verification_uses_current_database_secret(self, db_pool, user_factory):
        """A code for a replaced secret cannot authenticate.

        Callers supply only the code. The service
        reads and verifies the current secret while holding the user's row lock,
        so it cannot accidentally authenticate against stale caller-held state.
        """
        old_secret = pyotp.random_base32()
        old_code = pyotp.TOTP(old_secret).now()

        current_secret = pyotp.random_base32()
        while matched_step(current_secret, old_code) is not None:
            current_secret = pyotp.random_base32()

        handle = user_factory(totp_secret=encrypt_value(current_secret))

        assert await verify_and_consume_totp(db_pool, handle.id, old_code) is False

    async def test_totp_verification_undecryptable_secret_raises(self, db_pool, user_factory):
        """Atomic verification fails closed when the locked secret is corrupt."""
        handle = user_factory(totp_secret="garbage-not-fernet")

        with pytest.raises(TotpDecryptionError) as exc_info:
            await verify_and_consume_totp(db_pool, handle.id, "123456")

        assert exc_info.value.user_id == handle.id
