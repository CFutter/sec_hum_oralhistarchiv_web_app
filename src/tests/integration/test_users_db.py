"""Integration tests: user CRUD + TOTP persistence against real PostgreSQL."""

import asyncio
import contextlib
import time
from datetime import UTC, datetime
from unittest.mock import patch

import psycopg
import pyotp
import pytest
import time_machine

from app.service_errors import UserNotFound
from app.services import registration_setup
from app.services.authentication import (
    record_login_failure,
)
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
from app.services.totp_crypto import decrypt_value, encrypt_value
from app.services.users import (
    SetActiveResult,
    get_user_by_email,
    get_user_by_id,
    reap_unverified_accounts,
    set_user_active,
    update_access_tier,
    update_display_name,
)
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
    """Registration creates an inactive public shell without credentials or profile."""

    async def test_create_local_user_normalizes_email_and_defaults(self, db_pool, sync_conn):
        """Verify create local user normalizes email and defaults."""
        assert (
            await registration_setup.begin_local_registration(db_pool, email=" Alice@EXAMPLE.ORG ")
            is None
        )
        user = await get_user_by_email(db_pool, "alice@example.org")
        assert user is not None
        assert user.email == "alice@example.org"
        assert user.totp_configured is False
        assert user.access_tier == "public"
        assert user.auth_method == "local"
        assert user.is_active is False
        assert user.email_verified is False
        assert user.is_admin is False
        assert user.display_name is user.affiliation is user.country is None

        stored = _fetch_user_row(sync_conn, user.id, ["email", "access_tier", "password_hash"])
        assert stored == {
            "email": "alice@example.org",
            "access_tier": "public",
            "password_hash": None,
        }

    async def test_create_local_user_duplicate_email_case_insensitive(
        self, db_pool, user_factory, sync_conn
    ):
        """Verify create local user duplicate email case insensitive."""
        handle = user_factory(email="alice@example.org")
        before = sync_conn.execute("SELECT * FROM users WHERE id = %s", (handle.id,)).fetchone()
        sync_conn.commit()

        assert (
            await registration_setup.begin_local_registration(db_pool, email="ALICE@example.org")
            is None
        )
        user = await get_user_by_email(db_pool, "alice@example.org")
        assert user is not None and user.id == handle.id
        assert (
            sync_conn.execute("SELECT * FROM users WHERE id = %s", (handle.id,)).fetchone()
            == before
        )
        assert (
            sync_conn.execute(
                "SELECT user_id, message_type, recipient FROM email_outbox"
            ).fetchall()
            == []
        )

    async def test_new_local_account_has_no_active_pending_or_consumed_totp(
        self, db_pool, sync_conn
    ):
        """Verify new local account has no active pending or consumed TOTP."""
        await registration_setup.begin_local_registration(db_pool, email="new-person@example.org")
        user = await get_user_by_email(db_pool, "new-person@example.org")
        assert user is not None
        assert user.totp_configured is False
        assert sync_conn.execute(
            "SELECT totp_secret, pending_totp_secret, pending_totp_created_at, last_totp_step "
            "FROM users WHERE id = %s",
            (user.id,),
        ).fetchone() == (None, None, None, None)


class TestRegistrationTransaction:
    """Pending account and verification email commit in one transaction."""

    async def test_registration_enqueue_failure_rolls_back_account_and_can_retry(
        self, db_pool, sync_conn
    ):
        """Verify registration enqueue failure rolls back account and can retry."""
        email = "  AUDIT@EXAMPLE.ORG  "
        with (
            patch.object(
                registration_setup,
                "enqueue_outbound_email_cur",
                autospec=True,
                side_effect=RuntimeError("queue failed"),
            ),
            pytest.raises(RuntimeError, match="queue failed"),
        ):
            await registration_setup.begin_local_registration(db_pool, email=email)
        assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
        sync_conn.commit()
        await registration_setup.begin_local_registration(db_pool, email=email)
        user = await get_user_by_email(db_pool, "audit@example.org")
        assert user is not None
        assert user.email == "audit@example.org"
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
        """UPDATE ... RETURNING id on a missing user yields no row -> UserNotFound
        (guards the existence check the unit tier only mocks)."""
        with pytest.raises(UserNotFound, match="not found"):
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
        """Missing user -> UserNotFound via the RETURNING existence check."""
        with pytest.raises(UserNotFound, match="not found"):
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
        """Verify concurrent tier writes capture committed old value."""
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
        """Verify set user active true clears lockout counters."""
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
        """Verify set user active true on already active locked user clears lockout."""
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
        """Verify set user active true on expired lock still reports cleared."""
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
        """Verify set user active true on clean active user reports not cleared."""
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
        """Verify set user active false preserves lockout counters."""
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
        """Missing user -> UserNotFound for both directions of the flag."""
        with pytest.raises(UserNotFound, match="not found"):
            await set_user_active(
                db_pool,
                999_999,
                True,
                actor_id=admin_actor.id,
                actor_session_id=admin_actor.session_id,
            )
        with pytest.raises(UserNotFound, match="not found"):
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
        handle = user_factory(email="alice@example.org")
        user = await get_user_by_email(db_pool, "ALICE@EXAMPLE.ORG")
        assert user is not None
        assert user.id == handle.id
        assert user.email == "alice@example.org"

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
            "email_verified, created_at) SELECT 'reap' || i || '@example.org', 'Old', "
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
        """Verify login failure lockout crossing and clear."""
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
        """Verify TOTP code verifies once then replay rejected."""
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
        """Production setup stores encrypted pending material; the authorizing
        session can read the plaintext back within its TTL."""
        handle = user_factory()
        raw_session = session_factory(handle.id, purpose="totp_setup")
        pending = await get_or_create_pending_totp_secret(
            db_pool,
            handle.id,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=raw_session,
        )
        assert pending.outcome is PendingTotpOutcome.READY
        assert pending.secret is not None
        secret = pending.secret

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
        handle = user_factory()
        raw_session = session_factory(handle.id, purpose="totp_setup")
        pending = await get_or_create_pending_totp_secret(
            db_pool,
            handle.id,
            purpose=PendingTotpPurpose.ENROLLMENT,
            session_id=raw_session,
        )
        assert pending.outcome is PendingTotpOutcome.READY
        assert pending.secret is not None

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

        # Deliberately seed stale pending state beside an active authenticator;
        # production enrollment setup correctly refuses to create this state.
        handle = user_factory(
            email_verified=True,
            is_active=True,
            auth_method="local",
            totp_secret=encrypt_value(active_secret),
            last_totp_step=999999,
            pending_totp_secret=encrypt_value(pending_secret),
            pending_totp_created_at=datetime.now(UTC),
        )

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
