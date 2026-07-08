"""Integration tests: user CRUD + TOTP persistence against real PostgreSQL.

Pins the database behaviors the unit tier mocks away: the LOWER(email)
unique index, UPDATE ... RETURNING existence checks, the asymmetric
set_user_active counter handling, the SQL-side lockout threshold CASE,
the last_totp_step replay guard, pending-TOTP TTL/promotion, and the
fail-closed handling of undecryptable TOTP secrets.
"""

import time
from datetime import datetime, timezone

import pyotp
import pytest

from app.services.authentication import (
    clear_login_failures,
    record_login_failure,
)
from app.services.crypto import decrypt_value, encrypt_value
from app.services.totp import (
    TotpDecryptionError,
    get_pending_totp_secret,
    get_totp_secret,
    store_pending_totp_secret,
    update_totp_secret,
    verify_and_consume_totp,
)
from app.services.users import (
    UserAlreadyExistsError,
    create_local_user,
    get_user_by_email,
    get_user_by_id,
    set_user_active,
    update_access_tier,
    update_display_name,
)


def _fetch_user_row(sync_conn, user_id, columns):
    """Read raw column values for asserts (bypasses the app's SELECT builder)."""
    row = sync_conn.execute(
        f"SELECT {', '.join(columns)} FROM users WHERE id = %s", (user_id,)
    ).fetchone()
    assert row is not None, f"user {user_id} missing"
    return dict(zip(columns, row))


# ---------------------------------------------------------------------------
# create_local_user
# ---------------------------------------------------------------------------

async def test_create_local_user_normalizes_email_and_defaults(db_pool, sync_conn):
    """create_local_user strips/lowercases the email before INSERT and the
    returned User starts with totp_configured=False and tier 'public'
    (creation can never elevate — the INSERT hardcodes 'public')."""
    user = await create_local_user(
        db_pool, " Alice@UZH.ch ", "Alice", "s3cret-Pw!"
    )
    assert user.email == "alice@uzh.ch"
    assert user.totp_configured is False
    assert user.access_tier == "public"
    assert user.auth_method == "local"

    stored = _fetch_user_row(sync_conn, user.id, ["email", "access_tier"])
    assert stored["email"] == "alice@uzh.ch"
    assert stored["access_tier"] == "public"


async def test_create_local_user_duplicate_email_case_insensitive(db_pool, user_factory):
    """The LOWER(email) unique index rejects a duplicate that differs only in
    case: the UniqueViolation is translated to UserAlreadyExistsError
    end-to-end (not a raw psycopg error leaking to the route)."""
    user_factory(email="alice@uzh.ch")
    with pytest.raises(UserAlreadyExistsError) as exc_info:
        await create_local_user(db_pool, "ALICE@uzh.ch", "Impostor", "s3cret-Pw!")
    # The error carries the normalized (lowercased) email.
    assert exc_info.value.email == "alice@uzh.ch"


# ---------------------------------------------------------------------------
# update_display_name / update_access_tier
# ---------------------------------------------------------------------------

async def test_update_display_name_persists(db_pool, user_factory, sync_conn):
    """update_display_name writes the normalized name to the real row."""
    handle = user_factory()
    await update_display_name(db_pool, handle.id, "  New Name  ")
    stored = _fetch_user_row(sync_conn, handle.id, ["display_name"])
    assert stored["display_name"] == "New Name"


async def test_update_display_name_unknown_user_raises(db_pool):
    """UPDATE ... RETURNING id on a missing user yields no row -> ValueError
    (guards the existence check the unit tier only mocks)."""
    with pytest.raises(ValueError, match="not found"):
        await update_display_name(db_pool, 999_999, "Ghost")


async def test_update_access_tier_persists(db_pool, user_factory, sync_conn):
    """update_access_tier persists the new tier on the real row."""
    handle = user_factory()  # default tier: public
    await update_access_tier(db_pool, handle.id, "vetted")
    stored = _fetch_user_row(sync_conn, handle.id, ["access_tier"])
    assert stored["access_tier"] == "vetted"


async def test_update_access_tier_unknown_user_raises(db_pool):
    """Missing user -> ValueError via the RETURNING existence check."""
    with pytest.raises(ValueError, match="not found"):
        await update_access_tier(db_pool, 999_999, "registered")


# ---------------------------------------------------------------------------
# set_user_active asymmetry
# ---------------------------------------------------------------------------

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


async def test_set_user_active_true_clears_lockout_counters(db_pool, user_factory, sync_conn):
    """Reactivation is a fresh start: set_user_active(True) clears
    failed_login_count and locked_until so the user is not still locked
    out from before deactivation."""
    handle = user_factory()
    _plant_lockout(sync_conn, handle.id)

    await set_user_active(db_pool, handle.id, True)

    stored = _fetch_user_row(
        sync_conn, handle.id, ["is_active", "failed_login_count", "locked_until"]
    )
    assert stored["is_active"] is True
    assert stored["failed_login_count"] == 0
    assert stored["locked_until"] is None


async def test_set_user_active_false_preserves_lockout_counters(db_pool, user_factory, sync_conn):
    """Deactivation keeps the audit signal: counters and locked_until are
    NOT cleared when an admin disables the account."""
    handle = user_factory()
    sync_conn.execute(
        """UPDATE users
              SET failed_login_count = 5,
                  locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
            WHERE id = %s""",
        (handle.id,),
    )
    sync_conn.commit()

    await set_user_active(db_pool, handle.id, False)

    stored = _fetch_user_row(
        sync_conn, handle.id, ["is_active", "failed_login_count", "locked_until"]
    )
    assert stored["is_active"] is False
    assert stored["failed_login_count"] == 5
    assert stored["locked_until"] is not None


async def test_set_user_active_unknown_user_raises(db_pool):
    """Missing user -> ValueError for both directions of the flag."""
    with pytest.raises(ValueError, match="not found"):
        await set_user_active(db_pool, 999_999, True)
    with pytest.raises(ValueError, match="not found"):
        await set_user_active(db_pool, 999_999, False)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

async def test_get_user_by_email_case_insensitive(db_pool, user_factory):
    """get_user_by_email matches via LOWER(email) = LOWER(%s) against the
    real index, regardless of the caller's casing."""
    handle = user_factory(email="alice@uzh.ch")
    user = await get_user_by_email(db_pool, "ALICE@UZH.CH")
    assert user is not None
    assert user.id == handle.id
    assert user.email == "alice@uzh.ch"


async def test_get_user_by_id_missing_returns_none(db_pool):
    """Unknown id -> None (not an exception)."""
    assert await get_user_by_id(db_pool, 999_999) is None


# ---------------------------------------------------------------------------
# record_login_failure / clear_login_failures (threshold = 3 in test env)
# ---------------------------------------------------------------------------

async def test_login_failure_lockout_crossing_and_clear(db_pool, user_factory, sync_conn):
    """The SQL CASE locks exactly at the threshold: two failures leave the
    account unlocked; the third sets locked_until AND reports
    was_locked_this_call=True only on that crossing call (False on a 4th,
    which is 'still locked', not 'just locked'). clear_login_failures
    resets both columns."""
    handle = user_factory()

    count, locked = await record_login_failure(db_pool, handle.id)
    assert (count, locked) == (1, False)

    count, locked = await record_login_failure(db_pool, handle.id)
    assert (count, locked) == (2, False)
    stored = _fetch_user_row(sync_conn, handle.id, ["locked_until"])
    assert stored["locked_until"] is None  # below threshold: not locked

    # Third failure crosses the threshold (LOGIN_FAILURE_THRESHOLD=3).
    count, locked = await record_login_failure(db_pool, handle.id)
    assert (count, locked) == (3, True)
    stored = _fetch_user_row(sync_conn, handle.id, ["locked_until"])
    assert stored["locked_until"] is not None
    assert stored["locked_until"] > datetime.now(timezone.utc)

    # Fourth failure: already locked — the flag must NOT fire again.
    count, locked = await record_login_failure(db_pool, handle.id)
    assert (count, locked) == (4, False)

    await clear_login_failures(db_pool, handle.id)
    stored = _fetch_user_row(
        sync_conn, handle.id, ["failed_login_count", "locked_until"]
    )
    assert stored["failed_login_count"] == 0
    assert stored["locked_until"] is None


# ---------------------------------------------------------------------------
# TOTP replay guard (verify_and_consume_totp)
# ---------------------------------------------------------------------------

async def test_totp_code_verifies_once_then_replay_rejected(db_pool, user_factory):
    """A valid current code returns True exactly once: the conditional
    UPDATE consumes its time-step, so the SAME code immediately replayed
    hits rowcount 0 and returns False. A code for a FUTURE step (still
    inside valid_window=1) then verifies — the guard is monotonic-forward,
    not a blanket block."""
    secret = pyotp.random_base32()
    handle = user_factory(totp_secret=encrypt_value(secret))
    totp = pyotp.TOTP(secret)

    code = totp.now()
    assert await verify_and_consume_totp(db_pool, handle.id, secret, code) is True
    # Replay of the exact same code: step already consumed.
    assert await verify_and_consume_totp(db_pool, handle.id, secret, code) is False

    # Next-step code (offset +1 within valid_window=1) still verifies.
    future_code = totp.at(int(time.time()) + 30)
    assert await verify_and_consume_totp(db_pool, handle.id, secret, future_code) is True


async def test_totp_garbage_code_rejected_without_consuming(db_pool, user_factory):
    """An invalid code returns False and leaves last_totp_step untouched,
    so the genuine current code still works afterwards."""
    secret = pyotp.random_base32()
    handle = user_factory(totp_secret=encrypt_value(secret))

    assert await verify_and_consume_totp(db_pool, handle.id, secret, "000000") is False
    assert await verify_and_consume_totp(
        db_pool, handle.id, secret, pyotp.TOTP(secret).now()
    ) is True


# ---------------------------------------------------------------------------
# Pending TOTP enrollment (store / TTL / promotion)
# ---------------------------------------------------------------------------

async def test_pending_totp_roundtrip_encrypted_at_rest(db_pool, user_factory, sync_conn):
    """store_pending_totp_secret encrypts before writing: the raw column
    value is ciphertext (!= the secret) but decrypt_value recovers it, and
    get_pending_totp_secret returns the plaintext within the TTL."""
    secret = pyotp.random_base32()
    handle = user_factory()

    await store_pending_totp_secret(db_pool, handle.id, secret)

    stored = _fetch_user_row(
        sync_conn, handle.id, ["pending_totp_secret", "pending_totp_created_at"]
    )
    assert stored["pending_totp_secret"] is not None
    assert stored["pending_totp_secret"] != secret  # encrypted at rest
    assert decrypt_value(stored["pending_totp_secret"]) == secret
    assert stored["pending_totp_created_at"] is not None

    assert await get_pending_totp_secret(db_pool, handle.id) == secret


async def test_pending_totp_expires_after_ttl(db_pool, user_factory, sync_conn):
    """A pending secret aged past the 10-minute TTL is treated as absent:
    the SELECT's created_at window excludes it -> None."""
    secret = pyotp.random_base32()
    handle = user_factory()
    await store_pending_totp_secret(db_pool, handle.id, secret)

    sync_conn.execute(
        """UPDATE users
              SET pending_totp_created_at = CURRENT_TIMESTAMP - INTERVAL '11 minutes'
            WHERE id = %s""",
        (handle.id,),
    )
    sync_conn.commit()

    assert await get_pending_totp_secret(db_pool, handle.id) is None


async def test_update_totp_secret_promotes_and_clears_pending(db_pool, user_factory, sync_conn):
    """Promotion is one UPDATE: totp_secret set (encrypted, decryptable),
    both pending columns cleared, and last_totp_step set to the consumed
    step so the just-verified enrollment code cannot replay as a login."""
    secret = pyotp.random_base32()
    handle = user_factory()
    await store_pending_totp_secret(db_pool, handle.id, secret)

    consumed_step = int(time.time()) // 30
    await update_totp_secret(db_pool, handle.id, secret, consumed_step)

    stored = _fetch_user_row(
        sync_conn,
        handle.id,
        ["totp_secret", "pending_totp_secret", "pending_totp_created_at", "last_totp_step"],
    )
    assert stored["pending_totp_secret"] is None
    assert stored["pending_totp_created_at"] is None
    assert stored["last_totp_step"] == consumed_step
    assert stored["totp_secret"] != secret  # encrypted at rest
    assert decrypt_value(stored["totp_secret"]) == secret

    # The app's own reader agrees.
    assert await get_totp_secret(db_pool, handle.id) == secret
    assert await get_pending_totp_secret(db_pool, handle.id) is None


# ---------------------------------------------------------------------------
# get_totp_secret fail-closed behavior
# ---------------------------------------------------------------------------

async def test_get_totp_secret_none_when_absent(db_pool, user_factory):
    """No totp_secret configured (and unknown user) -> None, not an error."""
    handle = user_factory()  # no totp_secret
    assert await get_totp_secret(db_pool, handle.id) is None
    assert await get_totp_secret(db_pool, 999_999) is None


async def test_get_totp_secret_undecryptable_raises(db_pool, user_factory, sync_conn):
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
