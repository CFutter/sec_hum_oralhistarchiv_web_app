"""Store SHA-256 session-token hashes and flash messages in PostgreSQL.

Callers receive opaque raw tokens for cookies. full, totp_setup, and
totp_recovery purposes are interpreted by session middleware; lookup checks
expiry and account authority, while revocation deletes rows. Flash helpers
operate on any existing row, including expired sessions.
"""

import logging
import secrets
from datetime import timedelta
from typing import Any, Literal, NamedTuple, TypeGuard

from psycopg import AsyncCursor, InterfaceError, OperationalError, sql
from psycopg_pool import AsyncConnectionPool, PoolTimeout

from app.duration_contract import validate_session_max_age_seconds
from config import settings

from .account_clock import database_now_cur
from .db import get_db_cursor
from .session_ids import hash_session_id
from .users import User, parse_user, user_columns_sql

logger = logging.getLogger(__name__)
SessionPurpose = Literal["full", "totp_setup", "totp_recovery"]

_SESSION_PURPOSES: tuple[SessionPurpose, ...] = (
    "full",
    "totp_setup",
    "totp_recovery",
)

_CLEANUP_MAX_BATCH_SIZE = 5_000
_CLEANUP_MAX_BATCHES = 100
_SETUP_SESSION_MAX_AGE_SECONDS = 600
_HARDENED_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


def _is_session_purpose(value: object) -> TypeGuard[SessionPurpose]:
    """Return whether the value is a recognized session-purpose string."""
    return isinstance(value, str) and value in _SESSION_PURPOSES


class SessionNotFoundError(ValueError):
    """A flash write targeted a missing session; distinguish invalid-category errors."""


class SessionLookup(NamedTuple):
    """User, purpose, and pending-flash flag; invalid lookups yield None, None, False."""

    user: User | None
    purpose: SessionPurpose | None
    flash_present: bool


def _session_lifetime(value: int, purpose: SessionPurpose) -> int:
    """Validate lifetime; cap setup/recovery at 600s and reject hardened full values over 8h."""
    lifetime = validate_session_max_age_seconds(value)
    if purpose not in _SESSION_PURPOSES:
        raise ValueError(f"Invalid session purpose: {purpose!r}")
    if purpose != "full":
        return min(lifetime, _SETUP_SESSION_MAX_AGE_SECONDS)
    if settings.is_hardened and lifetime > _HARDENED_SESSION_MAX_AGE_SECONDS:
        raise ValueError("Hardened sessions cannot exceed eight hours")
    return lifetime


async def _refresh_session_activity_cur(
    cur: AsyncCursor[Any], session_hash: str, purpose: SessionPurpose
) -> bool:
    """Refresh due activity only after locking and checking database wall time.

    Recent activity takes a read-only path. A due row may wait for another
    transaction, so recheck both deadlines after that lock, before any write.
    A competing refresh can make the row no longer due; the final read still
    requires a live row with the same authority.
    """
    await cur.execute(
        """SELECT expires_at, last_activity_at FROM sessions
           WHERE id = %s AND purpose = %s
             AND last_activity_at <= clock_timestamp() - %s * INTERVAL '1 second'
           FOR UPDATE""",
        (session_hash, purpose, settings.session_activity_update_interval_seconds),
    )
    due = await cur.fetchone()
    if due is not None:
        now = await database_now_cur(cur)
        idle_cutoff = now - timedelta(seconds=settings.session_idle_timeout_seconds)
        if due["expires_at"] <= now or due["last_activity_at"] <= idle_cutoff:
            return False
        await cur.execute(
            """UPDATE sessions SET last_activity_at = clock_timestamp()
               WHERE id = %s AND purpose = %s AND expires_at > clock_timestamp()
                 AND last_activity_at > clock_timestamp() - %s * INTERVAL '1 second'
               RETURNING id""",
            (session_hash, purpose, settings.session_idle_timeout_seconds),
        )
        return await cur.fetchone() is not None
    await cur.execute(
        """SELECT id FROM sessions WHERE id = %s AND purpose = %s
             AND expires_at > clock_timestamp()
             AND last_activity_at > clock_timestamp() - %s * INTERVAL '1 second'""",
        (session_hash, purpose, settings.session_idle_timeout_seconds),
    )
    return await cur.fetchone() is not None


async def create_session_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    ip_address: str,
    purpose: SessionPurpose,
    max_age_seconds: int,
) -> str:
    """Insert a token hash and return the raw token before the caller commits.

    Callers check eligibility and commit before exposing it. Require an integer
    lifetime of 60..31536000 seconds; setup/recovery is capped at 600 seconds and
    hardened full sessions cannot exceed eight hours. Invalid lifetime/purpose
    raises ValueError before token generation or I/O; database failures propagate.
    """
    if purpose not in _SESSION_PURPOSES:
        raise ValueError(f"Invalid session purpose: {purpose!r}")

    max_age_seconds = _session_lifetime(max_age_seconds, purpose)
    session_id = secrets.token_urlsafe(32)
    session_hash = hash_session_id(session_id)

    await cur.execute(
        """
        INSERT INTO sessions (
            id, user_id, expires_at, ip_address, purpose
        )
        VALUES (
            %s,
            %s,
            clock_timestamp() + %s * INTERVAL '1 second',
            %s,
            %s
        )
        """,
        (session_hash, user_id, max_age_seconds, ip_address, purpose),
    )

    return session_id


async def create_session(
    pool: AsyncConnectionPool,
    user_id: int,
    ip_address: str,
    max_age_seconds: int | None = None,
    purpose: SessionPurpose = "totp_setup",
) -> str:
    """Commit a session and return its raw cookie token.

    None lifetime uses SESSION_MAX_AGE_SECONDS; setup is capped at 600 seconds.
    Before acquiring a connection, reject lifetimes outside integer
    60..31536000 seconds, hardened full lifetimes over eight hours, and unknown
    or totp_recovery purposes with ValueError. Recovery requires atomic redemption;
    account eligibility is the caller's responsibility.
    """
    if purpose == "totp_recovery":
        raise ValueError("TOTP recovery sessions require atomic code redemption")

    lifetime = _session_lifetime(
        settings.session_max_age_seconds if max_age_seconds is None else max_age_seconds,
        purpose,
    )

    async with get_db_cursor(pool) as cur:
        session_id = await create_session_cur(
            cur,
            user_id=user_id,
            ip_address=ip_address,
            purpose=purpose,
            max_age_seconds=lifetime,
        )

    logger.info(
        "Session created for user %d from %s (purpose: %s, id: %s...)",
        user_id,
        ip_address,
        purpose,
        hash_session_id(session_id)[:8],
    )
    return session_id


async def get_session_user(pool: AsyncConnectionPool, session_id: str) -> SessionLookup:
    """Return the eligible session's user, purpose, and pending-flash flag.

    Missing, absolute/idle-expired or ineligible sessions yield (None, None, False).
    Eligible application requests refresh activity at a bounded write cadence;
    neither the touch nor a concurrent request can revive an expired row. Local users
    must be active and recovery state must match the purpose. Shibboleth users
    must be active, approved, enabled, from a trusted issuer, and use full
    purpose. Delete invalid-purpose, recovery-mismatch, or disallowed federated
    rows so later changes cannot revive them. Email/TOTP readiness is not checked.
    """
    session_hash = hash_session_id(session_id)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                """SELECT {}, s.purpose,
                          (s.flash_message IS NOT NULL) AS flash_present,
                          u.auth_method AS session_auth_method,
                          u.is_active AS session_user_active,
                          u.federated_status AS session_federated_status,
                          u.shibboleth_issuer AS session_shibboleth_issuer
                   FROM sessions s
                   JOIN users u ON s.user_id = u.id
                   WHERE s.id = %s
                     AND s.expires_at > clock_timestamp()
                     AND s.last_activity_at > clock_timestamp() - %s * INTERVAL '1 second'
                     AND (u.is_active OR u.auth_method = 'shibboleth')"""
            ).format(user_columns_sql("u")),
            (session_hash, settings.session_idle_timeout_seconds),
        )
        row = await cur.fetchone()
        if not row:
            return SessionLookup(None, None, False)

        raw_purpose = row["purpose"]
        if not _is_session_purpose(raw_purpose):
            await cur.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
            return SessionLookup(None, None, False)

        auth_method = row["session_auth_method"]
        is_active = row["session_user_active"]
        if auth_method == "shibboleth":
            issuer = row["session_shibboleth_issuer"]
            federated_session_allowed = (
                settings.shibboleth_enabled
                and is_active
                and row["session_federated_status"] == "approved"
                and isinstance(issuer, str)
                and issuer in settings.shibboleth_trusted_issuers
            )
            if not federated_session_allowed or raw_purpose != "full":
                await cur.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
                return SessionLookup(None, None, False)
        elif auth_method != "local" or not is_active:
            return SessionLookup(None, None, False)
        elif (raw_purpose == "totp_recovery") != bool(row["totp_recovery_required"]):
            # A recovery capability is valid only while the user row remains
            # in the corresponding recovery state. Delete rather than merely
            # ignoring mismatched rows so a later state change cannot revive
            # the same browser token.
            await cur.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
            return SessionLookup(None, None, False)

        if not await _refresh_session_activity_cur(cur, session_hash, raw_purpose):
            return SessionLookup(None, None, False)
        return SessionLookup(parse_user(row), raw_purpose, row["flash_present"])


async def delete_session(pool: AsyncConnectionPool, session_id: str) -> None:
    """Delete a session (logout)."""
    session_hash = hash_session_id(session_id)
    async with get_db_cursor(pool) as cur:
        await cur.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
    logger.info("Session deleted: %s...", session_hash[:8])


async def set_flash(
    pool: AsyncConnectionPool,
    session_id: str,
    message: str,
    category: str = "success",
) -> None:
    """Overwrite the session's pending flash, including on expired rows.

    Raise ValueError unless category is success, error, or info; raise
    SessionNotFoundError if the raw token identifies no row.
    """
    if category not in ("success", "error", "info"):
        raise ValueError(f"Invalid flash category: {category!r}")

    session_hash = hash_session_id(session_id)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE sessions
               SET flash_message = %s, flash_category = %s
               WHERE id = %s
               RETURNING id""",
            (message, category, session_hash),
        )
        if not await cur.fetchone():
            raise SessionNotFoundError(
                f"Cannot set flash: session {session_hash[:8]}... does not exist."
            )


async def set_flash_if_exists(
    pool: AsyncConnectionPool,
    session_id: str,
    message: str,
    category: str = "success",
) -> bool:
    """Store post-commit feedback; return False on missing rows or connection errors.

    OperationalError, InterfaceError, and PoolTimeout are logged and suppressed;
    invalid categories and other failures propagate as in set_flash.
    """
    try:
        await set_flash(pool, session_id, message, category)
    except SessionNotFoundError:
        logger.info(
            "Flash dropped: session %s... revoked mid-request",
            hash_session_id(session_id)[:8],
        )
        return False
    except (OperationalError, InterfaceError, PoolTimeout):
        logger.warning("Post-commit flash storage unavailable", exc_info=True)
        return False
    return True


async def restore_flash_if_empty(
    pool: AsyncConnectionPool,
    session_id: str,
    message: str,
    category: str = "success",
) -> bool:
    """Atomically restore feedback only if the row exists and has no flash.

    Return whether stored; return False on OperationalError, InterfaceError, or
    PoolTimeout after logging. Raise ValueError unless category is success,
    error, or info. Used after a redirect consumes but does not display a flash.
    """
    if category not in ("success", "error", "info"):
        raise ValueError(f"Invalid flash category: {category!r}")

    session_hash = hash_session_id(session_id)
    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """UPDATE sessions
                   SET flash_message = %s, flash_category = %s
                   WHERE id = %s AND flash_message IS NULL
                   RETURNING id""",
                (message, category, session_hash),
            )
            return await cur.fetchone() is not None
    except (OperationalError, InterfaceError, PoolTimeout):
        logger.warning("Redirect flash restoration unavailable", exc_info=True)
        return False


async def consume_flash(pool: AsyncConnectionPool, session_id: str) -> tuple[str, str] | None:
    """Atomically consume and return (message, category), or None if absent.

    The row lock prevents concurrent calls from consuming the same stored flash;
    this does not guarantee browser delivery after the transaction commits.
    """
    session_hash = hash_session_id(session_id)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """WITH old AS (
                SELECT flash_message, flash_category
                FROM sessions
                WHERE id = %s AND flash_message IS NOT NULL
                FOR UPDATE
            )
            UPDATE sessions
            SET flash_message = NULL, flash_category = NULL
            FROM old
            WHERE sessions.id = %s
            RETURNING old.flash_message, old.flash_category""",
            (session_hash, session_hash),
        )
        row = await cur.fetchone()

        if not row:
            return None
        return row["flash_message"], row["flash_category"]


async def cleanup_expired_sessions(
    pool: AsyncConnectionPool,
    *,
    batch_size: int = 1_000,
    max_batches: int = 20,
) -> int:
    """Commit bounded batches deleting absolute- or idle-expired sessions; return count.

    Skip rows locked elsewhere; stop on a short batch. Earlier batches remain
    committed if a later one fails. Raise ValueError unless batch_size is
    1..5000 and max_batches is 1..100.
    """
    if not 1 <= batch_size <= _CLEANUP_MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_CLEANUP_MAX_BATCH_SIZE}")
    if not 1 <= max_batches <= _CLEANUP_MAX_BATCHES:
        raise ValueError(f"max_batches must be between 1 and {_CLEANUP_MAX_BATCHES}")

    total = 0

    for _ in range(max_batches):
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """
                WITH expired AS (
                    SELECT id
                    FROM sessions
                    WHERE expires_at <= clock_timestamp()
                       OR last_activity_at <= clock_timestamp() - %s * INTERVAL '1 second'
                    ORDER BY expires_at
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                DELETE FROM sessions AS session
                USING expired
                WHERE session.id = expired.id
                """,
                (settings.session_idle_timeout_seconds, batch_size),
            )
            deleted = cur.rowcount

        total += deleted
        if deleted < batch_size:
            break

    if total:
        logger.info("Cleaned up %d expired sessions", total)

    return total
