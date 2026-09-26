"""Store SHA-256 session-token hashes and flash messages in PostgreSQL.

Callers receive opaque raw tokens for cookies. full, totp_setup, and
totp_recovery purposes are interpreted by session middleware; lookup checks
expiry and account authority, while revocation deletes rows. Flash helpers
operate on any existing row, including expired sessions.
"""

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, NamedTuple, TypeGuard

from psycopg import AsyncCursor, InterfaceError, OperationalError, sql
from psycopg_pool import AsyncConnectionPool, PoolTimeout

from config import settings

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


async def create_session_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    ip_address: str,
    purpose: SessionPurpose,
    max_age_seconds: int,
) -> str:
    """Insert a hashed token; return its raw value before the caller commits.

    The caller must check account eligibility and commit before exposing the
    token. max_age_seconds is added to current UTC time without range checks.
    Raise ValueError for an unknown purpose; database failures propagate.
    """
    if purpose not in _SESSION_PURPOSES:
        raise ValueError(f"Invalid session purpose: {purpose!r}")

    session_id = secrets.token_urlsafe(32)
    session_hash = hash_session_id(session_id)
    expires_at = datetime.now(UTC) + timedelta(seconds=max_age_seconds)

    await cur.execute(
        """
        INSERT INTO sessions (
            id, user_id, expires_at, ip_address, purpose
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (session_hash, user_id, expires_at, ip_address, purpose),
    )

    return session_id


async def create_session(
    pool: AsyncConnectionPool,
    user_id: int,
    ip_address: str,
    max_age_seconds: int | None = None,
    purpose: SessionPurpose = "totp_setup",
) -> str:
    """Commit a session and return its raw token for the caller's cookie.

    None lifetime uses SESSION_MAX_AGE_SECONDS; account eligibility is the
    caller's responsibility. Raise ValueError for an unknown or totp_recovery
    purpose; recovery tokens require redeem_totp_recovery's atomic workflow.
    """
    if purpose == "totp_recovery":
        raise ValueError("TOTP recovery sessions require atomic code redemption")

    lifetime = settings.session_max_age_seconds if max_age_seconds is None else max_age_seconds

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

    Missing/expired/ineligible sessions yield (None, None, False). Local users
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
                     AND s.expires_at > CURRENT_TIMESTAMP
                     AND (u.is_active OR u.auth_method = 'shibboleth')"""
            ).format(user_columns_sql("u")),
            (session_hash,),
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
    """Commit batches deleting sessions expired before transaction start; return count.

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
                    WHERE expires_at < CURRENT_TIMESTAMP
                    ORDER BY expires_at
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                DELETE FROM sessions AS session
                USING expired
                WHERE session.id = expired.id
                """,
                (batch_size,),
            )
            deleted = cur.rowcount

        total += deleted
        if deleted < batch_size:
            break

    if total:
        logger.info("Cleaned up %d expired sessions", total)

    return total
