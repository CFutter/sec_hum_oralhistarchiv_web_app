"""Session management — server-side sessions with database storage.

Sessions are stored in the database, not in cookies. The cookie
only holds a random session ID. This prevents session tampering
and allows server-side invalidation (logout, expiry cleanup).

Session lifecycle:
1. User authenticates (password + TOTP, or Shibboleth callback)
2. create_session() generates a random ID, stores it in DB, returns it
3. The auth route sets a signed cookie with the session ID
4. On each request, session middleware reads the cookie, calls get_session_user()
5. get_session_user() looks up the session in DB, returns the (user, purpose, flash_present) if valid, 
where flash_present indicates a pending flash message to be consumed.
6. On logout, delete_session() removes the DB row

Session purposes:
- "full":       Normal session — full application access.
- "totp_setup": Limited session — can only access /setup-totp and /logout.
                Created during registration and login-without-TOTP.
                Upgraded to "full" after TOTP enrollment completes.
"""

from datetime import datetime, timedelta, timezone
import logging
import secrets
import hashlib
from typing import Literal, NamedTuple

from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from .db import get_db_cursor
from .users import User, parse_user, user_columns_sql

from config import settings

logger = logging.getLogger(__name__)
SessionPurpose = Literal["full", "totp_setup"]

class SessionLookup(NamedTuple):
    """Result of a session lookup: the user, the session's purpose, and whether
    a flash message is pending. All fields carry the 'empty' values
    (None, None, False) when the session is invalid/expired/inactive.
    """
    user: User | None
    purpose: SessionPurpose | None
    flash_present: bool


def _hash_session_id(session_id: str) -> str:
    """Creates a hash of the session id for database storage."""
    return hashlib.sha256(session_id.encode()).hexdigest()


async def create_session(
    pool: AsyncConnectionPool,
    user_id: int,
    ip_address: str,
    max_age_seconds: int | None = None,
    purpose: SessionPurpose = "totp_setup",
) -> str:
    """Create a new session for an authenticated user.

    Returns the session ID (a random token) to be stored in a cookie.

    Args:
        purpose: Session capability level. "full" for normal sessions,
            "totp_setup" for limited sessions that can only complete
            TOTP enrollment. Defaults to the more restrictive
            "totp_setup" — callers that need a full session must pass
            purpose="full" explicitly. This fail-closed default prevents
            a caller from accidentally creating a fully-authenticated
            session.
    """
    max_age_seconds = settings.session_max_age_seconds if max_age_seconds is None else max_age_seconds

    if purpose not in ("full", "totp_setup"):
        raise ValueError(f"Invalid session purpose: {purpose!r}")

    session_id = secrets.token_urlsafe(32)
    session_hash = _hash_session_id(session_id)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=max_age_seconds
    )

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """INSERT INTO sessions (id, user_id, expires_at, ip_address, purpose)
               VALUES (%s, %s, %s, %s, %s)""",
            (session_hash, user_id, expires_at, ip_address, purpose),
        )

    logger.info(
        "Session created for user %d from %s (purpose: %s, id: %s...)",
        user_id, ip_address, purpose, session_id[:8]
    )
    return session_id


async def get_session_user(pool: AsyncConnectionPool, session_id: str) -> SessionLookup:
    """Look up a valid session; return (user, purpose, flash_present).

    flash_present is True when the row has a pending flash, so the caller can
    skip the read-and-clear query entirely when there is nothing to show.
    All three are falsy (None, None, False) if the session is invalid,
    expired, or belongs to an inactive user.
    """
    session_hash = _hash_session_id(session_id)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                """SELECT {}, s.purpose,
                          (s.flash_message IS NOT NULL) AS flash_present
                   FROM sessions s
                   JOIN users u ON s.user_id = u.id
                   WHERE s.id = %s
                     AND s.expires_at > CURRENT_TIMESTAMP
                     AND u.is_active"""
            ).format(user_columns_sql("u")),
            (session_hash,),
        )
        row = await cur.fetchone()
        if not row:
            return SessionLookup(None, None, False)      
        return SessionLookup(parse_user(row), row["purpose"], row["flash_present"]) 

async def delete_session(pool: AsyncConnectionPool, session_id: str) -> None:
    """Delete a session (logout)."""
    session_hash = _hash_session_id(session_id)
    async with get_db_cursor(pool) as cur:
        await cur.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
    logger.info("Session deleted: %s...", session_id[:8])

async def delete_user_sessions(pool: AsyncConnectionPool, user_id: int) -> None:
    """Delete all sessions for a user (force logout everywhere)."""
    async with get_db_cursor(pool) as cur:
        await cur.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    logger.info("All sessions deleted for user %d", user_id)


async def upgrade_session_purpose(
    pool: AsyncConnectionPool, session_id: str, new_purpose: SessionPurpose
) -> None:
    """Upgrade a session's purpose (e.g., totp_setup → full).

    Raises ValueError if the session doesn't exist (silent no-op would
    leave callers thinking the upgrade succeeded when it didn't).
    """
    if new_purpose not in ("full", "totp_setup"):
        raise ValueError(
            f"Invalid session purpose: {new_purpose!r}. "
            f"Expected one of: 'full', 'totp_setup'."
        )

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE sessions SET purpose = %s WHERE id = %s RETURNING id",
            (new_purpose, _hash_session_id(session_id)),
        )
        if not await cur.fetchone():
            raise ValueError(
                f"Cannot upgrade session purpose: session {session_id[:8]}... "
                f"does not exist."
            )


async def set_flash(
    pool: AsyncConnectionPool,
    session_id: str,
    message: str,
    category: str = "success",
) -> None:
    """Store a flash message on a session for display on the next request.

    The message is consumed (cleared) on the next page load via
    consume_flash(). Overwrites any existing flash on the session.

    Args:
        pool: Database connection pool.
        session_id: The session that will see the message.
        message: The text to display.
        category: "success", "error", or "info" — controls the visual style.

    Raises:
        ValueError: If category is invalid, or if the session doesn't exist
            (flash messages on missing sessions silently disappearing is a
            class of bugs we want to catch loudly).
    """
    if category not in ("success", "error", "info"):
        raise ValueError(f"Invalid flash category: {category!r}")

    session_hash = _hash_session_id(session_id)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE sessions
               SET flash_message = %s, flash_category = %s
               WHERE id = %s
               RETURNING id""",
            (message, category, session_hash),
        )
        if not await cur.fetchone():
            raise ValueError(
                f"Cannot set flash: session {session_id[:8]}... does not exist."
            )


async def consume_flash(pool: AsyncConnectionPool, session_id: str) -> tuple[str, str] | None:
    """Atomically read and clear the flash message on a session.

    Returns the (message, category) tuple if a flash is present, or
    None if the session has no pending flash. The read-and-clear is
    a single SQL statement with FOR UPDATE, so concurrent requests
    on the same session are guaranteed exactly-once delivery — only
    one tab sees the message; others see None.

    Args:
        pool: Database connection pool.
        session_id: The raw session ID (will be hashed for lookup).
    """
    session_hash = _hash_session_id(session_id)
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

async def cleanup_expired_sessions(pool: AsyncConnectionPool) -> int:
    """Remove expired sessions from the database.

    Returns the number of sessions cleaned up.
    Call periodically (e.g., once per hour via background task).
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP"
        )
        # Get the count of deleted rows
        count = cur.rowcount
    if count > 0:
        logger.info("Cleaned up %d expired sessions.", count)
    return count


