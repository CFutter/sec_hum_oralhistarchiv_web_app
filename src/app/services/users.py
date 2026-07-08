"""User accounts: data model and CRUD.

Owns the User dataclass, the column list / SELECT builder, and all
operations that create, read, or update user rows. Authentication
(passwords, lockout) lives in authentication.py; TOTP secrets in totp.py;
access-tier checks in access_tiers.py.

Schema is enforced from two sides: USER_COLUMNS lists the SQL columns,
the User dataclass mirrors them, and validate_user_schema() asserts the
two stay in sync at startup. The SELECT builder user_columns_sql() (and
its cached USER_COLUMNS_SQL) is the single source of truth for what gets
fetched — adding a column means updating USER_COLUMNS and the dataclass,
nothing else.

The reaper (reap_unverified_accounts) runs on a schedule to clean up
local accounts that never completed email verification. Shibboleth
accounts are exempt — they're auto-verified at creation.
"""

from datetime import datetime
import logging
from dataclasses import dataclass, fields as dataclass_fields
from typing import Literal

from psycopg import sql
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool
from psycopg.sql import Composable

from argon2 import PasswordHasher
from starlette.concurrency import run_in_threadpool

from .access_tiers import AccessTier
from .db import get_db_cursor
from .crypto import audit_email_hash
from config import settings


logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")

_ph = PasswordHasher()
DISPLAY_NAME_MAX_LENGTH = 200

AuthMethod = Literal["local", "shibboleth"]

class UserAlreadyExistsError(ValueError):
    """Raised by create_local_user when the email is already registered."""
    def __init__(self, email: str):
        self.email = email
        super().__init__(f"User already exists [{email}]")

@dataclass
class User:
    """Represents an authenticated user."""
    id: int
    email: str
    display_name: str | None
    affiliation: str | None
    country: str | None
    auth_method: AuthMethod
    access_tier: AccessTier
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    totp_configured: bool
    is_admin: bool = False 
    email_verified: bool = False
    last_totp_step: int | None = None


def normalize_display_name(raw: str) -> str:
    """Strip, validate, and return a clean display name. Raises ValueError if invalid."""
    name = raw.strip()
    if not name:
        raise ValueError("Display name cannot be empty.")
    if len(name) > DISPLAY_NAME_MAX_LENGTH:
        raise ValueError(f"Display name must be at most {DISPLAY_NAME_MAX_LENGTH} characters.")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name):   # control chars (or whatever the current ban uses)
        raise ValueError("Display name cannot contain control characters.")
    return name


def parse_user(row: dict) -> User:
    """Parse a database row into a User dataclass.

    The `totp_configured` field is computed at the SQL layer via
    `(totp_secret IS NOT NULL) AS totp_configured` so the encrypted
    secret never leaves the database for routes that don't need it.
    Use get_totp_secret() for routes that need to verify TOTP codes.
    """
    return User(
        id=row["id"],
        email=row["email"],
        display_name=row.get("display_name"),
        affiliation=row.get("affiliation"),
        country=row.get("country"),
        auth_method=row["auth_method"],
        access_tier=row["access_tier"],
        is_active=row["is_active"],
        created_at=row["created_at"],
        last_login=row.get("last_login"),
        totp_configured=row.get("totp_configured", False),
        is_admin=row.get("is_admin", False),
        email_verified=row.get("email_verified", False),
        last_totp_step=row.get("last_totp_step"),
    )


USER_COLUMNS = [
    "id", "email", "display_name", "affiliation", "country",
    "auth_method", "access_tier", "is_active", "created_at", "last_login",
    "is_admin", "email_verified", "last_totp_step" 
]
_USER_COMPUTED_FIELDS = {"totp_configured"}

def validate_user_schema() -> None:
    """Verify that USER_COLUMNS and User dataclass fields are in sync.

    Catches drift between the SQL column list and the Python dataclass.
    Raises AssertionError with a clear message if they diverge.

    _USER_COMPUTED_FIELDS are excluded from the dataclass side because
    they're derived in SQL (e.g., totp_configured comes from
    `(totp_secret IS NOT NULL) AS totp_configured`).
    """
    dataclass_field_names = {
        f.name for f in dataclass_fields(User)
    } - _USER_COMPUTED_FIELDS

    select_columns = set(USER_COLUMNS)

    missing_from_dataclass = select_columns - dataclass_field_names
    missing_from_select = dataclass_field_names - select_columns

    errors = []
    if missing_from_dataclass:
        errors.append(
            f"Columns in USER_COLUMNS but not on User: {missing_from_dataclass}"
        )
    if missing_from_select:
        errors.append(
            f"Fields on User but not in USER_COLUMNS: {missing_from_select}"
        )

    if errors:
        raise AssertionError(
            "USER_COLUMNS / User mismatch: " + "; ".join(errors)
        )

def user_columns_sql(table_alias: str | None = None) -> sql.Composed:
    """Build the SELECT column list for user rows.
    
    Includes a computed `totp_configured` boolean derived from
    `totp_secret IS NOT NULL`. The actual totp_secret is not fetched
    in the default SELECT — use get_totp_secret() for routes that
    need to verify TOTP codes.

    Args:
        table_alias: Optional alias for joined queries (e.g., "u" produces
                     "u.id, u.email, ..."). None for unaliased queries.

    Single source of truth: any column add/remove updates USER_COLUMNS
    and all callers benefit automatically.
    """
    totp_part: Composable
    if table_alias:
        identifier_parts = [
            sql.Identifier(table_alias, col) for col in USER_COLUMNS
        ]
        totp_part = sql.SQL("({}.totp_secret IS NOT NULL) AS totp_configured").format(
            sql.Identifier(table_alias)
        )
    else:
        identifier_parts = [sql.Identifier(col) for col in USER_COLUMNS]
        totp_part = sql.SQL("(totp_secret IS NOT NULL) AS totp_configured")

    return sql.SQL(", ").join(identifier_parts + [totp_part])

USER_COLUMNS_SQL = user_columns_sql()


async def get_user_by_id(pool: AsyncConnectionPool, user_id: int) -> User | None:
    """Look up a user by database ID."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM users WHERE id = %s").format(USER_COLUMNS_SQL),
            (user_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return parse_user(row)


async def get_user_by_email(pool: AsyncConnectionPool, email: str) -> User | None:
    """Look up a user by email address (case-insensitive)."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM users WHERE LOWER(email) = LOWER(%s)").format(USER_COLUMNS_SQL),
            (email,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return parse_user(row)


async def create_local_user(
    pool: AsyncConnectionPool,
    email: str,
    display_name: str,
    password: str,
    totp_secret: str | None = None,
    affiliation: str = "",
    country: str = "",
) -> User:
    """Create a new local user with password and optional TOTP secret.

    In two-step registration, totp_secret is None at account creation and
    configured later via /setup-totp. The access tier is always "public" on
    creation; any elevation happens through admin intervention afterwards
    (a seeded admin therefore starts at the public tier and must raise
    their own tier via the admin dashboard if needed).

    Raises:
        UserAlreadyExistsError: If the email is already registered.
        RuntimeError: If the INSERT unexpectedly returns no row.
    """
    password_hash = await run_in_threadpool(_ph.hash, password)
    email = email.strip().lower()
    display_name_normalized = normalize_display_name(display_name)

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                sql.SQL("""INSERT INTO users (email, display_name, affiliation, country,
                    password_hash, totp_secret, auth_method, access_tier)
                    VALUES (%s, %s, %s, %s, %s, %s, 'local', 'public')
                    RETURNING {}""").format(USER_COLUMNS_SQL),
                (email, display_name_normalized, affiliation or None, country or None,
                 password_hash, totp_secret),
            )
            row = await cur.fetchone()
    except UniqueViolation as e:
        raise UserAlreadyExistsError(email) from e
        

    if not row:        
        raise RuntimeError(f"Failed to create user: {email}") 

    logger.info("Created local user: %s", email)
    return parse_user(row)


async def create_shibboleth_user(
    pool: AsyncConnectionPool,
    email: str,
    display_name: str | None = None,
    affiliation: str | None = None,
    country: str | None = None,
) -> User | None:
    """Create or update a Shibboleth user from IdP attributes.

    Auto-provisions on first login; on subsequent logins updates display
    name, affiliation, country, and last_login.

    The user created via shibboleth will always be registered, as an institutional account 
    will be needed for shibboleth users. "Vetting" and thus access to sensitive
    data can only be acquired through admin intervention.

    Returns None (does NOT raise) when no row is returned — either because
    the email already belongs to a local account (the ON CONFLICT ... WHERE
    auth_method = 'shibboleth' guard skips the update, so RETURNING is empty)
    or a genuine race/failover. Both cases must be treated as login failure
    by the caller — never issue a session for a None result.
    """
    email = email.strip().lower()
    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                sql.SQL("""INSERT INTO users (
                        email, display_name, affiliation, country,
                        auth_method, access_tier, email_verified, last_login
                    )
                    VALUES (%s, %s, %s, %s, 'shibboleth', 'registered', true, CURRENT_TIMESTAMP)
                    ON CONFLICT ((LOWER(email))) DO UPDATE SET
                        display_name = COALESCE(EXCLUDED.display_name, users.display_name),
                        affiliation = COALESCE(EXCLUDED.affiliation, users.affiliation),
                        country = COALESCE(EXCLUDED.country, users.country),
                        last_login = CURRENT_TIMESTAMP
                    WHERE users.auth_method = 'shibboleth' -- SECURITY: never merge into a local account
                    RETURNING {}""").format(USER_COLUMNS_SQL),
                (email, display_name, affiliation, country),
            )
            row = await cur.fetchone()

    except UniqueViolation:
        return None
    if not row:
        return None

    logger.info("Shibboleth user provisioned/updated: %s", email)
    return parse_user(row)


async def update_last_login(pool: AsyncConnectionPool, user_id: int) -> None:
    """Record a successful login timestamp."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id,),
        )


async def update_access_tier(
    pool: AsyncConnectionPool, user_id: int, new_tier: AccessTier
) -> None:
    """Change a user's access tier (admin action).
    
    Raises ValueError if the user doesn't exist.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET access_tier = %s WHERE id = %s RETURNING id",
            (new_tier, user_id),
        )
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")
    
    logger.info("User %d access tier changed to: %s", user_id, new_tier)


async def update_display_name(pool: AsyncConnectionPool, user_id: int, new_name: str) -> None:
    """Update a user's display name (self-service).

    Validates and normalizes the name before writing:
    - Strips leading/trailing whitespace
    - Rejects empty results
    - Rejects control characters
    - Enforces the max length

    Raises:
        ValueError: If the name is empty, too long, contains control
            characters, or the user doesn't exist.
    """
    normalized = normalize_display_name(new_name)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET display_name = %s WHERE id = %s RETURNING id",
            (normalized, user_id),
        )
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")

    logger.info("Display name updated for user %d", user_id)


async def get_all_users(pool: AsyncConnectionPool) -> list[User]:
    """Retrieve all users, ordered by creation date (newest first).

    Used by the admin dashboard for user management.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM users ORDER BY created_at DESC").format(
                USER_COLUMNS_SQL
            )
        )
        return [parse_user(row) for row in await cur.fetchall()]


async def set_user_active(pool: AsyncConnectionPool, user_id: int, is_active: bool) -> None:
    """Set a user's is_active flag.
        
    Asymmetric behavior by design:
    - Reactivating (is_active=True) also clears failed_login_count and
    locked_until, so an admin reactivating a user gives them an immediate
    fresh start (no leftover rate-limit lockout from before deactivation).
    - Deactivating (is_active=False) does NOT clear lockout state, preserving
    the audit signal of why the account was disabled.

    Raises ValueError if the user doesn't exist.
    """
    if is_active:
        sql_text = """
            UPDATE users
            SET is_active = true,
                failed_login_count = 0,
                locked_until = NULL
            WHERE id = %s
            RETURNING id
        """
        params = (user_id,)
    else:
        sql_text = """
            UPDATE users
            SET is_active = false
            WHERE id = %s
            RETURNING id
        """
        params = (user_id,)
    
    async with get_db_cursor(pool) as cur:
        await cur.execute(sql_text, params)
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")


async def set_user_admin(pool: AsyncConnectionPool, user_id: int, is_admin: bool) -> None:
    """Set is_admin to a specific value. Idempotent."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET is_admin = %s WHERE id = %s RETURNING id",
            (is_admin, user_id),
        )
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")


async def reap_unverified_accounts(
    pool: AsyncConnectionPool,
    max_age_days: int | None = None,
) -> int:
    """Delete local accounts that were never verified.
    
    Removes users where:
    - auth_method = 'local' (Shibboleth users are auto-verified)
    - email_verified = false
    - created_at < (now - max_age_days)
    
    Returns the number of deleted users.
    """
    max_age_days = settings.unverified_reap_after_days if max_age_days is None else max_age_days
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """DELETE FROM users
               WHERE auth_method = 'local'
                 AND email_verified = false
                 AND created_at < CURRENT_TIMESTAMP - %s * INTERVAL '1 day'
               RETURNING id, email""",
            (max_age_days,),
        )
        deleted = await cur.fetchall()
    
    if deleted:
        logger.info(
            "Reaped %d unverified accounts (older than %d days)",
            len(deleted), max_age_days,
        )
        # Audit each deletion individually for SIEM filtering
        for row in deleted:
            audit_logger.info(
                "user_reaped_unverified",
                extra={
                    "event_type": "user_reaped_unverified",
                    "user_id": row["id"],
                    "email": audit_email_hash(row["email"])[:16],
                    "reason": "verification_not_completed",
                    "max_age_days": max_age_days,
                },
            )
    
    return len(deleted)
