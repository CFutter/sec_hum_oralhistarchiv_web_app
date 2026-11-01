"""Bootstrap the first local administrator through an operator-only command.

An advisory transaction lock serializes concurrent invocations. The command
owns password input; long-running services do not receive bootstrap credentials.
"""

import logging

from psycopg_pool import AsyncConnectionPool

from app.credentials import validate_seed_credentials

from .crypto import password_hasher
from .db import get_db_cursor
from .password_validation import validate_password_strength
from .password_work import run_password_work

logger = logging.getLogger(__name__)

# Any stable, app-unique bigint; serializes concurrent seeders only.
_SEED_ADMIN_LOCK_KEY = 0x5EED_AD01


async def seed_admin_user(
    pool: AsyncConnectionPool,
    email: str,
    password: str,
) -> None:
    """Create a public-tier, verified local administrator if none exists.

    TOTP must be enrolled at first login. Existing administrators skip credential
    checks; concurrent seeders recheck under an advisory transaction lock.
    Raises RuntimeError for invalid seed credentials/password strength or an
    existing seed email; never elevates an existing user. The creation log uses
    the configured address-redaction policy.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT 1 FROM users WHERE is_admin = true LIMIT 1")
        if await cur.fetchone() is not None:
            return

    try:
        email = validate_seed_credentials(email, password)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    password_error = validate_password_strength(password, email=email)
    if password_error:
        raise RuntimeError(
            f"ADMIN_SEED_PASSWORD rejected: {password_error} "
            "Choose a stronger password and rerun the bootstrap command."
        )

    # Hash BEFORE taking the lock — argon2 is deliberately slow, and the
    # advisory lock should be held only for the two SELECTs and the INSERT.
    password_hash = await run_password_work(password_hasher.hash, password)

    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SEED_ADMIN_LOCK_KEY,))

        await cur.execute("SELECT 1 FROM users WHERE is_admin = true LIMIT 1")
        if await cur.fetchone():
            logger.debug("Admin user already exists — skipping seed.")
            return

        await cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
        if await cur.fetchone():
            raise RuntimeError(
                f"User {email} already exists; refusing to promote via seed. "
                f"Use the admin UI to grant admin status to existing users, "
                f"or give the bootstrap command a fresh email address."
            )

        await cur.execute(
            """INSERT INTO users (email, display_name, password_hash, auth_method,
                                  access_tier, is_admin, email_verified)
               VALUES (%s, 'Admin', %s, 'local', 'public', true, true)""",
            (email, password_hash),
        )

    logger.warning(
        "Initial administrator %s created. Complete authenticator enrollment "
        "before opening public access.",
        email,
    )
