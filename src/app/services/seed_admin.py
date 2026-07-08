"""Seed initial admin account from environment variables.

Creates the first admin user on startup if:
1. ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD are set
2. No admin user exists yet in the database

Once any admin exists, seeding is skipped — the env vars become inert.
This avoids re-seeding on every restart and allows safe removal of the
env vars after initial setup.
"""

import logging

from psycopg_pool import AsyncConnectionPool

from .db import get_db_cursor
from .users import create_local_user
from .password_validation import validate_password_strength

logger = logging.getLogger(__name__)


async def seed_admin_user(
    pool: AsyncConnectionPool,
    email: str,
    password: str,
) -> None:
    """Seed an admin user if no admin exists yet.

    The seeded user is created with:
    - auth_method: local
    - access_tier: public (access tier can't be set on user creation, only by admin intervention)
    - is_admin: True
    - TOTP: not configured (must be set up on first login)
    
    Refuses to elevate existing users — use the admin UI for that.

    Args:
        pool: Database connection pool.
        email: Admin email address from ADMIN_SEED_EMAIL.
        password: Admin password from ADMIN_SEED_PASSWORD.
    
    Raises:
        RuntimeError: If a user with the seed email already exists, or
            if the password fails strength validation.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT 1 FROM users WHERE is_admin = true LIMIT 1")
        if await cur.fetchone():
            logger.debug("Admin user already exists — skipping seed.")
            return
        
        await cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
        existing = await cur.fetchone()

    if existing:
        raise RuntimeError(
            f"User {email} already exists; refusing to promote via seed. "
            f"Use the admin UI to grant admin status to existing users, "
            f"or set ADMIN_SEED_EMAIL to a fresh email address."
        )

    if len(password) < 12:
        raise RuntimeError(
            "ADMIN_SEED_PASSWORD must be at least 12 characters long."
        )
    password_error = validate_password_strength(password, email=email)
    if password_error:
        raise RuntimeError(
            f"ADMIN_SEED_PASSWORD rejected: {password_error} "
            "Choose a stronger password and restart."
        )

    user = await create_local_user(
        pool,
        email=email.strip().lower(),
        display_name="Admin",
        password=password,
    )

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET is_admin = true, email_verified = true WHERE id = %s",
            (user.id,),
        )

    logger.warning(
        "Admin user %s created. REMOVE ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD "
        "from .env now — they are no longer needed and their presence is a "
        "security risk if .env is leaked.",
        email,
    )