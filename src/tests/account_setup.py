"""Test-only account/credential setup; production uses registration and TOTP workflows."""

from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from app.credentials import LOCAL_PASSWORD_MAX_CHARS, normalize_email
from app.services.crypto import encrypt_value, password_hasher
from app.services.db import get_db_cursor
from app.services.password_work import run_password_work
from app.services.users import User, UserAlreadyExistsError, insert_unverified_local_user_cur


async def create_local_user(
    pool: AsyncConnectionPool,
    *,
    email: str,
    display_name: str,
    password: str,
    affiliation: str | None = None,
    country: str | None = None,
) -> User:
    """Create a new local user without an enrolled authenticator.

    Only the verified /setup-totp flow may activate a TOTP secret.
    The access tier is always "public" on creation; any elevation
    happens through admin intervention afterwards (a seeded admin
    therefore starts at the public tier and must raise their own
    tier via the admin dashboard if needed).

    Raises:
        UserAlreadyExistsError: If the email is already registered.
        RuntimeError: If the INSERT unexpectedly returns no row.
    """
    if len(password) > LOCAL_PASSWORD_MAX_CHARS:
        raise ValueError("Password exceeds the supported length")
    normalized = normalize_email(email)
    if normalized is None:
        raise ValueError("Please enter a valid email address.")
    email = normalized
    password_hash = await run_password_work(password_hasher.hash, password)
    try:
        async with get_db_cursor(pool) as cur:
            return await insert_unverified_local_user_cur(
                cur,
                email=email,
                display_name=display_name,
                password_hash=password_hash,
                affiliation=affiliation,
                country=country,
            )
    except UniqueViolation as e:
        raise UserAlreadyExistsError(email) from e


async def store_pending_totp_secret(pool: AsyncConnectionPool, user_id: int, secret: str) -> None:
    """Encrypt and store a pending TOTP secret for secure enrollment.

    The secret is generated server-side, encrypted, and stored in the
    database so that the POST handler can retrieve it by user ID rather
    than trusting a client-submitted hidden form field. Overwrites any
    previous pending secret for this user.

    Args:
        pool: Database connection pool.
        user_id: The user enrolling a new authenticator.
        secret: The base32-encoded TOTP secret to store temporarily (plaintext).
    """
    encrypted = encrypt_value(secret)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET pending_totp_secret = %s,
                   pending_totp_created_at = CURRENT_TIMESTAMP
               WHERE id = %s""",
            (encrypted, user_id),
        )
