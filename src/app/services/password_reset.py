"""Password reset tokens and reset-completion.

Signed time-limited tokens (itsdangerous) carry the user's id and email
through the reset link; a SHA-256 hash of each token is stored on the
user row so the token is single-use. Successful reset clears the stored 
hash, the failed-login counter, and the lockout in one atomic UPDATE; 
existing sessions are then invalidated in a follow-up statement.

Defense in depth: itsdangerous validates signature and expiry; the DB
re-checks the token hash and the created_at window; the password is
re-validated for strength and against the current hash to reject reuse.
A request for a new token overwrites any previous hash, invalidating
the earlier link.

This module also owns the reset-token storage helpers
(store_reset_token_hash, verify_reset_token_hash), kept close to the
flow that actually uses them.
"""

import logging

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from psycopg_pool import AsyncConnectionPool
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.concurrency import run_in_threadpool
import hmac

from config import settings
from .tokens import RESET_TOKEN_MAX_AGE_SECONDS
from .db import get_db_cursor
from .sessions import delete_user_sessions
from .users import get_user_by_id
from .password_validation import validate_password_strength

logger = logging.getLogger(__name__)

_SALT = "password-reset"
_ph = PasswordHasher()

def generate_reset_token(email: str, user_id: int) -> str:
    """Generate a signed, time-limited password reset token.

    Args:
        email: The user's email address.
        user_id: The user's database ID.

    Returns:
        A URL-safe signed token string. The caller is responsible for
        storing hash_token(token) on the user record via
        store_reset_token_hash().
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    return signer.dumps({"email": email, "user_id": user_id}, salt=_SALT)


def validate_reset_token(token: str) -> dict | None:
    """Validate a password reset token's signature and expiry.

    This checks only that the token is well-formed, correctly signed,
    and not expired. The caller must also verify the token hash against
    the database via verify_reset_token_hash() to enforce single-use.

    Args:
        token: The signed token string from the reset URL.

    Returns:
        A dict with "email" and "user_id" keys, or None if invalid/expired.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        data = signer.loads(token, salt=_SALT, max_age=RESET_TOKEN_MAX_AGE_SECONDS)
        return data
    except (BadSignature, SignatureExpired) as e:
        logger.warning("Invalid or expired reset token: %s", e)
        return None

async def _is_same_as_current_password(
    pool: AsyncConnectionPool,
    user_id: int,
    new_password: str,
) -> bool:
    """Check whether new_password matches the user's current stored hash.
    
    Returns True if the new password is the same as the current one,
    False otherwise (including when the password hash can't be fetched).
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT password_hash FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()
        if not row or not row.get("password_hash"):
            return False
    
    try:
        await run_in_threadpool(_ph.verify, row["password_hash"], new_password)
        return True
    except VerifyMismatchError:
        return False
        

async def update_password_with_token(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    new_password: str,
) -> None:
    """Atomically verify the reset token and update the password.
    
    Combines four checks in a single SQL statement:
    1. user ID matches
    2. token hash matches the stored hash (single-use enforcement)
    3. token was created within the last RESET_TOKEN_MAX_AGE_SECONDS
       (defense-in-depth against itsdangerous validation bypass)
    4. user exists with current state
    
    Defense-in-depth checks before the UPDATE:
    - Password strength validation (against email/display_name blocklist)
    - Reject password reuse (new password must differ from current)
    
    On success, the password is updated, the token is cleared, and
    failed login state and existing sessions are reset.
    
    Raises:
        ValueError: If user doesn't exist, password fails strength
            validation, matches the current password, or the token is
            invalid/expired/already used.
    """
    user = await get_user_by_id(pool, user_id)
    if not user:
        raise ValueError(f"User {user_id} not found")
    
    error = validate_password_strength(
        new_password,
        email=user.email,
        display_name=user.display_name,
    )
    if error:
        raise ValueError(f"Password validation failed: {error}")
    
    if await _is_same_as_current_password(pool, user_id, new_password):
        raise ValueError("Please choose a different password from your current one.")
    
    new_hash = await run_in_threadpool(_ph.hash, new_password)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET password_hash = %s,
                   password_reset_token_hash = NULL,
                   password_reset_created_at = NULL,
                   failed_login_count = 0,
                   locked_until = NULL
               WHERE id = %s
                 AND password_reset_token_hash = %s
                 AND password_reset_created_at > CURRENT_TIMESTAMP 
                                                 - %s * INTERVAL '1 second'
               RETURNING id""",
            (new_hash, user_id, token_hash, RESET_TOKEN_MAX_AGE_SECONDS),
        )
        if not await cur.fetchone():
            raise ValueError("Invalid, expired, or already-used reset token")
    
    await delete_user_sessions(pool, user_id)
    logger.info("Password reset completed for user %d", user_id)


async def store_reset_token_hash(pool: AsyncConnectionPool, user_id: int, token_hash: str) -> None:
    """Store a hashed password reset token on the user record.

    Overwrites any previous token — only one outstanding reset token
    per user is allowed. The raw token is never stored; only its
    SHA-256 hash.

    Args:
        pool: Database connection pool.
        user_id: The user requesting a password reset.
        token_hash: SHA-256 hex digest of the raw reset token.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users 
               SET password_reset_token_hash = %s,
                   password_reset_created_at = CURRENT_TIMESTAMP
               WHERE id = %s""",
            (token_hash, user_id),
        )


async def verify_reset_token_hash(pool: AsyncConnectionPool, user_id: int, token_hash: str) -> bool:
    """Check whether a reset token hash matches the stored hash and is not expired.

    Uses constant-time comparison to prevent timing attacks. The DB-level
    expiry check is defense-in-depth alongside itsdangerous validation.
    
    Returns False if no token is stored, the user doesn't exist, the
    token has expired, or the hash doesn't match.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT password_reset_token_hash FROM users 
               WHERE id = %s
                 AND password_reset_token_hash IS NOT NULL
                 AND password_reset_created_at > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'""",
            (user_id, RESET_TOKEN_MAX_AGE_SECONDS),
        )
        row = await cur.fetchone()
        if not row or not row.get("password_reset_token_hash"):
            return False

    return hmac.compare_digest(row["password_reset_token_hash"], token_hash)