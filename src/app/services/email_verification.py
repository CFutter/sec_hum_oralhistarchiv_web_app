"""Email verification tokens — signed, time-limited, single-use.

Mirrors the password_reset module: itsdangerous for signing,
SHA-256 hash stored on the user record for single-use enforcement.

Flow:
1. User registers → generate_verification_token() creates a signed token →
   store_verification_token_hash() saves its hash on the user record →
   verification email sent (or link logged in dev mode)
2. User clicks the link → validate_verification_token() checks signature
   and expiry → confirm_email_verification() atomically verifies the
   stored hash and marks the user as verified
3. After verification, the user can proceed to TOTP enrollment

Security:
- Tokens are HMAC-signed with SECRET_KEY
- Tokens expire after 24 hours
- Tokens are single-use: confirm_email_verification() clears the stored
  hash atomically with the verification flag, so a second click fails
- Only one outstanding token per user: generating a new token overwrites
  the previous hash, invalidating any earlier link
"""
import logging

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from psycopg_pool import AsyncConnectionPool

from config import settings
from .db import get_db_cursor

logger = logging.getLogger(__name__)

_SALT = "email-verification"
VERIFICATION_TOKEN_MAX_AGE_SECONDS = 86400  # 24 hours




def generate_verification_token(email: str, user_id: int) -> str:
    """Generate a signed, time-limited email verification token.

    Args:
        email: The user's email address.
        user_id: The user's database ID.

    Returns:
        A URL-safe signed token string. The caller is responsible for
        storing hash_token(token) on the user record via
        store_verification_token_hash().
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    return signer.dumps({"email": email, "user_id": user_id}, salt=_SALT)


def validate_verification_token(token: str) -> dict | None:
    """Validate a verification token's signature and expiry.

    This checks only that the token is well-formed, correctly signed,
    and not expired. The caller must also call confirm_email_verification()
    to enforce single-use against the stored hash.

    Args:
        token: The signed token string from the verification URL.

    Returns:
        A dict with "email" and "user_id" keys, or None if invalid/expired.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        return signer.loads(
            token, salt=_SALT, max_age=VERIFICATION_TOKEN_MAX_AGE_SECONDS
        )
    except (BadSignature, SignatureExpired) as e:
        logger.warning("Invalid or expired verification token: %s", e)
        return None


async def store_verification_token_hash(pool: AsyncConnectionPool, user_id: int, token_hash: str) -> None:
    """Store a hashed verification token on the user record.

    Overwrites any previous token — only one outstanding verification
    token per user is allowed. The raw token is never stored; only its
    SHA-256 hash.

    Args:
        pool: Database connection pool.
        user_id: The user being verified.
        token_hash: SHA-256 hex digest of the raw verification token.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET email_verification_token_hash = %s,
                   email_verification_created_at = CURRENT_TIMESTAMP
               WHERE id = %s""",
            (token_hash, user_id),
        )


async def confirm_email_verification(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    expected_email: str,
) -> bool:
    """Atomically verify the token and mark the user as verified.

    Combines four checks into a single SQL statement:
    
    1. user ID matches
    2. token hash matches the stored hash (single-use enforcement)
    3. token was issued within the last VERIFICATION_TOKEN_MAX_AGE_SECONDS
       (defense-in-depth against itsdangerous validation bypass)
    4. user's current email matches the token's signed email
       (prevents stale tokens from verifying a changed email address)
    
    The single statement prevents a TOCTOU race where two concurrent
    clicks on the same link could both pass a separate verify step
    before either cleared the stored hash.

    Args:
        pool: Database connection pool.
        user_id: The user whose email to verify.
        token_hash: SHA-256 hex digest of the incoming token.
        expected_email: The email address the token was issued for.
            Compared against the user's current email — if the user
            changed their email after the token was issued, the stale
            token should not verify the new email.

    Returns:
        True if all checks passed and the user was marked verified.
        False if any check failed (already used, expired, replaced by
        a newer token, or email no longer matches).
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET email_verified = true,
                   email_verification_token_hash = NULL,
                   email_verification_created_at = NULL
               WHERE id = %s
                 AND email_verification_token_hash = %s
                 AND LOWER(email) = LOWER(%s)
                 AND email_verification_created_at > CURRENT_TIMESTAMP 
                                                     - %s * INTERVAL '1 second'
               RETURNING id""",
            (
                user_id,
                token_hash,
                expected_email,
                VERIFICATION_TOKEN_MAX_AGE_SECONDS,
            ),
        )
        return await cur.fetchone() is not None