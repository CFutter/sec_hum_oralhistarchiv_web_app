"""Issue SECRET_KEY-signed, 30-minute password-reset capabilities.

Persist a replacement hash and queued email in one caller-owned transaction.
Completion validates account/token state, checks strength/reuse, increments
auth_revision, clears lockout state, and revokes sessions/pending capabilities.
"""

import hmac
import logging
import secrets
from datetime import timedelta
from typing import Any

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from config import settings

from .crypto import password_hasher
from .db import get_db_cursor
from .email_outbox import cancel_pending_action_emails_cur
from .password_validation import validate_password_strength
from .password_work import run_password_work
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .tokens import (
    RESET_TOKEN_MAX_AGE_SECONDS,
    ActionEmailMetadata,
    EmailUserPayload,
    as_email_user_payload,
    hash_token,
)

logger = logging.getLogger(__name__)

_SALT = "password-reset"


def generate_reset_token(user_id: int, email: str) -> str:
    """Sign a nonce-bearing URL-safe email/user_id token; caller must store its hash."""
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    return signer.dumps(
        {"email": email, "user_id": user_id, "nonce": secrets.token_urlsafe(16)},
        salt=_SALT,
    )


def validate_reset_token(token: str) -> EmailUserPayload | None:
    """Return email/user_id for a valid unexpired signature and payload, else None.

    Invalid signatures are logged. This does not check or consume database
    state; update_password_with_token must consume the token atomically.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        return as_email_user_payload(
            signer.loads(token, salt=_SALT, max_age=RESET_TOKEN_MAX_AGE_SECONDS)
        )
    except (BadSignature, SignatureExpired) as e:
        logger.warning("Invalid or expired reset token: %s", e)
        return None


class InvalidResetToken(ValueError):
    """A reset capability is no longer eligible for use."""


def _invalid_reset_token() -> InvalidResetToken:
    """Build the common invalid-reset-capability exception."""
    return InvalidResetToken("Invalid, expired, or already-used reset token")


async def _is_same_as_current_password(
    password_hash: str | None, user_id: int, new_password: str
) -> bool:
    """Verify a hash snapshot off-thread; return False for missing/invalid hashes.

    Unverifiable hashes are logged; user_id is used only for that log.
    """
    if not password_hash:
        return False
    try:
        await run_password_work(password_hasher.verify, password_hash, new_password)
        return True
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError):
        logger.exception("Unverifiable password hash for user id=%s", user_id)
        return False


async def update_password_with_token(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    new_password: str,
    *,
    expected_email: str,
) -> None:
    """Consume an active local user's reset hash and commit a new password.

    The caller validates the signature first. Match expected_email without case
    and require a stored token younger than 30 minutes, rechecking at the write.
    Validate strength/reuse against a pre-hash snapshot, then increment
    auth_revision, clear failures/lockout, and revoke sessions/pending state.
    Current recovery codes and the recovery-required flag remain.

    Raises:
        InvalidResetToken: Account, email, token, or expiry checks fail.
        ValueError: Password strength fails or the current password is reused.
    """
    # Reject stale forms before password policy/reuse/hash work. This snapshot
    # is advisory; the final UPDATE repeats eligibility under concurrent change.
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT email, display_name, password_hash FROM users
               WHERE id = %s AND password_reset_token_hash = %s
                 AND password_reset_created_at > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'
                 AND auth_method = 'local' AND is_active AND LOWER(email) = LOWER(%s)""",
            (user_id, token_hash, RESET_TOKEN_MAX_AGE_SECONDS, expected_email),
        )
        snapshot = await cur.fetchone()
    if snapshot is None:
        raise _invalid_reset_token()

    error = validate_password_strength(
        new_password, email=snapshot["email"], display_name=snapshot["display_name"]
    )
    if error:
        raise ValueError(f"Password validation failed: {error}")

    if await _is_same_as_current_password(snapshot["password_hash"], user_id, new_password):
        raise ValueError("Please choose a different password from your current one.")

    new_hash = await run_password_work(password_hasher.hash, new_password)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET password_hash = %s,
                   auth_revision = auth_revision + 1,
                   password_reset_token_hash = NULL,
                   password_reset_created_at = NULL,
                   failed_login_count = 0,
                   locked_until = NULL,
                   lockout_notice_enqueued_at = NULL
               WHERE id = %s
                 AND password_reset_token_hash = %s
                 AND password_reset_created_at > CURRENT_TIMESTAMP
                                                 - %s * INTERVAL '1 second'
                AND auth_method = 'local'
                AND is_active
                AND LOWER(email) = LOWER(%s)
               RETURNING id""",
            (
                new_hash,
                user_id,
                token_hash,
                RESET_TOKEN_MAX_AGE_SECONDS,
                expected_email,
            ),
        )
        if not await cur.fetchone():
            raise _invalid_reset_token()

        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)
    logger.info("Password reset completed for user %d", user_id)


async def store_reset_token_hash_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Replace the reset hash/time and cancel pending reset mail transactionally.

    Raise ValueError unless the user is active/local and expected_email matches
    case-insensitively. The caller owns commit and any replacement mail insert.
    """
    await cur.execute(
        """
        UPDATE users
        SET password_reset_token_hash = %s,
            password_reset_created_at = CURRENT_TIMESTAMP
        WHERE id = %s
          AND auth_method = 'local'
          AND is_active
          AND LOWER(email) = LOWER(%s)
        RETURNING id
        """,
        (token_hash, user_id, expected_email),
    )
    if await cur.fetchone() is None:
        raise ValueError(
            f"User {user_id} is missing, ineligible for password reset, "
            "or its email address changed"
        )
    await cancel_pending_action_emails_cur(
        cur,
        user_id=user_id,
        message_type="password_reset",
    )


async def store_reset_token_hash(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Commit store_reset_token_hash_cur, including its eligibility checks.

    To queue replacement mail atomically, use that cursor helper instead.
    """
    async with get_db_cursor(pool) as cur:
        await store_reset_token_hash_cur(
            cur,
            user_id,
            token_hash,
            expected_email=expected_email,
        )


async def verify_reset_token_hash(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> bool:
    """Check a current 30-minute reset hash without consuming it.

    Return False unless the active local account and case-insensitive
    expected_email match. token_hash must be ASCII for hmac.compare_digest;
    non-ASCII strings raise TypeError. Completion must recheck atomically.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT password_reset_token_hash
            FROM users
            WHERE id = %s
              AND auth_method = 'local'
              AND is_active
              AND LOWER(email) = LOWER(%s)
              AND password_reset_token_hash IS NOT NULL
              AND password_reset_created_at
                    > CURRENT_TIMESTAMP
                      - %s * INTERVAL '1 second'
            """,
            (
                user_id,
                expected_email,
                RESET_TOKEN_MAX_AGE_SECONDS,
            ),
        )
        row = await cur.fetchone()

    if not row or not row.get("password_reset_token_hash"):
        return False

    return hmac.compare_digest(
        row["password_reset_token_hash"],
        token_hash,
    )


def reset_token_email_metadata(token: str) -> ActionEmailMetadata:
    """Return the token hash and signed UTC issue time plus its 30-minute lifetime.

    Invalid/expired signatures propagate itsdangerous exceptions.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())

    _, issued_at = signer.loads(
        token,
        salt=_SALT,
        max_age=RESET_TOKEN_MAX_AGE_SECONDS,
        return_timestamp=True,
    )

    return ActionEmailMetadata(
        token_hash=hash_token(token),
        expires_at=issued_at
        + timedelta(
            seconds=RESET_TOKEN_MAX_AGE_SECONDS,
        ),
    )
