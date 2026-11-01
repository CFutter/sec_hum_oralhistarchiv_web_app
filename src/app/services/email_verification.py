"""Issue SECRET_KEY-signed, 24-hour email-verification capabilities.

Persist token hashes with their queued mail in one transaction. A new hash
replaces the previous capability; confirmation atomically clears it.
"""

import logging
from typing import Any

from itsdangerous import BadSignature, SignatureExpired
from psycopg import AsyncCursor, sql
from psycopg_pool import AsyncConnectionPool

from app.account_contracts import PENDING_ACCOUNT_PREDICATE
from app.service_errors import UserStateChanged

from .db import get_db_cursor
from .email_outbox import cancel_pending_action_emails_cur
from .tokens import (
    VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    ActionEmailMetadata,
    EmailUserPayload,
    SignedActionToken,
    as_email_user_payload,
)

logger = logging.getLogger(__name__)

_SALT = "email-verification"
_ACTION_TOKEN = SignedActionToken(_SALT, VERIFICATION_TOKEN_MAX_AGE_SECONDS)


def generate_verification_token(user_id: int, email: str) -> str:
    """Sign a nonce-bearing URL-safe email/user_id token; caller must store its hash."""
    return _ACTION_TOKEN.issue({"email": email, "user_id": user_id})


def verification_token_email_metadata(token: str) -> ActionEmailMetadata:
    """Return the hash and signed expiration; signature/expiry errors propagate."""
    return _ACTION_TOKEN.email_metadata(token)


def validate_verification_token(token: str) -> EmailUserPayload | None:
    """Return email/user_id for a valid signature and lifetime, else None.

    Database state and single use are checked separately by the flow service.
    Rejections log a fixed message without attacker-supplied signature bytes.
    """
    try:
        return as_email_user_payload(_ACTION_TOKEN.loads(token))
    except (BadSignature, SignatureExpired):
        logger.warning("Invalid or expired verification token")
        return None


async def store_verification_token_hash_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Replace the verification hash/time and cancel pending verification mail.

    The caller owns the transaction. Only an uncancelled, passwordless pending
    local account qualifies. Raise UserStateChanged for an ineligible account.
    """
    await cur.execute(
        sql.SQL("""
        UPDATE users
        SET email_verification_token_hash = %s,
            email_verification_created_at = clock_timestamp()
        WHERE id = %s
          AND {pending_account}
          AND email_verification_token_hash IS NOT NULL
          AND email_verification_created_at IS NOT NULL
          AND LOWER(email) = LOWER(%s)
        RETURNING id
        """).format(pending_account=sql.SQL(PENDING_ACCOUNT_PREDICATE)),
        (token_hash, user_id, expected_email),
    )
    if await cur.fetchone() is None:
        raise UserStateChanged(
            f"User {user_id} is missing, already verified, or its email address changed"
        )
    await cancel_pending_action_emails_cur(
        cur,
        user_id=user_id,
        message_type="email_verification",
    )


async def store_verification_token_hash(
    pool: AsyncConnectionPool,
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Commit store_verification_token_hash_cur, including its eligibility checks.

    To queue replacement mail atomically, use that cursor helper instead.
    """
    async with get_db_cursor(pool) as cur:
        await store_verification_token_hash_cur(
            cur,
            user_id,
            token_hash,
            expected_email=expected_email,
        )
