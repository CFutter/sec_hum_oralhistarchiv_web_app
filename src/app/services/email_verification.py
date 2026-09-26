"""Issue SECRET_KEY-signed, 24-hour email-verification capabilities.

Persist token hashes with their queued mail in one transaction. A new hash
replaces the previous capability; confirmation atomically clears it.
"""

import logging
import secrets
from datetime import timedelta
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from config import settings

from .db import get_db_cursor
from .email_outbox import cancel_pending_action_emails_cur
from .tokens import (
    VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    ActionEmailMetadata,
    EmailUserPayload,
    as_email_user_payload,
    hash_token,
)

logger = logging.getLogger(__name__)

_SALT = "email-verification"


def generate_verification_token(user_id: int, email: str) -> str:
    """Sign a nonce-bearing URL-safe email/user_id token; caller must store its hash."""
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    return signer.dumps(
        {"email": email, "user_id": user_id, "nonce": secrets.token_urlsafe(16)},
        salt=_SALT,
    )


def verification_token_email_metadata(
    token: str,
) -> ActionEmailMetadata:
    """Return the token hash and signed UTC issue time plus its 24-hour lifetime.

    Invalid/expired signatures propagate itsdangerous exceptions.
    """
    signer = URLSafeTimedSerializer(
        settings.secret_key.get_secret_value(),
    )

    _, issued_at = signer.loads(
        token,
        salt=_SALT,
        max_age=VERIFICATION_TOKEN_MAX_AGE_SECONDS,
        return_timestamp=True,
    )

    return ActionEmailMetadata(
        token_hash=hash_token(token),
        expires_at=issued_at
        + timedelta(
            seconds=VERIFICATION_TOKEN_MAX_AGE_SECONDS,
        ),
    )


def validate_verification_token(token: str) -> EmailUserPayload | None:
    """Return email/user_id for a valid unexpired signature and payload, else None.

    No database check is performed; confirm_email_verification enforces
    single-use against the stored hash. Invalid signatures are logged.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        return as_email_user_payload(
            signer.loads(token, salt=_SALT, max_age=VERIFICATION_TOKEN_MAX_AGE_SECONDS)
        )
    except (BadSignature, SignatureExpired) as e:
        logger.warning("Invalid or expired verification token: %s", e)
        return None


async def store_verification_token_hash_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Replace the verification hash/time and cancel pending verification mail.

    The caller owns the transaction. Raise ValueError if the user is absent,
    already verified, or expected_email differs case-insensitively.
    """
    await cur.execute(
        """
        UPDATE users
        SET email_verification_token_hash = %s,
            email_verification_created_at = CURRENT_TIMESTAMP
        WHERE id = %s
          AND NOT email_verified
          AND LOWER(email) = LOWER(%s)
        RETURNING id
        """,
        (token_hash, user_id, expected_email),
    )
    if await cur.fetchone() is None:
        raise ValueError(
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


async def confirm_email_verification(
    pool: AsyncConnectionPool,
    user_id: int,
    expected_email: str,
    token_hash: str,
) -> bool:
    """Consume a matching hash and mark the account verified in one transaction.

    Return False unless the user, case-insensitive expected_email, hash, and
    stored timestamp within 24 hours match. The caller must validate the signed
    token separately; concurrent consumption succeeds at most once.
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
