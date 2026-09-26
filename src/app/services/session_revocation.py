"""Session and pending-capability revocation shared by account services."""

import logging
from typing import Any

from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from .db import get_db_cursor
from .email_outbox import cancel_pending_action_emails_cur

logger = logging.getLogger(__name__)

_PENDING_ACTION_MESSAGE_TYPES = (
    "password_reset",
    "email_verification",
    "email_change_verification",
)


async def invalidate_pending_email_change_cur(cur: AsyncCursor[Any], user_id: int) -> None:
    """Clear staged email state and cancel its pending outbox mail transactionally."""
    await cur.execute(
        """UPDATE users SET pending_email = NULL, pending_email_token_hash = NULL,
                  pending_email_created_at = NULL WHERE id = %s""",
        (user_id,),
    )
    await cancel_pending_action_emails_cur(
        cur, user_id=user_id, message_type="email_change_verification"
    )


async def invalidate_pending_authentication_state_cur(
    cur: AsyncCursor[Any],
    user_id: int,
) -> None:
    """Clear pending authentication capabilities in the caller's transaction.

    Clear token hashes, pending enrollment/email/recovery state, rotation and
    promotion requests, noncurrent recovery-code generations, and pending
    action mail. Current recovery codes and totp_recovery_required remain.
    When also revoking sessions, call delete_user_sessions_cur first to preserve
    the session-before-challenge lock order.
    """
    await cur.execute(
        """
        UPDATE users
        SET pending_totp_secret = NULL,
            pending_totp_created_at = NULL,
            pending_email = NULL,
            pending_email_token_hash = NULL,
            pending_email_created_at = NULL,
            password_reset_token_hash = NULL,
            password_reset_created_at = NULL,
            email_verification_token_hash = NULL,
            email_verification_created_at = NULL,
            pending_totp_recovery_code_generation = NULL,
            totp_recovery_expires_at = NULL,
            totp_recovery_authorized_at = NULL,
            totp_recovery_auth_revision = NULL
        WHERE id = %s
        """,
        (user_id,),
    )
    await cur.execute(
        "DELETE FROM pending_totp_rotations WHERE user_id = %s",
        (user_id,),
    )
    await cur.execute(
        """
        DELETE FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation <> (
              SELECT totp_recovery_code_generation
              FROM users
              WHERE id = %s
          )
        """,
        (user_id, user_id),
    )
    await cur.execute(
        "DELETE FROM admin_promotion_requests WHERE user_id = %s",
        (user_id,),
    )

    for message_type in _PENDING_ACTION_MESSAGE_TYPES:
        await cancel_pending_action_emails_cur(
            cur,
            user_id=user_id,
            message_type=message_type,
        )


async def delete_user_sessions_cur(
    cur: AsyncCursor[Any],
    user_id: int,
) -> None:
    """Delete all user sessions in the caller's transaction.

    Call before invalidate_pending_authentication_state_cur when both are
    needed; cascading challenge deletion makes the lock order significant.
    """
    await cur.execute(
        "DELETE FROM sessions WHERE user_id = %s",
        (user_id,),
    )


async def delete_user_sessions(
    pool: AsyncConnectionPool,
    user_id: int,
) -> None:
    """Increment auth_revision and atomically revoke sessions and pending state.

    Uses invalidate_pending_authentication_state_cur; current recovery codes
    and the recovery-required flag remain. Missing users are a no-op.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            UPDATE users
            SET auth_revision = auth_revision + 1
            WHERE id = %s
            """,
            (user_id,),
        )
        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)

    logger.info("All sessions and pending authentication state deleted for user %d", user_id)
