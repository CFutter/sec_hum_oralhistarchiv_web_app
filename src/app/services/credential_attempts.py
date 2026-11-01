"""Reserve persistent credential-proof attempts per full session.

Successful submissions also spend the session budget. Reservations commit
before callers verify credentials, so rejection cannot refund an attempt.
"""

import logging
from datetime import timedelta
from enum import StrEnum

from config import settings

from .account_clock import database_now_cur
from .db import Database, get_db_cursor
from .session_ids import hash_session_id

logger = logging.getLogger(__name__)


class SessionStepUpAttemptOutcome(StrEnum):
    """Result of reserving one credential-proof submission."""

    RESERVED = "reserved"
    INVALID_SESSION = "invalid_session"
    ACCOUNT_LOCKED = "account_locked"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"


async def reserve_session_step_up_attempt(
    pool: Database,
    *,
    user_id: int,
    session_id: str,
) -> SessionStepUpAttemptOutcome:
    """Commit one attempt against an active user's unexpired full session.

    The session row lock serializes reservations. Return INVALID_SESSION for
    a missing/ineligible session or RESERVED after incrementing the counter.
    Username-triggered login lockout does not consume an authenticated session's
    independent proof allowance. At SESSION_STEP_UP_ATTEMPT_LIMIT,
    expire the session, clear its flash, and return ATTEMPTS_EXHAUSTED. Account
    lockout state is unchanged; database failures propagate.

    Use a pool or an idle caller-owned connection for an independent commit.
    An existing outer transaction retains control of the final commit or rollback.
    """
    session_hash = hash_session_id(session_id)
    outcome: SessionStepUpAttemptOutcome

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT s.step_up_attempt_count, s.expires_at, s.last_activity_at
            FROM sessions AS s
            JOIN users AS u ON u.id = s.user_id
            WHERE s.id = %s
              AND s.user_id = %s
              AND s.purpose = 'full'
              AND s.expires_at > clock_timestamp()
              AND u.is_active
            FOR UPDATE OF s
            """,
            (session_hash, user_id),
        )
        row = await cur.fetchone()
        if row is None:
            return SessionStepUpAttemptOutcome.INVALID_SESSION

        # The SELECT may have waited for the session lock. Check both
        # deadlines against database wall time after acquiring that lock.
        now = await database_now_cur(cur)
        idle_cutoff = now - timedelta(seconds=settings.session_idle_timeout_seconds)
        if row["expires_at"] <= now or row["last_activity_at"] <= idle_cutoff:
            return SessionStepUpAttemptOutcome.INVALID_SESSION

        if row["step_up_attempt_count"] >= settings.session_step_up_attempt_limit:
            # Expiring avoids the cascading challenge-row locks of DELETE.
            await cur.execute(
                """
                UPDATE sessions
                SET expires_at = clock_timestamp(),
                    flash_message = NULL,
                    flash_category = NULL
                WHERE id = %s AND user_id = %s
                """,
                (session_hash, user_id),
            )
            outcome = SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED
        else:
            await cur.execute(
                """
                UPDATE sessions
                SET step_up_attempt_count = step_up_attempt_count + 1
                WHERE id = %s
                  AND user_id = %s
                RETURNING step_up_attempt_count
                """,
                (session_hash, user_id),
            )
            if await cur.fetchone() is None:
                raise RuntimeError("Locked step-up session disappeared")
            outcome = SessionStepUpAttemptOutcome.RESERVED

    if outcome is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        logger.warning(
            "Credential step-up budget exhausted for user %d, session %s...",
            user_id,
            session_hash[:8],
        )
    return outcome
