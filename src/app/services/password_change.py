"""Change a local password after current-session, password and fresh TOTP proof.

Reserve credential attempts independently, release the password snapshot
connection before Argon2 work, and recheck live authority under user/session
locks. Password replacement, TOTP consumption, revocation and notice share
one transaction; callers audit success only after this service returns.
"""

from datetime import timedelta
from typing import Any, Literal

from psycopg import AsyncCursor

from config import settings

from .account_clock import database_now_cur
from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import password_hasher
from .db import Database, get_db_cursor
from .email import build_password_changed_email
from .email_outbox import enqueue_outbound_email_cur
from .password_validation import validate_password_strength
from .password_verification import PasswordVerified, verify_password_hash
from .password_work import run_password_work
from .session_ids import hash_session_id
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .totp import verify_and_consume_totp_cur

PasswordChangeReason = Literal[
    "invalid_session",
    "account_locked",
    "step_up_exhausted",
    "ineligible_account",
    "invalid_password",
    "invalid_totp",
    "retry_required",
    "password_policy",
    "password_reused",
]


class PasswordChangeRejected(ValueError):
    """A bounded policy rejection; password_error is server-generated policy text."""

    def __init__(self, reason: PasswordChangeReason, *, password_error: str | None = None) -> None:
        """Expose a stable reason without retaining submitted credentials."""
        self.reason = reason
        self.password_error = password_error
        super().__init__(reason)


def _check_eligibility(row: dict[str, Any] | None) -> None:
    """Require an active verified local account with both credentials configured."""
    if (
        row is None
        or not row["is_active"]
        or not row["email_verified"]
        or row["auth_method"] != "local"
        or not row["password_hash"]
        or not row["totp_secret"]
        or row["totp_recovery_required"]
    ):
        raise PasswordChangeRejected("ineligible_account")


def _check_password_policy(new_password: str, row: dict[str, Any]) -> None:
    """Apply the existing policy using the account's current profile context."""
    error = validate_password_strength(
        new_password, email=row["email"], display_name=row["display_name"]
    )
    if error:
        raise PasswordChangeRejected("password_policy", password_error=error)


async def _password_snapshot(
    pool: Database, *, user_id: int, session_id: str, current_password: str
) -> dict[str, Any]:
    """Spend one durable attempt, then verify an eligible snapshot off-connection."""
    reservation = await reserve_session_step_up_attempt(
        pool, user_id=user_id, session_id=session_id
    )
    reasons: dict[SessionStepUpAttemptOutcome, PasswordChangeReason] = {
        SessionStepUpAttemptOutcome.INVALID_SESSION: "invalid_session",
        SessionStepUpAttemptOutcome.ACCOUNT_LOCKED: "account_locked",
        SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED: "step_up_exhausted",
    }
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        if reservation not in reasons:
            raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")
        raise PasswordChangeRejected(reasons[reservation])

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT email, display_name, password_hash, auth_revision,
                      is_active, email_verified, auth_method, totp_secret,
                      totp_recovery_required,
                      (locked_until IS NULL OR locked_until <= clock_timestamp())
                          AS login_unlocked
               FROM users WHERE id = %s""",
            (user_id,),
        )
        row: dict[str, Any] | None = await cur.fetchone()
    _check_eligibility(row)
    if row is None:  # narrowed by _check_eligibility
        raise RuntimeError("Eligible password-change account unexpectedly missing")
    verified = await verify_password_hash(
        password_hash=row["password_hash"],
        password=current_password,
        user_id=user_id,
        operation="password_change",
    )
    if not isinstance(verified, PasswordVerified):
        raise PasswordChangeRejected("invalid_password") from verified.cause
    return row


async def _lock_current_account(
    cur: AsyncCursor[Any], *, user_id: int, session_id: str, snapshot: dict[str, Any]
) -> dict[str, Any]:
    """Lock user then exact session and check freshness after both lock waits."""
    await cur.execute(
        """SELECT email, display_name, password_hash, auth_revision,
                  is_active, email_verified, auth_method, totp_secret,
                  totp_recovery_required, locked_until
           FROM users WHERE id = %s FOR UPDATE""",
        (user_id,),
    )
    row: dict[str, Any] | None = await cur.fetchone()
    _check_eligibility(row)
    if row is None:  # narrowed by _check_eligibility
        raise RuntimeError("Eligible password-change account unexpectedly missing")
    await cur.execute(
        """SELECT expires_at, last_activity_at FROM sessions
           WHERE id = %s AND user_id = %s AND purpose = 'full'
           FOR UPDATE""",
        (hash_session_id(session_id), user_id),
    )
    session = await cur.fetchone()
    now = await database_now_cur(cur)
    idle_cutoff = now - timedelta(seconds=settings.session_idle_timeout_seconds)
    if (
        session is None
        or session["expires_at"] <= now
        or session["last_activity_at"] <= idle_cutoff
    ):
        raise PasswordChangeRejected("invalid_session")
    if (
        row["password_hash"] != snapshot["password_hash"]
        or row["auth_revision"] != snapshot["auth_revision"]
    ):
        raise PasswordChangeRejected("retry_required")
    return row


async def change_password(
    pool: Database,
    *,
    user_id: int,
    session_id: str,
    current_password: str,
    new_password: str,
    totp_code: str,
) -> None:
    """Atomically replace a local password, revoke all sessions and queue a notice.

    Use a pool or idle connection: the step-up attempt commits before proof
    work and remains spent on rejection. Never change the active authenticator
    or current recovery codes. Storage/admission/decryption failures propagate.
    """
    snapshot = await _password_snapshot(
        pool, user_id=user_id, session_id=session_id, current_password=current_password
    )
    _check_password_policy(new_password, snapshot)
    if new_password == current_password:
        raise PasswordChangeRejected("password_reused")
    new_hash = await run_password_work(password_hasher.hash, new_password)

    async with get_db_cursor(pool) as cur:
        row = await _lock_current_account(
            cur, user_id=user_id, session_id=session_id, snapshot=snapshot
        )
        # Display-name edits do not advance auth_revision; repeat their cheap
        # policy check against the locked profile before writing credentials.
        _check_password_policy(new_password, row)
        if not await verify_and_consume_totp_cur(cur, user_id, totp_code):
            raise PasswordChangeRejected("invalid_totp")
        await cur.execute(
            """UPDATE users
               SET password_hash = %s, auth_revision = auth_revision + 1,
                   failed_login_count = 0, locked_until = NULL,
                   lockout_notice_enqueued_at = NULL
               WHERE id = %s""",
            (new_hash, user_id),
        )
        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)
        await enqueue_outbound_email_cur(
            cur, user_id=user_id, email=build_password_changed_email(row["email"]), action=None
        )
