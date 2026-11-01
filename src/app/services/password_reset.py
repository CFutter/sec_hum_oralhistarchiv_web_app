"""Issue SECRET_KEY-signed, 30-minute password-reset capabilities.

Anonymous requests preserve unexpired capabilities and apply shared mail budgets.
Completion validates account/token state, checks strength/reuse, increments
auth_revision, clears lockout state, and revokes sessions/pending capabilities.
"""

import hmac
import logging
from typing import Any

from itsdangerous import BadSignature, SignatureExpired
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from app import normalize_email
from app.service_errors import UserInputRejected, UserStateChanged
from config import settings

from .crypto import password_hasher
from .db import get_db_cursor
from .email import build_password_changed_email, build_password_reset_email
from .email_outbox import (
    cancel_pending_action_emails_cur,
    enqueue_outbound_email_cur,
    requeue_retained_action_email_cur,
)
from .mail_issuance import anonymous_mail_issuance_allowed_cur, record_mail_issuance_cur
from .password_validation import validate_password_strength
from .password_verification import PasswordVerified, verify_password_hash
from .password_work import run_password_work
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .sessions import create_session_cur
from .tokens import (
    RESET_TOKEN_MAX_AGE_SECONDS,
    ActionEmailMetadata,
    EmailUserPayload,
    SignedActionToken,
    action_token_url,
    as_email_user_payload,
    hash_token,
)
from .totp import verify_and_consume_totp_cur

logger = logging.getLogger(__name__)

_SALT = "password-reset"
_ACTION_TOKEN = SignedActionToken(_SALT, RESET_TOKEN_MAX_AGE_SECONDS)
RESET_TOTP_ATTEMPT_LIMIT = 5


def generate_reset_token(user_id: int, email: str) -> str:
    """Sign a nonce-bearing URL-safe email/user_id token; caller must store its hash."""
    return _ACTION_TOKEN.issue({"email": email, "user_id": user_id})


def validate_reset_token(token: str) -> EmailUserPayload | None:
    """Return email/user_id for a valid signature and lifetime, else None.

    Database state and single use are checked separately by the flow service.
    Rejections log a fixed message without attacker-supplied signature bytes.
    """
    try:
        return as_email_user_payload(_ACTION_TOKEN.loads(token))
    except (BadSignature, SignatureExpired):
        logger.warning("Invalid or expired reset token")
        return None


class InvalidResetToken(UserInputRejected):
    """A reset capability is no longer eligible for use."""


class InvalidResetTotp(UserInputRejected):
    """The owner did not prove a fresh configured authenticator code."""


def _invalid_reset_token() -> InvalidResetToken:
    """Build the common invalid-reset-capability exception."""
    return InvalidResetToken(
        "Invalid, expired, or already-used reset token. Resetting may also be temporarily "
        "unavailable; after repeated attempts, wait 30 minutes before trying again."
    )


async def _is_same_as_current_password(
    password_hash: str | None, user_id: int, new_password: str
) -> bool:
    """Verify a hash snapshot off-thread; return False for missing/invalid hashes.

    Unverifiable hashes are logged; user_id is used only for that log.
    """
    if not password_hash:
        return False
    result = await verify_password_hash(
        password_hash=password_hash,
        password=new_password,
        user_id=user_id,
        operation="password_reset",
    )
    return isinstance(result, PasswordVerified)


async def _reserve_reset_attempt(
    pool: AsyncConnectionPool, *, user_id: int, token_hash: str, expected_email: str
) -> dict[str, Any]:
    """Spend a durable account-wide proof attempt only for a live mailbox capability."""
    # The reservation commits separately: later policy, capacity or credential
    # failures cannot refund a valid capability's bounded proof attempts.
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET password_reset_attempt_count = CASE
                       WHEN password_reset_attempt_window_started_at IS NULL
                         OR password_reset_attempt_window_started_at <= clock_timestamp()
                                                - %(max_age)s * INTERVAL '1 second'
                       THEN 1 ELSE password_reset_attempt_count + 1 END,
                   password_reset_attempt_window_started_at = CASE
                       WHEN password_reset_attempt_window_started_at IS NULL
                         OR password_reset_attempt_window_started_at <= clock_timestamp()
                                                - %(max_age)s * INTERVAL '1 second'
                       THEN clock_timestamp() ELSE password_reset_attempt_window_started_at END
               WHERE id = %(user_id)s AND password_reset_token_hash = %(token_hash)s
                 AND password_reset_created_at > clock_timestamp()
                                                - %(max_age)s * INTERVAL '1 second'
                 AND (password_reset_attempt_count < %(attempt_limit)s
                      OR password_reset_attempt_window_started_at IS NULL
                      OR password_reset_attempt_window_started_at <= clock_timestamp()
                                                - %(max_age)s * INTERVAL '1 second')
                 AND auth_method = 'local' AND is_active AND email_verified
                 AND totp_secret IS NOT NULL AND NOT totp_recovery_required
                 AND LOWER(email) = LOWER(%(email)s)
               RETURNING email, display_name, password_hash, auth_revision""",
            {
                "user_id": user_id,
                "token_hash": token_hash,
                "max_age": RESET_TOKEN_MAX_AGE_SECONDS,
                "attempt_limit": RESET_TOTP_ATTEMPT_LIMIT,
                "email": expected_email,
            },
        )
        snapshot: dict[str, Any] | None = await cur.fetchone()
    if snapshot is None:
        raise _invalid_reset_token()
    return snapshot


async def update_password_with_token(
    pool: AsyncConnectionPool,
    user_id: int,
    token: str,
    new_password: str,
    *,
    expected_email: str,
    totp_code: str,
) -> None:
    """Consume an active local user's reset hash and commit a new password.

    Validate the raw signed token and its identity before password work, then
    recheck signed expiry after acquiring the user lock. Match expected_email
    without case and require a stored token younger than 30 minutes at the write.
    Reserve one of five account-wide attempts per 30 minutes for a live email
    capability before password work. Replacing a token does not replenish this
    budget. Validate strength/reuse outside locks, then recheck the hash
    and revision and consume a fresh TOTP in the password-write transaction.
    Clear failures/lockout, revoke sessions/pending state and queue a notice.
    The active authenticator and current recovery codes remain unchanged.

    Raises:
        InvalidResetToken: Account, email, token, or expiry checks fail.
        InvalidResetTotp: The authenticator code is invalid or already consumed.
        UserInputRejected: Password strength fails or the current password is reused.
    """
    data = validate_reset_token(token)
    if (
        data is None
        or data["user_id"] != user_id
        or data["email"].lower() != expected_email.lower()
    ):
        raise _invalid_reset_token()
    token_hash = hash_token(token)
    snapshot = await _reserve_reset_attempt(
        pool, user_id=user_id, token_hash=token_hash, expected_email=expected_email
    )

    error = validate_password_strength(
        new_password, email=snapshot["email"], display_name=snapshot["display_name"]
    )
    if error:
        raise UserInputRejected(f"Password validation failed: {error}")

    if await _is_same_as_current_password(snapshot["password_hash"], user_id, new_password):
        raise UserInputRejected("Please choose a different password from your current one.")

    new_hash = await run_password_work(password_hasher.hash, new_password)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT id, email, display_name FROM users
               WHERE id = %s AND password_hash = %s AND auth_revision = %s
                 AND password_reset_token_hash = %s
                 AND password_reset_created_at > clock_timestamp()
                                                - %s * INTERVAL '1 second'
                 AND auth_method = 'local' AND is_active AND email_verified
                 AND totp_secret IS NOT NULL AND NOT totp_recovery_required
                 AND LOWER(email) = LOWER(%s)
               FOR UPDATE""",
            (
                user_id,
                snapshot["password_hash"],
                snapshot["auth_revision"],
                token_hash,
                RESET_TOKEN_MAX_AGE_SECONDS,
                expected_email,
            ),
        )
        current = await cur.fetchone()
        if current is None or validate_reset_token(token) != data:
            raise _invalid_reset_token()
        error = validate_password_strength(
            new_password, email=current["email"], display_name=current["display_name"]
        )
        if error:
            raise UserInputRejected(f"Password validation failed: {error}")
        if not await verify_and_consume_totp_cur(cur, user_id, totp_code):
            raise InvalidResetTotp(
                "Authenticator code is invalid or already used. "
                "Wait for a fresh code and try again."
            )
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
                 AND password_reset_created_at > clock_timestamp()
                                                 - %s * INTERVAL '1 second'
                AND auth_method = 'local'
                AND is_active
                AND email_verified
                AND totp_secret IS NOT NULL AND NOT totp_recovery_required
                AND password_hash = %s AND auth_revision = %s
                AND LOWER(email) = LOWER(%s)
               RETURNING id""",
            (
                new_hash,
                user_id,
                token_hash,
                RESET_TOKEN_MAX_AGE_SECONDS,
                snapshot["password_hash"],
                snapshot["auth_revision"],
                expected_email,
            ),
        )
        if not await cur.fetchone():
            raise _invalid_reset_token()

        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)
        await enqueue_outbound_email_cur(
            cur,
            user_id=user_id,
            email=build_password_changed_email(snapshot["email"]),
            action=None,
        )
    logger.info("Password reset completed for user %d", user_id)


async def request_password_reset(pool: AsyncConnectionPool, *, email: str) -> None:
    """Queue bounded recovery mail without replacing an unexpired capability.

    Unknown, ineligible, limited and already-issued requests all return None.
    Account lookup, capability creation and enqueue share the issuance lock and
    transaction. Live token hashes, expiry and proof counters are untouched.
    Existing delivery retries continue. An admitted resend copies a retained
    delivered/failed message without changing its capability or original expiry.
    Storage failures roll back issuance and enqueue together.
    """
    normalized = normalize_email(email)
    if normalized is None:
        return
    async with get_db_cursor(pool) as cur:
        if not await anonymous_mail_issuance_allowed_cur(cur, normalized):
            return
        await cur.execute(
            """SELECT id, email, password_reset_token_hash,
                      (password_reset_token_hash IS NOT NULL
                       AND password_reset_created_at > clock_timestamp()
                           - %s * INTERVAL '1 second') AS reset_live
               FROM users
               WHERE LOWER(email) = LOWER(%s)
                 AND auth_method = 'local' AND is_active AND email_verified
                 AND totp_secret IS NOT NULL AND NOT totp_recovery_required
               FOR UPDATE""",
            (RESET_TOKEN_MAX_AGE_SECONDS, normalized),
        )
        row = await cur.fetchone()
        if row is None:
            return
        if row["reset_live"]:
            queued = await requeue_retained_action_email_cur(
                cur,
                user_id=row["id"],
                recipient=row["email"],
                message_type="password_reset",
                token_hash=row["password_reset_token_hash"],
            )
            if queued:
                await record_mail_issuance_cur(cur, row["email"])
            return
        token = generate_reset_token(row["id"], row["email"])
        action = reset_token_email_metadata(token)
        await store_reset_token_hash_cur(
            cur, row["id"], action.token_hash, expected_email=row["email"]
        )
        await enqueue_outbound_email_cur(
            cur,
            user_id=row["id"],
            email=build_password_reset_email(
                row["email"],
                f"{settings.public_base_url}{action_token_url('/reset-password', token)}",
                expires_at=action.expires_at,
                security_code=token,
            ),
            action=action,
        )
        await record_mail_issuance_cur(cur, row["email"])


async def unlock_account_with_token(
    pool: AsyncConnectionPool,
    user_id: int,
    token: str,
    *,
    expected_email: str,
    totp_code: str,
    ip_address: str,
) -> str:
    """Consume mailbox and authenticator proof, clear lockout and issue a new session.

    The password is unchanged. The same durable five-attempt recovery budget
    applies to reset and unlock. A username-only login lock cannot prevent this
    proof. Under the user lock, verify current credentials/revision/capability,
    consume a fresh TOTP, revoke old sessions and pending capabilities, and
    create a full session atomically. Return its raw token only after commit.
    """
    data = validate_reset_token(token)
    if (
        data is None
        or data["user_id"] != user_id
        or data["email"].lower() != expected_email.lower()
    ):
        raise _invalid_reset_token()
    token_hash = hash_token(token)
    snapshot = await _reserve_reset_attempt(
        pool, user_id=user_id, token_hash=token_hash, expected_email=expected_email
    )
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT id FROM users
               WHERE id = %s AND password_hash = %s AND auth_revision = %s
                 AND password_reset_token_hash = %s
                 AND password_reset_created_at > clock_timestamp()
                     - %s * INTERVAL '1 second'
                 AND auth_method = 'local' AND is_active AND email_verified
                 AND totp_secret IS NOT NULL AND NOT totp_recovery_required
                 AND LOWER(email) = LOWER(%s)
               FOR UPDATE""",
            (
                user_id,
                snapshot["password_hash"],
                snapshot["auth_revision"],
                token_hash,
                RESET_TOKEN_MAX_AGE_SECONDS,
                expected_email,
            ),
        )
        if await cur.fetchone() is None or validate_reset_token(token) != data:
            raise _invalid_reset_token()
        if not await verify_and_consume_totp_cur(cur, user_id, totp_code):
            raise InvalidResetTotp(
                "Authenticator code is invalid or already used. "
                "Wait for a fresh code and try again."
            )
        await cur.execute(
            """UPDATE users SET failed_login_count = 0, locked_until = NULL,
                      lockout_notice_enqueued_at = NULL, auth_revision = auth_revision + 1
               WHERE id = %s""",
            (user_id,),
        )
        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)
        session_id = await create_session_cur(
            cur,
            user_id=user_id,
            ip_address=ip_address,
            purpose="full",
            max_age_seconds=settings.session_max_age_seconds,
        )
    logger.info("Mailbox-protected account sign-in completed for user %d", user_id)
    return session_id


async def store_reset_token_hash_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    token_hash: str,
    *,
    expected_email: str,
) -> None:
    """Replace the reset hash/time and cancel pending reset mail transactionally.

    Raise UserStateChanged unless the user is active/local and expected_email matches
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
        raise UserStateChanged(
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
    """Return the hash and signed expiration; signature/expiry errors propagate."""
    return _ACTION_TOKEN.email_metadata(token)
