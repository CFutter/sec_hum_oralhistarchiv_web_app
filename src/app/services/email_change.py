"""Issue one-hour, revision-bound email-change capabilities.

Self-service staging spends a durable session attempt and verifies a
password snapshot; administrator staging guards the current admin session.
Both atomically stage the hash and confirmation/security-notice emails.
Confirmation needs no session but requires signature validation by its
caller, then consumes current pending state and revokes sessions.
"""

import logging
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal, NotRequired, TypedDict

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg import AsyncCursor
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from config import settings

from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import password_hasher
from .db import get_db_cursor
from .db_constraints import is_users_email_collision
from .email import build_email_change_notice, build_email_change_verification
from .email_outbox import (
    cancel_pending_action_emails_cur,
    enqueue_outbound_email_cur,
)
from .email_utils import normalize_email
from .password_work import run_password_work
from .session_ids import hash_session_id
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .tokens import EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS, ActionEmailMetadata, hash_token
from .users import guard_current_admin_session_cur

logger = logging.getLogger(__name__)

_SALT = "email-change"


class EmailChangePayload(TypedDict):
    """Signed target address/revision, with optional initiating administrator ID."""

    user_id: int
    new_email: str
    auth_revision: int
    acting_admin_id: NotRequired[int]


AdminEmailChangeReason = Literal[
    "invalid_email",
    "user_not_found",
    "federated_account",
    "inactive_account",
    "same_email",
    "email_in_use",
]

SelfEmailChangeReason = Literal[
    "invalid_email",
    "invalid_session",
    "account_locked",
    "step_up_exhausted",
    "ineligible_account",
    "invalid_password",
    "same_email",
    "retry_required",
]


class AdminEmailChangeRejected(ValueError):
    """An expected policy rejection while staging an admin email change."""

    def __init__(self, reason: AdminEmailChangeReason):
        """Expose the policy reason as both .reason and the exception message."""
        self.reason = reason
        super().__init__(reason)


class SelfEmailChangeRejected(ValueError):
    """An expected policy rejection while staging a self-service change."""

    def __init__(self, reason: SelfEmailChangeReason):
        """Expose the policy reason as both .reason and the exception message."""
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class AdminEmailChangeResult:
    """Committed staged change; the old address remains active until confirmation."""

    target_user_id: int
    old_email: str
    new_email: str


@dataclass(frozen=True, slots=True)
class SelfEmailChangeResult:
    """Committed staged change; the old address remains active until confirmation."""

    user_id: int
    old_email: str
    new_email: str


def generate_email_change_token(
    user_id: int,
    new_email: str,
    *,
    auth_revision: int,
    acting_admin_id: int | None = None,
) -> str:
    """Sign target/address/revision and optional administrator ID with a fresh nonce.

    Raise ValueError unless auth_revision is a nonnegative integer excluding
    bool. Other payload fields are not validated; caller must store the hash.
    """
    if not isinstance(auth_revision, int) or isinstance(auth_revision, bool) or auth_revision < 0:
        raise ValueError("auth_revision must be a non-negative integer")

    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    payload: dict[str, object] = {
        "user_id": user_id,
        "new_email": new_email,
        "auth_revision": auth_revision,
        "nonce": secrets.token_urlsafe(16),
    }
    if acting_admin_id is not None:
        payload["acting_admin_id"] = acting_admin_id
    return signer.dumps(payload, salt=_SALT)


def email_change_token_email_metadata(
    token: str,
) -> ActionEmailMetadata:
    """Return the token hash and signed UTC issue time plus its one-hour lifetime.

    Invalid/expired signatures propagate itsdangerous exceptions.
    """
    signer = URLSafeTimedSerializer(
        settings.secret_key.get_secret_value(),
    )

    _, issued_at = signer.loads(
        token,
        salt=_SALT,
        max_age=EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
        return_timestamp=True,
    )

    return ActionEmailMetadata(
        token_hash=hash_token(token),
        expires_at=issued_at
        + timedelta(
            seconds=EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
        ),
    )


def validate_email_change_token(token: str) -> EmailChangePayload | None:
    """Return valid one-hour signed payload fields, or None for invalid tokens.

    Require a positive non-boolean user ID, string email, and nonnegative
    non-boolean revision; email syntax and current database revision are not
    checked. Optional integer administrator IDs are retained, including
    nonpositive IDs; invalid optional values and extra keys are ignored.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        raw = signer.loads(
            token,
            salt=_SALT,
            max_age=EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
        )
    except (BadSignature, SignatureExpired) as exc:
        logger.warning("Invalid or expired email-change token: %s", exc)
        return None

    if not isinstance(raw, dict):
        return None

    user_id = raw.get("user_id")
    new_email = raw.get("new_email")
    auth_revision = raw.get("auth_revision")
    if (
        not isinstance(user_id, int)
        or isinstance(user_id, bool)
        or user_id <= 0
        or not isinstance(new_email, str)
        or not isinstance(auth_revision, int)
        or isinstance(auth_revision, bool)
        or auth_revision < 0
    ):
        return None

    payload = EmailChangePayload(
        user_id=user_id,
        new_email=new_email,
        auth_revision=auth_revision,
    )
    acting_admin_id = raw.get("acting_admin_id")
    if isinstance(acting_admin_id, int) and not isinstance(acting_admin_id, bool):
        payload["acting_admin_id"] = acting_admin_id
    return payload


async def store_pending_email_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    new_email: str,
    token_hash: str,
    *,
    expected_auth_revision: int,
) -> None:
    """Replace pending address/hash/time and cancel prior confirmation mail.

    The caller owns the transaction and must validate the email/hash. Raise
    ValueError unless an active local user matches expected_auth_revision.
    """
    await cur.execute(
        """
        UPDATE users
        SET pending_email = %s,
            pending_email_token_hash = %s,
            pending_email_created_at = CURRENT_TIMESTAMP
        WHERE id = %s
          AND auth_method = 'local'
          AND is_active
          AND auth_revision = %s
        RETURNING id
        """,
        (new_email, token_hash, user_id, expected_auth_revision),
    )
    if await cur.fetchone() is None:
        raise ValueError("Account security state changed before email staging")

    await cancel_pending_action_emails_cur(
        cur,
        user_id=user_id,
        message_type="email_change_verification",
    )


async def store_pending_email(
    pool: AsyncConnectionPool,
    user_id: int,
    new_email: str,
    token_hash: str,
    *,
    expected_auth_revision: int,
) -> None:
    """Commit store_pending_email_cur with its revision guard and mail cancellation.

    Use the cursor helper when replacement mail must share the transaction.
    """
    async with get_db_cursor(pool) as cur:
        await store_pending_email_cur(
            cur,
            user_id,
            new_email,
            token_hash,
            expected_auth_revision=expected_auth_revision,
        )


async def stage_self_email_change(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    session_id: str,
    current_password: str,
    new_email: str,
) -> SelfEmailChangeResult:
    """Verify the password and atomically stage normalized email plus two messages.

    session_id is a raw active full-session token. A separately committed
    step-up reservation remains spent after later rejection. Verify the password
    off-connection, then lock/recheck account, hash, revision, lockout, and
    session. Queue confirmation to the new address and notice to the old one;
    do not check whether the destination already belongs to another account.
    Return committed addresses; SelfEmailChangeRejected.reason identifies
    policy/credential failures, including retry_required after hash changes.
    """
    normalized_email = normalize_email(new_email)
    if normalized_email is None:
        raise SelfEmailChangeRejected("invalid_email")
    if not session_id:
        raise SelfEmailChangeRejected("invalid_session")

    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=user_id,
        session_id=session_id,
    )
    if reservation is SessionStepUpAttemptOutcome.INVALID_SESSION:
        raise SelfEmailChangeRejected("invalid_session")
    if reservation is SessionStepUpAttemptOutcome.ACCOUNT_LOCKED:
        raise SelfEmailChangeRejected("account_locked")
    if reservation is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        raise SelfEmailChangeRejected("step_up_exhausted")
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")

    # Release this snapshot transaction before waiting for Argon2 capacity.
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT password_hash,
                      auth_revision,
                      is_active,
                      auth_method,
                      (locked_until IS NULL OR locked_until <= clock_timestamp())
                          AS login_unlocked
               FROM users WHERE id = %s""",
            (user_id,),
        )
        snapshot = await cur.fetchone()
    if (
        snapshot is None
        or not snapshot["is_active"]
        or snapshot["auth_method"] != "local"
        or not snapshot["password_hash"]
    ):
        raise SelfEmailChangeRejected("ineligible_account")
    if not snapshot["login_unlocked"]:
        raise SelfEmailChangeRejected("account_locked")

    try:
        await run_password_work(
            password_hasher.verify,
            snapshot["password_hash"],
            current_password,
        )
    except VerifyMismatchError as exc:
        raise SelfEmailChangeRejected("invalid_password") from exc
    except (InvalidHashError, VerificationError) as exc:
        logger.exception("Unverifiable password hash for user id=%s", user_id)
        raise SelfEmailChangeRejected("invalid_password") from exc

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT email,
                   password_hash,
                   auth_revision,
                   is_active,
                   auth_method,
                   (locked_until IS NULL OR locked_until <= clock_timestamp())
                       AS login_unlocked
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        user = await cur.fetchone()
        if (
            user is None
            or not user["is_active"]
            or user["auth_method"] != "local"
            or not user["password_hash"]
        ):
            raise SelfEmailChangeRejected("ineligible_account")
        if not user["login_unlocked"]:
            raise SelfEmailChangeRejected("account_locked")

        await cur.execute(
            """
            SELECT 1
            FROM sessions
            WHERE id = %s
              AND user_id = %s
              AND purpose = 'full'
              AND expires_at > clock_timestamp()
            FOR UPDATE
            """,
            (hash_session_id(session_id), user_id),
        )
        if await cur.fetchone() is None:
            raise SelfEmailChangeRejected("invalid_session")

        if user["auth_revision"] != snapshot["auth_revision"]:
            raise SelfEmailChangeRejected("invalid_session")

        if user["password_hash"] != snapshot["password_hash"]:
            raise SelfEmailChangeRejected("retry_required")

        old_email = user["email"]
        if normalized_email.lower() == old_email.lower():
            raise SelfEmailChangeRejected("same_email")

        revision = user["auth_revision"]
        token = generate_email_change_token(
            user_id,
            normalized_email,
            auth_revision=revision,
        )
        action = email_change_token_email_metadata(token)
        verification_email = build_email_change_verification(
            normalized_email,
            f"{settings.public_base_url}/account/confirm-email/{token}",
            expires_at=action.expires_at,
        )
        await store_pending_email_cur(
            cur,
            user_id,
            normalized_email,
            action.token_hash,
            expected_auth_revision=revision,
        )

        notice_email = build_email_change_notice(old_email, normalized_email)
        await enqueue_outbound_email_cur(
            cur,
            user_id=user_id,
            email=notice_email,
            action=None,
        )

        await enqueue_outbound_email_cur(
            cur,
            user_id=user_id,
            email=verification_email,
            action=action,
        )

        return SelfEmailChangeResult(
            user_id=user_id,
            old_email=old_email,
            new_email=normalized_email,
        )


async def stage_admin_email_change(
    pool: AsyncConnectionPool,
    *,
    actor_id: int,
    actor_session_id: str,
    target_user_id: int,
    new_email: str,
) -> AdminEmailChangeResult:
    """Guard the admin session and atomically stage email plus confirmation/notice.

    Normalize the destination, lock an active local target, and reject its
    current address or another account's address. Return committed addresses.
    AdminEmailChangeRejected carries validation/target reasons; the admin guard
    may raise AdminActionRejected. Database/outbox failures roll back all writes.
    """
    normalized_email = normalize_email(new_email)
    if normalized_email is None:
        raise AdminEmailChangeRejected("invalid_email")

    async with get_db_cursor(pool) as cur:
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        await cur.execute(
            """
            SELECT email, auth_method, is_active, auth_revision
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (target_user_id,),
        )
        target = await cur.fetchone()
        if target is None:
            raise AdminEmailChangeRejected("user_not_found")
        if target["auth_method"] != "local":
            raise AdminEmailChangeRejected("federated_account")
        if not target["is_active"]:
            raise AdminEmailChangeRejected("inactive_account")

        old_email = target["email"]
        if normalized_email.lower() == old_email.lower():
            raise AdminEmailChangeRejected("same_email")

        await cur.execute(
            """
            SELECT 1
            FROM users
            WHERE LOWER(email) = LOWER(%s)
              AND id != %s
            LIMIT 1
            """,
            (normalized_email, target_user_id),
        )
        if await cur.fetchone() is not None:
            raise AdminEmailChangeRejected("email_in_use")

        revision = target["auth_revision"]
        token = generate_email_change_token(
            target_user_id,
            normalized_email,
            auth_revision=revision,
            acting_admin_id=actor_id,
        )
        action = email_change_token_email_metadata(token)
        verification_email = build_email_change_verification(
            normalized_email,
            f"{settings.public_base_url}/account/confirm-email/{token}",
            expires_at=action.expires_at,
        )
        notice_email = build_email_change_notice(old_email, normalized_email)

        await store_pending_email_cur(
            cur,
            target_user_id,
            normalized_email,
            action.token_hash,
            expected_auth_revision=revision,
        )
        await enqueue_outbound_email_cur(
            cur,
            user_id=target_user_id,
            email=verification_email,
            action=action,
        )
        await enqueue_outbound_email_cur(
            cur,
            user_id=target_user_id,
            email=notice_email,
            action=None,
        )

        return AdminEmailChangeResult(
            target_user_id=target_user_id,
            old_email=old_email,
            new_email=normalized_email,
        )


async def confirm_email_change(
    pool: AsyncConnectionPool,
    user_id: int,
    new_email: str,
    token_hash: str,
    *,
    expected_auth_revision: int,
) -> bool:
    """Consume a current pending capability and return whether the address changed.

    The caller validates the signature first. Require active/local state, exact
    pending address/hash/revision, age under one hour, and case-insensitive
    uniqueness. Success verifies the new email, increments auth_revision, and
    revokes sessions/pending capabilities atomically. Current recovery codes and
    the recovery-required flag remain. A stale capability or email collision
    returns False; other database failures propagate.
    """
    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """
                UPDATE users
                SET email = pending_email,
                    email_verified = true,
                    email_verification_token_hash = NULL,
                    email_verification_created_at = NULL,
                    pending_email = NULL,
                    pending_email_token_hash = NULL,
                    pending_email_created_at = NULL,
                    auth_revision = auth_revision + 1
                WHERE id = %s
                  AND pending_email_token_hash = %s
                  AND pending_email = %s
                  AND auth_revision = %s
                  AND auth_method = 'local'
                  AND is_active
                  AND pending_email_created_at >
                      CURRENT_TIMESTAMP - %s * INTERVAL '1 second'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM users u2
                      WHERE LOWER(u2.email) = LOWER(%s)
                        AND u2.id != %s
                  )
                RETURNING id
                """,
                (
                    user_id,
                    token_hash,
                    new_email,
                    expected_auth_revision,
                    EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
                    new_email,
                    user_id,
                ),
            )
            if await cur.fetchone() is None:
                return False

            await delete_user_sessions_cur(cur, user_id)
            await invalidate_pending_authentication_state_cur(cur, user_id)
            return True
    except UniqueViolation as exc:
        if is_users_email_collision(exc):
            return False
        raise


async def pending_email_change_matches(
    pool: AsyncConnectionPool,
    user_id: int,
    new_email: str,
    *,
    expected_auth_revision: int,
    expected_token_hash: str,
) -> bool:
    """Check current active/local pending address, hash, revision, and one-hour age.

    This does not consume the capability or check destination uniqueness;
    confirm_email_change must recheck when writing.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT 1 FROM users
               WHERE id = %s
                 AND pending_email = %s
                 AND pending_email_token_hash = %s
                 AND auth_revision = %s
                 AND auth_method = 'local'
                 AND is_active
                 AND pending_email_created_at
                       > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'""",
            (
                user_id,
                new_email,
                expected_token_hash,
                expected_auth_revision,
                EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
            ),
        )
        return await cur.fetchone() is not None
