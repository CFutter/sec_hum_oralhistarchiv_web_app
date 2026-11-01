"""Verify local passwords and finalize logins with revision-checked state.

Unusable credentials receive dummy Argon2 work, not constant-time requests.
Successful verification may rehash a password but does not log in or reset
failures; finalize_local_login performs eligibility, TOTP, and session writes
atomically. Failure recording ignores active locks and starts a new streak
after an expired lock, clearing its notice marker. Notices are queued once
per streak in the caller's transaction.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, NamedTuple

from psycopg import AsyncCursor, sql
from psycopg_pool import AsyncConnectionPool

from config import settings

from .account_clock import database_now_cur
from .crypto import password_hasher
from .db import get_db_cursor
from .email import build_account_locked_notice
from .email_outbox import OutboundEmail, enqueue_outbound_email_cur
from .password_verification import PasswordFailureReason, PasswordVerified, verify_password_hash
from .password_verification import (
    verify_dummy as verify_dummy,  # noqa: PLC0414 - import compatibility
)
from .password_verification import (
    warm_dummy_password_hash as warm_dummy_password_hash,  # noqa: PLC0414 - import compatibility
)
from .password_work import run_password_work
from .sessions import SessionPurpose, create_session_cur
from .totp import verify_and_consume_totp_cur
from .users import USER_COLUMNS_SQL, User, parse_user

logger = logging.getLogger(__name__)

LoginFailureReason = Literal[
    "unknown_email",
    "non_local_account",
    "inactive_account",
    "account_locked",
    "no_password_hash",
    "unverifiable_hash",
    "wrong_password",
]

LocalLoginFailureReason = Literal[
    "unknown_user",
    "non_local_account",
    "inactive_account",
    "unverified_email",
    "totp_recovery_required",
    "auth_state_changed",
    "account_locked",
    "wrong_totp",
]


@dataclass(frozen=True)
class LocalLoginSuccess:
    """Committed login with the raw session token and its access purpose."""

    user: User
    session_id: str = field(repr=False)
    purpose: SessionPurpose


@dataclass(frozen=True)
class LocalLoginFailure:
    """Rejected login; wrong_totp may include committed failure/notice state.

    just_locked means entry into a new lock window; user is None if absent.
    """

    reason: LocalLoginFailureReason
    user: User | None
    failed_count: int | None = None
    just_locked: bool = False
    lockout_notice_queued: bool = False


LocalLoginResult = LocalLoginSuccess | LocalLoginFailure

# These failures require credential repair, not another password attempt.
CREDENTIAL_INTEGRITY_FAULTS: frozenset[LoginFailureReason] = frozenset(
    {"unverifiable_hash", "no_password_hash"}
)


class PasswordCheck(NamedTuple):
    """Credential snapshot; only password_ok=True has no failure_reason.

    user is present for any matching account. locked_until is set only for an
    active local-account lock. auth_revision is present on real credential-check
    paths, including missing or invalid hashes, for subsequent guarded writes.
    """

    user: User | None
    password_ok: bool
    locked_until: datetime | None
    failure_reason: LoginFailureReason | None
    auth_revision: int | None


async def verify_password(pool: AsyncConnectionPool, email: str, password: str) -> PasswordCheck:
    """Verify a local, active, unlocked account using case-insensitive email.

    Email is not stripped. Returns PasswordCheck without changing failure state
    or checking email verification/TOTP. A successful stale Argon2 hash is
    replaced only if its hash and auth_revision still match the snapshot;
    finalize_local_login must recheck that revision before granting a session.
    Absent/ineligible accounts and unusable hashes receive dummy Argon2 work;
    unusable hashes are logged.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                """
                SELECT {}, password_hash, locked_until, auth_revision
                FROM users
                WHERE LOWER(email) = LOWER(%s)
                """
            ).format(USER_COLUMNS_SQL),
            (email,),
        )
        row = await cur.fetchone()
        locked_until = None
        if (
            row is not None
            and row["auth_method"] == "local"
            and row["is_active"]
            and row["locked_until"] is not None
        ):
            now = await database_now_cur(cur)
            if row["locked_until"] > now:
                locked_until = row["locked_until"]

    if not row:
        await verify_dummy(password)
        return PasswordCheck(
            user=None,
            password_ok=False,
            locked_until=None,
            failure_reason="unknown_email",
            auth_revision=None,
        )

    user = parse_user(row)

    # Preserve the authentication-method reason even for inactive federated users.
    if row["auth_method"] != "local":
        await verify_dummy(password)
        return PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="non_local_account",
            auth_revision=None,
        )

    if not row["is_active"]:
        await verify_dummy(password)
        return PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="inactive_account",
            auth_revision=None,
        )

    if locked_until is not None:
        await verify_dummy(password)
        return PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=locked_until,
            failure_reason="account_locked",
            auth_revision=None,
        )

    if not row["password_hash"]:
        # Missing or empty hashes require credential repair, not another login attempt.
        await verify_dummy(password)
        return PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="no_password_hash",
            auth_revision=row["auth_revision"],
        )

    result = await verify_password_hash(
        password_hash=row["password_hash"],
        password=password,
        user_id=row["id"],
        operation="login",
    )
    if (
        not isinstance(result, PasswordVerified)
        and result.reason is PasswordFailureReason.UNUSABLE_HASH
    ):
        await verify_dummy(password)
        return PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="unverifiable_hash",
            auth_revision=row["auth_revision"],
        )

    password_ok = isinstance(result, PasswordVerified)
    if password_ok and password_hasher.check_needs_rehash(row["password_hash"]):
        new_hash = await run_password_work(password_hasher.hash, password)
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
                    AND password_hash = %s
                    AND auth_revision = %s
                """,
                (
                    new_hash,
                    row["id"],
                    row["password_hash"],
                    row["auth_revision"],
                ),
            )
    return PasswordCheck(
        user=user,
        password_ok=password_ok,
        locked_until=None,
        failure_reason=None if password_ok else "wrong_password",
        auth_revision=row["auth_revision"],
    )


async def finalize_local_login(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    expected_auth_revision: int,
    totp_code: str,
    ip_address: str,
) -> LocalLoginResult:
    """Commit login after password proof at expected_auth_revision.

    Lock/recheck local active verified state, revision, lockout and recovery, then
    consume required TOTP. Wrong TOTP commits failure/notice state; other expected
    rejections return LocalLoginFailure. Success clears lockout, sets last_login,
    and returns a raw full-session token, or a totp_setup token without TOTP.
    Full sessions use SESSION_MAX_AGE_SECONDS; setup sessions are capped at 600
    seconds. Database/decryption failures roll back; a vanished locked user raises
    RuntimeError.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                """
                SELECT {}, auth_revision, locked_until
                FROM users
                WHERE id = %s
                FOR UPDATE
                """
            ).format(USER_COLUMNS_SQL),
            (user_id,),
        )
        row = await cur.fetchone()

        if row is None:
            return LocalLoginFailure(
                reason="unknown_user",
                user=None,
            )

        user = parse_user(row)

        if user.auth_method != "local":
            return LocalLoginFailure(
                reason="non_local_account",
                user=user,
            )

        if not user.is_active:
            return LocalLoginFailure(
                reason="inactive_account",
                user=user,
            )

        if not user.email_verified:
            return LocalLoginFailure(
                reason="unverified_email",
                user=user,
            )

        if row["auth_revision"] != expected_auth_revision:
            return LocalLoginFailure(
                reason="auth_state_changed",
                user=user,
            )

        # Administrator-authorized recovery must never fall through to the
        # ordinary "no TOTP yet" branch. Only the dedicated recovery-code
        # redemption path may mint a totp_recovery session.
        if user.totp_recovery_required:
            return LocalLoginFailure(
                reason="totp_recovery_required",
                user=user,
            )

        locked_until = row["locked_until"]
        if locked_until is not None and locked_until > await database_now_cur(cur):
            return LocalLoginFailure(
                reason="account_locked",
                user=user,
            )

        purpose: SessionPurpose = "totp_setup"

        if user.totp_configured:
            totp_valid = await verify_and_consume_totp_cur(
                cur,
                user.id,
                totp_code,
            )

            if not totp_valid:
                failed_count, just_locked = await record_login_failure_cur(
                    cur, user.id, expected_auth_revision=expected_auth_revision
                )

                notice_queued = False
                if just_locked:
                    notice_queued = await queue_lockout_notice_cur(
                        cur,
                        user_id=user.id,
                        expected_auth_revision=expected_auth_revision,
                        email=build_account_locked_notice(user.email),
                    )

                # Returning normally commits the failure counter and
                # any queued notice. Raising here would roll them back.
                return LocalLoginFailure(
                    reason="wrong_totp",
                    user=user,
                    failed_count=failed_count,
                    just_locked=just_locked,
                    lockout_notice_queued=notice_queued,
                )

            purpose = "full"

        await cur.execute(
            sql.SQL(
                """
                UPDATE users
                SET failed_login_count = 0,
                    locked_until = NULL,
                    lockout_notice_enqueued_at = NULL,
                    last_login = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING {}
                """
            ).format(USER_COLUMNS_SQL),
            (user.id,),
        )
        updated_row = await cur.fetchone()

        if updated_row is None:
            raise RuntimeError("Locked user disappeared during login finalization")

        session_id = await create_session_cur(
            cur,
            user_id=user.id,
            ip_address=ip_address,
            purpose=purpose,
            max_age_seconds=settings.session_max_age_seconds,
        )

        result = LocalLoginSuccess(
            user=parse_user(updated_row),
            session_id=session_id,
            purpose=purpose,
        )

    logger.info(
        "Local login finalized for user %d from %s (purpose: %s)",
        result.user.id,
        ip_address,
        result.purpose,
    )
    return result


async def queue_lockout_notice_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    expected_auth_revision: int,
    email: OutboundEmail,
) -> bool:
    """Claim and enqueue one notice per failure streak in the caller's transaction.

    The caller must hold the user row lock, acquired by record_login_failure_cur
    or finalize_local_login, before calling. Return False if the active local
    user/revision/lock no longer matches or a notice was claimed.
    An enqueue failure propagates so the transaction can roll back the claim.
    """
    await cur.execute(
        """
        UPDATE users
        SET lockout_notice_enqueued_at = clock_timestamp()
        WHERE id = %s
          AND auth_revision = %s
          AND auth_method = 'local'
          AND is_active
          AND locked_until > clock_timestamp()
          AND lockout_notice_enqueued_at IS NULL
        RETURNING id
        """,
        (user_id, expected_auth_revision),
    )
    if await cur.fetchone() is None:
        return False

    await enqueue_outbound_email_cur(
        cur,
        user_id=user_id,
        email=email,
        action=None,
    )
    return True


async def record_login_failure_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    *,
    expected_auth_revision: int,
) -> tuple[int | None, bool]:
    """Record a revision-matched active local user's failure under a row lock.

    Return (count, entered_lockout), or (None, False) if eligibility changed.
    An active lock leaves state unchanged. An expired lock starts at one failure
    and clears the notice marker; otherwise increment the count. At
    LOGIN_FAILURE_THRESHOLD, lock for LOGIN_LOCKOUT_MINUTES. The caller owns
    the transaction and queues a notice on a True transition.
    """
    threshold = settings.login_failure_threshold
    lockout_duration = timedelta(minutes=settings.login_lockout_minutes)

    await cur.execute(
        """
        SELECT failed_login_count, locked_until
        FROM users
        WHERE id = %s AND auth_revision = %s
          AND auth_method = 'local' AND is_active
        FOR UPDATE
        """,
        (user_id, expected_auth_revision),
    )
    previous = await cur.fetchone()
    if previous is None:
        return None, False

    # Read database time after acquiring the row lock. The request may have
    # waited for another transaction while the previous lock expired.
    database_now = await database_now_cur(cur)

    previous_locked_until = previous["locked_until"]

    # Another request may have locked the account during password verification.
    # This failure must not increment the counter or extend that active lock.
    if previous_locked_until is not None and previous_locked_until > database_now:
        return previous["failed_login_count"], False

    expired = previous_locked_until is not None
    new_count = 1 if expired else previous["failed_login_count"] + 1
    new_locked_until = database_now + lockout_duration if new_count >= threshold else None

    await cur.execute(
        """
        UPDATE users
        SET failed_login_count = %s,
            locked_until = %s,
            lockout_notice_enqueued_at = CASE
                WHEN %s THEN NULL
                ELSE lockout_notice_enqueued_at
            END
        WHERE id = %s AND auth_revision = %s
          AND auth_method = 'local' AND is_active
        RETURNING failed_login_count, locked_until
        """,
        (new_count, new_locked_until, expired, user_id, expected_auth_revision),
    )
    row = await cur.fetchone()
    if row is None:
        return None, False

    entered_lockout = row["locked_until"] is not None and row["locked_until"] > database_now
    return row["failed_login_count"], entered_lockout


async def record_login_failure(
    pool: AsyncConnectionPool,
    user_id: int,
    *,
    expected_auth_revision: int,
) -> tuple[int | None, bool]:
    """Commit record_login_failure_cur and return its (count, transition) pair.

    This wrapper queues no notice; login workflows must use the cursor helper
    and queue_lockout_notice_cur in the same transaction.
    """
    async with get_db_cursor(pool) as cur:
        return await record_login_failure_cur(
            cur, user_id, expected_auth_revision=expected_auth_revision
        )
