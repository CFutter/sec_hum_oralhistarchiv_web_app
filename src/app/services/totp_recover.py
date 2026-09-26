"""Authorize local TOTP replacement without disclosing target credentials to admins.

A different local administrator proves TOTP to reset the target factor.
The owner then redeems a retained recovery code plus password for enrollment.
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from psycopg_pool import AsyncConnectionPool

from app.credentials import normalize_email

from .authentication import verify_dummy
from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import password_hasher
from .db import get_db_cursor
from .password_work import run_password_work
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .sessions import create_session_cur
from .tokens import hash_token
from .totp import normalize_totp_code, verify_and_consume_totp_cur
from .totp_recovery_codes import (
    TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
    MatchedRecoveryCodeCandidate,
    ReservedRecoveryCodePasswordAttempt,
    consume_reserved_recovery_code_cur,
    has_unused_active_recovery_code_cur,
    normalize_recovery_code,
    reserve_recovery_code_password_attempt_cur,
)
from .users import guard_current_admin_session_cur

logger = logging.getLogger(__name__)

TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS = 30 * 60
TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS = 15 * 60
_NO_MATCH_RECOVERY_CODE_HASH = "z" * 64
TotpRecoveryRejectionReason = Literal[
    "self_recovery",
    "user_not_found",
    "ineligible_account",
    "authenticator_not_configured",
    "recovery_codes_unavailable",
    "actor_ineligible",
    "actor_session_invalid",
    "actor_account_locked",
    "actor_step_up_exhausted",
    "invalid_admin_totp",
]


class TotpRecoveryRejected(ValueError):
    """A recovery authorization failed a stable policy decision."""

    def __init__(self, reason: TotpRecoveryRejectionReason) -> None:
        """Expose the stable policy reason as .reason and the exception message."""
        self.reason = reason
        super().__init__(reason)


TotpRecoveryRedemptionReason = Literal[
    "invalid_credentials",
    "account_ineligible",
    "recovery_not_authorized",
    "recovery_expired",
    "auth_state_changed",
]


class TotpRecoveryRedemptionRejected(ValueError):
    """A public redemption failed; callers must use one generic response."""

    def __init__(
        self,
        reason: TotpRecoveryRedemptionReason,
        *,
        user_id: int | None = None,
    ) -> None:
        """Store an internal reason and optional known user ID for generic-response callers."""
        self.reason = reason
        self.user_id = user_id
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class TotpRecoveryTarget:
    """Non-secret target state used by the administrator confirmation page."""

    user_id: int
    email: str
    display_name: str | None
    auth_method: str
    is_active: bool
    email_verified: bool
    totp_configured: bool
    recovery_required: bool
    recovery_codes_available: bool
    recovery_authorization_active: bool
    recovery_expires_at: datetime | None

    @property
    def eligible(self) -> bool:
        """Check snapshot target eligibility; the authorizing write must revalidate it."""
        return (
            self.auth_method == "local"
            and self.is_active
            and self.email_verified
            and (self.totp_configured or self.recovery_required)
            and self.recovery_codes_available
        )


@dataclass(frozen=True, slots=True)
class TotpRecoveryAuthorization:
    """Committed administrator authorization without target credentials."""

    target_user_id: int
    email: str
    display_name: str | None
    expires_at: datetime
    reissued: bool


@dataclass(frozen=True, slots=True)
class TotpRecoveryRedemption:
    """A committed restricted recovery session."""

    user_id: int
    session_id: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _RecoveryPasswordAttempt:
    """A committed per-code attempt and the credential snapshot it permits."""

    reservation: ReservedRecoveryCodePasswordAttempt
    password_hash: str = field(repr=False)
    auth_revision: int


def _target_from_row(row: dict[str, Any]) -> TotpRecoveryTarget:
    """Map recovery-query fields into the non-secret target snapshot."""
    return TotpRecoveryTarget(
        user_id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        auth_method=row["auth_method"],
        is_active=row["is_active"],
        email_verified=row["email_verified"],
        totp_configured=row["totp_configured"],
        recovery_required=row["totp_recovery_required"],
        recovery_codes_available=row["recovery_codes_available"],
        recovery_authorization_active=row["recovery_authorization_active"],
        recovery_expires_at=row["totp_recovery_expires_at"],
    )


async def get_totp_recovery_target(
    pool: AsyncConnectionPool,
    user_id: int,
) -> TotpRecoveryTarget | None:
    """Return recovery presentation state, or None if the user is absent.

    This read does not authenticate or authorize its caller.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT id,
                   email,
                   display_name,
                   auth_method,
                   is_active,
                   email_verified,
                   (totp_secret IS NOT NULL) AS totp_configured,
                   totp_recovery_required,
                   EXISTS (
                       SELECT 1
                       FROM totp_recovery_codes AS codes
                       WHERE codes.user_id = users.id
                         AND codes.generation = users.totp_recovery_code_generation
                         AND codes.used_at IS NULL
                         AND codes.password_attempt_count < %s
                   ) AS recovery_codes_available,
                   (
                       totp_recovery_authorized_at IS NOT NULL
                       AND totp_recovery_expires_at > clock_timestamp()
                       AND totp_recovery_auth_revision = auth_revision
                   ) AS recovery_authorization_active,
                   totp_recovery_expires_at
            FROM users
            WHERE id = %s
            """,
            (TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT, user_id),
        )
        row = await cur.fetchone()

    return None if row is None else _target_from_row(row)


def _validate_locked_target(row: dict[str, Any] | None) -> bool:
    """Validate an active verified local target and return its recovery-required flag.

    Raise TotpRecoveryRejected for a missing/ineligible user or absent factor
    without existing recovery state. The caller holds the user-row lock.
    """
    if row is None:
        raise TotpRecoveryRejected("user_not_found")
    if row["auth_method"] != "local" or not row["is_active"] or not row["email_verified"]:
        raise TotpRecoveryRejected("ineligible_account")
    if row["totp_secret"] is None and not row["totp_recovery_required"]:
        raise TotpRecoveryRejected("authenticator_not_configured")
    return bool(row["totp_recovery_required"])


async def authorize_totp_recovery(
    pool: AsyncConnectionPool,
    *,
    actor_id: int,
    actor_session_id: str,
    target_user_id: int,
    admin_totp_code: str,
) -> TotpRecoveryAuthorization:
    """Commit a 30-minute recovery authorization after a different local admin proves TOTP.

    Spend a durable actor-session step-up attempt first. Under the admin guard,
    consume fresh actor TOTP, require a verified active local target with a
    usable retained code, revoke target sessions/pending state, clear its TOTP,
    and advance auth_revision. Return target metadata, expiry, and whether
    recovery was already required. TotpRecoveryRejected/ AdminActionRejected
    identify policy failures; decryption/storage errors roll back authorization
    but not the attempt. No target code is created or exposed.
    """
    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=actor_id,
        session_id=actor_session_id,
    )
    if reservation is SessionStepUpAttemptOutcome.INVALID_SESSION:
        raise TotpRecoveryRejected("actor_session_invalid")
    if reservation is SessionStepUpAttemptOutcome.ACCOUNT_LOCKED:
        raise TotpRecoveryRejected("actor_account_locked")
    if reservation is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        raise TotpRecoveryRejected("actor_step_up_exhausted")
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")

    normalized_admin_code = normalize_totp_code(admin_totp_code)
    if normalized_admin_code is None:
        raise TotpRecoveryRejected("invalid_admin_totp")

    async with get_db_cursor(pool) as cur:
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )

        if actor_id == target_user_id:
            raise TotpRecoveryRejected("self_recovery")

        await cur.execute(
            """
            SELECT auth_method,
                   (totp_secret IS NOT NULL) AS totp_configured,
                   (locked_until IS NULL OR locked_until <= clock_timestamp())
                       AS login_unlocked
            FROM users
            WHERE id = %s
            """,
            (actor_id,),
        )
        actor = await cur.fetchone()
        if actor is None or actor["auth_method"] != "local" or not actor["totp_configured"]:
            raise TotpRecoveryRejected("actor_ineligible")
        if not actor["login_unlocked"]:
            raise TotpRecoveryRejected("actor_account_locked")

        if not await verify_and_consume_totp_cur(
            cur,
            actor_id,
            normalized_admin_code,
        ):
            raise TotpRecoveryRejected("invalid_admin_totp")

        await cur.execute(
            """
            SELECT id,
                   email,
                   display_name,
                   auth_method,
                   is_active,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   totp_recovery_code_generation
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (target_user_id,),
        )
        target = await cur.fetchone()
        reissued = _validate_locked_target(target)
        if target is None:  # narrowed by _validate_locked_target
            raise RuntimeError("TOTP recovery target unexpectedly missing")
        if not await has_unused_active_recovery_code_cur(
            cur,
            user_id=target_user_id,
            active_generation=target["totp_recovery_code_generation"],
        ):
            raise TotpRecoveryRejected("recovery_codes_unavailable")

        await delete_user_sessions_cur(cur, target_user_id)
        await invalidate_pending_authentication_state_cur(cur, target_user_id)

        await cur.execute("SELECT clock_timestamp() AS now")
        clock_row = await cur.fetchone()
        if clock_row is None or not isinstance(clock_row["now"], datetime):
            raise RuntimeError("Database clock query returned no valid timestamp")
        authorized_at = clock_row["now"].astimezone(UTC)
        expires_at = authorized_at + timedelta(seconds=TOTP_RECOVERY_AUTHORIZATION_MAX_AGE_SECONDS)

        await cur.execute(
            """
            UPDATE users
            SET totp_secret = NULL,
                last_totp_step = NULL,
                auth_revision = auth_revision + 1,
                totp_recovery_required = true,
                totp_recovery_expires_at = %s,
                totp_recovery_authorized_at = %s,
                totp_recovery_auth_revision = auth_revision + 1
            WHERE id = %s
            """,
            (
                expires_at,
                authorized_at,
                target_user_id,
            ),
        )

    logger.info(
        "Administrator %d authorized TOTP recovery for user %d; reissued=%s; expires_at=%s",
        actor_id,
        target_user_id,
        reissued,
        expires_at.isoformat(),
    )
    return TotpRecoveryAuthorization(
        target_user_id=target_user_id,
        email=target["email"],
        display_name=target["display_name"],
        expires_at=expires_at,
        reissued=reissued,
    )


def _recovery_row_is_eligible(row: dict[str, Any] | None) -> bool:
    """Return whether a snapshot can reserve public recovery password work."""
    return bool(
        row is not None
        and row["auth_method"] == "local"
        and row["is_active"]
        and row["email_verified"]
        and row["totp_secret"] is None
        and row["totp_recovery_required"]
        and row["totp_recovery_authorized_at"] is not None
        and row["totp_recovery_auth_revision"] == row["auth_revision"]
        and row["recovery_unexpired"]
        and row["totp_recovery_code_generation"] > 0
        and isinstance(row["password_hash"], str)
        and row["password_hash"]
    )


async def _reserve_recovery_password_attempt(
    pool: AsyncConnectionPool,
    *,
    email: str,
    recovery_code: str,
) -> _RecoveryPasswordAttempt | None:
    """Normalize email, match a usable code without locks, then commit one attempt.

    Return None for invalid/ineligible/stale/exhausted state; otherwise return
    the reserved code and current password/revision snapshot. Only a code match
    reaches user/code locks, and later password failure cannot refund the attempt.
    """
    normalized_email = normalize_email(email)
    if normalized_email is None:
        return None

    canonical_code = normalize_recovery_code(recovery_code)
    candidate_hash = (
        hash_token(canonical_code) if canonical_code is not None else _NO_MATCH_RECOVERY_CODE_HASH
    )

    selection_sql = """
        SELECT users.id,
               users.password_hash,
               users.auth_revision,
               users.auth_method,
               users.is_active,
               users.email_verified,
               users.totp_secret,
               users.totp_recovery_required,
               users.totp_recovery_code_generation,
               users.totp_recovery_authorized_at,
               users.totp_recovery_auth_revision,
               (
                   users.totp_recovery_expires_at IS NOT NULL
                   AND users.totp_recovery_expires_at > clock_timestamp()
               ) AS recovery_unexpired,
               matched_code.position AS recovery_code_position
        FROM users
        LEFT JOIN totp_recovery_codes AS matched_code
          ON matched_code.user_id = users.id
         AND matched_code.generation = users.totp_recovery_code_generation
         AND matched_code.code_hash = %s
         AND matched_code.used_at IS NULL
         AND matched_code.password_attempt_count < %s
    """

    # An impossible digest keeps malformed codes on the same nonlocking query.
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            selection_sql
            + """
              WHERE LOWER(email) = LOWER(%s)
                AND auth_method = 'local'
            """,
            (
                candidate_hash,
                TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
                normalized_email,
            ),
        )
        initial = await cur.fetchone()
        if (
            not _recovery_row_is_eligible(initial)
            or initial is None
            or initial["recovery_code_position"] is None
        ):
            return None
        candidate = MatchedRecoveryCodeCandidate(
            user_id=initial["id"],
            generation=initial["totp_recovery_code_generation"],
            position=initial["recovery_code_position"],
            code_hash=candidate_hash,
        )

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT id,
                   password_hash,
                   auth_revision,
                   auth_method,
                   is_active,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   totp_recovery_code_generation,
                   totp_recovery_authorized_at,
                   totp_recovery_auth_revision,
                   (
                       totp_recovery_expires_at IS NOT NULL
                       AND totp_recovery_expires_at > clock_timestamp()
                   ) AS recovery_unexpired
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (candidate.user_id,),
        )
        locked = await cur.fetchone()
        if (
            not _recovery_row_is_eligible(locked)
            or locked is None
            or locked["totp_recovery_code_generation"] != candidate.generation
        ):
            return None

        reservation = await reserve_recovery_code_password_attempt_cur(
            cur,
            candidate=candidate,
        )
        if reservation is None:
            return None
        return _RecoveryPasswordAttempt(
            reservation=reservation,
            password_hash=locked["password_hash"],
            auth_revision=locked["auth_revision"],
        )


async def redeem_totp_recovery(
    pool: AsyncConnectionPool,
    *,
    email: str,
    password: str,
    recovery_code: str,
    ip_address: str,
) -> TotpRecoveryRedemption:
    """Consume a retained code/password and return a raw 15-minute recovery-session token.

    Require active/verified local recovery state and a current revision-bound
    admin authorization. Reserve a code's three-attempt password budget before
    hashing; unknown codes get dummy work without mutations. The final locked
    transaction rechecks credentials, consumes the code/authorization, clears
    login lockout state, and replaces every session with totp_recovery. An
    existing login lock does not block recovery. TotpRecoveryRedemptionRejected
    carries internal reasons; callers must return one generic public response.
    Later failures roll back completion but preserve the reserved attempt.
    """
    attempt = await _reserve_recovery_password_attempt(
        pool,
        email=email,
        recovery_code=recovery_code,
    )
    if attempt is None:
        await verify_dummy(password)
        raise TotpRecoveryRedemptionRejected("invalid_credentials")

    user_id = attempt.reservation.user_id
    try:
        await run_password_work(
            password_hasher.verify,
            attempt.password_hash,
            password,
        )
    except VerifyMismatchError as exc:
        raise TotpRecoveryRedemptionRejected(
            "invalid_credentials",
            user_id=user_id,
        ) from exc
    except (InvalidHashError, VerificationError) as exc:
        logger.exception("Unverifiable password hash during TOTP recovery for user %d", user_id)
        await verify_dummy(password)
        raise TotpRecoveryRedemptionRejected(
            "invalid_credentials",
            user_id=user_id,
        ) from exc

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT password_hash,
                   auth_revision,
                   auth_method,
                   is_active,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   totp_recovery_code_generation,
                   totp_recovery_authorized_at,
                   totp_recovery_auth_revision,
                   (
                       totp_recovery_expires_at IS NOT NULL
                       AND totp_recovery_expires_at > clock_timestamp()
                   ) AS recovery_unexpired
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        row = await cur.fetchone()

        if row is None:
            raise TotpRecoveryRedemptionRejected(
                "auth_state_changed",
                user_id=user_id,
            )
        if (
            row["password_hash"] != attempt.password_hash
            or row["auth_revision"] != attempt.auth_revision
        ):
            raise TotpRecoveryRedemptionRejected(
                "auth_state_changed",
                user_id=user_id,
            )
        if (
            row["auth_method"] != "local"
            or not row["is_active"]
            or not row["email_verified"]
            or row["totp_secret"] is not None
            or not row["totp_recovery_required"]
        ):
            raise TotpRecoveryRedemptionRejected(
                "account_ineligible",
                user_id=user_id,
            )

        recovery_is_bound = (
            row["totp_recovery_authorized_at"] is not None
            and row["totp_recovery_auth_revision"] == row["auth_revision"]
        )
        if not recovery_is_bound:
            raise TotpRecoveryRedemptionRejected(
                "recovery_not_authorized",
                user_id=user_id,
            )
        if not row["recovery_unexpired"]:
            raise TotpRecoveryRedemptionRejected(
                "recovery_expired",
                user_id=user_id,
            )
        if not await consume_reserved_recovery_code_cur(
            cur,
            reservation=attempt.reservation,
        ):
            raise TotpRecoveryRedemptionRejected(
                "invalid_credentials",
                user_id=user_id,
            )

        # A reissued authorization may race a request holding an older browser cookie.
        # Revoke every session again before installing the sole new capability.
        await delete_user_sessions_cur(cur, user_id)
        await cur.execute(
            """
            UPDATE users
            SET failed_login_count = 0,
                locked_until = NULL,
                lockout_notice_enqueued_at = NULL,
                totp_recovery_expires_at = NULL,
                totp_recovery_authorized_at = NULL,
                totp_recovery_auth_revision = NULL
            WHERE id = %s
            """,
            (user_id,),
        )
        session_id = await create_session_cur(
            cur,
            user_id=user_id,
            ip_address=ip_address,
            purpose="totp_recovery",
            max_age_seconds=TOTP_RECOVERY_SESSION_MAX_AGE_SECONDS,
        )

    logger.info("TOTP recovery code redeemed for user %d", user_id)
    return TotpRecoveryRedemption(user_id=user_id, session_id=session_id)
