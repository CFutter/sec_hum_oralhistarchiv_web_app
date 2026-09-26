"""Promote local users through an administrator invitation and target consent.

The target proves password/TOTP, receives a staged recovery-code set, and
confirms one code. Acceptance activates the set and role, advances
auth_revision, and revokes the target's sessions and pending capabilities.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from .authentication import verify_dummy
from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import password_hasher
from .db import get_db_cursor
from .password_work import run_password_work
from .session_ids import hash_session_id
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .totp import normalize_totp_code, verify_and_consume_totp_cur
from .totp_recovery_codes import (
    TOTP_RECOVERY_CODE_COUNT,
    TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
    PendingRecoveryCodeSet,
    activate_pending_recovery_code_set_cur,
    discard_pending_recovery_code_set_cur,
    generate_recovery_codes,
    stage_recovery_code_set_cur,
)
from .users import acquire_admin_action_lock_cur, guard_current_admin_session_cur

logger = logging.getLogger(__name__)

ADMIN_PROMOTION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS = 15 * 60

AdminPromotionRejectionReason = Literal[
    "user_not_found",
    "already_admin",
    "ineligible_account",
    "no_request",
    "invitation_expired",
    "invalid_session",
    "account_locked",
    "step_up_exhausted",
    "invalid_credentials",
    "invalid_totp",
    "state_changed",
    "requester_ineligible",
    "codes_not_prepared",
    "invalid_recovery_code",
]

AdminPromotionState = Literal["pending", "prepared", "expired"]


class AdminPromotionRejected(ValueError):
    """A promotion transition failed a stable, presentation-safe decision."""

    def __init__(self, reason: AdminPromotionRejectionReason) -> None:
        """Expose the stable rejection reason as .reason and the exception message."""
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class AdminPromotion:
    """Target-visible state for one administrator invitation."""

    user_id: int
    requested_by: int
    requested_at: datetime
    expires_at: datetime
    expired: bool
    prepared_for_current_session: bool


@dataclass(frozen=True, slots=True)
class AdminPromotionRequestResult:
    """Committed administrator invitation metadata."""

    user_id: int
    expires_at: datetime
    reissued: bool


@dataclass(frozen=True, slots=True)
class PreparedAdminPromotion:
    """Committed preparation deadlines and plaintext codes; retain before redirecting."""

    user_id: int
    invitation_expires_at: datetime
    preparation_expires_at: datetime
    recovery_codes: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class AcceptedAdminPromotion:
    """A committed promotion whose target sessions were revoked."""

    user_id: int
    requested_by: int


async def _lock_full_session_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    session_id: str,
) -> None:
    """Lock the target's unexpired full session or reject with invalid_session.

    The caller owns the transaction and supplies the raw session token.
    """
    if not session_id:
        raise AdminPromotionRejected("invalid_session")
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
        raise AdminPromotionRejected("invalid_session")


def _validate_target_row(row: dict[str, Any] | None) -> None:
    """Reject absent, existing-admin, or ineligible target snapshots.

    Require an active verified local user with TOTP and no recovery requirement;
    raise AdminPromotionRejected with the corresponding reason.
    """
    if row is None:
        raise AdminPromotionRejected("user_not_found")
    if row["is_admin"]:
        raise AdminPromotionRejected("already_admin")
    if (
        row["auth_method"] != "local"
        or not row["is_active"]
        or not row["email_verified"]
        or row["totp_secret"] is None
        or row["totp_recovery_required"]
    ):
        raise AdminPromotionRejected("ineligible_account")


async def _validate_requester_cur(cur: AsyncCursor[Any], requested_by: int) -> None:
    """Reject an absent/inactive/nonadmin requester in the caller's transaction.

    Local requesters also need TOTP and an unused, unexhausted current recovery
    code. Raise AdminPromotionRejected(requester_ineligible); caller holds the
    admin-action lock to serialize authority changes.
    """
    await cur.execute(
        """
        SELECT requester.is_active,
               requester.is_admin,
               requester.auth_method,
               requester.totp_secret,
               requester.totp_recovery_code_generation,
               EXISTS (
                   SELECT 1
                   FROM totp_recovery_codes AS codes
                   WHERE codes.user_id = requester.id
                     AND codes.generation =
                         requester.totp_recovery_code_generation
                     AND codes.used_at IS NULL
                     AND codes.password_attempt_count < %s
               ) AS recovery_codes_available
        FROM users AS requester
        WHERE requester.id = %s
        """,
        (TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT, requested_by),
    )
    requester = await cur.fetchone()
    if requester is None or not requester["is_active"] or not requester["is_admin"]:
        raise AdminPromotionRejected("requester_ineligible")
    if requester["auth_method"] == "local" and (
        requester["totp_secret"] is None
        or requester["totp_recovery_code_generation"] <= 0
        or not requester["recovery_codes_available"]
    ):
        raise AdminPromotionRejected("requester_ineligible")


async def _verify_password_snapshot(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    password: str,
) -> tuple[str, int]:
    """Verify off-connection and return (password_hash, auth_revision).

    Raise AdminPromotionRejected(invalid_credentials) for missing/bad hashes or
    wrong passwords; missing/unverifiable hashes also run dummy work. Does not
    check account eligibility; callers must revalidate the snapshot under lock.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT password_hash, auth_revision FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()

    if row is None or not isinstance(row["password_hash"], str) or not row["password_hash"]:
        await verify_dummy(password)
        raise AdminPromotionRejected("invalid_credentials")

    password_hash = row["password_hash"]
    try:
        await run_password_work(password_hasher.verify, password_hash, password)
    except VerifyMismatchError as exc:
        raise AdminPromotionRejected("invalid_credentials") from exc
    except (InvalidHashError, VerificationError) as exc:
        logger.exception("Unverifiable password hash during admin promotion for user %d", user_id)
        await verify_dummy(password)
        raise AdminPromotionRejected("invalid_credentials") from exc

    return password_hash, row["auth_revision"]


async def get_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    session_id: str,
) -> AdminPromotion | None:
    """Return invitation state, including expired requests, or None if absent.

    session_id only identifies prepared state; this read does not authorize the
    caller. A current preparation requires matching token hash, a 15-minute
    preparation, an unexpired invitation, and a complete pending code set.
    """
    session_hash = hash_session_id(session_id) if session_id else ""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT request.user_id,
                   request.requested_by,
                   request.requested_at,
                   request.expires_at,
                   request.expires_at <= clock_timestamp() AS expired,
                   (
                       request.prepared_session_id = %s
                       AND request.prepared_at IS NOT NULL
                       AND request.prepared_at >
                           clock_timestamp() - %s * INTERVAL '1 second'
                       AND request.expires_at > clock_timestamp()
                       AND users.pending_totp_recovery_code_generation IS NOT NULL
                       AND (
                           SELECT COUNT(*)
                           FROM totp_recovery_codes AS codes
                           WHERE codes.user_id = request.user_id
                             AND codes.generation =
                                 users.pending_totp_recovery_code_generation
                             AND codes.used_at IS NULL
                       ) = %s
                   ) AS prepared_for_current_session
            FROM admin_promotion_requests AS request
            JOIN users ON users.id = request.user_id
            WHERE request.user_id = %s
            """,
            (
                session_hash,
                ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS,
                TOTP_RECOVERY_CODE_COUNT,
                user_id,
            ),
        )
        row = await cur.fetchone()

    if row is None:
        return None
    return AdminPromotion(
        user_id=row["user_id"],
        requested_by=row["requested_by"],
        requested_at=row["requested_at"],
        expires_at=row["expires_at"],
        expired=row["expired"],
        prepared_for_current_session=row["prepared_for_current_session"],
    )


async def list_admin_promotion_states(
    pool: AsyncConnectionPool,
    user_ids: list[int],
) -> dict[int, AdminPromotionState]:
    """Map requested user IDs with invitations to expired/prepared/pending states.

    Missing IDs are omitted; empty input returns {}. prepared checks timestamps
    only, not session validity or recovery-code availability.
    """
    if not user_ids:
        return {}
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT user_id,
                   CASE
                       WHEN expires_at <= clock_timestamp() THEN 'expired'
                       WHEN prepared_at IS NOT NULL
                            AND prepared_at >
                                clock_timestamp() - %s * INTERVAL '1 second'
                           THEN 'prepared'
                       ELSE 'pending'
                   END AS state
            FROM admin_promotion_requests
            WHERE user_id = ANY(%s)
            """,
            (ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS, user_ids),
        )
        rows = await cur.fetchall()
    return {row["user_id"]: row["state"] for row in rows}


async def request_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    actor_id: int,
    actor_session_id: str,
    target_user_id: int,
) -> AdminPromotionRequestResult:
    """Guard the admin session and commit a seven-day invitation for an eligible target.

    Reissuing replaces requester/revision/expiry and discards staged recovery
    codes. Return expiry and whether a request existed. AdminActionRejected
    indicates actor failure; AdminPromotionRejected indicates target failure.
    Database/invariant failures roll back the transaction.
    """
    async with get_db_cursor(pool) as cur:
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        await cur.execute(
            """
            SELECT auth_revision,
                   auth_method,
                   is_active,
                   is_admin,
                   email_verified,
                   totp_secret,
                   totp_recovery_required
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (target_user_id,),
        )
        target = await cur.fetchone()
        _validate_target_row(target)
        if target is None:  # narrowed by _validate_target_row
            raise RuntimeError("Administrator-promotion target unexpectedly missing")

        await cur.execute(
            "SELECT 1 FROM admin_promotion_requests WHERE user_id = %s FOR UPDATE",
            (target_user_id,),
        )
        reissued = await cur.fetchone() is not None
        await discard_pending_recovery_code_set_cur(cur, user_id=target_user_id)

        await cur.execute(
            """
            INSERT INTO admin_promotion_requests (
                user_id,
                requested_by,
                requested_at,
                expires_at,
                expected_auth_revision,
                prepared_at,
                prepared_session_id
            )
            VALUES (
                %s,
                %s,
                clock_timestamp(),
                clock_timestamp() + %s * INTERVAL '1 second',
                %s,
                NULL,
                NULL
            )
            ON CONFLICT (user_id) DO UPDATE
            SET requested_by = EXCLUDED.requested_by,
                requested_at = EXCLUDED.requested_at,
                expires_at = EXCLUDED.expires_at,
                expected_auth_revision = EXCLUDED.expected_auth_revision,
                prepared_at = NULL,
                prepared_session_id = NULL
            RETURNING expires_at
            """,
            (
                target_user_id,
                actor_id,
                ADMIN_PROMOTION_MAX_AGE_SECONDS,
                target["auth_revision"],
            ),
        )
        request = await cur.fetchone()
        if request is None:
            raise RuntimeError("Administrator-promotion request was not persisted")

    logger.info(
        "Administrator %d invited user %d to accept administrator access; reissued=%s",
        actor_id,
        target_user_id,
        reissued,
    )
    return AdminPromotionRequestResult(
        user_id=target_user_id,
        expires_at=request["expires_at"],
        reissued=reissued,
    )


async def cancel_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    actor_id: int,
    actor_session_id: str,
    target_user_id: int,
) -> bool:
    """Guard the admin session, remove the invitation, and discard staged codes.

    Return whether an invitation existed. Raise AdminPromotionRejected for a
    missing target or AdminActionRejected for actor authorization failure. All
    writes share the administrator lock and transaction.
    """
    async with get_db_cursor(pool) as cur:
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        await cur.execute(
            "SELECT id FROM users WHERE id = %s FOR UPDATE",
            (target_user_id,),
        )
        if await cur.fetchone() is None:
            raise AdminPromotionRejected("user_not_found")
        await cur.execute(
            "DELETE FROM admin_promotion_requests WHERE user_id = %s RETURNING user_id",
            (target_user_id,),
        )
        deleted = await cur.fetchone() is not None
        await discard_pending_recovery_code_set_cur(cur, user_id=target_user_id)

    if deleted:
        logger.info(
            "Administrator %d cancelled admin invitation for user %d", actor_id, target_user_id
        )
    return deleted


async def prepare_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    session_id: str,
    password: str,
    totp_code: str,
) -> PreparedAdminPromotion:
    """Verify target password/TOTP and commit codes bound to its raw full-session token.

    Spend a separately committed step-up attempt even if later rejected. Under
    the admin-action lock, recheck eligibility, credentials/revision, invitation,
    requester, and session; consume a fresh TOTP step and replace staged codes.
    Return plaintext codes and deadlines (at most 15 minutes or invitation
    expiry). AdminPromotionRejected carries expected failure reasons; storage
    and TOTP decryption errors propagate without committing preparation.
    """
    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=user_id,
        session_id=session_id,
    )
    if reservation is SessionStepUpAttemptOutcome.INVALID_SESSION:
        raise AdminPromotionRejected("invalid_session")
    if reservation is SessionStepUpAttemptOutcome.ACCOUNT_LOCKED:
        raise AdminPromotionRejected("account_locked")
    if reservation is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        raise AdminPromotionRejected("step_up_exhausted")
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")

    normalized_totp = normalize_totp_code(totp_code)
    if normalized_totp is None:
        raise AdminPromotionRejected("invalid_totp")

    password_hash, verified_revision = await _verify_password_snapshot(
        pool,
        user_id=user_id,
        password=password,
    )
    plaintext_codes = generate_recovery_codes()

    async with get_db_cursor(pool) as cur:
        await acquire_admin_action_lock_cur(cur)
        await cur.execute(
            """
            SELECT password_hash,
                   auth_revision,
                   auth_method,
                   is_active,
                   is_admin,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   (locked_until IS NULL OR locked_until <= clock_timestamp())
                       AS login_unlocked
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        target = await cur.fetchone()
        _validate_target_row(target)
        if target is None:  # narrowed by _validate_target_row
            raise RuntimeError("Administrator-promotion target unexpectedly missing")
        if not target["login_unlocked"]:
            raise AdminPromotionRejected("account_locked")
        if target["password_hash"] != password_hash or target["auth_revision"] != verified_revision:
            raise AdminPromotionRejected("state_changed")

        await _lock_full_session_cur(cur, user_id=user_id, session_id=session_id)
        await cur.execute(
            """
            SELECT requested_by,
                   expected_auth_revision,
                   expires_at,
                   expires_at > clock_timestamp() AS unexpired
            FROM admin_promotion_requests
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        promotion = await cur.fetchone()
        if promotion is None:
            raise AdminPromotionRejected("no_request")
        if not promotion["unexpired"]:
            raise AdminPromotionRejected("invitation_expired")
        if promotion["expected_auth_revision"] != target["auth_revision"]:
            raise AdminPromotionRejected("state_changed")
        await _validate_requester_cur(cur, promotion["requested_by"])

        if not await verify_and_consume_totp_cur(cur, user_id, normalized_totp):
            raise AdminPromotionRejected("invalid_totp")

        staged: PendingRecoveryCodeSet = await stage_recovery_code_set_cur(
            cur,
            user_id=user_id,
            codes=plaintext_codes,
        )
        await cur.execute(
            """
            UPDATE admin_promotion_requests
            SET prepared_at = clock_timestamp(),
                prepared_session_id = %s
            WHERE user_id = %s
            RETURNING expires_at AS invitation_expires_at,
                LEAST(
                    expires_at,
                    prepared_at + %s * INTERVAL '1 second'
                ) AS preparation_expires_at
            """,
            (hash_session_id(session_id), user_id, ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS),
        )
        updated = await cur.fetchone()
        if updated is None:
            raise RuntimeError("Administrator-promotion request disappeared while preparing")

    logger.info(
        "User %d prepared administrator invitation with recovery-code generation %d",
        user_id,
        staged.generation,
    )
    return PreparedAdminPromotion(
        user_id=user_id,
        invitation_expires_at=updated["invitation_expires_at"],
        preparation_expires_at=updated["preparation_expires_at"],
        recovery_codes=staged.codes,
    )


async def accept_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    session_id: str,
    recovery_code: str,
) -> AcceptedAdminPromotion:
    """Confirm one staged code and commit administrator status and recovery codes.

    Spend a durable step-up attempt, then recheck target/requester eligibility,
    revision, invitation, and matching full-session preparation under the admin
    lock. The confirming code remains usable. Success increments auth_revision,
    revokes all target sessions/pending capabilities, and returns requester ID.
    AdminPromotionRejected carries expected failures; the attempt survives
    rollback of promotion writes.
    """
    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=user_id,
        session_id=session_id,
    )
    if reservation is SessionStepUpAttemptOutcome.INVALID_SESSION:
        raise AdminPromotionRejected("invalid_session")
    if reservation is SessionStepUpAttemptOutcome.ACCOUNT_LOCKED:
        raise AdminPromotionRejected("account_locked")
    if reservation is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        raise AdminPromotionRejected("step_up_exhausted")
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")

    async with get_db_cursor(pool) as cur:
        await acquire_admin_action_lock_cur(cur)
        await cur.execute(
            """
            SELECT auth_revision,
                   auth_method,
                   is_active,
                   is_admin,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   (locked_until IS NULL OR locked_until <= clock_timestamp())
                       AS login_unlocked
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        target = await cur.fetchone()
        _validate_target_row(target)
        if target is None:  # narrowed by _validate_target_row
            raise RuntimeError("Administrator-promotion target unexpectedly missing")
        if not target["login_unlocked"]:
            raise AdminPromotionRejected("account_locked")

        await _lock_full_session_cur(cur, user_id=user_id, session_id=session_id)
        await cur.execute(
            """
            SELECT requested_by,
                   expected_auth_revision,
                   expires_at > clock_timestamp() AS unexpired,
                   prepared_at,
                   prepared_session_id
            FROM admin_promotion_requests
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        promotion = await cur.fetchone()
        if promotion is None:
            raise AdminPromotionRejected("no_request")
        if not promotion["unexpired"]:
            raise AdminPromotionRejected("invitation_expired")
        if promotion["expected_auth_revision"] != target["auth_revision"]:
            raise AdminPromotionRejected("state_changed")
        if promotion["prepared_session_id"] != hash_session_id(session_id):
            raise AdminPromotionRejected("codes_not_prepared")
        if promotion["prepared_at"] is None:
            raise AdminPromotionRejected("codes_not_prepared")
        await cur.execute(
            """
            SELECT %s > clock_timestamp() - %s * INTERVAL '1 second'
                AS preparation_current
            """,
            (promotion["prepared_at"], ADMIN_PROMOTION_PREPARED_MAX_AGE_SECONDS),
        )
        current = await cur.fetchone()
        if current is None or not current["preparation_current"]:
            raise AdminPromotionRejected("codes_not_prepared")
        await _validate_requester_cur(cur, promotion["requested_by"])

        if not await activate_pending_recovery_code_set_cur(
            cur,
            user_id=user_id,
            candidate_code=recovery_code,
        ):
            raise AdminPromotionRejected("invalid_recovery_code")

        await cur.execute(
            """
            UPDATE users
            SET is_admin = true,
                auth_revision = auth_revision + 1
            WHERE id = %s
            """,
            (user_id,),
        )
        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)

    logger.warning(
        "User %d accepted administrator invitation issued by administrator %d",
        user_id,
        promotion["requested_by"],
    )
    return AcceptedAdminPromotion(user_id=user_id, requested_by=promotion["requested_by"])


async def decline_admin_promotion(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    session_id: str,
) -> int:
    """Delete an invitation and staged codes; return its requester ID.

    Require an active local user with the raw unexpired full-session token.
    AdminPromotionRejected identifies missing/ineligible user, invalid session,
    or missing request; TypeError signals a noninteger stored requester ID.
    The admin-action lock serializes these transactional changes.
    """
    async with get_db_cursor(pool) as cur:
        await acquire_admin_action_lock_cur(cur)
        await cur.execute(
            "SELECT id, is_active, auth_method FROM users WHERE id = %s FOR UPDATE",
            (user_id,),
        )
        target = await cur.fetchone()
        if target is None:
            raise AdminPromotionRejected("user_not_found")
        if not target["is_active"] or target["auth_method"] != "local":
            raise AdminPromotionRejected("ineligible_account")
        await _lock_full_session_cur(cur, user_id=user_id, session_id=session_id)
        await cur.execute(
            """
            DELETE FROM admin_promotion_requests
            WHERE user_id = %s
            RETURNING requested_by
            """,
            (user_id,),
        )
        deleted = await cur.fetchone()
        if deleted is None:
            raise AdminPromotionRejected("no_request")
        requested_by = deleted["requested_by"]
        if not isinstance(requested_by, int):
            raise TypeError("Administrator-promotion requester ID is invalid")
        await discard_pending_recovery_code_set_cur(cur, user_id=user_id)

    logger.info("User %d declined administrator invitation", user_id)
    return requested_by
