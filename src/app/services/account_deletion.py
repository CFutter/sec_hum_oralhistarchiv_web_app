"""Delete accounts after current-session, password and fresh TOTP proof.

Credential attempts commit before proof work. Password verification releases
the connection; the deletion transaction rechecks its snapshot and serializes
membership changes with the shared administrator lock. Child account records
are removed by the schema's cascading foreign keys. Callers emit the success
audit event from the returned pseudonymous result after this service commits.
"""

from dataclasses import dataclass
from typing import Any, Literal

from psycopg import AsyncCursor

from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import audit_email_hash
from .db import Database, get_db_cursor
from .password_verification import (
    PasswordVerified,
    VerifiedPasswordSnapshot,
    verify_password_hash,
)
from .session_ids import hash_session_id
from .totp import normalize_totp_code, verify_and_consume_totp_cur
from .users import (
    AdminActionRejected,
    AuthMethod,
    acquire_admin_action_lock_cur,
    guard_current_admin_session_cur,
)

AccountDeletionReason = Literal[
    "invalid_session",
    "account_locked",
    "step_up_exhausted",
    "ineligible_account",
    "invalid_password",
    "invalid_totp",
    "retry_required",
    "admin_required",
    "user_not_found",
    "self_admin_deletion",
    "last_active_admin",
]


class AccountDeletionRejected(ValueError):
    """An expected account/session, credential or administrator-policy rejection."""

    def __init__(self, reason: AccountDeletionReason) -> None:
        """Expose the stable rejection reason without credential or address data."""
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class AccountDeletionResult:
    """Committed deletion identity; the address is represented only by its audit hash."""

    target_user_id: int
    email_hash: str
    auth_method: AuthMethod


async def _verify_deletion_password(
    pool: Database,
    *,
    user_id: int,
    session_id: str,
    password: str,
) -> VerifiedPasswordSnapshot:
    """Spend one session attempt, then verify eligible credentials off-connection.

    Username-triggered login lockout does not block a live full session's
    independent proof budget. Current authority and credentials are rechecked
    in the final deletion transaction.
    """
    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=user_id,
        session_id=session_id,
    )
    if reservation is SessionStepUpAttemptOutcome.INVALID_SESSION:
        raise AccountDeletionRejected("invalid_session")
    if reservation is SessionStepUpAttemptOutcome.ACCOUNT_LOCKED:
        raise AccountDeletionRejected("account_locked")
    if reservation is SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED:
        raise AccountDeletionRejected("step_up_exhausted")
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}")

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT password_hash, auth_revision, is_active, email_verified,
                   auth_method, totp_secret, totp_recovery_required
            FROM users WHERE id = %s
            """,
            (user_id,),
        )
        row: dict[str, Any] | None = await cur.fetchone()
    _check_actor_eligibility(row)
    if row is None:  # narrowed by _check_actor_eligibility
        raise RuntimeError("Eligible deletion actor unexpectedly missing")

    result = await verify_password_hash(
        password_hash=row["password_hash"],
        password=password,
        user_id=user_id,
        operation="account_deletion",
    )
    if not isinstance(result, PasswordVerified):
        raise AccountDeletionRejected("invalid_password") from result.cause
    return VerifiedPasswordSnapshot(row["password_hash"], row["auth_revision"])


def _check_actor_eligibility(row: dict[str, Any] | None) -> None:
    """Require a verified active local actor with a password and active authenticator."""
    if (
        row is None
        or not row["is_active"]
        or not row["email_verified"]
        or row["auth_method"] != "local"
        or not row["password_hash"]
        or not row["totp_secret"]
        or row["totp_recovery_required"]
    ):
        raise AccountDeletionRejected("ineligible_account")


async def _lock_deletion_actor(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    session_id: str,
    snapshot: VerifiedPasswordSnapshot,
) -> dict[str, Any]:
    """Lock actor then session and reject changed credentials, eligibility or revision."""
    await cur.execute(
        """
        SELECT email, password_hash, auth_revision, is_active, is_admin,
               email_verified, auth_method, totp_secret, totp_recovery_required
        FROM users WHERE id = %s FOR UPDATE
        """,
        (user_id,),
    )
    row: dict[str, Any] | None = await cur.fetchone()
    _check_actor_eligibility(row)
    if row is None:  # narrowed by _check_actor_eligibility
        raise RuntimeError("Eligible deletion actor unexpectedly missing")
    if (
        row["password_hash"] != snapshot.password_hash
        or row["auth_revision"] != snapshot.auth_revision
    ):
        raise AccountDeletionRejected("retry_required")
    await cur.execute(
        """
        SELECT 1 FROM sessions
        WHERE id = %s AND user_id = %s AND purpose = 'full'
          AND expires_at > clock_timestamp()
        FOR UPDATE
        """,
        (hash_session_id(session_id), user_id),
    )
    if await cur.fetchone() is None:
        raise AccountDeletionRejected("invalid_session")
    return row


async def _delete_locked_target(
    cur: AsyncCursor[Any],
    *,
    target_user_id: int,
    target: dict[str, Any],
) -> AccountDeletionResult:
    """Keep at least one active administrator, then delete the locked account and children."""
    if target["is_active"] and target["is_admin"]:
        await cur.execute("SELECT count(*) AS total FROM users WHERE is_active AND is_admin")
        count = await cur.fetchone()
        if count is None or count["total"] <= 1:
            raise AccountDeletionRejected("last_active_admin")
    result = AccountDeletionResult(
        target_user_id=target_user_id,
        email_hash=audit_email_hash(target["email"]),
        auth_method=target["auth_method"],
    )
    await cur.execute("DELETE FROM users WHERE id = %s", (target_user_id,))
    if cur.rowcount != 1:
        raise RuntimeError("Locked deletion target unexpectedly missing")
    return result


async def delete_own_account(
    pool: Database,
    *,
    user_id: int,
    session_id: str,
    password: str,
    totp_code: str,
) -> AccountDeletionResult:
    """Immediately delete the local account using its raw full session and fresh proofs.

    A successful password check cannot authorize deletion after a credential or
    revision change. Federated accounts cannot use this path. The last active
    administrator is protected under the shared membership lock. Rejections
    roll back deletion and TOTP consumption but do not refund the independently
    committed step-up attempt. Use a pool or idle caller-owned connection.
    """
    snapshot = await _verify_deletion_password(
        pool,
        user_id=user_id,
        session_id=session_id,
        password=password,
    )
    normalized_code = normalize_totp_code(totp_code)
    if normalized_code is None:
        raise AccountDeletionRejected("invalid_totp")

    async with get_db_cursor(pool) as cur:
        await acquire_admin_action_lock_cur(cur)
        actor = await _lock_deletion_actor(
            cur, user_id=user_id, session_id=session_id, snapshot=snapshot
        )
        if not await verify_and_consume_totp_cur(cur, user_id, normalized_code):
            raise AccountDeletionRejected("invalid_totp")
        return await _delete_locked_target(cur, target_user_id=user_id, target=actor)


async def delete_account_as_admin(
    pool: Database,
    *,
    actor_id: int,
    actor_session_id: str,
    target_user_id: int,
    password: str,
    totp_code: str,
) -> AccountDeletionResult:
    """Delete another local or federated account after the administrator's fresh proofs.

    Require the current full local administrator session and usable recovery
    configuration, then lock the target. Pending or disabled federated rows
    remain removable. Administrators delete themselves through the self-service
    path; all paths preserve the last active administrator. Child rows cascade
    in the same transaction, including outbox rows and issued promotion requests.
    Database/decryption failures propagate without a successful result or audit.
    """
    snapshot = await _verify_deletion_password(
        pool,
        user_id=actor_id,
        session_id=actor_session_id,
        password=password,
    )
    normalized_code = normalize_totp_code(totp_code)
    if normalized_code is None:
        raise AccountDeletionRejected("invalid_totp")

    async with get_db_cursor(pool) as cur:
        try:
            await guard_current_admin_session_cur(
                cur, actor_id=actor_id, actor_session_id=actor_session_id
            )
        except AdminActionRejected as exc:
            raise AccountDeletionRejected("admin_required") from exc
        await _lock_deletion_actor(
            cur, user_id=actor_id, session_id=actor_session_id, snapshot=snapshot
        )
        if actor_id == target_user_id:
            raise AccountDeletionRejected("self_admin_deletion")
        await cur.execute(
            """SELECT email, auth_method, is_active, is_admin
               FROM users WHERE id = %s FOR UPDATE""",
            (target_user_id,),
        )
        target = await cur.fetchone()
        if target is None:
            raise AccountDeletionRejected("user_not_found")
        if not await verify_and_consume_totp_cur(cur, actor_id, normalized_code):
            raise AccountDeletionRejected("invalid_totp")
        return await _delete_locked_target(cur, target_user_id=target_user_id, target=target)
