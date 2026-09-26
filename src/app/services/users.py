"""Represent user snapshots, provision identities, and guard account administration.

USER_COLUMNS plus SQL-computed fields must match User; validate_user_schema
checks that mapping. Credential workflows live in their own services.
Administrative writes use a shared advisory lock and current actor/session
guards. The bounded reaper deletes stale unverified local nonadmins.
"""

import asyncio
import logging
from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any, Literal, NamedTuple

from psycopg import AsyncCursor, sql
from psycopg.errors import UniqueViolation
from psycopg.rows import tuple_row
from psycopg.sql import Composable
from psycopg_pool import AsyncConnectionPool

from app.credentials import normalize_email
from config import settings

from ..federation_contract import valid_federated_identity
from .access_tiers import AccessTier
from .crypto import audit_email_hash
from .db import get_db_cursor
from .db_constraints import is_users_email_collision
from .federated_session_policy import federation_policy_is_current_cur
from .schema_invariants import assert_columns_match_dataclass
from .session_ids import hash_session_id
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
    invalidate_pending_email_change_cur,
)
from .totp_recovery_codes import TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")

_ADMIN_ACTION_LOCK = 0x4F484141
DISPLAY_NAME_MAX_LENGTH = 200

AuthMethod = Literal["local", "shibboleth"]
FederatedStatus = Literal[
    "pending",
    "approved",
    "disabled",
    "legacy_quarantined",
]

_FEDERATED_ADMIN_MUTATION_ALLOWED = frozenset({"approved", "disabled"})
_ACCESS_TIERS: tuple[AccessTier, ...] = ("public", "registered", "vetted")


class UserAlreadyExistsError(ValueError):
    """Local registration collided with an existing case-insensitive email address."""

    def __init__(self, email: str):
        """Store the conflicting email and include it in the exception message."""
        self.email = email
        super().__init__(f"User already exists [{email}]")


class AdminActionRejected(ValueError):
    """The acting administrator or the requested membership change is invalid."""


class SetActiveResult(NamedTuple):
    """Committed active-state values; lock_cleared includes cleared failure counters."""

    old_value: bool
    new_value: bool
    lock_cleared: bool


@dataclass
class User:
    """Account snapshot, including inactive and unauthenticated accounts.

    TOTP flags are SQL-derived; configured means ciphertext exists, not that it
    decrypts. Recovery availability excludes used or password-exhausted codes.
    Neither this snapshot nor its defaults authorize an operation.
    """

    id: int
    email: str
    display_name: str | None
    affiliation: str | None
    country: str | None
    auth_method: AuthMethod
    access_tier: AccessTier
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    totp_configured: bool
    is_admin: bool = False
    email_verified: bool = False
    last_totp_step: int | None = None
    totp_recovery_code_generation: int = 0
    totp_recovery_codes_available: bool = False
    totp_recovery_required: bool = False
    shibboleth_issuer: str | None = None
    shibboleth_subject_id: str | None = None
    federated_status: FederatedStatus | None = None
    federated_approved_at: datetime | None = None
    federated_approved_by: int | None = None


_ASCII_PRINTABLE_START = 0x20
_ASCII_DELETE = 0x7F


async def acquire_admin_action_lock_cur(cur: AsyncCursor[Any]) -> None:
    """Acquire the shared transaction advisory lock before actor/target/session locks."""
    await cur.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMIN_ACTION_LOCK,))


async def guard_current_admin_session_cur(
    cur: AsyncCursor[Any],
    *,
    actor_id: int,
    actor_session_id: str,
) -> None:
    """Lock and validate the acting administrator and raw full-session token.

    Call before target locks in the same mutation transaction. Acquire the
    shared advisory lock, then actor and unexpired session locks. Active admin
    status is required; local actors also need TOTP and a usable active recovery
    code. Raise AdminActionRejected on rejection. This guard does not itself
    check federation policy or an account login lock.
    """
    if not actor_session_id:
        raise AdminActionRejected("Your administrator session is no longer valid.")

    await acquire_admin_action_lock_cur(cur)
    await cur.execute(
        """
        SELECT actor.is_active,
               actor.is_admin,
               actor.auth_method,
               actor.totp_secret,
               actor.totp_recovery_code_generation,
               EXISTS (
                   SELECT 1
                   FROM totp_recovery_codes AS codes
                   WHERE codes.user_id = actor.id
                     AND codes.generation = actor.totp_recovery_code_generation
                     AND codes.used_at IS NULL
                     AND codes.password_attempt_count < %s
               ) AS recovery_codes_available
        FROM users AS actor
        WHERE actor.id = %s
        FOR UPDATE
        """,
        (TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT, actor_id),
    )
    actor = await cur.fetchone()
    if actor is None or not actor["is_active"] or not actor["is_admin"]:
        raise AdminActionRejected("Your administrator access changed. Please log in again.")
    if actor["auth_method"] == "local" and (
        actor["totp_secret"] is None
        or actor["totp_recovery_code_generation"] <= 0
        or not actor["recovery_codes_available"]
    ):
        raise AdminActionRejected(
            "Your administrator recovery configuration is incomplete. Please contact support."
        )

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
        (hash_session_id(actor_session_id), actor_id),
    )
    if await cur.fetchone() is None:
        raise AdminActionRejected("Your administrator session is no longer valid.")


async def _guard_admin_membership_change_cur(
    cur: AsyncCursor[Any],
    *,
    actor_id: int,
    actor_session_id: str,
    user_id: int,
    new_is_active: bool | None = None,
    new_is_admin: bool | None = None,
) -> dict[str, Any]:
    """Guard the actor, lock the target, and return its membership snapshot.

    None proposed values mean no change to that property. Reject self-demotion,
    self-deactivation, or removal of the last active admin with
    AdminActionRejected; raise ValueError for a missing target.
    """
    await guard_current_admin_session_cur(
        cur,
        actor_id=actor_id,
        actor_session_id=actor_session_id,
    )
    await cur.execute(
        """SELECT is_active, is_admin, auth_method, federated_status
           FROM users WHERE id = %s FOR UPDATE""",
        (user_id,),
    )
    target: dict[str, Any] | None = await cur.fetchone()
    if target is None:
        raise ValueError(f"User {user_id} not found")
    if actor_id == user_id and new_is_active is False:
        raise AdminActionRejected("You cannot deactivate your own account.")
    if actor_id == user_id and new_is_admin is False:
        raise AdminActionRejected("You cannot remove your own admin status.")
    removes_active_admin = (
        target["is_active"]
        and target["is_admin"]
        and (new_is_active is False or new_is_admin is False)
    )
    if removes_active_admin:
        await cur.execute("SELECT count(*) AS total FROM users WHERE is_active AND is_admin")
        count = await cur.fetchone()
        if count is None or count["total"] <= 1:
            raise AdminActionRejected("At least one active administrator must remain.")
    return target


def _reject_unapproved_federated_admin_change(target: dict[str, Any]) -> None:
    """Raise AdminActionRejected for Shibboleth states other than approved/disabled."""
    if (
        target.get("auth_method") == "shibboleth"
        and target.get("federated_status") not in _FEDERATED_ADMIN_MUTATION_ALLOWED
    ):
        raise AdminActionRejected(
            "This federated identity must be approved through the dedicated "
            "federated-review action."
        )


def normalize_display_name(raw: str) -> str:
    """Strip whitespace; require 1..200 characters without ASCII controls or DEL.

    Raise ValueError on failure; other Unicode controls are not rejected.
    """
    name = raw.strip()
    if not name:
        raise ValueError("Display name cannot be empty.")
    if len(name) > DISPLAY_NAME_MAX_LENGTH:
        raise ValueError(f"Display name must be at most {DISPLAY_NAME_MAX_LENGTH} characters.")
    if any(ord(c) < _ASCII_PRINTABLE_START or ord(c) == _ASCII_DELETE for c in name):
        raise ValueError("Display name cannot contain control characters.")
    return name


def parse_user(row: dict[str, Any]) -> User:
    """Build User from every dataclass-named row key, ignoring extras.

    Missing keys raise KeyError; values are not validated or coerced. Use
    user_columns_sql for the required computed fields.
    """
    return User(**{field.name: row[field.name] for field in fields(User)})


USER_COLUMNS = [
    "id",
    "email",
    "display_name",
    "affiliation",
    "country",
    "auth_method",
    "access_tier",
    "is_active",
    "created_at",
    "last_login",
    "is_admin",
    "email_verified",
    "last_totp_step",
    "totp_recovery_code_generation",
    "totp_recovery_required",
    "shibboleth_issuer",
    "shibboleth_subject_id",
    "federated_status",
    "federated_approved_at",
    "federated_approved_by",
]

USER_COMPUTED_SOURCE_COLUMNS = frozenset({"totp_secret"})
_USER_COMPUTED_FIELDS = {
    "totp_configured",
    "totp_recovery_codes_available",
}


def validate_user_schema() -> None:
    """Raise AssertionError if User fields differ from stored plus computed columns."""
    assert_columns_match_dataclass(
        User,
        USER_COLUMNS,
        _USER_COMPUTED_FIELDS,
        columns_label="USER_COLUMNS",
        dataclass_label="User",
    )


def user_columns_sql(table_alias: str | None = None) -> sql.Composed:
    """Return the User projection without credential ciphertext or code hashes.

    Add computed TOTP presence and usable-code flags to USER_COLUMNS. A truthy
    table_alias qualifies identifiers; None/empty assumes the table is named
    users, as the recovery-code subquery references users.id.
    """
    totp_part: Composable
    if table_alias:
        identifier_parts = [sql.Identifier(table_alias, col) for col in USER_COLUMNS]
        totp_part = sql.SQL("({}.totp_secret IS NOT NULL) AS totp_configured").format(
            sql.Identifier(table_alias)
        )
        user_id = sql.Identifier(table_alias, "id")
        recovery_generation = sql.Identifier(
            table_alias,
            "totp_recovery_code_generation",
        )
    else:
        identifier_parts = [sql.Identifier(col) for col in USER_COLUMNS]
        totp_part = sql.SQL("(totp_secret IS NOT NULL) AS totp_configured")
        user_id = sql.Identifier("users", "id")
        recovery_generation = sql.Identifier(
            "users",
            "totp_recovery_code_generation",
        )

    recovery_codes_part = sql.SQL(
        """EXISTS (
               SELECT 1
               FROM totp_recovery_codes AS recovery_codes
               WHERE recovery_codes.user_id = {}
                 AND recovery_codes.generation = {}
                 AND recovery_codes.used_at IS NULL
                 AND recovery_codes.password_attempt_count < {}
           ) AS totp_recovery_codes_available"""
    ).format(
        user_id,
        recovery_generation,
        sql.Literal(TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT),
    )

    return sql.SQL(", ").join([*identifier_parts, totp_part, recovery_codes_part])


USER_COLUMNS_SQL = user_columns_sql()


async def get_user_by_id(pool: AsyncConnectionPool, user_id: int) -> User | None:
    """Return an account snapshot by ID, or None if absent."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM users WHERE id = %s").format(USER_COLUMNS_SQL),
            (user_id,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return parse_user(row)


async def get_user_by_email(pool: AsyncConnectionPool, email: str) -> User | None:
    """Return a case-insensitive email match, or None; whitespace is not stripped."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT {} FROM users WHERE LOWER(email) = LOWER(%s)").format(USER_COLUMNS_SQL),
            (email,),
        )
        row = await cur.fetchone()
        if not row:
            return None
        return parse_user(row)


async def list_users(
    pool: AsyncConnectionPool, *, page: int = 1, page_size: int = 20
) -> tuple[list[User], int]:
    """Return a one-based page ordered by creation/ID descending and the total count.

    Callers must supply nonnegative page_size and offset; negative SQL values
    raise database errors. Empty pages use a separate count transaction, so the
    count may reflect later concurrent changes.
    """
    offset = (page - 1) * page_size
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("""SELECT {}, COUNT(*) OVER() AS total_count
                       FROM users
                       ORDER BY created_at DESC, id DESC
                       LIMIT %s OFFSET %s""").format(USER_COLUMNS_SQL),
            (page_size, offset),
        )
        rows = await cur.fetchall()
    if not rows:
        async with get_db_cursor(pool, row_factory=tuple_row) as cur:
            await cur.execute("SELECT COUNT(*) FROM users")
            row = await cur.fetchone()
        return [], (row[0] if row else 0)
    return [parse_user(r) for r in rows], rows[0]["total_count"]


async def insert_unverified_local_user_cur(
    cur: AsyncCursor[Any],
    *,
    email: str,
    display_name: str,
    password_hash: str,
    affiliation: str | None = None,
    country: str | None = None,
) -> User:
    """Insert and return a public local account in the caller's transaction.

    Normalize email/display_name; raise ValueError for invalid values.
    password_hash must already be hashed; profile metadata is passed through.
    Database defaults supply active/unverified state. UniqueViolation propagates
    on collisions; a missing RETURNING row raises RuntimeError.
    """
    normalized = normalize_email(email)
    if normalized is None:
        raise ValueError("Please enter a valid email address.")
    await cur.execute(
        sql.SQL("""INSERT INTO users (email, display_name, affiliation, country,
            password_hash, auth_method, access_tier)
            VALUES (%s, %s, %s, %s, %s, 'local', 'public')
            RETURNING {}""").format(USER_COLUMNS_SQL),
        (normalized, normalize_display_name(display_name), affiliation, country, password_hash),
    )
    row = await cur.fetchone()
    if not row:
        raise RuntimeError(f"Failed to create user: {email}")
    return parse_user(row)


async def create_shibboleth_user_cur(
    cur: AsyncCursor[Any],
    *,
    issuer: str,
    subject_id: str,
    email: str,
    display_name: str | None = None,
    affiliation: str | None = None,
    country: str | None = None,
) -> User | None:
    """Provision or refresh an exact issuer/subject identity in the caller's transaction.

    Return None for invalid identity/empty email or missing conflict row. Email
    is stripped/lowercased, not syntax-validated; callers validate all assertion
    attributes/trust. New rows are public, inactive, unverified, and pending.
    Only active approved identities refresh profile; None metadata preserves
    old values. Email changes clear verification and pending email/reset tokens.
    Other identities remain locked and unchanged. Email is globally unique but
    never links identities; UniqueViolation propagates for collisions.
    """
    email = email.strip().lower()
    identity_values_are_exact = valid_federated_identity(issuer, subject_id)
    if not identity_values_are_exact or not email:
        return None

    await cur.execute(
        sql.SQL("""INSERT INTO users (
            shibboleth_issuer, shibboleth_subject_id,
            email, display_name, affiliation, country,
            auth_method, access_tier, email_verified, is_active,
            federated_status
        )
        VALUES (%s, %s, %s, %s, %s, %s,
                'shibboleth', 'public', false, false, 'pending')
        ON CONFLICT ON CONSTRAINT users_shibboleth_identity_key DO UPDATE SET
            email_verified = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.email_verified ELSE false END,
            email_verification_token_hash = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.email_verification_token_hash ELSE NULL END,
            email_verification_created_at = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.email_verification_created_at ELSE NULL END,
            pending_email = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.pending_email ELSE NULL END,
            pending_email_token_hash = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.pending_email_token_hash ELSE NULL END,
            pending_email_created_at = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.pending_email_created_at ELSE NULL END,
            password_reset_token_hash = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.password_reset_token_hash ELSE NULL END,
            password_reset_created_at = CASE
                WHEN users.email IS NOT DISTINCT FROM EXCLUDED.email
                THEN users.password_reset_created_at ELSE NULL END,
            email = EXCLUDED.email,
            display_name = COALESCE(EXCLUDED.display_name, users.display_name),
            affiliation = COALESCE(EXCLUDED.affiliation, users.affiliation),
            country = COALESCE(EXCLUDED.country, users.country)
        WHERE users.auth_method = 'shibboleth'
          AND users.federated_status = 'approved'
          AND users.is_active
        RETURNING {}""").format(USER_COLUMNS_SQL),
        (issuer, subject_id, email, display_name, affiliation, country),
    )
    row = await cur.fetchone()
    if row is not None:
        return parse_user(row)

    # A skipped conflict update returns no row; read the locked identity unchanged.
    await cur.execute(
        sql.SQL(
            """SELECT {} FROM users
               WHERE shibboleth_issuer = %s
                 AND shibboleth_subject_id = %s
                 AND auth_method = 'shibboleth'
               FOR UPDATE"""
        ).format(USER_COLUMNS_SQL),
        (issuer, subject_id),
    )
    row = await cur.fetchone()
    return parse_user(row) if row is not None else None


async def create_shibboleth_user(
    pool: AsyncConnectionPool,
    *,
    issuer: str,
    subject_id: str,
    email: str,
    display_name: str | None = None,
    affiliation: str | None = None,
    country: str | None = None,
) -> User | None:
    """Commit create_shibboleth_user_cur; return None for invalid input or email collision.

    Other database failures propagate. This provisioning wrapper does not
    authorize a login; use finalize_shibboleth_login for session issuance.
    """
    try:
        async with get_db_cursor(pool) as cur:
            user = await create_shibboleth_user_cur(
                cur,
                issuer=issuer,
                subject_id=subject_id,
                email=email,
                display_name=display_name,
                affiliation=affiliation,
                country=country,
            )
    except UniqueViolation as exc:
        if is_users_email_collision(exc):
            return None
        raise

    if user is not None:
        logger.info("Shibboleth user provisioned/updated: user_id=%d", user.id)
    return user


async def update_last_login(pool: AsyncConnectionPool, user_id: int) -> None:
    """Set last_login to transaction time; silently ignore a missing user."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id,),
        )


async def approve_federated_user(
    pool: AsyncConnectionPool,
    user_id: int,
    *,
    expected_issuer: str,
    expected_subject_id: str,
    access_tier: AccessTier,
    actor_id: int,
    actor_session_id: str,
) -> User:
    """Approve an exact pending identity/tier under current federation and admin policy.

    Match the review's case-sensitive issuer/subject and an enabled trusted
    issuer; set active/approved, retain nonadmin/unverified status, clear lockout,
    advance auth_revision, record approver/time, and revoke sessions atomically.
    Return the updated User. Raise AdminActionRejected for invalid/stale policy,
    actor, or review state; ValueError for a missing target.
    """
    identity_values_are_exact = valid_federated_identity(expected_issuer, expected_subject_id)
    federation_is_currently_trusted = (
        settings.shibboleth_enabled and expected_issuer in settings.shibboleth_trusted_issuers
    )
    if (
        not identity_values_are_exact
        or access_tier not in _ACCESS_TIERS
        or not federation_is_currently_trusted
    ):
        raise AdminActionRejected("The federated approval request is invalid.")

    async with get_db_cursor(pool) as cur:
        if not await federation_policy_is_current_cur(cur):
            raise AdminActionRejected(
                "The federation policy changed. Reload the review before approving."
            )
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        await cur.execute(
            sql.SQL(
                """UPDATE users
                      SET access_tier = %(access_tier)s,
                          is_active = true,
                          is_admin = false,
                          email_verified = false,
                          failed_login_count = 0,
                          locked_until = NULL,
                          lockout_notice_enqueued_at = NULL,
                          auth_revision = auth_revision + 1,
                          federated_status = 'approved',
                          federated_approved_at = clock_timestamp(),
                          federated_approved_by = %(actor_id)s
                    WHERE id = %(user_id)s
                      AND auth_method = 'shibboleth'
                      AND federated_status = 'pending'
                      AND NOT is_active
                      AND NOT is_admin
                      AND NOT email_verified
                      AND shibboleth_issuer = %(expected_issuer)s
                      AND shibboleth_subject_id = %(expected_subject_id)s
                RETURNING {}"""
            ).format(USER_COLUMNS_SQL),
            {
                "user_id": user_id,
                "expected_issuer": expected_issuer,
                "expected_subject_id": expected_subject_id,
                "access_tier": access_tier,
                "actor_id": actor_id,
            },
        )
        row = await cur.fetchone()
        if row is not None:
            # Approval is an authority transition. Remove any anomalous session
            # that predates approval in the same transaction, so only a later,
            # freshly validated assertion can create an authenticated session.
            await delete_user_sessions_cur(cur, user_id)
            return parse_user(row)

        # Distinguish a stale/mismatched review from a deleted target without
        # exposing either case outside the administrator-only route.  The
        # UPDATE above took (or waited for) the target row lock, so this read
        # observes the authoritative post-race state.
        await cur.execute(
            "SELECT 1 FROM users WHERE id = %s FOR UPDATE",
            (user_id,),
        )
        if await cur.fetchone() is None:
            raise ValueError(f"User {user_id} not found")
        raise AdminActionRejected(
            "The federated identity changed or is no longer pending approval."
        )


async def update_access_tier(
    pool: AsyncConnectionPool,
    user_id: int,
    new_tier: AccessTier,
    *,
    actor_id: int,
    actor_session_id: str,
) -> tuple[AccessTier, AccessTier]:
    """Guard the admin, lock the target, and commit its (old, new) access tiers.

    Reject unapproved/quarantined federation states with AdminActionRejected;
    the actor guard uses the same error. A missing target raises ValueError.
    new_tier is passed to the database without runtime validation; schema
    constraints reject invalid values. Existing sessions are retained.
    """
    async with get_db_cursor(pool) as cur:
        await guard_current_admin_session_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
        )
        await cur.execute(
            """SELECT access_tier, auth_method, federated_status
               FROM users WHERE id = %s FOR UPDATE""",
            (user_id,),
        )
        target = await cur.fetchone()
        if target is None:
            raise ValueError(f"User {user_id} not found")
        _reject_unapproved_federated_admin_change(target)

        await cur.execute(
            """
            UPDATE users
               SET access_tier = %(new_tier)s
             WHERE users.id = %(user_id)s
            RETURNING users.access_tier AS new_value
            """,
            {"user_id": user_id, "new_tier": new_tier},
        )
        row = await cur.fetchone()
        if not row:
            raise ValueError(f"User {user_id} not found")
        return (target["access_tier"], row["new_value"])


async def update_display_name(pool: AsyncConnectionPool, user_id: int, new_name: str) -> None:
    """Commit normalize_display_name(new_name); raise ValueError for invalid/missing user.

    The caller must authorize self-service; this helper does not check a session.
    """
    normalized = normalize_display_name(new_name)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "UPDATE users SET display_name = %s WHERE id = %s RETURNING id",
            (normalized, user_id),
        )
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")

    logger.info("Display name updated for user %d", user_id)


async def set_user_active(
    pool: AsyncConnectionPool,
    user_id: int,
    is_active: bool,
    *,
    actor_id: int,
    actor_session_id: str,
) -> SetActiveResult:
    """Commit active state under admin/self-change/last-active-admin guards.

    Every request advances auth_revision. Activation clears failures/lockout and
    pending email changes but retains sessions; pending/quarantined federated
    users cannot activate here. Deactivation preserves lockout, revokes sessions
    and pending capabilities, and changes approved federation state to disabled;
    reactivation restores approved. Return old/new and whether failures or a
    lock timestamp were cleared. AdminActionRejected signals policy rejection;
    ValueError signals a missing target. All writes roll back together.
    """
    if is_active:
        sql_text = """
            WITH before AS (
                SELECT is_active, failed_login_count, locked_until
                FROM users
                WHERE id = %(user_id)s
                FOR UPDATE
            )
            UPDATE users
               SET is_active = true,
                   failed_login_count = 0,
                   locked_until = NULL,
                   lockout_notice_enqueued_at = NULL,
                   auth_revision = users.auth_revision + 1,
                   federated_status = CASE
                       WHEN users.auth_method = 'shibboleth'
                       THEN 'approved'
                       ELSE users.federated_status
                   END
              FROM before
             WHERE users.id = %(user_id)s
            RETURNING before.is_active AS old_value,
                      users.is_active AS new_value,
                      (
                          before.failed_login_count > 0
                          OR before.locked_until IS NOT NULL
                      ) AS lock_cleared
        """
    else:
        sql_text = """
            WITH before AS (
                SELECT is_active
                FROM users
                WHERE id = %(user_id)s
                FOR UPDATE
            )
            UPDATE users
               SET is_active = false,
                   federated_status = CASE
                       WHEN users.auth_method = 'shibboleth'
                        AND users.federated_status = 'approved'
                       THEN 'disabled'
                       ELSE users.federated_status
                   END,
                   auth_revision = users.auth_revision + 1
              FROM before
             WHERE users.id = %(user_id)s
            RETURNING before.is_active AS old_value,
                      users.is_active AS new_value,
                      false AS lock_cleared
        """

    async with get_db_cursor(pool) as cur:
        target = await _guard_admin_membership_change_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
            user_id=user_id,
            new_is_active=is_active,
        )
        if is_active:
            _reject_unapproved_federated_admin_change(target)
        await cur.execute(sql_text, {"user_id": user_id})
        row = await cur.fetchone()

        if row is None:
            raise ValueError(f"User {user_id} not found")

        if is_active:
            await invalidate_pending_email_change_cur(cur, user_id)
        else:
            await delete_user_sessions_cur(cur, user_id)
            await invalidate_pending_authentication_state_cur(cur, user_id)

        return SetActiveResult(
            old_value=row["old_value"],
            new_value=row["new_value"],
            lock_cleared=row["lock_cleared"],
        )


async def set_user_admin(
    pool: AsyncConnectionPool,
    user_id: int,
    is_admin: bool,
    *,
    actor_id: int,
    actor_session_id: str,
) -> tuple[bool, bool]:
    """Commit demotion and return (old, new); retain sessions and auth_revision.

    is_admin=True raises AdminActionRejected: use the promotion workflow. The
    admin guard also rejects unauthorized actors, self-demotion, last-admin
    removal, and pending/quarantined federation state. Missing target raises
    ValueError. Target row locking makes the returned old value authoritative.
    """
    if is_admin:
        raise AdminActionRejected(
            "Administrator access must be offered and accepted through the promotion workflow."
        )

    async with get_db_cursor(pool) as cur:
        target = await _guard_admin_membership_change_cur(
            cur,
            actor_id=actor_id,
            actor_session_id=actor_session_id,
            user_id=user_id,
            new_is_admin=is_admin,
        )
        _reject_unapproved_federated_admin_change(target)
        await cur.execute(
            """
            UPDATE users
               SET is_admin = %(is_admin)s
             WHERE users.id = %(user_id)s
            RETURNING users.is_admin AS new_value
            """,
            {"user_id": user_id, "is_admin": is_admin},
        )
        row = await cur.fetchone()
        if not row:
            raise ValueError(f"User {user_id} not found")
        return (target["is_admin"], row["new_value"])


_REAP_BATCH_SIZE = 100
_REAP_MAX_BATCHES = 10


async def reap_unverified_accounts(
    pool: AsyncConnectionPool,
    max_age_days: int | None = None,
) -> int:
    """Delete at most 1,000 stale unverified local nonadmin users and return the count.

    None age uses UNVERIFIED_REAP_AFTER_DAYS; explicit ages are not validated.
    Commit independent batches of 100, skip locked rows, and audit deleted IDs
    with email hashes. Each batch has 250ms lock/5s statement limits; errors
    propagate after earlier batches have committed.
    """
    max_age_days = settings.unverified_reap_after_days if max_age_days is None else max_age_days
    total = 0
    for _ in range(_REAP_MAX_BATCHES):
        async with get_db_cursor(pool) as cur:
            await cur.execute("SET LOCAL lock_timeout = '250ms'")
            await cur.execute("SET LOCAL statement_timeout = '5s'")
            await cur.execute(
                """WITH candidates AS (
                       SELECT id FROM users
                       WHERE auth_method = 'local' AND NOT email_verified AND NOT is_admin
                         AND created_at < CURRENT_TIMESTAMP - %s * INTERVAL '1 day'
                       ORDER BY created_at, id
                       LIMIT %s FOR UPDATE SKIP LOCKED
                   )
                   DELETE FROM users u USING candidates c WHERE u.id = c.id
                   RETURNING u.id, u.email""",
                (max_age_days, _REAP_BATCH_SIZE),
            )
            deleted = await cur.fetchall()
        for row in deleted:
            audit_logger.info(
                "user_reaped_unverified",
                extra={
                    "event_type": "user_reaped_unverified",
                    "user_id": row["id"],
                    "email_hash": audit_email_hash(row["email"]),
                    "reason": "verification_not_completed",
                    "max_age_days": max_age_days,
                },
            )
        total += len(deleted)
        await asyncio.sleep(0)
        if len(deleted) < _REAP_BATCH_SIZE:
            break
    logger.info("Reaped %d unverified accounts (run limit: 1000)", total)
    return total
