"""Mailbox-bound creation and completion of passwordless pending accounts.

No login session is issued here. HTTP callers must protect the completion form
with CSRF and form-content checks before opening public registration. The
service owns each transaction; the signed capability and persisted state are
both required, including after password hashing and row-lock waits.
"""

from dataclasses import dataclass
from typing import Any

from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from app.account_contracts import PENDING_ACCOUNT_PREDICATE
from app.action_token_contract import ACTION_TOKEN_MAX_CHARS
from app.credentials import normalize_email
from app.service_errors import UserInputRejected
from config import settings

from .crypto import password_hasher
from .db import get_db_cursor
from .email import build_verification_email
from .email_outbox import enqueue_outbound_email_cur, requeue_retained_action_email_cur
from .email_verification import (
    generate_verification_token,
    store_verification_token_hash_cur,
    validate_verification_token,
    verification_token_email_metadata,
)
from .mail_issuance import anonymous_mail_issuance_allowed_cur, record_mail_issuance_cur
from .password_validation import validate_password_strength
from .password_work import run_password_work
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .tokens import (
    VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    EmailUserPayload,
    action_token_url,
    hash_token,
)
from .users import USER_COLUMNS_SQL, User, normalize_display_name, parse_user

REGISTRATION_TOKEN_MAX_CHARS = ACTION_TOKEN_MAX_CHARS
REGISTRATION_AFFILIATION_MAX_CHARS = 200
REGISTRATION_COUNTRY_MAX_CHARS = 100
_ASCII_PRINTABLE_START = 32
_ASCII_DELETE = 127


@dataclass(frozen=True, slots=True)
class RegistrationSetup:
    """Read-only mailbox identity for an eligible registration form."""

    user_id: int
    email: str


_PENDING_ACCOUNT_SQL = sql.SQL(PENDING_ACCOUNT_PREDICATE)
_PENDING_WHERE_SQL = sql.SQL("""
    id = %(user_id)s AND LOWER(email) = LOWER(%(email)s)
    AND {account}
    AND email_verification_token_hash = %(token_hash)s
    AND email_verification_created_at > clock_timestamp()
        - %(max_age)s * INTERVAL '1 second'
""").format(account=_PENDING_ACCOUNT_SQL)


def _capability(token: str) -> EmailUserPayload | None:
    """Validate a nonempty bounded verification token; return None when unusable."""
    if not isinstance(token, str) or not 0 < len(token) <= REGISTRATION_TOKEN_MAX_CHARS:
        return None
    return validate_verification_token(token)


def _parameters(data: EmailUserPayload, token: str) -> dict[str, Any]:
    """Bind pending-registration identity, token hash and verification lifetime."""
    return {
        "user_id": data["user_id"],
        "email": data["email"],
        "token_hash": hash_token(token),
        "max_age": VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    }


async def _pending_snapshot(
    pool: AsyncConnectionPool, params: dict[str, Any]
) -> dict[str, Any] | None:
    """Read an eligible pending-registration identity/revision, or None if absent."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL("SELECT id, email, auth_revision FROM users WHERE {} ").format(
                _PENDING_WHERE_SQL
            ),
            params,
        )
        return await cur.fetchone()


def _profile_value(value: str | None, *, limit: int, label: str) -> str | None:
    """Strip an optional profile value; map blank to None.

    Raise TypeError for non-strings or UserInputRejected for excessive length,
    ASCII control characters or DEL; limit counts characters.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"Invalid {label} type")
    value = value.strip()
    if len(value) > limit or any(
        ord(char) < _ASCII_PRINTABLE_START or ord(char) == _ASCII_DELETE for char in value
    ):
        raise UserInputRejected(f"Invalid {label}.")
    return value or None


async def begin_local_registration(pool: AsyncConnectionPool, *, email: str) -> None:
    """Queue bounded mailbox proof for a new email; existing addresses are no-ops.

    Admission, creation and enqueue share one transaction and a global issuance
    lock. A duplicate cannot churn credentials, capabilities or recipient mail.
    Callers render the same pending response for admitted, duplicate and limited
    requests; exact elapsed-time equality is not promised. Storage errors roll
    back creation and enqueue together.
    """
    normalized = normalize_email(email)
    if normalized is None:
        raise UserInputRejected("Please enter a valid email address.")
    async with get_db_cursor(pool) as cur:
        if not await anonymous_mail_issuance_allowed_cur(cur, normalized):
            return
        await cur.execute(
            """INSERT INTO users
                   (email, password_hash, auth_method, access_tier,
                    is_active, email_verified, is_admin)
               VALUES (%s, NULL, 'local', 'public', false, false, false)
               ON CONFLICT (LOWER(email)) DO NOTHING
               RETURNING id, email""",
            (normalized,),
        )
        row = await cur.fetchone()
        if row is None:
            return
        token = generate_verification_token(row["id"], row["email"])
        action = verification_token_email_metadata(token)
        # This row was inserted by this transaction; no anonymous resend can
        # initialize a capability cleared by an administrator's cancellation.
        await cur.execute(
            """UPDATE users SET email_verification_token_hash = %s,
                      email_verification_created_at = clock_timestamp()
               WHERE id = %s""",
            (action.token_hash, row["id"]),
        )
        message = build_verification_email(
            row["email"],
            f"{settings.public_base_url}{action_token_url('/verify-email', token)}",
            expires_at=action.expires_at,
            security_code=token,
        )
        await enqueue_outbound_email_cur(cur, user_id=row["id"], email=message, action=action)
        await record_mail_issuance_cur(cur, row["email"])


async def resend_local_registration(pool: AsyncConnectionPool, *, email: str) -> None:
    """Replace only an expired, uncancelled setup capability after mail admission.

    A still-live capability and its original expiry remain unchanged. Delivery
    retries continue automatically; an admitted resend copies a retained sent
    or delivery-failed message with the same capability. Unknown, completed,
    cancelled and limited requests
    share the void result. No password work or login occurs; storage failures
    roll back replacement and enqueue together.
    """
    normalized = normalize_email(email)
    if normalized is None:
        return
    async with get_db_cursor(pool) as cur:
        if not await anonymous_mail_issuance_allowed_cur(cur, normalized):
            return
        await cur.execute(
            sql.SQL("""SELECT id, email, email_verification_token_hash,
                    email_verification_created_at > clock_timestamp()
                        - %s * INTERVAL '1 second' AS verification_live
                FROM users WHERE LOWER(email) = LOWER(%s) AND {account}
                  AND email_verification_token_hash IS NOT NULL
                  AND email_verification_created_at IS NOT NULL
                FOR UPDATE""").format(account=_PENDING_ACCOUNT_SQL),
            (VERIFICATION_TOKEN_MAX_AGE_SECONDS, normalized),
        )
        row = await cur.fetchone()
        if row is None:
            return
        if row["verification_live"]:
            queued = await requeue_retained_action_email_cur(
                cur,
                user_id=row["id"],
                recipient=row["email"],
                message_type="email_verification",
                token_hash=row["email_verification_token_hash"],
            )
            if queued:
                await record_mail_issuance_cur(cur, row["email"])
            return
        token = generate_verification_token(row["id"], row["email"])
        action = verification_token_email_metadata(token)
        await store_verification_token_hash_cur(
            cur, row["id"], action.token_hash, expected_email=row["email"]
        )
        message = build_verification_email(
            row["email"],
            f"{settings.public_base_url}{action_token_url('/verify-email', token)}",
            expires_at=action.expires_at,
            security_code=token,
        )
        await enqueue_outbound_email_cur(cur, user_id=row["id"], email=message, action=action)
        await record_mail_issuance_cur(cur, row["email"])


async def inspect_local_registration(
    pool: AsyncConnectionPool, token: str
) -> RegistrationSetup | None:
    """Check signature and live pending state without consuming either."""
    data = _capability(token)
    if data is None:
        return None
    row = await _pending_snapshot(pool, _parameters(data, token))
    return RegistrationSetup(row["id"], row["email"]) if row is not None else None


async def complete_local_registration(
    pool: AsyncConnectionPool,
    *,
    token: str,
    display_name: str,
    password: str,
    affiliation: str | None = None,
    country: str | None = None,
) -> User | None:
    """Set credentials, verify and activate exactly one eligible pending account.

    Return None for an invalid, stale, expired or cancelled capability. Validate
    profile/password only after checking live capability state, then hash outside
    a transaction. Recheck signed expiry after the user-row lock, and persisted
    expiry/hash/email/pending state plus auth_revision in the final update.
    UserInputRejected means invalid profile/password. Revocation and outbox cancellation
    commit with credentials; any failure rolls everything back.
    """
    data = _capability(token)
    if data is None:
        return None
    params = _parameters(data, token)
    snapshot = await _pending_snapshot(pool, params)
    if snapshot is None:
        return None
    name = normalize_display_name(display_name)
    organization = _profile_value(
        affiliation, limit=REGISTRATION_AFFILIATION_MAX_CHARS, label="affiliation"
    )
    location = _profile_value(country, limit=REGISTRATION_COUNTRY_MAX_CHARS, label="country")
    if error := validate_password_strength(password, email=snapshot["email"], display_name=name):
        raise UserInputRejected(error)
    new_hash = await run_password_work(password_hasher.hash, password)
    params.update(
        password_hash=new_hash,
        display_name=name,
        affiliation=organization,
        country=location,
        auth_revision=snapshot["auth_revision"],
    )
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (data["user_id"],))
        if await cur.fetchone() is None or _capability(token) is None:
            return None
        await cur.execute(
            sql.SQL("""UPDATE users SET password_hash = %(password_hash)s,
                       display_name = %(display_name)s, affiliation = %(affiliation)s,
                       country = %(country)s, is_active = true, email_verified = true,
                       auth_revision = auth_revision + 1,
                       failed_login_count = 0, locked_until = NULL,
                       lockout_notice_enqueued_at = NULL,
                       email_verification_token_hash = NULL,
                       email_verification_created_at = NULL
                    WHERE {eligible} AND auth_revision = %(auth_revision)s
                    RETURNING {columns}""").format(
                eligible=_PENDING_WHERE_SQL, columns=USER_COLUMNS_SQL
            ),
            params,
        )
        row = await cur.fetchone()
        if row is None:
            return None
        await delete_user_sessions_cur(cur, data["user_id"])
        await invalidate_pending_authentication_state_cur(cur, data["user_id"])
        return parse_user(row)
