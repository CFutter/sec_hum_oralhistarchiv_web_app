"""Transactional encrypted email persistence; no SMTP operations.

Pool helpers commit on success and roll back on error; *_cur helpers
use the caller's transaction. Database and encryption errors propagate.
Lease updates require matching sending status and lock_token or raise
OutboxLeaseLostError; state checks additionally require an unexpired
lease and unchanged content.
"""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from psycopg import AsyncCursor, sql
from psycopg_pool import AsyncConnectionPool

from .crypto import decrypt_outbox_body, encrypt_outbox_body
from .db import get_db_cursor
from .db_schema_contract import EMAIL_OUTBOX_COLUMN_CONTRACT
from .tokens import (
    EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
    RESET_TOKEN_MAX_AGE_SECONDS,
    VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    ActionEmailMetadata,
)

_MAX_CLAIM_BATCH = 100
_MAX_ERROR_LENGTH = 1000

_CANCELLATION_REASONS = frozenset(
    {
        "superseded_or_consumed",
        "missing_user",
        "ineligible_account",
        "recipient_changed",
        "already_verified",
        "email_taken",
    }
)

TerminalOutcome = Literal["cancelled", "delivery_failed", "body_unreadable"]


def _delivery_block_outcome(reason: str) -> TerminalOutcome:
    """Classify why a claimed message became permanently undeliverable."""
    if reason in _CANCELLATION_REASONS:
        return "cancelled"

    return "delivery_failed"


_ACTION_TOKEN_FIELDS = {
    "password_reset": (
        "password_reset_token_hash",
        "password_reset_created_at",
        RESET_TOKEN_MAX_AGE_SECONDS,
    ),
    "email_verification": (
        "email_verification_token_hash",
        "email_verification_created_at",
        VERIFICATION_TOKEN_MAX_AGE_SECONDS,
    ),
    "email_change_verification": (
        "pending_email_token_hash",
        "pending_email_created_at",
        EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
    ),
}

_ACTION_MESSAGE_TYPES = frozenset(_ACTION_TOKEN_FIELDS)

_NOTICE_MESSAGE_TYPES = frozenset(
    {
        "duplicate_registration_notice",
        "email_change_notice",
        "account_credential_fault_notice",
        "account_locked_notice",
    }
)


@dataclass(frozen=True, slots=True)
class OutboundEmail:
    """A fully rendered email ready to enter the durable outbox."""

    message_type: str
    recipient: str
    subject: str
    body: str


@dataclass(frozen=True, slots=True)
class ClaimedEmail:
    """Leased ciphertext and immutable action metadata; attempt_count includes this claim."""

    id: int
    user_id: int | None
    message_type: str
    recipient: str
    subject: str
    body_ciphertext: str
    attempt_count: int
    lock_token: UUID
    action_token_hash: str | None = field(repr=False)
    expires_at: datetime | None


_CLAIM_IDENTITY_FIELDS = ("id",)

_IMMUTABLE_CONTENT_FIELDS = (
    "user_id",
    "message_type",
    "recipient",
    "subject",
    "body_ciphertext",
    "action_token_hash",
    "expires_at",
)

_MUTABLE_CLAIM_FIELDS = (
    "attempt_count",
    "lock_token",
)

_CLAIM_PROJECTION = tuple(dataclass_field.name for dataclass_field in fields(ClaimedEmail))

_LOCKED_ROW_PROJECTION = (
    *_IMMUTABLE_CONTENT_FIELDS,
    "status",
    "lock_token",
    "locked_at",
)

_CLAIM_RETURNING_SQL = sql.SQL(", ").join(
    sql.SQL("outbox.{}").format(sql.Identifier(name)) for name in _CLAIM_PROJECTION
)

_LOCKED_ROW_SELECT_SQL = sql.SQL(", ").join(sql.Identifier(name) for name in _LOCKED_ROW_PROJECTION)


class OutboxLeaseLostError(RuntimeError):
    """The row is no longer owned by the worker attempting to update it."""

    def __init__(self, message_id: int) -> None:
        """Store the message ID whose sending lease no longer matches."""
        self.message_id = message_id
        super().__init__(f"Email outbox lease lost for message {message_id}")


class OutboxBodyDecryptionError(RuntimeError):
    """A claimed outbox body cannot be decrypted."""

    def __init__(self, message_id: int) -> None:
        """Store the message ID whose ciphertext could not be decrypted."""
        self.message_id = message_id
        super().__init__(f"Cannot decrypt email outbox message {message_id}")


def _normalize_error(error: str) -> str:
    """Remove NULs, flatten lines, supply an empty-message fallback, and cap at 1,000 characters."""
    normalized = " ".join(error.replace("\x00", "").splitlines()).strip()
    return (normalized or "Unknown email delivery failure")[:_MAX_ERROR_LENGTH]


async def _mark_email_dead_cur(
    cur: AsyncCursor[Any],
    *,
    message_id: int,
    lock_token: UUID,
    error: str,
    outcome: TerminalOutcome,
) -> None:
    """Mark a matching sending lease dead in the caller's transaction;
    otherwise raise OutboxLeaseLostError.
    """
    await cur.execute(
        """
        UPDATE email_outbox
        SET status = 'dead',
            failed_at = clock_timestamp(),
            locked_at = NULL,
            lock_token = NULL,
            last_error = %s,
            terminal_outcome = %s,
            sent_at = NULL
        WHERE id = %s
          AND status = 'sending'
          AND lock_token = %s
        RETURNING id
        """,
        (_normalize_error(error), outcome, message_id, lock_token),
    )
    if await cur.fetchone() is None:
        raise OutboxLeaseLostError(message_id)


async def _lock_delivery_state_cur(
    cur: AsyncCursor[Any],
    message: ClaimedEmail,
    *,
    lease_timeout: timedelta,
) -> tuple[dict[str, Any], dict[str, Any] | None, datetime]:
    """Lock the action's user before its outbox row and return (row, user or None, DB time).

    Set a 250-ms transaction-local lock timeout. Reject nonpositive
    lease_timeout with ValueError, changed/expired leases with
    OutboxLeaseLostError, missing query results with RuntimeError, and an
    invalid clock type with TypeError. Database lock errors propagate.
    """
    if lease_timeout <= timedelta(0):
        raise ValueError("lease_timeout must be positive")

    await cur.execute("SET LOCAL lock_timeout = '250ms'")
    user = None
    if message.user_id is not None and message.message_type in _ACTION_MESSAGE_TYPES:
        await cur.execute(
            """
            SELECT id, is_active, auth_method, email_verified,
                   LOWER(email) = LOWER(%s) AS recipient_matches,
                   password_reset_token_hash, password_reset_created_at,
                   email_verification_token_hash,
                   email_verification_created_at,
                   pending_email, pending_email_token_hash,
                   pending_email_created_at
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (message.recipient, message.user_id),
        )
        user = await cur.fetchone()

    await cur.execute(
        sql.SQL(
            """
            SELECT {}
            FROM email_outbox
            WHERE id = %s
            FOR UPDATE
            """
        ).format(_LOCKED_ROW_SELECT_SQL),
        (message.id,),
    )
    row = await cur.fetchone()

    if row is None or row["status"] != "sending" or row["lock_token"] != message.lock_token:
        raise OutboxLeaseLostError(message.id)

    # Reject changed content instead of sending a cached body under
    # different metadata.
    for name in _IMMUTABLE_CONTENT_FIELDS:
        if row[name] != getattr(message, name):
            raise OutboxLeaseLostError(message.id)

    if user is not None and row["message_type"] == "email_change_verification":
        await cur.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM users
                WHERE LOWER(email) = LOWER(%s)
                  AND id != %s
            ) AS email_taken
            """,
            (row["recipient"], message.user_id),
        )
        email_taken_row = await cur.fetchone()
        if email_taken_row is None:
            raise RuntimeError("Email availability query returned no row")

        user["email_taken"] = bool(email_taken_row["email_taken"])

    await cur.execute("SELECT clock_timestamp() AS now")
    now_row = await cur.fetchone()
    if now_row is None:
        raise RuntimeError("Database clock query returned no row")

    now_value = now_row["now"]
    if not isinstance(now_value, datetime):
        raise TypeError("Database clock query returned an invalid timestamp type")

    now = now_value

    if row["locked_at"] is None or row["locked_at"] + lease_timeout <= now:
        raise OutboxLeaseLostError(message.id)

    return row, user, now


# Keep the ordered delivery-policy guards together so all terminal reasons
# can be reviewed as one security decision table.
def _delivery_block_reason(  # noqa: PLR0911, PLR0912
    row: dict[str, Any],
    user: dict[str, Any] | None,
    *,
    now: datetime,
    required_remaining: timedelta,
) -> str | None:
    """Return the first blocking reason, or None when delivery policy permits.

    Known notices need no action metadata or user. Actions require matching
    token/account/recipient state and lifetime strictly beyond now plus
    required_remaining, bounded by both signed expiry and token maximum age.
    """
    kind = row["message_type"]

    if kind in _NOTICE_MESSAGE_TYPES:
        if row["action_token_hash"] is not None or row["expires_at"] is not None:
            return "invalid_action_metadata"
        return None

    if kind not in _ACTION_TOKEN_FIELDS:
        return "unknown_message_type"
    if user is None:
        return "missing_user"
    if not row["action_token_hash"] or row["expires_at"] is None:
        return "missing_action_metadata"

    hash_column, time_column, max_age = _ACTION_TOKEN_FIELDS[kind]

    if user[hash_column] != row["action_token_hash"]:
        return "superseded_or_consumed"

    created_at = user[time_column]
    if created_at is None:
        return "missing_token_timestamp"

    if kind == "password_reset":
        if not user["is_active"] or user["auth_method"] != "local":
            return "ineligible_account"
        if not user["recipient_matches"]:
            return "recipient_changed"
        # Lockout does not prevent password recovery.

    elif kind == "email_verification":
        if user["email_verified"]:
            return "already_verified"
        if not user["recipient_matches"]:
            return "recipient_changed"

    elif user["pending_email"] != row["recipient"]:
        return "recipient_changed"

    elif user["email_taken"]:
        return "email_taken"

    deadline = min(
        row["expires_at"],
        created_at + timedelta(seconds=max_age),
    )

    if deadline <= now:
        return "expired"
    if deadline <= now + required_remaining:
        return "insufficient_lifetime"

    return None


def _claimed_email_from_row(
    row: Mapping[str, Any],
) -> ClaimedEmail:
    """Build a claim; raise RuntimeError unless row keys exactly match the claim projection."""
    expected = set(_CLAIM_PROJECTION)
    actual = set(row)

    if actual != expected:
        raise RuntimeError(
            "Claimed-email projection mismatch: "
            f"missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )

    return ClaimedEmail(**{name: row[name] for name in _CLAIM_PROJECTION})


async def mark_email_dead(
    pool: AsyncConnectionPool,
    *,
    message_id: int,
    lock_token: UUID,
    error: str,
    outcome: TerminalOutcome = "delivery_failed",
) -> None:
    """Permanently stop retrying a currently owned message."""
    async with get_db_cursor(pool) as cur:
        await _mark_email_dead_cur(
            cur,
            message_id=message_id,
            lock_token=lock_token,
            error=error,
            outcome=outcome,
        )


def decrypt_claimed_email_body(message: ClaimedEmail) -> str:
    """Return decrypted plaintext, raising OutboxBodyDecryptionError if decryption fails."""
    body = decrypt_outbox_body(message.body_ciphertext)
    if body is None:
        raise OutboxBodyDecryptionError(message.id)
    return body


async def enqueue_email_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int | None,
    message_type: str,
    recipient: str,
    subject: str,
    body: str,
    action: ActionEmailMetadata | None,
) -> int:
    """Encrypt the body and return the inserted ID in the caller's transaction.

    Strip type, recipient, and subject; require all fields nonempty. Actions
    require user_id and token metadata with an aware expiry, stored in UTC;
    notices require action=None. ValueError rejects unsupported types or
    invalid inputs. RuntimeError means no returned row; TypeError means
    a noninteger ID. Persist account changes with this same cursor.
    """
    message_type = message_type.strip()
    recipient = recipient.strip()
    subject = subject.strip()

    if not message_type:
        raise ValueError("message_type must not be empty")
    if not recipient:
        raise ValueError("recipient must not be empty")
    if not subject:
        raise ValueError("subject must not be empty")
    if not body:
        raise ValueError("body must not be empty")

    action_token_hash: str | None = None
    expires_at: datetime | None = None

    if message_type in _ACTION_MESSAGE_TYPES:
        if user_id is None:
            raise ValueError("Action emails require user_id")
        if action is None:
            raise ValueError("Action emails require action metadata")
        if not action.token_hash.strip():
            raise ValueError("Action token hash must not be empty")
        if action.expires_at.tzinfo is None or action.expires_at.utcoffset() is None:
            raise ValueError("Action expiry must be timezone-aware")

        action_token_hash = action.token_hash
        expires_at = action.expires_at.astimezone(UTC)

    elif message_type in _NOTICE_MESSAGE_TYPES:
        if action is not None:
            raise ValueError("Notice emails require action=None")

    else:
        raise ValueError(f"Unsupported message_type: {message_type!r}")

    await cur.execute(
        """
        INSERT INTO email_outbox (
            user_id,
            message_type,
            recipient,
            subject,
            body_ciphertext,
            action_token_hash,
            expires_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            user_id,
            message_type,
            recipient,
            subject,
            encrypt_outbox_body(body),
            action_token_hash,
            expires_at,
        ),
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Email outbox INSERT returned no id")

    message_id = row["id"]
    if not isinstance(message_id, int):
        raise TypeError("Email outbox INSERT id must be an integer")

    return message_id


def validate_email_outbox_contract() -> None:
    """Raise AssertionError for duplicate/unclassified claim fields
    or missing DB column contracts.
    """
    partitions = (
        _CLAIM_IDENTITY_FIELDS,
        _IMMUTABLE_CONTENT_FIELDS,
        _MUTABLE_CLAIM_FIELDS,
    )
    classified = [name for group in partitions for name in group]
    counts = Counter(classified)

    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if duplicates:
        raise AssertionError(f"ClaimedEmail fields classified more than once: {duplicates}")

    dataclass_fields = set(_CLAIM_PROJECTION)
    classified_fields = set(classified)

    if dataclass_fields != classified_fields:
        raise AssertionError(
            "ClaimedEmail classification mismatch: "
            f"unclassified={sorted(dataclass_fields - classified_fields)}, "
            f"unknown={sorted(classified_fields - dataclass_fields)}"
        )

    referenced_columns = dataclass_fields | set(_LOCKED_ROW_PROJECTION)
    if missing := referenced_columns - set(EMAIL_OUTBOX_COLUMN_CONTRACT):
        raise AssertionError(f"Outbox runtime fields lack DB contracts: {sorted(missing)}")


async def enqueue_outbound_email_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int | None,
    email: OutboundEmail,
    action: ActionEmailMetadata | None,
) -> int:
    """Delegate to enqueue_email_cur;
    return its ID with the same validation and transaction contract.
    """
    return await enqueue_email_cur(
        cur,
        user_id=user_id,
        message_type=email.message_type,
        recipient=email.recipient,
        subject=email.subject,
        body=email.body,
        action=action,
    )


async def claim_due_emails(
    pool: AsyncConnectionPool,
    *,
    limit: int,
    lease_timeout: timedelta,
) -> list[ClaimedEmail]:
    """Lease due pending or expired sending rows and increment their attempt counts.

    Return at most limit claims, with no guaranteed return order. Concurrent
    workers skip locked rows; one new token fences the whole claimed batch.
    ValueError rejects limits outside 1-100 or nonpositive lease_timeout.
    """
    if not 1 <= limit <= _MAX_CLAIM_BATCH:
        raise ValueError(f"limit must be between 1 and {_MAX_CLAIM_BATCH}, got {limit}")
    if lease_timeout <= timedelta(0):
        raise ValueError("lease_timeout must be positive")

    lock_token = uuid4()

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            sql.SQL(
                """
                WITH pending_candidates AS MATERIALIZED (
                    SELECT id, next_attempt_at AS due_at FROM email_outbox
                    WHERE status = 'pending' AND next_attempt_at <= CURRENT_TIMESTAMP
                    ORDER BY next_attempt_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %(limit)s
                ), stale_candidates AS MATERIALIZED (
                    SELECT id, locked_at AS due_at FROM email_outbox
                    WHERE status = 'sending'
                    AND locked_at < CURRENT_TIMESTAMP - %(lease_timeout)s
                    ORDER BY locked_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %(limit)s
                ), candidates AS (
                    SELECT id FROM (
                        SELECT id, due_at FROM pending_candidates
                        UNION ALL
                        SELECT id, due_at FROM stale_candidates
                    ) AS available
                    ORDER BY due_at, id
                    LIMIT %(limit)s
                )
                UPDATE email_outbox AS outbox
                SET status = 'sending',
                    attempt_count = outbox.attempt_count + 1,
                    locked_at = CURRENT_TIMESTAMP,
                    lock_token = %(lock_token)s
                FROM candidates
                WHERE outbox.id = candidates.id
                RETURNING {}
                """
            ).format(_CLAIM_RETURNING_SQL),
            {
                "lease_timeout": lease_timeout,
                "limit": limit,
                "lock_token": lock_token,
            },
        )
        rows = await cur.fetchall()

    return [_claimed_email_from_row(row) for row in rows]


async def _execute_lease_update(
    pool: AsyncConnectionPool,
    query: str,
    params: tuple[object, ...],
    *,
    message_id: int,
) -> None:
    """Commit a lease update; raise OutboxLeaseLostError if RETURNING yields no row."""
    async with get_db_cursor(pool) as cur:
        await cur.execute(query, params)
        row = await cur.fetchone()

    if row is None:
        raise OutboxLeaseLostError(message_id)


async def mark_email_sent(
    pool: AsyncConnectionPool,
    *,
    message_id: int,
    lock_token: UUID,
) -> None:
    """Mark a currently leased email as successfully delivered."""
    await _execute_lease_update(
        pool,
        """
        UPDATE email_outbox
        SET status = 'sent',
            sent_at = CURRENT_TIMESTAMP,
            failed_at = NULL,
            locked_at = NULL,
            lock_token = NULL,
            last_error = NULL
        WHERE id = %s
          AND status = 'sending'
          AND lock_token = %s
        RETURNING id
        """,
        (message_id, lock_token),
        message_id=message_id,
    )


async def defer_contended_email(
    pool: AsyncConnectionPool, message: ClaimedEmail, *, smtp_attempted: bool = False
) -> None:
    """Return a sending lease to pending for 30 seconds after a rolled-back lock wait.

    Use a 250-ms lock timeout without locking the user. Decrement the claim
    count unless smtp_attempted=True; raise OutboxLeaseLostError if replaced.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute("SET LOCAL lock_timeout = '250ms'")
        await cur.execute(
            """UPDATE email_outbox
               SET status = 'pending', next_attempt_at = clock_timestamp() + INTERVAL '30 seconds',
                   locked_at = NULL, lock_token = NULL, last_error = 'delivery_state_contended',
                   attempt_count = GREATEST(0, attempt_count - %s)
               WHERE id = %s AND status = 'sending' AND lock_token = %s
               RETURNING id""",
            (0 if smtp_attempted else 1, message.id, message.lock_token),
        )
        if await cur.fetchone() is None:
            raise OutboxLeaseLostError(message.id)


async def retry_email_later(
    pool: AsyncConnectionPool,
    *,
    message: ClaimedEmail,
    delay: timedelta,
    error: str,
    lease_timeout: timedelta,
    min_remaining_lifetime: timedelta,
) -> Literal["retried", "dead"]:
    """Return retried after rescheduling, or dead after a fresh policy check.

    Require usable action lifetime beyond delay + min_remaining_lifetime.
    ValueError rejects nonpositive delay/lease_timeout or negative minimum
    lifetime. Account/outbox locks use 250 ms; lease and database errors
    propagate. The error diagnostic is normalized before storage.
    """
    if delay <= timedelta(0):
        raise ValueError("retry delay must be positive")
    if min_remaining_lifetime < timedelta(0):
        raise ValueError("min_remaining_lifetime must not be negative")

    async with get_db_cursor(pool) as cur:
        row, user, now = await _lock_delivery_state_cur(
            cur,
            message,
            lease_timeout=lease_timeout,
        )
        reason = _delivery_block_reason(
            row,
            user,
            now=now,
            required_remaining=delay + min_remaining_lifetime,
        )

        if reason is not None:
            await _mark_email_dead_cur(
                cur,
                message_id=message.id,
                lock_token=message.lock_token,
                error=reason,
                outcome=_delivery_block_outcome(reason),
            )
            return "dead"

        await cur.execute(
            """
            UPDATE email_outbox
            SET status = 'pending',
                next_attempt_at = %s,
                locked_at = NULL,
                lock_token = NULL,
                last_error = %s,
                sent_at = NULL,
                failed_at = NULL
            WHERE id = %s
              AND status = 'sending'
              AND lock_token = %s
            RETURNING id
            """,
            (
                now + delay,
                _normalize_error(error),
                message.id,
                message.lock_token,
            ),
        )
        if await cur.fetchone() is None:
            raise OutboxLeaseLostError(message.id)

    return "retried"


async def cancel_pending_action_emails_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    message_type: str,
) -> None:
    """Cancel all pending mail for this user and action type in the caller's transaction.

    Sending rows are untouched. Unsupported action types raise ValueError.
    """
    if message_type not in _ACTION_MESSAGE_TYPES:
        raise ValueError(f"Not an action message type: {message_type!r}")

    await cur.execute(
        """
        UPDATE email_outbox
        SET status = 'dead',
            failed_at = clock_timestamp(),
            sent_at = NULL,
            locked_at = NULL,
            lock_token = NULL,
            last_error = 'superseded'
            , terminal_outcome = 'cancelled'
        WHERE user_id = %s
          AND message_type = %s
          AND status = 'pending'
        """,
        (user_id, message_type),
    )


async def prepare_email_delivery(
    pool: AsyncConnectionPool,
    message: ClaimedEmail,
    *,
    lease_timeout: timedelta,
    min_remaining_lifetime: timedelta,
) -> bool:
    """Return True after refreshing a valid lease, or False after marking unusable mail dead.

    Commit before returning; no transaction spans SMTP. ValueError rejects
    nonpositive lease_timeout or negative min_remaining_lifetime. Locks use
    250 ms; lease and database errors propagate, and callers must not send
    on error. The state may change again after this check commits.
    """
    if min_remaining_lifetime < timedelta(0):
        raise ValueError("min_remaining_lifetime must not be negative")
    async with get_db_cursor(pool) as cur:
        row, user, now = await _lock_delivery_state_cur(
            cur,
            message,
            lease_timeout=lease_timeout,
        )
        reason = _delivery_block_reason(
            row,
            user,
            now=now,
            required_remaining=min_remaining_lifetime,
        )
        if reason is not None:
            await _mark_email_dead_cur(
                cur,
                message_id=message.id,
                lock_token=message.lock_token,
                error=reason,
                outcome=_delivery_block_outcome(reason),
            )
            return False
        await cur.execute(
            """UPDATE email_outbox SET locked_at = clock_timestamp()
               WHERE id = %s AND status = 'sending' AND lock_token = %s
               RETURNING id""",
            (message.id, message.lock_token),
        )
        if await cur.fetchone() is None:
            raise OutboxLeaseLostError(message.id)
    return True
