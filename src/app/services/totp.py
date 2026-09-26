"""Enroll, verify, and rotate encrypted local TOTP credentials.

Enrollment/recovery secrets live for ten minutes; each setup-page request
replaces pending recovery codes. Rotation uses a separate five-minute
challenge bound to the authorizing session/revision after password and fresh
TOTP proof. Consume codes through locked helpers, not get_totp_secret.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import pyotp
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from config import settings

from .credential_attempts import (
    SessionStepUpAttemptOutcome,
    reserve_session_step_up_attempt,
)
from .crypto import decrypt_value, encrypt_value, password_hasher
from .db import get_db_cursor
from .password_work import run_password_work
from .session_ids import hash_session_id
from .session_revocation import (
    delete_user_sessions_cur,
    invalidate_pending_authentication_state_cur,
)
from .totp_recovery_codes import (
    activate_pending_recovery_code_set_cur,
    generate_recovery_codes,
    stage_recovery_code_set_cur,
)

logger = logging.getLogger(__name__)

_PENDING_TOTP_MAX_AGE_SECONDS = 600  # 10 minutes
_TOTP_ROTATION_MAX_AGE_SECONDS = 300  # 5 minutes
_TOTP_CODE_DIGITS = 6


class TotpDecryptionError(Exception):
    """An expected stored TOTP credential is missing or undecryptable; fail closed."""

    def __init__(self, user_id: int | None = None):
        """Record the optional user ID without exposing credential material."""
        self.user_id = user_id
        super().__init__(
            f"TOTP secret for user {user_id} is present but undecryptable "
            "(key mismatch, corruption, or incomplete key rotation)."
        )


class TotpRotationOutcome(StrEnum):
    """Result of confirming a session-bound authenticator rotation."""

    ROTATED = "rotated"
    PENDING_SECRET_MISSING = "pending_secret_missing"  # nosec B105
    INVALID_NEW_CODE = "invalid_new_code"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    ACCOUNT_LOCKED = "account_locked"
    SESSION_EXPIRED = "session_expired"
    INELIGIBLE = "ineligible"


class TotpRotationStartOutcome(StrEnum):
    """Result of fresh authentication for a new rotation challenge."""

    READY = "ready"
    INVALID_CREDENTIALS = "invalid_credentials"
    REPLAYED_CURRENT_CODE = "replayed_current_code"
    CURRENT_SECRET_MISSING = "current_secret_missing"  # nosec B105
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    ACCOUNT_LOCKED = "account_locked"
    SESSION_EXPIRED = "session_expired"
    INELIGIBLE = "ineligible"


@dataclass(frozen=True, slots=True)
class TotpRotationStartResult:
    """Rotation outcome; plaintext replacement secret is present only for READY."""

    outcome: TotpRotationStartOutcome
    secret: str | None = field(default=None, repr=False)


class TotpEnrollmentOutcome(StrEnum):
    """Result of an attempted atomic authenticator enrollment."""

    INELIGIBLE = "ineligible"
    SESSION_EXPIRED = "session_expired"
    ALREADY_CONFIGURED = "already_configured"
    PENDING_SECRET_MISSING = "pending_secret_missing"  # nosec B105
    INVALID_CODE = "invalid_code"
    INVALID_RECOVERY_CODE = "invalid_recovery_code"
    ENROLLED = "enrolled"
    RECOVERED = "recovered"


class PendingTotpPurpose(StrEnum):
    """Select initial enrollment or administrator-authorized recovery."""

    ENROLLMENT = "enrollment"
    RECOVERY = "recovery"


class PendingTotpOutcome(StrEnum):
    """Pending-secret eligibility/session result; only READY includes credentials."""

    READY = "ready"
    INELIGIBLE = "ineligible"
    SESSION_EXPIRED = "session_expired"
    ALREADY_CONFIGURED = "already_configured"


@dataclass(frozen=True, slots=True)
class PendingTotpResult:
    """Pending-secret outcome with plaintext secret and newly staged recovery codes.

    Do not log this object: secret is included in its generated repr.
    """

    outcome: PendingTotpOutcome
    secret: str | None = None
    recovery_codes: tuple[str, ...] = field(default=(), repr=False)


def normalize_totp_code(value: str) -> str | None:
    """Remove whitespace and return six ASCII digits, or None if malformed."""
    code = "".join(value.split())
    if len(code) != _TOTP_CODE_DIGITS or not code.isascii() or not code.isdigit():
        return None
    return code


def _session_purpose_matches(
    session_purpose: object,
    pending_purpose: PendingTotpPurpose,
) -> bool:
    """Match full/setup sessions to enrollment and recovery sessions to recovery.

    Raise ValueError for an unsupported PendingTotpPurpose.
    """
    if pending_purpose is PendingTotpPurpose.ENROLLMENT:
        return session_purpose in {"full", "totp_setup"}
    if pending_purpose is PendingTotpPurpose.RECOVERY:
        return session_purpose == "totp_recovery"
    raise ValueError(f"Unhandled pending TOTP purpose: {pending_purpose!r}")


async def _lock_authorizing_session_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    session_id: str,
    pending_purpose: PendingTotpPurpose,
) -> bool:
    """Lock the user's unexpired raw-token session and test its pending purpose.

    The caller owns the transaction and must lock the user first. Return False
    for absent or wrong-purpose sessions; unsupported purposes raise ValueError
    when a matching session exists.
    """
    await cur.execute(
        """
        SELECT purpose
        FROM sessions
        WHERE id = %s
          AND user_id = %s
          AND expires_at > clock_timestamp()
        FOR UPDATE
        """,
        (hash_session_id(session_id), user_id),
    )
    session = await cur.fetchone()
    return session is not None and _session_purpose_matches(
        session["purpose"],
        pending_purpose,
    )


def matched_step(
    secret: str,
    code: str,
    valid_window: int = 1,
    period: int = 30,
) -> int | None:
    """Return the earliest matching Unix-time step within +/- valid_window, else None.

    secret is Base32; period is seconds per step (normally 30), valid_window
    counts adjacent steps, and code is compared without normalization. Callers
    must supply a positive period and nonnegative window; malformed secrets or
    invalid numeric inputs may raise pyotp/datetime/arithmetic errors. No replay
    state is read or written.
    """

    totp = pyotp.TOTP(secret, interval=period)
    current_step = int(time.time()) // period

    for offset in range(-valid_window, valid_window + 1):
        step = current_step + offset
        if totp.verify(
            code,
            for_time=datetime.fromtimestamp(step * period, tz=UTC),
            valid_window=0,
        ):
            return step

    return None


async def get_totp_secret(pool: AsyncConnectionPool, user_id: int) -> str | None:
    """Return plaintext TOTP, or None for an absent user or empty stored credential.

    Raise TotpDecryptionError for undecryptable ciphertext. This snapshot does
    not authenticate the caller or prevent replay; use the consuming helpers.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
    if not row or not row.get("totp_secret"):
        return None
    plaintext = decrypt_value(row["totp_secret"])
    if plaintext is None:
        raise TotpDecryptionError(user_id)
    return plaintext


async def get_or_create_pending_totp_secret(
    pool: AsyncConnectionPool,
    user_id: int,
    *,
    purpose: PendingTotpPurpose,
    session_id: str,
) -> PendingTotpResult:
    """Commit a reused/fresh pending secret and fresh recovery codes for the raw session.

    Lock user then session. Require an active verified local account without
    TOTP; enrollment excludes recovery-required users, recovery requires them.
    Reuse decryptable secrets younger than ten minutes; replace expired/bad
    ones. Every READY result replaces pending recovery codes, so refreshing
    invalidates previously displayed codes while preserving an active set.
    Other outcomes identify account/session rejection. Unsupported enum purpose
    raises ValueError after account checks; storage failures propagate.
    """
    staged_plaintext_codes = (
        generate_recovery_codes()
        if purpose in {PendingTotpPurpose.ENROLLMENT, PendingTotpPurpose.RECOVERY}
        else ()
    )

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT
                is_active,
                auth_method,
                email_verified,
                totp_secret,
                totp_recovery_required,
                pending_totp_secret,
                (
                    pending_totp_created_at >
                    CURRENT_TIMESTAMP - %s * INTERVAL '1 second'
                ) AS pending_is_current
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (_PENDING_TOTP_MAX_AGE_SECONDS, user_id),
        )
        row = await cur.fetchone()

        if row is None or not row["is_active"] or row["auth_method"] != "local":
            return PendingTotpResult(PendingTotpOutcome.INELIGIBLE)

        if purpose is PendingTotpPurpose.ENROLLMENT:
            if not row["email_verified"] or row["totp_recovery_required"]:
                return PendingTotpResult(PendingTotpOutcome.INELIGIBLE)
            if row["totp_secret"] is not None:
                return PendingTotpResult(PendingTotpOutcome.ALREADY_CONFIGURED)

        elif purpose is PendingTotpPurpose.RECOVERY:
            if (
                not row["email_verified"]
                or not row["totp_recovery_required"]
                or row["totp_secret"] is not None
            ):
                return PendingTotpResult(PendingTotpOutcome.INELIGIBLE)

        else:
            raise ValueError(f"Unhandled pending TOTP purpose: {purpose!r}")

        if not await _lock_authorizing_session_cur(
            cur,
            user_id=user_id,
            session_id=session_id,
            pending_purpose=purpose,
        ):
            return PendingTotpResult(PendingTotpOutcome.SESSION_EXPIRED)

        pending_ciphertext = row["pending_totp_secret"]
        if pending_ciphertext and row["pending_is_current"]:
            secret = decrypt_value(pending_ciphertext)
            if secret is not None:
                recovery_codes: tuple[str, ...] = ()
                if staged_plaintext_codes:
                    staged = await stage_recovery_code_set_cur(
                        cur,
                        user_id=user_id,
                        codes=staged_plaintext_codes,
                    )
                    recovery_codes = staged.codes
                return PendingTotpResult(
                    PendingTotpOutcome.READY,
                    secret,
                    recovery_codes,
                )

        secret = generate_totp_secret()
        encrypted = encrypt_value(secret)

        await cur.execute(
            """
            UPDATE users
            SET pending_totp_secret = %s,
                pending_totp_created_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (encrypted, user_id),
        )

        recovery_codes = ()
        if staged_plaintext_codes:
            staged = await stage_recovery_code_set_cur(
                cur,
                user_id=user_id,
                codes=staged_plaintext_codes,
            )
            recovery_codes = staged.codes
        return PendingTotpResult(PendingTotpOutcome.READY, secret, recovery_codes)


async def verify_and_consume_totp_cur(
    cur: AsyncCursor[Any],
    user_id: int,
    code: str,
    *,
    valid_window: int = 1,
    period: int = 30,
) -> bool:
    """Consume a newer matching TOTP step under the caller's user-row lock.

    Normalize six-digit code; False means malformed/no credential/no match/replay.
    Use matched_step's window/period contract. True updates last_totp_step until
    commit; rollback restores it. Raise TotpDecryptionError for bad ciphertext.
    Caller checks account eligibility; this helper does not.
    """
    normalized_code = normalize_totp_code(code)
    if normalized_code is None:
        return False

    await cur.execute(
        """
        SELECT totp_secret, last_totp_step
        FROM users
        WHERE id = %s
        FOR UPDATE
        """,
        (user_id,),
    )
    row = await cur.fetchone()

    if row is None or not row["totp_secret"]:
        return False

    secret = decrypt_value(row["totp_secret"])
    if secret is None:
        raise TotpDecryptionError(user_id)

    step = matched_step(
        secret,
        normalized_code,
        valid_window=valid_window,
        period=period,
    )
    if step is None:
        return False

    last_step = row["last_totp_step"]
    if last_step is not None and step <= last_step:
        return False

    await cur.execute(
        """
        UPDATE users
        SET last_totp_step = %s
        WHERE id = %s
        """,
        (step, user_id),
    )
    return True


async def verify_and_consume_totp(
    pool: AsyncConnectionPool,
    user_id: int,
    code: str,
    *,
    valid_window: int = 1,
    period: int = 30,
) -> bool:
    """Commit verify_and_consume_totp_cur and return whether a fresh step was consumed.

    Uses that helper's input, rejection, and decryption-error contract.
    """
    async with get_db_cursor(pool) as cur:
        return await verify_and_consume_totp_cur(
            cur,
            user_id,
            code,
            valid_window=valid_window,
            period=period,
        )


async def verify_and_enroll_totp(
    pool: AsyncConnectionPool,
    user_id: int,
    code: str,
    recovery_code_confirmation: str,
    *,
    session_id: str,
) -> TotpEnrollmentOutcome:
    """Confirm pending TOTP and one staged recovery code under user/session locks.

    Require an active verified local account, no active factor, an appropriate
    unexpired raw-token session, and a decryptable secret younger than ten
    minutes. Return TotpEnrollmentOutcome for expected rejections. Success
    activates recovery codes, consumes the TOTP step, increments auth_revision,
    and clears pending capabilities. Initial setup upgrades only the supplied
    session to full; recovery clears recovery/lockout state and deletes all
    sessions. Database/invariant errors roll back the transaction.
    """
    normalized_code = normalize_totp_code(code)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT is_active, auth_method, email_verified,
                   totp_secret, pending_totp_secret,
                   pending_totp_created_at,
                   totp_recovery_required
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        row = await cur.fetchone()

        if (
            row is None
            or not row["is_active"]
            or row["auth_method"] != "local"
            or not row["email_verified"]
        ):
            return TotpEnrollmentOutcome.INELIGIBLE

        # Any stored active credential blocks initial enrollment,
        # including one whose ciphertext might be damaged.
        if row["totp_secret"] is not None:
            return TotpEnrollmentOutcome.ALREADY_CONFIGURED

        recovering = bool(row["totp_recovery_required"])
        pending_purpose = (
            PendingTotpPurpose.RECOVERY if recovering else PendingTotpPurpose.ENROLLMENT
        )
        if not await _lock_authorizing_session_cur(
            cur,
            user_id=user_id,
            session_id=session_id,
            pending_purpose=pending_purpose,
        ):
            return TotpEnrollmentOutcome.SESSION_EXPIRED

        ciphertext = row["pending_totp_secret"]
        created_at = row["pending_totp_created_at"]
        cutoff = datetime.now(UTC) - timedelta(seconds=_PENDING_TOTP_MAX_AGE_SECONDS)

        if not ciphertext or created_at is None or created_at <= cutoff:
            return TotpEnrollmentOutcome.PENDING_SECRET_MISSING

        secret = decrypt_value(ciphertext)
        if secret is None:
            return TotpEnrollmentOutcome.PENDING_SECRET_MISSING

        step = matched_step(secret, normalized_code) if normalized_code is not None else None
        if step is None:
            return TotpEnrollmentOutcome.INVALID_CODE

        if not await activate_pending_recovery_code_set_cur(
            cur,
            user_id=user_id,
            candidate_code=recovery_code_confirmation,
        ):
            return TotpEnrollmentOutcome.INVALID_RECOVERY_CODE

        if recovering:
            # The recovery CHECK constraint is immediate, so the active factor,
            # flag, and metadata must transition to the completed state in one
            # statement rather than through an invalid intermediate state.
            await cur.execute(
                """
                UPDATE users
                SET totp_secret = %s,
                    last_totp_step = %s,
                    auth_revision = auth_revision + 1,
                    pending_totp_secret = NULL,
                    pending_totp_created_at = NULL,
                    totp_recovery_required = false,
                    totp_recovery_expires_at = NULL,
                    totp_recovery_authorized_at = NULL,
                    totp_recovery_auth_revision = NULL,
                    failed_login_count = 0,
                    locked_until = NULL,
                    lockout_notice_enqueued_at = NULL
                WHERE id = %s
                """,
                (ciphertext, step, user_id),
            )
            await delete_user_sessions_cur(cur, user_id)
            await invalidate_pending_authentication_state_cur(cur, user_id)
            outcome = TotpEnrollmentOutcome.RECOVERED
        else:
            await cur.execute(
                """
                UPDATE users
                SET totp_secret = %s,
                    last_totp_step = %s,
                    auth_revision = auth_revision + 1,
                    pending_totp_secret = NULL,
                    pending_totp_created_at = NULL
                WHERE id = %s
                """,
                (ciphertext, step, user_id),
            )
            await invalidate_pending_authentication_state_cur(cur, user_id)
            await cur.execute(
                "UPDATE sessions SET purpose = 'full' WHERE id = %s",
                (hash_session_id(session_id),),
            )
            outcome = TotpEnrollmentOutcome.ENROLLED

    logger.info("TOTP %s completed for user %d", outcome.value, user_id)
    return outcome


async def _verify_rotation_password_snapshot(
    pool: AsyncConnectionPool,
    *,
    user_id: int,
    password: str,
) -> tuple[str, int] | None:
    """Verify off-connection; return (password_hash, auth_revision), or None on rejection.

    Missing/bad hashes also run dummy work. Callers recheck the snapshot and
    account eligibility under lock before using it.
    """
    # Imported lazily because authentication imports TOTP consumption helpers.
    from .authentication import verify_dummy  # noqa: PLC0415 - avoid import cycle

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT password_hash, auth_revision FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()

    if row is None or not isinstance(row["password_hash"], str) or not row["password_hash"]:
        await verify_dummy(password)
        return None

    password_hash = row["password_hash"]
    try:
        await run_password_work(password_hasher.verify, password_hash, password)
    except VerifyMismatchError:
        return None
    except (InvalidHashError, VerificationError):
        logger.exception("Unverifiable password hash during TOTP rotation for user %d", user_id)
        await verify_dummy(password)
        return None

    return password_hash, row["auth_revision"]


async def begin_totp_rotation(
    pool: AsyncConnectionPool,
    user_id: int,
    password: str,
    current_code: str,
    *,
    session_id: str,
    valid_window: int = 1,
    period: int = 30,
) -> TotpRotationStartResult:
    """Commit a five-minute replacement challenge after password and fresh TOTP proof.

    session_id is a raw full-session token. Spend a durable step-up attempt,
    verify password off-connection, then lock user/session and recheck
    eligibility, credentials/revision, lockout, and replay state. READY returns
    the sole plaintext replacement seed and replaces any earlier challenge;
    other outcomes reject without issuing a seed. Decryption errors propagate.
    Raise ValueError for a negative step window or nonpositive period in seconds.
    """
    if valid_window < 0:
        raise ValueError("valid_window must be non-negative")
    if period <= 0:
        raise ValueError("period must be positive")

    reservation = await reserve_session_step_up_attempt(
        pool,
        user_id=user_id,
        session_id=session_id,
    )
    if reservation is not SessionStepUpAttemptOutcome.RESERVED:
        rejected_outcomes = {
            SessionStepUpAttemptOutcome.INVALID_SESSION: TotpRotationStartOutcome.SESSION_EXPIRED,
            SessionStepUpAttemptOutcome.ACCOUNT_LOCKED: TotpRotationStartOutcome.ACCOUNT_LOCKED,
            SessionStepUpAttemptOutcome.ATTEMPTS_EXHAUSTED: (
                TotpRotationStartOutcome.ATTEMPTS_EXHAUSTED
            ),
        }
        try:
            return TotpRotationStartResult(rejected_outcomes[reservation])
        except KeyError as exc:
            raise RuntimeError(f"Unhandled step-up reservation outcome: {reservation!r}") from exc

    normalized_code = normalize_totp_code(current_code)
    password_snapshot = await _verify_rotation_password_snapshot(
        pool,
        user_id=user_id,
        password=password,
    )
    if password_snapshot is None or normalized_code is None:
        return TotpRotationStartResult(TotpRotationStartOutcome.INVALID_CREDENTIALS)

    verified_hash, verified_revision = password_snapshot
    session_hash = hash_session_id(session_id)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT password_hash,
                   auth_revision,
                   is_active,
                   email_verified,
                   auth_method,
                   totp_secret,
                   totp_recovery_required,
                   last_totp_step,
                   (locked_until IS NULL OR locked_until <= clock_timestamp())
                       AS login_unlocked
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (user_id,),
        )
        row = await cur.fetchone()

        if (
            row is None
            or not row["is_active"]
            or not row["email_verified"]
            or row["auth_method"] != "local"
            or row["totp_recovery_required"]
            or not row["login_unlocked"]
        ):
            return TotpRotationStartResult(TotpRotationStartOutcome.INELIGIBLE)

        if row["password_hash"] != verified_hash or row["auth_revision"] != verified_revision:
            return TotpRotationStartResult(TotpRotationStartOutcome.SESSION_EXPIRED)

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
            (session_hash, user_id),
        )
        if await cur.fetchone() is None:
            return TotpRotationStartResult(TotpRotationStartOutcome.SESSION_EXPIRED)

        active_ciphertext = row["totp_secret"]
        if not active_ciphertext:
            return TotpRotationStartResult(TotpRotationStartOutcome.CURRENT_SECRET_MISSING)

        current_secret = decrypt_value(active_ciphertext)
        if current_secret is None:
            raise TotpDecryptionError(user_id)

        current_step = matched_step(
            current_secret,
            normalized_code,
            valid_window=valid_window,
            period=period,
        )
        if current_step is None:
            return TotpRotationStartResult(TotpRotationStartOutcome.INVALID_CREDENTIALS)

        last_step = row["last_totp_step"]
        if last_step is not None and current_step <= last_step:
            return TotpRotationStartResult(TotpRotationStartOutcome.REPLAYED_CURRENT_CODE)

        replacement_secret = generate_totp_secret()
        replacement_ciphertext = encrypt_value(replacement_secret)
        await cur.execute(
            """
            UPDATE users
            SET last_totp_step = %s
            WHERE id = %s
            """,
            (current_step, user_id),
        )
        await cur.execute(
            """
            INSERT INTO pending_totp_rotations (
                user_id,
                session_id,
                auth_revision,
                encrypted_secret,
                created_at,
                expires_at
            )
            SELECT
                %s,
                %s,
                %s,
                %s,
                issued_at,
                issued_at + %s * INTERVAL '1 second'
            FROM (SELECT clock_timestamp() AS issued_at) AS issuance
            ON CONFLICT (user_id) DO UPDATE
            SET session_id = EXCLUDED.session_id,
                auth_revision = EXCLUDED.auth_revision,
                encrypted_secret = EXCLUDED.encrypted_secret,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at,
                confirmation_attempt_count = 0
            """,
            (
                user_id,
                session_hash,
                row["auth_revision"],
                replacement_ciphertext,
                _TOTP_ROTATION_MAX_AGE_SECONDS,
            ),
        )

    return TotpRotationStartResult(
        TotpRotationStartOutcome.READY,
        replacement_secret,
    )


async def confirm_totp_rotation(
    pool: AsyncConnectionPool,
    user_id: int,
    new_code: str,
    *,
    session_id: str,
    valid_window: int = 1,
    period: int = 30,
) -> TotpRotationOutcome:
    """Promote a matching session/revision-bound challenge and return its outcome.

    Lock user, raw-token full session, then challenge. Invalid codes spend its
    TOTP_ROTATION_CONFIRMATION_ATTEMPT_LIMIT budget; exhausted/expired/stale
    challenges are deleted. Success changes the factor, consumes its step,
    advances auth_revision, and revokes sessions/pending capabilities while
    retaining active recovery codes. Bad/missing active or bad pending
    ciphertext raises TotpDecryptionError and rolls back. Raise ValueError for
    a negative step window or nonpositive period in seconds.
    """
    if valid_window < 0:
        raise ValueError("valid_window must be non-negative")
    if period <= 0:
        raise ValueError("period must be positive")

    normalized_code = normalize_totp_code(new_code)
    session_hash = hash_session_id(session_id)

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT auth_revision,
                   is_active,
                   email_verified,
                   auth_method,
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
        row = await cur.fetchone()

        if (
            row is None
            or not row["is_active"]
            or not row["email_verified"]
            or row["auth_method"] != "local"
            or row["totp_recovery_required"]
        ):
            return TotpRotationOutcome.INELIGIBLE
        if not row["login_unlocked"]:
            return TotpRotationOutcome.ACCOUNT_LOCKED

        active_ciphertext = row["totp_secret"]
        if not active_ciphertext or decrypt_value(active_ciphertext) is None:
            raise TotpDecryptionError(user_id)

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
            (session_hash, user_id),
        )
        if await cur.fetchone() is None:
            return TotpRotationOutcome.SESSION_EXPIRED

        await cur.execute(
            """
            SELECT encrypted_secret,
                   auth_revision,
                   confirmation_attempt_count,
                   expires_at > clock_timestamp() AS unexpired
            FROM pending_totp_rotations
            WHERE user_id = %s
              AND session_id = %s
            FOR UPDATE
            """,
            (user_id, session_hash),
        )
        challenge = await cur.fetchone()
        if challenge is None:
            return TotpRotationOutcome.PENDING_SECRET_MISSING

        if not challenge["unexpired"] or challenge["auth_revision"] != row["auth_revision"]:
            await cur.execute(
                """DELETE FROM pending_totp_rotations
                   WHERE user_id = %s AND session_id = %s""",
                (user_id, session_hash),
            )
            return TotpRotationOutcome.PENDING_SECRET_MISSING

        attempt_count = challenge["confirmation_attempt_count"]
        if attempt_count >= settings.totp_rotation_confirmation_attempt_limit:
            await cur.execute(
                """DELETE FROM pending_totp_rotations
                   WHERE user_id = %s AND session_id = %s""",
                (user_id, session_hash),
            )
            return TotpRotationOutcome.ATTEMPTS_EXHAUSTED

        await cur.execute(
            """
            UPDATE pending_totp_rotations
            SET confirmation_attempt_count = confirmation_attempt_count + 1
            WHERE user_id = %s
              AND session_id = %s
            RETURNING confirmation_attempt_count
            """,
            (user_id, session_hash),
        )
        incremented = await cur.fetchone()
        if incremented is None:
            raise RuntimeError("Locked TOTP rotation challenge disappeared")
        attempt_count = incremented["confirmation_attempt_count"]

        pending_ciphertext = challenge["encrypted_secret"]
        replacement_secret = decrypt_value(pending_ciphertext)
        if replacement_secret is None:
            raise TotpDecryptionError(user_id)

        new_step = (
            matched_step(
                replacement_secret,
                normalized_code,
                valid_window=valid_window,
                period=period,
            )
            if normalized_code is not None
            else None
        )
        if new_step is None:
            if attempt_count >= settings.totp_rotation_confirmation_attempt_limit:
                await cur.execute(
                    """DELETE FROM pending_totp_rotations
                       WHERE user_id = %s AND session_id = %s""",
                    (user_id, session_hash),
                )
                return TotpRotationOutcome.ATTEMPTS_EXHAUSTED
            return TotpRotationOutcome.INVALID_NEW_CODE

        await cur.execute(
            """
            UPDATE users
            SET totp_secret = %s,
                last_totp_step = %s,
                auth_revision = auth_revision + 1
            WHERE id = %s
            """,
            (pending_ciphertext, new_step, user_id),
        )
        await delete_user_sessions_cur(cur, user_id)
        await invalidate_pending_authentication_state_cur(cur, user_id)

    logger.info(
        "TOTP rotation completed and sessions revoked for user %d",
        user_id,
    )
    return TotpRotationOutcome.ROTATED


async def get_pending_totp_secret(
    pool: AsyncConnectionPool,
    user_id: int,
    *,
    session_id: str,
    purpose: PendingTotpPurpose,
) -> str | None:
    """Return current enrollment/recovery plaintext for the authorized raw session.

    Lock user then session; return None for ineligible state, age >= ten
    minutes, absent/invalid session, or undecryptable ciphertext. No rotation
    seeds are returned. Unsupported enum purpose raises ValueError only after
    initial account/pending-state checks.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT is_active,
                   auth_method,
                   email_verified,
                   totp_secret,
                   totp_recovery_required,
                   pending_totp_secret,
                   (
                       pending_totp_created_at IS NOT NULL
                       AND pending_totp_created_at >
                           clock_timestamp() - %s * INTERVAL '1 second'
                   ) AS pending_is_current
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (_PENDING_TOTP_MAX_AGE_SECONDS, user_id),
        )
        row = await cur.fetchone()
        if (
            row is None
            or not row["is_active"]
            or row["auth_method"] != "local"
            or not row["email_verified"]
            or not row["pending_totp_secret"]
            or not row["pending_is_current"]
        ):
            return None

        if purpose is PendingTotpPurpose.ENROLLMENT:
            state_matches = not row["totp_recovery_required"] and row["totp_secret"] is None
        elif purpose is PendingTotpPurpose.RECOVERY:
            state_matches = row["totp_recovery_required"] and row["totp_secret"] is None
        else:
            raise ValueError(f"Unhandled pending TOTP purpose: {purpose!r}")

        if not state_matches or not await _lock_authorizing_session_cur(
            cur,
            user_id=user_id,
            session_id=session_id,
            pending_purpose=purpose,
        ):
            return None

        return decrypt_value(row["pending_totp_secret"])


def generate_totp_secret() -> str:
    """Generate a new random TOTP secret for user enrollment."""
    return pyotp.random_base32()
