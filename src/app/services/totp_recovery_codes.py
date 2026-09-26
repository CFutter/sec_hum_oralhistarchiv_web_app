"""Store SHA-256 digests of 80-bit, one-use local TOTP recovery codes.

A pending generation can be shown/confirmed while the active set remains
usable. Activate it in the same transaction as its credential/role change.
Plaintext codes are returned to callers, never persisted by this module.
"""

import secrets
from dataclasses import dataclass, field
from string import hexdigits
from typing import Any

from psycopg import AsyncCursor

from .tokens import hash_token

TOTP_RECOVERY_CODE_COUNT = 10
TOTP_RECOVERY_CODE_MAX_CHARS = 64
TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT = 3

_RECOVERY_CODE_BYTES = 10
_RECOVERY_CODE_GROUP_CHARS = 5


@dataclass(frozen=True, slots=True)
class PendingRecoveryCodeSet:
    """Staged generation and plaintext codes excluded from repr."""

    generation: int
    codes: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class MatchedRecoveryCodeCandidate:
    """Nonlocking match to revalidate when reserving; digest is excluded from repr."""

    user_id: int
    generation: int
    position: int
    code_hash: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ReservedRecoveryCodePasswordAttempt:
    """An exact code row whose password-attempt budget has been consumed."""

    user_id: int
    generation: int
    position: int
    code_hash: str = field(repr=False, compare=False)


def normalize_recovery_code(value: str) -> str | None:
    """Remove ASCII spaces/hyphens and uppercase 20 hex characters, or return None."""
    normalized = "".join(character for character in value if character not in {"-", " "})
    normalized = normalized.upper()
    expected_chars = _RECOVERY_CODE_BYTES * 2
    if (
        len(normalized) != expected_chars
        or not normalized.isascii()
        or any(character not in hexdigits for character in normalized)
    ):
        return None
    return normalized


def generate_recovery_codes() -> tuple[str, ...]:
    """Return ten random 80-bit uppercase hex codes, grouped as four blocks of five."""
    codes: list[str] = []
    for _ in range(TOTP_RECOVERY_CODE_COUNT):
        canonical = secrets.token_hex(_RECOVERY_CODE_BYTES).upper()
        codes.append(
            "-".join(
                canonical[offset : offset + _RECOVERY_CODE_GROUP_CHARS]
                for offset in range(0, len(canonical), _RECOVERY_CODE_GROUP_CHARS)
            )
        )
    return tuple(codes)


def _code_hash(code: str) -> str:
    """Hash a normalized code; raise ValueError if its format is invalid."""
    canonical = normalize_recovery_code(code)
    if canonical is None:
        raise ValueError("Generated recovery code is invalid")
    return hash_token(canonical)


async def stage_recovery_code_set_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    codes: tuple[str, ...],
) -> PendingRecoveryCodeSet:
    """Replace pending codes with active generation + 1; return plaintext metadata.

    The caller owns the transaction and must already hold the user-row lock
    (reacquired here). Preserve active codes and delete other generations.
    Require ten distinct valid codes: bad count/format or missing user raises
    ValueError; equivalent normalized codes raise RuntimeError.
    """
    if len(codes) != TOTP_RECOVERY_CODE_COUNT or len(set(codes)) != len(codes):
        raise ValueError("Recovery-code set has the wrong cardinality")

    hashes = tuple(_code_hash(code) for code in codes)
    if len(set(hashes)) != len(hashes):
        raise RuntimeError("Recovery-code generator produced duplicate values")

    await cur.execute(
        """
        SELECT totp_recovery_code_generation
        FROM users
        WHERE id = %s
        FOR UPDATE
        """,
        (user_id,),
    )
    row = await cur.fetchone()
    if row is None:
        raise ValueError(f"User {user_id} not found")

    active_generation = row["totp_recovery_code_generation"]
    generation = active_generation + 1

    await cur.execute(
        """
        DELETE FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation <> %s
        """,
        (user_id, active_generation),
    )
    await cur.executemany(
        """
        INSERT INTO totp_recovery_codes (
            user_id, generation, position, code_hash
        )
        VALUES (%s, %s, %s, %s)
        """,
        [
            (user_id, generation, position, code_hash)
            for position, code_hash in enumerate(hashes, start=1)
        ],
    )
    await cur.execute(
        """
        UPDATE users
        SET pending_totp_recovery_code_generation = %s
        WHERE id = %s
        """,
        (generation, user_id),
    )
    return PendingRecoveryCodeSet(generation=generation, codes=codes)


async def activate_pending_recovery_code_set_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    candidate_code: str,
) -> bool:
    """Activate a complete ten-code pending set after matching one unused code.

    Lock the user in the caller's transaction; delete all other generations and
    clear its pending pointer. The confirming code remains unused. Return False
    for invalid/missing/incomplete state; raise RuntimeError if pending is not
    newer than active.
    """
    canonical = normalize_recovery_code(candidate_code)
    if canonical is None:
        return False

    await cur.execute(
        """
        SELECT totp_recovery_code_generation,
               pending_totp_recovery_code_generation
        FROM users
        WHERE id = %s
        FOR UPDATE
        """,
        (user_id,),
    )
    row = await cur.fetchone()
    if row is None or row["pending_totp_recovery_code_generation"] is None:
        return False

    pending_generation = row["pending_totp_recovery_code_generation"]
    if pending_generation <= row["totp_recovery_code_generation"]:
        raise RuntimeError("Pending recovery-code generation is not newer than active set")

    await cur.execute(
        """
        SELECT COUNT(*) AS code_count,
               COUNT(*) FILTER (WHERE used_at IS NULL) AS unused_count,
               COUNT(*) FILTER (
                   WHERE code_hash = %s AND used_at IS NULL
               ) AS candidate_count
        FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation = %s
        """,
        (hash_token(canonical), user_id, pending_generation),
    )
    counts = await cur.fetchone()
    if (
        counts is None
        or counts["code_count"] != TOTP_RECOVERY_CODE_COUNT
        or counts["unused_count"] != TOTP_RECOVERY_CODE_COUNT
        or counts["candidate_count"] != 1
    ):
        return False

    await cur.execute(
        """
        DELETE FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation <> %s
        """,
        (user_id, pending_generation),
    )
    await cur.execute(
        """
        UPDATE users
        SET totp_recovery_code_generation = %s,
            pending_totp_recovery_code_generation = NULL
        WHERE id = %s
        """,
        (pending_generation, user_id),
    )
    return True


async def find_active_recovery_code_candidate_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    active_generation: int,
    candidate_code: str,
) -> MatchedRecoveryCodeCandidate | None:
    """Return an unused code match with fewer than three attempts, or None.

    This is a nonlocking read of the supplied generation, not authentication or
    proof it is still active. Reserve the candidate before password work.
    """
    canonical = normalize_recovery_code(candidate_code)
    if canonical is None or active_generation <= 0:
        return None

    code_hash = hash_token(canonical)
    await cur.execute(
        """
        SELECT position
        FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation = %s
          AND code_hash = %s
          AND used_at IS NULL
          AND password_attempt_count < %s
        """,
        (
            user_id,
            active_generation,
            code_hash,
            TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
        ),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    return MatchedRecoveryCodeCandidate(
        user_id=user_id,
        generation=active_generation,
        position=row["position"],
        code_hash=code_hash,
    )


async def reserve_recovery_code_password_attempt_cur(
    cur: AsyncCursor[Any],
    *,
    candidate: MatchedRecoveryCodeCandidate,
) -> ReservedRecoveryCodePasswordAttempt | None:
    """Reserve one of three password attempts on the exact still-active code.

    Lock user before code; return None for a missing/stale/used/exhausted match.
    The caller must commit before password work so later rejection cannot refund
    the attempt; successful submissions spend the budget too.
    """
    await cur.execute(
        """
        SELECT totp_recovery_code_generation
        FROM users
        WHERE id = %s
        FOR UPDATE
        """,
        (candidate.user_id,),
    )
    user = await cur.fetchone()
    if user is None or user["totp_recovery_code_generation"] != candidate.generation:
        return None

    await cur.execute(
        """
        UPDATE totp_recovery_codes
        SET password_attempt_count = password_attempt_count + 1
        WHERE user_id = %s
          AND generation = %s
          AND position = %s
          AND code_hash = %s
          AND used_at IS NULL
          AND password_attempt_count < %s
        RETURNING position
        """,
        (
            candidate.user_id,
            candidate.generation,
            candidate.position,
            candidate.code_hash,
            TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
        ),
    )
    if await cur.fetchone() is None:
        return None
    return ReservedRecoveryCodePasswordAttempt(
        user_id=candidate.user_id,
        generation=candidate.generation,
        position=candidate.position,
        code_hash=candidate.code_hash,
    )


async def consume_reserved_recovery_code_cur(
    cur: AsyncCursor[Any],
    *,
    reservation: ReservedRecoveryCodePasswordAttempt,
) -> bool:
    """Mark the exact active reserved code used; return whether consumption succeeded.

    The caller owns the final transaction and must revalidate credentials and
    authorization. The user lock serializes consumption; require an unused code
    with one to three attempts. A rollback restores its unused state.
    """
    await cur.execute(
        """
        SELECT totp_recovery_code_generation
        FROM users
        WHERE id = %s
        FOR UPDATE
        """,
        (reservation.user_id,),
    )
    user = await cur.fetchone()
    if user is None or user["totp_recovery_code_generation"] != reservation.generation:
        return False

    await cur.execute(
        """
        UPDATE totp_recovery_codes
        SET used_at = clock_timestamp()
        WHERE user_id = %s
          AND generation = %s
          AND position = %s
          AND code_hash = %s
          AND used_at IS NULL
          AND password_attempt_count BETWEEN 1 AND %s
        RETURNING position
        """,
        (
            reservation.user_id,
            reservation.generation,
            reservation.position,
            reservation.code_hash,
            TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
        ),
    )
    return await cur.fetchone() is not None


async def has_unused_active_recovery_code_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
    active_generation: int,
) -> bool:
    """Check the supplied generation for an unused code with fewer than three attempts.

    Return False for nonpositive generations; no user-row active-generation
    check or lock is performed.
    """
    if active_generation <= 0:
        return False
    await cur.execute(
        """
        SELECT 1
        FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation = %s
          AND used_at IS NULL
          AND password_attempt_count < %s
        LIMIT 1
        """,
        (
            user_id,
            active_generation,
            TOTP_RECOVERY_PASSWORD_ATTEMPT_LIMIT,
        ),
    )
    return await cur.fetchone() is not None


async def discard_pending_recovery_code_set_cur(
    cur: AsyncCursor[Any],
    *,
    user_id: int,
) -> None:
    """Delete nonactive code generations and clear the pending pointer transactionally.

    The caller must serialize this operation with generation changes.
    """
    await cur.execute(
        """
        DELETE FROM totp_recovery_codes
        WHERE user_id = %s
          AND generation <> (
              SELECT totp_recovery_code_generation
              FROM users
              WHERE id = %s
          )
        """,
        (user_id, user_id),
    )
    await cur.execute(
        """
        UPDATE users
        SET pending_totp_recovery_code_generation = NULL
        WHERE id = %s
        """,
        (user_id,),
    )
