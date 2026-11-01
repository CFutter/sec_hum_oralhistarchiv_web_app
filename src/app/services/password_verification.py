"""Shared password proof mechanics; account policy and writes stay with callers."""

import contextlib
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .crypto import password_hasher
from .db import Database, get_db_cursor
from .password_work import run_password_work

logger = logging.getLogger(__name__)
_DUMMY_HASH: str | None = None


class PasswordFailureReason(StrEnum):
    """Credential results only; capacity, cancellation and storage errors propagate."""

    MISSING_HASH = "missing_hash"
    MISMATCH = "mismatch"
    UNUSABLE_HASH = "unusable_hash"


@dataclass(frozen=True, slots=True)
class PasswordVerified:
    """A successful password proof, without account eligibility or authorization."""


@dataclass(frozen=True, slots=True)
class PasswordVerificationFailure:
    """A classified credential rejection, retaining its optional original cause."""

    reason: PasswordFailureReason
    cause: InvalidHashError | VerificationError | None = field(repr=False)


PasswordVerificationResult: TypeAlias = PasswordVerified | PasswordVerificationFailure


@dataclass(frozen=True, slots=True)
class VerifiedPasswordSnapshot:
    """Verified credentials; callers must compare both fields under their final lock."""

    password_hash: str = field(repr=False)
    auth_revision: int


async def warm_dummy_password_hash() -> str:
    """Cache a dummy Argon2 hash through the same bounded password-work runner.

    Concurrent first calls may each hash; the last completed value is cached.
    """
    global _DUMMY_HASH  # noqa: PLW0603 - one process-local, non-secret cache
    if _DUMMY_HASH is None:
        _DUMMY_HASH = await run_password_work(
            password_hasher.hash, "this-is-a-dummy-password-for-constant-time-verification"
        )
    return _DUMMY_HASH


async def verify_dummy(password: str) -> None:
    """Run dummy Argon2 work, suppressing only a password mismatch."""
    with contextlib.suppress(VerifyMismatchError):
        dummy_hash = await warm_dummy_password_hash()
        await run_password_work(password_hasher.verify, dummy_hash, password)


async def verify_password_hash(
    *, password_hash: str, password: str, user_id: int, operation: str
) -> PasswordVerificationResult:
    """Classify Argon2 credential failures without choosing workflow dummy-work policy."""
    try:
        await run_password_work(password_hasher.verify, password_hash, password)
    except VerifyMismatchError as exc:
        return PasswordVerificationFailure(PasswordFailureReason.MISMATCH, exc)
    except (InvalidHashError, VerificationError) as exc:
        logger.exception("Unverifiable password hash for user %d during %s", user_id, operation)
        return PasswordVerificationFailure(PasswordFailureReason.UNUSABLE_HASH, exc)
    return PasswordVerified()


async def verify_password_snapshot(
    pool: Database, *, user_id: int, password: str, operation: str
) -> VerifiedPasswordSnapshot | PasswordVerificationFailure:
    """Read credentials, release the cursor, then verify; this does not authorize an action.

    Missing and unusable hashes receive dummy work. Mismatches receive no extra
    dummy verification. Use a pool or idle connection; callers
    retain eligibility, attempt reservation and final locked hash/revision checks.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            "SELECT password_hash, auth_revision FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()

    if row is None or not isinstance(row["password_hash"], str) or not row["password_hash"]:
        await verify_dummy(password)
        return PasswordVerificationFailure(PasswordFailureReason.MISSING_HASH, None)

    result = await verify_password_hash(
        password_hash=row["password_hash"],
        password=password,
        user_id=user_id,
        operation=operation,
    )
    if not isinstance(result, PasswordVerified):
        if result.reason is PasswordFailureReason.UNUSABLE_HASH:
            await verify_dummy(password)
        return result
    return VerifiedPasswordSnapshot(row["password_hash"], row["auth_revision"])
