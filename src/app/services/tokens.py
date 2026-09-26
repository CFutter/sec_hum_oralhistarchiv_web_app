"""Shared action-token SHA-256 hashes, payload validation, and lifetimes in seconds."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypedDict

RESET_TOKEN_MAX_AGE_SECONDS = 1800  # 30 minutes
VERIFICATION_TOKEN_MAX_AGE_SECONDS = 86400
EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class ActionEmailMetadata:
    """Token hash and timezone-aware signed expiration for an action email."""

    token_hash: str = field(repr=False)
    expires_at: datetime


class EmailUserPayload(TypedDict):
    """Signed account reference: an email string and positive, non-boolean user ID."""

    email: str
    user_id: int


def as_email_user_payload(raw: object) -> EmailUserPayload | None:
    """Return email/user_id from a dict, or None for invalid field types/ID.

    IDs must be positive integers, excluding bool; email syntax is unchecked.
    Extra keys are discarded.
    """
    if not isinstance(raw, dict):
        return None
    email = raw.get("email")
    user_id = raw.get("user_id")
    if (
        not isinstance(email, str)
        or not isinstance(user_id, int)
        or isinstance(user_id, bool)
        or user_id <= 0
    ):
        return None
    return EmailUserPayload(email=email, user_id=user_id)


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a token, for storage in the database."""
    return hashlib.sha256(token.encode()).hexdigest()
