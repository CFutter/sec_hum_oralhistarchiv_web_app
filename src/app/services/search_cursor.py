"""Authenticated opaque catalogue bookmarks, never an authorization capability."""

import base64
import json
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import settings

from .policy_digest import CURSOR_DOMAIN as _DOMAIN
from .policy_digest import cursor_context_digest

__all__ = [
    "NUMBERED_SEARCH_PAGES",
    "SEARCH_CURSOR_MAX_AGE_SECONDS",
    "SEARCH_CURSOR_MAX_LENGTH",
    "SearchCursor",
    "SearchCursorInvalid",
    "cursor_context_digest",
    "issue_search_cursor",
    "read_search_cursor",
]

NUMBERED_SEARCH_PAGES = 100
SEARCH_CURSOR_MAX_AGE_SECONDS = 3600
SEARCH_CURSOR_MAX_LENGTH = 2048
_MAX_ID = 2_147_483_647
_FORMAT_VERSION = 2
_TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_-]+={0,2}", re.ASCII)
_DIGEST_SHAPE = re.compile(r"[a-f0-9]{64}", re.ASCII)


class SearchCursorInvalid(ValueError):
    """The bounded bookmark is invalid, expired or belongs to another search."""


@dataclass(frozen=True, slots=True)
class SearchCursor:
    """One identity boundary and original scan time; no timestamp ordering key."""

    anchor_id: int
    ceiling_id: int
    page: int
    direction: Literal["next", "previous"]
    issued_at: int


@lru_cache(maxsize=1)
def _cipher_for_secret(secret: str) -> Fernet:
    """Retain at most one derived key; a changed secret evicts the previous key."""
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_DOMAIN).derive(
        secret.encode()
    )
    return Fernet(base64.urlsafe_b64encode(derived))


def _cipher() -> Fernet:
    """Use the current process secret, including explicit configuration rotation."""
    return _cipher_for_secret(settings.secret_key.get_secret_value())


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys rather than selecting an ambiguous value."""
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("Duplicate search bookmark field")
        values[key] = value
    return values


def _valid_state(state: SearchCursor, now: int) -> bool:
    """Check integer ID/page bounds, direction and issued-at age against now in Unix seconds."""
    return (
        type(state.anchor_id) is int
        and type(state.ceiling_id) is int
        and 1 <= state.anchor_id <= state.ceiling_id <= _MAX_ID
        and type(state.page) is int
        and NUMBERED_SEARCH_PAGES <= state.page <= _MAX_ID
        and state.direction in ("next", "previous")
        and (state.direction == "previous" or state.page > NUMBERED_SEARCH_PAGES)
        and type(state.issued_at) is int
        and 0 <= state.issued_at <= now
        and now - state.issued_at <= SEARCH_CURSOR_MAX_AGE_SECONDS
    )


def issue_search_cursor(state: SearchCursor, *, context: str) -> str:
    """Encrypt a bookmark with its original one-hour scan deadline.

    Require context to be a 64-character lowercase hexadecimal digest, otherwise
    raise ValueError. Invalid, expired or oversized state raises SearchCursorInvalid.
    """
    if not isinstance(state, SearchCursor) or not _valid_state(state, int(time.time())):
        raise SearchCursorInvalid("Search bookmark is no longer valid")
    if not isinstance(context, str) or _DIGEST_SHAPE.fullmatch(context) is None:
        raise ValueError("Invalid search context digest")
    payload = {
        "v": _FORMAT_VERSION,
        "a": state.anchor_id,
        "h": state.ceiling_id,
        "p": state.page,
        "d": state.direction,
        "i": state.issued_at,
        "c": context,
    }
    encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("ascii")
    token = _cipher().encrypt_at_time(encoded, current_time=state.issued_at).decode("ascii")
    if len(token) > SEARCH_CURSOR_MAX_LENGTH:
        raise SearchCursorInvalid("Search bookmark is no longer valid")
    return token


def read_search_cursor(token: str, *, context: str) -> SearchCursor:
    """Authenticate shape, purpose, exact types, binding and the original deadline.

    Invalid values raise one fixed error without logging or echoing token data.
    The caller must still check current catalogue eligibility and permissions.
    """
    invalid = SearchCursorInvalid("Search bookmark is no longer valid")
    if (
        not isinstance(token, str)
        or not 1 <= len(token) <= SEARCH_CURSOR_MAX_LENGTH
        or _TOKEN_SHAPE.fullmatch(token) is None
        or not isinstance(context, str)
        or _DIGEST_SHAPE.fullmatch(context) is None
    ):
        raise invalid
    try:
        encoded = token.encode("ascii")
        if base64.urlsafe_b64encode(base64.urlsafe_b64decode(encoded)) != encoded:
            raise invalid
        now = int(time.time())
        cipher = _cipher()
        raw = cipher.decrypt_at_time(encoded, ttl=SEARCH_CURSOR_MAX_AGE_SECONDS, current_time=now)
        payload = json.loads(raw, object_pairs_hook=_unique_object)
        if (
            type(payload) is not dict
            or set(payload) != {"v", "a", "h", "p", "d", "i", "c"}
            or type(payload["v"]) is not int
            or payload["v"] != _FORMAT_VERSION
            or payload["c"] != context
            or type(payload["d"]) is not str
            or payload["d"] not in ("next", "previous")
        ):
            raise invalid
        state = SearchCursor(
            anchor_id=payload["a"],
            ceiling_id=payload["h"],
            page=payload["p"],
            direction="next" if payload["d"] == "next" else "previous",
            issued_at=payload["i"],
        )
        if not _valid_state(state, now) or cipher.extract_timestamp(encoded) != state.issued_at:
            raise invalid
        return state
    except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError) as error:
        raise invalid from error
