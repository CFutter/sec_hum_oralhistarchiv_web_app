"""Canonical, settings-independent catalogue and bookmark context fingerprints."""

import hashlib
import json
from collections.abc import Mapping

CURSOR_DOMAIN = b"oralhistarchiv-search-cursor-v2"


def cursor_context_digest(values: Mapping[str, object]) -> str:
    """Return a domain-separated SHA-256 hex digest of sorted compact ASCII JSON.

    Nonserializable or nonfinite values raise TypeError or ValueError.
    """
    encoded = json.dumps(
        dict(values), ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(CURSOR_DOMAIN + b"\x00context\x00" + encoded).hexdigest()
