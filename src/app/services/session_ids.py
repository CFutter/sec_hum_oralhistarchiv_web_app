"""Opaque session-identifier primitives shared across service boundaries."""

import hashlib


def hash_session_id(session_id: str) -> str:
    """Return the one-way database representation of a raw session ID."""
    return hashlib.sha256(session_id.encode()).hexdigest()
