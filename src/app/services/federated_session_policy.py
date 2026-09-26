"""Revoke federated sessions atomically when the policy fingerprint changes.

Fingerprint inputs are read from settings on each call. A locked singleton
row coordinates reconciliation and session issue across workers. Missing
state is a mismatch and triggers revocation on first reconciliation.
"""

import hashlib
import hmac
import json
import logging
from typing import Any

from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from config import settings

from .db import get_db_cursor

# Bump for a reviewed change to any session-authority rule that is not already
# represented by one of the explicit values in the fingerprint payload.
FEDERATED_SESSION_POLICY_VERSION = 1
REQUIRED_SHIBBOLETH_AUTHN_CONTEXT = "https://refeds.org/profile/mfa"
logger = logging.getLogger(__name__)


def federated_session_policy_fingerprint() -> str:
    """Hash enabled state, internal secret, trusted issuers, MFA context, and version."""
    internal_secret = settings.shibboleth_internal_secret
    payload = {
        "enabled": settings.shibboleth_enabled,
        # The credential is present only in this transient preimage. Neither
        # it nor a separately reusable component digest is stored or logged.
        "internal_secret": (
            internal_secret.get_secret_value() if internal_secret is not None else None
        ),
        "policy_version": FEDERATED_SESSION_POLICY_VERSION,
        "required_authn_context": REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        "trusted_issuers": sorted(settings.shibboleth_trusted_issuers),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


async def federation_policy_is_current_cur(cur: AsyncCursor[Any]) -> bool:
    """Compare the current fingerprint under a shared lock held by the caller.

    Return False for missing/non-string/non-ASCII/mismatched state. The lock
    serializes session issuance with reconciliation until the caller commits.
    """
    expected = federated_session_policy_fingerprint()
    await cur.execute("SELECT fingerprint FROM federation_policy_state WHERE id = 1 FOR SHARE")
    row = await cur.fetchone()
    if row is None:
        return False
    persisted = row.get("fingerprint")
    return (
        isinstance(persisted, str)
        and persisted.isascii()
        and hmac.compare_digest(persisted, expected)
    )


async def reconcile_federated_session_policy(pool: AsyncConnectionPool) -> int:
    """Commit the current fingerprint and revoke Shibboleth sessions on change.

    A singleton row lock serializes reconcilers and session issuers. Missing
    state counts as a change; local sessions remain. Return the number deleted.
    Database failures roll back both writes; missing/unwritable singleton state
    raises RuntimeError.
    """
    fingerprint = federated_session_policy_fingerprint()

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """INSERT INTO federation_policy_state (id, fingerprint)
               VALUES (1, '')
               ON CONFLICT (id) DO NOTHING"""
        )
        await cur.execute("SELECT fingerprint FROM federation_policy_state WHERE id = 1 FOR UPDATE")
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError("Federation policy state singleton is missing")
        if row["fingerprint"] == fingerprint:
            return 0

        await cur.execute(
            """DELETE FROM sessions
               USING users
               WHERE sessions.user_id = users.id
                 AND users.auth_method = 'shibboleth'"""
        )
        revoked = cur.rowcount
        await cur.execute(
            """UPDATE federation_policy_state
               SET fingerprint = %s, updated_at = clock_timestamp()
               WHERE id = 1""",
            (fingerprint,),
        )
        if cur.rowcount != 1:
            raise RuntimeError("Federation policy state singleton could not be updated")

    logger.info("Federated-session authority policy changed; revoked %d sessions", revoked)
    return revoked
