"""Email-change tokens — signed, time-limited, single-use.

Mirrors email_verification.py, but stages a *change* to a new address
rather than verifying the existing one. The verification link is sent to
the NEW address — clicking it proves the user controls that address before
the change commits.

Flow:
1. User submits new email + current password on /account/change-email.
   The route re-authenticates, validates the address, then calls
   store_pending_email() and sends the link (to the NEW address).
2. User clicks the link → validate_email_change_token() checks signature
   and expiry → confirm_email_change() atomically verifies the stored
   hash, confirms the token's email matches the stored pending_email,
   re-checks uniqueness, commits the change, and clears the pending columns.

Security (four-layer confirm check):
- Signature:  token is HMAC-signed with SECRET_KEY (cannot be forged)
- Expiry:     itsdangerous max_age + a DB-level created_at check
- Hash:       SHA-256 hash stored on the row enforces single-use
- Email bind: the token's embedded email must equal the stored
              pending_email, so a stale token from a previous request
              cannot commit a different address

Re-authentication (enforced in the route, not here): the request step
requires the current password, so a hijacked session cannot silently
relocate the account — email is the account-recovery vector.

Only one outstanding change per user: store_pending_email() overwrites
any previous pending change, invalidating an earlier link.
"""
import logging

from email_validator import validate_email, EmailNotValidError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from psycopg_pool import AsyncConnectionPool

from config import settings
from .db import get_db_cursor

logger = logging.getLogger(__name__)

_SALT = "email-change"
EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS = 3600  # 1 hour


def normalize_email(raw: str) -> str | None:
    """Validate and normalize an email address (syntax only, no DNS).

    Returns the normalized address on success, or None if the address
    is syntactically invalid. check_deliverability=False keeps this
    fast and offline-safe — we prove deliverability by sending the
    confirmation link, not by DNS lookup here.
    """
    try:
        result = validate_email(raw, check_deliverability=False)
        return result.normalized.lower()
    except EmailNotValidError:
        return None


def generate_email_change_token(
    user_id: int, new_email: str, acting_admin_id: int | None = None
) -> str:
    """Generate a signed token binding a user to a requested new email.

    acting_admin_id is set when an admin initiated the change on behalf of
    the user; None for self-service changes. It's carried through to the
    confirm step so the audit trail records who initiated the change. When
    None, the key is omitted from the payload entirely, so self-service
    tokens are unchanged from before this parameter existed.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    payload = {"user_id": user_id, "new_email": new_email}
    if acting_admin_id is not None:
        payload["acting_admin_id"] = acting_admin_id
    return signer.dumps(payload, salt=_SALT)


def validate_email_change_token(token: str) -> dict | None:
    """Validate a token's signature and expiry.

    Checks only that the token is well-formed, correctly signed, and not
    expired. The caller must also call confirm_email_change() to enforce
    single-use and the email binding against the stored pending state.

    Returns a dict with "user_id" and "new_email", or None if invalid.
    """
    signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    try:
        return signer.loads(
            token, salt=_SALT, max_age=EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS
        )
    except (BadSignature, SignatureExpired) as e:
        logger.warning("Invalid or expired email-change token: %s", e)
        return None


async def store_pending_email(
    pool: AsyncConnectionPool, user_id: int, new_email: str, token_hash: str
) -> None:
    """Stage a pending email change on the user record.

    Overwrites any previous pending change — only one outstanding request
    per user. Raises ValueError if the user doesn't exist.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET pending_email = %s,
                   pending_email_token_hash = %s,
                   pending_email_created_at = CURRENT_TIMESTAMP
               WHERE id = %s
               RETURNING id""",
            (new_email, token_hash, user_id),
        )
        if not await cur.fetchone():
            raise ValueError(f"User {user_id} not found")


async def confirm_email_change(
    pool: AsyncConnectionPool, user_id: int, new_email: str, token_hash: str
) -> bool:
    """Atomically commit a staged email change.

    All conditions are enforced in a single UPDATE...WHERE so there is no
    check-then-act race:
    - the stored token hash matches (single-use)
    - the stored pending_email matches the token's email (binding)
    - the pending change hasn't expired (DB-level defense-in-depth)
    - the new email isn't already taken by another account (re-checked
      here because someone could have registered it between request and
      confirm)

    On success: email is set to pending_email, email_verified is left unchanged 
    (already true for any account that reached this flow), and all pending_*
    columns are cleared. Returns True on success, False if any condition
    fails.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
               SET email = pending_email,
                   pending_email = NULL,
                   pending_email_token_hash = NULL,
                   pending_email_created_at = NULL
               WHERE id = %s
                 AND pending_email_token_hash = %s
                 AND pending_email = %s
                 AND pending_email_created_at
                       > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'
                 AND NOT EXISTS (
                     SELECT 1 FROM users u2
                     WHERE LOWER(u2.email) = LOWER(%s)
                       AND u2.id != %s
                 )
               RETURNING id""",
            (
                user_id,
                token_hash,
                new_email,
                EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS,
                new_email,
                user_id,
            ),
        )
        return await cur.fetchone() is not None
    
async def pending_email_change_matches(
    pool: AsyncConnectionPool, user_id: int, new_email: str
) -> bool:
    """Read-only: is there an unexpired pending change to new_email for this user?

    Used by the confirm *page* (GET) to decide whether to show the confirm
    button — WITHOUT consuming the token. The actual single-use enforcement
    stays in confirm_email_change() (the POST). Mirrors that function's
    pending/expiry predicate but does not mutate.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT 1 FROM users
               WHERE id = %s
                 AND pending_email = %s
                 AND pending_email_token_hash IS NOT NULL
                 AND pending_email_created_at
                       > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'""",
            (user_id, new_email, EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS),
        )
        return await cur.fetchone() is not None