"""TOTP enrollment and verification helpers.

Stored TOTP secrets are encrypted at rest (services.crypto). Enrollment
uses a two-step pending model: the server generates a secret, stores it
encrypted in pending_totp_secret with a short TTL, then promotes it to
totp_secret only after the user proves they can read codes from it.
This avoids trusting a client-submitted hidden form field across the
QR-scan → verify hop.

Pending secrets expire after _PENDING_TOTP_MAX_AGE_SECONDS (10 minutes).
Promotion clears the pending columns in the same UPDATE. Routes that
only need to know whether TOTP is configured can read the `totp_configured`
boolean from the User dataclass (computed at the SQL layer); only routes
that verify codes call get_totp_secret().
"""

from .crypto import encrypt_value, decrypt_value
from .db import get_db_cursor
import logging
import time
import pyotp
from psycopg_pool import AsyncConnectionPool
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class TotpDecryptionError(Exception):
    """A user's stored TOTP secret exists but cannot be decrypted.

    Signals key mismatch, ciphertext corruption, or an incomplete key
    rotation — explicitly NOT "no TOTP configured". Lets callers fail
    closed instead of treating an undecryptable secret as "no second factor".
    """
    def __init__(self, user_id: int | None = None):
        self.user_id = user_id
        super().__init__(
            f"TOTP secret for user {user_id} is present but undecryptable "
            "(key mismatch, corruption, or incomplete key rotation)."
        )


def matched_step(secret: str, code: str, valid_window: int = 1, period: int = 30) -> int | None:
    """Return the time-step this code matches against secret, or None."""
    totp = pyotp.TOTP(secret)
    current_step = int(time.time()) // period
    for offset in range(-valid_window, valid_window + 1):
        step = current_step + offset
        if totp.verify(code, for_time=datetime.fromtimestamp(step * period, tz=timezone.utc), valid_window=0):
            return step
    return None


async def get_totp_secret(pool: AsyncConnectionPool, user_id: int) -> str | None:
    """Returns the plaintext TOTP secret, or None if the user doesn't 
    exist or has no TOTP configured. Raises TotpDecryptionError if the 
    secret exists but cannot be decrypted (key mismatch / corruption / incomplete rotation).
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

async def verify_and_consume_totp(
    pool: AsyncConnectionPool, 
    user_id: int, 
    secret: str, 
    code: str,
    valid_window: int = 1, 
    period: int = 30
) -> bool:
    """Verify a TOTP code and atomically consume its time-step so it can't
    be replayed. Returns True exactly once per valid code."""
    step = matched_step(secret, code, valid_window, period)
    if step is None:
        return False

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
                  SET last_totp_step = %s
                WHERE id = %s
                  AND (last_totp_step IS NULL OR last_totp_step < %s)""",
            (step, user_id, step),
        )
        return cur.rowcount == 1



async def update_totp_secret(
    pool: AsyncConnectionPool,
    user_id: int, 
    new_secret: str, 
    consumed_step: int | None
) -> None:
    """Set the user's TOTP secret and reset replay state to match it.

    consumed_step: the step of the code the user just verified against
    new_secret, so it can't be replayed as a login. Pass None only when
    there is genuinely no just-verified code to consume (e.g. an admin
    or recovery reset that clears TOTP).
    """
    encrypted = encrypt_value(new_secret)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users
                  SET totp_secret = %s,
                      last_totp_step = %s,        -- reset to the new secret's space
                      pending_totp_secret = NULL,
                      pending_totp_created_at = NULL
                WHERE id = %s""",
            (encrypted, consumed_step, user_id),
        )
    logger.info("TOTP secret updated for user %d", user_id)


async def store_pending_totp_secret(pool: AsyncConnectionPool, user_id: int, secret: str) -> None:
    """Encrypt and store a pending TOTP secret for secure enrollment.
 
    The secret is generated server-side, encrypted, and stored in the
    database so that the POST handler can retrieve it by user ID rather
    than trusting a client-submitted hidden form field. Overwrites any
    previous pending secret for this user.
 
    Args:
        pool: Database connection pool.
        user_id: The user enrolling a new authenticator.
        secret: The base32-encoded TOTP secret to store temporarily (plaintext).
    """
    encrypted = encrypt_value(secret)
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """UPDATE users 
               SET pending_totp_secret = %s,
                   pending_totp_created_at = CURRENT_TIMESTAMP
               WHERE id = %s""",
            (encrypted, user_id),
        )

_PENDING_TOTP_MAX_AGE_SECONDS = 600  # 10 minutes

async def get_pending_totp_secret(pool: AsyncConnectionPool, user_id: int) -> str | None:
    """Retrieve and decrypt the pending TOTP secret if it exists and is not expired.
 
    Returns the plaintext secret, or None if no pending secret exists,
    the user doesn't exist, the secret is expired, or decryption fails.
    """
    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """SELECT pending_totp_secret FROM users
               WHERE id = %s
                 AND pending_totp_secret IS NOT NULL
                 AND pending_totp_created_at > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'""",
            (user_id, _PENDING_TOTP_MAX_AGE_SECONDS),
        )
        row = await cur.fetchone()
        if not row or not row.get("pending_totp_secret"):
            return None
        return decrypt_value(row["pending_totp_secret"])

def generate_totp_secret() -> str:
    """Generate a new random TOTP secret for user enrollment."""
    return pyotp.random_base32()