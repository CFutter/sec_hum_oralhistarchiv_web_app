"""Bound anonymous mail with short-lived, noncascading issuance history.

Every admitted producer holds the same transaction lock through enqueue and
ledger insertion. Only actual queued messages create a recipient digest. User,
outbox and federation-reservation deletion cannot refund a mail allowance.
"""

import hashlib
import hmac
from typing import Any
from uuid import uuid4

from psycopg import AsyncCursor

from config import settings

ANONYMOUS_MAIL_RECIPIENT_COOLDOWN_SECONDS = 300
ANONYMOUS_MAIL_RECIPIENT_HOURLY_LIMIT = 5
ANONYMOUS_MAIL_GLOBAL_HOURLY_LIMIT = 500
ANONYMOUS_MAIL_GLOBAL_DAILY_LIMIT = 2_000
_ISSUANCE_CLEANUP_BATCH = 100
_ISSUANCE_LOCK_KEY = 0x4D41494C495353
_RECIPIENT_KEY = hmac.digest(
    settings.secret_key.get_secret_value().encode(),
    b"oralhistarchiv-anonymous-mail-recipient-v1",
    hashlib.sha256,
)


def _recipient_key(recipient: str) -> str:
    """Return a domain-separated keyed identifier for a normalized address."""
    return hmac.digest(_RECIPIENT_KEY, recipient.strip().lower().encode(), hashlib.sha256).hex()


async def anonymous_mail_issuance_allowed_cur(cur: AsyncCursor[Any], recipient: str) -> bool:
    """Hold issuance admission, purge bounded expired history and check mail budgets.

    The caller owns the transaction. Queue an admitted message and record it
    before committing; otherwise no allowance is spent. History has no account
    or outbox foreign key and survives cancellation/deletion for one day.
    Database errors propagate; no process-local or permissive fallback exists.
    """
    await cur.execute("SET LOCAL lock_timeout = '250ms'")
    await cur.execute("SELECT pg_try_advisory_xact_lock(%s) AS admitted", (_ISSUANCE_LOCK_KEY,))
    admission = await cur.fetchone()
    if admission is None:
        raise RuntimeError("Anonymous mail lock query returned no row")
    if not admission["admitted"]:
        return False
    await cur.execute(
        """WITH expired AS (
               SELECT id FROM anonymous_mail_issuance
               WHERE created_at <= clock_timestamp() - INTERVAL '1 day'
               ORDER BY created_at, id LIMIT %s
          )
          DELETE FROM anonymous_mail_issuance AS issuance
          USING expired WHERE issuance.id = expired.id""",
        (_ISSUANCE_CLEANUP_BATCH,),
    )
    await cur.execute(
        """SELECT
               count(*) AS global_day,
               count(*) FILTER (WHERE created_at > clock_timestamp() - INTERVAL '1 hour')
                   AS global_hour,
               count(*) FILTER (WHERE recipient_key = %(recipient)s
                    AND created_at > clock_timestamp() - INTERVAL '1 hour') AS recipient_hour,
               count(*) FILTER (WHERE recipient_key = %(recipient)s
                    AND created_at > clock_timestamp()
                        - %(cooldown)s * INTERVAL '1 second') AS recipient_recent
           FROM anonymous_mail_issuance
           WHERE created_at > clock_timestamp() - INTERVAL '1 day'""",
        {
            "recipient": _recipient_key(recipient),
            "cooldown": ANONYMOUS_MAIL_RECIPIENT_COOLDOWN_SECONDS,
        },
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Anonymous mail admission query returned no row")
    return bool(
        row["global_day"] < ANONYMOUS_MAIL_GLOBAL_DAILY_LIMIT
        and row["global_hour"] < ANONYMOUS_MAIL_GLOBAL_HOURLY_LIMIT
        and row["recipient_hour"] < ANONYMOUS_MAIL_RECIPIENT_HOURLY_LIMIT
        and row["recipient_recent"] == 0
    )


async def record_mail_issuance_cur(cur: AsyncCursor[Any], recipient: str) -> None:
    """Append actual anonymous enqueue in its admission transaction, without a foreign key."""
    await cur.execute(
        "INSERT INTO anonymous_mail_issuance (id, recipient_key) VALUES (%s, %s)",
        (uuid4(), _recipient_key(recipient)),
    )
