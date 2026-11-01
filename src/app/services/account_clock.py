"""Database wall time for persisted account deadlines.

Call after acquiring all relevant row locks: a time expression in the locking
SELECT can be evaluated before the lock wait finishes. TOTP algorithm time
and signed-token timestamps retain their separate cryptographic contracts.
"""

from datetime import datetime
from typing import Any

from psycopg import AsyncCursor


async def database_now_cur(cur: AsyncCursor[Any]) -> datetime:
    """Read timezone-aware database wall time, independent of transaction start.

    Raise RuntimeError for a missing row or TypeError for an invalid timestamp.
    """
    await cur.execute("SELECT clock_timestamp() AS database_now")
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Account clock query returned no row")
    now = row["database_now"]
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise TypeError("Account clock query returned an invalid database timestamp")
    return now
