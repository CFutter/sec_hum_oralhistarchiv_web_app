"""Bounded reads for the writers-stopped TOTP key-rotation procedure."""

from collections.abc import AsyncIterator
from typing import Any

from psycopg_pool import AsyncConnectionPool

from .db import get_db_cursor

MAINTENANCE_STATEMENT_TIMEOUT = "60s"
DEFAULT_BATCH_SIZE = 500
_MAX_BATCH_SIZE = 5000


async def secret_pages(
    pool: AsyncConnectionPool,
    batch_size: int,
) -> AsyncIterator[list[dict[str, Any]]]:
    """Yield id/totp_secret/pending_totp_secret rows in ascending-ID pages.

    Only rows with ciphertext are included. Each page uses a separate
    transaction; stop writers for a consistent rotation. Raise ValueError unless
    batch_size is 1..5000. This helper does not set a statement timeout.
    """
    if not 1 <= batch_size <= _MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")
    after = 0
    while True:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """SELECT id, totp_secret, pending_totp_secret FROM users
                   WHERE id > %s AND (totp_secret IS NOT NULL OR pending_totp_secret IS NOT NULL)
                   ORDER BY id LIMIT %s""",
                (after, batch_size),
            )
            rows = await cur.fetchall()
        if not rows:
            return
        yield rows
        after = rows[-1]["id"]


async def rotation_secret_pages(
    pool: AsyncConnectionPool,
    batch_size: int,
) -> AsyncIterator[list[dict[str, Any]]]:
    """Yield user_id/encrypted_secret rotation rows in ascending-ID pages.

    Each page uses a separate transaction; stop writers for a consistent
    rotation. Raise ValueError unless batch_size is 1..5000. This helper does
    not set a statement timeout.
    """
    if not 1 <= batch_size <= _MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")
    after = 0
    while True:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """SELECT user_id, encrypted_secret
                   FROM pending_totp_rotations
                   WHERE user_id > %s
                   ORDER BY user_id
                   LIMIT %s""",
                (after, batch_size),
            )
            rows = await cur.fetchall()
        if not rows:
            return
        yield rows
        after = rows[-1]["user_id"]
