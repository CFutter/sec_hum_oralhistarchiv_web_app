"""Queue credential-free owner notifications in the caller's security transaction."""

from typing import Any

from psycopg import AsyncCursor

from .email import build_security_change_notice
from .email_outbox import enqueue_outbound_email_cur


async def queue_security_change_notice_cur(
    cur: AsyncCursor[Any], *, user_id: int, change: str
) -> None:
    """Queue one notice for an actual transition while its account lock is held.

    Call only after a successful state change, in the same transaction. Rejected
    or repeated transitions must not call this helper. Outbox errors propagate
    so the state change and notice roll back together.
    """
    await cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Security notification account disappeared")
    await enqueue_outbound_email_cur(
        cur,
        user_id=user_id,
        email=build_security_change_notice(row["email"], change=change),
        action=None,
    )
