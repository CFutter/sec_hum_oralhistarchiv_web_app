"""Bounded terminal-message retention and aggregate outbox diagnostics."""

import logging
from datetime import timedelta
from typing import Any, Literal, TypedDict

from psycopg import AsyncCursor, sql
from psycopg_pool import AsyncConnectionPool

from config import settings

from .db import get_db_cursor

logger = logging.getLogger(__name__)
_RETENTION_SCHEDULING_GRACE = timedelta(hours=2)
_FAILURE_HEALTH_WINDOW = timedelta(hours=24)


_HEALTH_COUNT_LIMIT = 1000


class OutboxMetrics(TypedDict):
    """Queue counts capped at counts_capped_at and nonnegative oldest ages; empty ages are None."""

    counts_capped_at: int
    pending_count: int
    sending_count: int
    dead_count: int
    recent_failure_count: int
    oldest_pending_age_seconds: float | None
    oldest_sending_age_seconds: float | None
    retention_overdue_count: int


async def _purge_terminal_cur(
    cur: AsyncCursor[Any],
    *,
    status: Literal["sent", "dead"],
    retention: timedelta,
    limit: int,
) -> int:
    """Delete up to limit expired terminal rows, skipping locks, and return their count.

    Use the caller's transaction; sent uses sent_at and dead uses failed_at.
    Callers supply a nonnegative limit and retention. Missing count rows
    raise RuntimeError; database errors propagate.
    """
    timestamp = "sent_at" if status == "sent" else "failed_at"
    await cur.execute(
        sql.SQL("""
            WITH candidates AS (
                SELECT id
                FROM email_outbox
                WHERE status = {status}
                  AND {timestamp} < CURRENT_TIMESTAMP - %s
                ORDER BY {timestamp}, id
                FOR UPDATE SKIP LOCKED
                LIMIT %s
            ), deleted AS (
                DELETE FROM email_outbox AS outbox
                USING candidates
                WHERE outbox.id = candidates.id
                RETURNING outbox.id
            )
            SELECT COUNT(*) AS deleted_count FROM deleted
        """).format(status=sql.Literal(status), timestamp=sql.Identifier(timestamp)),
        (retention, limit),
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Outbox retention returned no count")
    return int(row["deleted_count"])


async def purge_terminal_emails(pool: AsyncConnectionPool) -> int:
    """Delete and count one batch each of expired sent and dead rows atomically.

    Use OUTBOX_SENT_RETENTION_DAYS, OUTBOX_DEAD_RETENTION_DAYS, and
    OUTBOX_RETENTION_BATCH_SIZE; skip locked rows and log deletion counts.
    """
    async with get_db_cursor(pool) as cur:
        sent = await _purge_terminal_cur(
            cur,
            status="sent",
            retention=timedelta(days=settings.outbox_sent_retention_days),
            limit=settings.outbox_retention_batch_size,
        )
        dead = await _purge_terminal_cur(
            cur,
            status="dead",
            retention=timedelta(days=settings.outbox_dead_retention_days),
            limit=settings.outbox_retention_batch_size,
        )
    logger.info(
        "Outbox retention deleted %d sent and %d dead messages",
        sent,
        dead,
        extra={"event_type": "outbox_retention", "sent_deleted": sent, "dead_deleted": dead},
    )
    return sent + dead


async def get_outbox_metrics_cur(cur: AsyncCursor[Any]) -> OutboxMetrics:
    """Read capped queue counts and oldest ages in the caller's transaction.

    Counts cap at 1,000; equality means at least that many rows. Recent
    failures cover 24 hours and exclude cancellation. Retention uses the
    configured sent/dead days plus two hours' grace. Empty ages are None.
    Raise RuntimeError if no aggregate row arrives.
    """
    await cur.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
             WHERE status = 'pending' LIMIT %(limit)s) p) AS pending_count,
            (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
             WHERE status = 'sending' LIMIT %(limit)s) s) AS sending_count,
            (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
             WHERE status = 'dead' LIMIT %(limit)s) d) AS dead_count,
            (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
             WHERE status = 'dead'
               AND terminal_outcome IN ('delivery_failed', 'body_unreadable')
               AND failed_at >= CURRENT_TIMESTAMP - %(failure_window)s
             LIMIT %(limit)s) f) AS recent_failure_count,
            EXTRACT(EPOCH FROM CURRENT_TIMESTAMP -
                (SELECT created_at FROM email_outbox WHERE status = 'pending'
                 ORDER BY created_at, id LIMIT 1)) AS pending_age,
            EXTRACT(EPOCH FROM CURRENT_TIMESTAMP -
                (SELECT locked_at FROM email_outbox WHERE status = 'sending'
                 ORDER BY locked_at, id LIMIT 1)) AS sending_age,
            LEAST(%(limit)s,
                (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
                 WHERE status = 'sent' AND sent_at < CURRENT_TIMESTAMP - %(sent_retention)s
                 LIMIT %(limit)s) s) +
                (SELECT COUNT(*) FROM (SELECT 1 FROM email_outbox
                 WHERE status = 'dead' AND failed_at < CURRENT_TIMESTAMP - %(dead_retention)s
                 LIMIT %(limit)s) d)) AS retention_overdue_count
        """,
        {
            "limit": _HEALTH_COUNT_LIMIT,
            "failure_window": _FAILURE_HEALTH_WINDOW,
            "sent_retention": timedelta(days=settings.outbox_sent_retention_days)
            + _RETENTION_SCHEDULING_GRACE,
            "dead_retention": timedelta(days=settings.outbox_dead_retention_days)
            + _RETENTION_SCHEDULING_GRACE,
        },
    )
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError("Outbox metrics returned no aggregate row")
    return OutboxMetrics(
        counts_capped_at=_HEALTH_COUNT_LIMIT,
        pending_count=int(row["pending_count"]),
        sending_count=int(row["sending_count"]),
        dead_count=int(row["dead_count"]),
        recent_failure_count=int(row["recent_failure_count"]),
        oldest_pending_age_seconds=(
            max(0.0, float(row["pending_age"])) if row["pending_age"] is not None else None
        ),
        oldest_sending_age_seconds=(
            max(0.0, float(row["sending_age"])) if row["sending_age"] is not None else None
        ),
        retention_overdue_count=int(row["retention_overdue_count"]),
    )


def outbox_is_degraded(metrics: OutboxMetrics) -> bool:
    """Flag overdue retention, a failure in 24 hours,
    or an age at least OUTBOX_STALE_AFTER_SECONDS.
    """
    return (
        metrics["retention_overdue_count"] > 0
        or metrics["recent_failure_count"] > 0
        or (metrics["oldest_pending_age_seconds"] or 0) >= settings.outbox_stale_after_seconds
        or (metrics["oldest_sending_age_seconds"] or 0) >= settings.outbox_stale_after_seconds
    )
