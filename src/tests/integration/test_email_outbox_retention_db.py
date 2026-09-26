"""Integration tests for email outbox retention, maintenance, and metrics
against PostgreSQL.

These tests pin the PostgreSQL-dependent behavior that mocks cannot verify:
retention batching and bounding per terminal status, concurrent-worker
locking (``FOR UPDATE SKIP LOCKED``), rollback on partial failure, the exact
retention boundary, and the bounded live-queue metrics, implemented in
``app.services.outbox_maintenance``. Lease, delivery, and development
mailbox coverage for ``app.services.email_outbox`` and
``app.services.email_delivery`` lives in ``test_email_outbox_db.py``.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

import app.services.outbox_maintenance as maintenance
from app.services.db import get_db_cursor
from app.services.outbox_maintenance import get_outbox_metrics_cur, purge_terminal_emails
from config import settings


def _insert(sync_conn, status, age_days):
    timestamp = datetime.now(UTC) - timedelta(days=age_days)
    row = sync_conn.execute(
        """
        INSERT INTO email_outbox (
            message_type, recipient, subject, body_ciphertext, status,
            created_at, sent_at, failed_at, locked_at, lock_token, terminal_outcome
        ) VALUES ('account_locked_notice', 'person@example.org', 'Notice', 'ciphertext',
                  %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            status,
            datetime.now(UTC) - timedelta(days=100),
            timestamp if status == "sent" else None,
            timestamp if status == "dead" else None,
            timestamp if status == "sending" else None,
            uuid4() if status == "sending" else None,
            "cancelled" if status == "dead" else None,
        ),
    ).fetchone()
    sync_conn.commit()
    return row[0]


def _remaining(sync_conn):
    return {row[0] for row in sync_conn.execute("SELECT id FROM email_outbox").fetchall()}


class TestRetention:
    """Retention boundaries, batching, locking, rollback, and metrics."""

    async def test_retention_uses_terminal_timestamp_and_keeps_active_rows(
        self, db_pool, sync_conn, monkeypatch
    ):
        monkeypatch.setattr(settings, "outbox_sent_retention_days", 7)
        monkeypatch.setattr(settings, "outbox_dead_retention_days", 30)
        expired_sent = _insert(sync_conn, "sent", 8)
        expired_dead = _insert(sync_conn, "dead", 31)
        kept = {
            _insert(sync_conn, "sent", 6),
            _insert(sync_conn, "dead", 29),
            _insert(sync_conn, "pending", 100),
            _insert(sync_conn, "sending", 100),
        }
        assert await purge_terminal_emails(db_pool) == 2
        assert _remaining(sync_conn) == kept
        assert expired_sent not in kept and expired_dead not in kept

    async def test_retention_is_bounded_per_status(self, db_pool, sync_conn, monkeypatch):
        monkeypatch.setattr(settings, "outbox_retention_batch_size", 2)
        for state in ("sent", "dead"):
            for _ in range(5):
                _insert(sync_conn, state, 100)
        assert await purge_terminal_emails(db_pool) == 4
        assert len(_remaining(sync_conn)) == 6
        assert await purge_terminal_emails(db_pool) == 4
        assert await purge_terminal_emails(db_pool) == 2
        assert await purge_terminal_emails(db_pool) == 0

    async def test_concurrent_retention_workers_do_not_double_count(
        self, db_pool, sync_conn, monkeypatch
    ):
        monkeypatch.setattr(settings, "outbox_retention_batch_size", 100)
        for state in ("sent", "dead"):
            for _ in range(4):
                _insert(sync_conn, state, 100)
        deleted = await asyncio.wait_for(
            asyncio.gather(
                purge_terminal_emails(db_pool),
                purge_terminal_emails(db_pool),
            ),
            timeout=5,
        )
        assert sum(deleted) == 8
        assert _remaining(sync_conn) == set()

    async def test_retention_skips_a_locked_row_without_waiting(self, db_pool, sync_conn):
        locked = _insert(sync_conn, "sent", 100)
        unlocked = _insert(sync_conn, "sent", 99)
        with sync_conn.transaction():
            sync_conn.execute("SELECT id FROM email_outbox WHERE id = %s FOR UPDATE", (locked,))
            assert await asyncio.wait_for(purge_terminal_emails(db_pool), timeout=2) == 1
        assert _remaining(sync_conn) == {locked}
        assert unlocked not in _remaining(sync_conn)

    async def test_failure_in_second_delete_rolls_back_first_delete(
        self, db_pool, sync_conn, monkeypatch
    ):
        sent = _insert(sync_conn, "sent", 100)
        dead = _insert(sync_conn, "dead", 100)
        real_purge = maintenance._purge_terminal_cur

        async def fail_dead(cur, *, status, retention, limit):
            if status == "dead":
                await cur.execute("SELECT 1 / 0")
            return await real_purge(cur, status=status, retention=retention, limit=limit)

        monkeypatch.setattr(maintenance, "_purge_terminal_cur", fail_dead)
        with pytest.raises(psycopg.errors.DivisionByZero):
            await purge_terminal_emails(db_pool)
        assert _remaining(sync_conn) == {sent, dead}

    async def test_metrics_report_real_queue_counts_and_overdue_retention(self, db_pool, sync_conn):
        _insert(sync_conn, "pending", 0)
        _insert(sync_conn, "sending", 1)
        _insert(sync_conn, "dead", 100)
        _insert(sync_conn, "sent", 100)
        async with get_db_cursor(db_pool) as cur:
            metrics = await get_outbox_metrics_cur(cur)
        assert metrics["pending_count"] == 1
        assert metrics["sending_count"] == 1
        assert metrics["dead_count"] == 1
        assert metrics["retention_overdue_count"] == 2
        assert metrics["oldest_pending_age_seconds"] >= 99 * 86400
        assert metrics["oldest_sending_age_seconds"] >= 86400

    async def test_metrics_counts_are_explicitly_capped(self, db_pool, sync_conn):
        """Live queue counts stop at a fixed cap instead of a full COUNT(*)
        scan over an unbounded pending queue: pending_count and
        counts_capped_at both report the cap, while the oldest-pending age
        is still populated past it."""
        sync_conn.execute(
            "INSERT INTO email_outbox (message_type, recipient, subject, body_ciphertext) "
            "SELECT 'account_locked_notice', 'user@uzh.ch', 'Notice', 'unused' "
            "FROM generate_series(1, 1005)"
        )
        sync_conn.commit()
        async with get_db_cursor(db_pool) as cur:
            metrics = await get_outbox_metrics_cur(cur)
        assert metrics["pending_count"] == metrics["counts_capped_at"] == 1000
        assert metrics["oldest_pending_age_seconds"] is not None

    async def test_exact_retention_boundary_is_preserved(self, db_pool):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """
                INSERT INTO email_outbox (
                    message_type, recipient, subject, body_ciphertext, status, sent_at
                ) VALUES
                    ('account_locked_notice', 'a@example.org', 'Notice', 'ciphertext',
                     'sent', CURRENT_TIMESTAMP - INTERVAL '7 days'),
                    ('account_locked_notice', 'b@example.org', 'Notice', 'ciphertext',
                     'sent', CURRENT_TIMESTAMP - INTERVAL '7 days 1 second')
                """
            )
            deleted = await maintenance._purge_terminal_cur(
                cur,
                status="sent",
                retention=timedelta(days=7),
                limit=10,
            )
            assert deleted == 1
            await cur.execute("SELECT recipient FROM email_outbox")
            assert [row["recipient"] for row in await cur.fetchall()] == ["a@example.org"]
