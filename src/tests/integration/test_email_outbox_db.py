"""Integration tests for transactional email outbox leases and delivery
against PostgreSQL.

These tests pin the PostgreSQL-dependent behavior that mocks cannot verify:
transactional enqueue, encrypted storage, competing-worker claims, abandoned
lease recovery, lease-token ownership, lease renewal, retries, terminal
failure, delivery outcomes, row-contention deferral, and the development
mailbox end-to-end delivery path, implemented in
``app.services.email_outbox`` and ``app.services.email_delivery``. Retention,
maintenance and metrics coverage for ``app.services.outbox_maintenance``
lives in ``test_email_outbox_retention_db.py``.
"""

import asyncio
import re
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from typing import Any
from unittest.mock import create_autospec, patch

import pytest

from app.services import email_change
from app.services.db import get_db_cursor
from app.services.email import DeliveryResult
from app.services.email_delivery import deliver_email_outbox_batch, send_claimed_email
from app.services.email_outbox import (
    OutboundEmail,
    OutboxBodyDecryptionError,
    OutboxLeaseLostError,
    claim_due_emails,
    decrypt_claimed_email_body,
    enqueue_email_cur,
    enqueue_outbound_email_cur,
    mark_email_dead,
    mark_email_sent,
    prepare_email_delivery,
    retry_email_later,
)
from app.services.registration import queue_verification_email_cur
from app.services.users import get_user_by_id

_BODY = """Use this one-time link:

https://example.test/reset/secret-token
"""
_LEASE_TIMEOUT = timedelta(minutes=5)

_STATE_COLUMNS = (
    "status",
    "attempt_count",
    "next_attempt_at",
    "locked_at",
    "lock_token",
    "last_error",
    "sent_at",
    "failed_at",
)


async def _enqueue(db_pool, *, body: str = _BODY) -> int:
    async with get_db_cursor(db_pool) as cur:
        return await enqueue_email_cur(
            cur,
            user_id=None,
            message_type="account_locked_notice",
            recipient="alice@example.test",
            subject="Test notice",
            body=body,
            action=None,
        )


async def _enqueue_worker_test_email(db_pool) -> int:
    email = OutboundEmail(
        message_type="account_locked_notice",
        recipient="worker-test@example.org",
        subject="Worker integration test",
        body="Secret reset link body",
    )

    async with get_db_cursor(db_pool) as cur:
        return await enqueue_outbound_email_cur(
            cur,
            user_id=None,
            email=email,
            action=None,
        )


def _fetch_outbox_state(sync_conn, message_id: int) -> dict[str, Any]:
    row = sync_conn.execute(
        f"""
        SELECT {", ".join(_STATE_COLUMNS)}
        FROM email_outbox
        WHERE id = %s
        """,
        (message_id,),
    ).fetchone()
    assert row is not None
    return dict(zip(_STATE_COLUMNS, row, strict=True))


class _DeliberateRollback(Exception):
    """Test-only exception used to force transaction rollback."""


class TestLeases:
    """Claiming, ownership, renewal, and retry of leased outbox rows."""

    async def test_enqueue_stores_encrypted_body_and_claim_decrypts_it(
        self,
        db_pool,
        sync_conn,
    ):
        message_id = await _enqueue(db_pool)

        stored = sync_conn.execute(
            """
            SELECT status, attempt_count, body_ciphertext
            FROM email_outbox
            WHERE id = %s
            """,
            (message_id,),
        ).fetchone()

        assert stored is not None
        assert stored[0] == "pending"
        assert stored[1] == 0
        assert stored[2] != _BODY
        assert "secret-token" not in stored[2]

        claimed = await claim_due_emails(
            db_pool,
            limit=10,
            lease_timeout=_LEASE_TIMEOUT,
        )

        assert len(claimed) == 1
        assert claimed[0].id == message_id
        assert claimed[0].attempt_count == 1
        assert decrypt_claimed_email_body(claimed[0]) == _BODY

    async def test_enqueue_participates_in_callers_transaction(
        self,
        db_pool,
        sync_conn,
    ):
        with pytest.raises(_DeliberateRollback):
            async with get_db_cursor(db_pool) as cur:
                await enqueue_email_cur(
                    cur,
                    user_id=None,
                    message_type="account_locked_notice",
                    recipient="alice@example.test",
                    subject="Account locked",
                    body=_BODY,
                    action=None,
                )
                raise _DeliberateRollback

        count = sync_conn.execute("SELECT COUNT(*) FROM email_outbox").fetchone()

        assert count == (0,)

    async def test_competing_workers_cannot_claim_same_message(
        self,
        db_pool,
    ):
        message_id = await _enqueue(db_pool)

        first, second = await asyncio.gather(
            claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            ),
            claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            ),
        )

        claimed = first + second

        assert len(claimed) == 1
        assert claimed[0].id == message_id
        assert sorted((len(first), len(second))) == [0, 1]

    async def test_expired_lease_is_reclaimed_and_old_owner_is_rejected(
        self,
        db_pool,
        sync_conn,
    ):
        message_id = await _enqueue(db_pool)

        original = (
            await claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            )
        )[0]

        sync_conn.execute(
            """
            UPDATE email_outbox
            SET locked_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes'
            WHERE id = %s
            """,
            (message_id,),
        )
        sync_conn.commit()

        replacement = (
            await claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            )
        )[0]

        assert replacement.id == message_id
        assert replacement.lock_token != original.lock_token
        assert replacement.attempt_count == 2

        with pytest.raises(OutboxLeaseLostError) as exc_info:
            await mark_email_sent(
                db_pool,
                message_id=message_id,
                lock_token=original.lock_token,
            )

        assert exc_info.value.message_id == message_id

        await mark_email_sent(
            db_pool,
            message_id=message_id,
            lock_token=replacement.lock_token,
        )

        stored = sync_conn.execute(
            """
            SELECT status, locked_at, lock_token, sent_at
            FROM email_outbox
            WHERE id = %s
            """,
            (message_id,),
        ).fetchone()

        assert stored is not None
        assert stored[0] == "sent"
        assert stored[1] is None
        assert stored[2] is None
        assert stored[3] is not None

    async def test_preflight_renews_live_lease_and_rejects_reclaimed_owner(self, db_pool):
        async with get_db_cursor(db_pool) as cur:
            await enqueue_email_cur(
                cur,
                user_id=None,
                message_type="account_locked_notice",
                recipient="person@example.test",
                subject="Notice",
                body="Body",
                action=None,
            )
        (message,) = await claim_due_emails(db_pool, limit=1, lease_timeout=timedelta(minutes=10))
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "UPDATE email_outbox SET locked_at = clock_timestamp() - INTERVAL '9 minutes' "
                "WHERE id = %s",
                (message.id,),
            )
        assert await prepare_email_delivery(
            db_pool,
            message,
            lease_timeout=timedelta(minutes=10),
            min_remaining_lifetime=timedelta(minutes=2),
        )
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "SELECT locked_at > clock_timestamp() - INTERVAL '1 minute' AS fresh "
                "FROM email_outbox WHERE id = %s",
                (message.id,),
            )
            assert (await cur.fetchone())["fresh"] is True
            await cur.execute(
                "UPDATE email_outbox SET locked_at = clock_timestamp() - INTERVAL '11 minutes' "
                "WHERE id = %s",
                (message.id,),
            )
        (replacement,) = await claim_due_emails(
            db_pool, limit=1, lease_timeout=timedelta(minutes=10)
        )
        assert replacement.lock_token != message.lock_token
        with pytest.raises(OutboxLeaseLostError):
            await prepare_email_delivery(
                db_pool,
                message,
                lease_timeout=timedelta(minutes=10),
                min_remaining_lifetime=timedelta(minutes=2),
            )

    async def test_retry_releases_lease_but_is_not_immediately_claimable(
        self,
        db_pool,
        sync_conn,
    ):
        message_id = await _enqueue(db_pool)

        message = (
            await claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            )
        )[0]

        await retry_email_later(
            db_pool,
            message=message,
            delay=timedelta(minutes=10),
            error="temporary SMTP failure\nplease retry",
            lease_timeout=_LEASE_TIMEOUT,
            min_remaining_lifetime=timedelta(minutes=2),
        )

        stored = sync_conn.execute(
            """
            SELECT
                status,
                locked_at,
                lock_token,
                last_error,
                next_attempt_at > CURRENT_TIMESTAMP
            FROM email_outbox
            WHERE id = %s
            """,
            (message_id,),
        ).fetchone()

        assert stored == (
            "pending",
            None,
            None,
            "temporary SMTP failure please retry",
            True,
        )

        assert (
            await claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            )
            == []
        )

    async def test_undecryptable_message_can_be_marked_dead(
        self,
        db_pool,
        sync_conn,
    ):
        message_id = await _enqueue(db_pool)

        sync_conn.execute(
            """
            UPDATE email_outbox
            SET body_ciphertext = 'not-valid-fernet'
            WHERE id = %s
            """,
            (message_id,),
        )
        sync_conn.commit()

        message = (
            await claim_due_emails(
                db_pool,
                limit=1,
                lease_timeout=_LEASE_TIMEOUT,
            )
        )[0]

        with pytest.raises(OutboxBodyDecryptionError) as exc_info:
            decrypt_claimed_email_body(message)

        assert exc_info.value.message_id == message_id

        await mark_email_dead(
            db_pool,
            message_id=message.id,
            lock_token=message.lock_token,
            error="Outbox body could not be decrypted",
        )

        stored = sync_conn.execute(
            """
            SELECT
                status,
                failed_at,
                locked_at,
                lock_token,
                last_error
            FROM email_outbox
            WHERE id = %s
            """,
            (message_id,),
        ).fetchone()

        assert stored is not None
        assert stored[0] == "dead"
        assert stored[1] is not None
        assert stored[2] is None
        assert stored[3] is None
        assert stored[4] == "Outbox body could not be decrypted"


class TestDeliveryOutcomes:
    """Outcomes of a delivery batch run against real outbox rows."""

    async def test_delivery_worker_marks_real_outbox_row_sent(
        self,
        db_pool,
        sync_conn,
    ) -> None:
        message_id = await _enqueue_worker_test_email(db_pool)

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
            return_value=DeliveryResult(status="sent", reason="smtp_accepted"),
        ) as send:
            await deliver_email_outbox_batch(db_pool)

        send.assert_awaited_once()
        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["status"] == "sent"
        assert state["attempt_count"] == 1
        assert state["sent_at"] is not None
        assert state["locked_at"] is None
        assert state["lock_token"] is None
        assert state["last_error"] is None
        assert state["failed_at"] is None

    async def test_delivery_worker_reschedules_real_outbox_row_after_failure(
        self,
        db_pool,
        sync_conn,
    ) -> None:
        message_id = await _enqueue_worker_test_email(db_pool)

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
            return_value=DeliveryResult(status="temporary_failure", reason="smtp_transport_error"),
        ):
            await deliver_email_outbox_batch(db_pool)

        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["status"] == "pending"
        assert state["attempt_count"] == 1
        assert state["next_attempt_at"] > datetime.now(UTC)
        assert state["locked_at"] is None
        assert state["lock_token"] is None
        assert state["last_error"] == "smtp_transport_error"
        assert state["sent_at"] is None
        assert state["failed_at"] is None

    async def test_delivery_worker_marks_exhausted_row_dead(
        self,
        db_pool,
        sync_conn,
    ) -> None:
        message_id = await _enqueue_worker_test_email(db_pool)
        sync_conn.execute(
            "UPDATE email_outbox SET attempt_count = 6 WHERE id = %s",
            (message_id,),
        )
        sync_conn.commit()

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
            return_value=DeliveryResult(status="temporary_failure", reason="smtp_transport_error"),
        ):
            await deliver_email_outbox_batch(db_pool)

        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["status"] == "dead"
        assert state["attempt_count"] == 7
        assert state["failed_at"] is not None
        assert state["last_error"] == "smtp_transport_error"
        assert state["locked_at"] is None
        assert state["lock_token"] is None
        assert state["sent_at"] is None

    async def test_delivery_worker_marks_undecryptable_row_dead(
        self,
        db_pool,
        sync_conn,
    ) -> None:
        message_id = await _enqueue_worker_test_email(db_pool)
        sync_conn.execute(
            "UPDATE email_outbox SET body_ciphertext = %s WHERE id = %s",
            ("not-valid-ciphertext", message_id),
        )
        sync_conn.commit()

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
        ) as send:
            await deliver_email_outbox_batch(db_pool)

        send.assert_not_called()
        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["status"] == "dead"
        assert state["attempt_count"] == 1
        assert state["failed_at"] is not None
        assert state["last_error"] == "Outbox body decryption failed"
        assert state["locked_at"] is None
        assert state["lock_token"] is None
        assert state["sent_at"] is None


class TestRecipientRowContention:
    """A locked recipient user row blocks only mail that itself needs that
    row locked (action mail carrying a token bound to account state);
    unrelated mail queued for the same recipient in the same batch still
    delivers, and the blocked action email is deferred without consuming a
    delivery attempt."""

    async def test_locked_recipient_does_not_block_other_mail_or_consume_attempt(
        self, db_pool, sync_conn, user_factory
    ):
        user = user_factory(email_verified=False)
        async with get_db_cursor(db_pool) as cur:
            await queue_verification_email_cur(cur, await get_user_by_id(db_pool, user.id))
            notice_id = await enqueue_email_cur(
                cur,
                user_id=user.id,
                message_type="account_locked_notice",
                recipient=user.email,
                subject="Notice",
                body="Body",
                action=None,
            )
        sync_conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user.id,))
        sender = create_autospec(send_claimed_email, return_value=True)
        try:
            with patch("app.services.email_delivery.send_claimed_email", new=sender):
                async with asyncio.timeout(3):
                    await deliver_email_outbox_batch(db_pool)
        finally:
            sync_conn.rollback()
        assert sender.await_count == 1
        assert sender.await_args.args[0].id == notice_id
        assert sync_conn.execute(
            "SELECT status, attempt_count FROM email_outbox WHERE message_type = 'email_verification'"
        ).fetchone() == ("pending", 0)


class TestDevelopmentMailboxEndToEnd:
    """The development mailbox (SMTP disabled, ``.eml`` files on disk) is a
    real delivery channel: a capability link written by the outbox worker
    into a ``.eml`` file drives the same routes a production recipient would
    use, end to end through registration, password reset, and an
    admin-initiated email change."""

    async def test_development_mailbox_links_complete_real_account_workflows(
        self, db_pool, sync_conn, e2e_client, admin_actor, monkeypatch, tmp_path
    ):
        """Real routes -> committed outbox -> SMTP child -> .eml -> capability route."""
        mailbox = tmp_path / "mailbox"
        monkeypatch.setenv("SMTP_ENABLED", "false")
        monkeypatch.setenv("DEV_MAILBOX_DIR", str(mailbox))
        email = "dev-flow@example.org"
        password = "Original-Strong-Password-9876!"

        async def delivered_token(path):
            await deliver_email_outbox_batch(db_pool)
            for message_path in mailbox.glob("*.eml"):
                message = BytesParser(policy=policy.default).parsebytes(message_path.read_bytes())
                match = re.search(re.escape(path) + r"([A-Za-z0-9_.-]+)", message.get_content())
                if match:
                    return match.group(1)
            raise AssertionError(f"No delivered capability for {path}")

        e2e_client.get("/register")
        response = e2e_client.post(
            "/register",
            data={
                "email": email,
                "display_name": "Development User",
                "password": password,
                "password_confirm": password,
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert response.status_code == 200
        verification = await delivered_token("/verify-email/")
        response = e2e_client.post(
            "/verify-email", data={"token": verification}, follow_redirects=False
        )
        assert response.status_code == 303
        e2e_client.get("/forgot-password")
        response = e2e_client.post(
            "/forgot-password",
            data={"email": email, "csrf_token": e2e_client.cookies.get("csrf_token")},
        )
        assert response.status_code == 200
        reset = await delivered_token("/reset-password/")
        assert e2e_client.get(f"/reset-password/{reset}").status_code == 200
        response = e2e_client.post(
            "/reset-password",
            data={
                "token": reset,
                "csrf_token": e2e_client.cookies.get("csrf_token"),
                "password": "Replacement-Strong-Password-2468!",
                "password_confirm": "Replacement-Strong-Password-2468!",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        user_id = sync_conn.execute("SELECT id FROM users WHERE email=%s", (email,)).fetchone()[0]
        sync_conn.commit()
        await email_change.stage_admin_email_change(
            db_pool,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
            target_user_id=user_id,
            new_email="dev-new@example.org",
        )
        confirmation = await delivered_token("/account/confirm-email/")
        response = e2e_client.post(
            "/account/confirm-email", data={"token": confirmation}, follow_redirects=False
        )
        assert response.status_code == 303
        assert sync_conn.execute("SELECT email FROM users WHERE id=%s", (user_id,)).fetchone() == (
            "dev-new@example.org",
        )
