"""Integration tests for transactional email outbox leases and delivery against PostgreSQL."""

import asyncio
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from typing import Any
from unittest.mock import create_autospec, patch
from uuid import UUID

import pyotp
import pytest
import time_machine
from lxml import html

from app.services import begin_local_registration, email_change, get_user_by_email
from app.services.db import get_db_cursor
from app.services.email import DeliveryResult
from app.services.email_delivery import deliver_email_outbox_batch
from app.services.email_outbox import (
    OutboundEmail,
    OutboxBodyDecryptionError,
    OutboxLeaseLostError,
    claim_due_emails,
    decrypt_claimed_email_body,
    defer_contended_email,
    enqueue_email_cur,
    enqueue_outbound_email_cur,
    mark_email_dead,
    mark_email_sent,
    prepare_email_delivery,
    retry_email_later,
)
from app.services.outbox_maintenance import get_outbox_metrics_cur, outbox_is_degraded
from app.services.smtp_process import send_claimed_email
from app.services.tokens import action_token_public_id
from tests.action_links import action_path, token_from_action_email
from tests.integration.conftest import do_login

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
    "terminal_outcome",
)


async def _enqueue(db_pool, *, body: str = _BODY) -> int:
    """Enqueue a non-action notice and return its message ID."""
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
    """Enqueue the synthetic worker-test notice and return its ID."""
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
    """Read the outbox state columns into a dictionary; require the row to exist."""
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
        """Verify enqueue stores encrypted body and claim decrypts it."""
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
        """Verify enqueue participates in callers transaction."""
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
        """Verify competing workers cannot claim same message."""
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
        """Verify expired lease is reclaimed and old owner is rejected."""
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
        """Verify preflight renews live lease and rejects reclaimed owner."""
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
        """Verify retry releases lease but is not immediately claimable."""
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
        """Verify undecryptable message can be marked dead."""
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
        """Verify delivery worker marks real outbox row sent."""
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
        """Verify delivery worker reschedules real outbox row after failure."""
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
        """Verify delivery worker marks exhausted row dead."""
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
        """Verify delivery worker marks undecryptable row dead."""
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
        self, db_pool, sync_conn
    ):
        """Verify locked recipient does not block other mail or consume attempt."""
        email = "contended-registration@example.org"
        await begin_local_registration(db_pool, email=email)
        user = await get_user_by_email(db_pool, email)
        assert user is not None
        async with get_db_cursor(db_pool) as cur:
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

    @pytest.mark.parametrize(
        ("age", "expected_status"),
        [
            (timedelta(minutes=59), "pending"),
            (timedelta(hours=1), "dead"),
            (timedelta(minutes=61), "dead"),
        ],
        ids=["before-cutoff", "exact-cutoff", "after-cutoff"],
    )
    async def test_contention_has_independent_queue_age_budget(
        self, db_pool, sync_conn, caplog, age, expected_status
    ):
        """An account lock cannot prevent terminal escalation; SMTP is never invoked."""
        await begin_local_registration(db_pool, email="queue-age@example.org")
        user = await get_user_by_email(db_pool, "queue-age@example.org")
        assert user is not None
        message_id = sync_conn.execute(
            "UPDATE email_outbox SET created_at = clock_timestamp() - %s, attempt_count = 2 "
            "WHERE user_id = %s RETURNING id",
            (age, user.id),
        ).fetchone()[0]
        sync_conn.commit()
        sync_conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user.id,))
        with patch("app.services.email_delivery.send_claimed_email", autospec=True) as send:
            try:
                with caplog.at_level(logging.INFO):
                    await deliver_email_outbox_batch(db_pool)
            finally:
                sync_conn.rollback()
        send.assert_not_awaited()
        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["status"] == expected_status
        assert state["attempt_count"] == 2  # only the unattempted claim was refunded
        assert state["locked_at"] is None and state["lock_token"] is None
        assert state["sent_at"] is None
        terminal = expected_status == "dead"
        assert (state["failed_at"] is not None) is terminal
        assert state["terminal_outcome"] == ("delivery_failed" if terminal else None)
        assert state["last_error"] == (
            "delivery_state_contention_exhausted" if terminal else "delivery_state_contended"
        )
        exhausted_events = [
            r
            for r in caplog.records
            if getattr(r, "event_type", None) == "email_outbox_contention_exhausted"
        ]
        assert len(exhausted_events) == int(terminal)
        async with get_db_cursor(db_pool) as cur:
            metrics = await get_outbox_metrics_cur(cur)
        assert metrics["recent_failure_count"] == int(terminal)
        if terminal:
            assert outbox_is_degraded(metrics)
            assert await claim_due_emails(db_pool, limit=1, lease_timeout=_LEASE_TIMEOUT) == []
        else:
            assert state["next_attempt_at"] > datetime.now(UTC)

    @pytest.mark.parametrize("smtp_attempted", [False, True])
    async def test_contention_preserves_attempt_accounting_and_lease_fence(
        self, db_pool, sync_conn, smtp_attempted
    ):
        """Verify contention preserves attempt accounting and lease fence."""
        message_id = await _enqueue(db_pool)
        sync_conn.execute(
            "UPDATE email_outbox SET created_at = clock_timestamp() - INTERVAL '1 hour', "
            "attempt_count = 3 WHERE id = %s",
            (message_id,),
        )
        sync_conn.commit()
        message = (await claim_due_emails(db_pool, limit=1, lease_timeout=_LEASE_TIMEOUT))[0]
        with pytest.raises(OutboxLeaseLostError):
            await defer_contended_email(db_pool, replace(message, lock_token=UUID(int=0)))
        assert _fetch_outbox_state(sync_conn, message_id)["status"] == "sending"
        sync_conn.rollback()
        assert (
            await defer_contended_email(db_pool, message, smtp_attempted=smtp_attempted) == "dead"
        )
        state = _fetch_outbox_state(sync_conn, message_id)
        assert state["attempt_count"] == (4 if smtp_attempted else 3)
        assert state["status"] == "dead"
        with pytest.raises(OutboxLeaseLostError):
            await defer_contended_email(db_pool, message, smtp_attempted=smtp_attempted)


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
            """Drain up to five outbox batches and extract the delivered action token; otherwise
            assert.
            """
            for _ in range(5):
                await deliver_email_outbox_batch(db_pool)
                for message_path in mailbox.glob("*.eml"):
                    message = BytesParser(policy=policy.default).parsebytes(
                        message_path.read_bytes()
                    )
                    links = [
                        line.strip()
                        for line in message.get_content().splitlines()
                        if line.strip().startswith("http") and path in line
                    ]
                    if links:
                        return token_from_action_email(message.get_content(), links[0])
            raise AssertionError(f"No delivered capability for {path}")

        e2e_client.get("/register")
        response = e2e_client.post(
            "/register",
            data={
                "email": email,
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert response.status_code == 200
        verification = await delivered_token("/verify-email/")
        assert e2e_client.get(action_path("/verify-email", verification)).status_code == 200
        response = e2e_client.post(
            "/verify-email",
            data={
                "token": verification,
                "public_id": action_token_public_id(verification),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
                "display_name": "Development User",
                "password": password,
                "password_confirm": password,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?notice=registration_complete"

        # A reset now needs an enrolled authenticator. Exercise the real setup
        # route and use the previous valid step so reset has a fresh code.
        with time_machine.travel(datetime.now(UTC), tick=False):
            login = do_login(e2e_client, email, password)
            assert login.status_code == 303
            assert login.headers["location"] == "/setup-totp"
            setup = e2e_client.get("/setup-totp")
            assert setup.status_code == 200
            document = html.fromstring(setup.text)
            secret = document.xpath('string(//code[@class="totp-key"])').strip()
            recovery_codes = document.xpath('//ol[@class="recovery-code-list"]/li/code/text()')
            assert secret and recovery_codes
            enrolled = e2e_client.post(
                "/setup-totp",
                data={
                    "totp_code": pyotp.TOTP(secret).at(datetime.now(UTC) - timedelta(seconds=30)),
                    "recovery_code_confirmation": recovery_codes[0],
                    "csrf_token": e2e_client.cookies.get("csrf_token"),
                },
                follow_redirects=False,
            )
            assert enrolled.status_code == 303
            assert enrolled.headers["location"] == "/login?notice=totp_setup_completed"
            assert e2e_client.cookies.get("oha_session") is None
        # Recovery mail becomes eligible after the earlier registration's cooldown.
        sync_conn.execute(
            "UPDATE anonymous_mail_issuance SET created_at=clock_timestamp()-INTERVAL '6 minutes'"
        )
        sync_conn.commit()
        e2e_client.get("/forgot-password")
        response = e2e_client.post(
            "/forgot-password",
            data={"email": email, "csrf_token": e2e_client.cookies.get("csrf_token")},
        )
        assert response.status_code == 200
        reset = await delivered_token("/reset-password/")
        assert e2e_client.get(action_path("/reset-password", reset)).status_code == 200
        response = e2e_client.post(
            "/reset-password",
            data={
                "token": reset,
                "public_id": action_token_public_id(reset),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
                "password": "Replacement-Strong-Password-2468!",
                "password_confirm": "Replacement-Strong-Password-2468!",
                "totp_code": pyotp.TOTP(secret).now(),
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
            "/account/confirm-email",
            data={"token": confirmation, "public_id": action_token_public_id(confirmation)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert sync_conn.execute("SELECT email FROM users WHERE id=%s", (user_id,)).fetchone() == (
            "dev-new@example.org",
        )
