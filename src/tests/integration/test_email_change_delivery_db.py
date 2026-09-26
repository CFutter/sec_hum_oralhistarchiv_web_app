"""Email-change outbox delivery and enqueue-failure behavior — real PostgreSQL.

Covers how a staged email-change reaches SMTP through
app.services.email_delivery.deliver_email_outbox_batch (an already-occupied
destination must never be delivered, even though it was queued before the
race was known) and what happens to pending state and prior outbox rows when
a mid-staging enqueue call raises
(app.services.email_change / app.services.email_outbox).

Staging is exercised through the real POST route so each scenario starts
from a durable outbox row exactly as production would produce it.
"""

from unittest.mock import patch

import pyotp
from fastapi import status

from app.services.crypto import encrypt_value
from app.services.email import DeliveryResult
from app.services.email_delivery import deliver_email_outbox_batch
from app.services.email_outbox import enqueue_outbound_email_cur
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

NEW_EMAIL = "new@uzh.ch"
_EMAIL_CHANGE_MESSAGE_COUNT = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_totp_user(user_factory, **overrides):
    """A local user with working TOTP; returns (handle, secret)."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret), **overrides)
    return u, secret


def _login(client, u, secret):
    """Real login (password + current TOTP code) → full session in the jar."""
    resp = do_login(client, u.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
    assert resp.status_code == status.HTTP_303_SEE_OTHER, "login must succeed to a full session"
    return resp


def _csrf_for_session(client):
    """After any GET the middleware syncs the csrf cookie to the session."""
    client.get("/account/change-email")
    return client.cookies.get("csrf_token")


def _pending_state(sync_conn, user_id):
    """(email, pending_email, pending_email_token_hash, pending_email_created_at)."""
    return sync_conn.execute(
        """SELECT email, pending_email, pending_email_token_hash,
                  pending_email_created_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


def _outbox_messages(sync_conn, user_id):
    """Return this user's queued messages in insertion order."""
    columns = (
        "message_type",
        "recipient",
        "subject",
        "body_ciphertext",
        "status",
    )
    rows = sync_conn.execute(
        """SELECT message_type, recipient, subject, body_ciphertext, status
           FROM email_outbox
           WHERE user_id = %s
           ORDER BY id""",
        (user_id,),
    ).fetchall()
    return [dict(zip(columns, row, strict=True)) for row in rows]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


class TestBatchDeliveryDiscardsOccupiedDestinations:
    async def test_occupied_destination_verification_is_discarded_before_smtp(
        self,
        e2e_client,
        db_pool,
        user_factory,
        sync_conn,
    ):
        """A queued capability must never be delivered to an existing account,
        while the sibling notice to the actor's own (unchanged) address is
        still delivered normally — the block is destination-specific, not a
        wholesale delivery failure."""
        occupied = user_factory(email="occupied@uzh.ch")
        actor, secret = _make_totp_user(user_factory)
        _login(e2e_client, actor, secret)
        csrf = _csrf_for_session(e2e_client)

        response = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": occupied.email,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert response.status_code == status.HTTP_303_SEE_OTHER

        with patch(
            "app.services.email_delivery.send_claimed_email",
            autospec=True,
            return_value=DeliveryResult(status="sent", reason="smtp_accepted"),
        ) as smtp:
            await deliver_email_outbox_batch(db_pool)

        sent_recipients = [call.args[1].recipient for call in smtp.await_args_list]
        assert sent_recipients == [actor.email]
        states = dict(
            sync_conn.execute(
                """
                SELECT message_type, status
                FROM email_outbox
                WHERE user_id = %s
                """,
                (actor.id,),
            ).fetchall()
        )
        assert states == {
            "email_change_notice": "sent",
            "email_change_verification": "dead",
        }
        error = sync_conn.execute(
            """
            SELECT last_error
            FROM email_outbox
            WHERE user_id = %s
              AND message_type = 'email_change_verification'
            """,
            (actor.id,),
        ).fetchone()[0]
        assert error == "email_taken"


class TestEnqueueFailureRollsBackStaging:
    async def test_change_email_staging_rolls_back_if_second_enqueue_fails(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """The staged change and the first message roll back with the second enqueue."""
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        csrf = _csrf_for_session(e2e_client)
        enqueue_count = 0

        async def enqueue_then_fail(cur, *, user_id, email, action):
            nonlocal enqueue_count
            enqueue_count += 1
            if enqueue_count == _EMAIL_CHANGE_MESSAGE_COUNT:
                raise ValueError("second enqueue failed")
            return await enqueue_outbound_email_cur(
                cur,
                user_id=user_id,
                email=email,
                action=action,
            )

        with patch(
            "app.services.email_change.enqueue_outbound_email_cur",
            autospec=True,
            side_effect=enqueue_then_fail,
        ):
            resp = e2e_client.post(
                "/account/change-email",
                data={
                    "new_email": NEW_EMAIL,
                    "current_password": DEFAULT_PASSWORD,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )

        assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "Something went wrong. Please try again." in resp.text
        assert enqueue_count == _EMAIL_CHANGE_MESSAGE_COUNT

        email, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
        assert email == u.email
        assert (pending, token_hash, created_at) == (None, None, None)
        assert _outbox_messages(sync_conn, u.id) == []
