"""Token transactions, current-state checks and retry deadlines."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import psycopg
import pytest
from psycopg.errors import CheckViolation

from app.services import email_delivery
from app.services.db import get_db_cursor
from app.services.email import DeliveryResult
from app.services.email_change import store_pending_email_cur
from app.services.email_outbox import (
    OutboxLeaseLostError,
    claim_due_emails,
    enqueue_email_cur,
    mark_email_sent,
    prepare_email_delivery,
    retry_email_later,
)
from app.services.email_verification import store_verification_token_hash_cur
from app.services.password_reset import store_reset_token_hash_cur
from app.services.tokens import ActionEmailMetadata, hash_token
from config import settings

_KINDS = {
    "password_reset": (
        "password_reset_token_hash",
        "password_reset_created_at",
        1800,
    ),
    "email_verification": (
        "email_verification_token_hash",
        "email_verification_created_at",
        86400,
    ),
    "email_change_verification": (
        "pending_email_token_hash",
        "pending_email_created_at",
        3600,
    ),
}

_LEASE = timedelta(minutes=10)
_MINIMUM = timedelta(minutes=2)


async def _store(cur, kind, user, action):
    if kind == "password_reset":
        await store_reset_token_hash_cur(
            cur,
            user.id,
            action.token_hash,
            expected_email=user.email,
        )
    elif kind == "email_verification":
        await store_verification_token_hash_cur(
            cur,
            user.id,
            action.token_hash,
            expected_email=user.email,
        )
    else:
        await cur.execute(
            "SELECT auth_revision FROM users WHERE id = %s",
            (user.id,),
        )
        row = await cur.fetchone()
        assert row is not None
        await store_pending_email_cur(
            cur,
            user.id,
            "new@example.test",
            action.token_hash,
            expected_auth_revision=row["auth_revision"],
        )


async def _queue(pool, kind, user, *, action=None):
    if action is None:
        action = ActionEmailMetadata(
            hash_token(uuid4().hex),
            datetime.now(UTC) + timedelta(seconds=_KINDS[kind][2]),
        )

    recipient = "new@example.test" if kind == "email_change_verification" else user.email

    async with get_db_cursor(pool) as cur:
        await _store(cur, kind, user, action)
        message_id = await enqueue_email_cur(
            cur,
            user_id=user.id,
            message_type=kind,
            recipient=recipient,
            subject="Action",
            body="Action link body",
            action=action,
        )

    return message_id, action


async def _notice(pool, user_id=None, *, kind="account_locked_notice"):
    async with get_db_cursor(pool) as cur:
        return await enqueue_email_cur(
            cur,
            user_id=user_id,
            message_type=kind,
            recipient="person@example.test",
            subject="Notice",
            body="Account notice",
            action=None,
        )


async def _claim(pool):
    messages = await claim_due_emails(
        pool,
        limit=10,
        lease_timeout=_LEASE,
    )
    assert len(messages) == 1
    return messages[0]


async def _fetch(pool, query, params=()):
    async with get_db_cursor(pool) as cur:
        await cur.execute(query, params)
        return await cur.fetchone()


async def _execute(pool, query, params=()):
    async with get_db_cursor(pool) as cur:
        await cur.execute(query, params)


async def _state(pool, message_id):
    return await _fetch(
        pool,
        "SELECT * FROM email_outbox WHERE id = %s",
        (message_id,),
    )


@pytest.mark.parametrize("kind", _KINDS)
async def test_replacement_cancels_pending_but_keeps_notices(
    db_pool,
    user_factory,
    kind,
):
    user = user_factory(email_verified=False)
    old_id, action = await _queue(db_pool, kind, user)
    notice_id = await _notice(db_pool, user.id)

    # An identical hash must still cancel the older pending row.
    new_id, _ = await _queue(db_pool, kind, user, action=action)

    old = await _state(db_pool, old_id)
    assert old["status"] == "dead"
    assert old["last_error"] == "superseded"
    assert old["failed_at"] is not None
    assert old["locked_at"] is None
    assert old["lock_token"] is None
    assert (await _state(db_pool, new_id))["status"] == "pending"
    assert (await _state(db_pool, notice_id))["status"] == "pending"


@pytest.mark.parametrize("kind", _KINDS)
async def test_failed_replacement_restores_old_token_and_message(
    db_pool,
    user_factory,
    kind,
):
    user = user_factory(email_verified=False)
    old_id, old_action = await _queue(db_pool, kind, user)
    replacement = ActionEmailMetadata(
        hash_token(uuid4().hex),
        old_action.expires_at,
    )

    with pytest.raises(ValueError, match="require action metadata"):
        async with get_db_cursor(db_pool) as cur:
            await _store(cur, kind, user, replacement)
            await enqueue_email_cur(
                cur,
                user_id=user.id,
                message_type=kind,
                recipient=user.email,
                subject="Action",
                body="Replacement",
                action=None,
            )

    column = _KINDS[kind][0]
    stored = await _fetch(
        db_pool,
        f"SELECT {column} AS hash FROM users WHERE id = %s",
        (user.id,),
    )
    assert stored["hash"] == old_action.token_hash
    assert (await _state(db_pool, old_id))["status"] == "pending"
    assert (await _fetch(db_pool, "SELECT count(*) AS n FROM email_outbox"))["n"] == 1


@pytest.mark.parametrize("kind", _KINDS)
async def test_superseded_claim_is_discarded_before_smtp(db_pool, user_factory, kind):
    user = user_factory(email_verified=False)
    old_id, _ = await _queue(db_pool, kind, user)
    old = await _claim(db_pool)
    new_id, _ = await _queue(db_pool, kind, user)
    assert (await _state(db_pool, old_id))["status"] == "sending"
    with patch.object(email_delivery, "send_claimed_email", autospec=True) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, old) == "dead"
    smtp.assert_not_awaited()
    assert (await _state(db_pool, old_id))["last_error"] == "superseded_or_consumed"
    assert (await _state(db_pool, new_id))["status"] == "pending"


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("change", ["consumed", "database_expired"])
async def test_user_state_is_reread_after_claim(db_pool, user_factory, kind, change):
    user = user_factory(email_verified=False)
    message_id, _ = await _queue(db_pool, kind, user)
    message = await _claim(db_pool)
    column = _KINDS[kind][0 if change == "consumed" else 1]
    value = None if change == "consumed" else datetime.now(UTC) - timedelta(days=2)
    await _execute(db_pool, f"UPDATE users SET {column} = %s WHERE id = %s", (value, user.id))
    with patch.object(email_delivery, "send_claimed_email", autospec=True) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "dead"
    smtp.assert_not_awaited()
    assert (await _state(db_pool, message_id))["status"] == "dead"


@pytest.mark.parametrize("kind", _KINDS)
async def test_expired_signed_deadline_is_terminal_without_smtp(db_pool, user_factory, kind):
    user = user_factory(email_verified=False)
    action = ActionEmailMetadata(hash_token(uuid4().hex), datetime.now(UTC) - timedelta(seconds=1))
    message_id, _ = await _queue(db_pool, kind, user, action=action)
    message = await _claim(db_pool)
    with patch.object(email_delivery, "send_claimed_email", autospec=True) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "dead"
    smtp.assert_not_awaited()
    stored = await _state(db_pool, message_id)
    assert stored["last_error"] == "expired"
    assert stored["expires_at"] == action.expires_at


@pytest.mark.parametrize(
    "kind,mutation",
    [
        ("password_reset", "inactive"),
        ("password_reset", "nonlocal"),
        ("password_reset", "recipient"),
        ("email_verification", "recipient"),
        ("email_verification", "verified"),
        ("email_change_verification", "pending_recipient"),
        ("email_change_verification", "taken"),
    ],
)
async def test_changed_account_predicate_blocks_smtp(db_pool, user_factory, kind, mutation):
    user = user_factory(email_verified=False)
    await _queue(db_pool, kind, user)
    message = await _claim(db_pool)
    if mutation == "taken":
        user_factory(email="new@example.test")
    else:
        assignments = {
            "inactive": "is_active = false",
            "nonlocal": (
                "auth_method = 'shibboleth', password_hash = NULL, "
                "shibboleth_subject_id = 'test-subject', shibboleth_issuer = 'https://idp.example.org', "
                "federated_status = 'pending', is_active = false, access_tier = 'public'"
            ),
            "recipient": "email = 'changed@example.test'",
            "verified": "email_verified = true",
            "pending_recipient": "pending_email = 'different@example.test'",
        }
        await _execute(
            db_pool, f"UPDATE users SET {assignments[mutation]} WHERE id = %s", (user.id,)
        )
    with patch.object(email_delivery, "send_claimed_email", autospec=True) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "dead"
    smtp.assert_not_awaited()


@pytest.mark.parametrize("kind", _KINDS)
async def test_valid_action_sends_without_holding_database_locks(db_pool, user_factory, kind):
    user = user_factory(email_verified=False)
    message_id, action = await _queue(db_pool, kind, user)
    message = await _claim(db_pool)

    async def smtp(_message, _email, *, deadline):
        assert deadline > 0
        with psycopg.connect(settings.database_url.get_secret_value()) as conn:
            conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE NOWAIT", (user.id,))
            conn.execute(
                "SELECT id FROM email_outbox WHERE id = %s FOR UPDATE NOWAIT", (message_id,)
            )
        return DeliveryResult(status="sent", reason="smtp_accepted")

    with patch.object(
        email_delivery, "send_claimed_email", autospec=True, side_effect=smtp
    ) as send:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "sent"
    send.assert_awaited_once()
    row = await _state(db_pool, message_id)
    assert row["status"] == "sent"
    assert row["expires_at"] == action.expires_at


async def test_locked_account_can_receive_password_recovery(db_pool, user_factory):
    user = user_factory(locked_until=datetime.now(UTC) + timedelta(hours=1), failed_login_count=20)
    await _queue(db_pool, "password_reset", user)
    message = await _claim(db_pool)
    with patch.object(
        email_delivery,
        "send_claimed_email",
        autospec=True,
        return_value=DeliveryResult(status="sent", reason="smtp_accepted"),
    ) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "sent"
    smtp.assert_awaited_once()


@pytest.mark.parametrize("loss", ["timeout", "reclaimed", "deleted_user"])
async def test_lost_lease_never_reaches_smtp(db_pool, user_factory, loss):
    user = user_factory()
    message_id, _ = await _queue(db_pool, "password_reset", user)
    message = await _claim(db_pool)
    if loss == "deleted_user":
        await _execute(db_pool, "DELETE FROM users WHERE id = %s", (user.id,))
    elif loss == "timeout":
        await _execute(
            db_pool,
            "UPDATE email_outbox SET locked_at = clock_timestamp() - INTERVAL '1 hour' WHERE id = %s",
            (message_id,),
        )
    else:
        await _execute(
            db_pool, "UPDATE email_outbox SET lock_token = %s WHERE id = %s", (uuid4(), message_id)
        )
    with (
        patch.object(
            email_delivery,
            "send_claimed_email",
            autospec=True,
        ) as smtp,
        pytest.raises(OutboxLeaseLostError),
    ):
        await email_delivery._deliver_claimed_email(
            db_pool,
            message,
        )
    smtp.assert_not_awaited()


async def test_retry_preserves_metadata_and_notice_has_no_action_deadline(
    db_pool,
    user_factory,
):
    user = user_factory()
    message_id, action = await _queue(db_pool, "password_reset", user)
    message = await _claim(db_pool)

    assert (
        await retry_email_later(
            db_pool,
            message=message,
            delay=timedelta(seconds=30),
            error="SMTP failed",
            lease_timeout=_LEASE,
            min_remaining_lifetime=_MINIMUM,
        )
        == "retried"
    )

    row = await _state(db_pool, message_id)
    assert (row["action_token_hash"], row["expires_at"]) == (
        action.token_hash,
        action.expires_at,
    )
    assert row["status"] == "pending"
    assert row["lock_token"] is None

    await _execute(
        db_pool,
        """
        UPDATE email_outbox
        SET next_attempt_at = clock_timestamp()
        WHERE id = %s
        """,
        (message_id,),
    )
    message = await _claim(db_pool)

    assert (
        await retry_email_later(
            db_pool,
            message=message,
            delay=timedelta(seconds=60),
            error="SMTP failed again",
            lease_timeout=_LEASE,
            min_remaining_lifetime=_MINIMUM,
        )
        == "retried"
    )

    assert (await _state(db_pool, message_id))["expires_at"] == action.expires_at

    # Keep the action row out of the next claim independently of test speed.
    await _execute(
        db_pool,
        """
        UPDATE email_outbox
        SET next_attempt_at = clock_timestamp() + INTERVAL '1 day'
        WHERE id = %s
        """,
        (message_id,),
    )
    notice_id = await _notice(db_pool)
    notice = await _claim(db_pool)

    assert (
        await retry_email_later(
            db_pool,
            message=notice,
            delay=timedelta(days=2),
            error="SMTP failed",
            lease_timeout=_LEASE,
            min_remaining_lifetime=_MINIMUM,
        )
        == "retried"
    )

    assert (await _state(db_pool, notice_id))["expires_at"] is None


async def test_retry_that_leaves_too_little_lifetime_becomes_dead(
    db_pool,
    user_factory,
):
    user = user_factory()
    action = ActionEmailMetadata(
        hash_token(uuid4().hex),
        datetime.now(UTC) + timedelta(minutes=5),
    )
    message_id, _ = await _queue(
        db_pool,
        "password_reset",
        user,
        action=action,
    )
    message = await _claim(db_pool)

    assert (
        await prepare_email_delivery(
            db_pool,
            message,
            lease_timeout=_LEASE,
            min_remaining_lifetime=_MINIMUM,
        )
        is True
    )

    assert (
        await retry_email_later(
            db_pool,
            message=message,
            delay=timedelta(minutes=4),
            error="SMTP failed",
            lease_timeout=_LEASE,
            min_remaining_lifetime=_MINIMUM,
        )
        == "dead"
    )

    row = await _state(db_pool, message_id)
    assert row["last_error"] == "insufficient_lifetime"
    assert row["expires_at"] == action.expires_at
    assert row["lock_token"] is None
    assert row["failed_at"] is not None


async def test_failed_smtp_rechecks_token_before_scheduling_retry(db_pool, user_factory):
    user = user_factory()
    message_id, _ = await _queue(db_pool, "password_reset", user)
    message = await _claim(db_pool)

    async def smtp(_message, _email, *, deadline):
        assert deadline > 0
        with psycopg.connect(settings.database_url.get_secret_value()) as conn:
            conn.execute(
                "UPDATE users SET password_reset_token_hash = NULL WHERE id = %s", (user.id,)
            )
        return DeliveryResult(status="temporary_failure", reason="smtp_transport_error")

    with patch.object(
        email_delivery, "send_claimed_email", autospec=True, side_effect=smtp
    ) as send:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "dead"
    send.assert_awaited_once()
    assert (await _state(db_pool, message_id))["last_error"] == "superseded_or_consumed"


async def test_replacement_does_not_rewrite_sent_messages(
    db_pool,
    user_factory,
):
    user = user_factory()
    old_id, _ = await _queue(db_pool, "password_reset", user)
    message = await _claim(db_pool)

    await mark_email_sent(
        db_pool,
        message_id=message.id,
        lock_token=message.lock_token,
    )
    await _queue(db_pool, "password_reset", user)

    assert (await _state(db_pool, old_id))["status"] == "sent"


@pytest.mark.parametrize(
    "kind,user_bound,has_metadata",
    [
        ("password_reset", True, False),
        ("password_reset", False, True),
        ("account_locked_notice", True, True),
        ("unknown", True, False),
    ],
)
async def test_database_rejects_invalid_action_metadata(
    db_pool,
    user_factory,
    kind,
    user_bound,
    has_metadata,
):
    user = user_factory()

    with pytest.raises(CheckViolation):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """
                INSERT INTO email_outbox (
                    user_id, message_type, recipient, subject,
                    body_ciphertext, action_token_hash, expires_at
                )
                VALUES (%s, %s, 'a@example.test', 'Subject',
                        'ciphertext', %s, %s)
                """,
                (
                    user.id if user_bound else None,
                    kind,
                    hash_token("test") if has_metadata else None,
                    (datetime.now(UTC) + timedelta(hours=1) if has_metadata else None),
                ),
            )


async def test_cancellation_is_scoped_to_user_and_message_type(
    db_pool,
    user_factory,
):
    user = user_factory(email_verified=False)
    other = user_factory(email_verified=False)

    old_id, _ = await _queue(db_pool, "password_reset", user)
    verification_id, _ = await _queue(db_pool, "email_verification", user)
    other_id, _ = await _queue(db_pool, "password_reset", other)

    await _queue(db_pool, "password_reset", user)

    assert (await _state(db_pool, old_id))["status"] == "dead"
    assert (await _state(db_pool, verification_id))["status"] == "pending"
    assert (await _state(db_pool, other_id))["status"] == "pending"


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate_registration_notice",
        "email_change_notice",
        "account_credential_fault_notice",
        "account_locked_notice",
    ],
)
async def test_notices_send_without_action_state(db_pool, kind):
    message_id = await _notice(db_pool, kind=kind)
    message = await _claim(db_pool)
    with patch.object(
        email_delivery,
        "send_claimed_email",
        autospec=True,
        return_value=DeliveryResult(status="sent", reason="smtp_accepted"),
    ) as smtp:
        assert await email_delivery._deliver_claimed_email(db_pool, message) == "sent"
    smtp.assert_awaited_once()
    row = await _state(db_pool, message_id)
    assert row["action_token_hash"] is None and row["expires_at"] is None
