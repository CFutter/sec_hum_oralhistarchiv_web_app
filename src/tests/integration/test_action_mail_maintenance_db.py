"""Maintenance revokes obsolete action mail without bypassing issuance/proof budgets."""

from uuid import uuid4

import psycopg
import pyotp
import pytest
from psycopg import sql
from psycopg.errors import LockNotAvailable

from app.paths import PROJECT_ROOT
from app.services import password_reset, registration_setup
from app.services.crypto import decrypt_outbox_body, encrypt_outbox_body
from app.services.db import get_db_cursor
from app.services.email_outbox import enqueue_email_cur
from app.services.tokens import hash_token
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.action_links import token_from_action_email
from tests.integration.conftest import TEST_DATABASE_URL

_SQL_PATH = PROJECT_ROOT / "deploy/invalidate-action-email-capabilities.sql"
_SECRET = "JBSWY3DPEHPK3PXP"
_NEW_PASSWORD = "Fresh-R3covery-Credential!92"


def _invalidate():
    """Execute the maintenance SQL in an independently committed transaction."""
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as connection:
        connection.execute(_SQL_PATH.read_text(encoding="utf-8"))


def _rows(connection, table):
    """Snapshot a fixed test table as JSON and end the observer transaction."""
    assert table in {"users", "email_outbox", "anonymous_mail_issuance"}
    rows = connection.execute(
        sql.SQL("SELECT to_jsonb(entry) FROM {} AS entry ORDER BY id").format(sql.Identifier(table))
    ).fetchall()
    connection.commit()
    return [row[0] for row in rows]


def _action_mail(connection, kind):
    """Read action mail in ID order and end the observer transaction."""
    rows = connection.execute(
        "SELECT id, body_ciphertext, action_token_hash FROM email_outbox "
        "WHERE message_type = %s ORDER BY id",
        (kind,),
    ).fetchall()
    connection.commit()
    return rows


def _token(message, kind):
    """Extract the separate signed code from a synthetic action email."""
    body = decrypt_outbox_body(message[1])
    assert body is not None
    path = "/reset-password/" if kind == "password_reset" else "/verify-email/"
    link = next(
        line.strip() for line in body.splitlines() if settings.public_base_url + path in line
    )
    return token_from_action_email(body, link)


@pytest.mark.parametrize("kind", ["password_reset", "email_verification"])
@pytest.mark.parametrize("old_status", ["pending", "sending", "sent", "dead"])
async def test_cutover_reissues_usable_mail_without_copying_obsolete_bodies(
    db_pool, sync_conn, user_factory, kind, old_status
):
    """Keep budgets/history, revoke old codes, then admit and redeem a newly minted code."""
    if kind == "password_reset":
        user = user_factory(totp_secret=encrypt_value(_SECRET))
        email = user.email
        issue = password_reset.request_password_reset
        await issue(db_pool, email=email)
    else:
        email = "setup@example.org"
        await registration_setup.begin_local_registration(db_pool, email=email)
        issue = registration_setup.resend_local_registration

    old_message = _action_mail(sync_conn, kind)[0]
    old_token = _token(old_message, kind)
    sync_conn.execute(
        """UPDATE users SET password_reset_attempt_count = 2,
                  password_reset_attempt_window_started_at = clock_timestamp(),
                  pending_email = 'replacement@example.org',
                  pending_email_token_hash = 'obsolete-change-hash',
                  pending_email_created_at = clock_timestamp()
           WHERE email = %s""",
        (email,),
    )
    sync_conn.execute(
        """UPDATE email_outbox SET status = %(status)s,
                  sent_at = CASE WHEN %(status)s = 'sent' THEN clock_timestamp() END,
                  failed_at = CASE WHEN %(status)s = 'dead' THEN clock_timestamp() END,
                  terminal_outcome = CASE WHEN %(status)s = 'dead' THEN 'delivery_failed' END,
                  locked_at = CASE WHEN %(status)s = 'sending' THEN clock_timestamp() END,
                  lock_token = CASE WHEN %(status)s = 'sending' THEN %(lock)s::uuid END,
                  body_ciphertext = %(body)s
           WHERE id = %(id)s""",
        {
            "status": old_status,
            "lock": uuid4(),
            "body": encrypt_outbox_body("Obsolete action-message format"),
            "id": old_message[0],
        },
    )
    sync_conn.commit()
    before_user = _rows(sync_conn, "users")[0]
    async with get_db_cursor(db_pool) as cursor:
        await enqueue_email_cur(
            cursor,
            user_id=before_user["id"],
            message_type="account_locked_notice",
            recipient=email,
            subject="Notice",
            body="Non-action notice",
            action=None,
        )
    before_mail = _rows(sync_conn, "email_outbox")
    before_issuance = _rows(sync_conn, "anonymous_mail_issuance")

    _invalidate()

    after_user = _rows(sync_conn, "users")[0]
    changed_fields = {
        "password_reset_created_at",
        "email_verification_created_at",
        "pending_email",
        "pending_email_token_hash",
        "pending_email_created_at",
    }
    assert {k: v for k, v in before_user.items() if k not in changed_fields} == {
        k: v for k, v in after_user.items() if k not in changed_fields
    }
    assert all(after_user[name] is None for name in changed_fields if name.startswith("pending_"))
    assert _rows(sync_conn, "anonymous_mail_issuance") == before_issuance
    after_mail = _rows(sync_conn, "email_outbox")
    assert after_mail[1] == before_mail[1]
    if old_status in {"pending", "sending"}:
        assert after_mail[0]["status"] == "dead"
        assert after_mail[0]["terminal_outcome"] == "cancelled"
        assert after_mail[0]["locked_at"] is after_mail[0]["lock_token"] is None
        assert after_mail[0]["body_ciphertext"] == before_mail[0]["body_ciphertext"]
    else:
        assert after_mail[0] == before_mail[0]
    if kind == "password_reset":
        assert not await password_reset.verify_reset_token_hash(
            db_pool, before_user["id"], hash_token(old_token), expected_email=email
        )
    else:
        assert await registration_setup.inspect_local_registration(db_pool, old_token) is None

    _invalidate()
    assert _rows(sync_conn, "users")[0] == after_user
    assert _rows(sync_conn, "email_outbox") == after_mail

    await issue(db_pool, email=email)
    assert len(_action_mail(sync_conn, kind)) == 1  # Existing recipient cooldown still applies.
    sync_conn.execute(
        "UPDATE anonymous_mail_issuance SET created_at = clock_timestamp() - INTERVAL '6 minutes'"
    )
    sync_conn.commit()
    await issue(db_pool, email=email)
    messages = _action_mail(sync_conn, kind)
    assert len(messages) == 2
    new_token = _token(messages[1], kind)
    assert new_token != old_token
    assert messages[1][2] == hash_token(new_token) != old_message[2]
    assert _rows(sync_conn, "users")[0]["password_reset_attempt_count"] == 2
    if kind == "password_reset":
        await password_reset.update_password_with_token(
            db_pool,
            before_user["id"],
            new_token,
            _NEW_PASSWORD,
            expected_email=email,
            totp_code=pyotp.TOTP(_SECRET).now(),
        )
        assert _rows(sync_conn, "users")[0]["password_reset_attempt_count"] == 3
    else:
        completed = await registration_setup.complete_local_registration(
            db_pool, token=new_token, display_name="Mira Cole", password=_NEW_PASSWORD
        )
        assert completed is not None and completed.is_active and completed.email_verified


async def test_cutover_does_not_reopen_a_cancelled_setup(db_pool, sync_conn, user_factory):
    """A missing setup hash stays cancelled rather than becoming anonymously reissuable."""
    user = user_factory(password_hash=None, is_active=False, email_verified=False)
    before = _rows(sync_conn, "users")
    _invalidate()
    await registration_setup.resend_local_registration(db_pool, email=user.email)
    assert _rows(sync_conn, "users") == before
    assert _rows(sync_conn, "email_outbox") == []
    assert _rows(sync_conn, "anonymous_mail_issuance") == []


async def test_mail_lock_failure_rolls_back_capability_invalidation(
    db_pool, sync_conn, user_factory
):
    """A blocked mail cancellation cannot leave only the capability-state changes committed."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    before_users = _rows(sync_conn, "users")
    before_mail = _rows(sync_conn, "email_outbox")
    before_issuance = _rows(sync_conn, "anonymous_mail_issuance")
    with psycopg.connect(TEST_DATABASE_URL) as blocker:
        blocker.execute("SELECT id FROM email_outbox FOR UPDATE")
        with pytest.raises(LockNotAvailable):
            _invalidate()
    assert _rows(sync_conn, "users") == before_users
    assert _rows(sync_conn, "email_outbox") == before_mail
    assert _rows(sync_conn, "anonymous_mail_issuance") == before_issuance
