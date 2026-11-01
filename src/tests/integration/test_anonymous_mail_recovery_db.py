"""Cross-worker mail admission and protected recovery against real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import pyotp
import pytest

from app.services import mail_issuance, password_reset, registration_setup
from app.services.authentication import record_login_failure_cur, verify_password
from app.services.crypto import decrypt_outbox_body
from app.services.db import get_db_cursor
from app.services.password_reset import InvalidResetToken, InvalidResetTotp
from app.services.session_ids import hash_session_id
from app.services.sessions import get_session_user
from app.services.tokens import hash_token
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.action_links import token_from_action_email

_SECRET = "JBSWY3DPEHPK3PXP"


def _messages(connection, kind="password_reset"):
    """Read and commit action-email rows of the requested message type in ID order."""
    rows = connection.execute(
        """SELECT id, body_ciphertext, action_token_hash, created_at
           FROM email_outbox WHERE message_type = %s ORDER BY id""",
        (kind,),
    ).fetchall()
    connection.commit()
    return rows


def _age_issuance(connection, minutes):
    """Backdate all issuance and outbox rows by minutes without committing."""
    connection.execute(
        "UPDATE anonymous_mail_issuance SET created_at = clock_timestamp() - %s * INTERVAL '1 minute'",
        (minutes,),
    )
    connection.execute(
        "UPDATE email_outbox SET created_at = clock_timestamp() - %s * INTERVAL '1 minute'",
        (minutes,),
    )


def _token(connection, kind="password_reset"):
    """Decrypt the newest action email of the requested kind and return its token."""
    rows = _messages(connection, kind)
    assert rows
    body = decrypt_outbox_body(rows[-1][1])
    assert body is not None
    path = "/reset-password/" if kind == "password_reset" else "/verify-email/"
    link = next(
        line.strip() for line in body.splitlines() if settings.public_base_url + path in line
    )
    return token_from_action_email(body, link)


def _reset_state(connection, user_id):
    """Read the user's password-reset token and issuance state."""
    result = connection.execute(
        """SELECT password_reset_token_hash, password_reset_created_at,
                  password_reset_attempt_count, password_reset_attempt_window_started_at,
                  password_hash, failed_login_count, locked_until
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()
    connection.commit()
    return result


async def test_many_request_origins_preserve_one_live_reset_capability(
    db_pool, sync_conn, user_factory
):
    """Verify many request origins preserve one live reset capability."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    sync_conn.execute(
        """UPDATE users SET password_reset_attempt_count = 2,
                  password_reset_attempt_window_started_at = clock_timestamp()
           WHERE id = %s""",
        (user.id,),
    )
    # Move delivery history beyond the cooldown without expiring the capability,
    # proving preservation independently from the issuance admission decision.
    _age_issuance(sync_conn, 6)
    sync_conn.commit()
    before = _reset_state(sync_conn, user.id)
    await asyncio.gather(
        *(
            password_reset.request_password_reset(db_pool, email=user.email.upper())
            for _ in range(20)
        )
    )
    assert _reset_state(sync_conn, user.id) == before
    assert len(_messages(sync_conn)) == 1
    assert await password_reset.verify_reset_token_hash(
        db_pool, user.id, hash_token(token), expected_email=user.email
    )


async def test_concurrent_new_registration_cannot_exceed_shared_global_mail_budget(
    db_pool, sync_conn, monkeypatch
):
    """Verify concurrent new registration cannot exceed shared global mail budget."""
    monkeypatch.setattr(mail_issuance, "ANONYMOUS_MAIL_GLOBAL_HOURLY_LIMIT", 3)
    await asyncio.gather(
        *(
            registration_setup.begin_local_registration(
                db_pool, email=f"recipient{index}@example.org"
            )
            for index in range(15)
        )
    )
    assert 1 <= len(_messages(sync_conn, "email_verification")) <= 3
    # Contended callers may be conservatively refused. Independent later calls
    # prove unused capacity is available and the fixed budget is the final bound.
    for index in range(4):
        await registration_setup.begin_local_registration(
            db_pool, email=f"later{index}@example.org"
        )
    assert len(_messages(sync_conn, "email_verification")) == 3
    assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 3
    sync_conn.commit()


async def test_account_and_cascaded_outbox_deletion_cannot_refund_mail_allowances(
    db_pool, sync_conn, monkeypatch
):
    """Verify account and cascaded outbox deletion cannot refund mail allowances."""
    monkeypatch.setattr(mail_issuance, "ANONYMOUS_MAIL_GLOBAL_DAILY_LIMIT", 2)
    email = "owned-address@example.org"
    await registration_setup.begin_local_registration(db_pool, email=email)
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 1
    sync_conn.execute("DELETE FROM users WHERE email = %s", (email,))
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
    assert sync_conn.execute("SELECT count(*) FROM anonymous_mail_issuance").fetchone()[0] == 1
    sync_conn.commit()

    # The same address is still cooling down even though its account and mail
    # were deleted, as happens when replacing a pending federation reservation.
    await registration_setup.begin_local_registration(db_pool, email=email.upper())
    assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    sync_conn.commit()
    _age_issuance(sync_conn, 6)
    sync_conn.commit()
    await registration_setup.begin_local_registration(db_pool, email=email)
    sync_conn.execute("DELETE FROM users WHERE email = %s", (email,))
    sync_conn.commit()

    # Deleting both accounts cannot restore global capacity for a new address.
    await registration_setup.begin_local_registration(db_pool, email="different@example.org")
    assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
    rows = sync_conn.execute("SELECT recipient_key FROM anonymous_mail_issuance").fetchall()
    assert rows == [(mail_issuance._recipient_key(email),)] * 2
    assert email not in repr(rows)
    sync_conn.commit()


async def test_issuance_cleanup_is_bounded_and_unknown_addresses_create_no_state(
    db_pool, sync_conn, user_factory
):
    """Verify issuance cleanup is bounded and unknown addresses create no state."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    sync_conn.execute(
        """INSERT INTO anonymous_mail_issuance (id, recipient_key, created_at)
           SELECT gen_random_uuid(), repeat('a', 64), clock_timestamp() - INTERVAL '25 hours'
           FROM generate_series(1, 205)"""
    )
    sync_conn.commit()
    for expected in (106, 6, 1):
        await password_reset.request_password_reset(db_pool, email="unknown@example.org")
        assert (
            sync_conn.execute("SELECT count(*) FROM anonymous_mail_issuance").fetchone()[0]
            == expected
        )
        sync_conn.commit()
    assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 1
    assert len(_messages(sync_conn)) == 1


async def test_duplicate_and_live_resend_cannot_generate_mail_or_replace_setup(db_pool, sync_conn):
    """Verify duplicate and live resend cannot generate mail or replace setup."""
    email = "pending@example.org"
    await registration_setup.begin_local_registration(db_pool, email=email)
    original_token = _token(sync_conn, "email_verification")
    before = sync_conn.execute(
        "SELECT email_verification_token_hash, email_verification_created_at FROM users"
    ).fetchone()
    _age_issuance(sync_conn, 6)
    sync_conn.commit()
    await asyncio.gather(
        *(
            function(db_pool, email=email.upper())
            for function in [
                registration_setup.begin_local_registration,
                registration_setup.resend_local_registration,
            ]
            * 8
        )
    )
    assert len(_messages(sync_conn, "email_verification")) == 1
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 1
    assert (
        sync_conn.execute(
            "SELECT email_verification_token_hash, email_verification_created_at FROM users"
        ).fetchone()
        == before
    )
    sync_conn.commit()
    assert await registration_setup.inspect_local_registration(db_pool, original_token) is not None


async def test_expired_reset_can_be_replaced_without_refunding_proof_budget(
    db_pool, sync_conn, user_factory
):
    """Verify expired reset can be replaced without refunding proof budget."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    old = _token(sync_conn)
    sync_conn.execute(
        """UPDATE users SET password_reset_created_at = clock_timestamp() - INTERVAL '31 minutes',
                  password_reset_attempt_count = 3,
                  password_reset_attempt_window_started_at = clock_timestamp()
           WHERE id = %s""",
        (user.id,),
    )
    _age_issuance(sync_conn, 31)
    sync_conn.commit()
    await password_reset.request_password_reset(db_pool, email=user.email)
    new = _token(sync_conn)
    assert new != old and _reset_state(sync_conn, user.id)[2] == 3
    assert not await password_reset.verify_reset_token_hash(
        db_pool, user.id, hash_token(old), expected_email=user.email
    )


@pytest.mark.parametrize("kind", ["password_reset", "email_verification"])
async def test_bounded_resend_reuses_delivered_ciphertext_and_original_expiry(
    db_pool, sync_conn, user_factory, kind
):
    """Verify bounded resend reuses delivered ciphertext and original expiry."""
    if kind == "password_reset":
        user = user_factory(totp_secret=encrypt_value(_SECRET))
        email = user.email
        issue = password_reset.request_password_reset
    else:
        email = "resend@example.org"
        await registration_setup.begin_local_registration(db_pool, email=email)
        issue = registration_setup.resend_local_registration
    if kind == "password_reset":
        await issue(db_pool, email=email)
    original = sync_conn.execute(
        """SELECT body_ciphertext, action_token_hash, expires_at
           FROM email_outbox WHERE message_type = %s""",
        (kind,),
    ).fetchone()
    sync_conn.execute(
        """UPDATE email_outbox SET status = 'sent', sent_at = clock_timestamp(),
                  created_at = clock_timestamp() - INTERVAL '6 minutes'"""
    )
    _age_issuance(sync_conn, 6)
    sync_conn.commit()
    await asyncio.gather(*(issue(db_pool, email=email) for _ in range(12)))
    rows = sync_conn.execute(
        """SELECT body_ciphertext, action_token_hash, expires_at
           FROM email_outbox WHERE message_type = %s ORDER BY id""",
        (kind,),
    ).fetchall()
    sync_conn.commit()
    assert rows == [original, original]


async def test_failed_and_cancelled_mail_still_spends_the_shared_issuance_budget(
    db_pool, sync_conn, user_factory, monkeypatch
):
    """Verify failed and cancelled mail still spends the shared issuance budget."""
    monkeypatch.setattr(mail_issuance, "ANONYMOUS_MAIL_GLOBAL_HOURLY_LIMIT", 1)
    first = user_factory(totp_secret=encrypt_value(_SECRET))
    second = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=first.email)
    sync_conn.execute(
        """UPDATE email_outbox SET status = 'dead', failed_at = clock_timestamp(),
                  terminal_outcome = 'cancelled'"""
    )
    sync_conn.commit()
    await password_reset.request_password_reset(db_pool, email=second.email)
    assert len(_messages(sync_conn)) == 1
    assert _reset_state(sync_conn, second.id)[0] is None


async def test_retained_resends_cannot_exceed_the_recipient_hourly_budget(
    db_pool, sync_conn, user_factory, monkeypatch
):
    """Verify retained resends cannot exceed the recipient hourly budget."""
    monkeypatch.setattr(mail_issuance, "ANONYMOUS_MAIL_RECIPIENT_HOURLY_LIMIT", 2)
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    for _ in range(4):
        sync_conn.execute(
            """UPDATE email_outbox SET status = 'sent', sent_at = clock_timestamp(),
                      created_at = clock_timestamp() - INTERVAL '6 minutes'"""
        )
        _age_issuance(sync_conn, 6)
        sync_conn.commit()
        await password_reset.request_password_reset(db_pool, email=user.email)
    assert len(_messages(sync_conn)) == 2


async def test_issuance_failure_rolls_back_capability_and_mail(
    db_pool, sync_conn, user_factory, monkeypatch
):
    """Verify issuance failure rolls back capability and mail."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    monkeypatch.setattr(
        password_reset,
        "enqueue_outbound_email_cur",
        create_autospec(
            password_reset.enqueue_outbound_email_cur, side_effect=RuntimeError("queue failed")
        ),
    )
    with pytest.raises(RuntimeError, match="queue failed"):
        await password_reset.request_password_reset(db_pool, email=user.email)
    assert _reset_state(sync_conn, user.id)[0] is None
    assert not _messages(sync_conn)
    assert sync_conn.execute("SELECT count(*) FROM anonymous_mail_issuance").fetchone()[0] == 0
    sync_conn.commit()


@pytest.mark.parametrize("flow", ["reset", "registration"])
async def test_ledger_failure_rolls_back_actual_enqueue_and_capability(
    db_pool, sync_conn, user_factory, monkeypatch, flow
):
    """Verify ledger failure rolls back actual enqueue and capability."""
    if flow == "reset":
        user = user_factory(totp_secret=encrypt_value(_SECRET))
        email = user.email
        module, issue = password_reset, password_reset.request_password_reset
    else:
        email = "new-owner@example.org"
        module, issue = registration_setup, registration_setup.begin_local_registration
    monkeypatch.setattr(
        module,
        "record_mail_issuance_cur",
        create_autospec(
            module.record_mail_issuance_cur, side_effect=RuntimeError("ledger unavailable")
        ),
    )
    with pytest.raises(RuntimeError, match="ledger unavailable"):
        await issue(db_pool, email=email)
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
    assert sync_conn.execute("SELECT count(*) FROM anonymous_mail_issuance").fetchone()[0] == 0
    if flow == "reset":
        assert _reset_state(sync_conn, user.id)[0] is None
    else:
        assert sync_conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    sync_conn.commit()


async def test_locked_owner_can_consume_mailbox_and_totp_proof_without_password_change(
    db_pool, sync_conn, user_factory, session_factory
):
    """Verify locked owner can consume mailbox and TOTP proof without password change."""
    user = user_factory(
        totp_secret=encrypt_value(_SECRET),
        failed_login_count=10,
        locked_until=datetime.now(UTC) + timedelta(hours=1),
    )
    old_session = session_factory(user.id)
    before_password = _reset_state(sync_conn, user.id)[4]
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    fresh_session = await password_reset.unlock_account_with_token(
        db_pool,
        user.id,
        token,
        expected_email=user.email,
        totp_code=pyotp.TOTP(_SECRET).now(),
        ip_address="192.0.2.8",
    )
    state = _reset_state(sync_conn, user.id)
    assert state[0] is None and state[4] == before_password and state[5:] == (0, None)
    assert (await get_session_user(db_pool, old_session)).user is None
    current = await get_session_user(db_pool, fresh_session)
    assert current.user is not None and current.user.id == user.id and current.purpose == "full"
    assert sync_conn.execute(
        "SELECT id FROM sessions WHERE user_id = %s", (user.id,)
    ).fetchall() == [(hash_session_id(fresh_session),)]
    sync_conn.commit()
    with pytest.raises(InvalidResetToken):
        await password_reset.unlock_account_with_token(
            db_pool,
            user.id,
            token,
            expected_email=user.email,
            totp_code=pyotp.TOTP(_SECRET).now(),
            ip_address="192.0.2.9",
        )


async def test_unlock_proof_attempts_are_durable_and_cannot_be_refunded_by_rerequest(
    db_pool, sync_conn, user_factory
):
    """Verify unlock proof attempts are durable and cannot be refunded by rerequest."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    kwargs = {"expected_email": user.email, "totp_code": "not-a-code", "ip_address": "192.0.2.9"}
    for attempt in range(5):
        with pytest.raises(InvalidResetTotp):
            await password_reset.unlock_account_with_token(db_pool, user.id, token, **kwargs)
        assert _reset_state(sync_conn, user.id)[2] == attempt + 1
        await password_reset.request_password_reset(db_pool, email=user.email)
    with pytest.raises(InvalidResetToken):
        await password_reset.unlock_account_with_token(
            db_pool, user.id, token, **{**kwargs, "totp_code": pyotp.TOTP(_SECRET).now()}
        )
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    sync_conn.commit()


async def test_failed_unlock_session_insert_does_not_consume_successful_proofs(
    db_pool, sync_conn, user_factory, monkeypatch
):
    """Verify failed unlock session insert does not consume successful proofs."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    monkeypatch.setattr(
        password_reset,
        "create_session_cur",
        create_autospec(
            password_reset.create_session_cur, side_effect=RuntimeError("insert failed")
        ),
    )
    with pytest.raises(RuntimeError, match="insert failed"):
        await password_reset.unlock_account_with_token(
            db_pool,
            user.id,
            token,
            expected_email=user.email,
            totp_code=pyotp.TOTP(_SECRET).now(),
            ip_address="192.0.2.9",
        )
    assert _reset_state(sync_conn, user.id)[0] == hash_token(token)
    assert _reset_state(sync_conn, user.id)[2] == 1
    assert (
        sync_conn.execute("SELECT last_totp_step FROM users WHERE id = %s", (user.id,)).fetchone()[
            0
        ]
        is None
    )
    sync_conn.commit()


@pytest.mark.parametrize("change", ["revision", "deactivated", "expired", "email"])
async def test_unlock_rechecks_account_and_capability_after_attempt_reservation(
    db_pool, sync_conn, user_factory, monkeypatch, change
):
    """Verify unlock rechecks account and capability after attempt reservation."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    real_reservation = password_reset._reserve_reset_attempt

    async def changed_after_reservation(*args, **kwargs):
        """Mutate account authority after anonymous-mail reservation to exercise its recheck."""
        snapshot = await real_reservation(*args, **kwargs)
        if change == "revision":
            statement = "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s"
        elif change == "deactivated":
            statement = "UPDATE users SET is_active = false WHERE id = %s"
        elif change == "expired":
            statement = (
                "UPDATE users SET password_reset_created_at = clock_timestamp() "
                "- INTERVAL '31 minutes' WHERE id = %s"
            )
        else:
            statement = "UPDATE users SET email = 'changed@example.org' WHERE id = %s"
        sync_conn.execute(statement, (user.id,))
        sync_conn.commit()
        return snapshot

    monkeypatch.setattr(password_reset, "_reserve_reset_attempt", changed_after_reservation)
    with pytest.raises(InvalidResetToken):
        await password_reset.unlock_account_with_token(
            db_pool,
            user.id,
            token,
            expected_email=user.email,
            totp_code=pyotp.TOTP(_SECRET).now(),
            ip_address="192.0.2.9",
        )
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    assert (
        sync_conn.execute("SELECT last_totp_step FROM users WHERE id = %s", (user.id,)).fetchone()[
            0
        ]
        is None
    )
    sync_conn.commit()


async def test_simultaneous_unlock_forms_have_one_session_winner(db_pool, sync_conn, user_factory):
    """Verify simultaneous unlock forms have one session winner."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    await password_reset.request_password_reset(db_pool, email=user.email)
    token = _token(sync_conn)
    outcomes = await asyncio.gather(
        *(
            password_reset.unlock_account_with_token(
                db_pool,
                user.id,
                token,
                expected_email=user.email,
                totp_code=pyotp.TOTP(_SECRET).now(),
                ip_address=f"192.0.2.{index}",
            )
            for index in (1, 2)
        ),
        return_exceptions=True,
    )
    assert len([outcome for outcome in outcomes if isinstance(outcome, str)]) == 1
    assert len([outcome for outcome in outcomes if isinstance(outcome, InvalidResetToken)]) == 1
    assert (
        sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone()[0]
        == 1
    )
    sync_conn.commit()


async def test_username_failures_still_trip_the_account_wide_login_bound(db_pool, user_factory):
    """Verify username failures still trip the account wide login bound."""
    user = user_factory(totp_secret=encrypt_value(_SECRET))
    async with get_db_cursor(db_pool) as cur:
        for _ in range(settings.login_failure_threshold):
            await record_login_failure_cur(cur, user.id, expected_auth_revision=0)
    check = await verify_password(db_pool, user.email, user.password)
    assert not check.password_ok and check.locked_until is not None
