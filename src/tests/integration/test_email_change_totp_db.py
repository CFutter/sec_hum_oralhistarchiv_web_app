"""Fresh TOTP is atomic with self-service email-change staging."""

import asyncio
import time

import pyotp
import pytest

from app.services import email_change
from app.services.session_ids import hash_session_id
from app.services.totp_crypto import encrypt_value


@pytest.mark.parametrize("proof", ["malformed", "wrong", "replayed"])
async def test_email_change_rejects_invalid_or_consumed_totp_without_staging(
    db_pool, sync_conn, user_factory, session_factory, proof
):
    """Verify email change rejects invalid or consumed TOTP without staging."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))
    raw_session = session_factory(user.id, purpose="full")
    code = pyotp.TOTP(secret).now()
    if proof == "malformed":
        code = "not-a-code"
    elif proof == "wrong":
        allowed = {pyotp.TOTP(secret).at(time.time() + 30 * step) for step in range(-2, 4)}
        code = next(f"{value:06d}" for value in range(10) if f"{value:06d}" not in allowed)
    else:
        sync_conn.execute(
            "UPDATE users SET last_totp_step = %s WHERE id = %s",
            (int(time.time()) // 30, user.id),
        )
        sync_conn.commit()
    before = sync_conn.execute(
        "SELECT last_totp_step FROM users WHERE id = %s", (user.id,)
    ).fetchone()

    with pytest.raises(email_change.SelfEmailChangeRejected) as rejected:
        await email_change.stage_self_email_change(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_email="new-address@example.org",
            totp_code=code,
        )

    assert rejected.value.reason == "invalid_totp"
    assert sync_conn.execute(
        "SELECT pending_email, pending_email_token_hash, pending_email_created_at FROM users"
        " WHERE id = %s",
        (user.id,),
    ).fetchone() == (None, None, None)
    assert (
        sync_conn.execute("SELECT last_totp_step FROM users WHERE id = %s", (user.id,)).fetchone()
        == before
    )
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
    assert sync_conn.execute(
        "SELECT step_up_attempt_count FROM sessions WHERE id = %s",
        (hash_session_id(raw_session),),
    ).fetchone() == (1,)


async def test_same_totp_cannot_stage_two_concurrent_email_changes(
    db_pool, sync_conn, user_factory, session_factory
):
    """Verify same TOTP cannot stage two concurrent email changes."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))
    raw_sessions = [session_factory(user.id, purpose="full") for _ in range(2)]
    code = pyotp.TOTP(secret).now()
    results = await asyncio.gather(
        *(
            email_change.stage_self_email_change(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                current_password=user.password,
                new_email=f"new-address-{index}@example.org",
                totp_code=code,
            )
            for index, raw_session in enumerate(raw_sessions)
        ),
        return_exceptions=True,
    )

    successful = [
        result for result in results if isinstance(result, email_change.SelfEmailChangeResult)
    ]
    rejected = [
        result for result in results if isinstance(result, email_change.SelfEmailChangeRejected)
    ]
    assert len(successful) == len(rejected) == 1
    assert rejected[0].reason == "invalid_totp"
    assert sync_conn.execute(
        "SELECT pending_email FROM users WHERE id = %s", (user.id,)
    ).fetchone() == (successful[0].new_email,)
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 2


async def test_staging_failure_rolls_back_totp_consumption(
    db_pool, sync_conn, user_factory, session_factory, monkeypatch
):
    """Verify staging failure rolls back TOTP consumption."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))
    raw_session = session_factory(user.id, purpose="full")
    code = pyotp.TOTP(secret).now()
    real_enqueue = email_change.enqueue_outbound_email_cur
    calls = 0

    async def fail_second_enqueue(cur, *, user_id, email, action):
        """Raise on the second enqueue and delegate earlier messages to the real writer."""
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("outbox insert unavailable")
        return await real_enqueue(cur, user_id=user_id, email=email, action=action)

    monkeypatch.setattr(email_change, "enqueue_outbound_email_cur", fail_second_enqueue)
    with pytest.raises(RuntimeError, match="outbox insert unavailable"):
        await email_change.stage_self_email_change(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_email="new-address@example.org",
            totp_code=code,
        )

    assert sync_conn.execute(
        "SELECT last_totp_step, pending_email FROM users WHERE id = %s", (user.id,)
    ).fetchone() == (None, None)
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
    monkeypatch.setattr(email_change, "enqueue_outbound_email_cur", real_enqueue)
    result = await email_change.stage_self_email_change(
        db_pool,
        user_id=user.id,
        session_id=raw_session,
        current_password=user.password,
        new_email="new-address@example.org",
        totp_code=code,
    )
    assert result.new_email == "new-address@example.org"


async def test_administrator_must_use_protected_self_email_change(
    db_pool, sync_conn, user_factory, session_factory
):
    """Verify administrator must use protected self email change."""
    admin = user_factory(is_admin=True)
    raw_session = session_factory(admin.id, purpose="full")

    with pytest.raises(email_change.AdminEmailChangeRejected) as rejected:
        await email_change.stage_admin_email_change(
            db_pool,
            actor_id=admin.id,
            actor_session_id=raw_session,
            target_user_id=admin.id,
            new_email="new-admin-address@example.org",
        )

    assert rejected.value.reason == "self_change"
    assert sync_conn.execute(
        "SELECT email, pending_email FROM users WHERE id = %s", (admin.id,)
    ).fetchone() == (admin.email, None)
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
