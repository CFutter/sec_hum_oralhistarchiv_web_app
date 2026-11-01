"""Session-owned enrollment, durable owner notices and idle expiry in PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta

import psycopg
import pyotp
import pytest

from app.services import security_notifications, totp
from app.services.crypto import decrypt_outbox_body
from app.services.session_ids import hash_session_id
from app.services.sessions import create_session, get_session_user
from app.services.tokens import hash_token
from app.services.totp import (
    PendingTotpOutcome,
    PendingTotpPurpose,
    TotpEnrollmentOutcome,
    get_or_create_pending_totp_secret,
    get_pending_totp_secret,
    verify_and_enroll_totp,
)
from app.services.totp_crypto import encrypt_value
from app.services.totp_recover import authorize_totp_recovery, redeem_totp_recovery
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.test_account_database_clock_db import _wait_for_blocked_task


async def _begin(pool, user_id, session):
    """Issue an enrollment challenge bound to the supplied session."""
    return await get_or_create_pending_totp_secret(
        pool, user_id, session_id=session, purpose=PendingTotpPurpose.ENROLLMENT
    )


async def test_separate_sessions_never_share_or_activate_pending_factor_material(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify separate sessions never share or activate pending factor material."""
    user = user_factory()
    creator = session_factory(user.id, purpose="totp_setup")
    other = session_factory(user.id, purpose="totp_setup")
    pending = await _begin(db_pool, user.id, creator)
    assert pending.outcome is PendingTotpOutcome.READY
    assert pending.secret is not None
    original = sync_conn.execute(
        "SELECT pending_totp_secret, pending_totp_recovery_code_generation FROM users WHERE id=%s",
        (user.id,),
    ).fetchone()
    assert (await _begin(db_pool, user.id, other)).outcome is PendingTotpOutcome.INELIGIBLE
    assert (
        await get_pending_totp_secret(
            db_pool, user.id, session_id=other, purpose=PendingTotpPurpose.ENROLLMENT
        )
        is None
    )
    assert (
        await verify_and_enroll_totp(
            db_pool,
            user.id,
            pyotp.TOTP(pending.secret).now(),
            pending.recovery_codes[0],
            session_id=other,
        )
        is TotpEnrollmentOutcome.PENDING_SECRET_MISSING
    )
    assert (
        sync_conn.execute(
            "SELECT pending_totp_secret, pending_totp_recovery_code_generation FROM users WHERE id=%s",
            (user.id,),
        ).fetchone()
        == original
    )
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0


async def test_enrollment_revokes_every_old_bearer_and_queues_one_credential_free_notice(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify enrollment revokes every old bearer and queues one credential free notice."""
    user = user_factory()
    creator = session_factory(user.id, purpose="totp_setup")
    copy = creator
    independent = session_factory(user.id, purpose="totp_setup")
    pending = await _begin(db_pool, user.id, creator)
    assert pending.secret is not None
    code = pyotp.TOTP(pending.secret).now()
    assert (
        await verify_and_enroll_totp(
            db_pool, user.id, code, pending.recovery_codes[0], session_id=creator
        )
        is TotpEnrollmentOutcome.ENROLLED
    )
    for bearer in (creator, copy, independent):
        assert await get_session_user(db_pool, bearer) == (None, None, False)
    rows = sync_conn.execute(
        "SELECT message_type, body_ciphertext, action_token_hash FROM email_outbox"
    ).fetchall()
    assert len(rows) == 1 and rows[0][0] == "totp_enrolled_notice" and rows[0][2] is None
    body = decrypt_outbox_body(rows[0][1])
    assert body is not None
    assert pending.secret not in body and code not in body
    assert not any(saved in body for saved in pending.recovery_codes)
    assert (
        await verify_and_enroll_totp(
            db_pool, user.id, code, pending.recovery_codes[0], session_id=creator
        )
        is TotpEnrollmentOutcome.ALREADY_CONFIGURED
    )
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 1


async def test_notice_and_factor_activation_roll_back_together(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch
):
    """Verify notice and factor activation roll back together."""
    user = user_factory()
    creator = session_factory(user.id, purpose="totp_setup")
    pending = await _begin(db_pool, user.id, creator)
    assert pending.secret is not None

    async def fail_after_enqueue(cur, *, user_id, change):
        """Queue the real security notice, then raise before transaction commit."""
        await security_notifications.queue_security_change_notice_cur(
            cur, user_id=user_id, change=change
        )
        raise RuntimeError("Simulated failure before commit")

    monkeypatch.setattr(totp, "queue_security_change_notice_cur", fail_after_enqueue)
    with pytest.raises(RuntimeError, match="before commit"):
        await verify_and_enroll_totp(
            db_pool,
            user.id,
            pyotp.TOTP(pending.secret).now(),
            pending.recovery_codes[0],
            session_id=creator,
        )
    assert (
        sync_conn.execute("SELECT totp_secret FROM users WHERE id=%s", (user.id,)).fetchone()[0]
        is None
    )
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 1
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0


async def test_expired_creator_does_not_transfer_its_pending_seed(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify expired creator does not transfer its pending seed."""
    user = user_factory()
    creator = session_factory(user.id, purpose="totp_setup")
    other = session_factory(user.id, purpose="totp_setup")
    first = await _begin(db_pool, user.id, creator)
    sync_conn.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=%s",
        (hash_session_id(creator),),
    )
    sync_conn.commit()
    replacement = await _begin(db_pool, user.id, other)
    assert replacement.outcome is PendingTotpOutcome.READY
    assert first.secret != replacement.secret
    assert first.recovery_codes != replacement.recovery_codes


@pytest.mark.parametrize("age", [1800, 1801])
async def test_idle_boundary_never_authenticates_or_revives_a_session(
    db_pool, user_factory, session_factory, sync_conn, age
):
    """Verify idle boundary never authenticates or revives a session."""
    user = user_factory()
    bearer = session_factory(user.id)
    sync_conn.execute(
        "UPDATE sessions SET last_activity_at=clock_timestamp()-%s*INTERVAL '1 second' WHERE id=%s",
        (age, hash_session_id(bearer)),
    )
    sync_conn.commit()
    before = sync_conn.execute(
        "SELECT last_activity_at FROM sessions WHERE id=%s", (hash_session_id(bearer),)
    ).fetchone()[0]
    assert await get_session_user(db_pool, bearer) == (None, None, False)
    assert (
        sync_conn.execute(
            "SELECT last_activity_at FROM sessions WHERE id=%s", (hash_session_id(bearer),)
        ).fetchone()[0]
        == before
    )


async def test_concurrent_activity_is_bounded_and_does_not_extend_absolute_expiry(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify concurrent activity is bounded and does not extend absolute expiry."""
    user = user_factory()
    bearer = session_factory(user.id)
    sync_conn.execute(
        "UPDATE sessions SET last_activity_at=clock_timestamp()-INTERVAL '2 minutes' WHERE id=%s",
        (hash_session_id(bearer),),
    )
    sync_conn.commit()
    before_expiry = sync_conn.execute(
        "SELECT expires_at FROM sessions WHERE id=%s", (hash_session_id(bearer),)
    ).fetchone()[0]
    results = await asyncio.gather(*(get_session_user(db_pool, bearer) for _ in range(6)))
    assert all(result.user is not None for result in results)
    first_touch = sync_conn.execute(
        "SELECT last_activity_at, expires_at, xmin::text FROM sessions WHERE id=%s",
        (hash_session_id(bearer),),
    ).fetchone()
    assert first_touch[1] == before_expiry
    assert first_touch[0] > datetime.now(UTC) - timedelta(seconds=30)
    assert (await get_session_user(db_pool, bearer)).user is not None
    assert (
        sync_conn.execute(
            "SELECT last_activity_at, expires_at, xmin::text FROM sessions WHERE id=%s",
            (hash_session_id(bearer),),
        ).fetchone()
        == first_touch
    )


async def test_partial_sessions_have_a_separate_short_absolute_lifetime(
    db_pool, user_factory, sync_conn
):
    """Verify partial sessions have a separate short absolute lifetime."""
    user = user_factory()
    bearer = await create_session(db_pool, user.id, "127.0.0.1", purpose="totp_setup")
    remaining = sync_conn.execute(
        "SELECT EXTRACT(EPOCH FROM expires_at-clock_timestamp()) FROM sessions WHERE id=%s",
        (hash_session_id(bearer),),
    ).fetchone()[0]
    assert 0 < remaining <= 600


async def test_hardened_service_override_cannot_issue_a_year_long_session(
    db_pool, user_factory, sync_conn, monkeypatch
):
    """Verify hardened service override cannot issue a year long session."""
    user = user_factory()
    monkeypatch.setattr(settings, "env_state", "production")
    with pytest.raises(ValueError, match="eight hours"):
        await create_session(
            db_pool, user.id, "127.0.0.1", purpose="full", max_age_seconds=365 * 24 * 60 * 60
        )
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


async def test_activity_cannot_revive_idle_expiry_after_waiting_for_a_session_lock(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify activity cannot revive idle expiry after waiting for a session lock."""
    user = user_factory()
    bearer = session_factory(user.id)
    identity = hash_session_id(bearer)
    sync_conn.execute(
        """UPDATE sessions SET last_activity_at=clock_timestamp()
            - %s * INTERVAL '1 second' + INTERVAL '3 seconds' WHERE id=%s""",
        (settings.session_idle_timeout_seconds, identity),
    )
    sync_conn.commit()
    async with (
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL) as blocker,
        await psycopg.AsyncConnection.connect(TEST_DATABASE_URL, autocommit=True) as observer,
    ):
        await blocker.execute("SELECT id FROM sessions WHERE id=%s FOR UPDATE", (identity,))
        lookup = asyncio.create_task(get_session_user(db_pool, bearer))
        try:
            await _wait_for_blocked_task(observer, lookup, blocker.info.backend_pid)
            await observer.execute(
                """SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM
                   (last_activity_at + %s * INTERVAL '1 second' - clock_timestamp())),0)+0.05)
                   FROM sessions WHERE id=%s""",
                (settings.session_idle_timeout_seconds, identity),
            )
            await blocker.commit()
            async with asyncio.timeout(5):
                assert await lookup == (None, None, False)
        finally:
            if not lookup.done():
                lookup.cancel()
                await asyncio.gather(lookup, return_exceptions=True)


async def test_recovery_notifies_each_distinct_stage_and_deduplicates_authorization_reissues(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify recovery notifies each distinct stage and deduplicates authorization reissues."""
    actor_secret = pyotp.random_base32()
    actor = user_factory(is_admin=True, totp_secret=encrypt_value(actor_secret))
    actor_session = session_factory(actor.id)
    target = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
    saved_code = "AAAAA-BBBBB-CCCCC-DDDDD"
    sync_conn.execute("UPDATE users SET totp_recovery_code_generation=1 WHERE id=%s", (target.id,))
    sync_conn.execute(
        """INSERT INTO totp_recovery_codes(user_id,generation,position,code_hash)
           VALUES(%s,1,1,%s)""",
        (target.id, hash_token(saved_code.replace("-", ""))),
    )
    sync_conn.commit()
    for seconds in (0, 30):
        result = await authorize_totp_recovery(
            db_pool,
            actor_id=actor.id,
            actor_session_id=actor_session,
            target_user_id=target.id,
            admin_totp_code=pyotp.TOTP(actor_secret).at(
                datetime.now(UTC) + timedelta(seconds=seconds)
            ),
        )
        assert result.reissued is (seconds != 0)
    redeemed = await redeem_totp_recovery(
        db_pool,
        email=target.email,
        password=target.password,
        recovery_code=saved_code,
        ip_address="192.0.2.10",
    )
    pending = await get_or_create_pending_totp_secret(
        db_pool,
        target.id,
        session_id=redeemed.session_id,
        purpose=PendingTotpPurpose.RECOVERY,
    )
    assert pending.secret is not None
    assert (
        await verify_and_enroll_totp(
            db_pool,
            target.id,
            pyotp.TOTP(pending.secret).now(),
            pending.recovery_codes[0],
            session_id=redeemed.session_id,
        )
        is TotpEnrollmentOutcome.RECOVERED
    )
    notices = sync_conn.execute(
        "SELECT message_type,body_ciphertext FROM email_outbox WHERE user_id=%s ORDER BY id",
        (target.id,),
    ).fetchall()
    assert [row[0] for row in notices] == [
        "totp_recovery_authorized_notice",
        "totp_recovery_redeemed_notice",
        "totp_recovery_completed_notice",
    ]
    for _, ciphertext in notices:
        body = decrypt_outbox_body(ciphertext)
        assert body is not None
        assert saved_code not in body and pending.secret not in body
        assert not any(code in body for code in pending.recovery_codes)
