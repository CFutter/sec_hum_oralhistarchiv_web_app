"""Password change proves credentials and commits revocation with its notice."""

import asyncio
from types import SimpleNamespace
from unittest.mock import create_autospec

import pyotp
import pytest

from app.services import password_change, password_verification, totp
from app.services.crypto import password_hasher
from app.services.password_change import PasswordChangeRejected, change_password
from app.services.session_ids import hash_session_id
from app.services.totp import verify_and_consume_totp
from app.services.totp_crypto import encrypt_value
from config import settings

pytestmark = pytest.mark.integration
_NEW_PASSWORD = "Frosted-Canyons-739!River"
_TOTP_TIME = 1_770_000_000


@pytest.fixture(autouse=True)
def _fixed_totp_clock(monkeypatch):
    """Freeze the TOTP service's wall clock at the test instant."""
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: _TOTP_TIME))


def _user_with_factor(user_factory, **overrides):
    """Create a user with an encrypted TOTP factor and return the user and plaintext seed."""
    secret = pyotp.random_base32()
    return user_factory(totp_secret=encrypt_value(secret), **overrides), secret


def _code(secret):
    """Generate the seed's TOTP code at the frozen test instant."""
    return pyotp.TOTP(secret).at(_TOTP_TIME)


def _state(conn, user_id):
    """Read the user credential, pending-action and lock fields as a row tuple, or None."""
    return conn.execute(
        """SELECT password_hash, auth_revision, last_totp_step,
                  pending_email, pending_email_token_hash, password_reset_token_hash,
                  pending_totp_secret, totp_secret, failed_login_count, locked_until
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


def _attempt_count(conn, raw_session):
    """Read the presented session's durable step-up attempt count."""
    return conn.execute(
        "SELECT step_up_attempt_count FROM sessions WHERE id = %s",
        (hash_session_id(raw_session),),
    ).fetchone()[0]


def _pending_notice_count(conn, user_id):
    """Count stored password-change notices for the user."""
    return conn.execute(
        "SELECT count(*) FROM email_outbox WHERE user_id = %s AND message_type = 'password_changed_notice'",
        (user_id,),
    ).fetchone()[0]


async def test_success_replaces_password_consumes_factor_and_revokes_pending_authority(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify success replaces password consumes factor and revokes pending authority."""
    user, secret = _user_with_factor(user_factory)
    raw_session = session_factory(user.id)
    session_factory(user.id)
    bystander = user_factory()
    bystander_session = session_factory(bystander.id)
    sync_conn.execute(
        """UPDATE users
           SET pending_email = 'pending@example.org', pending_email_token_hash = %s,
               pending_email_created_at = clock_timestamp(), password_reset_token_hash = %s,
               password_reset_created_at = clock_timestamp(), pending_totp_secret = %s,
               pending_totp_created_at = clock_timestamp(), totp_recovery_code_generation = 1,
               failed_login_count = 1
           WHERE id = %s""",
        ("e" * 64, "r" * 64, encrypt_value(pyotp.random_base32()), user.id),
    )
    sync_conn.execute(
        """INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
           VALUES (%s, 1, 1, %s)""",
        (user.id, "c" * 64),
    )
    sync_conn.execute(
        """INSERT INTO pending_totp_rotations
               (user_id, session_id, auth_revision, encrypted_secret, expires_at)
           VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')""",
        (user.id, hash_session_id(raw_session), encrypt_value(pyotp.random_base32())),
    )
    sync_conn.execute(
        """INSERT INTO email_outbox
               (user_id, message_type, recipient, subject, body_ciphertext, action_token_hash, expires_at)
           VALUES (%s, 'password_reset', %s, 'Reset', 'ciphertext', %s,
                   clock_timestamp() + INTERVAL '30 minutes')""",
        (user.id, user.email, "r" * 64),
    )
    sync_conn.commit()
    before = _state(sync_conn, user.id)

    await change_password(
        db_pool,
        user_id=user.id,
        session_id=raw_session,
        current_password=user.password,
        new_password=_NEW_PASSWORD,
        totp_code=_code(secret),
    )

    after = _state(sync_conn, user.id)
    assert after[0] != before[0]
    assert password_hasher.verify(after[0], _NEW_PASSWORD)
    assert after[1] == before[1] + 1
    assert after[2] == _TOTP_TIME // 30
    assert after[3:7] == (None, None, None, None)
    assert after[7] == before[7]  # Changing the password must preserve the enrolled factor.
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
    ).fetchone() == (0,)
    assert sync_conn.execute(
        "SELECT count(*) FROM pending_totp_rotations WHERE user_id = %s", (user.id,)
    ).fetchone() == (0,)
    assert sync_conn.execute(
        "SELECT count(*) FROM totp_recovery_codes WHERE user_id = %s AND generation = 1", (user.id,)
    ).fetchone() == (1,)
    assert sync_conn.execute(
        "SELECT status, terminal_outcome FROM email_outbox WHERE user_id = %s AND message_type = 'password_reset'",
        (user.id,),
    ).fetchone() == ("dead", "cancelled")
    notice = sync_conn.execute(
        "SELECT recipient, action_token_hash, expires_at, status FROM email_outbox WHERE user_id = %s AND message_type = 'password_changed_notice'",
        (user.id,),
    ).fetchall()
    assert notice == [(user.email, None, None, "pending")]
    assert sync_conn.execute(
        "SELECT 1 FROM sessions WHERE id = %s", (hash_session_id(bystander_session),)
    ).fetchone() == (1,)


@pytest.mark.parametrize("proof", ["password", "totp", "replayed_totp"])
async def test_invalid_proof_spends_attempt_without_changing_credentials(
    db_pool, user_factory, session_factory, sync_conn, proof
):
    """Verify invalid proof spends attempt without changing credentials."""
    user, secret = _user_with_factor(user_factory)
    raw_session = session_factory(user.id)
    code = _code(secret)
    if proof == "replayed_totp":
        assert await verify_and_consume_totp(db_pool, user.id, code)
    before = _state(sync_conn, user.id)
    with pytest.raises(PasswordChangeRejected) as rejected:
        await change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password="incorrect-password" if proof == "password" else user.password,
            new_password=_NEW_PASSWORD,
            totp_code="not-a-code" if proof == "totp" else code,
        )
    assert rejected.value.reason == ("invalid_password" if proof == "password" else "invalid_totp")
    assert _state(sync_conn, user.id) == before
    assert _attempt_count(sync_conn, raw_session) == 1
    assert _pending_notice_count(sync_conn, user.id) == 0


@pytest.mark.parametrize("password_kind", ["weak", "reused"])
async def test_password_policy_failure_preserves_credentials_and_totp(
    db_pool, user_factory, session_factory, sync_conn, password_kind
):
    """Verify password policy failure preserves credentials and TOTP."""
    user, secret = _user_with_factor(user_factory, password="Golden-cedars-482!Cloud")
    raw_session = session_factory(user.id)
    before = _state(sync_conn, user.id)
    with pytest.raises(PasswordChangeRejected) as rejected:
        await change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_password="short" if password_kind == "weak" else user.password,
            totp_code=_code(secret),
        )
    assert rejected.value.reason == (
        "password_policy" if password_kind == "weak" else "password_reused"
    )
    assert _state(sync_conn, user.id) == before
    assert _pending_notice_count(sync_conn, user.id) == 0


async def test_exhaustion_expires_only_the_presented_session(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch
):
    """Verify exhaustion expires only the presented session."""
    monkeypatch.setattr(settings, "session_step_up_attempt_limit", 1)
    user, secret = _user_with_factor(user_factory)
    raw_session = session_factory(user.id)
    other_session = session_factory(user.id)
    before = _state(sync_conn, user.id)
    for password, reason in (
        ("incorrect-password", "invalid_password"),
        (user.password, "step_up_exhausted"),
    ):
        with pytest.raises(PasswordChangeRejected, match=reason):
            await change_password(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                current_password=password,
                new_password=_NEW_PASSWORD,
                totp_code=_code(secret),
            )
    assert _state(sync_conn, user.id) == before
    assert sync_conn.execute(
        "SELECT expires_at <= clock_timestamp() FROM sessions WHERE id = %s",
        (hash_session_id(raw_session),),
    ).fetchone() == (True,)
    assert sync_conn.execute(
        "SELECT expires_at > clock_timestamp() FROM sessions WHERE id = %s",
        (hash_session_id(other_session),),
    ).fetchone() == (True,)


@pytest.mark.parametrize(
    "state", ["totp_setup", "totp_recovery", "expired", "wrong_owner", "missing"]
)
async def test_change_requires_the_exact_active_full_session(
    db_pool, user_factory, session_factory, sync_conn, state
):
    """Verify change requires the exact active full session."""
    user, secret = _user_with_factor(user_factory)
    owner = user_factory() if state == "wrong_owner" else user
    raw_session = (
        "missing-session"
        if state == "missing"
        else session_factory(
            owner.id,
            purpose=state if state in {"totp_setup", "totp_recovery"} else "full",
            expires_in_seconds=-1 if state == "expired" else 3600,
        )
    )
    before = _state(sync_conn, user.id)
    with pytest.raises(PasswordChangeRejected, match="invalid_session"):
        await change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_password=_NEW_PASSWORD,
            totp_code=_code(secret),
        )
    assert _state(sync_conn, user.id) == before
    assert _pending_notice_count(sync_conn, user.id) == 0


@pytest.mark.parametrize("state", ["federated", "unverified", "no_factor", "recovery_required"])
async def test_ineligible_accounts_cannot_change_a_local_password(
    db_pool, user_factory, session_factory, sync_conn, state
):
    """Verify ineligible accounts cannot change a local password."""
    overrides = {
        "federated": {"auth_method": "shibboleth"},
        "unverified": {"email_verified": False},
        "no_factor": {"totp_secret": None},
        "recovery_required": {"totp_secret": None, "totp_recovery_required": True},
    }[state]
    secret = pyotp.random_base32()
    user = user_factory(**{"totp_secret": encrypt_value(secret), **overrides})
    raw_session = session_factory(user.id)
    before = _state(sync_conn, user.id)
    with pytest.raises(PasswordChangeRejected, match="ineligible_account"):
        await change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_password=_NEW_PASSWORD,
            totp_code=_code(secret),
        )
    assert _state(sync_conn, user.id) == before


async def test_notice_storage_failure_rolls_back_password_factor_and_revocation(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch
):
    """Verify notice storage failure rolls back password factor and revocation."""
    user, secret = _user_with_factor(user_factory)
    raw_session = session_factory(user.id)
    sync_conn.execute(
        """UPDATE users SET pending_email = 'pending@example.org',
               pending_email_token_hash = %s, pending_email_created_at = clock_timestamp(),
               password_reset_token_hash = %s, password_reset_created_at = clock_timestamp()
           WHERE id = %s""",
        ("e" * 64, "r" * 64, user.id),
    )
    sync_conn.execute(
        """INSERT INTO email_outbox
               (user_id, message_type, recipient, subject, body_ciphertext, action_token_hash, expires_at)
           VALUES (%s, 'password_reset', %s, 'Reset', 'ciphertext', %s,
                   clock_timestamp() + INTERVAL '30 minutes')""",
        (user.id, user.email, "r" * 64),
    )
    sync_conn.commit()
    before = _state(sync_conn, user.id)
    real_enqueue = password_change.enqueue_outbound_email_cur
    monkeypatch.setattr(
        password_change,
        "enqueue_outbound_email_cur",
        create_autospec(real_enqueue, side_effect=RuntimeError("outbox unavailable")),
    )
    with pytest.raises(RuntimeError, match="outbox unavailable"):
        await change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_password=_NEW_PASSWORD,
            totp_code=_code(secret),
        )
    assert _state(sync_conn, user.id) == before
    assert _attempt_count(sync_conn, raw_session) == 1
    assert _pending_notice_count(sync_conn, user.id) == 0
    assert sync_conn.execute(
        "SELECT status FROM email_outbox WHERE user_id = %s AND message_type = 'password_reset'",
        (user.id,),
    ).fetchone() == ("pending",)


@pytest.mark.parametrize(
    "mutation",
    [
        "revision",
        "password",
        "session",
        "expired",
        pytest.param("idle_expired", marks=pytest.mark.known_defect),
        "deactivated",
        "locked",
    ],
)
async def test_authority_is_rechecked_after_real_password_work_releases_connection(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch, mutation
):
    """Verify authority is rechecked after real password work releases connection."""
    user, secret = _user_with_factor(user_factory)
    raw_session = session_factory(user.id)
    verified, resume = asyncio.Event(), asyncio.Event()
    real_password_work = password_verification.run_password_work

    async def pause_after_password_work(*args, **kwargs):
        """Complete real password work, signal readiness and hold its result until released."""
        result = await real_password_work(*args, **kwargs)
        verified.set()
        await resume.wait()
        return result

    monkeypatch.setattr(
        password_verification,
        "run_password_work",
        create_autospec(real_password_work, side_effect=pause_after_password_work),
    )
    task = asyncio.create_task(
        change_password(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            current_password=user.password,
            new_password=_NEW_PASSWORD,
            totp_code=_code(secret),
        )
    )
    try:
        await asyncio.wait_for(verified.wait(), timeout=10)
        sync_conn.execute("SET LOCAL statement_timeout = '2s'")
        if mutation == "revision":
            sync_conn.execute(
                "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s", (user.id,)
            )
        elif mutation == "password":
            sync_conn.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (password_hasher.hash("Other-secure-password-991!"), user.id),
            )
        elif mutation == "session":
            sync_conn.execute("DELETE FROM sessions WHERE id = %s", (hash_session_id(raw_session),))
        elif mutation == "expired":
            sync_conn.execute(
                "UPDATE sessions SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = %s",
                (hash_session_id(raw_session),),
            )
        elif mutation == "idle_expired":
            sync_conn.execute(
                """UPDATE sessions
                   SET last_activity_at = clock_timestamp() - %s * INTERVAL '1 second'
                   WHERE id = %s""",
                (settings.session_idle_timeout_seconds + 30, hash_session_id(raw_session)),
            )
        elif mutation == "deactivated":
            sync_conn.execute("UPDATE users SET is_active = false WHERE id = %s", (user.id,))
        else:
            sync_conn.execute(
                "UPDATE users SET locked_until = clock_timestamp() + INTERVAL '1 hour', failed_login_count = 1 WHERE id = %s",
                (user.id,),
            )
        sync_conn.commit()
        expected = _state(sync_conn, user.id)
        if mutation == "idle_expired":
            assert sync_conn.execute(
                """SELECT expires_at > clock_timestamp(),
                          last_activity_at <= clock_timestamp() - %s * INTERVAL '1 second'
                   FROM sessions WHERE id = %s""",
                (settings.session_idle_timeout_seconds, hash_session_id(raw_session)),
            ).fetchone() == (True, True)
    finally:
        resume.set()
    if mutation == "locked":
        # The username-only login lock cannot revoke a previously authenticated
        # session's independently budgeted password and authenticator proof.
        await asyncio.wait_for(task, timeout=10)
        changed = _state(sync_conn, user.id)
        assert password_hasher.verify(changed[0], _NEW_PASSWORD)
        assert changed[8:] == (0, None)
        assert _pending_notice_count(sync_conn, user.id) == 1
        return
    with pytest.raises(PasswordChangeRejected) as rejected:
        await asyncio.wait_for(task, timeout=10)
    expected_reason = {
        "revision": "retry_required",
        "password": "retry_required",
        "session": "invalid_session",
        "expired": "invalid_session",
        "idle_expired": "invalid_session",
        "deactivated": "ineligible_account",
        "locked": "account_locked",
    }[mutation]
    assert rejected.value.reason == expected_reason
    assert _state(sync_conn, user.id) == expected
    assert _pending_notice_count(sync_conn, user.id) == 0
    if mutation == "idle_expired":
        assert _attempt_count(sync_conn, raw_session) == 1
        assert sync_conn.execute(
            "SELECT expires_at > clock_timestamp() FROM sessions WHERE id = %s",
            (hash_session_id(raw_session),),
        ).fetchone() == (True,)


async def test_two_verified_changes_cannot_reuse_the_same_totp_or_restore_a_session(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch
):
    """Verify two verified changes cannot reuse the same TOTP or restore a session."""
    user, secret = _user_with_factor(user_factory)
    raw_sessions = [session_factory(user.id), session_factory(user.id)]
    both_verified, resume = asyncio.Event(), asyncio.Event()
    completed_proofs = 0
    real_password_work = password_verification.run_password_work

    async def pause_after_password_work(*args, **kwargs):
        """Complete real password work, signal readiness and hold its result until released."""
        nonlocal completed_proofs
        result = await real_password_work(*args, **kwargs)
        completed_proofs += 1
        if completed_proofs == 2:
            both_verified.set()
        await resume.wait()
        return result

    monkeypatch.setattr(
        password_verification,
        "run_password_work",
        create_autospec(real_password_work, side_effect=pause_after_password_work),
    )
    tasks = [
        asyncio.create_task(
            change_password(
                db_pool,
                user_id=user.id,
                session_id=raw_session,
                current_password=user.password,
                new_password=f"{_NEW_PASSWORD}-{index}",
                totp_code=_code(secret),
            )
        )
        for index, raw_session in enumerate(raw_sessions)
    ]
    try:
        await asyncio.wait_for(both_verified.wait(), timeout=10)
    finally:
        resume.set()
    outcomes = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=10)
    assert sum(outcome is None for outcome in outcomes) == 1
    rejection = next(outcome for outcome in outcomes if outcome is not None)
    assert isinstance(rejection, PasswordChangeRejected)
    assert rejection.reason == "invalid_session"
    assert sync_conn.execute(
        "SELECT auth_revision, last_totp_step FROM users WHERE id = %s", (user.id,)
    ).fetchone() == (1, _TOTP_TIME // 30)
    assert sync_conn.execute(
        "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
    ).fetchone() == (0,)
    assert _pending_notice_count(sync_conn, user.id) == 1
