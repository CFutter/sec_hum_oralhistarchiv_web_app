"""Account deletion through real credentials, PostgreSQL and HTTP middleware."""

import asyncio
import json
import logging
from unittest.mock import create_autospec

import psycopg
import pyotp
import pytest
from psycopg import sql

from app.services import password_verification
from app.services.account_deletion import (
    AccountDeletionRejected,
    AccountDeletionResult,
    delete_account_as_admin,
    delete_own_account,
)
from app.services.crypto import audit_email_hash
from app.services.db import get_db_cursor
from app.services.email_change import generate_email_change_token, store_pending_email
from app.services.email_verification import generate_verification_token
from app.services.password_reset import generate_reset_token, store_reset_token_hash
from app.services.session_ids import hash_session_id
from app.services.tokens import action_token_public_id, hash_token
from app.services.totp import matched_step, verify_and_consume_totp
from app.services.totp_crypto import encrypt_value
from app.services.users import acquire_admin_action_lock_cur
from config import settings
from tests.action_links import action_path
from tests.fixtures import sign_session_id

pytestmark = pytest.mark.integration


@pytest.fixture
def deletion_audit(caplog):
    """Observe audit records even when an earlier test configured its logger."""
    audit = logging.getLogger("audit")
    handlers, propagate = audit.handlers[:], audit.propagate
    audit.addHandler(caplog.handler)
    audit.propagate = False
    caplog.set_level(logging.INFO, logger="audit")
    try:
        yield caplog
    finally:
        audit.handlers[:] = handlers
        audit.propagate = propagate


def totp_user(user_factory, **overrides):
    """Create a user with an encrypted TOTP factor and return the user and plaintext seed."""
    secret = pyotp.random_base32()
    return user_factory(totp_secret=encrypt_value(secret), **overrides), secret


def current_code(secret):
    """Generate the seed's current TOTP code."""
    return pyotp.TOTP(secret).now()


def count_owned_rows(conn, user_id):
    """Keep the per-table assertions explicit, including both promotion owners."""
    result = {}
    for table in (
        "users",
        "sessions",
        "pending_totp_rotations",
        "totp_recovery_codes",
        "email_outbox",
    ):
        column = "id" if table == "users" else "user_id"
        result[table] = conn.execute(
            sql.SQL("SELECT count(*) FROM {} WHERE {} = %s").format(
                sql.Identifier(table), sql.Identifier(column)
            ),
            (user_id,),
        ).fetchone()[0]
    result["admin_promotion_requests"] = conn.execute(
        "SELECT count(*) FROM admin_promotion_requests WHERE user_id = %s OR requested_by = %s",
        (user_id, user_id),
    ).fetchone()[0]
    return result


def install_outbox_states(conn, user_id, email):
    """Create each retention/lease state without depending on an SMTP server."""
    for state in ("pending", "sending", "sent", "dead"):
        conn.execute(
            """INSERT INTO email_outbox
                   (user_id, message_type, recipient, subject, body_ciphertext,
                    status, locked_at, lock_token, sent_at, failed_at, terminal_outcome)
               VALUES (%s, 'email_change_notice', %s, 'Account notice', 'ciphertext',
                    %s, CASE WHEN %s = 'sending' THEN clock_timestamp() END,
                    CASE WHEN %s = 'sending' THEN
                        '00000000-0000-0000-0000-000000000001'::uuid END,
                    CASE WHEN %s = 'sent' THEN clock_timestamp() END,
                    CASE WHEN %s = 'dead' THEN clock_timestamp() END,
                    CASE WHEN %s = 'dead' THEN 'delivery_failed' END)""",
            (user_id, email, state, state, state, state, state, state),
        )


def install_recovery_code(conn, user_id):
    """Insert a known first-generation recovery-code hash without committing."""
    conn.execute("UPDATE users SET totp_recovery_code_generation = 1 WHERE id = %s", (user_id,))
    conn.execute(
        """INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
           VALUES (%s, 1, 1, %s)""",
        (user_id, hash_token(f"saved-recovery-{user_id}")),
    )


def set_browser_session(client, raw_session):
    """Clear browser cookies and install the signed session cookie for localhost."""
    client.cookies.clear()
    client.cookies.set(
        settings.session_cookie_name,
        sign_session_id(raw_session),
        domain="localhost.local",
        path="/",
    )


def deletion_events(caplog):
    """Select captured self-service and administrator account-deletion audit events."""
    return [
        record
        for record in caplog.records
        if record.name == "audit"
        and getattr(record, "event_type", None) in {"account_deleted", "admin_account_deleted"}
    ]


@pytest.mark.parametrize("lock_phase", ["before_request", "after_password"])
async def test_existing_full_session_can_delete_while_username_login_is_locked(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch, lock_phase
):
    """Verify existing full session can delete while username login is locked."""
    user, secret = totp_user(user_factory)
    raw_session = session_factory(user.id)

    def lock_login():
        """Set and commit a fifteen-minute login lock at the configured failure threshold."""
        sync_conn.execute(
            """UPDATE users SET failed_login_count = %s,
                      locked_until = clock_timestamp() + INTERVAL '15 minutes'
               WHERE id = %s""",
            (settings.login_failure_threshold, user.id),
        )
        sync_conn.commit()

    if lock_phase == "before_request":
        lock_login()
    else:
        original = password_verification.run_password_work

        async def lock_after_password(*args, **kwargs):
            """Verify the real password, then lock the account before returning its proof."""
            verified = await original(*args, **kwargs)
            lock_login()
            return verified

        monkeypatch.setattr(
            password_verification,
            "run_password_work",
            create_autospec(original, side_effect=lock_after_password),
        )

    result = await delete_own_account(
        db_pool,
        user_id=user.id,
        session_id=raw_session,
        password=user.password,
        totp_code=current_code(secret),
    )
    assert result.target_user_id == user.id
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (user.id,)).fetchone() is None
    assert (
        sync_conn.execute(
            "SELECT 1 FROM sessions WHERE id = %s", (hash_session_id(raw_session),)
        ).fetchone()
        is None
    )


async def test_self_deletion_cascades_every_owned_table_and_preserves_other_accounts(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify self deletion cascades every owned table and preserves other accounts."""
    user, secret = totp_user(user_factory)
    requester = user_factory()
    recipient = user_factory()
    unrelated = user_factory()
    unrelated_requester = user_factory()
    raw_session = session_factory(user.id)
    session_factory(user.id, purpose="totp_setup")
    session_factory(user.id, purpose="totp_recovery")
    unrelated_session = session_factory(unrelated.id)
    install_recovery_code(sync_conn, user.id)
    install_recovery_code(sync_conn, unrelated.id)
    for target, actor in (
        (user.id, requester.id),
        (recipient.id, user.id),
        (unrelated.id, unrelated_requester.id),
    ):
        sync_conn.execute(
            """INSERT INTO admin_promotion_requests
                   (user_id, requested_by, expires_at, expected_auth_revision)
               VALUES (%s, %s, clock_timestamp() + INTERVAL '1 hour', 0)""",
            (target, actor),
        )
    sync_conn.execute(
        """INSERT INTO pending_totp_rotations
               (user_id, session_id, auth_revision, encrypted_secret, expires_at)
           VALUES (%s, %s, 0, %s, clock_timestamp() + INTERVAL '5 minutes')""",
        (user.id, hash_session_id(raw_session), encrypt_value(pyotp.random_base32())),
    )
    install_outbox_states(sync_conn, user.id, user.email)
    install_outbox_states(sync_conn, unrelated.id, unrelated.email)
    sync_conn.commit()
    owned_foreign_keys = sync_conn.execute(
        """SELECT c.conrelid::regclass::text, a.attname
           FROM pg_constraint AS c
           CROSS JOIN LATERAL unnest(c.conkey) AS key(attnum)
           JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = key.attnum
           WHERE c.contype = 'f' AND c.confrelid = 'users'::regclass"""
    ).fetchall()
    assert set(owned_foreign_keys) == {
        ("sessions", "user_id"),
        ("pending_totp_rotations", "user_id"),
        ("totp_recovery_codes", "user_id"),
        ("email_outbox", "user_id"),
        ("admin_promotion_requests", "user_id"),
        ("admin_promotion_requests", "requested_by"),
    }
    before = count_owned_rows(sync_conn, user.id)
    assert before == {
        "users": 1,
        "sessions": 3,
        "pending_totp_rotations": 1,
        "totp_recovery_codes": 1,
        "email_outbox": 4,
        "admin_promotion_requests": 2,
    }
    unrelated_before = count_owned_rows(sync_conn, unrelated.id)

    result = await delete_own_account(
        db_pool,
        user_id=user.id,
        session_id=raw_session,
        password=user.password,
        totp_code=current_code(secret),
    )

    assert result == AccountDeletionResult(user.id, audit_email_hash(user.email), "local")
    assert user.email not in repr(result)
    assert count_owned_rows(sync_conn, user.id) == dict.fromkeys(before, 0)
    assert count_owned_rows(sync_conn, unrelated.id) == unrelated_before
    assert sync_conn.execute(
        "SELECT 1 FROM sessions WHERE id = %s", (hash_session_id(unrelated_session),)
    ).fetchone() == (1,)
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (recipient.id,)).fetchone() == (
        1,
    )


@pytest.mark.parametrize("proof", ["password", "totp", "replayed_totp", "malformed_totp"])
async def test_invalid_proof_spends_an_attempt_without_deleting_or_consuming_other_state(
    db_pool, user_factory, session_factory, sync_conn, proof
):
    """Verify invalid proof spends an attempt without deleting or consuming other state."""
    user, secret = totp_user(user_factory)
    raw_session = session_factory(user.id)
    password = "incorrect-password" if proof == "password" else user.password
    code = current_code(secret)
    if proof == "replayed_totp":
        assert await verify_and_consume_totp(db_pool, user.id, code)
    elif proof == "totp":
        code = next(
            f"{value:06d}"
            for value in range(1_000_000)
            if matched_step(secret, f"{value:06d}", valid_window=3) is None
        )
    elif proof == "malformed_totp":
        code = "not-a-code"
    before = sync_conn.execute(
        "SELECT last_totp_step, auth_revision FROM users WHERE id = %s", (user.id,)
    ).fetchone()

    with pytest.raises(AccountDeletionRejected) as rejected:
        await delete_own_account(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            password=password,
            totp_code=code,
        )

    assert rejected.value.reason == ("invalid_password" if proof == "password" else "invalid_totp")
    assert (
        sync_conn.execute(
            "SELECT last_totp_step, auth_revision FROM users WHERE id = %s", (user.id,)
        ).fetchone()
        == before
    )
    assert sync_conn.execute(
        "SELECT step_up_attempt_count FROM sessions WHERE id = %s", (hash_session_id(raw_session),)
    ).fetchone() == (1,)


async def test_deletion_budget_exhaustion_expires_only_the_presented_session(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch
):
    """Verify deletion budget exhaustion expires only the presented session."""
    monkeypatch.setattr(settings, "session_step_up_attempt_limit", 1)
    user, secret = totp_user(user_factory)
    raw_session = session_factory(user.id)
    other_session = session_factory(user.id)
    with pytest.raises(AccountDeletionRejected, match="invalid_password"):
        await delete_own_account(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            password="incorrect-password",
            totp_code=current_code(secret),
        )
    with pytest.raises(AccountDeletionRejected, match="step_up_exhausted"):
        await delete_own_account(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            password=user.password,
            totp_code=current_code(secret),
        )
    assert sync_conn.execute(
        "SELECT expires_at <= clock_timestamp() FROM sessions WHERE id = %s",
        (hash_session_id(raw_session),),
    ).fetchone() == (True,)
    assert sync_conn.execute(
        "SELECT expires_at > clock_timestamp() FROM sessions WHERE id = %s",
        (hash_session_id(other_session),),
    ).fetchone() == (True,)
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (user.id,)).fetchone() == (1,)


@pytest.mark.parametrize("purpose", ["totp_setup", "totp_recovery", "expired", "wrong_owner"])
async def test_self_deletion_requires_the_actors_current_full_session(
    db_pool, user_factory, session_factory, sync_conn, purpose
):
    """Verify self deletion requires the actors current full session."""
    user, secret = totp_user(user_factory)
    owner = user_factory() if purpose == "wrong_owner" else user
    raw_session = session_factory(
        owner.id,
        purpose=purpose if purpose in {"totp_setup", "totp_recovery"} else "full",
        expires_in_seconds=-1 if purpose == "expired" else 3600,
    )
    with pytest.raises(AccountDeletionRejected, match="invalid_session"):
        await delete_own_account(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            password=user.password,
            totp_code=current_code(secret),
        )
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (user.id,)).fetchone() == (1,)


async def test_federated_account_cannot_delete_itself_even_with_an_anomalous_full_session(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify federated account cannot delete itself even with an anomalous full session."""
    user = user_factory(auth_method="shibboleth")
    raw_session = session_factory(user.id)
    with pytest.raises(AccountDeletionRejected, match="ineligible_account"):
        await delete_own_account(
            db_pool,
            user_id=user.id,
            session_id=raw_session,
            password=user.password,
            totp_code="123456",
        )
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (user.id,)).fetchone() == (1,)


@pytest.mark.parametrize("federated_status", ["pending", "approved", "disabled"])
async def test_administrator_can_delete_each_federated_state_without_altering_other_identities(
    db_pool, user_factory, session_factory, sync_conn, federated_status
):
    """Verify administrator can delete each federated state without altering other identities."""
    admin, secret = totp_user(user_factory, is_admin=True)
    raw_session = session_factory(admin.id)
    target = user_factory(auth_method="shibboleth", federated_status=federated_status)
    session_factory(target.id)
    result = await delete_account_as_admin(
        db_pool,
        actor_id=admin.id,
        actor_session_id=raw_session,
        target_user_id=target.id,
        password=admin.password,
        totp_code=current_code(secret),
    )
    assert result == AccountDeletionResult(target.id, audit_email_hash(target.email), "shibboleth")
    assert all(value == 0 for value in count_owned_rows(sync_conn, target.id).values())
    assert sync_conn.execute(
        "SELECT is_admin FROM users WHERE id = %s", (admin.id,)
    ).fetchone() == (True,)


async def test_approver_deletion_preserves_another_accounts_historical_approval_marker(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify approver deletion preserves another accounts historical approval marker."""
    approver, secret = totp_user(user_factory, is_admin=True)
    user_factory(is_admin=True)
    federated = user_factory(auth_method="shibboleth", federated_approved_by=approver.id)
    raw_session = session_factory(approver.id)
    await delete_own_account(
        db_pool,
        user_id=approver.id,
        session_id=raw_session,
        password=approver.password,
        totp_code=current_code(secret),
    )
    assert sync_conn.execute(
        "SELECT federated_status, federated_approved_by FROM users WHERE id = %s", (federated.id,)
    ).fetchone() == ("approved", approver.id)
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (approver.id,)).fetchone() is None


async def test_last_active_admin_cannot_delete_themselves_and_rejection_does_not_spend_totp(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify last active admin cannot delete themselves and rejection does not spend TOTP."""
    admin, secret = totp_user(user_factory, is_admin=True)
    user_factory(is_admin=True, is_active=False)
    raw_session = session_factory(admin.id)
    code = current_code(secret)
    with pytest.raises(AccountDeletionRejected, match="last_active_admin"):
        await delete_own_account(
            db_pool,
            user_id=admin.id,
            session_id=raw_session,
            password=admin.password,
            totp_code=code,
        )
    assert sync_conn.execute(
        "SELECT last_totp_step FROM users WHERE id = %s", (admin.id,)
    ).fetchone() == (None,)
    assert await verify_and_consume_totp(db_pool, admin.id, code)


@pytest.mark.parametrize("mutation", ["revision", "session", "admin", "recovery"])
async def test_authority_is_rechecked_after_real_password_work_releases_its_connection(
    db_pool, user_factory, session_factory, sync_conn, monkeypatch, mutation
):
    """Verify authority is rechecked after real password work releases its connection."""
    admin, secret = totp_user(user_factory, is_admin=True)
    target = user_factory()
    raw_session = session_factory(admin.id)
    verified, resume = asyncio.Event(), asyncio.Event()
    real_password_work = password_verification.run_password_work

    async def pause_after_real_password_work(*args, **kwargs):
        """Complete real password work, signal readiness and hold its result until released."""
        result = await real_password_work(*args, **kwargs)
        verified.set()
        await resume.wait()
        return result

    monkeypatch.setattr(
        password_verification,
        "run_password_work",
        create_autospec(real_password_work, side_effect=pause_after_real_password_work),
    )
    task = asyncio.create_task(
        delete_account_as_admin(
            db_pool,
            actor_id=admin.id,
            actor_session_id=raw_session,
            target_user_id=target.id,
            password=admin.password,
            totp_code=current_code(secret),
        )
    )
    try:
        await asyncio.wait_for(verified.wait(), timeout=10)
        sync_conn.execute("SET LOCAL statement_timeout = '2s'")
        if mutation == "revision":
            sync_conn.execute(
                "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s", (admin.id,)
            )
        elif mutation == "session":
            sync_conn.execute("DELETE FROM sessions WHERE id = %s", (hash_session_id(raw_session),))
        elif mutation == "admin":
            sync_conn.execute("UPDATE users SET is_admin = false WHERE id = %s", (admin.id,))
        else:
            sync_conn.execute("DELETE FROM totp_recovery_codes WHERE user_id = %s", (admin.id,))
        sync_conn.commit()
    finally:
        resume.set()
    with pytest.raises(AccountDeletionRejected) as rejected:
        await asyncio.wait_for(task, timeout=10)
    assert rejected.value.reason == (
        "retry_required" if mutation == "revision" else "admin_required"
    )
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (target.id,)).fetchone() == (1,)
    assert sync_conn.execute(
        "SELECT last_totp_step FROM users WHERE id = %s", (admin.id,)
    ).fetchone() == (None,)


async def test_two_admin_self_deletions_observe_the_shared_lock_and_leave_one_active_admin(
    db_pool, user_factory, session_factory, sync_conn
):
    """Verify two admin self deletions observe the shared lock and leave one active admin."""
    admins = [totp_user(user_factory, is_admin=True) for _ in range(2)]
    sessions = [session_factory(user.id) for user, _ in admins]
    tasks = []
    async with await psycopg.AsyncConnection.connect(
        settings.database_url.get_secret_value(), autocommit=True
    ) as blocker:
        async with get_db_cursor(blocker) as cur:
            await acquire_admin_action_lock_cur(cur)
            for (user, secret), session in zip(admins, sessions, strict=True):
                tasks.append(
                    asyncio.create_task(
                        delete_own_account(
                            db_pool,
                            user_id=user.id,
                            session_id=session,
                            password=user.password,
                            totp_code=current_code(secret),
                        )
                    )
                )
            deadline = asyncio.get_running_loop().time() + 15
            while True:
                await cur.execute("SELECT pg_stat_clear_snapshot()")
                await cur.execute(
                    """SELECT count(*) AS waiting FROM pg_stat_activity
                       WHERE %s = ANY(pg_blocking_pids(pid)) AND query LIKE %s""",
                    (blocker.info.backend_pid, "SELECT pg_advisory_xact_lock(%"),
                )
                row = await cur.fetchone()
                if row["waiting"] == 2:
                    break
                assert all(not task.done() for task in tasks)
                if asyncio.get_running_loop().time() >= deadline:
                    pytest.fail("both deletions did not reach the observed membership lock")
                await asyncio.sleep(0.01)
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=10)
    assert sum(isinstance(result, AccountDeletionResult) for result in results) == 1
    rejected = [result for result in results if isinstance(result, AccountDeletionRejected)]
    assert len(rejected) == 1 and rejected[0].reason == "last_active_admin"
    assert sync_conn.execute(
        "SELECT count(*) FROM users WHERE is_active AND is_admin"
    ).fetchone() == (1,)


async def test_http_self_deletion_audits_once_revokes_other_sessions_and_invalidates_action_links(
    e2e_client, db_pool, user_factory, session_factory, sync_conn, deletion_audit
):
    """Verify HTTP self deletion audits once revokes other sessions and invalidates action links."""
    user, secret = totp_user(user_factory)
    raw_session = session_factory(user.id)
    other_session = session_factory(user.id)
    reset_token = generate_reset_token(user.id, user.email)
    await store_reset_token_hash(
        db_pool, user.id, hash_token(reset_token), expected_email=user.email
    )
    change_token = generate_email_change_token(user.id, "replacement@example.org", auth_revision=0)
    await store_pending_email(
        db_pool,
        user.id,
        "replacement@example.org",
        hash_token(change_token),
        expected_auth_revision=0,
    )
    set_browser_session(e2e_client, raw_session)
    assert e2e_client.get(action_path("/reset-password", reset_token)).status_code == 200
    assert e2e_client.get(action_path("/account/confirm-email", change_token)).status_code == 200
    page = e2e_client.get("/account/delete", follow_redirects=False)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert count_owned_rows(sync_conn, user.id)["users"] == 1
    response = e2e_client.post(
        "/account/delete",
        data={
            "password": user.password,
            "totp_code": current_code(secret),
            "confirm": "delete",
            "csrf_token": e2e_client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/login?notice=account_deleted"
    assert settings.session_cookie_name not in e2e_client.cookies
    assert all(value == 0 for value in count_owned_rows(sync_conn, user.id).values())
    events = deletion_events(deletion_audit)
    assert len(events) == 1
    assert events[0].event_type == "account_deleted"
    assert events[0].user_id == user.id
    assert events[0].email_hash == audit_email_hash(user.email)
    assert user.email not in json.dumps(events[0].__dict__, default=str)
    assert user.password not in json.dumps(events[0].__dict__, default=str)

    set_browser_session(e2e_client, other_session)
    rejected_session = e2e_client.get("/account", follow_redirects=False)
    assert rejected_session.status_code == 303
    assert rejected_session.headers["location"].startswith("/login")
    assert e2e_client.get(action_path("/reset-password", reset_token)).status_code == 200
    assert e2e_client.get(action_path("/account/confirm-email", change_token)).status_code == 200
    e2e_client.get("/login")
    reset = e2e_client.post(
        "/reset-password",
        data={
            "token": reset_token,
            "public_id": action_token_public_id(reset_token),
            "password": "A-new-password-with-entropy!93",
            "password_confirm": "A-new-password-with-entropy!93",
            "csrf_token": e2e_client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert reset.status_code == 422, reset.text
    change = e2e_client.post(
        "/account/confirm-email",
        data={"token": change_token, "public_id": action_token_public_id(change_token)},
        follow_redirects=False,
    )
    assert change.status_code == 400
    assert len(deletion_events(deletion_audit)) == 1
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (user.id,)).fetchone() is None


def test_http_admin_deletion_audits_once_and_registration_capability_cannot_recreate_account(
    e2e_client, user_factory, session_factory, sync_conn, deletion_audit
):
    """Verify HTTP admin deletion audits once and registration capability cannot recreate account."""
    admin, secret = totp_user(user_factory, is_admin=True)
    raw_session = session_factory(admin.id)
    target = user_factory(password_hash=None, is_active=False, email_verified=False)
    token = generate_verification_token(target.id, target.email)
    sync_conn.execute(
        """UPDATE users SET email_verification_token_hash = %s,
                  email_verification_created_at = clock_timestamp() WHERE id = %s""",
        (hash_token(token), target.id),
    )
    sync_conn.commit()
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    set_browser_session(e2e_client, raw_session)
    path = f"/admin/users/{target.id}/delete"
    assert e2e_client.get(path).status_code == 200
    response = e2e_client.post(
        path,
        data={
            "password": admin.password,
            "totp_code": current_code(secret),
            "confirm": "delete",
            "csrf_token": e2e_client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/admin"
    assert e2e_client.get("/account").status_code == 200
    assert all(value == 0 for value in count_owned_rows(sync_conn, target.id).values())
    events = deletion_events(deletion_audit)
    assert len(events) == 1
    assert events[0].event_type == "admin_account_deleted"
    assert events[0].actor_admin_id == admin.id
    assert events[0].target_user_id == target.id
    assert events[0].email_hash == audit_email_hash(target.email)
    assert target.email not in json.dumps(events[0].__dict__, default=str)
    assert e2e_client.get(action_path("/verify-email", token)).status_code == 200
    e2e_client.cookies.clear()
    e2e_client.get("/login")
    replay = e2e_client.post(
        "/verify-email",
        data={
            "token": token,
            "public_id": action_token_public_id(token),
            "display_name": "A returned account",
            "password": "A-new-password-with-entropy!93",
            "password_confirm": "A-new-password-with-entropy!93",
            "csrf_token": e2e_client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )
    assert replay.status_code == 400, replay.text
    assert sync_conn.execute("SELECT 1 FROM users WHERE id = %s", (target.id,)).fetchone() is None
    assert len(deletion_events(deletion_audit)) == 1
