"""Trusted claims delete reservations without transferring account authority."""

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import replace

import psycopg
import pytest

from app.services import federated_authentication as auth
from app.services import registration_setup as registration
from app.services.crypto import audit_email_hash
from app.services.federated_session_policy import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    reconcile_federated_session_policy,
)
from app.services.users import create_shibboleth_user
from config import settings

ISSUER = "https://idp.example.org/idp/shibboleth"
SUBJECT = "urn:subject:reservation-owner"
EMAIL = "reserved@example.org"
PASSWORD = "Copper lanterns 7! beside quiet rivers"
EVENT = "federated_email_reservation_claimed"


def principal(email=EMAIL, subject=SUBJECT):
    """Build the test's federated principal with supplied identity overrides."""
    return auth.build_federated_principal(
        issuer=ISSUER,
        subject_id=subject,
        email=email,
        authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
        display_name="Federated owner",
    )


async def login(pool, assertion=None):
    """Finalize the supplied or default federated principal from loopback."""
    return await auth.finalize_shibboleth_login(
        pool, principal=assertion or principal(), ip_address="127.0.0.1"
    )


@pytest.fixture(autouse=True)
async def federation(monkeypatch, clean_db, db_pool, caplog):
    """Trust the test issuer, reconcile policy and capture audit events."""
    del clean_db
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])
    await reconcile_federated_session_policy(db_pool)
    caplog.set_level(logging.INFO, logger="audit")


def claims(caplog):
    """Select captured federated reservation-claim audit events."""
    return [record for record in caplog.records if record.getMessage() == EVENT]


async def pending_registration(db_pool, sync_conn, monkeypatch):
    """Reserve a local registration and return its user ID and captured verification token."""
    issued = []
    real = registration.generate_verification_token

    def capture(*args):
        """Record the real generated registration token before returning it."""
        token = real(*args)
        issued.append(token)
        return token

    monkeypatch.setattr(registration, "generate_verification_token", capture)
    await registration.begin_local_registration(db_pool, email=EMAIL)
    user_id = sync_conn.execute("SELECT id FROM users WHERE email = %s", (EMAIL,)).fetchone()[0]
    return user_id, issued[0]


async def verify(db_pool, token):
    """Complete local registration with the supplied token and fixed mailbox-owner profile."""
    return await registration.complete_local_registration(
        db_pool, token=token, display_name="Mailbox owner", password=PASSWORD
    )


async def observed_wait(connection, blocker_pid):
    """Prove a real PostgreSQL lock wait with bounded observer queries."""
    # ConnectionInfo.dsn omits the password, including when TCP uses SCRAM.
    async with await psycopg.AsyncConnection.connect(
        connection.info.dsn,
        password=connection.info.password,
        autocommit=True,
        connect_timeout=3,
        options="-c statement_timeout=2000",
    ) as observer:
        async with asyncio.timeout(8):
            deadline = asyncio.get_running_loop().time() + 8
            while asyncio.get_running_loop().time() < deadline:
                cur = await observer.execute(
                    """SELECT EXISTS (
                        SELECT 1 FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND %s = ANY(pg_blocking_pids(pid)))""",
                    (blocker_pid,),
                )
                if (await cur.fetchone())[0]:
                    return
                await asyncio.sleep(0.01)
    raise AssertionError("Expected PostgreSQL row-lock wait was not observed")


async def test_claim_deletes_passwordless_signup_and_revokes_its_code(
    db_pool, sync_conn, monkeypatch, caplog
):
    """Verify claim deletes passwordless signup and revokes its code."""
    old_id, token = await pending_registration(db_pool, sync_conn, monkeypatch)
    assert sync_conn.execute(
        "SELECT count(*) FROM email_outbox WHERE user_id = %s", (old_id,)
    ).fetchone() == (1,)

    result = await login(db_pool)

    assert isinstance(result, auth.FederatedLoginFailure)
    assert result.reason == "inactive_account"
    assert result.user is not None and result.user.id != old_id
    assert result.user.federated_status == "pending"
    assert sync_conn.execute(
        """SELECT auth_method, access_tier, is_active, is_admin, email_verified,
                  password_hash, totp_secret, pending_totp_secret, auth_revision,
                  email_verification_token_hash, pending_email_token_hash,
                  password_reset_token_hash, federated_review_revision
           FROM users WHERE id = %s""",
        (result.user.id,),
    ).fetchone() == (
        "shibboleth",
        "public",
        False,
        False,
        False,
        None,
        None,
        None,
        0,
        None,
        None,
        None,
        1,
    )
    assert sync_conn.execute("SELECT count(*) FROM users WHERE id = %s", (old_id,)).fetchone() == (
        0,
    )
    assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone() == (0,)
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)
    assert await registration.inspect_local_registration(db_pool, token) is None
    assert await verify(db_pool, token) is None
    (event,) = claims(caplog)
    assert event.removed_user_id == old_id and event.user_id == result.user.id
    assert event.email_hash == audit_email_hash(EMAIL)
    assert EMAIL not in repr(event.__dict__) and token not in repr(event.__dict__)
    assert event.client_ip == "127.0.0.1"
    assert (await login(db_pool)).user.id == result.user.id
    assert len(claims(caplog)) == 1


async def test_legacy_credentials_and_cascading_children_are_deleted_never_transferred(
    db_pool, sync_conn, user_factory, session_factory, caplog
):
    """Verify legacy credentials and cascading children are deleted never transferred."""
    local = user_factory(
        email="RESERVED@example.org",
        email_verified=False,
        access_tier="vetted",
        totp_secret="attacker-encrypted-secret",
        totp_recovery_code_generation=1,
    )
    session_factory(local.id)
    sync_conn.execute(
        """INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
           VALUES (%s, 1, 1, 'attacker-code-hash')""",
        (local.id,),
    )
    sync_conn.commit()

    result = await login(db_pool)

    assert result.reason == "inactive_account" and result.user.id != local.id
    assert sync_conn.execute(
        "SELECT password_hash, totp_secret, access_tier FROM users WHERE id = %s",
        (result.user.id,),
    ).fetchone() == (None, None, "public")
    assert sync_conn.execute("SELECT count(*) FROM sessions").fetchone() == (0,)
    assert sync_conn.execute("SELECT count(*) FROM totp_recovery_codes").fetchone() == (0,)
    assert len(claims(caplog)) == 1


@pytest.mark.parametrize("protected", ["verified", "administrator", "federated"])
async def test_protected_collision_preserves_every_account(
    db_pool, sync_conn, user_factory, caplog, protected
):
    """Verify protected collision preserves every account."""
    values = {"email": EMAIL}
    if protected == "administrator":
        values.update(email_verified=False, is_admin=True)
    elif protected == "federated":
        values.update(auth_method="shibboleth", shibboleth_subject_id="different-subject")
    local = user_factory(**values)
    before = sync_conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    assert await login(db_pool) == auth.FederatedLoginFailure("account_conflict")
    assert sync_conn.execute("SELECT * FROM users ORDER BY id").fetchall() == before
    assert not claims(caplog)
    assert local.id > 0


@pytest.mark.parametrize("status", ["pending", "approved", "disabled"])
async def test_existing_exact_identity_does_not_delete_a_different_email_reservation(
    db_pool, sync_conn, user_factory, caplog, status
):
    """Verify existing exact identity does not delete a different email reservation."""
    identity = user_factory(
        email="existing@example.org",
        auth_method="shibboleth",
        shibboleth_issuer=ISSUER,
        shibboleth_subject_id=SUBJECT,
        federated_status=status,
    )
    reservation = user_factory(email=EMAIL, email_verified=False)
    result = await login(db_pool)
    if status == "approved":
        assert result == auth.FederatedLoginFailure("account_conflict")
    else:
        assert result.reason == "inactive_account" and result.user.id == identity.id
    assert sync_conn.execute(
        "SELECT email FROM users WHERE id = %s", (reservation.id,)
    ).fetchone() == (EMAIL,)
    assert sync_conn.execute(
        "SELECT email FROM users WHERE id = %s", (identity.id,)
    ).fetchone() == ("existing@example.org",)
    assert not claims(caplog)


@pytest.mark.parametrize(
    "failure", ["untrusted_issuer", "insufficient_mfa", "disabled", "stale_policy"]
)
async def test_untrusted_or_stale_assertion_cannot_claim(
    db_pool, sync_conn, user_factory, monkeypatch, caplog, failure
):
    """Verify untrusted or stale assertion cannot claim."""
    local = user_factory(email=EMAIL, email_verified=False)
    assertion = principal()
    if failure == "untrusted_issuer":
        assertion = replace(assertion, issuer="https://other.example.org/idp")
    elif failure == "insufficient_mfa":
        assertion = replace(assertion, authn_context="password")
    elif failure == "disabled":
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
    else:
        monkeypatch.setattr(
            settings, "shibboleth_trusted_issuers", [ISSUER, "https://other.example.org/idp"]
        )
    assert await login(db_pool, assertion) == auth.FederatedLoginFailure("untrusted_assertion")
    assert sync_conn.execute("SELECT id FROM users WHERE email = %s", (EMAIL,)).fetchone() == (
        local.id,
    )
    assert not claims(caplog)


async def test_generic_provisioning_wrapper_has_no_claim_authority(
    db_pool, sync_conn, user_factory, caplog
):
    """Verify generic provisioning wrapper has no claim authority."""
    local = user_factory(email=EMAIL, email_verified=False)
    assert (
        await create_shibboleth_user(db_pool, issuer=ISSUER, subject_id=SUBJECT, email=EMAIL)
        is None
    )
    assert sync_conn.execute("SELECT id FROM users WHERE email = %s", (EMAIL,)).fetchone() == (
        local.id,
    )
    assert not claims(caplog)


async def test_failure_after_claim_rolls_back_deleted_row_children_and_audit(
    db_pool, sync_conn, monkeypatch, caplog
):
    """Verify failure after claim rolls back deleted row children and audit."""
    old_id, token = await pending_registration(db_pool, sync_conn, monkeypatch)
    before = sync_conn.execute("SELECT * FROM users ORDER BY id").fetchall()

    async def storage_failure(cur, **kwargs):
        """Trigger a PostgreSQL division error during capability storage."""
        del kwargs
        await cur.execute("SELECT 1 / 0")

    monkeypatch.setattr(auth, "record_federated_review_cur", storage_failure)
    with pytest.raises(psycopg.errors.DivisionByZero):
        await login(db_pool)
    assert sync_conn.execute("SELECT * FROM users ORDER BY id").fetchall() == before
    assert sync_conn.execute(
        "SELECT count(*) FROM email_outbox WHERE user_id = %s", (old_id,)
    ).fetchone() == (1,)
    assert await registration.inspect_local_registration(db_pool, token) is not None
    assert not claims(caplog)


@pytest.mark.parametrize("winner", ["verification", "federation"])
async def test_verification_claim_race_has_observed_locks_and_one_winner(
    db_pool, sync_conn, monkeypatch, caplog, winner
):
    """Verify verification claim race has observed locks and one winner."""
    old_id, token = await pending_registration(db_pool, sync_conn, monkeypatch)
    owner_module = registration if winner == "verification" else auth
    real_cursor = owner_module.get_db_cursor
    held, release = asyncio.Event(), asyncio.Event()
    owner = {}

    @asynccontextmanager
    async def hold_committing_winner(pool):
        """Pause the winning verification or federation transaction before commit."""
        async with real_cursor(pool) as cur:
            yield cur
            await cur.execute("SELECT email_verified FROM users WHERE id = %s", (old_id,))
            row = await cur.fetchone()
            if (winner == "verification" and row is not None and row["email_verified"]) or (
                winner == "federation" and row is None
            ):
                owner["pid"] = cur.connection.info.backend_pid
                held.set()
                await asyncio.wait_for(release.wait(), 10)

    monkeypatch.setattr(owner_module, "get_db_cursor", hold_committing_winner)
    first = asyncio.create_task(
        verify(db_pool, token) if winner == "verification" else login(db_pool)
    )
    second = None
    try:
        await asyncio.wait_for(held.wait(), 8)
        second = asyncio.create_task(
            login(db_pool) if winner == "verification" else verify(db_pool, token)
        )
        await observed_wait(sync_conn, owner["pid"])
        assert not second.done()
        assert not claims(caplog)
    finally:
        release.set()
        if second is None:
            first.cancel()
        outcomes = await asyncio.wait_for(asyncio.gather(first, *([second] if second else [])), 10)
    if winner == "verification":
        assert outcomes[0].id == old_id
        assert outcomes[1] == auth.FederatedLoginFailure("account_conflict")
        assert sync_conn.execute(
            "SELECT email_verified, auth_method FROM users WHERE id = %s", (old_id,)
        ).fetchone() == (True, "local")
        assert not claims(caplog)
    else:
        assert outcomes[0].reason == "inactive_account" and outcomes[0].user.id != old_id
        assert outcomes[1] is None
        assert len(claims(caplog)) == 1
    assert sync_conn.execute("SELECT count(*) FROM users").fetchone() == (1,)


async def test_concurrent_same_subject_creation_restores_losing_reservation(
    db_pool, sync_conn, monkeypatch, caplog
):
    """The fresh-insert fence prevents deletion for another winning email."""
    old_id, token = await pending_registration(db_pool, sync_conn, monkeypatch)
    async with await psycopg.AsyncConnection.connect(
        sync_conn.info.dsn, password=sync_conn.info.password
    ) as blocker:
        async with blocker.transaction():
            await blocker.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (old_id,))
            task = asyncio.create_task(login(db_pool))
            try:
                await observed_wait(sync_conn, blocker.info.backend_pid)
                winner = await create_shibboleth_user(
                    db_pool, issuer=ISSUER, subject_id=SUBJECT, email="winner@example.org"
                )
                assert winner is not None and winner.federated_status == "pending"
            except BaseException:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise
        result = await asyncio.wait_for(task, 8)
    assert result == auth.FederatedLoginFailure("account_conflict")
    assert sync_conn.execute("SELECT id FROM users WHERE email = %s", (EMAIL,)).fetchone() == (
        old_id,
    )
    assert sync_conn.execute("SELECT email FROM users WHERE id = %s", (winner.id,)).fetchone() == (
        "winner@example.org",
    )
    assert sync_conn.execute(
        "SELECT count(*) FROM email_outbox WHERE user_id = %s", (old_id,)
    ).fetchone() == (1,)
    assert await registration.inspect_local_registration(db_pool, token) is not None
    assert not claims(caplog)
