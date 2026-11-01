"""Mailbox proof precedes local profile/password creation, against real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec

import pytest
import time_machine
from psycopg.errors import CheckViolation

from app.services import (
    begin_local_registration,
    complete_local_registration,
    generate_reset_token,
    inspect_local_registration,
    registration_setup,
)
from app.services.authentication import verify_password
from app.services.crypto import decrypt_outbox_body
from app.services.email_verification import store_verification_token_hash
from app.services.password_reset import (
    InvalidResetToken,
    store_reset_token_hash,
    update_password_with_token,
)
from app.services.tokens import hash_token
from app.services.totp_crypto import encrypt_value
from app.services.users import AdminActionRejected, set_user_active
from config import settings
from tests.action_links import token_from_action_email

EMAIL = "mailbox@example.org"
PASSWORD = "Fresh-N3w-Passw0rd!"
OTHER_PASSWORD = "An0ther-G00d-Pw!x"


def _row(sync_conn):
    """Read the required registration row as JSON and commit the observer transaction."""
    row = sync_conn.execute(
        "SELECT to_jsonb(users) FROM users WHERE email = %s", (EMAIL,)
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    return row[0]


def _token(sync_conn):
    """Decrypt the newest verification email and return its validated capability token."""
    row = sync_conn.execute(
        """SELECT body_ciphertext, action_token_hash, user_id FROM email_outbox
           WHERE message_type = 'email_verification' ORDER BY id DESC LIMIT 1"""
    ).fetchone()
    sync_conn.commit()
    assert row is not None
    body = decrypt_outbox_body(row[0])
    assert body is not None
    prefix = settings.public_base_url + "/verify-email/"
    token = token_from_action_email(
        body, next(line.strip() for line in body.splitlines() if prefix in line)
    )
    assert token not in row[0]
    user = _row(sync_conn)
    assert row[1] == user["email_verification_token_hash"] == hash_token(token)
    assert row[2] == user["id"]
    return token


async def test_request_creates_only_pending_shell_and_duplicate_preserves_it(db_pool, sync_conn):
    """Verify request creates only pending shell and duplicate preserves it."""
    await begin_local_registration(db_pool, email=EMAIL)
    before = _row(sync_conn)
    assert (before["is_active"], before["email_verified"], before["is_admin"]) == (False,) * 3
    assert before["auth_method"] == "local" and before["access_tier"] == "public"
    assert all(
        before[key] is None for key in ("password_hash", "display_name", "affiliation", "country")
    )
    token = _token(sync_conn)
    for _ in range(2):
        setup = await inspect_local_registration(db_pool, token)
        assert setup is not None and (setup.user_id, setup.email) == (before["id"], EMAIL)
    await begin_local_registration(db_pool, email=EMAIL.upper())
    assert _row(sync_conn) == before
    assert sync_conn.execute(
        "SELECT message_type, user_id FROM email_outbox ORDER BY id"
    ).fetchall() == [("email_verification", before["id"])]


async def test_existing_verified_account_is_not_replaced_by_registration(
    db_pool, sync_conn, user_factory
):
    """Verify existing verified account is not replaced by registration."""
    user_factory(email=EMAIL, email_verified=True)
    before = _row(sync_conn)
    await begin_local_registration(db_pool, email=EMAIL)
    assert _row(sync_conn) == before
    notice = sync_conn.execute(
        "SELECT message_type, recipient, user_id FROM email_outbox"
    ).fetchall()
    sync_conn.commit()
    assert notice == []


async def test_completion_sets_credentials_revokes_pending_state_and_rejects_replay(
    db_pool, sync_conn, session_factory, monkeypatch
):
    """Verify completion sets credentials revokes pending state and rejects replay."""
    await begin_local_registration(db_pool, email=EMAIL)
    token = _token(sync_conn)
    before = _row(sync_conn)
    session_factory(before["id"])
    sync_conn.execute(
        """UPDATE users SET password_reset_token_hash = 'stale-reset',
               password_reset_created_at = clock_timestamp(), failed_login_count = 2,
               locked_until = clock_timestamp() + INTERVAL '1 hour',
               lockout_notice_enqueued_at = clock_timestamp(), pending_email = 'staged@example.org',
               pending_email_token_hash = 'stale-email', pending_email_created_at = clock_timestamp(),
               pending_totp_secret = %s, pending_totp_created_at = clock_timestamp()
           WHERE id = %s""",
        (encrypt_value("JBSWY3DPEHPK3PXP"), before["id"]),
    )
    sync_conn.commit()
    user = await complete_local_registration(
        db_pool,
        token=token,
        display_name="Mira Cole",
        password=PASSWORD,
        affiliation="Research Centre",
        country="GB",
    )
    assert user is not None and user.id == before["id"] and user.is_active and user.email_verified
    after = _row(sync_conn)
    assert (after["display_name"], after["affiliation"], after["country"]) == (
        "Mira Cole",
        "Research Centre",
        "GB",
    )
    assert after["auth_revision"] == before["auth_revision"] + 1
    assert after["access_tier"] == "public" and not after["is_admin"]
    assert after["failed_login_count"] == 0
    assert all(
        after[key] is None
        for key in (
            "email_verification_token_hash",
            "email_verification_created_at",
            "password_reset_token_hash",
            "password_reset_created_at",
            "locked_until",
            "lockout_notice_enqueued_at",
            "pending_email",
            "pending_email_token_hash",
            "pending_email_created_at",
            "pending_totp_secret",
            "pending_totp_created_at",
        )
    )
    assert (
        sync_conn.execute(
            "SELECT count(*) FROM sessions WHERE user_id = %s", (user.id,)
        ).fetchone()[0]
        == 0
    )
    assert (await verify_password(db_pool, EMAIL, PASSWORD)).password_ok
    work = create_autospec(registration_setup.run_password_work, spec_set=True)
    monkeypatch.setattr(registration_setup, "run_password_work", work)
    assert await inspect_local_registration(db_pool, token) is None
    replay = await complete_local_registration(
        db_pool, token=token, display_name="Different Name", password=OTHER_PASSWORD
    )
    assert replay is None
    work.assert_not_awaited()
    assert _row(sync_conn) == after


@pytest.mark.parametrize("expiry", ["database", "signature", "tampered"])
async def test_invalid_setup_does_not_hash_or_modify_user(db_pool, sync_conn, monkeypatch, expiry):
    """Verify invalid setup does not hash or modify user."""
    await begin_local_registration(db_pool, email=EMAIL)
    token = _token(sync_conn)
    if expiry == "database":
        sync_conn.execute(
            "UPDATE users SET email_verification_created_at = clock_timestamp() - INTERVAL '25 hours'"
        )
        sync_conn.commit()
    before = _row(sync_conn)
    work = create_autospec(registration_setup.run_password_work, spec_set=True)
    monkeypatch.setattr(registration_setup, "run_password_work", work)
    with time_machine.travel(
        datetime.now(UTC) + timedelta(hours=25) if expiry == "signature" else datetime.now(UTC)
    ):
        candidate = token + "tampered" if expiry == "tampered" else token
        assert await inspect_local_registration(db_pool, candidate) is None
        result = await complete_local_registration(
            db_pool, token=candidate, display_name="Mira Cole", password=PASSWORD
        )
        assert result is None
    work.assert_not_awaited()
    assert _row(sync_conn) == before


async def test_pending_shell_cannot_login_reset_or_use_token_only_confirmation(
    db_pool, sync_conn, admin_actor
):
    """Verify pending shell cannot login reset or use token only confirmation."""
    await begin_local_registration(db_pool, email=EMAIL)
    token = _token(sync_conn)
    user_id = _row(sync_conn)["id"]
    with pytest.raises(AdminActionRejected, match="complete email setup"):
        await set_user_active(
            db_pool,
            user_id,
            True,
            actor_id=admin_actor.id,
            actor_session_id=admin_actor.session_id,
        )
    check = await verify_password(db_pool, EMAIL, PASSWORD)
    assert not check.password_ok and check.failure_reason == "inactive_account"
    with pytest.raises(ValueError):
        await store_reset_token_hash(db_pool, user_id, "reset-hash", expected_email=EMAIL)
    reset_token = generate_reset_token(user_id, EMAIL)
    sync_conn.execute(
        """UPDATE users SET password_reset_token_hash = %s,
               password_reset_created_at = clock_timestamp() WHERE id = %s""",
        (hash_token(reset_token), user_id),
    )
    sync_conn.commit()
    with pytest.raises(InvalidResetToken):
        await update_password_with_token(
            db_pool, user_id, reset_token, PASSWORD, expected_email=EMAIL, totp_code=""
        )
    await set_user_active(
        db_pool,
        user_id,
        False,
        actor_id=admin_actor.id,
        actor_session_id=admin_actor.session_id,
    )
    cancelled = _row(sync_conn)
    assert cancelled["email_verification_token_hash"] is None
    with pytest.raises(ValueError):
        await store_verification_token_hash(
            db_pool, user_id, hash_token(token), expected_email=EMAIL
        )
    await begin_local_registration(db_pool, email=EMAIL)
    assert _row(sync_conn) == cancelled
    assert await inspect_local_registration(db_pool, token) is None
    result = await complete_local_registration(
        db_pool, token=token, display_name="Mira Cole", password=PASSWORD
    )
    assert result is None
    assert _row(sync_conn)["password_hash"] is None


@pytest.mark.parametrize(
    "active,verified,admin", [(True, False, False), (False, True, False), (False, False, True)]
)
def test_schema_rejects_passwordless_local_outside_pending_state(
    sync_conn, active, verified, admin
):
    """Verify schema rejects passwordless local outside pending state."""
    with (
        pytest.raises(CheckViolation, match="users_local_password_required"),
        sync_conn.transaction(),
    ):
        sync_conn.execute(
            """INSERT INTO users (email, auth_method, password_hash, is_active, email_verified, is_admin)
               VALUES (%s, 'local', NULL, %s, %s, %s)""",
            (EMAIL, active, verified, admin),
        )


async def test_concurrent_setup_forms_have_one_credential_winner(db_pool, sync_conn, monkeypatch):
    """Verify concurrent setup forms have one credential winner."""
    await begin_local_registration(db_pool, email=EMAIL)
    token = _token(sync_conn)
    real_work = registration_setup.run_password_work
    both_hashing = asyncio.Event()
    arrivals = 0

    async def hash_after_both_snapshots(function, *args, **kwargs):
        """Wait until both callers reach password hashing, then perform the real work."""
        nonlocal arrivals
        arrivals += 1
        if arrivals == 2:
            both_hashing.set()
        await asyncio.wait_for(both_hashing.wait(), timeout=10)
        return await real_work(function, *args, **kwargs)

    work = create_autospec(real_work, spec_set=True, side_effect=hash_after_both_snapshots)
    monkeypatch.setattr(registration_setup, "run_password_work", work)
    completions = [
        complete_local_registration(
            db_pool, token=token, display_name="Mira Cole", password=password
        )
        for password in (PASSWORD, OTHER_PASSWORD)
    ]
    results = await asyncio.gather(*completions)
    assert sum(result is not None for result in results) == 1
    assert arrivals == 2
    for result, password in zip(results, (PASSWORD, OTHER_PASSWORD), strict=True):
        assert (await verify_password(db_pool, EMAIL, password)).password_ok is (result is not None)
    assert _row(sync_conn)["auth_revision"] == 1
