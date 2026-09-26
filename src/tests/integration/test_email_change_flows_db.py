"""Self-service email-change staging — real PostgreSQL, real routes, real services.

Covers POST /account/change-email (src/app/routes/auth/email_change.py) and
the staging half of src/app/services/email_change.py: who receives which
mail, the account-membership secrecy shape, the re-auth gate, and the
row-lock release/recheck around the slow password-verification work.

Self-service confirmation (GET/POST /account/confirm-email) lives in
test_email_change_confirmation_db.py, the administrator-initiated variant in
test_admin_email_change_flows_db.py, and delivery to SMTP plus
enqueue-failure rollback in test_email_change_delivery_db.py.
"""

import asyncio
import logging

import pyotp
import pytest
from fastapi import status
from pydantic import SecretStr

from app.services import email_change, federated_session_policy
from app.services.crypto import decrypt_outbox_body, encrypt_value
from app.services.session_ids import hash_session_id
from config import settings
from tests.fixtures import sign_session_id
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


def _decrypt_body(message):
    """Decrypt one persisted body and assert that encryption was real."""
    body = decrypt_outbox_body(message["body_ciphertext"])
    assert body is not None
    assert body != message["body_ciphertext"]
    return body


def _confirmation_url(body):
    """Extract the absolute confirmation URL from a rendered email body."""
    prefix = f"{settings.public_base_url}/account/confirm-email/"
    matches = [word.rstrip(".,)") for word in body.split() if word.startswith(prefix)]
    assert len(matches) == 1
    return matches[0]


def _audit_events(caplog, event_type):
    return [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == event_type
    ]


# ---------------------------------------------------------------------------
# Staging (POST /account/change-email through the real route)
# ---------------------------------------------------------------------------


class TestStagingRequest:
    async def test_change_email_post_stages_pending_change(
        self, e2e_client, user_factory, sync_conn
    ):
        """Happy-path staging commits pending state and both outbox messages."""
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        csrf = _csrf_for_session(e2e_client)

        resp = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/account"
        assert resp.content == b""

        email, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
        assert email == u.email
        assert pending == NEW_EMAIL
        assert token_hash is not None
        assert created_at is not None

        messages = _outbox_messages(sync_conn, u.id)
        assert len(messages) == _EMAIL_CHANGE_MESSAGE_COUNT
        by_type = {message["message_type"]: message for message in messages}
        assert set(by_type) == {
            "email_change_verification",
            "email_change_notice",
        }
        assert by_type["email_change_verification"]["recipient"] == NEW_EMAIL
        assert by_type["email_change_notice"]["recipient"] == u.email
        assert all(message["status"] == "pending" for message in messages)

        flash = sync_conn.execute(
            "SELECT flash_message, flash_category FROM sessions WHERE user_id = %s",
            (u.id,),
        ).fetchone()
        assert flash == (
            "If the requested address can be used, a confirmation email will be sent shortly.",
            "success",
        )

    async def test_change_email_rejects_only_the_users_own_current_address(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """The current address is the actor's own known state, not membership data."""
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        csrf = _csrf_for_session(e2e_client)

        response = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": u.email,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "That is already your email address." in response.text
        _, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
        assert (pending, token_hash, created_at) == (None, None, None)

    async def test_change_email_does_not_disclose_destination_account_membership(
        self,
        e2e_client,
        user_factory,
        sync_conn,
        caplog,
    ):
        """Membership is absent from HTTP, audit, flash, and actor mail."""
        occupied = user_factory(email="occupied@uzh.ch")
        actor, secret = _make_totp_user(user_factory)
        _login(e2e_client, actor, secret)
        csrf = _csrf_for_session(e2e_client)

        with caplog.at_level(logging.INFO, logger="audit"):
            occupied_response = e2e_client.post(
                "/account/change-email",
                data={
                    "new_email": occupied.email,
                    "current_password": DEFAULT_PASSWORD,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )

        email, pending, token_hash, created_at = _pending_state(sync_conn, actor.id)
        assert email == actor.email
        assert pending == occupied.email
        assert token_hash is not None
        assert created_at is not None
        first_token_hash = token_hash
        occupied_messages = _outbox_messages(sync_conn, actor.id)
        assert len(occupied_messages) == _EMAIL_CHANGE_MESSAGE_COUNT
        occupied_notice = next(
            message
            for message in occupied_messages
            if message["message_type"] == "email_change_notice"
        )
        occupied_verification = next(
            message
            for message in occupied_messages
            if message["message_type"] == "email_change_verification"
        )
        assert occupied_notice["message_type"] == "email_change_notice"
        assert occupied_notice["recipient"] == actor.email
        assert occupied_notice["status"] == "pending"
        assert occupied_verification["recipient"] == occupied.email
        assert occupied_verification["status"] == "pending"
        occupied_notice_observable = (
            occupied_notice["message_type"],
            occupied_notice["recipient"],
            occupied_notice["subject"],
            _decrypt_body(occupied_notice),
            occupied_notice["status"],
        )
        assert occupied.email in occupied_notice_observable[3]

        occupied_flash = sync_conn.execute(
            "SELECT flash_message, flash_category FROM sessions WHERE user_id = %s",
            (actor.id,),
        ).fetchone()
        occupied_account = e2e_client.get("/account")

        sync_conn.execute("DELETE FROM users WHERE id = %s", (occupied.id,))
        sync_conn.commit()

        with caplog.at_level(logging.INFO, logger="audit"):
            available_response = e2e_client.post(
                "/account/change-email",
                data={
                    "new_email": occupied.email,
                    "current_password": DEFAULT_PASSWORD,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )

        occupied_observable = (
            occupied_response.status_code,
            occupied_response.headers.get("location"),
            occupied_response.content,
        )
        available_observable = (
            available_response.status_code,
            available_response.headers.get("location"),
            available_response.content,
        )
        assert occupied_observable == available_observable
        assert occupied_observable == (status.HTTP_303_SEE_OTHER, "/account", b"")
        assert "cannot be used" not in occupied_response.text

        email, pending, token_hash, created_at = _pending_state(sync_conn, actor.id)
        assert email == actor.email
        assert pending == occupied.email
        assert token_hash is not None
        assert token_hash != first_token_hash
        assert created_at is not None
        messages = _outbox_messages(sync_conn, actor.id)
        assert len(messages) == 4
        notices = [
            message for message in messages if message["message_type"] == "email_change_notice"
        ]
        verifications = [
            message
            for message in messages
            if message["message_type"] == "email_change_verification"
        ]
        assert len(notices) == 2
        assert len(verifications) == 2
        assert [message["recipient"] for message in verifications] == [
            occupied.email,
            occupied.email,
        ]
        assert [message["status"] for message in verifications] == ["dead", "pending"]

        available_notice = notices[1]
        available_notice_observable = (
            available_notice["message_type"],
            available_notice["recipient"],
            available_notice["subject"],
            _decrypt_body(available_notice),
            available_notice["status"],
        )
        assert available_notice_observable == occupied_notice_observable

        available_flash = sync_conn.execute(
            "SELECT flash_message, flash_category FROM sessions WHERE user_id = %s",
            (actor.id,),
        ).fetchone()
        available_account = e2e_client.get("/account")
        assert (
            occupied_flash
            == available_flash
            == (
                "If the requested address can be used, a confirmation email will be sent shortly.",
                "success",
            )
        )
        assert occupied_account.status_code == available_account.status_code == status.HTTP_200_OK
        assert occupied_account.text == available_account.text

        events = _audit_events(caplog, "email_change_requested")
        assert len(events) == 2
        assert [event.user_id for event in events] == [actor.id, actor.id]

    async def test_later_occupied_request_supersedes_prior_pending_capability(
        self,
        e2e_client,
        user_factory,
        sync_conn,
    ):
        """An occupied probe cannot preserve an older usable change token."""
        occupied = user_factory(email="occupied@uzh.ch")
        actor, secret = _make_totp_user(user_factory)
        _login(e2e_client, actor, secret)
        csrf = _csrf_for_session(e2e_client)

        first = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": "first-unused@uzh.ch",
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert first.status_code == status.HTTP_303_SEE_OTHER
        first_messages = _outbox_messages(sync_conn, actor.id)
        first_verification = next(
            message
            for message in first_messages
            if message["message_type"] == "email_change_verification"
        )
        first_url = _confirmation_url(_decrypt_body(first_verification))

        occupied_response = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": occupied.email,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert occupied_response.status_code == status.HTTP_303_SEE_OTHER
        assert occupied_response.headers["location"] == "/account"
        assert occupied_response.content == b""

        email, pending, token_hash, created_at = _pending_state(sync_conn, actor.id)
        assert email == actor.email
        assert pending == occupied.email
        assert token_hash is not None
        assert created_at is not None

        messages = _outbox_messages(sync_conn, actor.id)
        verification_messages = [
            message
            for message in messages
            if message["message_type"] == "email_change_verification"
        ]
        assert len(verification_messages) == 2
        assert verification_messages[0]["recipient"] == "first-unused@uzh.ch"
        assert verification_messages[0]["status"] == "dead"
        assert verification_messages[1]["recipient"] == occupied.email
        assert verification_messages[1]["status"] == "pending"

        old_page = e2e_client.get(first_url.removeprefix(settings.public_base_url))
        assert old_page.status_code == status.HTTP_400_BAD_REQUEST
        assert "Link no longer valid" in old_page.text

    async def test_staging_rejected_with_wrong_current_password(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """Re-auth gate: a wrong current password → 422 with 'Current password is
        incorrect', an 'email_change_blocked_invalid_password' audit event, and
        NOTHING staged (a hijacked session cannot silently relocate the account).
        """
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        csrf = _csrf_for_session(e2e_client)

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                "/account/change-email",
                data={
                    "new_email": NEW_EMAIL,
                    "current_password": "definitely-wrong-Pw1!",
                    "csrf_token": csrf,
                },
            )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Current password is incorrect." in resp.text

        events = _audit_events(caplog, "email_change_blocked_invalid_password")
        assert len(events) == 1
        assert events[0].user_id == u.id

        _, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
        assert (pending, token_hash, created_at) == (None, None, None)

    async def test_change_email_forbidden_for_shibboleth_user(
        self, e2e_client, user_factory, session_factory, monkeypatch, db_pool
    ):
        """Local-auth gate: a Shibboleth user (attributes come from the IdP)
        gets 403 from GET /account/change-email. Session planted directly —
        shibboleth accounts have no password login path.
        """
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(
            settings, "shibboleth_trusted_issuers", ["https://idp.test.example/idp/shibboleth"]
        )
        monkeypatch.setattr(
            settings,
            "shibboleth_internal_secret",
            SecretStr("independent-test-secret-for-session-policy"),
        )
        await federated_session_policy.reconcile_federated_session_policy(db_pool)
        u = user_factory(auth_method="shibboleth")
        raw = session_factory(u.id)
        e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))

        resp = e2e_client.get("/account/change-email")
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_change_email_recipient_wiring_and_emailed_link_works(
        self, e2e_client, user_factory, sync_conn
    ):
        """The staged flow's entire security value is WHO gets WHICH
        email: the confirmation capability link goes to the NEW address (proving
        control of it before commit) and the heads-up notice to the OLD address
        (so a hijack victim is alarmed). An argument swap inverts both and ships
        green without this test. The captured link is then driven end-to-end: the
        URL persisted in the durable outbox is the URL that works."""
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        csrf = _csrf_for_session(e2e_client)

        resp = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        messages = _outbox_messages(sync_conn, u.id)
        assert len(messages) == _EMAIL_CHANGE_MESSAGE_COUNT
        by_type = {message["message_type"]: message for message in messages}

        verification = by_type["email_change_verification"]
        assert verification["recipient"] == NEW_EMAIL
        verification_body = _decrypt_body(verification)
        confirm_url = _confirmation_url(verification_body)

        notice = by_type["email_change_notice"]
        assert notice["recipient"] == u.email
        notice_body = _decrypt_body(notice)
        assert NEW_EMAIL in notice_body
        assert all(message["status"] == "pending" for message in messages)

        # The emailed link is live: GET renders the confirm page, POST commits.
        path = confirm_url[len(settings.public_base_url) :]
        page = e2e_client.get(path)
        assert page.status_code == status.HTTP_200_OK
        assert NEW_EMAIL in page.text

        token = path.removeprefix("/account/confirm-email/")
        done = e2e_client.post(
            "/account/confirm-email", data={"token": token}, follow_redirects=False
        )
        assert done.status_code == status.HTTP_303_SEE_OTHER
        email, pending, _, _ = _pending_state(sync_conn, u.id)
        assert email == NEW_EMAIL and pending is None


# ---------------------------------------------------------------------------
# Lock release around the slow password-verification work in staging
# ---------------------------------------------------------------------------


class TestPasswordWorkLockRelease:
    """`stage_self_email_change` releases the user and presenting-session row
    locks while the slow password-verification work runs, then rechecks the
    account/session snapshot before committing anything — so a concurrent
    change to either row is never staged against, or built on top of, a
    stale read.
    """

    @pytest.mark.parametrize(
        "change",
        ["hash", "revision", "session", "expiry", "inactive"],
        ids=[
            "password_changed_during_verification",
            "auth_revision_bumped_during_verification",
            "presenting_session_deleted_during_verification",
            "presenting_session_expired_during_verification",
            "account_deactivated_during_verification",
        ],
    )
    async def test_email_change_releases_locks_during_password_work_and_rechecks_snapshot(
        self, db_pool, sync_conn, user_factory, session_factory, monkeypatch, change
    ):
        """While the CPU-bound password verification runs (off the row
        locks), a concurrent write lands on the user or session row using
        `FOR UPDATE NOWAIT` — which only succeeds if staging is genuinely not
        holding either lock during that work. Once the concurrent write
        commits, staging must reject with SelfEmailChangeRejected on its
        post-verification recheck and must queue no pending email change or
        outbox message."""
        user = user_factory()
        session_id = session_factory(user.id, purpose="full")
        password_started = asyncio.Event()
        release_password = asyncio.Event()
        real_work = email_change.run_password_work

        async def delayed_password_work(function, *args):
            password_started.set()
            await release_password.wait()
            return await real_work(function, *args)

        monkeypatch.setattr(email_change, "run_password_work", delayed_password_work)
        task = asyncio.create_task(
            email_change.stage_self_email_change(
                db_pool,
                user_id=user.id,
                session_id=session_id,
                current_password=user.password,
                new_email="new-address@uzh.ch",
            )
        )
        try:
            await asyncio.wait_for(password_started.wait(), 5)
            # NOWAIT would fail if the queued password work retained either lock.
            sync_conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE NOWAIT", (user.id,))
            sync_conn.execute(
                "SELECT id FROM sessions WHERE id = %s FOR UPDATE NOWAIT",
                (hash_session_id(session_id),),
            )
            if change == "hash":
                sync_conn.execute(
                    "UPDATE users SET password_hash = 'different-hash' WHERE id = %s", (user.id,)
                )
            elif change == "revision":
                sync_conn.execute(
                    "UPDATE users SET auth_revision = auth_revision + 1 WHERE id = %s", (user.id,)
                )
            elif change == "inactive":
                sync_conn.execute("UPDATE users SET is_active = false WHERE id = %s", (user.id,))
            elif change == "expiry":
                sync_conn.execute(
                    "UPDATE sessions SET expires_at = clock_timestamp() - interval '1 second'"
                    " WHERE id = %s",
                    (hash_session_id(session_id),),
                )
            else:
                sync_conn.execute(
                    "DELETE FROM sessions WHERE id = %s", (hash_session_id(session_id),)
                )
            sync_conn.commit()
            release_password.set()
            with pytest.raises(email_change.SelfEmailChangeRejected):
                await asyncio.wait_for(task, 5)
            assert (
                sync_conn.execute(
                    "SELECT pending_email FROM users WHERE id = %s", (user.id,)
                ).fetchone()[0]
                is None
            )
            assert sync_conn.execute("SELECT count(*) FROM email_outbox").fetchone()[0] == 0
        finally:
            release_password.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
