"""Self-service email-change confirmation — real PostgreSQL, real routes, real services."""

import logging

import pyotp
from fastapi import status

from app.services.db import get_db_cursor
from app.services.email_change import (
    generate_email_change_token,
    pending_email_change_matches,
    store_pending_email,
)
from app.services.tokens import action_token_public_id, hash_token
from app.services.totp_crypto import encrypt_value
from tests.action_links import action_path
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

NEW_EMAIL = "new@example.org"
_SESSION_COUNT_BEFORE_CONFIRM = 2


# Helpers


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


def _pending_state(sync_conn, user_id):
    """(email, pending_email, pending_email_token_hash, pending_email_created_at)."""
    return sync_conn.execute(
        """SELECT email, pending_email, pending_email_token_hash,
                  pending_email_created_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


def _session_count(sync_conn, user_id):
    """Count stored sessions for the user, including expired rows."""
    return sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]


def _audit_events(caplog, event_type):
    """Select the requested audit event from captured log records."""
    return [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == event_type
    ]


async def _stage_via_service(db_pool, user_id, new_email, acting_admin_id=None):
    """Stage a revision-bound pending row for confirmation-only tests."""
    async with get_db_cursor(db_pool) as cur:
        await cur.execute(
            "SELECT auth_revision FROM users WHERE id = %s",
            (user_id,),
        )
        row = await cur.fetchone()
    assert row is not None
    revision = row["auth_revision"]
    token = generate_email_change_token(
        user_id,
        new_email,
        auth_revision=revision,
        acting_admin_id=acting_admin_id,
    )
    await store_pending_email(
        db_pool,
        user_id,
        new_email,
        hash_token(token),
        expected_auth_revision=revision,
    )
    return token


# Confirmation (GET page + POST /account/confirm-email), self-service


class TestConfirmationFlow:
    """Check confirmation Flow."""

    async def test_confirm_flow_commits_change_and_kills_sessions(
        self, e2e_client, db_pool, user_factory, session_factory, sync_conn, caplog
    ):
        """Verify confirm flow commits change and kills sessions."""
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        session_factory(u.id)  # a second device's session — must die too
        assert _session_count(sync_conn, u.id) == _SESSION_COUNT_BEFORE_CONFIRM

        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)
        staged = _pending_state(sync_conn, u.id)

        # GET twice — side-effect-free both times.
        for _ in range(2):
            page = e2e_client.get(action_path("/account/confirm-email", token))
            assert page.status_code == status.HTTP_200_OK
            assert NEW_EMAIL not in page.text and token not in page.text
            assert _pending_state(sync_conn, u.id) == staged

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                "/account/confirm-email",
                data={
                    "token": token,
                    "public_id": action_token_public_id(token),
                },  # no csrf_token — by design
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/login?notice=email_changed"

        email, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
        assert email == NEW_EMAIL
        assert (pending, token_hash, created_at) == (None, None, None)

        assert _session_count(sync_conn, u.id) == 0
        # The presented cookie is dead: an account page hit bounces to login.
        after = e2e_client.get("/account", follow_redirects=False)
        assert after.status_code == status.HTTP_303_SEE_OTHER
        assert after.headers["location"].startswith("/login")

        events = _audit_events(caplog, "email_changed")
        assert len(events) == 1
        assert events[0].user_id == u.id

        verified = sync_conn.execute(
            "SELECT email_verified FROM users WHERE id = %s", (u.id,)
        ).fetchone()[0]
        assert verified is True

    async def test_staged_change_expires_at_db_level(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """Verify staged change expires at database level."""
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)
        sync_conn.execute(
            """UPDATE users
               SET pending_email_created_at = CURRENT_TIMESTAMP - INTERVAL '61 minutes'
               WHERE id = %s""",
            (u.id,),
        )
        sync_conn.commit()

        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in resp.text
        email, _, _, _ = _pending_state(sync_conn, u.id)
        assert email == u.email

    async def test_confirm_token_is_single_use(self, e2e_client, db_pool, user_factory):
        """Verify confirm token is single use."""
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)

        first = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
            follow_redirects=False,
        )
        assert first.status_code == status.HTTP_303_SEE_OTHER

        second = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
        )
        assert second.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in second.text

    async def test_restaging_invalidates_previous_token(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """One outstanding change per user: staging 'b@example.org' overwrites the
        pending row for 'a@example.org', so the FIRST token now fails the stored
        hash/email binding and cannot commit the stale address.
        """
        u = user_factory()
        token_a = await _stage_via_service(db_pool, u.id, "a@example.org")
        token_b = await _stage_via_service(db_pool, u.id, "b@example.org")
        assert token_a != token_b

        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token_a, "public_id": action_token_public_id(token_a)},
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in resp.text

        # Untouched: email unchanged, the 'b' staging still pending.
        email, pending, token_hash, _ = _pending_state(sync_conn, u.id)
        assert email == u.email
        assert pending == "b@example.org"
        assert token_hash == hash_token(token_b)

    async def test_confirm_rechecks_uniqueness_against_register_race(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """Uniqueness re-check at confirm: someone registers the staged address
        between request and confirm → the confirm POST fails with 400 and the
        user's email is unchanged (the NOT EXISTS clause in the atomic UPDATE).
        """
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, "taken@example.org")
        user_factory(email="taken@example.org")  # the race: address now owned

        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in resp.text

        email, _, _, _ = _pending_state(sync_conn, u.id)
        assert email == u.email

    async def test_confirmation_get_rejects_replaced_token_for_same_email_and_revision(
        self, db_pool, user_factory
    ):
        """The non-consuming GET-page check (pending_email_change_matches)
        binds on the exact token hash, not just the pending email/revision
        pair: restaging the same address with a new hash makes the OLD hash
        stop matching immediately, while the newly-staged hash matches."""
        user = user_factory()
        await store_pending_email(db_pool, user.id, NEW_EMAIL, "a" * 64, expected_auth_revision=0)
        await store_pending_email(db_pool, user.id, NEW_EMAIL, "b" * 64, expected_auth_revision=0)
        assert not await pending_email_change_matches(
            db_pool, user.id, NEW_EMAIL, expected_auth_revision=0, expected_token_hash="a" * 64
        )
        assert await pending_email_change_matches(
            db_pool, user.id, NEW_EMAIL, expected_auth_revision=0, expected_token_hash="b" * 64
        )
