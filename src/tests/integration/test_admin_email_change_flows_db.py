"""Administrator-initiated email-change confirmation — real PostgreSQL, real routes, real services."""

import logging

import pyotp
from fastapi import status

from app.services.db import get_db_cursor
from app.services.email_change import generate_email_change_token, store_pending_email
from app.services.tokens import action_token_public_id, hash_token
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

NEW_EMAIL = "new@example.org"


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


# Confirmation of an administrator-staged change


class TestAdminInitiatedConfirmation:
    """Check admin Initiated Confirmation."""

    async def test_admin_initiated_confirm_logs_admin_audit_event(
        self, e2e_client, db_pool, user_factory, sync_conn, caplog
    ):
        """Admin-initiated variant: a token carrying acting_admin_id commits the
        change and the audit trail records 'admin_email_changed' with
        actor_admin_id + target_user_id (not the self-service 'email_changed').
        """
        admin = user_factory(is_admin=True)
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL, acting_admin_id=admin.id)

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                "/account/confirm-email",
                data={"token": token, "public_id": action_token_public_id(token)},
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        email, _, _, _ = _pending_state(sync_conn, u.id)
        assert email == NEW_EMAIL

        events = _audit_events(caplog, "admin_email_changed")
        assert len(events) == 1
        assert events[0].actor_admin_id == admin.id
        assert events[0].target_user_id == u.id
        assert not _audit_events(caplog, "email_changed")

    async def test_admin_confirm_verifies_previously_unverified_account(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """Verify admin confirm verifies previously unverified account."""
        target = user_factory(email_verified=False)
        admin = user_factory(is_admin=True)

        # Sanity: the pre-state is genuinely unverified with a live verification token.
        # (If user_factory doesn't stamp a verification token, stage one so the
        # clear-on-confirm assertion has something to clear.)
        token = await _stage_via_service(db_pool, target.id, NEW_EMAIL, acting_admin_id=admin.id)

        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER

        row = sync_conn.execute(
            """SELECT email, email_verified,
                      email_verification_token_hash, email_verification_created_at,
                      pending_email
               FROM users WHERE id = %s""",
            (target.id,),
        ).fetchone()
        email, verified, ev_hash, ev_created, pending = row
        assert email == NEW_EMAIL  # change committed
        assert verified is True
        assert ev_hash is None  # stale verification token cleared
        assert ev_created is None
        assert pending is None  # pending_* cleared as before

    async def test_bystander_admin_confirming_others_change_keeps_admin_logged_in(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """Verify bystander admin confirming others change keeps admin logged in."""
        admin, admin_secret = _make_totp_user(user_factory, is_admin=True)
        _login(e2e_client, admin, admin_secret)
        admin_cookie_before = e2e_client.cookies.get(settings.session_cookie_name)
        assert admin_cookie_before

        target = user_factory()
        token = await _stage_via_service(db_pool, target.id, NEW_EMAIL, acting_admin_id=admin.id)

        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token, "public_id": action_token_public_id(token)},
            follow_redirects=False,
        )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/login?notice=email_changed"

        # No Set-Cookie for the session cookie at all on this response: the
        # mismatch (admin.id != target.id) skips clear_session_cookie entirely,
        # and nothing else on this route touches the session cookie.
        assert not any(
            h.startswith(f"{settings.session_cookie_name}=")
            for h in resp.headers.get_list("set-cookie")
        )

        email, pending, _, _ = _pending_state(sync_conn, target.id)
        assert email == NEW_EMAIL and pending is None  # target's change committed

        # The admin's own cookie is unchanged and still authenticates them.
        assert e2e_client.cookies.get(settings.session_cookie_name) == admin_cookie_before
        after = e2e_client.get("/account", follow_redirects=False)
        assert after.status_code == status.HTTP_200_OK

        assert _session_count(sync_conn, target.id) == 0
