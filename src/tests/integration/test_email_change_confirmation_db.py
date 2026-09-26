"""Self-service email-change confirmation — real PostgreSQL, real routes, real services.

Covers GET/POST /account/confirm-email (src/app/routes/auth/email_change.py)
for a self-service-staged token against src/app/services/email_change.py:
the token single-use, expiry, uniqueness-recheck, and missing-`await` shapes
that only a real database exercises — a zero-row UPDATE must report failure.

Confirmation is exercised by staging directly through the service so each
test controls the exact signed token under test. Staging through the real
POST route and the lock-release behaviour around it live in
test_email_change_flows_db.py; the administrator-initiated confirmation
variant lives in test_admin_email_change_flows_db.py; delivery to SMTP and
enqueue-failure rollback live in test_email_change_delivery_db.py.
"""

import logging

import pyotp
from fastapi import status

from app.services.crypto import encrypt_value
from app.services.db import get_db_cursor
from app.services.email_change import (
    generate_email_change_token,
    pending_email_change_matches,
    store_pending_email,
)
from app.services.tokens import hash_token
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

NEW_EMAIL = "new@uzh.ch"
_SESSION_COUNT_BEFORE_CONFIRM = 2


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


def _pending_state(sync_conn, user_id):
    """(email, pending_email, pending_email_token_hash, pending_email_created_at)."""
    return sync_conn.execute(
        """SELECT email, pending_email, pending_email_token_hash,
                  pending_email_created_at
           FROM users WHERE id = %s""",
        (user_id,),
    ).fetchone()


def _session_count(sync_conn, user_id):
    return sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]


def _audit_events(caplog, event_type):
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


# ---------------------------------------------------------------------------
# Confirmation (GET page + POST /account/confirm-email), self-service
# ---------------------------------------------------------------------------


class TestConfirmationFlow:
    async def test_confirm_flow_commits_change_and_kills_sessions(
        self, e2e_client, db_pool, user_factory, session_factory, sync_conn, caplog
    ):
        """Full confirm flow for a service-staged token:

        - GET /account/confirm-email/{token} is SAFE: 200 confirm page, fetched
          TWICE, pending state byte-identical after both (mail scanners must not
          consume the token — see the route's docstring).
        - POST /account/confirm-email {'token': ...} — deliberately WITHOUT CSRF
          (the signed single-use token is the capability; the click may come
          from a device with no app session) — → 303 to /login?email_changed=1.
        - DB: email committed, all pending_* columns NULL.
        - ALL of the user's sessions are deleted, including the one presented
          with the request (email = account-recovery vector), so the old cookie
          no longer authenticates.
        - Audit channel records 'email_changed' for the user.
        """
        u, secret = _make_totp_user(user_factory)
        _login(e2e_client, u, secret)
        session_factory(u.id)  # a second device's session — must die too
        assert _session_count(sync_conn, u.id) == _SESSION_COUNT_BEFORE_CONFIRM

        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)
        staged = _pending_state(sync_conn, u.id)

        # GET twice — side-effect-free both times.
        for _ in range(2):
            page = e2e_client.get(f"/account/confirm-email/{token}")
            assert page.status_code == status.HTTP_200_OK
            assert NEW_EMAIL in page.text
            assert _pending_state(sync_conn, u.id) == staged

        with caplog.at_level(logging.INFO, logger="audit"):
            resp = e2e_client.post(
                "/account/confirm-email",
                data={"token": token},  # no csrf_token — by design
                follow_redirects=False,
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/login?email_changed=1"

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
        """The 60-minute window is enforced in SQL as well as in the
        itsdangerous signature: with the row's pending_email_created_at aged past
        the hour, the still-validly-signed token must fail (400) and change
        nothing. An interval-math typo (minutes vs seconds) voids this second
        expiry layer silently."""
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)
        sync_conn.execute(
            """UPDATE users
               SET pending_email_created_at = CURRENT_TIMESTAMP - INTERVAL '61 minutes'
               WHERE id = %s""",
            (u.id,),
        )
        sync_conn.commit()

        resp = e2e_client.post("/account/confirm-email", data={"token": token})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in resp.text
        email, _, _, _ = _pending_state(sync_conn, u.id)
        assert email == u.email

    async def test_confirm_token_is_single_use(self, e2e_client, db_pool, user_factory):
        """Single-use: replaying the SAME token after a successful confirm →
        400 'Could not change email' (the atomic UPDATE...WHERE matches zero
        rows because pending_email_token_hash was cleared).

        The zero-row second attempt must be reported as failure: an implementation
        that checks `cur.fetchone() is not None` without `await`-ing the coroutine
        would instead see a truthy coroutine object and report success.
        """
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)

        first = e2e_client.post(
            "/account/confirm-email", data={"token": token}, follow_redirects=False
        )
        assert first.status_code == status.HTTP_303_SEE_OTHER

        second = e2e_client.post("/account/confirm-email", data={"token": token})
        assert second.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in second.text

    async def test_restaging_invalidates_previous_token(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """One outstanding change per user: staging 'b@uzh.ch' overwrites the
        pending row for 'a@uzh.ch', so the FIRST token now fails the stored
        hash/email binding and cannot commit the stale address.
        """
        u = user_factory()
        token_a = await _stage_via_service(db_pool, u.id, "a@uzh.ch")
        token_b = await _stage_via_service(db_pool, u.id, "b@uzh.ch")
        assert token_a != token_b

        resp = e2e_client.post("/account/confirm-email", data={"token": token_a})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Could not change email" in resp.text

        # Untouched: email unchanged, the 'b' staging still pending.
        email, pending, token_hash, _ = _pending_state(sync_conn, u.id)
        assert email == u.email
        assert pending == "b@uzh.ch"
        assert token_hash == hash_token(token_b)

    async def test_confirm_rechecks_uniqueness_against_register_race(
        self, e2e_client, db_pool, user_factory, sync_conn
    ):
        """Uniqueness re-check at confirm: someone registers the staged address
        between request and confirm → the confirm POST fails with 400 and the
        user's email is unchanged (the NOT EXISTS clause in the atomic UPDATE).
        """
        u = user_factory()
        token = await _stage_via_service(db_pool, u.id, "taken@uzh.ch")
        user_factory(email="taken@uzh.ch")  # the race: address now owned

        resp = e2e_client.post("/account/confirm-email", data={"token": token})
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
