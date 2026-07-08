"""Self-service email-change flow — real PostgreSQL, real routes, real services.

End-to-end coverage of src/app/routes/auth/email_change.py and
src/app/services/email_change.py (cf. TESTING_BACKLOG §2.1/§2.5 family:
the token single-use / uniqueness-recheck / missing-`await` shapes that
only a real database exercises — a zero-row UPDATE must report failure).

Staging is exercised through the real POST route; the confirm tests stage
via the service (generate_email_change_token + store_pending_email) because
the route's token is random-signed and only leaves the app inside the
outgoing email.
"""
import logging
from unittest.mock import patch

import pyotp

from app.services.crypto import encrypt_value
from app.services.email_change import (
    generate_email_change_token,
    store_pending_email,
)
from app.services.tokens import hash_token
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

NEW_EMAIL = "new@uzh.ch"


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
    assert resp.status_code == 303, "login must succeed to a full session"
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


def _session_count(sync_conn, user_id):
    return sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (user_id,)
    ).fetchone()[0]


def _audit_events(caplog, event_type):
    return [
        r for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == event_type
    ]


async def _stage_via_service(db_pool, user_id, new_email, acting_admin_id=None):
    """Stage a pending change exactly as the route does, returning the token."""
    token = generate_email_change_token(
        user_id, new_email, acting_admin_id=acting_admin_id
    )
    await store_pending_email(db_pool, user_id, new_email, hash_token(token))
    return token


# ---------------------------------------------------------------------------
# Staging (POST /account/change-email through the real route)
# ---------------------------------------------------------------------------

async def test_change_email_post_stages_pending_change(
    e2e_client, user_factory, sync_conn
):
    """Happy-path staging: POST /account/change-email with the correct
    current password → 303 to /account, a success flash staged on the
    session, and the users row gets pending_email + token hash + created_at
    while the live email column stays untouched.

    Regression guard: a missing `await` on store_pending_email would leave
    every pending_* column NULL while the route still 303s "success".
    """
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
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"

    email, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
    assert email == u.email  # not changed yet — only staged
    assert pending == NEW_EMAIL
    assert token_hash is not None
    assert created_at is not None

    # Flash staged on the presenting session (set_flash via the raw cookie id).
    flash = sync_conn.execute(
        "SELECT flash_message, flash_category FROM sessions WHERE user_id = %s",
        (u.id,),
    ).fetchone()
    assert flash == (
        "Check your new email address for a confirmation link.", "success",
    )


async def test_staging_rejected_with_wrong_current_password(
    e2e_client, user_factory, sync_conn, caplog
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
    assert resp.status_code == 422
    assert "Current password is incorrect." in resp.text

    events = _audit_events(caplog, "email_change_blocked_invalid_password")
    assert len(events) == 1
    assert events[0].user_id == u.id

    _, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
    assert (pending, token_hash, created_at) == (None, None, None)


async def test_staging_rejects_same_and_taken_addresses(
    e2e_client, user_factory, sync_conn
):
    """Address validation at staging: (a) the user's own current address →
    422 'That is already your email address.'; (b) an address owned by
    another account → 422 with the neutral 'That email address cannot be
    used.' (no account-existence oracle). Nothing is staged either way.

    Regression guard (backlog §2.5 shape): `get_user_by_email(...)` used
    without `await` makes EVERY address look taken.
    """
    other = user_factory(email="taken@uzh.ch")
    u, secret = _make_totp_user(user_factory)
    _login(e2e_client, u, secret)
    csrf = _csrf_for_session(e2e_client)

    resp_same = e2e_client.post(
        "/account/change-email",
        data={
            "new_email": u.email,
            "current_password": DEFAULT_PASSWORD,
            "csrf_token": csrf,
        },
    )
    assert resp_same.status_code == 422
    assert "That is already your email address." in resp_same.text

    resp_taken = e2e_client.post(
        "/account/change-email",
        data={
            "new_email": other.email,
            "current_password": DEFAULT_PASSWORD,
            "csrf_token": csrf,
        },
    )
    assert resp_taken.status_code == 422
    assert "That email address cannot be used." in resp_taken.text

    _, pending, token_hash, _ = _pending_state(sync_conn, u.id)
    assert pending is None and token_hash is None


async def test_change_email_forbidden_for_shibboleth_user(
    e2e_client, user_factory, session_factory
):
    """Local-auth gate: a Shibboleth user (attributes come from the IdP)
    gets 403 from GET /account/change-email. Session planted directly —
    shibboleth accounts have no password login path.
    """
    u = user_factory(auth_method="shibboleth")
    raw = session_factory(u.id)
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))

    resp = e2e_client.get("/account/change-email")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Confirmation (GET page + POST /account/confirm-email)
# ---------------------------------------------------------------------------

async def test_confirm_flow_commits_change_and_kills_sessions(
    e2e_client, db_pool, user_factory, session_factory, sync_conn, caplog
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
    assert _session_count(sync_conn, u.id) == 2

    token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)
    staged = _pending_state(sync_conn, u.id)

    # GET twice — side-effect-free both times.
    for _ in range(2):
        page = e2e_client.get(f"/account/confirm-email/{token}")
        assert page.status_code == 200
        assert NEW_EMAIL in page.text
        assert _pending_state(sync_conn, u.id) == staged

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            "/account/confirm-email",
            data={"token": token},  # no csrf_token — by design
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?email_changed=1"

    email, pending, token_hash, created_at = _pending_state(sync_conn, u.id)
    assert email == NEW_EMAIL
    assert (pending, token_hash, created_at) == (None, None, None)

    assert _session_count(sync_conn, u.id) == 0
    # The presented cookie is dead: an account page hit bounces to login.
    after = e2e_client.get("/account", follow_redirects=False)
    assert after.status_code == 303
    assert after.headers["location"].startswith("/login")

    events = _audit_events(caplog, "email_changed")
    assert len(events) == 1
    assert events[0].user_id == u.id


async def test_change_email_recipient_wiring_and_emailed_link_works(
    e2e_client, user_factory, sync_conn
):
    """TEST-013 — the staged flow's entire security value is WHO gets WHICH
    email: the confirmation capability link goes to the NEW address (proving
    control of it before commit) and the heads-up notice to the OLD address
    (so a hijack victim is alarmed). An argument swap inverts both and ships
    green without this test. The captured link is then driven end-to-end
    (TEST-015 family): the URL the app would email is the URL that works."""
    u, secret = _make_totp_user(user_factory)
    _login(e2e_client, u, secret)
    csrf = _csrf_for_session(e2e_client)

    with patch(
        "app.routes.auth.email_change.send_email_change_verification",
        autospec=True,
    ) as verify, patch(
        "app.routes.auth.email_change.send_email_change_notice",
        autospec=True,
    ) as notice:
        resp = e2e_client.post(
            "/account/change-email",
            data={
                "new_email": NEW_EMAIL,
                "current_password": DEFAULT_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
    assert resp.status_code == 303

    # Capability link → the NEW address, built on public_base_url.
    verify.assert_called_once()
    verify_to, confirm_url = verify.call_args.args
    assert verify_to == NEW_EMAIL
    assert confirm_url.startswith(
        settings.public_base_url + "/account/confirm-email/"
    )
    # Notice → the OLD address, naming the new one.
    notice.assert_called_once()
    assert notice.call_args.args[0] == u.email
    assert notice.call_args.args[1] == NEW_EMAIL

    # The emailed link is live: GET renders the confirm page, POST commits.
    path = confirm_url[len(settings.public_base_url):]
    page = e2e_client.get(path)
    assert page.status_code == 200
    assert NEW_EMAIL in page.text

    token = path.removeprefix("/account/confirm-email/")
    done = e2e_client.post(
        "/account/confirm-email", data={"token": token}, follow_redirects=False
    )
    assert done.status_code == 303
    email, pending, _, _ = _pending_state(sync_conn, u.id)
    assert email == NEW_EMAIL and pending is None


async def test_staged_change_expires_at_db_level(
    e2e_client, db_pool, user_factory, sync_conn
):
    """TEST-059 — the 60-minute window is enforced in SQL as well as in the
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
    assert resp.status_code == 400
    assert "Could not change email" in resp.text
    email, _, _, _ = _pending_state(sync_conn, u.id)
    assert email == u.email


async def test_confirm_token_is_single_use(e2e_client, db_pool, user_factory):
    """Single-use: replaying the SAME token after a successful confirm →
    400 'Could not change email' (the atomic UPDATE...WHERE matches zero
    rows because pending_email_token_hash was cleared).

    Regression guard (backlog §2.1 shape): `cur.fetchone() is not None`
    without `await` reports success on the zero-row second attempt.
    """
    u = user_factory()
    token = await _stage_via_service(db_pool, u.id, NEW_EMAIL)

    first = e2e_client.post(
        "/account/confirm-email", data={"token": token}, follow_redirects=False
    )
    assert first.status_code == 303

    second = e2e_client.post("/account/confirm-email", data={"token": token})
    assert second.status_code == 400
    assert "Could not change email" in second.text


async def test_restaging_invalidates_previous_token(
    e2e_client, db_pool, user_factory, sync_conn
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
    assert resp.status_code == 400
    assert "Could not change email" in resp.text

    # Untouched: email unchanged, the 'b' staging still pending.
    email, pending, token_hash, _ = _pending_state(sync_conn, u.id)
    assert email == u.email
    assert pending == "b@uzh.ch"
    assert token_hash == hash_token(token_b)


async def test_confirm_rechecks_uniqueness_against_register_race(
    e2e_client, db_pool, user_factory, sync_conn
):
    """Uniqueness re-check at confirm: someone registers the staged address
    between request and confirm → the confirm POST fails with 400 and the
    user's email is unchanged (the NOT EXISTS clause in the atomic UPDATE).
    """
    u = user_factory()
    token = await _stage_via_service(db_pool, u.id, "taken@uzh.ch")
    user_factory(email="taken@uzh.ch")  # the race: address now owned

    resp = e2e_client.post("/account/confirm-email", data={"token": token})
    assert resp.status_code == 400
    assert "Could not change email" in resp.text

    email, _, _, _ = _pending_state(sync_conn, u.id)
    assert email == u.email


async def test_admin_initiated_confirm_logs_admin_audit_event(
    e2e_client, db_pool, user_factory, sync_conn, caplog
):
    """Admin-initiated variant: a token carrying acting_admin_id commits the
    change and the audit trail records 'admin_email_changed' with
    actor_admin_id + target_user_id (not the self-service 'email_changed').
    """
    admin = user_factory(is_admin=True)
    u = user_factory()
    token = await _stage_via_service(
        db_pool, u.id, NEW_EMAIL, acting_admin_id=admin.id
    )

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            "/account/confirm-email", data={"token": token},
            follow_redirects=False,
        )
    assert resp.status_code == 303

    email, _, _, _ = _pending_state(sync_conn, u.id)
    assert email == NEW_EMAIL

    events = _audit_events(caplog, "admin_email_changed")
    assert len(events) == 1
    assert events[0].actor_admin_id == admin.id
    assert events[0].target_user_id == u.id
    assert not _audit_events(caplog, "email_changed")
