"""Admin-flow integration tests — real PostgreSQL, real routes, real middleware.

Covers TESTING_BACKLOG §2.5 (admin email change to a fresh address — the
un-awaited `get_user_by_email(...) is not None` regression rejected EVERY
change as "already in use") and §2.6 (admin action flash messages — the
un-awaited `set_flash` inside `_admin_redirect` silently dropped every
admin flash), plus the surrounding admin-route behaviors in
src/app/routes/auth/admin.py: set-active session revocation and the
asymmetric lockout clear, set-admin grant/revoke, self-action refusals,
no-change no-ops, require_admin's 404 cloak, and the federated-account
guard on change-email.

Every test drives the REAL login form (password + TOTP) so the session,
CSRF token, and flash storage are all the production paths.
"""
import logging
from unittest.mock import patch

import pyotp

from app.middleware.csrf import _compute_csrf_token
from app.services.crypto import encrypt_value
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.conftest import DEFAULT_PASSWORD, do_login


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login_admin(e2e_client, user_factory):
    """Create a TOTP-enabled admin and log them in for a FULL session.

    Returns (admin_handle, csrf_token) where csrf_token is the
    session-bound token minted by the subsequent GET /admin — the valid
    token for every admin POST in the test.
    """
    secret = pyotp.random_base32()
    admin = user_factory(is_admin=True, totp_secret=encrypt_value(secret))
    resp = do_login(
        e2e_client, admin.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now()
    )
    assert resp.status_code == 303  # sanity: full-session login succeeded

    page = e2e_client.get("/admin")
    assert page.status_code == 200  # sanity: the session really is admin
    return admin, e2e_client.cookies.get("csrf_token")


def _user_row(sync_conn, user_id, columns):
    return sync_conn.execute(
        f"SELECT {columns} FROM users WHERE id = %s", (user_id,)
    ).fetchone()


def _audit_records(caplog, event_type):
    return [
        rec for rec in caplog.records
        if rec.name == "audit" and getattr(rec, "event_type", None) == event_type
    ]


# ---------------------------------------------------------------------------
# §2.5 — admin email change to a FRESH address succeeds
# ---------------------------------------------------------------------------

def test_admin_change_email_fresh_address_stages_pending(
    e2e_client, user_factory, sync_conn, caplog
):
    """§2.5: changing a user's email to an address NO account uses stages
    the change (pending_email set, token hash stored) and flashes
    'Confirmation link sent' (§2.6: the flash actually renders).

    Regression: `if get_user_by_email(...) is not None:` without `await`
    made the coroutine object non-None for EVERY address, so every admin
    email change was rejected as 'already in use'.
    """
    admin, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()

    with patch(
        "app.routes.auth.admin.send_email_change_verification", autospec=True
    ) as verify, patch(
        "app.routes.auth.admin.send_email_change_notice", autospec=True
    ) as notice, caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            f"/admin/users/{target.id}/change-email",
            data={"new_email": "fresh@uzh.ch", "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin"

    row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
    assert row[0] == "fresh@uzh.ch"
    assert row[1] is not None

    # TEST-013 (admin site): capability link → the NEW address; heads-up
    # notice → the TARGET's current address. A swap silently commits changes
    # without proof of control while the victim never hears about it.
    verify.assert_called_once()
    assert verify.call_args.args[0] == "fresh@uzh.ch"
    assert verify.call_args.args[1].startswith(
        settings.public_base_url + "/account/confirm-email/"
    )
    notice.assert_called_once()
    assert notice.call_args.args[0] == target.email
    assert notice.call_args.args[1] == "fresh@uzh.ch"

    # TEST-024 family: the admin-initiated request leaves an audit trail.
    events = _audit_records(caplog, "admin_email_change_requested")
    assert len(events) == 1
    assert events[0].actor_admin_id == admin.id
    assert events[0].target_user_id == target.id

    # §2.6: following the redirect renders the success flash.
    page = e2e_client.get("/admin")
    assert "Confirmation link sent" in page.text


def test_admin_change_email_taken_address_rejected(
    e2e_client, user_factory, sync_conn
):
    """§2.5 pair: an address ANOTHER account already owns is rejected with
    the 'already in use' flash and nothing is staged on the target."""
    _, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()
    user_factory(email="taken@uzh.ch")  # the address's rightful owner

    resp = e2e_client.post(
        f"/admin/users/{target.id}/change-email",
        data={"new_email": "taken@uzh.ch", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = e2e_client.get("/admin")
    assert "already in use" in page.text

    row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
    assert row == (None, None)


def test_admin_change_email_shibboleth_target_refused(
    e2e_client, user_factory, sync_conn
):
    """A federated (shibboleth) target is refused — email is owned by the
    IdP — with the 'federated account' flash and nothing staged."""
    _, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory(auth_method="shibboleth")

    resp = e2e_client.post(
        f"/admin/users/{target.id}/change-email",
        data={"new_email": "fresh@uzh.ch", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = e2e_client.get("/admin")
    assert "federated account" in page.text

    row = _user_row(sync_conn, target.id, "pending_email, pending_email_token_hash")
    assert row == (None, None)


# ---------------------------------------------------------------------------
# §2.6 — admin action flash messages appear (set-tier as the exemplar)
# ---------------------------------------------------------------------------

def test_admin_set_tier_updates_db_flashes_and_audits(
    e2e_client, user_factory, sync_conn, caplog
):
    """§2.6: POST set-tier on a public user → 303 → the follow-up GET /admin
    renders 'Tier changed: public → vetted.'; the DB tier is updated; and
    an admin_user_tier_changed audit record carries actor_admin_id and
    target_user_id.

    Regression: sync `_admin_redirect` called async set_flash without
    `await` — every admin flash was silently dropped.
    """
    admin, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()  # defaults to tier 'public'

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-tier",
            data={"access_tier": "vetted", "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin"

    assert _user_row(sync_conn, target.id, "access_tier")[0] == "vetted"

    page = e2e_client.get("/admin")
    assert "Tier changed: public → vetted." in page.text

    records = _audit_records(caplog, "admin_user_tier_changed")
    assert len(records) == 1
    rec = records[0]
    assert rec.actor_admin_id == admin.id
    assert rec.target_user_id == target.id
    assert rec.old_value == "public"
    assert rec.new_value == "vetted"


def test_admin_set_tier_same_tier_is_info_noop(e2e_client, user_factory, sync_conn):
    """No-change no-op: setting the tier the user already has flashes the
    'already has tier' INFO message and changes nothing."""
    _, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()  # already 'public'

    resp = e2e_client.post(
        f"/admin/users/{target.id}/set-tier",
        data={"access_tier": "public", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = e2e_client.get("/admin")
    assert "already has tier" in page.text
    assert "auth-info" in page.text  # rendered with the 'info' category

    assert _user_row(sync_conn, target.id, "access_tier")[0] == "public"


# ---------------------------------------------------------------------------
# set-active — deactivation revokes sessions; reactivation clears lockout
# ---------------------------------------------------------------------------

def test_admin_deactivate_user_revokes_their_sessions(
    e2e_client, user_factory, session_factory, sync_conn, caplog
):
    """Deactivating a user flips is_active AND hard-revokes their live
    sessions (misuse response — the session row must be GONE, not just
    expired), the success flash renders (§2.6), and the action is audited
    as admin_user_active_changed with the actor/target/old/new fields
    (TEST-024 — deleting the emit erases the misuse trail, suite green)."""
    admin, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()
    session_factory(target.id)  # a live session that must not survive

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-active",
            data={"is_active": "false", "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303

    assert _user_row(sync_conn, target.id, "is_active")[0] is False
    count = sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (target.id,)
    ).fetchone()
    assert count[0] == 0

    records = _audit_records(caplog, "admin_user_active_changed")
    assert len(records) == 1
    rec = records[0]
    assert rec.actor_admin_id == admin.id
    assert rec.target_user_id == target.id
    assert rec.old_value is True and rec.new_value is False

    page = e2e_client.get("/admin")
    assert "User deactivated." in page.text


def test_admin_reactivate_clears_lockout_state(e2e_client, user_factory, sync_conn):
    """Reactivation clears failed_login_count and locked_until (the
    asymmetric-clear design: a reactivated user gets a fresh start, while
    deactivation preserves the lockout audit signal)."""
    _, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory(is_active=False)
    sync_conn.execute(
        """UPDATE users
           SET failed_login_count = 5,
               locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
           WHERE id = %s""",
        (target.id,),
    )
    sync_conn.commit()

    resp = e2e_client.post(
        f"/admin/users/{target.id}/set-active",
        data={"is_active": "true", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    row = _user_row(sync_conn, target.id, "is_active, failed_login_count, locked_until")
    assert row == (True, 0, None)

    page = e2e_client.get("/admin")
    assert "User activated." in page.text


def test_admin_cannot_deactivate_own_account(e2e_client, user_factory, sync_conn):
    """Self-deactivation is refused: error flash renders, the admin stays
    active, and their session keeps working (GET /admin still 200)."""
    admin, csrf = _login_admin(e2e_client, user_factory)

    resp = e2e_client.post(
        f"/admin/users/{admin.id}/set-active",
        data={"is_active": "false", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = e2e_client.get("/admin")
    assert page.status_code == 200  # session survived — no self-lockout
    assert "cannot deactivate your own account" in page.text
    assert _user_row(sync_conn, admin.id, "is_active")[0] is True


# ---------------------------------------------------------------------------
# set-admin — grant/revoke on another user works; self-demotion refused
# ---------------------------------------------------------------------------

def test_admin_grant_then_revoke_admin_on_another_user(
    e2e_client, user_factory, sync_conn, caplog
):
    """Granting then revoking admin on ANOTHER user both take effect in the
    DB and flash their status message (§2.6) — and BOTH directions emit the
    admin_user_admin_changed audit record (TEST-024): 'who made whom admin'
    is the single most audit-worthy trail in the app, and it had no
    assertion before this."""
    admin, csrf = _login_admin(e2e_client, user_factory)
    target = user_factory()

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-admin",
            data={"is_admin": "true", "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert _user_row(sync_conn, target.id, "is_admin")[0] is True
    page = e2e_client.get("/admin")
    assert "User admin status: True." in page.text

    grants = _audit_records(caplog, "admin_user_admin_changed")
    assert len(grants) == 1
    assert grants[0].actor_admin_id == admin.id
    assert grants[0].target_user_id == target.id
    assert grants[0].old_value is False and grants[0].new_value is True
    caplog.clear()

    with caplog.at_level(logging.INFO, logger="audit"):
        resp = e2e_client.post(
            f"/admin/users/{target.id}/set-admin",
            data={"is_admin": "false", "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert _user_row(sync_conn, target.id, "is_admin")[0] is False
    page = e2e_client.get("/admin")
    assert "User admin status: False." in page.text

    revokes = _audit_records(caplog, "admin_user_admin_changed")
    assert len(revokes) == 1
    assert revokes[0].old_value is True and revokes[0].new_value is False


def test_admin_cannot_revoke_own_admin_status(e2e_client, user_factory, sync_conn):
    """Self-demotion is refused with the error flash; the actor remains
    admin (no lock-yourself-out footgun)."""
    admin, csrf = _login_admin(e2e_client, user_factory)

    resp = e2e_client.post(
        f"/admin/users/{admin.id}/set-admin",
        data={"is_admin": "false", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    page = e2e_client.get("/admin")
    assert "cannot remove your own admin status" in page.text
    assert _user_row(sync_conn, admin.id, "is_admin")[0] is True


# ---------------------------------------------------------------------------
# Authorization — require_admin hides the surface with a 404
# ---------------------------------------------------------------------------

def test_non_admin_session_gets_404_on_admin_post(
    e2e_client, user_factory, session_factory, sync_conn
):
    """A NON-admin full session POSTing set-tier gets a 404 (require_admin
    cloaks the endpoint's existence, not a 403) and the target's tier is
    untouched. CSRF is deliberately VALID, and the user has TOTP configured
    (otherwise TotpGateMiddleware 303s to /setup-totp first), so the 404 is
    attributable to require_admin alone."""
    user = user_factory(totp_secret=encrypt_value(pyotp.random_base32()))
    target = user_factory()

    raw = session_factory(user.id)
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))
    csrf = _compute_csrf_token(raw)
    e2e_client.cookies.set("csrf_token", csrf)

    resp = e2e_client.post(
        f"/admin/users/{target.id}/set-tier",
        data={"access_tier": "vetted", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 404
    assert _user_row(sync_conn, target.id, "access_tier")[0] == "public"


def test_anonymous_get_admin_is_404(e2e_client):
    """An unauthenticated GET /admin is a 404 — the dashboard's existence
    is not revealed to guests (require_admin, not require_login)."""
    resp = e2e_client.get("/admin", follow_redirects=False)
    assert resp.status_code == 404
