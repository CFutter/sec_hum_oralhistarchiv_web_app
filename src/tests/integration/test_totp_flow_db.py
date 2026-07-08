"""TOTP enrollment & rotation — real database, real pyotp codes (TEST-003).

The client tier (client/test_totp_routes.py) pins the route WIRING with
mocked services; this file drives the same flows end-to-end: password-only
login mints a totp_setup session, GET /setup-totp stores an encrypted pending
secret, POST with a real code promotes it — and the stored active secret is
proven EQUAL to the pending one (the anti-substitution property, asserted on
real ciphertext), the session row's purpose flips to 'full', and the replay
step is recorded.

TOTP timing note: verify_and_consume_totp is monotonic per user (any step <=
last consumed fails), and login itself consumes the current step. Rotation
therefore proves the CURRENT authenticator with the NEXT step's code
(time+30s — inside the ±1 matched_step window, strictly greater than the
consumed step).
"""
import time

import pyotp

from app.services.crypto import decrypt_value, encrypt_value
from tests.integration.conftest import do_login


def _user_row(sync_conn, user_id):
    row = sync_conn.execute(
        "SELECT totp_secret, pending_totp_secret, last_totp_step, display_name"
        " FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return {
        "totp_secret": row[0],
        "pending_totp_secret": row[1],
        "last_totp_step": row[2],
        "display_name": row[3],
    }


def _session_purpose(sync_conn):
    row = sync_conn.execute("SELECT purpose FROM sessions").fetchone()
    return row[0] if row else None


def _csrf_after_get(client, path):
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    return client.cookies.get("csrf_token"), resp


# ---------------------------------------------------------------------------
# Enrollment: password login → totp_setup session → verified code → full
# ---------------------------------------------------------------------------

def test_enrollment_end_to_end_persists_pending_and_upgrades_session(
    e2e_client, user_factory, sync_conn
):
    user = user_factory()  # local, verified, NO totp secret

    # Password-only login mints a totp_setup session and routes to enrollment.
    login = do_login(e2e_client, user.email, user.password)
    assert login.status_code == 303
    assert login.headers["location"] == "/setup-totp"
    assert _session_purpose(sync_conn) == "totp_setup"

    # GET mints + stores an ENCRYPTED pending secret (never plaintext at rest).
    csrf, page = _csrf_after_get(e2e_client, "/setup-totp")
    stored = _user_row(sync_conn, user.id)
    assert stored["pending_totp_secret"] is not None
    pending = decrypt_value(stored["pending_totp_secret"])
    assert pending is not None
    assert stored["pending_totp_secret"] != pending  # encrypted at rest
    assert pending in page.text                      # manual-entry rendering

    # POST a real code for the pending secret; a hostile form field rides
    # along and must be ignored (the route reads the secret from the DB).
    code = pyotp.TOTP(pending).now()
    resp = e2e_client.post(
        "/setup-totp",
        data={"totp_code": code, "secret": "EVILATTACKERSECRET",
              "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"

    after = _user_row(sync_conn, user.id)
    assert after["totp_secret"] is not None
    assert decrypt_value(after["totp_secret"]) == pending  # DB secret promoted
    assert after["pending_totp_secret"] is None            # staging cleared
    now_step = int(time.time()) // 30
    assert abs(after["last_totp_step"] - now_step) <= 1    # replay guard seeded
    assert _session_purpose(sync_conn) == "full"           # gate lifted

    # And the lifted gate is real: a state-changing POST now executes.
    csrf2 = e2e_client.cookies.get("csrf_token")
    rename = e2e_client.post(
        "/account/change-name",
        data={"display_name": "Enrolled User", "csrf_token": csrf2},
        follow_redirects=False,
    )
    assert rename.status_code == 303
    assert rename.headers["location"] == "/account"
    assert _user_row(sync_conn, user.id)["display_name"] == "Enrolled User"


def test_enrollment_wrong_code_keeps_gate_down(e2e_client, user_factory, sync_conn):
    """Wrong code: 422, nothing promoted, purpose stays totp_setup — and the
    gate still blocks a state-changing POST for real (TEST-006, e2e level)."""
    user = user_factory()
    do_login(e2e_client, user.email, user.password)
    csrf, _ = _csrf_after_get(e2e_client, "/setup-totp")
    pending = decrypt_value(
        _user_row(sync_conn, user.id)["pending_totp_secret"]
    )
    good = pyotp.TOTP(pending).now()
    wrong = str((int(good) + 1) % 1_000_000).zfill(6)

    resp = e2e_client.post(
        "/setup-totp",
        data={"totp_code": wrong, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 422
    assert "Invalid code" in resp.text

    after = _user_row(sync_conn, user.id)
    assert after["totp_secret"] is None                  # nothing promoted
    assert _session_purpose(sync_conn) == "totp_setup"   # gate still down

    # The still-gated session cannot execute a mutating POST.
    blocked = e2e_client.post(
        "/account/change-name",
        data={"display_name": "Mallory", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert blocked.status_code == 303
    assert blocked.headers["location"] == "/setup-totp"
    assert _user_row(sync_conn, user.id)["display_name"] == "Test User"


# ---------------------------------------------------------------------------
# Rotation: prove current authenticator, verify new one, swap atomically
# ---------------------------------------------------------------------------

def _totp_login(e2e_client, user_factory):
    """Login with a real TOTP secret; returns (user, plaintext_secret)."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret))
    resp = do_login(e2e_client, user.email, user.password,
                    pyotp.TOTP(secret).now())
    assert resp.status_code == 303, resp.text
    return user, secret


def test_reset_totp_end_to_end_rotates_secret(e2e_client, user_factory, sync_conn):
    user, old_secret = _totp_login(e2e_client, user_factory)

    csrf, page = _csrf_after_get(e2e_client, "/account/reset-totp")
    new_pending = decrypt_value(
        _user_row(sync_conn, user.id)["pending_totp_secret"]
    )
    assert new_pending is not None and new_pending != old_secret
    assert new_pending in page.text

    # Login consumed the current step; prove possession with the NEXT step
    # (inside matched_step's ±1 window, above the monotonic consume floor).
    current_code = pyotp.TOTP(old_secret).at(int(time.time()) + 30)
    new_code = pyotp.TOTP(new_pending).now()
    resp = e2e_client.post(
        "/account/reset-totp",
        data={"current_totp_code": current_code, "new_totp_code": new_code,
              "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"

    after = _user_row(sync_conn, user.id)
    assert decrypt_value(after["totp_secret"]) == new_pending  # rotated
    assert after["pending_totp_secret"] is None
    now_step = int(time.time()) // 30
    # The NEW secret's consumed step is recorded — no cross-rotation replay
    # headroom (a code minted before the rotation cannot be replayed after).
    assert abs(after["last_totp_step"] - now_step) <= 1


def test_reset_totp_wrong_current_code_keeps_old_secret(
    e2e_client, user_factory, sync_conn
):
    """Rotation without possession of the CURRENT authenticator is refused:
    the stored secret stays the old one — a stolen password alone cannot
    displace the second factor."""
    user, old_secret = _totp_login(e2e_client, user_factory)

    csrf, _ = _csrf_after_get(e2e_client, "/account/reset-totp")
    new_pending = decrypt_value(
        _user_row(sync_conn, user.id)["pending_totp_secret"]
    )
    stale_current = pyotp.TOTP(old_secret).at(0)  # 1970 — hopelessly stale
    resp = e2e_client.post(
        "/account/reset-totp",
        data={"current_totp_code": stale_current,
              "new_totp_code": pyotp.TOTP(new_pending).now(),
              "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 422
    assert "Current authentication code is incorrect." in resp.text

    after = _user_row(sync_conn, user.id)
    assert decrypt_value(after["totp_secret"]) == old_secret  # unchanged
