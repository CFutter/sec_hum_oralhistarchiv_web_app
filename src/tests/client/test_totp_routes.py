"""TOTP enrollment & rotation routes — the MFA-critical surface (TEST-003).

Before this file, no test in any tier POSTed /setup-totp or
/account/reset-totp: the entire enrollment/rotation wiring (18% coverage) was
unverified, including its three deliberate security properties:

1. The persisted secret comes FROM THE DATABASE (get_pending_totp_secret),
   never from the form — the anti-substitution defence. The success test
   posts a hostile `secret` form field and pins that it is ignored.
2. A wrong code persists nothing and upgrades nothing (no enrollment with an
   unverified authenticator).
3. The totp_setup session purpose is upgraded to full exactly on success.

Plus the two middleware-interaction guards:
- TEST-006: a `totp_setup` session (password-only login) can NOT execute a
  state-changing POST anywhere — the gate blocks all methods. Without this a
  gate regression is a full MFA bypass (password-only attacker changes the
  account email).
- TEST-042: GET /setup-totp stays reachable DURING enrollment (it is in
  _TOTP_EXEMPT_PREFIXES; dropping it = infinite redirect loop for every new
  user).

All service calls are patched (autospec — arity drift fails loudly); the
sibling integration file test_totp_flow_db.py drives the same flows against
the real database.
"""
from unittest.mock import patch

from app.services.totp import TotpDecryptionError
from tests.fixtures import RAW_SESSION_ID, make_sample_user

SECRET = "JBSWY3DPEHPK3PXP"
NEW_SECRET = "GEZDGNBVGY3TQOJQ"


def _patch(name, **kw):
    return patch(f"app.routes.auth.totp.{name}", autospec=True, **kw)


# ---------------------------------------------------------------------------
# GET /setup-totp — enrollment page
# ---------------------------------------------------------------------------

def test_setup_totp_page_reachable_during_enrollment(totp_setup_client):
    """TEST-042: a totp_setup session can reach the enrollment page itself
    (200 with the pending secret rendered), not an infinite 303 loop —
    /setup-totp must stay in the gate's exempt list."""
    with _patch("get_pending_totp_secret", return_value=None), \
         _patch("generate_totp_secret", return_value=SECRET), \
         _patch("store_pending_totp_secret") as store:
        resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

    assert resp.status_code == 200
    assert SECRET in resp.text  # manual-entry secret rendered
    store.assert_awaited_once()
    assert store.await_args.args[2] == SECRET  # the freshly minted secret


def test_setup_totp_page_reuses_existing_pending_secret(totp_setup_client):
    """A live pending secret is reused, not rotated on every GET — a reload
    must not invalidate the QR the user just scanned (within the 10-min TTL)."""
    with _patch("get_pending_totp_secret", return_value=SECRET), \
         _patch("generate_totp_secret") as gen, \
         _patch("store_pending_totp_secret") as store:
        resp = totp_setup_client.get("/setup-totp", follow_redirects=False)

    assert resp.status_code == 200
    assert SECRET in resp.text
    gen.assert_not_called()
    store.assert_not_awaited()


def test_setup_totp_page_redirects_when_already_configured(authenticated_client):
    """A user with TOTP already configured is bounced to /account before any
    pending-secret work — re-enrollment is only via /account/reset-totp."""
    with _patch("get_pending_totp_secret") as pending:
        resp = authenticated_client.get("/setup-totp", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"
    pending.assert_not_awaited()


def test_setup_totp_page_blocks_unverified_email(client_builder):
    """The email_verified gate: an unverified user gets the
    verify-email-pending page, and NO pending secret is minted — enrollment
    cannot begin before the address is proven."""
    user = make_sample_user(totp_configured=False, email_verified=False)
    client = client_builder(session_user=user, session_purpose="totp_setup")
    with _patch("get_pending_totp_secret") as pending, \
         _patch("store_pending_totp_secret") as store:
        resp = client.get("/setup-totp", follow_redirects=False)

    assert resp.status_code == 200
    assert user.email in resp.text  # verify_email_pending.html
    pending.assert_not_awaited()
    store.assert_not_awaited()


# ---------------------------------------------------------------------------
# POST /setup-totp — enrollment verification
# ---------------------------------------------------------------------------

def test_setup_totp_valid_code_persists_db_secret_and_upgrades_purpose(
    totp_setup_client,
):
    """The enrollment success path: the persisted secret is the DB pending
    secret — a hostile `secret` form field is ignored (anti-substitution) —
    the consumed step is recorded (replay guard seeded), and the session
    purpose is upgraded totp_setup → full for exactly this session."""
    with _patch("get_pending_totp_secret", return_value=SECRET), \
         _patch("matched_step", return_value=42), \
         _patch("update_totp_secret") as persist, \
         _patch("upgrade_session_purpose") as upgrade:
        resp = totp_setup_client.post(
            "/setup-totp",
            data={
                "totp_code": "123456",
                "secret": "EVILATTACKERSECRET",  # must be ignored
                "csrf_token": totp_setup_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"

    persist.assert_awaited_once()
    assert persist.await_args.args[1] == 1                # the session user
    assert persist.await_args.args[2] == SECRET           # DB secret, not form
    assert "EVILATTACKERSECRET" not in str(persist.await_args)
    assert persist.await_args.kwargs["consumed_step"] == 42

    upgrade.assert_awaited_once()
    assert upgrade.await_args.args[1] == RAW_SESSION_ID   # this session only
    assert upgrade.await_args.args[2] == "full"


def test_setup_totp_wrong_code_never_persists_or_upgrades(totp_setup_client):
    """Negative control: an unverified code re-renders the page 422 and calls
    NEITHER update_totp_secret NOR upgrade_session_purpose — the purpose stays
    totp_setup, so there is no MFA-less path to a full session."""
    with _patch("get_pending_totp_secret", return_value=SECRET), \
         _patch("matched_step", return_value=None), \
         _patch("update_totp_secret") as persist, \
         _patch("upgrade_session_purpose") as upgrade:
        resp = totp_setup_client.post(
            "/setup-totp",
            data={"totp_code": "000000",
                  "csrf_token": totp_setup_client.csrf_token},
            follow_redirects=False,
        )

    assert resp.status_code == 422
    assert "Invalid code. Please scan the QR code and try again." in resp.text
    persist.assert_not_awaited()
    upgrade.assert_not_awaited()


def test_setup_totp_missing_pending_secret_restarts_enrollment(totp_setup_client):
    """No pending secret in the DB (expired 10-min TTL / never minted) → 303
    back to GET /setup-totp to restart; nothing verified or persisted."""
    with _patch("get_pending_totp_secret", return_value=None), \
         _patch("matched_step") as match, \
         _patch("update_totp_secret") as persist:
        resp = totp_setup_client.post(
            "/setup-totp",
            data={"totp_code": "123456",
                  "csrf_token": totp_setup_client.csrf_token},
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"
    match.assert_not_called()
    persist.assert_not_awaited()


def test_setup_totp_vanished_session_redirects_to_login(totp_setup_client):
    """If the session row vanished between code verification and the purpose
    upgrade (upgrade_session_purpose raises ValueError), the user is sent to
    /login?error=session_expired instead of a 500."""
    with _patch("get_pending_totp_secret", return_value=SECRET), \
         _patch("matched_step", return_value=42), \
         _patch("update_totp_secret"), \
         _patch("upgrade_session_purpose", side_effect=ValueError("no session")):
        resp = totp_setup_client.post(
            "/setup-totp",
            data={"totp_code": "123456",
                  "csrf_token": totp_setup_client.csrf_token},
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?error=session_expired"


# ---------------------------------------------------------------------------
# TEST-006 — the MFA-bypass guard: totp_setup sessions cannot mutate state
# ---------------------------------------------------------------------------

def test_totp_setup_session_cannot_execute_state_changing_post(totp_setup_client):
    """THE gate test: a totp_setup session (minted from password alone) that
    POSTs a non-exempt state-changing route is 303'd to /setup-totp and the
    handler NEVER RUNS. If TotpGateMiddleware regressed to method-conditional
    dispatch or a weakened purpose check, a password-only attacker could
    execute /account/change-name (or worse, /account/change-email — whose
    only re-auth is the password they already hold) — a full MFA bypass."""
    with patch("app.routes.auth.account.update_display_name",
               autospec=True) as update:
        resp = totp_setup_client.post(
            "/account/change-name",
            data={"display_name": "Mallory",
                  "csrf_token": totp_setup_client.csrf_token},
            follow_redirects=False,
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"  # gated…
    update.assert_not_awaited()                       # …and never executed


def test_totp_setup_session_cannot_reach_account_page(totp_setup_client):
    """GET direction of the same gate: the account page (and everything else
    non-exempt) redirects to /setup-totp while the purpose is totp_setup."""
    resp = totp_setup_client.get("/account", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"


# ---------------------------------------------------------------------------
# GET /account/reset-totp — rotation page
# ---------------------------------------------------------------------------

def test_reset_totp_page_mints_pending_for_local_user(authenticated_client):
    """A local user with a working current secret gets the rotation page with
    a NEW pending secret rendered (mint-or-reuse, same as enrollment)."""
    with _patch("get_totp_secret", return_value=SECRET), \
         _patch("get_pending_totp_secret", return_value=None), \
         _patch("generate_totp_secret", return_value=NEW_SECRET), \
         _patch("store_pending_totp_secret") as store:
        resp = authenticated_client.get("/account/reset-totp",
                                        follow_redirects=False)

    assert resp.status_code == 200
    assert NEW_SECRET in resp.text
    store.assert_awaited_once()


def test_reset_totp_page_shibboleth_user_flashed_to_account(client_builder):
    """Non-local accounts manage MFA at the IdP: 303 to /account with the
    SWITCH edu-ID info flash, and no TOTP work happens."""
    shib = make_sample_user(auth_method="shibboleth")
    client = client_builder(session_user=shib)
    with _patch("set_flash") as flash, \
         _patch("get_totp_secret") as get_secret:
        resp = client.get("/account/reset-totp", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"
    get_secret.assert_not_awaited()
    flash.assert_awaited_once()
    assert flash.await_args.args[1] == RAW_SESSION_ID
    assert "SWITCH edu-ID" in flash.await_args.args[2]
    assert flash.await_args.args[3] == "info"


def test_reset_totp_page_undecryptable_secret_fails_closed_503(
    authenticated_client,
):
    """TotpDecryptionError (key-rotation accident) renders the 503 error page
    — fail-closed, never a silent fall-through into re-enrollment (which
    would let a password-only attacker replace the authenticator)."""
    with _patch("get_totp_secret", side_effect=TotpDecryptionError(1)), \
         _patch("store_pending_totp_secret") as store:
        resp = authenticated_client.get("/account/reset-totp",
                                        follow_redirects=False)

    assert resp.status_code == 503
    assert "Two-factor temporarily unavailable" in resp.text
    store.assert_not_awaited()


def test_reset_totp_page_without_current_secret_goes_to_enrollment(
    authenticated_client,
):
    """No current secret (never enrolled) → the rotation flow refuses and
    redirects to first-time enrollment."""
    with _patch("get_totp_secret", return_value=None):
        resp = authenticated_client.get("/account/reset-totp",
                                        follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"


# ---------------------------------------------------------------------------
# POST /account/reset-totp — rotation verification
# ---------------------------------------------------------------------------

def _post_reset(client, current="111111", new="222222"):
    return client.post(
        "/account/reset-totp",
        data={"current_totp_code": current, "new_totp_code": new,
              "csrf_token": client.csrf_token},
        follow_redirects=False,
    )


def test_reset_totp_valid_codes_rotate_to_db_pending_secret(authenticated_client):
    """Rotation success: current code proves possession (verified AND
    consumed — replay-guarded), the new code proves the new authenticator,
    and the persisted secret is the DB pending secret with the new consumed
    step recorded."""
    with _patch("get_totp_secret", return_value=SECRET), \
         _patch("get_pending_totp_secret", return_value=NEW_SECRET), \
         _patch("verify_and_consume_totp", return_value=True) as consume, \
         _patch("matched_step", return_value=7), \
         _patch("update_totp_secret") as persist:
        resp = _post_reset(authenticated_client)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"
    consume.assert_awaited_once()
    assert consume.await_args.args[2] == SECRET       # current secret proven
    assert consume.await_args.args[3] == "111111"
    persist.assert_awaited_once()
    assert persist.await_args.args[2] == NEW_SECRET   # DB pending, not form
    assert persist.await_args.kwargs["consumed_step"] == 7


def test_reset_totp_wrong_current_code_blocks_rotation(authenticated_client):
    """Wrong current code → 422 with the exact error, and update_totp_secret
    is never awaited: possession of the password alone (this session) cannot
    swap the authenticator."""
    with _patch("get_totp_secret", return_value=SECRET), \
         _patch("get_pending_totp_secret", return_value=NEW_SECRET), \
         _patch("verify_and_consume_totp", return_value=False), \
         _patch("matched_step", return_value=7), \
         _patch("update_totp_secret") as persist:
        resp = _post_reset(authenticated_client)

    assert resp.status_code == 422
    assert "Current authentication code is incorrect." in resp.text
    persist.assert_not_awaited()


def test_reset_totp_wrong_new_code_blocks_rotation(authenticated_client):
    """Wrong NEW code → 422 and nothing persisted: rotating to an
    authenticator the user cannot actually generate codes for would lock
    them out permanently."""
    with _patch("get_totp_secret", return_value=SECRET), \
         _patch("get_pending_totp_secret", return_value=NEW_SECRET), \
         _patch("verify_and_consume_totp", return_value=True), \
         _patch("matched_step", return_value=None), \
         _patch("update_totp_secret") as persist:
        resp = _post_reset(authenticated_client)

    assert resp.status_code == 422
    assert "New authentication code is incorrect." in resp.text
    persist.assert_not_awaited()


def test_reset_totp_missing_pending_restarts_flow(authenticated_client):
    """Expired/missing pending secret → 303 back to the rotation page; the
    current code is not even checked (nothing to rotate to)."""
    with _patch("get_totp_secret", return_value=SECRET), \
         _patch("get_pending_totp_secret", return_value=None), \
         _patch("verify_and_consume_totp") as consume, \
         _patch("update_totp_secret") as persist:
        resp = _post_reset(authenticated_client)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/account/reset-totp"
    consume.assert_not_awaited()
    persist.assert_not_awaited()
