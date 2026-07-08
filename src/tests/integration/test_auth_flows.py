"""P0 auth-flow integration tests — real PostgreSQL, real services, real routes.

Covers TESTING_BACKLOG §2.1 (two-click email verification single-use),
§2.2 (password reset invalidates sessions), §2.3 (reset with a different
password succeeds / same password rejected), §2.4 (reset token validity),
and §2.7 (seed admin on an empty database).

These sections all guard missing-`await` regressions that mypy cannot see
(`coroutine is not None` / `if coroutine:` shapes) and that only a real
database exercise catches: the buggy code returned truthy on ZERO-row
UPDATEs, so mocked cursors happily "passed."
"""
import time
from unittest.mock import patch

import pytest

from app.services.authentication import verify_password
from app.services.email_verification import (
    confirm_email_verification,
    generate_verification_token,
    store_verification_token_hash,
)
from app.services.password_reset import (
    generate_reset_token,
    store_reset_token_hash,
    update_password_with_token,
)
from app.services.seed_admin import seed_admin_user
from app.services.sessions import get_session_user
from app.services.tokens import hash_token
from config import settings

from tests.fixtures import sign_session_id
from tests.integration.conftest import DEFAULT_PASSWORD, do_login

# Strong passwords used across tests. None contain the factory users'
# email local parts ("userN") or display-name parts ("test"/"user"),
# so validate_password_strength never trips on them incidentally.
NEW_PASSWORD = "Fresh-N3w-Passw0rd!"
THIRD_PASSWORD = "An0ther-G00d-Pw!x"
SEED_PASSWORD = "Xk9!mQ2#vL8@pZw4"  # 16 chars, no "admin" substring


def _email_verified(sync_conn, user_id: int) -> bool:
    row = sync_conn.execute(
        "SELECT email_verified FROM users WHERE id = %s", (user_id,)
    ).fetchone()
    return row[0]


def _store_verification_hash_sync(sync_conn, user_id: int, token: str) -> None:
    """Sync-side equivalent of store_verification_token_hash for e2e setup."""
    sync_conn.execute(
        """UPDATE users
           SET email_verification_token_hash = %s,
               email_verification_created_at = CURRENT_TIMESTAMP
           WHERE id = %s""",
        (hash_token(token), user_id),
    )
    sync_conn.commit()


def _store_reset_hash_sync(sync_conn, user_id: int, token: str) -> None:
    """Sync-side equivalent of store_reset_token_hash for e2e setup."""
    sync_conn.execute(
        """UPDATE users
           SET password_reset_token_hash = %s,
               password_reset_created_at = CURRENT_TIMESTAMP
           WHERE id = %s""",
        (hash_token(token), user_id),
    )
    sync_conn.commit()


# ---------------------------------------------------------------------------
# §2.1 — two-click email verification is single-use (service level)
# ---------------------------------------------------------------------------

async def test_confirm_email_verification_is_single_use(
    db_pool, user_factory, sync_conn
):
    """§2.1: first confirm returns True and flips email_verified; the SAME
    token a second time returns False.

    Regression: `return cur.fetchone() is not None` without `await` made the
    coroutine object always non-None, so a zero-row UPDATE (token already
    consumed) still reported success.
    """
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    await store_verification_token_hash(db_pool, u.id, hash_token(token))

    first = await confirm_email_verification(db_pool, u.id, hash_token(token), u.email)
    assert first is True
    assert _email_verified(sync_conn, u.id) is True

    second = await confirm_email_verification(db_pool, u.id, hash_token(token), u.email)
    assert second is False


async def test_confirm_email_verification_rejects_expired_token(
    db_pool, user_factory, sync_conn
):
    """§2.1: a token whose created_at is older than 24h fails the DB-level
    expiry check (defense-in-depth beyond itsdangerous), returning False."""
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    await store_verification_token_hash(db_pool, u.id, hash_token(token))

    sync_conn.execute(
        """UPDATE users
           SET email_verification_created_at = CURRENT_TIMESTAMP - INTERVAL '25 hours'
           WHERE id = %s""",
        (u.id,),
    )
    sync_conn.commit()

    ok = await confirm_email_verification(db_pool, u.id, hash_token(token), u.email)
    assert ok is False
    assert _email_verified(sync_conn, u.id) is False


async def test_confirm_email_verification_rejects_changed_email(
    db_pool, user_factory, sync_conn
):
    """§2.1: a token is bound to the email it was issued for — if the user's
    current email no longer matches, the stale token must not verify."""
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    await store_verification_token_hash(db_pool, u.id, hash_token(token))

    sync_conn.execute(
        "UPDATE users SET email = %s WHERE id = %s", ("other@x.org", u.id)
    )
    sync_conn.commit()

    ok = await confirm_email_verification(db_pool, u.id, hash_token(token), u.email)
    assert ok is False
    assert _email_verified(sync_conn, u.id) is False


async def test_confirm_email_verification_rejects_replaced_token(
    db_pool, user_factory, sync_conn
):
    """§2.1: storing a newer token overwrites the previous hash, so the
    EARLIER link no longer verifies (one outstanding token per user)."""
    u = user_factory(email_verified=False)
    token_a = generate_verification_token(u.email, u.id)
    await store_verification_token_hash(db_pool, u.id, hash_token(token_a))
    # itsdangerous timestamps have 1-second granularity: two tokens minted in
    # the same second are byte-identical (so "replacement" would be a no-op).
    # Sleep just past the boundary so token_b genuinely differs from token_a.
    time.sleep(1.05)
    token_b = generate_verification_token(u.email, u.id)
    assert token_b != token_a
    await store_verification_token_hash(db_pool, u.id, hash_token(token_b))

    ok = await confirm_email_verification(db_pool, u.id, hash_token(token_a), u.email)
    assert ok is False
    assert _email_verified(sync_conn, u.id) is False


# ---------------------------------------------------------------------------
# §2.1 — two-click email verification (route level, e2e)
# ---------------------------------------------------------------------------

def test_verify_email_post_consumes_token_once(e2e_client, user_factory, sync_conn):
    """§2.1 route: first POST /verify-email (deliberately WITHOUT CSRF — the
    signed single-use token IS the capability, per the route's security note)
    redirects 303 to /login; the SECOND POST with the same token renders the
    200 'Already verified' page, NOT a second success redirect."""
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    _store_verification_hash_sync(sync_conn, u.id, token)

    resp = e2e_client.post(
        "/verify-email", data={"token": token}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    assert _email_verified(sync_conn, u.id) is True

    resp2 = e2e_client.post(
        "/verify-email", data={"token": token}, follow_redirects=False
    )
    assert resp2.status_code == 200
    assert "Already verified" in resp2.text


def test_verify_email_post_tampered_token_is_400(e2e_client, user_factory, sync_conn):
    """§2.1 route: a token with a broken signature renders the 400
    invalid-link error page and does not verify anyone."""
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    _store_verification_hash_sync(sync_conn, u.id, token)

    resp = e2e_client.post(
        "/verify-email", data={"token": token + "tampered"}, follow_redirects=False
    )
    assert resp.status_code == 400
    assert "Invalid verification link" in resp.text
    assert _email_verified(sync_conn, u.id) is False


def test_verify_email_with_active_session_redirects_to_setup_totp(
    e2e_client, user_factory, session_factory, sync_conn
):
    """TEST-038 arm (a): verifying while holding an active session for the
    SAME user gives a success flash and 303 to /setup-totp — not /login. A
    regression here strands a new user mid-onboarding at the login page with
    no message.

    The session is planted directly (login blocks unverified users, but the
    session middleware resolves on is_active, not email_verified — a session
    can legitimately outlive the verified flag flipping during this request).
    The verify-email POST is CSRF-exempt (the token is the capability), so no
    CSRF cookie is needed for the planted session."""
    u = user_factory(email_verified=False)
    raw = session_factory(u.id, purpose="totp_setup")
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw))

    token = generate_verification_token(u.email, u.id)
    _store_verification_hash_sync(sync_conn, u.id, token)

    resp = e2e_client.post(
        "/verify-email", data={"token": token}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"
    assert _email_verified(sync_conn, u.id) is True

    flash = sync_conn.execute(
        "SELECT flash_message FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()
    assert flash is not None
    assert "set up two-factor" in flash[0].lower()


def test_verify_email_replaced_hash_while_unverified_is_400(
    e2e_client, user_factory, sync_conn
):
    """TEST-038 arm (b): a valid-SIGNATURE token whose stored hash was
    replaced (a newer link issued) while the user is STILL unverified must
    render the 400 'no longer valid' page — the distinct arm from the
    already-verified 200 case. Only the already-verified arm was tested
    before."""
    u = user_factory(email_verified=False)
    token_a = generate_verification_token(u.email, u.id)
    _store_verification_hash_sync(sync_conn, u.id, token_a)
    # Replace the stored hash with a different token's, user still unverified.
    time.sleep(1.05)
    token_b = generate_verification_token(u.email, u.id)
    assert token_b != token_a
    _store_verification_hash_sync(sync_conn, u.id, token_b)

    resp = e2e_client.post(
        "/verify-email", data={"token": token_a}, follow_redirects=False
    )
    assert resp.status_code == 400
    assert "no longer valid" in resp.text
    assert _email_verified(sync_conn, u.id) is False


def test_verify_email_get_does_not_consume_token(e2e_client, user_factory, sync_conn):
    """§2.1 route: GET /verify-email/{token} is side-effect-free (prefetcher
    guard) — two GETs must not burn the token, so the POST still succeeds."""
    u = user_factory(email_verified=False)
    token = generate_verification_token(u.email, u.id)
    _store_verification_hash_sync(sync_conn, u.id, token)

    for _ in range(2):
        resp = e2e_client.get(f"/verify-email/{token}")
        assert resp.status_code == 200
    assert _email_verified(sync_conn, u.id) is False

    resp = e2e_client.post(
        "/verify-email", data={"token": token}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    assert _email_verified(sync_conn, u.id) is True


# ---------------------------------------------------------------------------
# §2.2 — password reset invalidates existing sessions
# ---------------------------------------------------------------------------

async def test_password_reset_invalidates_existing_sessions(
    db_pool, user_factory, session_factory, sync_conn
):
    """§2.2: a stolen session must NOT survive a password reset.

    Regression: delete_user_sessions was called without `await` inside
    update_password_with_token — coroutine created, never run, sessions
    silently left alive."""
    u = user_factory()
    raw_session = session_factory(u.id)
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)

    row = sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()
    assert row[0] == 0

    lookup = await get_session_user(db_pool, raw_session)
    assert lookup == (None, None, False)


# ---------------------------------------------------------------------------
# §2.3 — reset with a genuinely different password succeeds
# ---------------------------------------------------------------------------

async def test_password_reset_with_different_password_succeeds(db_pool, user_factory):
    """§2.3: resetting to a DIFFERENT password succeeds; afterwards the new
    password verifies and the old one does not.

    Regression: `if _is_same_as_current_password(...)` without `await` —
    the coroutine is always truthy, so EVERY reset was rejected with
    'choose a different password'."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)

    user, ok_new, _ = await verify_password(db_pool, u.email, NEW_PASSWORD)
    assert user is not None and user.id == u.id
    assert ok_new is True

    _, ok_old, _ = await verify_password(db_pool, u.email, DEFAULT_PASSWORD)
    assert ok_old is False


async def test_password_reset_same_password_is_rejected(db_pool, user_factory):
    """§2.3 pair: resetting to the CURRENT password raises ValueError
    ('different password') — the anti-reuse check still fires when it should.

    display_name is overridden because the factory default 'Test User' makes
    DEFAULT_PASSWORD ('...-for-tests') trip the strength check's contains-name
    rule BEFORE the same-password check we want to reach."""
    u = user_factory(display_name="Alice Wonder")
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    with pytest.raises(ValueError, match="different password"):
        await update_password_with_token(
            db_pool, u.id, hash_token(token), DEFAULT_PASSWORD
        )


# ---------------------------------------------------------------------------
# §2.4 — reset token validity
# ---------------------------------------------------------------------------

async def test_password_reset_wrong_token_hash_rejected(db_pool, user_factory):
    """§2.4: a hash that doesn't match the stored one → zero-row UPDATE →
    ValueError (not a silent 'success')."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
        await update_password_with_token(
            db_pool, u.id, hash_token("not-the-real-token"), NEW_PASSWORD
        )


async def test_password_reset_expired_token_rejected(db_pool, user_factory, sync_conn):
    """§2.4: a token older than the 30-minute window fails the DB-level
    created_at check even with a matching hash."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    sync_conn.execute(
        """UPDATE users
           SET password_reset_created_at = CURRENT_TIMESTAMP - INTERVAL '31 minutes'
           WHERE id = %s""",
        (u.id,),
    )
    sync_conn.commit()

    with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
        await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)


async def test_password_reset_token_is_single_use(db_pool, user_factory):
    """§2.4: a successful reset clears the stored hash, so reusing the same
    token (with yet another password) raises ValueError."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)

    with pytest.raises(ValueError, match="Invalid, expired, or already-used"):
        await update_password_with_token(
            db_pool, u.id, hash_token(token), THIRD_PASSWORD
        )


def test_reset_password_route_mismatched_confirm_rerenders_form(
    e2e_client, user_factory, sync_conn
):
    """§2.4 route: POST /reset-password/{token} with password !=
    password_confirm re-renders the form as 422 and does NOT consume the
    token (CSRF required: minted by the prior GET)."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    _store_reset_hash_sync(sync_conn, u.id, token)

    page = e2e_client.get(f"/reset-password/{token}")
    assert page.status_code == 200
    csrf = e2e_client.cookies.get("csrf_token")

    resp = e2e_client.post(
        f"/reset-password/{token}",
        data={
            "password": NEW_PASSWORD,
            "password_confirm": THIRD_PASSWORD,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 422
    assert "Passwords do not match" in resp.text

    # Token not consumed and password unchanged: the stored hash survives.
    row = sync_conn.execute(
        "SELECT password_reset_token_hash FROM users WHERE id = %s", (u.id,)
    ).fetchone()
    assert row[0] == hash_token(token)


# ---------------------------------------------------------------------------
# TEST-004 — POST /forgot-password: the reset REQUEST side, previously 0 tests
# ---------------------------------------------------------------------------

def test_forgot_password_is_enumeration_neutral_and_stores_token(
    e2e_client, user_factory, sync_conn
):
    """The response for a KNOWN email and an UNKNOWN email must be
    byte-identical (no enumeration oracle), while the side effects differ:
    the real user gets a stored token hash + a queued reset email, the
    unknown address gets neither. (2 POSTs — within the 3/minute limit.)"""
    known = user_factory()
    e2e_client.get("/forgot-password")
    csrf = e2e_client.cookies.get("csrf_token")

    with patch(
        "app.routes.auth.password_reset.send_password_reset_email", autospec=True
    ) as send:
        r_known = e2e_client.post(
            "/forgot-password",
            data={"email": known.email, "csrf_token": csrf},
            follow_redirects=False,
        )
        r_unknown = e2e_client.post(
            "/forgot-password",
            data={"email": "nobody@uzh.ch", "csrf_token": csrf},
            follow_redirects=False,
        )

    assert r_known.status_code == r_unknown.status_code == 200
    assert r_known.text == r_unknown.text  # byte-identical: no oracle
    assert "reset link has been sent" in r_known.text

    # Positive control: a hash WAS stored and an email WAS queued — for the
    # real user only.
    row = sync_conn.execute(
        "SELECT password_reset_token_hash FROM users WHERE id = %s", (known.id,)
    ).fetchone()
    assert row[0] is not None
    send.assert_called_once()
    assert send.call_args.args[0] == known.email


def test_forgot_password_issues_nothing_for_inactive_or_shibboleth(
    e2e_client, user_factory, sync_conn
):
    """The auth_method=='local' / is_active gate: deactivated and federated
    accounts get the same neutral page but NO token and NO email — a reset
    link must never re-open a disabled account or bypass the IdP."""
    inactive = user_factory(is_active=False)
    shib = user_factory(auth_method="shibboleth")
    e2e_client.get("/forgot-password")
    csrf = e2e_client.cookies.get("csrf_token")

    with patch(
        "app.routes.auth.password_reset.send_password_reset_email", autospec=True
    ) as send:
        for email in (inactive.email, shib.email):
            resp = e2e_client.post(
                "/forgot-password",
                data={"email": email, "csrf_token": csrf},
                follow_redirects=False,
            )
            assert resp.status_code == 200
            assert "reset link has been sent" in resp.text

    send.assert_not_called()
    rows = sync_conn.execute(
        "SELECT password_reset_token_hash FROM users WHERE id IN (%s, %s)",
        (inactive.id, shib.id),
    ).fetchall()
    assert all(r[0] is None for r in rows)


# ---------------------------------------------------------------------------
# TEST-012 — the reset path enforces the SAME password policy as registration
# ---------------------------------------------------------------------------

async def test_password_reset_rejects_weak_password(db_pool, user_factory):
    """Removing validate_password_strength from update_password_with_token
    would let anyone set 'a' as their password via recovery — a policy bypass
    on an auth-critical path. Positive control: a strong password succeeds
    through the exact same call."""
    u = user_factory(display_name="Alice Wonder")
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    with pytest.raises(ValueError, match="Password validation failed"):
        await update_password_with_token(db_pool, u.id, hash_token(token), "a")

    # The failed attempt must not have consumed the token.
    await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)
    _, ok, _ = await verify_password(db_pool, u.email, NEW_PASSWORD)
    assert ok is True


def test_reset_password_route_rejects_weak_password_as_422(
    e2e_client, user_factory, sync_conn
):
    """Route-level twin: the weak-password ValueError surfaces as a 422
    re-render with the policy message, and the token survives for a retry."""
    u = user_factory()
    token = generate_reset_token(u.email, u.id)
    _store_reset_hash_sync(sync_conn, u.id, token)

    e2e_client.get(f"/reset-password/{token}")
    csrf = e2e_client.cookies.get("csrf_token")
    resp = e2e_client.post(
        f"/reset-password/{token}",
        data={"password": "a", "password_confirm": "a", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 422
    assert "at least 12 characters" in resp.text

    row = sync_conn.execute(
        "SELECT password_reset_token_hash FROM users WHERE id = %s", (u.id,)
    ).fetchone()
    assert row[0] == hash_token(token)


# ---------------------------------------------------------------------------
# TEST-014 — reset clears lockout state (the recovery promise)
# ---------------------------------------------------------------------------

async def test_password_reset_clears_lockout_state(db_pool, user_factory, sync_conn):
    """The lockout email promises 'resetting your password also unlocks the
    account'. Dropping failed_login_count=0 / locked_until=NULL from the
    reset UPDATE leaves the user with a working new password but a
    still-locked account — this pins both columns AND a subsequent login."""
    u = user_factory()
    sync_conn.execute(
        """UPDATE users
           SET failed_login_count = 7,
               locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
           WHERE id = %s""",
        (u.id,),
    )
    sync_conn.commit()
    token = generate_reset_token(u.email, u.id)
    await store_reset_token_hash(db_pool, u.id, hash_token(token))

    await update_password_with_token(db_pool, u.id, hash_token(token), NEW_PASSWORD)

    row = sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (u.id,),
    ).fetchone()
    assert row == (0, None)

    # The documented recovery path actually works: login succeeds, unlocked.
    user, ok, locked_until = await verify_password(db_pool, u.email, NEW_PASSWORD)
    assert user is not None and ok is True and locked_until is None


# ---------------------------------------------------------------------------
# TEST-037 — the GET reset-form gate (verify_reset_token_hash)
# ---------------------------------------------------------------------------

def test_reset_form_get_rejects_replaced_token_but_accepts_current(
    e2e_client, user_factory, sync_conn
):
    """GET /reset-password/{token} consults verify_reset_token_hash: after a
    NEWER token replaces the stored hash, the old link renders the 422
    'invalid or expired' page — while the current link still renders the form
    (positive control; an inverted comparison would fail it)."""
    u = user_factory()
    token_a = generate_reset_token(u.email, u.id)
    _store_reset_hash_sync(sync_conn, u.id, token_a)
    # itsdangerous timestamps have 1s granularity — force distinct tokens.
    time.sleep(1.05)
    token_b = generate_reset_token(u.email, u.id)
    assert token_b != token_a
    _store_reset_hash_sync(sync_conn, u.id, token_b)

    stale = e2e_client.get(f"/reset-password/{token_a}")
    assert stale.status_code == 422
    assert "invalid or has expired" in stale.text

    current = e2e_client.get(f"/reset-password/{token_b}")
    assert current.status_code == 200
    assert "Reset Password" in current.text


# ---------------------------------------------------------------------------
# TEST-015 / TEST-016 — the emailed link is driven end-to-end (both flows)
# ---------------------------------------------------------------------------

def _path_of(url: str) -> str:
    assert url.startswith(settings.public_base_url + "/"), (
        f"emailed URL {url!r} does not use settings.public_base_url — "
        "Host-header-derived links are poisonable"
    )
    return url[len(settings.public_base_url):]


def test_register_flow_emailed_link_verifies_account(
    e2e_client, sync_conn
):
    """Register → capture the ACTUAL emailed URL → drive it → account
    verified. Pins the whole store↔email seam: the URL is built from
    public_base_url, the token in the URL is the token whose hash was stored
    (hash_token equality), and the link WORKS. A swapped-argument
    generate_verification_token(user.id, user.email) or a path typo makes
    every registrant's link dead — the (tested) 7-day reaper then deletes
    every new account.

    The form also smuggles hostile is_admin/access_tier fields — the created
    row must keep server-side defaults (mass-assignment pin)."""
    e2e_client.get("/register")
    csrf = e2e_client.cookies.get("csrf_token")

    with patch(
        "app.routes.auth.register.send_verification_email", autospec=True
    ) as send:
        resp = e2e_client.post(
            "/register",
            data={
                "email": "newcomer@uzh.ch",
                "display_name": "New Comer",
                "affiliation": "UZH",
                "country": "CH",
                "password": "Str0ng-Horse-Battery!9",
                "password_confirm": "Str0ng-Horse-Battery!9",
                "csrf_token": csrf,
                # Hostile mass-assignment extras — must be ignored:
                "is_admin": "true",
                "access_tier": "vetted",
                "email_verified": "true",
            },
            follow_redirects=False,
        )
    assert resp.status_code == 200
    assert "Check your email" in resp.text

    send.assert_called_once()
    to_addr, url = send.call_args.args
    assert to_addr == "newcomer@uzh.ch"
    path = _path_of(url)
    assert path.startswith("/verify-email/")
    token = path.removeprefix("/verify-email/")

    row = sync_conn.execute(
        """SELECT email_verification_token_hash, is_admin, access_tier,
                  email_verified
           FROM users WHERE email = %s""",
        ("newcomer@uzh.ch",),
    ).fetchone()
    assert row is not None
    stored_hash, is_admin, access_tier, email_verified = row
    assert stored_hash == hash_token(token)  # URL token IS the stored token
    assert is_admin is False                 # hostile extras ignored
    assert access_tier == "public"
    assert email_verified is False

    # The emailed link actually verifies the account.
    confirm = e2e_client.post(
        "/verify-email", data={"token": token}, follow_redirects=False
    )
    assert confirm.status_code == 303
    assert confirm.headers["location"] == "/login"
    verified = sync_conn.execute(
        "SELECT email_verified FROM users WHERE email = %s",
        ("newcomer@uzh.ch",),
    ).fetchone()
    assert verified[0] is True


def test_forgot_password_emailed_link_completes_a_real_reset(
    e2e_client, user_factory, sync_conn
):
    """Forgot-password → capture the ACTUAL emailed URL → GET renders the
    form → POST a new password through it → old sessions dead, new password
    logs in. The request and completion sides of recovery are proven against
    the SAME token for the first time."""
    u = user_factory()
    e2e_client.get("/forgot-password")
    csrf = e2e_client.cookies.get("csrf_token")

    with patch(
        "app.routes.auth.password_reset.send_password_reset_email", autospec=True
    ) as send:
        resp = e2e_client.post(
            "/forgot-password",
            data={"email": u.email, "csrf_token": csrf},
            follow_redirects=False,
        )
    assert resp.status_code == 200
    send.assert_called_once()
    path = _path_of(send.call_args.args[1])
    assert path.startswith("/reset-password/")

    form = e2e_client.get(path)
    assert form.status_code == 200
    assert "Reset Password" in form.text

    csrf = e2e_client.cookies.get("csrf_token")
    done = e2e_client.post(
        path,
        data={
            "password": NEW_PASSWORD,
            "password_confirm": NEW_PASSWORD,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert done.status_code == 303
    assert done.headers["location"] == "/login"

    login = do_login(e2e_client, u.email, NEW_PASSWORD)
    assert login.status_code == 303  # new password works (no TOTP → setup)


# ---------------------------------------------------------------------------
# §2.7 — seed admin on an empty database
# ---------------------------------------------------------------------------

async def test_seed_admin_creates_admin_on_empty_db_and_is_idempotent(
    db_pool, sync_conn
):
    """§2.7: on an EMPTY users table the seed CREATES the admin (the buggy
    un-awaited fetchone made `if existing:` truthy on a fresh DB, so a new
    deployment failed to boot). Running it AGAIN skips silently — still
    exactly one admin, no raise."""
    await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)

    row = sync_conn.execute(
        """SELECT is_admin, email_verified, access_tier, auth_method
           FROM users WHERE email = %s""",
        ("admin@uzh.ch",),
    ).fetchone()
    assert row is not None
    assert row == (True, True, "public", "local")

    # Second run: idempotent skip, no error, no duplicate admin.
    await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)
    count = sync_conn.execute(
        "SELECT COUNT(*) FROM users WHERE is_admin = true"
    ).fetchone()
    assert count[0] == 1


async def test_seed_admin_refuses_to_promote_existing_user(db_pool, user_factory):
    """§2.7: if a NON-admin user already owns the seed email (and no admin
    exists), seeding raises RuntimeError instead of silently elevating."""
    user_factory(email="admin@uzh.ch")

    with pytest.raises(RuntimeError, match="refusing to promote"):
        await seed_admin_user(db_pool, "admin@uzh.ch", SEED_PASSWORD)


async def test_seed_admin_rejects_short_password(db_pool, sync_conn):
    """§2.7: a password under 12 characters is refused with RuntimeError
    and no user is created."""
    with pytest.raises(RuntimeError, match="at least 12 characters"):
        await seed_admin_user(db_pool, "admin@uzh.ch", "Sh0rt!pw")

    count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
    assert count[0] == 0


async def test_seed_admin_rejects_password_containing_email_local_part(
    db_pool, sync_conn
):
    """§2.7: the strength check runs with the seed email — a long password
    that contains the email local part ('admin') is refused."""
    with pytest.raises(RuntimeError, match="ADMIN_SEED_PASSWORD rejected"):
        await seed_admin_user(db_pool, "admin@uzh.ch", "admin-Xk9!mQ2#vL")

    count = sync_conn.execute("SELECT COUNT(*) FROM users").fetchone()
    assert count[0] == 0
