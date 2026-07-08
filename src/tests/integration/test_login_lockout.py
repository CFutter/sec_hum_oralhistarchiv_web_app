"""Integration tests: consolidated verify_password, lockout, re-login revocation.

Backlog coverage:
- §2.9 — verify_password's 3-tuple contract (user, password_ok, locked_until),
  the verify_dummy timing equalization on every non-success path, the
  dummy-only verify on locked accounts, the transparent rehash upgrade, and
  the route-level login flows (TOTP / no-TOTP / wrong password / unverified).
- §2.10 — lockout after LOGIN_FAILURE_THRESHOLD (=3 in the test env) failures,
  audit 'account_locked' exactly once, and the 'login_blocked_locked' audit
  line carrying a valid locked_until.isoformat() string.
- §2.12 — re-login revokes the previously presented session ONLY on success
  (a failed login must not revoke the presented session — the logout-DoS guard).

/login POST is rate-limited 5/minute in the test env; no test here issues
more than 4 login POSTs.
"""
import logging
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pyotp
import pytest
from argon2 import PasswordHasher
from starlette.concurrency import run_in_threadpool as real_run_in_threadpool

from app.middleware.cookies import SESSION_SIGNER
from app.middleware.csrf import _compute_csrf_token
from app.services import authentication
from app.services.authentication import verify_password
from app.services.crypto import encrypt_value
from app.services.sessions import _hash_session_id
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.conftest import DEFAULT_PASSWORD, do_login


# ---------------------------------------------------------------------------
# SQL helpers (test-side asserts / setup against the real schema)
# ---------------------------------------------------------------------------

def _user_lock_state(sync_conn, user_id):
    """(failed_login_count, locked_until) straight from the users table."""
    row = sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return row[0], row[1]


def _set_locked_until(sync_conn, user_id, dt):
    sync_conn.execute(
        "UPDATE users SET locked_until = %s WHERE id = %s", (dt, user_id)
    )
    sync_conn.commit()


def _session_row_exists(sync_conn, raw_session_id):
    """True if the session created for RAW id raw_session_id is still stored."""
    row = sync_conn.execute(
        "SELECT 1 FROM sessions WHERE id = %s",
        (_hash_session_id(raw_session_id),),
    ).fetchone()
    return row is not None


def _wrong_totp_code(secret):
    """A 6-digit code guaranteed NOT to verify against secret right now
    (checks the same ±1-step window verify_and_consume_totp uses)."""
    totp = pyotp.TOTP(secret)
    now = time.time()
    valid = {totp.at(now + offset * 30) for offset in (-1, 0, 1)}
    for candidate in ("000000", "111111", "222222", "333333"):
        if candidate not in valid:
            return candidate
    raise AssertionError("could not find an invalid TOTP code")  # pragma: no cover


def _audit_records(caplog, event):
    return [
        rec for rec in caplog.records
        if rec.name == "audit" and rec.getMessage() == event
    ]


# ===========================================================================
# §2.9 — service level: await verify_password(pool, email, pw) directly
# ===========================================================================

async def test_verify_password_correct_local_active(db_pool, user_factory):
    """§2.9: correct password on a local, active account -> (user, True, None).

    Guards the consolidated single-query lookup returning the full 3-tuple.
    """
    u = user_factory()
    user, password_ok, locked_until = await verify_password(
        db_pool, u.email, DEFAULT_PASSWORD
    )
    assert user is not None
    assert user.id == u.id
    assert password_ok is True
    assert locked_until is None


async def test_verify_password_wrong_password_returns_user(db_pool, user_factory):
    """§2.9: wrong password -> (user, False, None) with user NON-None.

    The 3-tuple design point: the route needs the user id to record the
    failure. Also pins that argon2's VerifyMismatchError was CAUGHT inside
    verify_password (argon2 raises, it never returns False) — a leak here
    would 500 the login route.
    """
    u = user_factory()
    user, password_ok, locked_until = await verify_password(
        db_pool, u.email, "definitely-not-the-password"
    )
    assert user is not None
    assert user.id == u.id
    assert password_ok is False
    assert locked_until is None


async def test_verify_password_unknown_email_runs_dummy_verify(db_pool):
    """§2.9: no such email -> (None, False, None) AND verify_dummy ran.

    The user-enumeration timing guard, asserted by CALL (spy on
    verify_dummy) rather than wall-clock — losing the dummy verify on the
    no-user branch would reopen the enumeration oracle.
    """
    real = authentication.verify_dummy
    with patch(
        "app.services.authentication.verify_dummy",
        AsyncMock(side_effect=real),
    ) as dummy_spy:
        user, password_ok, locked_until = await verify_password(
            db_pool, "no-such-user@nowhere.example", "any-password"
        )
    assert user is None
    assert password_ok is False
    assert locked_until is None
    dummy_spy.assert_awaited_once_with("any-password")


async def test_verify_password_shibboleth_account_rejected_with_dummy(
    db_pool, user_factory
):
    """§2.9: a Shibboleth account (password_hash None) with any password ->
    (user, False, None), and the dummy verify still ran (timing parity).
    This also covers the empty-password_hash edge — shibboleth users have
    hash None via the factory.
    """
    u = user_factory(auth_method="shibboleth")
    real = authentication.verify_dummy
    with patch(
        "app.services.authentication.verify_dummy",
        AsyncMock(side_effect=real),
    ) as dummy_spy:
        user, password_ok, locked_until = await verify_password(
            db_pool, u.email, "any-password"
        )
    assert user is not None
    assert user.id == u.id
    assert password_ok is False
    assert locked_until is None
    dummy_spy.assert_awaited_once()


async def test_verify_password_inactive_local_rejected_with_dummy(
    db_pool, user_factory
):
    """§2.9: an inactive local account -> (user, False, None) + dummy ran."""
    u = user_factory(is_active=False)
    real = authentication.verify_dummy
    with patch(
        "app.services.authentication.verify_dummy",
        AsyncMock(side_effect=real),
    ) as dummy_spy:
        user, password_ok, locked_until = await verify_password(
            db_pool, u.email, DEFAULT_PASSWORD
        )
    assert user is not None
    assert user.id == u.id
    assert password_ok is False
    assert locked_until is None
    dummy_spy.assert_awaited_once()


async def test_verify_password_locked_account_dummy_only(
    db_pool, user_factory, sync_conn
):
    """§2.9: a currently locked account rejects EVEN the correct password,
    returns locked_until non-None, and the REAL hash is never Argon2-verified
    — every _ph.verify call on the locked path uses _DUMMY_HASH only.

    Guards the lockout-check ordering inside the consolidated function
    (locked must short-circuit before the real verify).
    """
    u = user_factory()
    lock_expiry = datetime.now(timezone.utc) + timedelta(minutes=15)
    _set_locked_until(sync_conn, u.id, lock_expiry)

    calls = []

    async def recording(func, *args, **kwargs):
        calls.append((func, args))
        return await real_run_in_threadpool(func, *args, **kwargs)

    with patch("app.services.authentication.run_in_threadpool", recording):
        user, password_ok, locked_until = await verify_password(
            db_pool, u.email, DEFAULT_PASSWORD
        )

    assert user is not None
    assert user.id == u.id
    assert password_ok is False
    assert locked_until is not None
    assert locked_until == lock_expiry

    # NB: bound-method equality (==), not identity — _ph.verify is a fresh
    # bound-method object on every attribute access.
    verify_calls = [args for func, args in calls if func == authentication._ph.verify]
    assert verify_calls, "dummy verify must run on the locked path (timing parity)"
    for args in verify_calls:
        assert args[0] == authentication._DUMMY_HASH, (
            "real password hash was Argon2-verified on the locked path"
        )


async def test_verify_password_corrupt_hash_rejected_with_dummy(
    db_pool, user_factory
):
    """TEST-044: a genuinely CORRUPT password_hash (not Argon2-parseable) is
    caught inside verify_password (InvalidHashError/VerificationError branch)
    → (user, False, None) with the dummy verify still run (timing parity). An
    argon2 exception-hierarchy shift that let this escape would 500 the login
    route for every affected row and lose the timing guard."""
    u = user_factory(password_hash="not-a-valid-argon2-hash-at-all")
    real = authentication.verify_dummy
    with patch(
        "app.services.authentication.verify_dummy",
        AsyncMock(side_effect=real),
    ) as dummy_spy:
        user, password_ok, locked_until = await verify_password(
            db_pool, u.email, "any-password"
        )
    assert user is not None and user.id == u.id
    assert password_ok is False
    assert locked_until is None
    dummy_spy.assert_awaited_once()


async def test_local_account_cannot_have_null_password_hash(db_pool, user_factory):
    """TEST-044 (defence-in-depth boundary): the verify_password NULL-hash
    branch is UNREACHABLE for local accounts because a DB CHECK constraint
    (users_local_password_required) forbids that state. Pin the constraint
    itself — it is what keeps a local login from ever reaching a NULL-hash
    ambiguity. A migration that drops it would make this test the tripwire."""
    import psycopg

    u = user_factory()
    from app.services.db import get_db_cursor

    with pytest.raises(psycopg.errors.CheckViolation, match="local_password_required"):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "UPDATE users SET password_hash = NULL WHERE id = %s", (u.id,)
            )


async def test_verify_password_expired_lock_auto_expires(
    db_pool, user_factory, sync_conn
):
    """§2.9: locked_until in the PAST is treated as unlocked — correct
    password -> password_ok True, locked_until None (lock auto-expires,
    no manual reset required)."""
    u = user_factory()
    _set_locked_until(
        sync_conn, u.id, datetime.now(timezone.utc) - timedelta(minutes=1)
    )
    user, password_ok, locked_until = await verify_password(
        db_pool, u.email, DEFAULT_PASSWORD
    )
    assert user is not None
    assert password_ok is True
    assert locked_until is None


async def test_verify_password_transparent_rehash_upgrade(
    db_pool, user_factory, sync_conn
):
    """§2.9: a hash made with weaker argon2 params succeeds AND is
    transparently upgraded in the DB (check_needs_rehash path), and the
    new stored hash still verifies the same password."""
    password = "Rehash-me-p4ssword!"
    weak_ph = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    weak_hash = weak_ph.hash(password)
    # Precondition of the scenario: the app's hasher wants this rehashed.
    assert authentication._ph.check_needs_rehash(weak_hash) is True

    u = user_factory(password_hash=weak_hash)
    user, password_ok, locked_until = await verify_password(
        db_pool, u.email, password
    )
    assert user is not None
    assert password_ok is True
    assert locked_until is None

    row = sync_conn.execute(
        "SELECT password_hash FROM users WHERE id = %s", (u.id,)
    ).fetchone()
    new_hash = row[0]
    assert new_hash != weak_hash, "stored hash was not upgraded"
    assert authentication._ph.check_needs_rehash(new_hash) is False
    # The upgraded hash still verifies the original password (raises if not).
    authentication._ph.verify(new_hash, password)


# ===========================================================================
# §2.9 — route level: the real /login flow over e2e_client
# ===========================================================================

def test_login_without_totp_redirects_to_setup(e2e_client, user_factory, sync_conn):
    """§2.9: correct password, TOTP not yet configured -> 303 to /setup-totp
    and the issued session row has purpose 'totp_setup' (the purpose-limited
    session, not a full one)."""
    u = user_factory()
    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup-totp"

    row = sync_conn.execute(
        "SELECT purpose FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()
    assert row is not None
    assert row[0] == "totp_setup"


def test_login_with_totp_issues_full_session(e2e_client, user_factory, sync_conn):
    """§2.9: correct password + current TOTP code -> 303 to '/' and a
    session with purpose 'full'."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    code = pyotp.TOTP(secret).now()

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=code)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"

    row = sync_conn.execute(
        "SELECT purpose FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()
    assert row is not None
    assert row[0] == "full"


def test_wrong_totp_code_counts_toward_lockout(e2e_client, user_factory, sync_conn):
    """§2.9: correct password but WRONG TOTP code -> 401 and
    failed_login_count incremented (TOTP failures count toward lockout,
    not just password failures)."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    wrong = _wrong_totp_code(secret)

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=wrong)
    assert resp.status_code == 401

    failed_count, locked_until = _user_lock_state(sync_conn, u.id)
    assert failed_count == 1
    assert locked_until is None


def test_wrong_password_records_failure_and_audits(
    e2e_client, user_factory, sync_conn, caplog
):
    """§2.9: wrong password on an existing local account -> 401,
    failed_login_count == 1 in the DB (the 3-tuple's non-None user let the
    route record the failure), and an audit 'login_failed' record carrying
    user_id and email_was_registered=True."""
    u = user_factory()
    with caplog.at_level(logging.INFO, logger="audit"):
        resp = do_login(e2e_client, u.email, "wrong-password-123")
    assert resp.status_code == 401

    failed_count, _ = _user_lock_state(sync_conn, u.id)
    assert failed_count == 1

    failures = _audit_records(caplog, "login_failed")
    assert len(failures) == 1
    rec = failures[0]
    assert rec.user_id == u.id
    assert rec.email_was_registered is True
    assert rec.failed_count == 1


def test_unverified_email_blocked_after_credential_check(
    e2e_client, user_factory, sync_conn
):
    """§2.9: unverified local account with the CORRECT password -> 401 with
    the 'verify your email' message. The block happens AFTER the credential
    check: clear_login_failures already ran, so pre-existing failures are
    wiped even though login is refused (pins the route's ordering)."""
    u = user_factory(email_verified=False)
    sync_conn.execute(
        "UPDATE users SET failed_login_count = 2 WHERE id = %s", (u.id,)
    )
    sync_conn.commit()

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
    assert resp.status_code == 401
    assert "verify your email" in resp.text.lower()

    failed_count, locked_until = _user_lock_state(sync_conn, u.id)
    assert failed_count == 0, "credential check passed, so failures must clear"
    assert locked_until is None
    # No session was issued for the blocked login.
    row = sync_conn.execute(
        "SELECT 1 FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()
    assert row is None


# ===========================================================================
# TEST-008 — session-cookie security attributes on the REAL login response
# ===========================================================================

def test_login_session_cookie_flags(e2e_client, user_factory):
    """set_session_cookie is the single choke point for HttpOnly /
    SameSite=strict / Max-Age / Secure on the session cookie, and no test
    ever asserted any of them on a local-login response. XSS-readable or
    cross-site-sendable session cookies ship green without this."""
    u = user_factory()
    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
    assert resp.status_code == 303

    raw = next(
        h for h in resp.headers.get_list("set-cookie")
        if h.startswith(settings.session_cookie_name + "=")
    ).lower()
    assert "httponly" in raw
    assert "samesite=strict" in raw
    assert f"max-age={settings.session_max_age_seconds}" in raw
    assert "path=/" in raw
    # The cookies_secure knob's EFFECT (not just its validator): the test env
    # sets COOKIES_SECURE=false, so 'secure' must be absent — a hardcoded
    # secure=True (severed knob) fails here.
    assert settings.cookies_secure is False  # env sanity for the next line
    assert "secure" not in raw


# ===========================================================================
# TEST-011 — the login_success audit event, emitted by the real route
# ===========================================================================

def test_login_success_is_audited_with_identity_fields(
    e2e_client, user_factory, caplog
):
    """The SIEM's primary login signal: exactly one 'login_success' record
    per successful login, carrying user_id, auth_method, session_purpose and
    access_tier. (The failure side was pinned; the only 'login_success'
    string in the tree used to be one a redaction test emitted itself.)"""
    u = user_factory(access_tier="registered")
    with caplog.at_level(logging.INFO, logger="audit"):
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
    assert resp.status_code == 303

    events = _audit_records(caplog, "login_success")
    assert len(events) == 1
    rec = events[0]
    assert rec.user_id == u.id
    assert rec.auth_method == "local"
    assert rec.session_purpose == "totp_setup"  # no TOTP yet → limited session
    assert rec.access_tier == "registered"
    assert rec.ip not in (None, "", "unknown")
    assert rec.request_id


# ===========================================================================
# §2.10 — lockout state and the locked-login audit line
# ===========================================================================

def test_lockout_after_threshold_and_blocked_audit(
    e2e_client, user_factory, sync_conn, caplog
):
    """§2.10: 3 wrong-password logins (LOGIN_FAILURE_THRESHOLD=3) set
    users.locked_until; audit 'account_locked' fires exactly once (the
    just_locked flag on the 3rd failure only); the 4th attempt WITH THE
    CORRECT password is still 401 and audits 'login_blocked_locked' whose
    locked_until field is a valid isoformat string (the .isoformat() crash
    guard). 4 login POSTs total — under the 5/minute route limit."""
    u = user_factory()

    with caplog.at_level(logging.INFO, logger="audit"):
        for _ in range(3):
            resp = do_login(e2e_client, u.email, "wrong-password")
            assert resp.status_code == 401

        failed_count, locked_until = _user_lock_state(sync_conn, u.id)
        assert failed_count == 3
        assert locked_until is not None
        assert locked_until > datetime.now(timezone.utc)

        locked_events = _audit_records(caplog, "account_locked")
        assert len(locked_events) == 1, "just_locked must be True exactly once"
        assert locked_events[0].user_id == u.id

        # 4th attempt: CORRECT password, but the account is locked.
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
        assert resp.status_code == 401

    blocked = _audit_records(caplog, "login_blocked_locked")
    assert len(blocked) == 1
    assert blocked[0].user_id == u.id
    # The audit field is a string produced by .isoformat() and parses back.
    assert isinstance(blocked[0].locked_until, str)
    parsed = datetime.fromisoformat(blocked[0].locked_until)
    assert parsed == locked_until


def test_successful_login_clears_failures(e2e_client, user_factory, sync_conn):
    """§2.10/§2.9: 2 failures (below threshold) then a successful login ->
    failed_login_count back to 0 and locked_until NULL (clear-on-success)."""
    u = user_factory()
    for _ in range(2):
        resp = do_login(e2e_client, u.email, "wrong-password")
        assert resp.status_code == 401

    failed_count, _ = _user_lock_state(sync_conn, u.id)
    assert failed_count == 2

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
    assert resp.status_code == 303

    failed_count, locked_until = _user_lock_state(sync_conn, u.id)
    assert failed_count == 0
    assert locked_until is None


# ===========================================================================
# §2.12 — re-login revokes the presented session ONLY on success
# ===========================================================================

def test_relogin_revokes_previous_session(e2e_client, user_factory, sync_conn):
    """§2.12: logging in again while carrying session S1's cookie issues a
    new session S2 AND deletes S1 (session-fixation guard) — the old cookie
    no longer authenticates.

    Uses a TOTP-configured user so both sessions are purpose 'full' (a
    totp_setup session would be gated away from POST /login entirely). The
    second login uses the NEXT time-step's code because
    verify_and_consume_totp consumes the step (anti-replay)."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    totp = pyotp.TOTP(secret)

    resp1 = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=totp.now())
    assert resp1.status_code == 303
    signed_s1 = e2e_client.cookies.get(settings.session_cookie_name)
    raw_s1 = SESSION_SIGNER.loads(signed_s1)
    assert _session_row_exists(sync_conn, raw_s1)

    # Re-login carrying S1's cookie; code for the next step evades the
    # consumed-step replay guard.
    next_step_code = totp.at((int(time.time()) // 30 + 1) * 30)
    resp2 = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=next_step_code)
    assert resp2.status_code == 303

    raw_s2 = SESSION_SIGNER.loads(e2e_client.cookies.get(settings.session_cookie_name))
    assert raw_s2 != raw_s1, "re-login must issue a NEW session id"
    assert _session_row_exists(sync_conn, raw_s2)
    assert not _session_row_exists(sync_conn, raw_s1), (
        "the previously presented session must be revoked on successful re-login"
    )

    # The old cookie no longer authenticates: a client presenting only S1
    # is treated as logged out and bounced to /login.
    e2e_client.cookies.clear()
    e2e_client.cookies.set(settings.session_cookie_name, signed_s1)
    resp3 = e2e_client.get("/account", follow_redirects=False)
    assert resp3.status_code == 303
    assert resp3.headers["location"].startswith("/login")


# ===========================================================================
# TEST-027 — undecryptable TOTP secret fails CLOSED (no session issued)
# ===========================================================================

def test_wrong_totp_crossing_threshold_sends_locked_notice(
    e2e_client, user_factory, sync_conn
):
    """TEST-047: wrong-TOTP failures count toward lockout, and the failure
    that CROSSES the threshold queues send_account_locked_notice as a
    background task (reason 'wrong_totp'). A dropped add_task / swapped args
    means the user is locked out with no email explaining why. Threshold is 3
    in the test env, so the 3rd wrong-TOTP attempt trips it."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    wrong = _wrong_totp_code(secret)

    with patch(
        "app.routes.auth.login.send_account_locked_notice", autospec=True
    ) as notice:
        for _ in range(3):
            resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=wrong)
            assert resp.status_code == 401

    _, locked_until = _user_lock_state(sync_conn, u.id)
    assert locked_until is not None
    notice.assert_called_once()
    assert notice.call_args.args[0] == u.email


def test_relogin_survives_a_delete_session_failure(
    e2e_client, user_factory, session_factory, sync_conn
):
    """TEST-045: a successful re-login must not be turned into a 500 by a
    transient failure while revoking the OLD session — the delete is
    best-effort. With delete_session raising, the login still 303s and the
    NEW session is created and works."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    totp = pyotp.TOTP(secret)

    # First login establishes S1 in the cookie jar.
    assert do_login(
        e2e_client, u.email, DEFAULT_PASSWORD, totp_code=totp.now()
    ).status_code == 303

    next_step = totp.at((int(time.time()) // 30 + 1) * 30)
    with patch(
        "app.routes.auth.login.delete_session",
        side_effect=RuntimeError("transient DB error during revoke"),
    ):
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=next_step)

    assert resp.status_code == 303, "a failed old-session delete broke the login"
    # A fresh session exists and authenticates.
    account = e2e_client.get("/account")
    assert account.status_code == 200
    assert u.email in account.text


def test_undecryptable_totp_secret_fails_closed(e2e_client, user_factory, sync_conn):
    """login.py catches TotpDecryptionError and returns 401 fail-closed. A
    'fix' that mapped the failure to totp_secret=None would fall into the
    no-TOTP branch and mint a totp_setup session from the PASSWORD ALONE — an
    attacker with just the password could re-enroll. Pins that the correct
    password on a user whose secret is un-decryptable (key-rotation accident)
    yields 401 AND no session row of ANY purpose."""
    u = user_factory(totp_secret="garbage-not-a-fernet-token")

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code="123456")
    assert resp.status_code == 401
    assert "contact support" in resp.text.lower()

    count = sync_conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (u.id,)
    ).fetchone()[0]
    assert count == 0, "a session was minted despite an undecryptable secret"


# ===========================================================================
# TEST-028 — ?next= redirect wiring on POST /login (open-redirect guard)
# ===========================================================================

def test_login_next_param_safe_path_is_honoured(e2e_client, user_factory):
    """A safe relative ?next= is honoured after a full (TOTP) login: the
    route composes safe_redirect_url(request) at the redirect site, so a
    login to ?next=/account lands on /account."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    e2e_client.get("/login?next=/account")
    csrf = e2e_client.cookies.get("csrf_token")
    resp = e2e_client.post(
        "/login?next=/account",
        data={"email": u.email, "password": DEFAULT_PASSWORD,
              "totp_code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account"


def test_login_next_param_evil_url_falls_back_to_root(e2e_client, user_factory):
    """An absolute off-site ?next= is rejected by safe_redirect_url — the
    login redirect falls back to '/', never to the attacker's URL (open-
    redirect / phishing guard). If a refactor read request.query_params['next']
    directly, this would leak."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    evil = "https://evil.example.com/phish"
    e2e_client.get("/login")
    csrf = e2e_client.cookies.get("csrf_token")
    resp = e2e_client.post(
        f"/login?next={evil}",
        data={"email": u.email, "password": DEFAULT_PASSWORD,
              "totp_code": pyotp.TOTP(secret).now(), "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert "evil.example.com" not in resp.headers["location"]


# ===========================================================================
# TEST-029 — update_last_login's EFFECT (a missing await leaves it NULL)
# ===========================================================================

def test_successful_login_updates_last_login(e2e_client, user_factory, sync_conn):
    """login.py awaits update_last_login on every success. This codebase's own
    docstrings document repeated missing-await regressions; dropping this
    await yields only a RuntimeWarning while every login test still passes and
    last_login silently stops updating (corrupting the admin UI and the
    reaper). Pin the EFFECT: NULL before, a recent timestamp after."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    sync_conn.execute("UPDATE users SET last_login = NULL WHERE id = %s", (u.id,))
    sync_conn.commit()
    assert sync_conn.execute(
        "SELECT last_login FROM users WHERE id = %s", (u.id,)
    ).fetchone()[0] is None  # control

    resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
    assert resp.status_code == 303

    last_login = sync_conn.execute(
        "SELECT last_login FROM users WHERE id = %s", (u.id,)
    ).fetchone()[0]
    assert last_login is not None
    age = datetime.now(timezone.utc) - last_login
    assert age < timedelta(minutes=5)


# ===========================================================================
# TEST-033 — attempts against a LOCKED account do not extend the lock
# ===========================================================================

def test_locked_account_attempts_do_not_extend_the_lock(
    e2e_client, user_factory, sync_conn
):
    """The route returns on locked_until BEFORE calling record_login_failure,
    so an attacker hammering a locked account cannot keep pushing the unlock
    time out (a permanent victim-lockout DoS). Pins that a 4th attempt while
    locked leaves failed_login_count AND locked_until UNCHANGED."""
    u = user_factory()
    for _ in range(3):
        assert do_login(e2e_client, u.email, "wrong-password").status_code == 401

    count_before, locked_before = _user_lock_state(sync_conn, u.id)
    assert locked_before is not None  # actually locked now

    # A further attempt while locked (wrong OR right password) must not move
    # either column — the locked branch returns before record_login_failure.
    resp = do_login(e2e_client, u.email, "another-wrong-password")
    assert resp.status_code == 401

    count_after, locked_after = _user_lock_state(sync_conn, u.id)
    assert count_after == count_before
    assert locked_after == locked_before


# ===========================================================================
# TEST-046 — GET /login while authenticated redirects, and is no-store
# ===========================================================================

def test_get_login_while_authenticated_redirects_home(e2e_client, user_factory):
    """A logged-in user hitting GET /login is 303'd to '/' (no double-login),
    and the login page itself carries Cache-Control: no-store (a shared-cache
    must not serve a page that may have a prefilled email)."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))

    # Guest GET: the login form renders with no-store.
    guest_page = e2e_client.get("/login")
    assert guest_page.status_code == 200
    assert "no-store" in guest_page.headers.get("cache-control", "")

    do_login(e2e_client, u.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
    authed = e2e_client.get("/login", follow_redirects=False)
    assert authed.status_code == 303
    assert authed.headers["location"] == "/"


def test_failed_login_does_not_revoke_presented_session(
    e2e_client, user_factory, session_factory, sync_conn
):
    """§2.12 counterpart (the logout-DoS guard): POSTing garbage credentials
    while carrying a victim's valid session cookie returns 401 and the
    presented session is STILL valid — revocation is gated on SUCCESS, so an
    attacker can't log a victim out by replaying their cookie with bad creds."""
    secret = pyotp.random_base32()
    u = user_factory(totp_secret=encrypt_value(secret))
    raw_s1 = session_factory(u.id, purpose="full")

    # Plant the victim's session cookie plus a CSRF pair bound to it.
    csrf = _compute_csrf_token(raw_s1)
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(raw_s1))
    e2e_client.cookies.set("csrf_token", csrf)

    resp = e2e_client.post(
        "/login",
        data={
            "email": "attacker-garbage@nowhere.example",
            "password": "not-a-real-password",
            "totp_code": "",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 401

    # The presented session survived the failed login...
    assert _session_row_exists(sync_conn, raw_s1)
    # ...and still authenticates.
    resp2 = e2e_client.get("/account", follow_redirects=False)
    assert resp2.status_code == 200
