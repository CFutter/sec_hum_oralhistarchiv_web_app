"""Integration tests: the login-lockout contract observed through the real
/login route over `e2e_client` — status codes, messages, cookies, audit
events, session issuance/revocation, and the per-route rate-limit budget.

The service-level contract (verify_password's PasswordCheck, record_login_
failure's threshold/transition behaviour) is covered in
`test_login_lockout_db.py`. The safe-redirect-target (`?next=`) contract is
covered in `test_login_redirect_target_routes_db.py`.

/login POST is rate-limited 5/minute in the test env; no test here issues
more than 4 login POSTs.
"""

import html
import logging
import re
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlsplit

import pyotp
import time_machine

from app.middleware.cookies import SESSION_SIGNER
from app.middleware.csrf import _compute_csrf_token
from app.services.crypto import encrypt_value
from app.services.session_ids import hash_session_id
from config import settings
from tests.fixtures import sign_session_id
from tests.integration.conftest import DEFAULT_PASSWORD, do_login


def _user_lock_state(sync_conn, user_id):
    """(failed_login_count, locked_until) straight from the users table."""
    row = sync_conn.execute(
        "SELECT failed_login_count, locked_until FROM users WHERE id = %s",
        (user_id,),
    ).fetchone()
    return row[0], row[1]


def _session_row_exists(sync_conn, raw_session_id):
    """True if the session created for RAW id raw_session_id is still stored."""
    row = sync_conn.execute(
        "SELECT 1 FROM sessions WHERE id = %s",
        (hash_session_id(raw_session_id),),
    ).fetchone()
    return row is not None


_FIXED_TOTP_INSTANT = datetime(2031, 1, 1, tzinfo=UTC)


def _wrong_totp_code(secret, instant=_FIXED_TOTP_INSTANT):
    """A 6-digit code guaranteed NOT to verify against secret at instant
    (checks the same ±1-step window verify_and_consume_totp uses)."""
    totp = pyotp.TOTP(secret)
    valid = {totp.at(instant + timedelta(seconds=offset * 30)) for offset in (-1, 0, 1)}
    for candidate in ("000000", "111111", "222222", "333333"):
        if candidate not in valid:
            return candidate
    raise AssertionError("could not find an invalid TOTP code")  # pragma: no cover


def _audit_records(caplog, event):
    return [rec for rec in caplog.records if rec.name == "audit" and rec.getMessage() == event]


def _login_form_action(page: str) -> str:
    m = re.search(r'<form class="auth-form"\s+action="([^"]+)"', page)
    assert m, "login form not found in page"
    return html.unescape(m.group(1))  # undo Jinja attribute-escaping (e.g. &amp;)


def _form_next_param(action: str):
    """The DECODED next value carried in a form action's query (None if absent)."""
    values = parse_qs(urlsplit(action).query).get("next")
    return values[0] if values else None


class TestLoginCredentialAndTotpBranching:
    """The route's dispatch across no-TOTP / TOTP / wrong-credential paths."""

    def test_login_without_totp_redirects_to_setup(self, e2e_client, user_factory, sync_conn):
        """Correct password, TOTP not yet configured -> 303 to /setup-totp
        and the issued session row has purpose 'totp_setup' (the
        purpose-limited session, not a full one)."""
        u = user_factory()
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"

        row = sync_conn.execute(
            "SELECT purpose FROM sessions WHERE user_id = %s", (u.id,)
        ).fetchone()
        assert row is not None
        assert row[0] == "totp_setup"

    def test_login_with_totp_issues_full_session(self, e2e_client, user_factory, sync_conn):
        """Correct password + current TOTP code -> 303 to '/' and a session
        with purpose 'full'."""
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

    def test_wrong_totp_code_counts_toward_lockout(self, e2e_client, user_factory, sync_conn):
        """Correct password but WRONG TOTP code -> 401 and
        failed_login_count incremented (TOTP failures count toward lockout,
        not just password failures)."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        wrong = _wrong_totp_code(secret)

        with time_machine.travel(_FIXED_TOTP_INSTANT, tick=False):
            resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=wrong)
        assert resp.status_code == 401

        failed_count, locked_until = _user_lock_state(sync_conn, u.id)
        assert failed_count == 1
        assert locked_until is None

    def test_wrong_password_records_failure_and_audits(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """Wrong password on an existing local account -> 401,
        failed_login_count == 1 in the DB (the PasswordCheck's non-None user
        let the route record the failure), and an audit 'login_failed'
        record carrying user_id and email_was_registered=True."""
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
        self, e2e_client, user_factory, sync_conn
    ):
        """Unverified local account with the CORRECT password -> 401 with the
        'verify your email' message, and pre-existing failures are NOT
        cleared — clear_login_failures runs only on a fully COMPLETED login,
        so the clear sits BELOW the unverified block (pins the route's
        ordering in the direction the code chose; a reordering that clears
        on proven credentials turns this red).

        The wrong-password leg (POSITIVE CONTROL for the ordering) pins that
        the block really sits AFTER the credential check: without the
        correct password the response is the uniform generic error, never
        the 'verify your email' message — otherwise unverified-account
        status would leak to anyone probing an email address (user
        enumeration).

        Seeds count=1 (not 2): the wrong-password leg increments to 2, which
        must stay below LOGIN_FAILURE_THRESHOLD=3 in the test env, or the
        correct-password leg would hit the locked branch instead."""
        u = user_factory(email_verified=False)
        sync_conn.execute("UPDATE users SET failed_login_count = 1 WHERE id = %s", (u.id,))
        sync_conn.commit()

        # Wrong password: generic message only — unverified status must not leak.
        resp = do_login(e2e_client, u.email, "wrong-password-123")
        assert resp.status_code == 401
        assert "verify your email" not in resp.text.lower()
        assert "invalid email, password" in resp.text.lower()

        # Correct password: the unverified block fires, with the specific message.
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
        assert resp.status_code == 401
        assert "verify your email" in resp.text.lower()

        failed_count, locked_until = _user_lock_state(sync_conn, u.id)
        assert failed_count == 2, (
            "failures must NOT clear on a blocked (unverified) login — "
            "clear_login_failures is reserved for fully completed logins"
        )
        assert locked_until is None
        # No session was issued for either blocked attempt.
        row = sync_conn.execute("SELECT 1 FROM sessions WHERE user_id = %s", (u.id,)).fetchone()
        assert row is None

    def test_undecryptable_totp_secret_fails_closed(self, e2e_client, user_factory, sync_conn):
        """login.py catches TotpDecryptionError and returns 401 fail-closed.
        A 'fix' that mapped the failure to totp_secret=None would fall into
        the no-TOTP branch and mint a totp_setup session from the PASSWORD
        ALONE — an attacker with just the password could re-enroll. Pins
        that the correct password on a user whose secret is un-decryptable
        (key-rotation accident) yields 401 AND no session row of ANY
        purpose."""
        u = user_factory(totp_secret="garbage-not-a-fernet-token")

        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code="123456")
        assert resp.status_code == 401
        assert "contact support" in resp.text.lower()

        count = sync_conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = %s", (u.id,)
        ).fetchone()[0]
        assert count == 0, "a session was minted despite an undecryptable secret"


class TestSuccessfulLoginEffects:
    """Observable side effects of a completed login: cookie flags, audit
    fields, and the last_login timestamp."""

    def test_login_session_cookie_flags(self, e2e_client, user_factory):
        """set_session_cookie is the single choke point for HttpOnly /
        SameSite=strict / Max-Age / Secure on the session cookie."""
        u = user_factory()
        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD)
        assert resp.status_code == 303

        raw = next(
            h
            for h in resp.headers.get_list("set-cookie")
            if h.startswith(settings.session_cookie_name + "=")
        ).lower()
        assert "httponly" in raw
        assert "samesite=strict" in raw
        assert f"max-age={settings.session_max_age_seconds}" in raw
        assert "path=/" in raw
        # The cookies_secure knob's EFFECT (not just its validator): the test
        # env sets COOKIES_SECURE=false, so 'secure' must be absent — a
        # hardcoded secure=True (severed knob) fails here.
        assert settings.cookies_secure is False  # env sanity for the next line
        assert "secure" not in raw

    def test_login_success_is_audited_with_identity_fields(self, e2e_client, user_factory, caplog):
        """Exactly one 'login_success' record per successful login, carrying
        user_id, auth_method, session_purpose and access_tier."""
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
        assert rec.client_ip not in (None, "", "unknown")
        assert rec.request_id

    def test_successful_login_updates_last_login(self, e2e_client, user_factory, sync_conn):
        """login.py awaits update_last_login on every success. Dropping this
        await yields only a RuntimeWarning while every login test still
        passes and last_login silently stops updating (corrupting the admin
        UI and the reaper). Pin the EFFECT: NULL before, a recent timestamp
        after."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        sync_conn.execute("UPDATE users SET last_login = NULL WHERE id = %s", (u.id,))
        sync_conn.commit()
        assert (
            sync_conn.execute("SELECT last_login FROM users WHERE id = %s", (u.id,)).fetchone()[0]
            is None
        )  # control

        resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
        assert resp.status_code == 303

        last_login = sync_conn.execute(
            "SELECT last_login FROM users WHERE id = %s", (u.id,)
        ).fetchone()[0]
        assert last_login is not None
        age = datetime.now(UTC) - last_login
        assert age < timedelta(minutes=5)

    def test_get_login_while_authenticated_redirects_home(self, e2e_client, user_factory):
        """A logged-in user hitting GET /login is 303'd to '/' (no
        double-login), and the login page itself carries Cache-Control:
        no-store (a shared cache must not serve a page that may have a
        prefilled email)."""
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


class TestLockoutEnforcementThroughTheRoute:
    """The route-observed side of crossing LOGIN_FAILURE_THRESHOLD (=3)."""

    def test_lockout_after_threshold_and_blocked_audit(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """3 wrong-password logins set users.locked_until; audit
        'account_locked' fires exactly once (the just_locked flag on the 3rd
        failure only); the 4th attempt WITH THE CORRECT password is still
        401 and audits 'login_blocked_locked' whose locked_until field is a
        valid isoformat string (the .isoformat() crash guard). 4 login POSTs
        total — under the 5/minute route limit."""
        u = user_factory()

        with caplog.at_level(logging.INFO, logger="audit"):
            for _ in range(3):
                resp = do_login(e2e_client, u.email, "wrong-password")
                assert resp.status_code == 401

            failed_count, locked_until = _user_lock_state(sync_conn, u.id)
            assert failed_count == 3
            assert locked_until is not None
            assert locked_until > datetime.now(UTC)

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

    def test_successful_login_clears_failures(self, e2e_client, user_factory, sync_conn):
        """2 failures (below threshold) then a successful login ->
        failed_login_count back to 0 and locked_until NULL
        (clear-on-success)."""
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

    def test_locked_account_attempts_do_not_extend_the_lock(
        self, e2e_client, user_factory, sync_conn
    ):
        """The route returns on locked_until BEFORE calling
        record_login_failure, so an attacker hammering a locked account
        cannot keep pushing the unlock time out (a permanent victim-lockout
        DoS). Pins that a 4th attempt while locked leaves
        failed_login_count AND locked_until UNCHANGED."""
        u = user_factory()
        for _ in range(3):
            assert do_login(e2e_client, u.email, "wrong-password").status_code == 401

        count_before, locked_before = _user_lock_state(sync_conn, u.id)
        assert locked_before is not None  # actually locked now

        # A further attempt while locked (wrong OR right password) must not
        # move either column — the locked branch returns before
        # record_login_failure.
        resp = do_login(e2e_client, u.email, "another-wrong-password")
        assert resp.status_code == 401

        count_after, locked_after = _user_lock_state(sync_conn, u.id)
        assert count_after == count_before
        assert locked_after == locked_before

    def test_after_an_expired_lock_wrong_passwords_count_from_one_again(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """An account whose old streak ran past the threshold and whose lock
        has since expired gets a complete new budget: the first wrong
        password counts as one and leaves the account usable, and the account
        is locked again only once the new streak reaches the threshold —
        announced by exactly one 'account_locked' audit event. Anything less
        would let one guess per lockout window keep the owner locked out for
        as long as the attacker cares to continue. Three login POSTs, under
        the route's 5/minute limit."""
        threshold = settings.login_failure_threshold  # 3 in the test env
        u = user_factory(
            failed_login_count=threshold + 2,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
        )

        with caplog.at_level(logging.INFO, logger="audit"):
            for attempt in range(1, threshold + 1):
                resp = do_login(e2e_client, u.email, "wrong-password")
                assert resp.status_code == 401

                failed_count, locked_until = _user_lock_state(sync_conn, u.id)
                assert failed_count == attempt, f"attempt {attempt} did not count from one"
                if attempt < threshold:
                    assert locked_until is None, f"locked again at attempt {attempt}"

        assert locked_until is not None
        assert locked_until > datetime.now(UTC)

        locked_events = _audit_records(caplog, "account_locked")
        assert len(locked_events) == 1, "the fresh streak must announce exactly one lockout"
        assert locked_events[0].user_id == u.id

    def test_after_an_expired_lock_a_wrong_totp_code_also_counts_from_one(
        self, e2e_client, user_factory, sync_conn, caplog
    ):
        """The second-factor failure path shares the same budget. A correct
        password with a wrong authenticator code, submitted after the lock
        expired, counts as failure one and must not put the account straight
        back into lockout."""
        threshold = settings.login_failure_threshold
        secret = pyotp.random_base32()
        user = user_factory(
            totp_secret=encrypt_value(secret),
            failed_login_count=threshold + 2,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
        )
        wrong_code = _wrong_totp_code(secret)

        with (
            caplog.at_level(logging.INFO, logger="audit"),
            time_machine.travel(_FIXED_TOTP_INSTANT, tick=False),
        ):
            resp = do_login(e2e_client, user.email, DEFAULT_PASSWORD, totp_code=wrong_code)
        assert resp.status_code == 401

        failed_count, locked_until = _user_lock_state(sync_conn, user.id)
        assert failed_count == 1
        assert locked_until is None, "one failure must not relock an account below the threshold"
        assert _audit_records(caplog, "account_locked") == []

    def test_wrong_totp_crossing_threshold_queues_locked_notice(
        self, e2e_client, user_factory, sync_conn
    ):
        """The threshold-crossing wrong TOTP queues one lockout notice."""
        secret = pyotp.random_base32()
        user = user_factory(totp_secret=encrypt_value(secret))
        wrong_code = _wrong_totp_code(secret)

        with time_machine.travel(_FIXED_TOTP_INSTANT, tick=False):
            for _ in range(3):
                response = do_login(e2e_client, user.email, DEFAULT_PASSWORD, totp_code=wrong_code)
                assert response.status_code == 401

        failed_count, locked_until = _user_lock_state(sync_conn, user.id)
        assert failed_count == 3
        assert locked_until is not None

        outbox_rows = sync_conn.execute(
            """
            SELECT user_id, recipient, status, attempt_count
            FROM email_outbox
            WHERE user_id = %s
              AND message_type = 'account_locked_notice'
            ORDER BY id
            """,
            (user.id,),
        ).fetchall()

        assert outbox_rows == [(user.id, user.email, "pending", 0)]

    def test_wrong_case_email_lockout_notice_uses_canonical_stored_address(
        self, e2e_client, user_factory, sync_conn
    ):
        """The lockout notice uses the canonical database email address."""
        user = user_factory()
        wrong_case_email = user.email.upper()

        assert wrong_case_email != user.email, "test setup requires a differently cased address"

        for _ in range(3):
            response = do_login(e2e_client, wrong_case_email, "Definitely-Wrong-Passw0rd!")
            assert response.status_code == 401

        failed_count, locked_until = _user_lock_state(sync_conn, user.id)
        assert failed_count == 3
        assert locked_until is not None

        outbox_rows = sync_conn.execute(
            """
            SELECT recipient
            FROM email_outbox
            WHERE user_id = %s
              AND message_type = 'account_locked_notice'
            ORDER BY id
            """,
            (user.id,),
        ).fetchall()

        assert outbox_rows == [(user.email,)]
        assert outbox_rows[0][0] != wrong_case_email


class TestSessionRevocationOnLogin:
    """Session issuance/revocation around re-login and failed attempts."""

    def test_relogin_revokes_previous_session(self, e2e_client, user_factory, sync_conn):
        """Logging in again while carrying session S1's cookie issues a new
        session S2 AND deletes S1 (session-fixation guard) — the old cookie
        no longer authenticates.

        Uses a TOTP-configured user so both sessions have purpose ``full``. A
        ``totp_setup`` session is rejected by the login route's
        public-or-full dependency. The second login uses the next
        time-step's code because ``verify_and_consume_totp`` consumes the
        step (anti-replay)."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        totp = pyotp.TOTP(secret)

        with time_machine.travel(_FIXED_TOTP_INSTANT, tick=False):
            resp1 = do_login(
                e2e_client, u.email, DEFAULT_PASSWORD, totp_code=totp.at(_FIXED_TOTP_INSTANT)
            )
            assert resp1.status_code == 303
            signed_s1 = e2e_client.cookies.get(settings.session_cookie_name)
            raw_s1 = SESSION_SIGNER.loads(signed_s1)
            assert _session_row_exists(sync_conn, raw_s1)

            # Re-login carrying S1's cookie; code for the next step evades the
            # consumed-step replay guard.
            next_step_code = totp.at(_FIXED_TOTP_INSTANT + timedelta(seconds=30))
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

    def test_relogin_survives_a_delete_session_failure(self, e2e_client, user_factory):
        """A successful re-login must not be turned into a 500 by a
        transient failure while revoking the OLD session — the delete is
        best-effort. With delete_session raising, the login still 303s and
        the NEW session is created and works."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        totp = pyotp.TOTP(secret)

        with time_machine.travel(_FIXED_TOTP_INSTANT, tick=False):
            # First login establishes S1 in the cookie jar.
            assert (
                do_login(
                    e2e_client,
                    u.email,
                    DEFAULT_PASSWORD,
                    totp_code=totp.at(_FIXED_TOTP_INSTANT),
                ).status_code
                == 303
            )

            next_step = totp.at(_FIXED_TOTP_INSTANT + timedelta(seconds=30))
            with patch(
                "app.routes.auth.login.delete_session",
                autospec=True,
                side_effect=RuntimeError("transient DB error during revoke"),
            ):
                resp = do_login(e2e_client, u.email, DEFAULT_PASSWORD, totp_code=next_step)

            assert resp.status_code == 303, "a failed old-session delete broke the login"
            # A fresh session exists and authenticates.
            account = e2e_client.get("/account")
            assert account.status_code == 200
            assert u.email in account.text

    def test_failed_login_does_not_revoke_presented_session(
        self, e2e_client, user_factory, session_factory, sync_conn
    ):
        """The logout-DoS guard's counterpart: POSTing garbage credentials
        while carrying a victim's valid session cookie returns 401 and the
        presented session is STILL valid — revocation is gated on SUCCESS,
        so an attacker can't log a victim out by replaying their cookie with
        bad creds."""
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


class TestLoginRedirectTarget:
    """The `?next=` safe-redirect-target contract, driven through the REAL
    login form action wherever the scenario needs the template seam, and
    through a hand-crafted POST where it needs to stay independent of it."""

    def test_safe_next_param_is_honoured_through_the_form(self, e2e_client, user_factory):
        """A safe relative ?next= is honoured after a full (TOTP) login,
        driven through the REAL form action. Hand-crafting the POST URL
        bypasses login.html's action attribute. The GET-rendered action must
        itself carry the next param, and POSTing credentials to that
        extracted action must land on /account. POSITIVE CONTROL for the
        evil-URL fallback siblings below."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))

        page = e2e_client.get("/login?next=/account")
        action = _login_form_action(page.text)
        # The template seam itself: the action's query string carries the target.
        assert _form_next_param(action) == "/account"

        csrf = e2e_client.cookies.get("csrf_token")
        resp = e2e_client.post(
            action,
            data={
                "email": u.email,
                "password": DEFAULT_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"

    def test_offsite_next_param_falls_back_to_root_through_the_form(self, e2e_client, user_factory):
        """An absolute off-site ?next= is rejected by safe_redirect_url even
        when the POST is driven through the REAL form action — the redirect
        falls back to '/', never the attacker's URL. This exercises the
        open-redirect guard through the template seam, not just the route
        contract (the direct-POST sibling below pins that half)."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        evil = "https://evil.example.com/phish"

        page = e2e_client.get(f"/login?next={quote(evil, safe='')}")
        action = _login_form_action(page.text)
        assert _form_next_param(action) == evil  # the form faithfully forwards it

        csrf = e2e_client.cookies.get("csrf_token")
        resp = e2e_client.post(
            action,
            data={
                "email": u.email,
                "password": DEFAULT_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"
        assert "evil.example.com" not in resp.headers["location"]

    def test_offsite_next_param_falls_back_to_root_on_direct_post(self, e2e_client, user_factory):
        """ROUTE-level contract pin, independent of the template — a
        hand-crafted POST /login?next=<absolute off-site URL> still falls
        back to '/' (safe_redirect_url composed at the redirect site). The
        form-driven twin above pins the template seam; this one stays red
        even if login.html's form action changes shape. If a refactor read
        request.query_params['next'] directly, this would leak."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        evil = "https://evil.example.com/phish"
        e2e_client.get("/login")
        csrf = e2e_client.cookies.get("csrf_token")
        resp = e2e_client.post(
            f"/login?next={evil}",
            data={
                "email": u.email,
                "password": DEFAULT_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"
        assert "evil.example.com" not in resp.headers["location"]

    def test_next_param_survives_a_failed_attempt(self, e2e_client, user_factory):
        """The 401 error re-render must keep carrying ?next= in its form
        action — a template that rebuilt the action without the query would
        silently strand users at '/' after they correct a typo'd password.
        Wrong password to the GET-extracted action (401), re-extract from
        the ERROR page, then correct credentials to THAT action → lands on
        /account. 2 login POSTs — under the 5/minute route limit."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))

        page = e2e_client.get("/login?next=/account")
        action = _login_form_action(page.text)

        fail = e2e_client.post(
            action,
            data={
                "email": u.email,
                "password": "definitely-wrong-password",
                "totp_code": "",
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert fail.status_code == 401

        error_action = _login_form_action(fail.text)
        assert _form_next_param(error_action) == "/account", (
            "the error re-render dropped the next target"
        )

        resp = e2e_client.post(
            error_action,
            data={
                "email": u.email,
                "password": DEFAULT_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": e2e_client.cookies.get("csrf_token"),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"

    def test_next_param_with_its_own_query_string_round_trips_exactly(
        self, e2e_client, user_factory
    ):
        """A next target with its OWN query string (/search?q=a&b) survives
        the encode-into-the-form / decode-on-POST round trip exactly once.
        Double-encoding (%2526… in the action) or an un-encoded '&' splitting
        the action's query would corrupt the target — the final location
        must equal the original value verbatim."""
        secret = pyotp.random_base32()
        u = user_factory(totp_secret=encrypt_value(secret))
        target = "/search?q=a&b"

        page = e2e_client.get(f"/login?next={quote(target, safe='')}")
        action = _login_form_action(page.text)
        assert _form_next_param(action) == target

        csrf = e2e_client.cookies.get("csrf_token")
        resp = e2e_client.post(
            action,
            data={
                "email": u.email,
                "password": DEFAULT_PASSWORD,
                "totp_code": pyotp.TOTP(secret).now(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == target
