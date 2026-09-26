"""Client-tier contracts for `/login` and `/logout`.

Covers three scenario classes exercised through `app.routes.auth.login`:
the login page's Shibboleth entry link, the fixed (never-reflected) login
error messages, and logout's cookie hygiene (including the federated SP
logout hand-off).
"""

import html
import logging
import re
import urllib.parse
from contextlib import asynccontextmanager
from unittest.mock import patch, sentinel

import pytest
import starlette.requests
from psycopg_pool import PoolTimeout, TooManyRequests
from pydantic import SecretStr
from starlette.datastructures import UploadFile

from app.middleware.csrf import CSRF_COOKIE_NAME
from app.services import (
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
)
from app.services.authentication import PasswordCheck
from app.services.federated_authentication import FederatedLoginSuccess
from app.services.federated_session_policy import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
)
from app.template_setup import templates
from config import settings
from tests.fixtures import RAW_SESSION_ID, csrf_token_for, make_sample_user, sign_session_id

_SHIB_LINK_RE = re.compile(r'<a\b[^>]*\bhref="([^"]*/Shibboleth\.sso/Login\?[^"]+)"')
_SHIB_TARGET_RE = re.compile(r"(?:^|&)target=([^&]+)")
_CALLBACK_PREFIX = "/auth/shibboleth/callback?next="


def _shib_target(page: str) -> str:
    """The raw, still-encoded `target=` value of the Shibboleth href (only
    HTML entities undone) — what the SP link literally carries."""
    link = _shib_href(page)
    match = _SHIB_TARGET_RE.search(urllib.parse.urlsplit(link).query)
    assert match, "Shibboleth.sso login link not found on page"
    return match.group(1)


def _shib_href(page: str) -> str:
    """Return the HTML-decoded SessionInitiator href."""
    match = _SHIB_LINK_RE.search(page)
    assert match, "Shibboleth.sso login link not found on page"
    return html.unescape(match.group(1))


def _assert_exact_mfa_request(page: str) -> None:
    """Pin the UI's fresh-auth/MFA request parameters.

    ``forceAuthn`` here is defense in depth, not proof that every public SP
    handler invocation requested fresh authentication; deployment acceptance
    tests that property at the SP/IdP boundary.
    """
    href = _shib_href(page)
    query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(href).query,
        strict_parsing=True,
    )
    assert query["authnContextClassRef"] == [REQUIRED_SHIBBOLETH_AUTHN_CONTEXT]
    assert query["authnContextComparison"] == ["exact"]
    assert query["forceAuthn"] == ["true"]
    # Structural evidence that the context URI was carried as a query value,
    # rather than pasted into the link as an unescaped second URL.
    assert REQUIRED_SHIBBOLETH_AUTHN_CONTEXT not in href


def _recovered_next(target: str) -> str:
    """Decode the raw target along the real redirect chain.

    First unquote: what the SP receives as `target` — the URL it sends the
    browser back to. Second unquote: the callback's query parser percent-
    decoding that URL's `next` parameter. What this returns is the `next`
    value the callback route would actually see.
    """
    once = urllib.parse.unquote(target)
    assert once.startswith(_CALLBACK_PREFIX), once
    return urllib.parse.unquote(once[len(_CALLBACK_PREFIX) :])


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


class TestLoginPageShibbolethLink:
    """login.html's half of the federated `next` round-trip.

    No Shibboleth SP exists until Phase 2, so this half is pinned here so it
    cannot rot meanwhile. The template builds `/Shibboleth.sso/Login?target=
    <urlencode(callback + '?next=' + urlencode(next))>` — the inner urlencode
    protects `?`/`&` inside `next` from the callback URL's own query parsing,
    the outer one protects the whole target inside the SP link. The tests
    decode the href the way the real redirect chain does (SP unquotes
    `target` once; the callback's query parser unquotes `next` once) instead
    of asserting encoded literals, because Jinja's urlencode safe-character
    set (it leaves `/` intact) is an implementation detail.

    Decoding alone is not enough: `unquote` on already-plain text is a
    no-op, so a template that dropped one or both urlencode layers would
    round-trip to the identical recovered `next`. Each test therefore also
    pins structural evidence of the encoding it claims: the raw target must
    carry no naked `?` (outer layer applied) and, when `next` has its own
    query string, must contain `%25` re-encoded escapes (inner layer applied
    under the outer one). Those hold for ANY safe-character set that encodes
    the reserved `?`/`=`/`&`/`%` — still no exact-literal assertions.

    Gotcha pinned by the patching style: template_setup.py freezes
    `shibboleth_enabled` into templates.env.globals at import time —
    monkeypatching settings does nothing; the global itself must be patched.
    """

    def test_shibboleth_href_round_trips_simple_next(self, guest_client):
        """The template-side half of the federated `next` round-trip. A
        dropped or doubled urlencode in login.html must fail here long
        before an SP exists to notice. The no-naked-`?` pin is what makes
        the decode non-vacuous: without it, a dropped outer urlencode
        yields the same recovered `next` (see class docstring)."""
        with patch.dict(templates.env.globals, {"shibboleth_enabled": True}):
            response = guest_client.get("/login?next=/dataset/42")

        assert response.status_code == 200
        target = _shib_target(response.text)
        # Outer-layer evidence: the callback URL's own "?" must reach the SP
        # percent-encoded; a naked "?" means the outer urlencode is gone (the
        # SP would parse everything after it as ITS query, losing `next`).
        assert "?" not in target, target
        assert _recovered_next(target) == "/dataset/42"
        assert "administrator must approve the account" in response.text
        _assert_exact_mfa_request(response.text)

    def test_shibboleth_href_round_trips_next_with_embedded_query(self, guest_client):
        """The double-encoding pin. With `next` carrying its own query
        string, a single-encoded target lets the SP's query parser swallow
        everything after the embedded `&` (here: `b` would be lost as a
        separate parameter). The `%25` pin is evidence that both urlencode
        layers ran: only inner escapes re-encoded by the outer layer produce
        `%25xx`, and dropping either layer removes every one of them while
        the two-hop decode still comes out identical — the blind spot a
        decode-only assertion would miss."""
        with patch.dict(templates.env.globals, {"shibboleth_enabled": True}):
            response = guest_client.get("/login?next=/search?q=a%26b")

        assert response.status_code == 200
        target = _shib_target(response.text)
        assert "%25" in target, target  # inner escapes re-encoded by the outer layer
        assert "?" not in target and "&" not in target, target  # nothing naked
        assert _recovered_next(target) == "/search?q=a&b"
        _assert_exact_mfa_request(response.text)

    def test_shibboleth_link_absent_when_flag_disabled(self, guest_client):
        """The institutional-login link is absent when federation is
        disabled (the positive case, with the link present, is proven by
        the two round-trip tests above)."""
        with patch.dict(
            templates.env.globals,
            {"shibboleth_enabled": False},
        ):
            response = guest_client.get("/login?next=/dataset/42")

        assert response.status_code == 200
        assert "Shibboleth.sso" not in response.text
        assert 'class="auth-form"' in response.text


class TestLoginErrorReporting:
    """Redirected login errors are fixed messages, never reflected query text."""

    @pytest.mark.parametrize(
        ("code", "message"),
        [
            (
                "account_conflict",
                "This email address is already linked to another account.",
            ),
            (
                "shibboleth_invalid_email",
                "Your institution did not provide a valid email address.",
            ),
            ("session_expired", "Your session has expired. Please sign in again."),
        ],
    )
    def test_known_login_error_is_visible(self, guest_client, code, message):
        """A recognized error code renders its fixed message and marks the
        response non-cacheable (the positive case for the reflection check
        below)."""
        response = guest_client.get("/login", params={"error": code})
        assert response.status_code == 200
        assert message in response.text
        assert 'class="auth-error"' in response.text
        assert response.headers["Cache-Control"] == "no-store"

    @pytest.mark.parametrize(
        "code",
        ["", "unknown", "<script>alert(1)</script>"],
        ids=[
            "empty_error_code",
            "unrecognized_error_code",
            "script_injection_attempt",
        ],
    )
    def test_unknown_login_error_is_not_reflected(self, guest_client, code):
        """An error code outside the fixed mapping — including one carrying
        markup — never appears on the page and never triggers the error
        styling."""
        response = guest_client.get("/login", params={"error": code})
        assert response.status_code == 200
        assert 'class="auth-error"' not in response.text
        assert "alert(1)" not in response.text

    def test_authenticated_login_redirect_is_preserved(self, authenticated_client):
        """An already-authenticated visitor is redirected away from the
        login page even when an error code is present in the query."""
        response = authenticated_client.get("/login?error=session_expired", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/"


class TestLogoutCookies:
    """Logout cookie hygiene — each auth cookie dies exactly once.

    POST /logout must end the browser session by deleting BOTH auth cookies
    (the signed session cookie and the HMAC-bound CSRF cookie), and each
    deletion must appear exactly once on the response. A second code path
    (handler and middleware, or a re-introduced duplicate delete_cookie
    call) emitting the same deletion twice would hide which layer owns
    cookie clearing and mask set+delete ordering bugs.

    Runs against the mocked-pool client harness — delete_session is patched
    at the route's namespace so the session revocation never reaches the
    tripwire pool.
    """

    def test_logout_deletes_session_and_csrf_cookies_exactly_once(self, authenticated_client):
        """Logout deletes both auth cookies exactly once for an authenticated
        session (the positive control for the anonymous-session case below,
        which must delete no session server-side)."""
        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = authenticated_client.post(
                "/logout",
                data={"csrf_token": authenticated_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/"
        # Mock-pool tripwire: the revocation went through the patched service.
        delete_spy.assert_awaited_once_with(authenticated_client.mock_pool, RAW_SESSION_ID)

        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            headers = _set_cookie_headers(response, cookie_name)
            assert len(headers) == 1, (cookie_name, headers)
            assert "max-age=0" in headers[0].lower(), (cookie_name, headers[0])

    def test_federated_logout_revokes_app_session_then_uses_fixed_sp_logout(
        self, client_builder, monkeypatch
    ):
        """A federated logout also terminates the browser's Shibboleth SP
        session.

        The SP return target is derived only from PUBLIC_BASE_URL. Request
        query values therefore cannot turn logout into a redirector or carry
        credentials into the SP handler.
        """
        federated = make_sample_user(
            auth_method="shibboleth",
            federated_status="approved",
            shibboleth_issuer="https://idp.example.org/idp/shibboleth",
            shibboleth_subject_id="urn:test:subject:logout",
        )
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        client = client_builder(session_user=federated)

        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = client.post(
                "/logout?return=https://attacker.example/&token=secret",
                data={"csrf_token": client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        location = response.headers["location"]
        parsed = urllib.parse.urlsplit(location)
        assert parsed.path == "/Shibboleth.sso/Logout"
        assert urllib.parse.parse_qs(parsed.query, strict_parsing=True) == {
            "return": [f"{settings.public_base_url}/"]
        }
        assert "attacker.example" not in location
        assert "secret" not in location
        delete_spy.assert_awaited_once_with(client.mock_pool, RAW_SESSION_ID)

        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            headers = _set_cookie_headers(response, cookie_name)
            assert len(headers) == 1, (cookie_name, headers)
            assert "max-age=0" in headers[0].lower(), (cookie_name, headers[0])

    def test_anonymous_logout_never_enters_shibboleth_handler(self, guest_client):
        """A guest gets the local redirect and still has both auth cookies
        cleared, without any session revocation call (there is no session to
        revoke)."""
        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = guest_client.post(
                "/logout",
                data={"csrf_token": guest_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/"
        delete_spy.assert_not_awaited()

        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            headers = _set_cookie_headers(response, cookie_name)
            assert len(headers) == 1, (cookie_name, headers)
            assert "max-age=0" in headers[0].lower(), (cookie_name, headers[0])

    def test_shibboleth_hand_off_still_happens_for_a_session_that_no_longer_resolves(
        self, guest_client, monkeypatch
    ):
        """The SP hand-off is driven only by `settings.shibboleth_enabled`,
        never by whether the session cookie actually resolved to a user.

        A session cookie that is present but already revoked/expired (here
        simulated on the guest client, whose session lookup always resolves
        to no user) still reaches `delete_session` and still redirects to
        the fixed Shibboleth logout endpoint when federation is enabled —
        the positive case for a live federated session is proven by
        `test_federated_logout_revokes_app_session_then_uses_fixed_sp_logout`
        above.
        """
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        guest_client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))
        token = csrf_token_for(RAW_SESSION_ID)
        guest_client.cookies.set(CSRF_COOKIE_NAME, token)
        with patch("app.routes.auth.login.delete_session", autospec=True):
            response = guest_client.post(
                "/logout", data={"csrf_token": token}, follow_redirects=False
            )
        assert response.status_code == 303
        assert response.headers["location"].startswith("/Shibboleth.sso/Logout?return=")

    @pytest.mark.parametrize(
        "valid_csrf_token",
        [True, False],
        ids=["accepted_request", "rejected_request"],
    )
    def test_logout_closes_uploaded_multipart_files_on_both_outcomes(
        self, guest_client, valid_csrf_token
    ):
        """Every `UploadFile` opened while parsing the POST body is closed by
        the time the response is returned, whether the request is accepted
        (valid CSRF token) or rejected (invalid token) — a rejected request
        must not leak open file descriptors for its uploaded parts."""
        uploads = []
        original = UploadFile.__init__

        def retain(self, *args, **kwargs):
            original(self, *args, **kwargs)
            uploads.append(self)

        with patch.object(UploadFile, "__init__", retain):
            response = guest_client.post(
                "/logout",
                data={"csrf_token": guest_client.csrf_token if valid_csrf_token else "invalid"},
                files={"extra": ("large.txt", b"x" * (1024 * 1024 + 1))},
                follow_redirects=False,
            )
        assert response.status_code == (303 if valid_csrf_token else 403)
        assert uploads and all(upload.file.closed for upload in uploads)


class TestLoginLockoutTransitionAudit:
    """The account_locked audit event tracks the database's own unlocked-to-
    locked transition, never the (best-effort) lockout-notice helper."""

    @pytest.mark.parametrize(
        "notice_result",
        [True, False],
        ids=["notice_enqueued", "notice_already_claimed"],
    )
    def test_entering_lockout_is_always_audited_regardless_of_the_notice_helpers_return(
        self, guest_client, notice_result, caplog
    ):
        """record_login_failure_cur reporting an unlocked->locked transition
        always audits `account_locked` and always calls the notice helper
        exactly once — the helper's own return value (whether it actually
        won the enqueue race) can never suppress that audit event."""
        user = make_sample_user(email="alice@uzh.ch")
        check = PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="wrong_password",
            auth_revision=3,
        )

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch("app.routes.auth.login.verify_password", autospec=True, return_value=check),
            patch(
                "app.routes.auth.login.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ),
            patch(
                "app.routes.auth.login.record_login_failure_cur",
                autospec=True,
                return_value=(5, True),
            ) as record,
            patch(
                "app.routes.auth.login.queue_lockout_notice_cur",
                autospec=True,
                return_value=notice_result,
            ) as notice,
            caplog.at_level(logging.INFO, logger="audit"),
        ):
            response = guest_client.post(
                "/login",
                data={
                    "email": user.email,
                    "password": "wrong-password",
                    "csrf_token": guest_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 401
        record.assert_awaited_once_with(sentinel.cursor, user.id, expected_auth_revision=3)
        notice.assert_awaited_once()
        assert notice.await_args.kwargs["user_id"] == user.id
        assert notice.await_args.kwargs["expected_auth_revision"] == 3

        locked_events = [
            r
            for r in caplog.records
            if r.name == "audit" and getattr(r, "event_type", None) == "account_locked"
        ]
        assert len(locked_events) == 1
        assert locked_events[0].user_id == user.id

    def test_not_entering_lockout_never_calls_the_notice_helper(self, guest_client, caplog):
        """Positive control: an ordinary (non-transitioning) failure neither
        audits `account_locked` nor calls the notice helper at all."""
        user = make_sample_user(email="alice@uzh.ch")
        check = PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="wrong_password",
            auth_revision=3,
        )

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch("app.routes.auth.login.verify_password", autospec=True, return_value=check),
            patch(
                "app.routes.auth.login.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ),
            patch(
                "app.routes.auth.login.record_login_failure_cur",
                autospec=True,
                return_value=(2, False),
            ),
            patch("app.routes.auth.login.queue_lockout_notice_cur", autospec=True) as notice,
            caplog.at_level(logging.INFO, logger="audit"),
        ):
            response = guest_client.post(
                "/login",
                data={
                    "email": user.email,
                    "password": "wrong-password",
                    "csrf_token": guest_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 401
        notice.assert_not_awaited()
        locked_events = [
            r
            for r in caplog.records
            if r.name == "audit" and getattr(r, "event_type", None) == "account_locked"
        ]
        assert locked_events == []


class TestForgotPasswordRoute:
    """GET renders the request form; POST is enumeration-neutral and
    CSRF/content-type protected like every other mutation route."""

    def test_guest_sees_the_request_form(self, guest_client):
        response = guest_client.get("/forgot-password")
        assert response.status_code == 200
        assert 'name="email"' in response.text

    def test_valid_pair_reaches_the_lookup_service_and_renders_the_neutral_page(self, guest_client):
        user = make_sample_user(email="alice@uzh.ch")

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch(
                "app.routes.auth.password_reset.get_user_by_email",
                autospec=True,
                return_value=user,
            ) as lookup,
            patch(
                "app.routes.auth.password_reset.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ),
            patch("app.routes.auth.password_reset.store_reset_token_hash_cur", autospec=True),
            patch(
                "app.routes.auth.password_reset.enqueue_outbound_email_cur", autospec=True
            ) as enqueue,
        ):
            response = guest_client.post(
                "/forgot-password",
                data={"email": user.email, "csrf_token": guest_client.csrf_token},
            )

        assert response.status_code == 200
        assert "we&#39;ll send" in response.text.lower() or "we'll send" in response.text.lower()
        lookup.assert_awaited_once_with(guest_client.mock_pool, user.email)
        enqueue.assert_awaited_once()

    def test_missing_csrf_pair_is_refused_before_any_lookup(self, guest_client):
        with patch("app.routes.auth.password_reset.get_user_by_email", autospec=True) as lookup:
            response = guest_client.post(
                "/forgot-password",
                data={"email": "alice@uzh.ch"},
            )
        assert response.status_code == 403
        lookup.assert_not_awaited()

    def test_json_body_is_415_before_any_lookup(self, guest_client):
        with patch("app.routes.auth.password_reset.get_user_by_email", autospec=True) as lookup:
            response = guest_client.post(
                "/forgot-password",
                content='{"email": "alice@uzh.ch"}',
                headers={"Content-Type": "application/json"},
            )
        assert response.status_code == 415
        lookup.assert_not_awaited()


class TestForgotPasswordCapacityFailureIsEnumerationNeutral:
    """A saturated pool must fail exactly like an ordinary failure: identical
    response for any address, and nothing durable minted."""

    @pytest.mark.parametrize(
        "exception",
        [PoolTimeout("pool exhausted"), TooManyRequests("queue full")],
        ids=["pool_timeout", "too_many_requests"],
    )
    def test_lookup_failure_produces_the_identical_generic_page_for_any_address(
        self, guest_client, exception
    ):
        with (
            patch(
                "app.routes.auth.password_reset.get_user_by_email",
                autospec=True,
                side_effect=exception,
            ) as lookup,
            patch(
                "app.routes.auth.password_reset.generate_reset_token", autospec=True
            ) as generate_token,
            patch(
                "app.routes.auth.password_reset.store_reset_token_hash_cur", autospec=True
            ) as store,
            patch(
                "app.routes.auth.password_reset.enqueue_outbound_email_cur", autospec=True
            ) as enqueue,
        ):
            first = guest_client.post(
                "/forgot-password",
                data={"email": "alice@uzh.ch", "csrf_token": guest_client.csrf_token},
            )
            second = guest_client.post(
                "/forgot-password",
                data={"email": "nobody@uzh.ch", "csrf_token": guest_client.csrf_token},
            )

        assert first.status_code == second.status_code == 200
        assert first.text == second.text
        # X-Request-ID is a per-request correlation id, not part of the
        # enumeration-neutral contract; every other header must match exactly.
        headers_first = {k: v for k, v in first.headers.items() if k != "x-request-id"}
        headers_second = {k: v for k, v in second.headers.items() if k != "x-request-id"}
        assert headers_first == headers_second
        assert lookup.await_count == 2
        generate_token.assert_not_called()
        store.assert_not_awaited()
        enqueue.assert_not_awaited()

    def test_healthy_lookup_still_enqueues_for_the_known_address(self, guest_client):
        """Positive control: absent the injected failure, an eligible address
        does reach the outbox."""
        user = make_sample_user(email="alice@uzh.ch")

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            yield sentinel.cursor

        with (
            patch(
                "app.routes.auth.password_reset.get_user_by_email",
                autospec=True,
                return_value=user,
            ),
            patch(
                "app.routes.auth.password_reset.get_db_cursor",
                autospec=True,
                side_effect=fake_get_db_cursor,
            ),
            patch("app.routes.auth.password_reset.store_reset_token_hash_cur", autospec=True),
            patch(
                "app.routes.auth.password_reset.enqueue_outbound_email_cur", autospec=True
            ) as enqueue,
        ):
            response = guest_client.post(
                "/forgot-password",
                data={"email": user.email, "csrf_token": guest_client.csrf_token},
            )

        assert response.status_code == 200
        enqueue.assert_awaited_once()


class TestResetPasswordRoute:
    """GET consults the token gate before rendering; POST commits once."""

    def test_valid_token_renders_the_new_password_form(self, guest_client):
        with (
            patch(
                "app.routes.auth.password_reset.validate_reset_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@uzh.ch"},
            ) as validate,
            patch(
                "app.routes.auth.password_reset.verify_reset_token_hash",
                autospec=True,
                return_value=True,
            ),
        ):
            response = guest_client.get("/reset-password/a-live-reset-token")

        assert response.status_code == 200
        assert 'name="password"' in response.text
        validate.assert_called_once_with("a-live-reset-token")

    def test_invalid_token_renders_the_error_page_instead(self, guest_client):
        with patch(
            "app.routes.auth.password_reset.validate_reset_token",
            autospec=True,
            return_value=None,
        ):
            response = guest_client.get("/reset-password/not-a-real-token")

        assert response.status_code == 422
        assert "invalid or has expired" in response.text
        assert 'name="password"' not in response.text

    def test_valid_submission_redirects_and_commits_exactly_once(self, guest_client):
        with (
            patch(
                "app.routes.auth.password_reset.validate_reset_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@uzh.ch"},
            ),
            patch(
                "app.routes.auth.password_reset.update_password_with_token", autospec=True
            ) as update,
        ):
            response = guest_client.post(
                "/reset-password",
                data={
                    "token": "a-live-reset-token",
                    "password": "correct-horse-battery-staple-9",
                    "password_confirm": "correct-horse-battery-staple-9",
                    "csrf_token": guest_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        update.assert_awaited_once()


class TestShibbolethCallbackAccess:
    """The internal callback is refused whenever federation is off, and only
    ever reaches the finalizer through the trusted, authenticated path."""

    def test_disabled_federation_refuses_without_creating_a_session(
        self, guest_client, monkeypatch
    ):
        monkeypatch.setattr(settings, "shibboleth_enabled", False)
        with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
            response = guest_client.get("/auth/shibboleth/callback", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert "set-cookie" not in response.headers
        finalize.assert_not_awaited()

    def test_enabled_federation_with_the_trusted_internal_header_reaches_the_finalizer(
        self, guest_client, monkeypatch
    ):
        """Positive control: nginx's internal secret and a trusted assertion
        are enough to reach finalize_shibboleth_login exactly once.

        The deployment-only "reached over TCP" guard (request.client is
        always non-None inside TestClient, unlike the production Unix
        socket) is neutralised here so this test isolates the header/secret
        gate that this route itself owns; that guard's own behaviour is
        pinned directly against the handler in
        unit/test_shibboleth_callback.py.
        """
        monkeypatch.setattr(settings, "shibboleth_enabled", True)
        monkeypatch.setattr(
            settings, "shibboleth_internal_secret", SecretStr("test-internal-secret")
        )
        federated_user = make_sample_user(
            id=5,
            auth_method="shibboleth",
            federated_status="approved",
        )
        with (
            patch.object(starlette.requests.HTTPConnection, "client", property(lambda _self: None)),
            patch(
                "app.routes.auth.login.is_trusted_federated_principal",
                autospec=True,
                return_value=True,
            ),
            patch(
                "app.routes.auth.login.finalize_shibboleth_login",
                autospec=True,
                return_value=FederatedLoginSuccess(user=federated_user, session_id="fed-sess-1"),
            ) as finalize,
        ):
            response = guest_client.get(
                "/auth/shibboleth/callback",
                headers={
                    SHIBBOLETH_INTERNAL_AUTH_HEADER: "test-internal-secret",
                    SHIBBOLETH_ISSUER_HEADER: "https://idp.test.example/idp/shibboleth",
                    SHIBBOLETH_SUBJECT_HEADER: "urn:test:subject:5",
                    SHIBBOLETH_MAIL_HEADER: federated_user.email,
                    SHIBBOLETH_AUTHN_CONTEXT_HEADER: REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/"
        assert "set-cookie" in response.headers
        finalize.assert_awaited_once()
