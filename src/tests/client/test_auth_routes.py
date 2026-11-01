"""Client-tier contracts for `/login` and `/logout`."""

import html
import logging
import re
import urllib.parse
from contextlib import asynccontextmanager
from unittest.mock import patch, sentinel

import pytest
import starlette.requests
from lxml import html as html_tree
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
from app.services.password_reset import InvalidResetTotp
from app.services.tokens import action_token_public_id
from app.services.totp import TotpDecryptionError
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
    """Require fresh-authentication and MFA parameters on the UI link; this does not prove IdP
    enforcement.
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
    """Decode the SP target once, then parse its callback query to recover next."""
    once = urllib.parse.unquote(target)
    assert once.startswith(_CALLBACK_PREFIX), once
    return urllib.parse.unquote(once[len(_CALLBACK_PREFIX) :])


def _set_cookie_headers(response, name: str) -> list[str]:
    """All raw Set-Cookie headers for a given cookie name."""
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


class TestLoginPageLayout:
    """Initial and rejected sign-in responses keep the complete form in its layout."""

    @pytest.mark.parametrize("shibboleth_enabled", [False, True], ids=["local", "federated"])
    @pytest.mark.parametrize("response_kind", ["success-notice", "failed-post"])
    def test_login_content_stays_inside_one_auth_section(
        self, guest_client, shibboleth_enabled, response_kind
    ):
        """Check login content stays inside one auth section."""
        with patch.dict(templates.env.globals, {"shibboleth_enabled": shibboleth_enabled}):
            if response_kind == "success-notice":
                response = guest_client.get(
                    "/login", params={"notice": "totp_setup_completed", "next": "/dataset/42"}
                )
            else:
                with patch(
                    "app.routes.auth.login.verify_password",
                    autospec=True,
                    return_value=PasswordCheck(
                        user=None,
                        password_ok=False,
                        locked_until=None,
                        failure_reason="unknown_user",
                        auth_revision=None,
                    ),
                ):
                    response = guest_client.post(
                        "/login?next=%2Fdataset%2F42",
                        data={
                            "email": "reader@example.org",
                            "password": "incorrect-password",
                            "csrf_token": guest_client.csrf_token,
                        },
                    )

        assert response.status_code == (200 if response_kind == "success-notice" else 401)
        assert response.headers["Cache-Control"] == "no-store"
        document = html_tree.fromstring(response.text)
        sections = document.xpath(
            '//section[contains(concat(" ", normalize-space(@class), " "), " auth-page ")]'
        )
        assert len(sections) == 1
        section = sections[0]
        assert "container" in section.get("class", "").split()
        assert len(section.xpath("parent::main")) == 1
        assert document.xpath("//main//h1") == section.xpath("./h1")
        assert section.xpath("./h1/text()") == ["Login"]

        forms = section.xpath('.//form[@class="auth-form"]')
        assert len(forms) == 1
        assert document.xpath('//form[@class="auth-form"]') == forms
        assert forms[0].get("method") == "post"
        form_url = urllib.parse.urlsplit(forms[0].get("action"))
        assert form_url.path == "/login"
        assert urllib.parse.parse_qs(form_url.query) == {"next": ["/dataset/42"]}
        assert forms[0].xpath('.//input[@name="csrf_token"]/@value') == [guest_client.csrf_token]
        assert forms[0].xpath('.//input[@name="password"]/@type') == ["password"]

        messages = document.xpath('//div[@role="status" or @role="alert"]')
        assert len(messages) == 1
        assert section.xpath('.//div[@role="status" or @role="alert"]') == messages
        expected_role = "status" if response_kind == "success-notice" else "alert"
        assert messages[0].get("role") == expected_role

        links = document.xpath('//a[contains(@href, "/Shibboleth.sso/Login?")]')
        assert len(links) == int(shibboleth_enabled)
        assert section.xpath('.//a[contains(@href, "/Shibboleth.sso/Login?")]') == links
        if shibboleth_enabled:
            _assert_exact_mfa_request(response.text)
            assert _recovered_next(_shib_target(response.text)) == "/dataset/42"


class TestLoginPageShibbolethLink:
    """Require both Shibboleth URL-encoding layers; patch frozen template globals to change federation."""

    def test_shibboleth_href_round_trips_simple_next(self, guest_client):
        """Require simple next targets to round-trip with structural evidence of the outer encoding
        layer.
        """
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
        """Require embedded query values to round-trip with structural evidence of both encoding
        layers.
        """
        with patch.dict(templates.env.globals, {"shibboleth_enabled": True}):
            response = guest_client.get("/login?next=/search?q=a%26b")

        assert response.status_code == 200
        target = _shib_target(response.text)
        assert "%25" in target, target  # inner escapes re-encoded by the outer layer
        assert "?" not in target and "&" not in target, target
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
    """Require each authentication cookie to expire exactly once on logout."""

    def test_logout_deletes_session_and_csrf_cookies_exactly_once(self, authenticated_client):
        """Check logout deletes session and CSRF cookies exactly once (HTTP 303)."""
        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = authenticated_client.post(
                "/logout",
                data={"csrf_token": authenticated_client.csrf_token},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/"
        delete_spy.assert_awaited_once_with(authenticated_client.mock_pool, RAW_SESSION_ID)

        for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
            headers = _set_cookie_headers(response, cookie_name)
            assert len(headers) == 1, (cookie_name, headers)
            assert "max-age=0" in headers[0].lower(), (cookie_name, headers[0])

    def test_federated_logout_revokes_app_session_then_uses_fixed_sp_logout(
        self, client_builder, monkeypatch
    ):
        """Require session revocation followed by the fixed Shibboleth logout redirect."""
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
        """The SP hand-off is driven only by `settings.shibboleth_enabled`, never by whether the
        session cookie actually resolved to a user.
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
        self, authenticated_client, valid_csrf_token
    ):
        """Require multipart upload closure before both accepted and rejected logout responses return."""
        uploads = []
        original = UploadFile.__init__

        def retain(self, *args, **kwargs):
            """Initialize the upload and retain it so the test can check closure."""
            original(self, *args, **kwargs)
            uploads.append(self)

        with (
            patch.object(UploadFile, "__init__", retain),
            patch("app.routes.auth.login.delete_session", autospec=True),
        ):
            response = authenticated_client.post(
                "/logout",
                data={
                    "csrf_token": authenticated_client.csrf_token if valid_csrf_token else "invalid"
                },
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
        """Audit every lockout transition regardless of whether notification enqueueing wins its race."""
        user = make_sample_user(email="alice@example.org")
        check = PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="wrong_password",
            auth_revision=3,
        )

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            """Yield the scripted cursor after checking the database boundary."""
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
        """Check not entering lockout never calls the notice helper (HTTP 401)."""
        user = make_sample_user(email="alice@example.org")
        check = PasswordCheck(
            user=user,
            password_ok=False,
            locked_until=None,
            failure_reason="wrong_password",
            auth_revision=3,
        )

        @asynccontextmanager
        async def fake_get_db_cursor(_pool):
            """Yield the scripted cursor after checking the database boundary."""
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
    """The request boundary is generic and delegates atomic issuance to its service."""

    def test_guest_sees_the_request_form(self, guest_client):
        """Check guest sees the request form (HTTP 200)."""
        response = guest_client.get("/forgot-password")
        assert response.status_code == 200
        assert 'name="email"' in response.text

    def test_valid_pair_reaches_the_lookup_service_and_renders_the_neutral_page(self, guest_client):
        """Check valid pair reaches the lookup service and renders the neutral page (HTTP 200)."""
        with patch("app.routes.auth.password_reset.request_password_reset", autospec=True) as issue:
            response = guest_client.post(
                "/forgot-password",
                data={"email": " ALICE@example.org ", "csrf_token": guest_client.csrf_token},
            )
        assert response.status_code == 200
        assert "existing code stays valid" in response.text.lower()
        issue.assert_awaited_once_with(guest_client.mock_pool, email="alice@example.org")

    def test_missing_csrf_pair_is_refused_before_any_lookup(self, guest_client):
        """Check missing CSRF pair is refused before any lookup (HTTP 403)."""
        with patch("app.routes.auth.password_reset.request_password_reset", autospec=True) as issue:
            response = guest_client.post("/forgot-password", data={"email": "alice@example.org"})
        assert response.status_code == 403
        issue.assert_not_awaited()

    def test_json_body_is_415_before_any_lookup(self, guest_client):
        """Check JSON body is 415 before any lookup."""
        with patch("app.routes.auth.password_reset.request_password_reset", autospec=True) as issue:
            response = guest_client.post(
                "/forgot-password",
                content='{"email": "alice@example.org"}',
                headers={"Content-Type": "application/json"},
            )
        assert response.status_code == 415
        issue.assert_not_awaited()


class TestForgotPasswordCapacityFailureIsEnumerationNeutral:
    """Issuance failures preserve the same response for every submitted address."""

    @pytest.mark.parametrize(
        "exception", [PoolTimeout("pool exhausted"), TooManyRequests("queue full")]
    )
    def test_lookup_failure_produces_the_identical_generic_page_for_any_address(
        self, guest_client, exception
    ):
        """Check lookup failure produces the identical generic page for any address (HTTP 200)."""
        with patch(
            "app.routes.auth.password_reset.request_password_reset",
            autospec=True,
            side_effect=exception,
        ) as issue:
            responses = [
                guest_client.post(
                    "/forgot-password", data={"email": email, "csrf_token": guest_client.csrf_token}
                )
                for email in ("alice@example.org", "nobody@example.org")
            ]
        first, second = responses
        assert first.status_code == second.status_code == 200
        assert first.text == second.text
        assert {k: v for k, v in first.headers.items() if k != "x-request-id"} == {
            k: v for k, v in second.headers.items() if k != "x-request-id"
        }
        assert issue.await_count == 2

    def test_healthy_lookup_still_enqueues_for_the_known_address(self, guest_client):
        """The HTTP boundary reaches the service; database tests prove actual enqueue."""
        with patch("app.routes.auth.password_reset.request_password_reset", autospec=True) as issue:
            response = guest_client.post(
                "/forgot-password",
                data={"email": "alice@example.org", "csrf_token": guest_client.csrf_token},
            )
        assert response.status_code == 200
        issue.assert_awaited_once()


class TestResetPasswordRoute:
    """GET renders a generic identifier-only form; POST checks the capability and commits once."""

    def test_valid_token_renders_the_new_password_form(self, guest_client):
        """A non-secret identifier renders a generic form without resolving a token."""
        token = "a-live-reset-token"
        with patch(
            "app.routes.auth.password_reset.validate_reset_token", autospec=True
        ) as validate:
            response = guest_client.get(f"/reset-password/{action_token_public_id(token)}")
        assert response.status_code == 200
        assert 'name="password"' in response.text and 'name="public_id"' in response.text
        assert 'name="totp_code"' in response.text
        assert token not in response.text and "alice@example.org" not in response.text
        validate.assert_not_called()
        guest_client.mock_pool.connection.assert_not_called()

    def test_invalid_token_renders_the_error_page_instead(self, guest_client):
        """Legacy secret-bearing paths are rejected rather than parsed as capabilities."""
        with patch(
            "app.routes.auth.password_reset.validate_reset_token", autospec=True
        ) as validate:
            response = guest_client.get("/reset-password/not-a-real-token")
        assert response.status_code == 404
        assert 'name="password"' not in response.text
        validate.assert_not_called()

    def test_valid_submission_redirects_and_commits_exactly_once(self, guest_client):
        """Check valid submission redirects and commits exactly once (HTTP 303)."""
        with (
            patch(
                "app.routes.auth.password_reset.validate_reset_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@example.org"},
            ),
            patch(
                "app.routes.auth.password_reset.update_password_with_token", autospec=True
            ) as update,
        ):
            response = guest_client.post(
                "/reset-password",
                data={
                    "token": "a-live-reset-token",
                    "public_id": action_token_public_id("a-live-reset-token"),
                    "password": "correct-horse-battery-staple-9",
                    "password_confirm": "correct-horse-battery-staple-9",
                    "totp_code": "123456",
                    "csrf_token": guest_client.csrf_token,
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        update.assert_awaited_once_with(
            guest_client.mock_pool,
            7,
            "a-live-reset-token",
            "correct-horse-battery-staple-9",
            expected_email="alice@example.org",
            totp_code="123456",
        )

    def test_missing_authenticator_code_never_calls_completion(self, guest_client):
        """Check missing authenticator code never calls completion (HTTP 422)."""
        with patch(
            "app.routes.auth.password_reset.update_password_with_token", autospec=True
        ) as update:
            response = guest_client.post(
                "/reset-password",
                data={
                    "token": "a-live-reset-token",
                    "public_id": action_token_public_id("a-live-reset-token"),
                    "password": "correct-horse-battery-staple-9",
                    "password_confirm": "correct-horse-battery-staple-9",
                    "csrf_token": guest_client.csrf_token,
                },
            )
        assert response.status_code == 422
        update.assert_not_awaited()

    @pytest.mark.parametrize("unreadable", [False, True])
    def test_failed_totp_never_echoes_authenticator_code(self, guest_client, unreadable):
        """Check failed TOTP never echoes authenticator code."""
        token = "a-live-reset-token"
        code = "765432"
        failure = TotpDecryptionError(7) if unreadable else InvalidResetTotp("Invalid code")
        with (
            patch(
                "app.routes.auth.password_reset.validate_reset_token",
                autospec=True,
                return_value={"user_id": 7, "email": "alice@example.org"},
            ),
            patch(
                "app.routes.auth.password_reset.update_password_with_token",
                autospec=True,
                side_effect=failure,
            ),
        ):
            response = guest_client.post(
                "/reset-password",
                data={
                    "token": token,
                    "public_id": action_token_public_id(token),
                    "password": "correct-horse-battery-staple-9",
                    "password_confirm": "correct-horse-battery-staple-9",
                    "totp_code": code,
                    "csrf_token": guest_client.csrf_token,
                },
            )
        assert response.status_code == (503 if unreadable else 422)
        assert code not in response.text
        if unreadable:
            assert token not in response.text
        else:
            assert token in response.text


class TestShibbolethCallbackAccess:
    """The internal callback is refused whenever federation is off, and only
    ever reaches the finalizer through the trusted, authenticated path."""

    def test_disabled_federation_refuses_without_creating_a_session(
        self, guest_client, monkeypatch
    ):
        """Check disabled federation refuses without creating a session (HTTP 303)."""
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
        """Require trusted federation headers to reach finalization with the TCP-deployment guard
        patched.
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
