"""Session middleware over the real stack: cookies, CSRF, routing, audit."""

import http.cookies
from contextlib import ExitStack, contextmanager
from unittest.mock import create_autospec, patch

import itsdangerous.timed
import pytest

from app.main import app
from app.middleware.audit_logging import AuditLoggingMiddleware
from app.middleware.cookies import SESSION_SIGNER
from app.middleware.csrf import CSRF_COOKIE_NAME
from app.middleware.rate_limiting import limiter
from app.middleware.session import SessionResolutionMiddleware
from app.services.authentication import LocalLoginSuccess, PasswordCheck
from app.services.sessions import SessionLookup
from app.services.sessions import consume_flash as _real_consume_flash
from app.services.sessions import get_session_user as _real_get_session_user
from config import settings
from tests.fixtures import (
    RAW_SESSION_ID,
    csrf_token_for,
    make_sample_user,
    sign_session_id,
)


def _deleted_cookie_names(response) -> set[str]:
    """Names of cookies the response deletes (Max-Age=0 per delete_cookie)."""
    deleted = set()
    for header in response.headers.get_list("set-cookie"):
        cookie = http.cookies.SimpleCookie()
        cookie.load(header)
        for name, morsel in cookie.items():
            if morsel.get("max-age") == "0":
                deleted.add(name)
    return deleted


def _session_set_cookie_headers(response) -> list[str]:
    """All raw Set-Cookie headers for the session cookie, in emission order."""
    return [
        h
        for h in response.headers.get_list("set-cookie")
        if h.startswith(f"{settings.session_cookie_name}=")
    ]


class TestExactRouteSessionLookupSkip:
    """Only the reviewed health probes and the static mount skip session lookup."""

    @pytest.fixture(autouse=True)
    def _exact_route_rules_only(self, monkeypatch):
        """Disable limiter admission so route-specific session-lookup skip rules are tested in
        isolation.
        """
        monkeypatch.setattr(limiter, "enabled", False)

    def test_healthiness_collision_still_resolves_session(self, authenticated_client):
        """A lookalike health path must not inherit the exact probe exception."""
        response = authenticated_client.get("/healthiness")
        assert response.status_code == 404
        assert authenticated_client.session_spy.await_count >= 1

    def test_exact_health_gets_and_static_reads_skip_session_lookup(self, authenticated_client):
        """Only the reviewed probes and read-only StaticFiles mount skip lookup."""
        for path in ("/health", "/health/detail", "/static/anything.css"):
            authenticated_client.session_spy.reset_mock()
            authenticated_client.get(path)
            assert authenticated_client.session_spy.await_count == 0, path

    def test_other_methods_do_not_inherit_session_lookup_skip(self, authenticated_client):
        """Method/path exceptions are exact; POST /health still resolves the cookie."""
        authenticated_client.session_spy.reset_mock()
        response = authenticated_client.post("/health", follow_redirects=False)
        assert response.status_code == 405
        assert authenticated_client.session_spy.await_count >= 1

    def test_a_query_string_does_not_change_the_exact_route_skip_decision(
        self, authenticated_client
    ):
        """The skip key is (method, request.url.path) â€” a query string must
        not turn an exempt path into a non-exempt one or vice versa."""
        authenticated_client.session_spy.reset_mock()
        response = authenticated_client.get("/health?x=1")
        assert response.status_code == 200
        assert authenticated_client.session_spy.await_count == 0

    @pytest.mark.parametrize("path", ["/healthz", "/health/"])
    def test_lookalike_paths_do_not_inherit_the_exact_skip(self, authenticated_client, path):
        """Check lookalike paths do not inherit the exact skip."""
        authenticated_client.session_spy.reset_mock()
        authenticated_client.get(path)
        assert authenticated_client.session_spy.await_count >= 1

    def test_the_static_mount_skip_is_limited_to_read_methods(self, authenticated_client):
        """The static-mount exemption only covers GET/HEAD; POST under
        /static/ still resolves the session, mirroring POST /health above."""
        authenticated_client.session_spy.reset_mock()
        authenticated_client.post("/static/anything.css")
        assert authenticated_client.session_spy.await_count >= 1

    def test_head_robots_txt_skips_session_lookup(self, authenticated_client):
        """HEAD is exempted alongside GET for the exact-probe paths, not
        just for /health â€” /robots.txt is one of the reviewed pairs."""
        authenticated_client.session_spy.reset_mock()
        authenticated_client.request("HEAD", "/robots.txt")
        assert authenticated_client.session_spy.await_count == 0


class TestAdminRecoveryCodeBackstop:
    """Cover admin recovery code backstop."""

    @staticmethod
    def _admin_dashboard_service_patches():
        """Return patches for an empty user dashboard with no pending invitations."""
        return (
            patch(
                "app.routes.auth.admin.list_admin_promotion_states",
                autospec=True,
                return_value={},
            ),
            patch(
                "app.routes.auth.admin.list_users",
                autospec=True,
                return_value=([], 0),
            ),
        )

    def test_local_admin_without_active_recovery_codes_is_refused(self, client_builder):
        """Check local admin without active recovery codes is refused (HTTP 403)."""
        admin = make_sample_user(
            is_admin=True,
            totp_recovery_code_generation=0,
            totp_recovery_codes_available=False,
        )
        client = client_builder(session_user=admin)

        response = client.get("/admin", follow_redirects=False)

        assert response.status_code == 403

    def test_local_admin_with_active_recovery_codes_is_admitted(self, admin_client):
        """Check local admin with active recovery codes is admitted (HTTP 200)."""
        with ExitStack() as stack:
            for p in self._admin_dashboard_service_patches():
                stack.enter_context(p)
            response = admin_client.get("/admin", follow_redirects=False)

        assert response.status_code == 200

    def test_federated_admin_is_not_subject_to_the_recovery_code_check(self, client_builder):
        """Check federated admin is not subject to the recovery code check (HTTP 200)."""
        admin = make_sample_user(is_admin=True, auth_method="shibboleth")
        client = client_builder(session_user=admin)

        with ExitStack() as stack:
            for p in self._admin_dashboard_service_patches():
                stack.enter_context(p)
            response = client.get("/admin", follow_redirects=False)

        assert response.status_code == 200


class TestFlashConsumptionGating:
    """Flash is consumed in middleware BEFORE call_next, gated on flash_present."""

    def test_flash_consumed_before_render_and_visible_in_page(self, client_builder):
        """Check flash consumed before render and visible in page (HTTP 200)."""
        client = client_builder(
            session_user=make_sample_user(),
            flash=("Saved.", "success"),
        )

        with patch(
            "app.middleware.session.restore_flash_if_empty",
            autospec=True,
        ) as restore:
            response = client.get("/account")

        assert response.status_code == 200
        client.consume_flash_spy.assert_awaited_once()
        restore.assert_not_awaited()
        assert "Saved." in response.text

    def test_no_flash_skips_consume_entirely(self, client_builder):
        """flash_present=False skips the read-and-clear query: consume_flash
        must not be called at all."""
        client = client_builder(session_user=make_sample_user())
        response = client.get("/account")
        assert response.status_code == 200
        assert client.consume_flash_spy.await_count == 0


class TestCookieSignatureAndLivenessHandling:
    """Passive cookie handling: invalid, dead-session, and expired cookies."""

    def test_unsigned_garbage_cookie_is_inert_and_not_passively_deleted(self, client_builder):
        """Unsigned cookies confer no authority and cannot erase a newer login.

        CSRF preparation supplies a usable anonymous form token independently.
        """
        client = client_builder(session_user=None)
        client.cookies.set(settings.session_cookie_name, "garbage-unsigned")

        client.cookies.delete(CSRF_COOKIE_NAME)
        response = client.get("/about")
        assert response.status_code == 200
        deleted = _deleted_cookie_names(response)
        assert settings.session_cookie_name not in deleted
        assert CSRF_COOKIE_NAME not in deleted

        csrf_sets = [
            v.decode().split(";", 1)[0]
            for k, v in response.headers.raw
            if k == b"set-cookie" and v.decode().startswith(f"{CSRF_COOKIE_NAME}=")
        ]
        assert len(csrf_sets) == 1 and not csrf_sets[0].endswith('=""'), csrf_sets
        assert client.session_spy.await_count == 0

    def test_valid_cookie_for_dead_session_is_only_an_anonymous_nonce(self, client_builder):
        """Check valid cookie for dead session is only an anonymous nonce (HTTP 200)."""
        client = client_builder(session_user=None)
        client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))
        response = client.get("/about")
        assert response.status_code == 200

        assert client.session_spy.await_count >= 1
        deleted = _deleted_cookie_names(response)
        assert settings.session_cookie_name not in deleted
        assert CSRF_COOKIE_NAME not in deleted

    def test_signature_expired_cookie_is_treated_as_guest(self, client_builder):
        """Check signature expired cookie is treated as guest (HTTP 200)."""
        # Sign the value with the real signer but a clock set far enough in the
        # past that max_age (session_max_age_seconds) has elapsed by now.
        stale_epoch = 1_000_000_000  # 2001 â€” comfortably older than any max_age
        with patch.object(itsdangerous.timed.time, "time", return_value=stale_epoch):
            stale_value = SESSION_SIGNER.dumps(RAW_SESSION_ID)

        client = client_builder(session_user=None)
        client.cookies.set(settings.session_cookie_name, stale_value)
        response = client.get("/about")

        assert response.status_code == 200
        assert client.session_spy.await_count == 0
        assert settings.session_cookie_name not in _deleted_cookie_names(response)


class TestSessionPurposeRouteAccess:
    """SecureAPIRouter dependencies enforce partial-session and enrollment
    boundaries after routing, for both purpose-limited and full sessions."""

    def test_totp_setup_purpose_redirect_carries_security_headers(self, totp_setup_client):
        """A public route rejects a partial session and the response is wrapped."""
        response = totp_setup_client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/setup-totp"
        assert "content-security-policy" in response.headers
        assert "x-request-id" in response.headers

    def test_verify_email_capability_is_reachable_during_totp_setup(self, totp_setup_client):
        """The exact capability route remains independent of session purpose."""
        response = totp_setup_client.get("/verify-email/" + "A" * 43, follow_redirects=False)
        assert response.status_code == 200

    def test_logout_is_usable_during_totp_setup(self, totp_setup_client):
        """The exact open route lets a purpose-limited session end itself."""
        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = totp_setup_client.post(
                "/logout",
                data={"csrf_token": totp_setup_client.csrf_token},
                follow_redirects=False,
            )
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        assert delete_spy.await_count == 1

    def test_send_verification_submit_is_usable_during_totp_setup(self, client_builder):
        """The resend form rendered by verify_email_pending.html
        posts to the exact open route while the session is purpose-limited."""
        user = make_sample_user(totp_configured=False, email_verified=False)
        client = client_builder(session_user=user, session_purpose="totp_setup")

        with patch(
            "app.routes.auth.register.resend_local_registration",
            autospec=True,
            return_value=None,  # keep the route off the tripwire mock pool
        ):
            response = client.post(
                "/send_verification",
                data={"csrf_token": client.csrf_token, "email": user.email},
                follow_redirects=False,
            )

        assert response.status_code == 200
        assert "location" not in response.headers

    def test_send_verification_page_is_usable_during_totp_setup(self, totp_setup_client):
        """The exact open GET hosts the resend form during enrollment."""
        response = totp_setup_client.get("/send_verification", follow_redirects=False)
        assert response.status_code == 200

    def test_local_user_without_totp_gets_enrollment_redirect(self, client_builder):
        """A full-purpose local session still fails closed if TOTP is absent."""
        client = client_builder(session_user=make_sample_user(totp_configured=False))
        response = client.get("/account", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/setup-totp"

    def test_policy_approved_shibboleth_session_does_not_require_local_totp(self, client_builder):
        """Check policy approved Shibboleth session does not require local TOTP (HTTP 200)."""
        client = client_builder(
            session_user=make_sample_user(auth_method="shibboleth", totp_configured=False)
        )
        response = client.get("/account", follow_redirects=False)
        assert response.status_code == 200


class TestSessionCookieTransitionSafety:
    """Explicit login/logout cookie transitions never collide with, nor are
    undone by, the middleware's passive handling of a stale session cookie."""

    STALE_SESSION_ID = "stale-id"
    FRESH_SESSION_ID = "fresh-raw-id"

    def _plant_stale_session(self, client) -> str:
        """Install a signed dead-session cookie, rebind its CSRF pair, and return the form token."""
        client.cookies.set(settings.session_cookie_name, sign_session_id(self.STALE_SESSION_ID))
        token = csrf_token_for(self.STALE_SESSION_ID)
        client.cookies.set(CSRF_COOKIE_NAME, token)
        return token

    @contextmanager
    def _successful_login_services(self):
        """Mock atomic login finalizer, preserving the cookie behaviour."""
        user = make_sample_user()
        returns = {
            "verify_password": PasswordCheck(
                user=user,
                password_ok=True,
                locked_until=None,
                failure_reason=None,
                auth_revision=7,
            ),
            "finalize_local_login": LocalLoginSuccess(user, self.FRESH_SESSION_ID, "full"),
            "delete_session": None,
        }
        with ExitStack() as stack:
            yield {
                name: stack.enter_context(
                    patch(f"app.routes.auth.login.{name}", autospec=True, return_value=value)
                )
                for name, value in returns.items()
            }

    def test_fresh_login_cookie_suppresses_stale_session_deletion(self, guest_client):
        """A stale cookie is revoked without deleting the finalizer's fresh cookie."""
        token = self._plant_stale_session(guest_client)
        with self._successful_login_services() as mocks:
            response = guest_client.post(
                "/login",
                data={
                    "email": "alice@example.org",
                    "password": "correct-password",
                    "totp_code": "123456",
                    "csrf_token": token,
                },
                follow_redirects=False,
            )
        assert response.status_code == 303
        mocks["delete_session"].assert_awaited_once_with(
            guest_client.mock_pool, self.STALE_SESSION_ID
        )
        finalizer = mocks["finalize_local_login"]
        finalizer.assert_awaited_once()
        assert finalizer.call_args.args == (guest_client.mock_pool,)
        assert finalizer.call_args.kwargs["user_id"] == 1
        assert finalizer.call_args.kwargs["expected_auth_revision"] == 7
        assert finalizer.call_args.kwargs["totp_code"] == "123456"
        assert isinstance(finalizer.call_args.kwargs["ip_address"], str)
        headers = _session_set_cookie_headers(response)
        assert len(headers) == 1, headers
        assert "max-age=0" not in headers[0].lower(), headers[0]
        signed_value = headers[0].split(";", 1)[0].split("=", 1)[1].strip('"')
        assert SESSION_SIGNER.loads(signed_value) == self.FRESH_SESSION_ID

    def test_stale_session_response_never_deletes_browser_session_cookie(self, guest_client):
        """A passive guest page leaves explicit session transitions to their owners."""
        self._plant_stale_session(guest_client)
        response = guest_client.get("/about")
        assert response.status_code == 200

        assert settings.session_cookie_name not in _deleted_cookie_names(response)
        headers = _session_set_cookie_headers(response)
        assert headers == []

    def test_handler_side_deletion_counts_as_fresh_and_is_not_duplicated(self, guest_client):
        """Check handler side deletion counts as fresh and is not duplicated (HTTP 303)."""
        token = self._plant_stale_session(guest_client)

        with patch("app.routes.auth.login.delete_session", autospec=True) as delete_spy:
            response = guest_client.post(
                "/logout", data={"csrf_token": token}, follow_redirects=False
            )

        assert response.status_code == 303
        delete_spy.assert_awaited_once_with(guest_client.mock_pool, self.STALE_SESSION_ID)
        headers = _session_set_cookie_headers(response)
        assert len(headers) == 1, headers
        assert "max-age=0" in headers[0].lower(), headers[0]

    def test_consumed_flash_is_restored_when_get_redirects(self, client_builder):
        """A consumed flash survives a non-rendering GET redirect."""
        client = client_builder(
            session_user=make_sample_user(totp_configured=False),
            session_purpose="totp_setup",
            flash=("Saved.", "success"),
        )

        with patch(
            "app.middleware.session.restore_flash_if_empty",
            autospec=True,
        ) as restore:
            response = client.get(
                "/account",
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert response.headers["location"] == "/setup-totp"
        client.consume_flash_spy.assert_awaited_once()
        restore.assert_awaited_once_with(
            client.mock_pool,
            RAW_SESSION_ID,
            "Saved.",
            "success",
        )


class TestSessionFailureAuditTrace:
    """Session resolution failures must retain request IDs and one request
    audit event; successes and route-dependency redirects remain audited."""

    @pytest.mark.parametrize("phase", ["lookup", "flash"])
    def test_session_failure_has_correlated_500(self, authenticated_client, phase):
        # This test covers failures in session resolution and request auditing.
        # Keep admission independent of the shared Redis limiter, whose
        # fail-closed 503 would correctly happen before either failure is reached.
        """Check session failure has correlated 500."""
        with (
            patch.object(authenticated_client.app.state.limiter, "enabled", False),
            patch(
                "app.middleware.session.get_session_user",
                new=create_autospec(
                    _real_get_session_user,
                    return_value=SessionLookup(make_sample_user(), "full", True),
                ),
            ) as lookup,
            patch(
                "app.middleware.session.consume_flash",
                new=create_autospec(_real_consume_flash),
            ) as flash,
            patch("app.middleware.audit_logging.audit_logger") as audit,
        ):
            (lookup if phase == "lookup" else flash).side_effect = RuntimeError(
                "database unavailable"
            )
            response = authenticated_client.get("/about", follow_redirects=False)
        assert response.status_code == 500
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) == 16
        audit.exception.assert_called_once()
        audit.log.assert_not_called()
        extra = audit.exception.call_args.kwargs["extra"]
        assert extra["request_id"] == request_id
        assert extra["event_type"] == "request_error"
        assert extra["status_code"] == 500
        assert extra["user_id"] == (None if phase == "lookup" else 1)

    def test_success_still_audits_resolved_user(self, authenticated_client):
        """Check success still audits resolved user (HTTP 200)."""
        with patch("app.middleware.audit_logging.audit_logger") as audit:
            response = authenticated_client.get("/about", follow_redirects=False)
        assert response.status_code == 200
        audit.exception.assert_not_called()
        audit.log.assert_called_once()
        assert audit.log.call_args.kwargs["extra"]["user_id"] == 1
        assert audit.log.call_args.kwargs["extra"]["request_id"] == response.headers["X-Request-ID"]

    def test_audit_wraps_session_resolution_in_application_stack(self):
        """Audit logging must run outside session resolution so a lookup
        failure is still traced."""
        classes = [middleware.cls for middleware in app.user_middleware]
        assert classes.index(AuditLoggingMiddleware) < classes.index(SessionResolutionMiddleware)

    def test_health_success_keeps_request_id_without_audit_noise(self, guest_client):
        """A successful health probe is exempt from the audit log; positive
        control is test_success_still_audits_resolved_user above."""
        with patch("app.middleware.audit_logging.audit_logger") as audit:
            response = guest_client.get("/health")
        assert response.status_code == 200
        assert response.headers["X-Request-ID"]
        audit.log.assert_not_called()
        audit.exception.assert_not_called()

    def test_route_dependency_redirect_is_still_audited(self, totp_setup_client):
        """Check route dependency redirect is still audited (HTTP 303)."""
        with patch("app.middleware.audit_logging.audit_logger") as audit:
            response = totp_setup_client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/setup-totp"
        audit.log.assert_called_once()
        assert audit.log.call_args.kwargs["extra"]["user_id"] == 1
