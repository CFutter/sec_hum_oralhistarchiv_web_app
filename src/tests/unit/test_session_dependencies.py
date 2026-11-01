"""FastAPI session dependencies in app.middleware.session against test doubles."""

import asyncio
import http.cookies
import inspect
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from fastapi import HTTPException, Request, Response
from psycopg import InterfaceError, OperationalError, ProgrammingError
from psycopg_pool import PoolTimeout
from starlette import status

from app.exceptions import UserFacingForbidden
from app.middleware.cookies import SESSION_SIGNER
from app.middleware.session import (
    SessionResolutionMiddleware,
    require_admin,
    require_full_session,
    require_local_auth,
    require_public_or_full_session,
    require_totp_enrollment_session,
    set_session_cookie,
)
from app.services import (
    admin_promotion,
    email_change,
    password_reset,
    session_revocation,
    sessions,
    totp,
    totp_recover,
    users,
)
from app.services.sessions import SessionLookup
from app.services.sessions import get_session_user as _real_get_session_user
from config import settings


def _user(
    *,
    auth_method: str = "local",
    email_verified: bool = True,
    totp_configured: bool = True,
    is_active: bool = True,
    is_admin: bool = False,
    federated_status: str | None = None,
    totp_recovery_required: bool = False,
    # require_admin (app/middleware/session.py) 403s a local administrator
    # whose active recovery-code generation is absent or empty. Default a
    # sample administrator to the healthy state so tests exercising the
    # accepted admin path aren't tripped by the recovery-code guard.
    totp_recovery_code_generation: int = 1,
    totp_recovery_codes_available: bool = True,
) -> SimpleNamespace:
    """Build session user state; unspecified federated status defaults to approved for Shibboleth."""
    if auth_method == "shibboleth" and federated_status is None:
        federated_status = "approved"
    return SimpleNamespace(
        id=1,
        auth_method=auth_method,
        email_verified=email_verified,
        totp_configured=totp_configured,
        is_active=is_active,
        is_admin=is_admin,
        federated_status=federated_status,
        totp_recovery_required=totp_recovery_required,
        totp_recovery_code_generation=totp_recovery_code_generation,
        totp_recovery_codes_available=totp_recovery_codes_available,
    )


def _request(
    *,
    user: SimpleNamespace | None,
    purpose: str | None,
    path: str = "/account",
    query: bytes = b"",
) -> Request:
    """Build a request with resolved user, session purpose, and a conditional resolved session ID."""
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query,
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("archive.example.org", 443),
        }
    )
    request.state.user = user
    request.state.session_purpose = purpose
    request.state.session_id = "resolved-session" if user is not None else None
    return request


def _assert_http_exception(
    dependency,
    request: Request,
    status_code: int,
    location: str | None = None,
) -> None:
    """Require the dependency to raise the selected HTTP status and optional redirect location."""
    with pytest.raises(HTTPException) as caught:
        dependency(request)
    assert caught.value.status_code == status_code
    if location is not None:
        assert caught.value.headers == {"Location": location}


class TestFullSessionDependency:
    """require_full_session admits only a completed session for the caller's account."""

    def test_full_session_accepts_only_completed_local_or_approved_federated_state(self):
        """Check full session accepts only completed local or approved federated state."""
        require_full_session(_request(user=_user(), purpose="full"))
        require_full_session(
            _request(
                user=_user(
                    auth_method="shibboleth",
                    email_verified=False,
                    totp_configured=False,
                ),
                purpose="full",
            )
        )

    def test_full_session_routes_each_recoverable_local_state_without_a_loop(self):
        """Check full session routes each recoverable local state without a loop."""
        _assert_http_exception(
            require_full_session,
            _request(user=_user(totp_configured=False), purpose="totp_setup"),
            status.HTTP_303_SEE_OTHER,
            "/setup-totp",
        )
        _assert_http_exception(
            require_full_session,
            _request(user=_user(email_verified=False), purpose="full"),
            status.HTTP_303_SEE_OTHER,
            "/send_verification",
        )
        _assert_http_exception(
            require_full_session,
            _request(user=_user(totp_configured=False), purpose="full"),
            status.HTTP_303_SEE_OTHER,
            "/setup-totp",
        )

    def test_full_session_redirects_guest_to_login_with_original_target(self):
        """Check full session redirects guest to login with original target."""
        _assert_http_exception(
            require_full_session,
            _request(
                user=None,
                purpose=None,
                path="/account",
                query=b"tab=security",
            ),
            status.HTTP_303_SEE_OTHER,
            "/login?next=%2Faccount%3Ftab%3Dsecurity",
        )

    @pytest.mark.parametrize(
        ("user", "purpose"),
        [
            (_user(is_active=False), "full"),
            (_user(), None),
            (_user(), "unexpected"),
            (_user(auth_method="unexpected"), "full"),
            (_user(auth_method="shibboleth", federated_status="pending"), "full"),
            (_user(auth_method="shibboleth"), "totp_setup"),
        ],
        ids=(
            "inactive",
            "missing-purpose",
            "unknown-purpose",
            "unknown-auth-method",
            "unapproved-federation",
            "federated-setup-purpose",
        ),
    )
    def test_full_session_fails_closed_for_impossible_or_ineligible_state(self, user, purpose):
        """Check full session fails closed for impossible or ineligible state."""
        _assert_http_exception(
            require_full_session,
            _request(user=user, purpose=purpose),
            status.HTTP_403_FORBIDDEN,
        )


class TestPublicOrFullSessionDependency:
    """require_public_or_full_session admits guests but never a partial session's authority."""

    def test_public_route_accepts_guest_and_full_session_but_not_partial_session(self):
        """Check public route accepts guest and full session but not partial session."""
        require_public_or_full_session(_request(user=None, purpose=None, path="/search"))
        require_public_or_full_session(_request(user=_user(), purpose="full", path="/search"))

        _assert_http_exception(
            require_public_or_full_session,
            _request(
                user=_user(totp_configured=False),
                purpose="totp_setup",
                path="/search",
            ),
            status.HTTP_303_SEE_OTHER,
            "/setup-totp",
        )


class TestTotpEnrollmentSessionDependency:
    """require_totp_enrollment_session admits only a state-matched local session."""

    @pytest.mark.parametrize("email_verified", [False, True])
    def test_totp_enrollment_accepts_active_local_setup_session(self, email_verified):
        """Check TOTP enrollment accepts active local setup session."""
        require_totp_enrollment_session(
            _request(
                user=_user(
                    email_verified=email_verified,
                    totp_configured=False,
                ),
                purpose="totp_setup",
                path="/setup-totp",
            )
        )

    def test_totp_enrollment_accepts_full_local_session_for_recovery_and_races(self):
        """Check TOTP enrollment accepts full local session for recovery and races."""
        require_totp_enrollment_session(
            _request(
                user=_user(totp_configured=False),
                purpose="full",
                path="/setup-totp",
            )
        )
        require_totp_enrollment_session(_request(user=_user(), purpose="full", path="/setup-totp"))

    @pytest.mark.parametrize(
        ("user", "purpose", "expected_status"),
        [
            (None, None, status.HTTP_303_SEE_OTHER),
            (
                _user(is_active=False, totp_configured=False),
                "totp_setup",
                status.HTTP_403_FORBIDDEN,
            ),
            (
                _user(auth_method="shibboleth", totp_configured=False),
                "full",
                status.HTTP_403_FORBIDDEN,
            ),
            (_user(totp_configured=False), None, status.HTTP_403_FORBIDDEN),
            (_user(totp_configured=False), "unexpected", status.HTTP_403_FORBIDDEN),
        ],
        ids=("guest", "inactive", "federated", "missing-purpose", "unknown-purpose"),
    )
    def test_totp_enrollment_rejects_every_other_principal(self, user, purpose, expected_status):
        """Check TOTP enrollment rejects every other principal."""
        _assert_http_exception(
            require_totp_enrollment_session,
            _request(user=user, purpose=purpose, path="/setup-totp"),
            expected_status,
        )


class TestAdminDependency:
    """require_admin cloaks the admin surface and still requires a full session."""

    def test_admin_dependency_preserves_cloak_and_requires_full_session(self):
        """Check admin dependency preserves cloak and requires full session."""
        _assert_http_exception(
            require_admin,
            _request(user=None, purpose=None, path="/admin"),
            status.HTTP_404_NOT_FOUND,
        )
        _assert_http_exception(
            require_admin,
            _request(user=_user(is_admin=False), purpose="full", path="/admin"),
            status.HTTP_404_NOT_FOUND,
        )
        _assert_http_exception(
            require_admin,
            _request(
                user=_user(is_admin=True, totp_configured=False),
                purpose="totp_setup",
                path="/admin",
            ),
            status.HTTP_303_SEE_OTHER,
            "/setup-totp",
        )
        require_admin(_request(user=_user(is_admin=True), purpose="full", path="/admin"))


class TestLocalAuthDependency:
    """require_local_auth restricts local-account-only actions to local sessions."""

    def test_local_auth_dependency_cannot_be_used_without_a_full_local_session(self):
        """Check local auth dependency cannot be used without a full local session
        (UserFacingForbidden).
        """
        _assert_http_exception(
            require_local_auth,
            _request(
                user=_user(totp_configured=False),
                purpose="totp_setup",
                path="/account/change-email",
            ),
            status.HTTP_303_SEE_OTHER,
            "/setup-totp",
        )

        with pytest.raises(UserFacingForbidden) as federated:
            require_local_auth(
                _request(
                    user=_user(auth_method="shibboleth"),
                    purpose="full",
                    path="/account/change-email",
                )
            )
        assert federated.value.status_code == status.HTTP_403_FORBIDDEN

        require_local_auth(_request(user=_user(), purpose="full", path="/account/change-email"))


class TestRevocationLockOrder:
    """Paired session/challenge revocation callers keep dependency-visible state in order."""

    @pytest.mark.parametrize(
        "mutation",
        [
            email_change.confirm_email_change,
            password_reset.update_password_with_token,
            admin_promotion.accept_admin_promotion,
            users.set_user_active,
            totp_recover.authorize_totp_recovery,
            totp.verify_and_enroll_totp,
            totp.confirm_totp_rotation,
            session_revocation.delete_user_sessions,
        ],
        ids=[
            "confirm_email_change",
            "update_password_with_token",
            "accept_admin_promotion",
            "set_user_active",
            "authorize_totp_recovery",
            "verify_and_enroll_totp",
            "confirm_totp_rotation",
            "delete_user_sessions",
        ],
    )
    def test_paired_revocation_deletes_sessions_before_pending_challenges(self, mutation):
        """Check paired revocation deletes sessions before pending challenges."""
        source = inspect.getsource(mutation)
        session_delete = source.index("delete_user_sessions_cur(")
        pending_invalidation = source.index("invalidate_pending_authentication_state_cur(")

        assert session_delete < pending_invalidation


class TestPostCommitSessionFeedback:
    """Cover POST commit session feedback."""

    @pytest.mark.parametrize(
        "operation",
        [sessions.set_flash_if_exists, sessions.restore_flash_if_empty],
        ids=["set_flash_if_exists", "restore_flash_if_empty"],
    )
    @pytest.mark.parametrize(
        "error",
        [OperationalError, InterfaceError, PoolTimeout],
        ids=["operational_error", "interface_error", "pool_timeout"],
    )
    async def test_database_unavailability_is_tolerated_but_invalid_category_still_raises(
        self, monkeypatch, operation, error
    ):
        """Check database unavailability is tolerated but invalid category still raises (ValueError)."""

        @asynccontextmanager
        async def unavailable(_pool):
            """Raise the selected unavailable-database exception before yielding a cursor."""
            raise error("unavailable")
            yield  # pragma: no cover

        monkeypatch.setattr(
            sessions,
            "get_db_cursor",
            create_autospec(sessions.get_db_cursor, side_effect=unavailable),
        )
        assert await operation(object(), "session", "Saved") is False
        with pytest.raises(ValueError):
            await operation(object(), "session", "Saved", "invalid")

    async def test_programming_error_is_not_swallowed_as_a_tolerated_failure(self, monkeypatch):
        """The tolerance above is scoped to connectivity failures: a SQL
        programming error is a coding bug and must still propagate."""

        @asynccontextmanager
        async def broken(_pool):
            """Raise ProgrammingError before yielding a cursor."""
            raise ProgrammingError("wrong SQL")
            yield  # pragma: no cover

        monkeypatch.setattr(
            sessions,
            "get_db_cursor",
            create_autospec(sessions.get_db_cursor, side_effect=broken),
        )
        with pytest.raises(ProgrammingError):
            await sessions.set_flash_if_exists(object(), "session", "Saved")


class TestConcurrentLoginDuringStaleResponse:
    """SessionResolutionMiddleware never lets a slow, stale-cookie response
    clobber a login that completes in the browser while that response is
    still in flight.
    """

    async def test_stale_response_preserves_a_concurrently_issued_login_cookie(self):
        """Check stale response preserves a concurrently issued login cookie."""
        entered, release = asyncio.Event(), asyncio.Event()
        app = MagicMock()
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/about",
                "headers": [
                    (
                        b"cookie",
                        f"{settings.session_cookie_name}={SESSION_SIGNER.dumps('old')}".encode(),
                    )
                ],
                "app": app,
            }
        )

        async def delayed(_request):
            """Delay an empty response until the concurrent login test releases it."""
            entered.set()
            await release.wait()
            return Response()

        with patch(
            "app.middleware.session.get_session_user",
            new=create_autospec(
                _real_get_session_user,
                return_value=SessionLookup(None, None, False),
            ),
        ):
            task = asyncio.create_task(SessionResolutionMiddleware(app).dispatch(request, delayed))
            await entered.wait()
            login = Response()
            set_session_cookie(login, "new")
            browser = http.cookies.SimpleCookie()
            for header in login.headers.getlist("set-cookie"):
                browser.load(header)
            release.set()
            stale = await task
            for header in stale.headers.getlist("set-cookie"):
                browser.load(header)
        assert SESSION_SIGNER.loads(browser[settings.session_cookie_name].value) == "new"
        assert request.state.user is None
        assert request.state.session_id is None
