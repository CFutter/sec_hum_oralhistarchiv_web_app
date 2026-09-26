"""FastAPI session dependencies in app.middleware.session against test doubles.

Covers the dependencies that admit or refuse a request by session purpose,
account tier and admin state (``app.middleware.session``), the lock order
the paired session/challenge revocation callers take before this module's
dependencies can trust that a superseded session is gone, the post-commit
session feedback (flash) helpers in ``app.services.sessions`` that those
dependencies' callers rely on, and the concurrency contract
``SessionResolutionMiddleware`` keeps between a slow response and a login
that completes while that response is still in flight.
"""

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
            "server": ("archive.example.uzh.ch", 443),
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
    with pytest.raises(HTTPException) as caught:
        dependency(request)
    assert caught.value.status_code == status_code
    if location is not None:
        assert caught.value.headers == {"Location": location}


class TestFullSessionDependency:
    """require_full_session admits only a completed session for the caller's account."""

    def test_full_session_accepts_only_completed_local_or_approved_federated_state(self):
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
        _assert_http_exception(
            require_full_session,
            _request(user=user, purpose=purpose),
            status.HTTP_403_FORBIDDEN,
        )


class TestPublicOrFullSessionDependency:
    """require_public_or_full_session admits guests but never a partial session's authority."""

    def test_public_route_accepts_guest_and_full_session_but_not_partial_session(self):
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
        _assert_http_exception(
            require_totp_enrollment_session,
            _request(user=user, purpose=purpose, path="/setup-totp"),
            expected_status,
        )


class TestAdminDependency:
    """require_admin cloaks the admin surface and still requires a full session."""

    def test_admin_dependency_preserves_cloak_and_requires_full_session(self):
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
    """Paired session/challenge revocation callers keep dependency-visible state in order.

    Every caller that revokes a user's authority deletes their sessions
    before it invalidates their pending authentication challenges, so a
    concurrent request resolved by the dependencies above never observes a
    still-valid session alongside a cleared challenge.
    """

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
        source = inspect.getsource(mutation)
        session_delete = source.index("delete_user_sessions_cur(")
        pending_invalidation = source.index("invalidate_pending_authentication_state_cur(")

        assert session_delete < pending_invalidation


class TestPostCommitSessionFeedback:
    """set_flash_if_exists / restore_flash_if_empty tolerate a database that
    is unavailable, or a session already gone, without turning an already-
    committed mutation into a failed response.

    Both dependencies write feedback strictly after the triggering mutation
    has committed, so a session revoked or a database made unavailable in
    that window must never surface as a 500 to the caller — but an invalid
    `category` is a coding bug, not a race, and must still raise.
    """

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
        @asynccontextmanager
        async def unavailable(_pool):
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
