"""The live HTTP route table, its contract validator, and the security
headers applied to every response are fail-closed by construction."""

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from app.main import app
from app.middleware.content_type import validate_form_content_type
from app.middleware.csrf import verify_csrf
from app.middleware.security_headers import build_secure_headers
from app.middleware.session import (
    require_admin,
    require_full_session,
    require_local_auth,
    require_public_or_full_session,
    require_totp_enrollment_session,
)
from app.paths import STATIC_DIR
from app.route_security import (
    _POLICY_EXTENSION_KEY,
    RouteAccess,
    SecureAPIRouter,
    SecuredAPIRoute,
    validate_route_security_contract,
)
from config import settings

EXPECTED_ROUTE_POLICIES = {
    RouteAccess.PUBLIC: {
        ("GET", "/"),
        ("GET", "/about"),
        ("GET", "/dataset/{dataset_id}"),
        ("GET", "/dataset/{dataset_id}/resource/{proxy_index}"),
        ("GET", "/forgot-password"),
        ("POST", "/forgot-password"),
        ("GET", "/health"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/recover-totp"),
        ("POST", "/recover-totp"),
        ("GET", "/register"),
        ("POST", "/register"),
        ("GET", "/search"),
    },
    RouteAccess.OPEN_DURING_ENROLLMENT: {
        ("POST", "/logout"),
        ("GET", "/send_verification"),
        ("POST", "/send_verification"),
    },
    RouteAccess.CAPABILITY: {
        ("GET", "/account/confirm-email/{public_id}"),
        ("POST", "/account/confirm-email"),
        ("GET", "/auth/shibboleth/callback"),
        ("GET", "/health/detail"),
        ("GET", "/reset-password/{public_id}"),
        ("POST", "/reset-password"),
        ("POST", "/unlock-account"),
        ("GET", "/verify-email/{public_id}"),
        ("POST", "/verify-email"),
    },
    RouteAccess.TOTP_ENROLLMENT: {
        ("GET", "/setup-totp"),
        ("POST", "/setup-totp"),
    },
    RouteAccess.FULL_SESSION: {
        ("GET", "/account"),
        ("GET", "/account/reset-totp"),
        ("POST", "/account/reset-totp"),
        ("POST", "/account/reset-totp/confirm"),
    },
    RouteAccess.LOCAL_FULL_SESSION: {
        ("GET", "/account/delete"),
        ("POST", "/account/delete"),
        ("POST", "/account/change-name"),
        ("GET", "/account/change-email"),
        ("POST", "/account/change-email"),
        ("GET", "/account/change-password"),
        ("POST", "/account/change-password"),
        ("GET", "/account/admin-promotion"),
        ("POST", "/account/admin-promotion/prepare"),
        ("POST", "/account/admin-promotion/accept"),
        ("POST", "/account/admin-promotion/decline"),
    },
    RouteAccess.ADMIN: {
        ("GET", "/admin/users/{user_id}/delete"),
        ("POST", "/admin/users/{user_id}/delete"),
        ("GET", "/admin"),
        ("GET", "/admin/datasets"),
        ("GET", "/admin/datasets/{dataset_id}"),
        ("POST", "/admin/datasets/{dataset_id}/state"),
        ("POST", "/admin/users/{user_id}/approve-federated"),
        ("POST", "/admin/users/{user_id}/change-email"),
        ("POST", "/admin/users/{user_id}/set-active"),
        ("POST", "/admin/users/{user_id}/set-admin"),
        ("POST", "/admin/users/{user_id}/set-tier"),
        ("GET", "/admin/users/{user_id}/totp-recovery"),
        ("POST", "/admin/users/{user_id}/totp-recovery"),
        ("POST", "/admin/users/{user_id}/cancel-admin-promotion"),
    },
}

CSRF_EXEMPT_POSTS = {
    "/account/confirm-email",
}
EXPECTED_ROUTE_COUNT = 57
EXPECTED_POST_COUNT = 29


def _api_routes(target: FastAPI = app) -> list[APIRoute]:
    """Select FastAPI routes from the target application."""
    return [route for route in target.routes if isinstance(route, APIRoute)]


def _dependency_calls(route: APIRoute) -> set[Callable[..., Any]]:
    """Collect the non-null direct dependency callables of a route."""
    return {
        dependency.call
        for dependency in route.dependant.dependencies
        if dependency.call is not None
    }


def _policy(route: APIRoute) -> RouteAccess:
    """Read the RouteAccess value from the route security extension."""
    metadata = route.openapi_extra or {}
    return RouteAccess(metadata[_POLICY_EXTENSION_KEY])


def _empty_app() -> FastAPI:
    """Build a FastAPI application with all framework documentation routes disabled."""
    return FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _headers_for(is_production: bool) -> dict[str, Any]:
    """Apply the selected secure-header policy and return the resulting header mapping."""
    response = Response()
    secure = build_secure_headers(is_production)
    await secure.set_headers_async(response)  # type: ignore[arg-type]
    return dict(response.headers)


class TestRoutePolicyMatrix:
    """The live app's route table matches the reviewed access matrix exactly."""

    def test_live_route_table_has_exact_reviewed_policy_matrix(self):
        """Check live route table has exact reviewed policy matrix."""
        actual = {access: set() for access in RouteAccess}
        for route in _api_routes():
            assert isinstance(route, SecuredAPIRoute)
            access = _policy(route)
            actual[access].update((method, route.path) for method in route.methods)

        assert actual == EXPECTED_ROUTE_POLICIES
        assert sum(map(len, actual.values())) == EXPECTED_ROUTE_COUNT
        validate_route_security_contract(app)

    def test_every_mutation_has_content_type_and_csrf_unless_exact_capability_exception(self):
        """Check every mutation has content type and CSRF unless exact capability exception."""
        posts = [route for route in _api_routes() if "POST" in route.methods]
        assert len(posts) == EXPECTED_POST_COUNT

        missing_content_type = {
            route.path
            for route in posts
            if validate_form_content_type not in _dependency_calls(route)
        }
        missing_csrf = {
            route.path for route in posts if verify_csrf not in _dependency_calls(route)
        }

        assert missing_content_type == set()
        assert missing_csrf == CSRF_EXEMPT_POSTS
        assert all(
            _policy(route) is RouteAccess.CAPABILITY
            for route in posts
            if route.path in missing_csrf
        )

    def test_policy_dependencies_are_present_on_every_protected_route(self):
        """Check policy dependencies are present on every protected route."""
        expected = {
            RouteAccess.PUBLIC: require_public_or_full_session,
            RouteAccess.TOTP_ENROLLMENT: require_totp_enrollment_session,
            RouteAccess.FULL_SESSION: require_full_session,
            RouteAccess.LOCAL_FULL_SESSION: require_local_auth,
            RouteAccess.ADMIN: require_admin,
        }
        for route in _api_routes():
            dependency = expected.get(_policy(route))
            if dependency is not None:
                assert dependency in _dependency_calls(route), route.path


class TestRouteSecurityContractValidation:
    """``validate_route_security_contract`` rejects anything outside the
    centrally reviewed allowlist, on a synthetic app that never touches the
    real route table."""

    def test_plain_fastapi_route_is_rejected_even_if_metadata_is_forged(self):
        """Check plain fastapi route is rejected even if metadata is forged (TypeError)."""
        target = _empty_app()

        @target.get(
            "/forgotten-policy",
            openapi_extra={_POLICY_EXTENSION_KEY: RouteAccess.FULL_SESSION.value},
        )
        async def forgotten_policy() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        with pytest.raises(TypeError, match="is not secured"):
            validate_route_security_contract(target)

    @pytest.mark.parametrize(
        ("access", "method", "path", "expected_match"),
        [
            pytest.param(
                RouteAccess.PUBLIC,
                "GET",
                "/new-public",
                "Unreviewed public route",
                id="public_route_needs_allowlist_entry",
            ),
            pytest.param(
                RouteAccess.OPEN_DURING_ENROLLMENT,
                "GET",
                "/send_verification/export",
                "Unreviewed open_during_enrollment route",
                id="open_during_enrollment_child_route_needs_allowlist_entry",
            ),
            pytest.param(
                RouteAccess.CAPABILITY,
                "POST",
                "/new-capability",
                "Unreviewed capability route",
                id="capability_route_needs_allowlist_entry",
            ),
        ],
    )
    def test_route_outside_the_reviewed_allowlist_is_rejected(
        self, access, method, path, expected_match
    ):
        """Check route outside the reviewed allowlist is rejected (RuntimeError)."""
        target = _empty_app()
        router = SecureAPIRouter(access=access)

        @router.api_route(path, methods=[method])
        async def unreviewed_route() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match=expected_match):
            validate_route_security_contract(target)

    def test_missing_reviewed_exception_is_rejected_by_complete_validation(self):
        """Check missing reviewed exception is rejected by complete validation (RuntimeError)."""
        target = _empty_app()
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        router = SecureAPIRouter(access=RouteAccess.PUBLIC)

        @router.get("/about")
        async def about() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match="Missing reviewed public route"):
            validate_route_security_contract(target)

    def test_duplicate_method_and_path_are_rejected(self):
        """Check duplicate method and path are rejected (RuntimeError)."""
        target = _empty_app()
        first = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
        second = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @first.get("/duplicate")
        async def first_handler() -> dict[str, int]:
            """Return a marker distinguishing the first duplicate handler."""
            return {"handler": 1}

        @second.get("/duplicate")
        async def second_handler() -> dict[str, int]:
            """Return a marker distinguishing the second duplicate handler."""
            return {"handler": 2}

        target.include_router(first)
        target.include_router(second)
        with pytest.raises(RuntimeError, match="Duplicate HTTP route"):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_websocket_route_is_rejected_until_a_security_policy_exists(self):
        """Check websocket route is rejected until a security policy exists (TypeError)."""
        target = _empty_app()

        @target.websocket("/ws")
        async def websocket_endpoint() -> None:
            """Provide an inert WebSocket endpoint for route-policy validation."""
            return

        with pytest.raises(TypeError, match="WebSocket route /ws is not permitted"):
            validate_route_security_contract(target)

    def test_only_the_real_staticfiles_mount_is_accepted(self):
        """Check only the real staticfiles mount is accepted (RuntimeError)."""
        valid = _empty_app()
        valid.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        validate_route_security_contract(valid, allow_incomplete_for_test=True)

        async def arbitrary_asgi_app(scope, receive, send):
            """Serve the unreviewed plain-text response through an arbitrary ASGI application."""
            response = PlainTextResponse("unreviewed")
            await response(scope, receive, send)

        invalid = _empty_app()
        invalid.mount("/static", arbitrary_asgi_app, name="static")
        with pytest.raises(RuntimeError, match="Unreviewed mounted application: /static"):
            validate_route_security_contract(invalid)

    def test_duplicate_staticfiles_mount_is_rejected(self):
        """Check duplicate staticfiles mount is rejected (RuntimeError)."""
        target = _empty_app()
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        with pytest.raises(RuntimeError, match="Unreviewed mounted application: /static"):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_framework_route_name_cannot_be_spoofed_while_debug_is_off(self):
        """Check framework route name cannot be spoofed while debug is off (RuntimeError)."""

        async def fake_docs(_request):
            """Return an unreviewed framework-route response."""
            return PlainTextResponse("unreviewed")

        target = _empty_app()
        target.router.routes.append(
            Route("/docs", fake_docs, methods=["GET"], name="swagger_ui_html")
        )

        with (
            patch.object(settings, "fastapi_debug", False),
            pytest.raises(RuntimeError, match="Unreviewed Starlette route: /docs"),
        ):
            validate_route_security_contract(target)

    def test_exact_fastapi_debug_routes_are_accepted_only_in_debug_mode(self):
        """Check exact fastapi debug routes are accepted only in debug mode (RuntimeError)."""
        target = FastAPI()

        with patch.object(settings, "fastapi_debug", True):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

        with (
            patch.object(settings, "fastapi_debug", False),
            pytest.raises(RuntimeError, match="Unreviewed Starlette route"),
        ):
            validate_route_security_contract(target)

    def test_admin_path_cannot_be_downgraded_to_full_session_only(self):
        """Check admin path cannot be downgraded to full session only (RuntimeError)."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION, prefix="/admin")

        @router.get("/report")
        async def report() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match="does not use the admin policy"):
            validate_route_security_contract(target)


class TestMiddlewareOrder:
    """``SecureAPIRouter`` attaches mutation guards and access dependencies
    in a fixed order, and the validator can see through nested dependencies
    to confirm CSRF is still enforced."""

    def test_capability_router_skips_csrf_only_for_the_exact_email_change_action(self):
        """Check capability router skips CSRF only for the exact email change action."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.CAPABILITY)

        @router.post("/reset-password")
        async def reset_password() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        @router.post("/verify-email")
        async def verify_email() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        @router.post("/account/confirm-email")
        async def confirm_email_change() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        validate_route_security_contract(target, allow_incomplete_for_test=True)

        routes = {route.path: route for route in _api_routes(target)}
        assert verify_csrf in _dependency_calls(routes["/reset-password"])
        assert verify_csrf in _dependency_calls(routes["/verify-email"])
        assert verify_csrf not in _dependency_calls(routes["/account/confirm-email"])
        assert validate_form_content_type in _dependency_calls(routes["/verify-email"])
        assert validate_form_content_type in _dependency_calls(routes["/account/confirm-email"])

    def test_new_full_session_custom_method_gets_mutation_guards_by_default(self):
        """Check new full session custom method gets mutation guards by default."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @router.api_route("/future-sensitive-action", methods=["PROPFIND"])
        async def future_sensitive_action() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        validate_route_security_contract(target, allow_incomplete_for_test=True)

        route = _api_routes(target)[0]
        assert route.methods == {"PROPFIND"}
        assert [dependency.call for dependency in route.dependant.dependencies] == [
            validate_form_content_type,
            verify_csrf,
            require_full_session,
        ]

    def test_validator_rejects_a_missing_automatic_mutation_guard(self):
        """Check validator rejects a missing automatic mutation guard (RuntimeError)."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @router.post("/future-sensitive-action")
        async def future_sensitive_action() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        route = _api_routes(target)[0]
        route.dependant.dependencies = [
            dependency
            for dependency in route.dependant.dependencies
            if dependency.call is not verify_csrf
        ]

        with pytest.raises(RuntimeError, match="lacks CSRF validation"):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_validator_recognizes_a_nested_executed_security_dependency(self):
        """Check validator recognizes a nested executed security dependency."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        async def nested_csrf(_verified: bool = Depends(verify_csrf)) -> None:
            """Provide a dependency that executes the nested CSRF check."""
            return

        @router.post("/future-sensitive-action", dependencies=[Depends(nested_csrf)])
        async def future_sensitive_action() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        route = _api_routes(target)[0]
        route.dependant.dependencies = [
            dependency
            for dependency in route.dependant.dependencies
            if dependency.call is not verify_csrf
        ]
        validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_admin_cloak_runs_before_mutation_parsing(self):
        """Check admin cloak runs before mutation parsing."""
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.ADMIN, prefix="/admin")

        @router.post("/future-action")
        async def future_admin_action() -> dict[str, bool]:
            """Return a success marker if route validation permits this handler to run."""
            return {"ok": True}

        target.include_router(router)
        validate_route_security_contract(target, allow_incomplete_for_test=True)

        route = _api_routes(target)[0]
        assert [dependency.call for dependency in route.dependant.dependencies] == [
            require_admin,
            validate_form_content_type,
            verify_csrf,
        ]


class TestSecurityHeaders:
    """Security-header configuration values. Guards silent weakening of
    CSP/HSTS/XFO — nothing else fails when a directive is dropped, so the
    values are pinned here."""

    async def test_production_sets_hsts_with_preload(self):
        """HSTS only makes sense over TLS: production-only, 1 year,
        subdomains, preload (the deploy docs warn about the preload-list
        consequence)."""
        headers = await _headers_for(is_production=True)
        hsts = headers["strict-transport-security"]
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts
        assert "preload" in hsts

    async def test_dev_has_no_hsts(self):
        """Local plaintext-HTTP dev must not lock browsers onto https."""
        headers = await _headers_for(is_production=False)
        assert "strict-transport-security" not in headers

    async def test_csp_directives_are_strict(self):
        """CSP pins: self-only sources, no framing, no plugins, no inline script."""
        headers = await _headers_for(is_production=True)
        csp = headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert "form-action 'self'" in csp
        assert "base-uri 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp

    async def test_clickjacking_and_sniffing_headers(self):
        """Check clickjacking and sniffing headers."""
        headers = await _headers_for(is_production=True)
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "strict-origin-when-cross-origin"

    async def test_permissions_policy_disables_unused_features(self):
        """Defense-in-depth: injected content can't invoke camera/mic/etc."""
        headers = await _headers_for(is_production=True)
        policy = headers["permissions-policy"]
        for feature in ("camera", "microphone", "geolocation", "payment", "usb"):
            assert f"{feature}=()" in policy
