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
        ("GET", "/account/confirm-email/{token}"),
        ("POST", "/account/confirm-email"),
        ("GET", "/auth/shibboleth/callback"),
        ("GET", "/health/detail"),
        ("GET", "/reset-password/{token}"),
        ("POST", "/reset-password"),
        ("GET", "/verify-email/{token}"),
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
        ("POST", "/account/change-name"),
        ("GET", "/account/change-email"),
        ("POST", "/account/change-email"),
        ("GET", "/account/admin-promotion"),
        ("POST", "/account/admin-promotion/prepare"),
        ("POST", "/account/admin-promotion/accept"),
        ("POST", "/account/admin-promotion/decline"),
    },
    RouteAccess.ADMIN: {
        ("GET", "/admin"),
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
    "/verify-email",
}
EXPECTED_ROUTE_COUNT = 46
EXPECTED_POST_COUNT = 24


def _api_routes(target: FastAPI = app) -> list[APIRoute]:
    return [route for route in target.routes if isinstance(route, APIRoute)]


def _dependency_calls(route: APIRoute) -> set[Callable[..., Any]]:
    return {
        dependency.call
        for dependency in route.dependant.dependencies
        if dependency.call is not None
    }


def _policy(route: APIRoute) -> RouteAccess:
    metadata = route.openapi_extra or {}
    return RouteAccess(metadata[_POLICY_EXTENSION_KEY])


def _empty_app() -> FastAPI:
    return FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _headers_for(is_production: bool) -> dict[str, Any]:
    response = Response()
    secure = build_secure_headers(is_production)
    await secure.set_headers_async(response)  # type: ignore[arg-type]
    return dict(response.headers)


class TestRoutePolicyMatrix:
    """The live app's route table matches the reviewed access matrix exactly."""

    def test_live_route_table_has_exact_reviewed_policy_matrix(self):
        actual = {access: set() for access in RouteAccess}
        for route in _api_routes():
            assert isinstance(route, SecuredAPIRoute)
            access = _policy(route)
            actual[access].update((method, route.path) for method in route.methods)

        assert actual == EXPECTED_ROUTE_POLICIES
        assert sum(map(len, actual.values())) == EXPECTED_ROUTE_COUNT
        validate_route_security_contract(app)

    def test_every_mutation_has_content_type_and_csrf_unless_exact_capability_exception(self):
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
        target = _empty_app()

        @target.get(
            "/forgotten-policy",
            openapi_extra={_POLICY_EXTENSION_KEY: RouteAccess.FULL_SESSION.value},
        )
        async def forgotten_policy() -> dict[str, bool]:
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
        target = _empty_app()
        router = SecureAPIRouter(access=access)

        @router.api_route(path, methods=[method])
        async def unreviewed_route() -> dict[str, bool]:
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match=expected_match):
            validate_route_security_contract(target)

    def test_missing_reviewed_exception_is_rejected_by_complete_validation(self):
        target = _empty_app()
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        router = SecureAPIRouter(access=RouteAccess.PUBLIC)

        @router.get("/about")
        async def about() -> dict[str, bool]:
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match="Missing reviewed public route"):
            validate_route_security_contract(target)

    def test_duplicate_method_and_path_are_rejected(self):
        target = _empty_app()
        first = SecureAPIRouter(access=RouteAccess.FULL_SESSION)
        second = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @first.get("/duplicate")
        async def first_handler() -> dict[str, int]:
            return {"handler": 1}

        @second.get("/duplicate")
        async def second_handler() -> dict[str, int]:
            return {"handler": 2}

        target.include_router(first)
        target.include_router(second)
        with pytest.raises(RuntimeError, match="Duplicate HTTP route"):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_websocket_route_is_rejected_until_a_security_policy_exists(self):
        target = _empty_app()

        @target.websocket("/ws")
        async def websocket_endpoint() -> None:
            return None

        with pytest.raises(TypeError, match="WebSocket route /ws is not permitted"):
            validate_route_security_contract(target)

    def test_only_the_real_staticfiles_mount_is_accepted(self):
        valid = _empty_app()
        valid.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        validate_route_security_contract(valid, allow_incomplete_for_test=True)

        async def arbitrary_asgi_app(scope, receive, send):
            response = PlainTextResponse("unreviewed")
            await response(scope, receive, send)

        invalid = _empty_app()
        invalid.mount("/static", arbitrary_asgi_app, name="static")
        with pytest.raises(RuntimeError, match="Unreviewed mounted application: /static"):
            validate_route_security_contract(invalid)

    def test_duplicate_staticfiles_mount_is_rejected(self):
        target = _empty_app()
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
        target.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        with pytest.raises(RuntimeError, match="Unreviewed mounted application: /static"):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

    def test_framework_route_name_cannot_be_spoofed_while_debug_is_off(self):
        async def fake_docs(_request):
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
        target = FastAPI()

        with patch.object(settings, "fastapi_debug", True):
            validate_route_security_contract(target, allow_incomplete_for_test=True)

        with (
            patch.object(settings, "fastapi_debug", False),
            pytest.raises(RuntimeError, match="Unreviewed Starlette route"),
        ):
            validate_route_security_contract(target)

    def test_admin_path_cannot_be_downgraded_to_full_session_only(self):
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION, prefix="/admin")

        @router.get("/report")
        async def report() -> dict[str, bool]:
            return {"ok": True}

        target.include_router(router)
        with pytest.raises(RuntimeError, match="does not use the admin policy"):
            validate_route_security_contract(target)


class TestMiddlewareOrder:
    """``SecureAPIRouter`` attaches mutation guards and access dependencies
    in a fixed order, and the validator can see through nested dependencies
    to confirm CSRF is still enforced."""

    def test_capability_router_skips_csrf_only_for_two_exact_action_routes(self):
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.CAPABILITY)

        @router.post("/reset-password")
        async def reset_password() -> dict[str, bool]:
            return {"ok": True}

        @router.post("/verify-email")
        async def verify_email() -> dict[str, bool]:
            return {"ok": True}

        target.include_router(router)
        validate_route_security_contract(target, allow_incomplete_for_test=True)

        routes = {route.path: route for route in _api_routes(target)}
        assert verify_csrf in _dependency_calls(routes["/reset-password"])
        assert verify_csrf not in _dependency_calls(routes["/verify-email"])
        assert validate_form_content_type in _dependency_calls(routes["/verify-email"])

    def test_new_full_session_custom_method_gets_mutation_guards_by_default(self):
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @router.api_route("/future-sensitive-action", methods=["PROPFIND"])
        async def future_sensitive_action() -> dict[str, bool]:
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
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        @router.post("/future-sensitive-action")
        async def future_sensitive_action() -> dict[str, bool]:
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
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.FULL_SESSION)

        async def nested_csrf(_verified: bool = Depends(verify_csrf)) -> None:
            return None

        @router.post("/future-sensitive-action", dependencies=[Depends(nested_csrf)])
        async def future_sensitive_action() -> dict[str, bool]:
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
        target = _empty_app()
        router = SecureAPIRouter(access=RouteAccess.ADMIN, prefix="/admin")

        @router.post("/future-action")
        async def future_admin_action() -> dict[str, bool]:
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
        """CSP pins: self-only sources, no framing, no plugins, no inline
        script.

        Each directive is explicit rather than relying on default-src
        fallback (see security_headers.py) — a dropped directive silently
        widens the policy, which is why the full set is asserted."""
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
