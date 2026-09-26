"""Declare and validate route authorization, mutation checks and reviewed allowlists."""

from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI
from fastapi.params import Depends as DependsParam
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.staticfiles import StaticFiles
from starlette.routing import Mount, Route, WebSocketRoute

from config import settings

from .middleware.content_type import validate_form_content_type
from .middleware.csrf import verify_csrf
from .middleware.session import (
    require_admin,
    require_full_session,
    require_local_auth,
    require_public_or_full_session,
    require_totp_enrollment_session,
)
from .paths import STATIC_DIR

_POLICY_EXTENSION_KEY = "x-oralhistarchiv-access"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FRAMEWORK_ROUTE_SIGNATURES = frozenset(
    {
        (
            "/openapi.json",
            "openapi",
            frozenset({"GET", "HEAD"}),
            "fastapi.applications",
            "FastAPI.setup.<locals>.openapi",
        ),
        (
            "/docs",
            "swagger_ui_html",
            frozenset({"GET", "HEAD"}),
            "fastapi.applications",
            "FastAPI.setup.<locals>.swagger_ui_html",
        ),
        (
            "/docs/oauth2-redirect",
            "swagger_ui_redirect",
            frozenset({"GET", "HEAD"}),
            "fastapi.applications",
            "FastAPI.setup.<locals>.swagger_ui_redirect",
        ),
        (
            "/redoc",
            "redoc_html",
            frozenset({"GET", "HEAD"}),
            "fastapi.applications",
            "FastAPI.setup.<locals>.redoc_html",
        ),
    }
)
_CSRF_EXEMPT_ROUTE_KEYS = frozenset(
    {
        ("POST", "/account/confirm-email"),
        ("POST", "/verify-email"),
    }
)


class RouteAccess(StrEnum):
    """The complete set of HTTP authorization boundaries."""

    PUBLIC = "public"
    OPEN_DURING_ENROLLMENT = "open_during_enrollment"
    CAPABILITY = "capability"
    TOTP_ENROLLMENT = "totp_enrollment"
    FULL_SESSION = "full_session"
    LOCAL_FULL_SESSION = "local_full_session"
    ADMIN = "admin"


_PUBLIC_ALLOWLIST = frozenset(
    {
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
    }
)

_OPEN_DURING_ENROLLMENT_ALLOWLIST = frozenset(
    {
        ("POST", "/logout"),
        ("GET", "/send_verification"),
        ("POST", "/send_verification"),
    }
)

_CAPABILITY_ALLOWLIST = frozenset(
    {
        ("GET", "/account/confirm-email/{token}"),
        ("POST", "/account/confirm-email"),
        ("GET", "/auth/shibboleth/callback"),
        ("GET", "/health/detail"),
        ("GET", "/reset-password/{token}"),
        ("POST", "/reset-password"),
        ("GET", "/verify-email/{token}"),
        ("POST", "/verify-email"),
    }
)

_TOTP_ENROLLMENT_ALLOWLIST = frozenset(
    {
        ("GET", "/setup-totp"),
        ("POST", "/setup-totp"),
    }
)

_ALLOWLISTS = {
    RouteAccess.PUBLIC: _PUBLIC_ALLOWLIST,
    RouteAccess.OPEN_DURING_ENROLLMENT: _OPEN_DURING_ENROLLMENT_ALLOWLIST,
    RouteAccess.CAPABILITY: _CAPABILITY_ALLOWLIST,
    RouteAccess.TOTP_ENROLLMENT: _TOTP_ENROLLMENT_ALLOWLIST,
}


class SecuredAPIRoute(APIRoute):
    """Marker type retained when FastAPI includes a secured router."""


def _access_dependencies(access: RouteAccess) -> tuple[DependsParam, ...]:
    """Return guards for access, or none for enrollment-open and capability policies."""
    if access is RouteAccess.PUBLIC:
        return (Depends(require_public_or_full_session),)
    if access is RouteAccess.TOTP_ENROLLMENT:
        return (Depends(require_totp_enrollment_session),)
    if access is RouteAccess.FULL_SESSION:
        return (Depends(require_full_session),)
    if access is RouteAccess.LOCAL_FULL_SESSION:
        return (Depends(require_local_auth),)
    if access is RouteAccess.ADMIN:
        return (Depends(require_admin),)
    return ()


def _is_mutation(method: str) -> bool:
    """Return whether the case-insensitive method is outside GET, HEAD and OPTIONS."""
    return method.upper() not in _SAFE_METHODS


class SecureAPIRouter(APIRouter):
    """Add one access policy and automatic mutation dependencies to a router.

    Treat access as immutable: it is a writable attribute, but dependencies are
    captured at construction. Do not change it after creating the router.
    """

    def __init__(self, *, access: RouteAccess, **kwargs: Any) -> None:
        """Capture access dependencies and require the secured route class.

        Raises TypeError for nonempty dependencies or any route_class argument; other
        kwargs pass to APIRouter. Keep access unchanged after construction.
        """
        if kwargs.get("dependencies"):
            raise TypeError("SecureAPIRouter owns its access dependencies")
        if "route_class" in kwargs:
            raise TypeError("SecureAPIRouter owns its route class")
        self.access = access
        self._route_access_dependencies = _access_dependencies(access)
        super().__init__(route_class=SecuredAPIRoute, **kwargs)

    def add_api_route(
        self,
        path: str,
        endpoint: Callable[..., Any],
        *,
        methods: set[str] | list[str] | None = None,
        dependencies: Sequence[DependsParam] | None = None,
        openapi_extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Register a route with policy metadata, access guards and mutation validation.

        Missing/empty methods means GET. Non-GET/HEAD/OPTIONS methods require form
        content type and CSRF except the two exact reviewed capability POSTs. Admin
        guards run first; extra dependencies follow automatic guards. Raises
        RuntimeError if openapi_extra supplies the owned policy key; FastAPI errors propagate.
        """
        normalized_methods = {method.upper() for method in (methods or {"GET"})}
        full_path = f"{self.prefix}{path}"
        mutation_keys = {
            (method, full_path) for method in normalized_methods if _is_mutation(method)
        }

        mutation_dependencies: tuple[DependsParam, ...] = ()
        if mutation_keys:
            mutation_dependencies = (Depends(validate_form_content_type),)
            if not mutation_keys <= _CSRF_EXEMPT_ROUTE_KEYS:
                mutation_dependencies += (Depends(verify_csrf),)

        metadata = dict(openapi_extra or {})
        if _POLICY_EXTENSION_KEY in metadata:
            raise RuntimeError(f"{_POLICY_EXTENSION_KEY} is owned by SecureAPIRouter")
        metadata[_POLICY_EXTENSION_KEY] = self.access.value

        access_dependencies = self._route_access_dependencies
        if self.access is RouteAccess.ADMIN:
            automatic = (*access_dependencies, *mutation_dependencies)
        else:
            automatic = (*mutation_dependencies, *access_dependencies)

        super().add_api_route(
            path,
            endpoint,
            methods=list(normalized_methods),
            dependencies=[*automatic, *(dependencies or ())],
            openapi_extra=metadata,
            **kwargs,
        )


def _dependency_calls(route: APIRoute) -> set[Callable[..., Any]]:
    """Collect every callable in the route's recursive dependency graph."""
    calls: set[Callable[..., Any]] = set()
    pending = list(route.dependant.dependencies)
    while pending:
        dependency = pending.pop()
        if dependency.call is not None:
            calls.add(dependency.call)
        pending.extend(dependency.dependencies)
    return calls


def _validate_api_route(route: APIRoute) -> tuple[RouteAccess, set[tuple[str, str]]]:
    """Return (access, method/path keys) after checking policy, allowlists and guards.

    Raises TypeError for an unsecured route or missing/nonstring policy; raises
    RuntimeError for invalid policy, unreviewed exposure, or missing access/form/CSRF guards.
    """
    if not isinstance(route, SecuredAPIRoute):
        raise TypeError(f"Route {sorted(route.methods)} {route.path} is not secured")

    metadata = route.openapi_extra or {}
    raw_access = metadata.get(_POLICY_EXTENSION_KEY)
    if not isinstance(raw_access, str):
        raise TypeError(f"Route {sorted(route.methods)} {route.path} has no access policy")
    try:
        access = RouteAccess(raw_access)
    except ValueError as exc:
        raise RuntimeError(
            f"Route {sorted(route.methods)} {route.path} has no valid access policy"
        ) from exc

    if (
        route.path == "/admin" or route.path.startswith("/admin/")
    ) and access is not RouteAccess.ADMIN:
        raise RuntimeError(f"Admin path {route.path} does not use the admin policy")

    route_keys = {(method.upper(), route.path) for method in route.methods}
    allowlist = _ALLOWLISTS.get(access)
    if allowlist is not None and not route_keys <= allowlist:
        unexpected = sorted(route_keys - allowlist)
        raise RuntimeError(f"Unreviewed {access.value} route(s): {unexpected}")

    calls = _dependency_calls(route)
    expected_access_dependency = {
        RouteAccess.PUBLIC: require_public_or_full_session,
        RouteAccess.TOTP_ENROLLMENT: require_totp_enrollment_session,
        RouteAccess.FULL_SESSION: require_full_session,
        RouteAccess.LOCAL_FULL_SESSION: require_local_auth,
        RouteAccess.ADMIN: require_admin,
    }.get(access)
    if expected_access_dependency is not None and expected_access_dependency not in calls:
        raise RuntimeError(f"Route {route.path} lacks its {access.value} dependency")

    mutation_keys = {key for key in route_keys if _is_mutation(key[0])}
    if not mutation_keys:
        return access, route_keys
    if validate_form_content_type not in calls:
        raise RuntimeError(f"Mutation route {route.path} lacks content-type validation")

    csrf_exempt = mutation_keys <= _CSRF_EXEMPT_ROUTE_KEYS
    if csrf_exempt and access is not RouteAccess.CAPABILITY:
        raise RuntimeError(f"CSRF exception {route.path} is not a capability route")
    if not csrf_exempt and verify_csrf not in calls:
        raise RuntimeError(f"Mutation route {route.path} lacks CSRF validation")
    return access, route_keys


def _framework_route_signature(
    route: Route,
) -> tuple[str, str, frozenset[str], str, str]:
    """Return path, name, methods and endpoint identity for framework-route comparison."""
    endpoint = route.endpoint
    return (
        route.path,
        route.name,
        frozenset(route.methods or ()),
        getattr(endpoint, "__module__", ""),
        getattr(endpoint, "__qualname__", ""),
    )


def validate_route_security_contract(
    app: FastAPI,
    *,
    allow_incomplete_for_test: bool = False,
) -> None:
    """Validate routes, reviewed mounts, unique method/path pairs and required surfaces.

    Raises TypeError for unsupported/unsecured route objects and RuntimeError for
    policy violations. Framework docs require FASTAPI_DEBUG. allow_incomplete_for_test
    skips only final missing-route/mount checks; it does not permit unsafe routes.
    """
    observed_allowlisted: dict[RouteAccess, set[tuple[str, str]]] = {
        access: set() for access in _ALLOWLISTS
    }
    seen_route_keys: set[tuple[str, str]] = set()
    static_mount_seen = False

    for route in app.routes:
        if isinstance(route, (APIWebSocketRoute, WebSocketRoute)):
            raise TypeError(f"WebSocket route {route.path} is not permitted")
        if isinstance(route, Mount):
            valid_static_mount = (
                route.path == "/static"
                and route.name == "static"
                and isinstance(route.app, StaticFiles)
                and route.app.directory is not None
                and STATIC_DIR.resolve() == Path(route.app.directory).resolve()
            )
            if not valid_static_mount or static_mount_seen:
                raise RuntimeError(f"Unreviewed mounted application: {route.path}")
            static_mount_seen = True
            continue
        if isinstance(route, Route) and not isinstance(route, APIRoute):
            signature = _framework_route_signature(route)
            if not settings.fastapi_debug or signature not in _FRAMEWORK_ROUTE_SIGNATURES:
                raise RuntimeError(f"Unreviewed Starlette route: {route.path}")
            route_keys = {(method, route.path) for method in route.methods or ()}
            duplicates = route_keys & seen_route_keys
            if duplicates:
                raise RuntimeError(f"Duplicate HTTP route(s): {sorted(duplicates)}")
            seen_route_keys.update(route_keys)
            continue
        if not isinstance(route, APIRoute):
            raise TypeError(f"Unreviewed route object: {route!r}")
        access, route_keys = _validate_api_route(route)
        duplicates = route_keys & seen_route_keys
        if duplicates:
            raise RuntimeError(f"Duplicate HTTP route(s): {sorted(duplicates)}")
        seen_route_keys.update(route_keys)
        if access in observed_allowlisted:
            observed_allowlisted[access].update(route_keys)

    if allow_incomplete_for_test:
        return
    if not static_mount_seen:
        raise RuntimeError("Required StaticFiles mount /static is missing")
    for access, expected in _ALLOWLISTS.items():
        missing = expected - observed_allowlisted[access]
        if missing:
            raise RuntimeError(f"Missing reviewed {access.value} route(s): {sorted(missing)}")
