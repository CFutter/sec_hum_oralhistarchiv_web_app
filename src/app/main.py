"""Construct the FastAPI app, route policy, middleware and exception handlers.

Importing loads settings/templates and validates route declarations; lifespan
opens external resources. The scheduler runs separately via run_scheduler.py.
"""

import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from alembic.config import Config
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

from alembic import command
from config import settings, setup_logging, warn_unconsumed_env_keys

from .exceptions import UserFacingForbidden
from .middleware import (
    build_secure_headers,
    setup_audit_logging,
    setup_csrf_middleware,
    setup_database_capacity_middleware,
    setup_rate_limiting,
    setup_session_middleware,
    validate_security_settings,
)
from .middleware.rate_limiting import validate_rate_limit_backend
from .paths import ALEMBIC_DIR, ALEMBIC_INI, STATIC_DIR
from .request_utils import get_client_ip, safe_request_path
from .route_security import validate_route_security_contract
from .routes import application_routers
from .runtime_preflight import validate_runtime_schema
from .services import (
    CatalogueStatsCache,
    create_pool,
    reconcile_federated_session_policy,
    seed_admin_user,
    warm_password_blocklist,
)
from .services.authentication import warm_dummy_password_hash
from .template_setup import templates

# =============================================================================
# Startup
# =============================================================================

logger = logging.getLogger(__name__)

_STATIC_ASSET_PREFIX = "/static/"

_SENSITIVE_ACTION_PREFIXES = (
    "/reset-password",
    "/verify-email",
    "/account/confirm-email",
)
_VALIDATION_SOURCES = frozenset({"body", "path", "query", "header", "cookie"})


def _validation_error_summary(exc: RequestValidationError) -> list[dict[str, str]]:
    """Return bounded validation metadata without submitted values or messages."""
    summary: list[dict[str, str]] = []

    for error in exc.errors()[:20]:
        location = error.get("loc", ())
        source = (
            location[0]
            if location and isinstance(location[0], str) and location[0] in _VALIDATION_SOURCES
            else "request"
        )
        summary.append(
            {
                "source": source,
                "type": str(error.get("type", "unknown"))[:80],
            }
        )

    return summary


def _is_sensitive_action_request(request: Request) -> bool:
    """Match reset-password, verify-email and account/confirm-email paths and descendants."""
    path = request.url.path
    return any(
        path == prefix or path.startswith(f"{prefix}/") for prefix in _SENSITIVE_ACTION_PREFIXES
    )


def _apply_response_privacy_headers(request: Request, response: Response) -> None:
    """Make dynamic responses non-cacheable and contain action capabilities."""
    if not request.url.path.startswith(_STATIC_ASSET_PREFIX):
        response.headers["Cache-Control"] = "no-store"

    if _is_sensitive_action_request(request):
        response.headers["Referrer-Policy"] = "no-referrer"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Prepare web resources, yield once, then stop the cache and close PostgreSQL.

    Configures logging; validates settings/routes/limiter; warms password caches;
    runs dev migrations; opens app.state.db_pool; checks schema/role contracts;
    reconciles federated sessions; sets app.state.catalogue_stats_cache; and seeds
    requested dev data/admin. Startup errors propagate; cleanup errors are logged.
    Requires the configured database and hardened limiter; SMTP preflight may connect.
    """
    setup_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
    )

    if settings.env_state == "dev":
        logger.info("Checking unconsumed .env keys (dev mode)...")
        warn_unconsumed_env_keys()

    validate_security_settings()
    validate_route_security_contract(app)
    await validate_rate_limit_backend()
    await run_in_threadpool(warm_password_blocklist)
    await warm_dummy_password_hash()

    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option(
        "script_location",
        str(ALEMBIC_DIR),
    )

    if settings.env_state == "dev":
        await run_in_threadpool(
            command.upgrade,
            alembic_cfg,
            "head",
        )

    pool = create_pool()
    catalogue_stats_cache: CatalogueStatsCache | None = None

    try:
        await pool.open()
        app.state.db_pool = pool

        await validate_runtime_schema(pool, process="web")
        await reconcile_federated_session_policy(pool)

        catalogue_stats_cache = CatalogueStatsCache(pool, subscribe=True)
        app.state.catalogue_stats_cache = catalogue_stats_cache

        if settings.seed_mock_data and settings.env_state == "dev":
            from .services.seed_mock_data import seed_mock_data  # noqa: PLC0415

            await seed_mock_data(pool)

        if settings.admin_seed_email and settings.admin_seed_password:
            await seed_admin_user(
                pool,
                settings.admin_seed_email,
                settings.admin_seed_password.get_secret_value(),
            )

        logger.info("Database ready!")
        yield
    finally:
        logger.info("App is shutting down...")

        if catalogue_stats_cache is not None:
            try:
                catalogue_stats_cache.stop()
            except Exception:
                logger.exception("Failed to stop catalogue statistics cache")

        try:
            await pool.close()
        except Exception:
            logger.exception("Failed to close database pool")

        logger.info("App shutdown complete!")


app = FastAPI(
    title="Oral History Archive",
    version="0.1.0",
    lifespan=lifespan,
    redirect_slashes=False,
    docs_url="/docs" if settings.fastapi_debug else None,
    redoc_url="/redoc" if settings.fastapi_debug else None,
    openapi_url="/openapi.json" if settings.fastapi_debug else None,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# =============================================================================
# Middleware Configuration
# =============================================================================

# CSRF protection — double-submit cookie pattern.
# Middleware sets the cookie on GET responses. SecureAPIRouter installs
# verification and Content-Type validation on every mutation method.
setup_csrf_middleware(app)


# Security Headers
secure_headers = build_secure_headers(settings.is_production)


@app.middleware("http")
async def set_secure_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Add security headers, no-store on dynamic paths and no-referrer on capability paths."""
    response = await call_next(request)
    await secure_headers.set_headers_async(response)  # type: ignore[arg-type]
    _apply_response_privacy_headers(request, response)
    return response


# Session lookup runs inside rate admission: a 429/503, and every 404/405 the
# limiter marks as unmatched, is decided before any database lookup.
setup_session_middleware(app)

# Rate admission wraps session resolution; audit wraps both so 429s are logged.
setup_rate_limiting(app)
setup_database_capacity_middleware(app)
setup_audit_logging(app)

# CORS is inside TrustedHost and outside session resolution, audit, and routing.
# Preflight OPTIONS can short-circuit safely because it carries no application
# authorization result; responses from the inner stack still receive CORS headers.
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

# TrustedHost — outermost. Rejects unknown Host headers before any
# other middleware spends cycles on the request. Coordinates with
# nginx's default-reject server block (defense-in-depth).
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)

# =============================================================================
# Routes
# =============================================================================

for application_router in application_routers:
    app.include_router(application_router)

# Validate the committed table during module construction. Lifespan repeats
# the check before external services are touched, catching late embedding code.
validate_route_security_contract(app)

# =============================================================================
# Exception handlers
# =============================================================================


@app.exception_handler(303)
async def redirect_handler(request: Request, exc: HTTPException) -> Response:
    """Convert 303 exceptions into redirect responses."""
    return RedirectResponse(url=(exc.headers or {}).get("Location", "/"), status_code=303)


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: HTTPException) -> Response:
    """Render explicit UserFacingForbidden copy or a generic 403 without exposing detail."""
    if isinstance(exc, UserFacingForbidden):
        title, msg = exc.title, exc.detail
    else:
        title = "Request could not be verified"
        msg = (
            "Your session may have changed — for example after logging out "
            "or back in from another tab. Please go back, reload the page, "
            "and try again."
        )
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": title,
            "error_message": msg,
        },
        status_code=403,
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException) -> Response:
    """Render the generic 404 page for routing and explicitly raised 404 errors."""
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "Page not found",
            "error_message": "The page you're looking for doesn't exist or has been moved.",
        },
        status_code=404,
    )


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc: HTTPException) -> Response:
    """Render a 405 page and preserve the exception's Allow header when present."""
    response = templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "That action can't be opened directly",
            "error_message": "This address only accepts form submissions, not "
            "direct navigation. Use the corresponding button "
            "or link in the application instead.",
        },
        status_code=405,
    )
    if exc.headers and "Allow" in exc.headers:
        response.headers["Allow"] = exc.headers["Allow"]
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
    """Log bounded validation metadata without submitted values and render a generic 422."""
    errors = exc.errors()
    logger.warning(
        "Request validation failed",
        extra={
            "request_id": getattr(request.state, "request_id", "unknown"),
            "path": safe_request_path(request),
            "validation_error_count": len(errors),
            "validation_errors": _validation_error_summary(exc),
        },
    )
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "Invalid request",
            "error_message": "The request contained invalid parameters.",
        },
        status_code=422,
    )


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Log and render a secured 429; add rate headers from captured request.state statistics."""
    safe_path = safe_request_path(request)
    logger.warning(
        "Rate limit exceeded",
        extra={
            "request_id": getattr(request.state, "request_id", "unknown"),
            "client_ip": get_client_ip(request),
            "path": safe_path,
        },
    )
    response = templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "Too many requests",
            "error_message": (
                "You have made too many requests. Please wait a moment before trying again."
            ),
        },
        status_code=429,
    )
    secure_headers.set_headers(response)  # type: ignore[arg-type]
    _apply_response_privacy_headers(request, response)

    # Reuse captured statistics to avoid another synchronous Redis read.
    current = getattr(request.state, "view_rate_limit", None)
    stats = getattr(request.state, "rate_limit_stats", None)
    if current is not None and stats is not None:
        limit_item, _ = current
        reset_at, remaining = stats
        response.headers["Retry-After"] = str(max(1, int(reset_at + 1 - time.time())))
        response.headers["X-RateLimit-Limit"] = str(limit_item.amount)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_at) + 1)
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    """Log the exception and render a secured generic 500, preserving the request ID."""
    logger.error(
        "Unhandled exception",
        exc_info=(type(exc), exc, exc.__traceback__),
        extra={
            "request_id": getattr(request.state, "request_id", "unknown"),
            "path": safe_request_path(request),
            "exception_type": type(exc).__name__,
        },
    )
    response = templates.TemplateResponse(
        request,
        "error.html",
        {
            "error_title": "Internal Server Error",
            "error_message": "An unexpected error occurred. Please try again later.",
        },
        status_code=500,
    )

    await secure_headers.set_headers_async(response)  # type: ignore[arg-type]

    _apply_response_privacy_headers(request, response)
    rid = getattr(request.state, "request_id", None)
    if rid:
        response.headers["X-Request-ID"] = rid
    return response
