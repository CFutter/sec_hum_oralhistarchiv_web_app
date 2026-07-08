"""Digital Oral History Archive — FastAPI application setup."""
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException
import logging
from collections.abc import Callable

from config import settings, setup_logging, warn_unconsumed_env_keys
from .services import (
    FacetCache,
    create_pool,
    get_db_cursor,
    seed_admin_user,
    validate_dataset_schema,
    validate_dataset_insert_schema,
    validate_user_schema,
    validate_schema_against_db,
    assert_redaction_total,
    verify_smtp_tls
    )

from .template_setup import templates

from .middleware import (
    build_secure_headers, 
    setup_rate_limiting, 
    validate_security_settings,
    setup_audit_logging,
    setup_session_middleware,
    setup_totp_gate_middleware,
    setup_csrf_middleware,
    get_client_ip
    )
from .routes import pages_router, health_router, auth_router
from .paths import STATIC_DIR, ALEMBIC_INI, ALEMBIC_DIR


# =============================================================================
# Startup
# =============================================================================

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle.

    Startup, in order: configures logging; warns about unconsumed .env keys
    (dev only); validates security settings and the SMTP TLS setup; opens
    the database connection pool and creates the facet cache; runs Alembic
    migrations to head in dev, while in staging/production it only verifies
    that the database is already at the expected head (migrations run out
    of band, e.g. via the systemd ExecStartPre) and refuses to start on a
    mismatch; validates the dataset/user schema invariants, the
    redaction-field classification, and the live database columns (drift
    check); seeds mock restricted datasets when FASTAPI_DEBUG is true; and
    seeds the admin account if ADMIN_SEED_EMAIL / ADMIN_SEED_PASSWORD are
    set and no admin exists yet.

    The background scheduler is NOT started here — it runs as a separate
    process (run_scheduler.py in the project root).

    Shutdown: stops the facet cache's Redis subscriber thread and closes
    the connection pool.
    """
    setup_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
    )
    if settings.env_state == "dev":
        logger.info("Checking unconsumed .env keys (dev mode)...")
        warn_unconsumed_env_keys()

    validate_security_settings()
    verify_smtp_tls()
    pool = create_pool()
    await pool.open()
    app.state.db_pool = pool
    try:
        app.state.facet_cache = FacetCache(pool)
        alembic_cfg = Config(str(ALEMBIC_INI))
        alembic_cfg.set_main_option("script_location", str(ALEMBIC_DIR))

        if settings.env_state == "dev":
            alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url.get_secret_value())
            command.upgrade(alembic_cfg, "head")
        else:
            expected_head = ScriptDirectory.from_config(alembic_cfg).get_current_head()
            async with get_db_cursor(pool) as cur:
                await cur.execute("SELECT version_num FROM alembic_version")
                row = await cur.fetchone()
            if not row:
                raise RuntimeError("Database has no alembic_version. Run `alembic upgrade head` first.")
            if row["version_num"] != expected_head:
                raise RuntimeError(
                    f"Schema at {row['version_num']!r} but code expects head {expected_head!r}. "
                    "Run `alembic upgrade head` (ExecStartPre) before starting the app."
                )

        validate_dataset_schema()
        validate_dataset_insert_schema()
        validate_user_schema()
        assert_redaction_total()
        await validate_schema_against_db(pool)

        # Seed mock restricted datasets in debug mode for testing tiered access
        # Will be deleted in production
        if settings.fastapi_debug:
            from .services.seed_mock_data import seed_mock_data
            await seed_mock_data(pool)

        if settings.admin_seed_email and settings.admin_seed_password:
            await seed_admin_user(pool, settings.admin_seed_email, settings.admin_seed_password.get_secret_value())

        logger.info("Database ready!")
    except BaseException:
        fc = getattr(app.state, "facet_cache", None)
        if fc is not None:
            fc.stop()
        await pool.close()
        raise

    yield
    logger.info("App is shutting down...")
    app.state.facet_cache.stop()
    await pool.close()
    logger.info("App shutdown complete!")


app = FastAPI(
    title="Oral History Archive",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.fastapi_debug else None,
    redoc_url="/redoc" if settings.fastapi_debug else None,
    openapi_url="/openapi.json" if settings.fastapi_debug else None,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# =============================================================================
# Middleware Configuration
# =============================================================================

# CORS Configuration
if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

# CSRF Protection — double-submit cookie pattern.
# Sets a CSRF token cookie on GET responses. POST routes verify the token
# via the verify_csrf dependency (see routes/auth.py).
setup_csrf_middleware(app)

# Gate runs INSIDE secure-headers + audit so its redirects get headers + an
# audit line. Reads request.state set by the (outer) resolution middleware.
setup_totp_gate_middleware(app)


# Security Headers
secure_headers = build_secure_headers(settings.is_production)

@app.middleware("http")
async def set_secure_headers(request: Request, call_next: Callable) -> Response:
    """Apply security headers to every response.

    Adds Cache-Control: no-store for authenticated pages to prevent
    browser caching of restricted metadata. Static assets are excluded.
    """
    response = await call_next(request)
    await secure_headers.set_headers_async(response)

    # Prevent browser caching of authenticated content (admin pages,
    # restricted dataset details, account info). Static assets are
    # excluded so fonts/CSS/images still cache normally.
    if (
        getattr(request.state, "user", None)
        and not request.url.path.startswith("/static/")
    ):
        response.headers["Cache-Control"] = "no-store"

    return response


# Rate limiting — outside CSRF / secure headers / CORS / routes so
# rejected requests short-circuit most of the stack. Deliberately NOT
# outermost: session + audit run first so rate-limited requests are
# still captured in the audit log.
setup_rate_limiting(app)

# Audit logging — just inside session so it can log user_id, and outside
# rate limiting so 429 responses still get audited via the post-call_next
# path.
setup_audit_logging(app) 

# Session — every downstream middleware (including audit)
# can read request.state.user. Session middleware does not raise on
# missing/invalid sessions, so audit still captures those requests.
setup_session_middleware(app)


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

app.include_router(pages_router)
app.include_router(health_router)
app.include_router(auth_router)

# =============================================================================
# Exception handlers
# =============================================================================

@app.exception_handler(303)
async def redirect_handler(request: Request, exc: HTTPException) -> Response:
    """Convert 303 exceptions into redirect responses."""
    return RedirectResponse(url=(exc.headers or {}).get("Location", "/"), status_code=303)

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException) -> Response:
    """Render a 404 error page for unmatched routes."""
    return templates.TemplateResponse(request, "error.html", {
        "error_title": "Page not found",
        "error_message": "The page you're looking for doesn't exist or has been moved.",
    }, status_code=404)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
    """Render a 422 error page for malformed request parameters."""
    logger.warning("Validation error on %s", request.url.path, extra={
        "request_id": getattr(request.state, "request_id", "unknown"),
        "path": request.url.path,
        "detail": str(exc.errors())
    })
    return templates.TemplateResponse(
        request, 
        "error.html", {
            "error_title": "Invalid request",
            "error_message": "The request contained invalid parameters.",
        }, status_code=422)

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Render the generic error page for rate-limited requests.
    
    MUST stay `def` (sync): slowapi's SlowAPIMiddleware ignores coroutine
    handlers for default-limit breaches and falls back to its own JSON
    handler (see slowapi.middleware.sync_check_limits)."""
    logger.warning("Rate limit exceeded on %s", request.url.path, extra={
        "request_id": getattr(request.state, "request_id", "unknown"),
        "client_ip": get_client_ip(request),
        "path": request.url.path,
    })
    response = templates.TemplateResponse(
        request, "error.html", {
            "error_title": "Too many requests",
            "error_message": "You have made too many requests. Please wait a moment before trying again.",
        }, status_code=429,
    )
    if exc.limit is not None:
        response.headers["Retry-After"] = str(exc.limit.limit.get_expiry())
    return response

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    """Log and render a 500 error page for uncaught exceptions."""
    logger.error("Unhandled exception: %s", exc, exc_info=True, extra={
        "request_id": getattr(request.state, "request_id", "unknown"),
        "path": request.url.path,
    })
    response = templates.TemplateResponse(request, "error.html", {
        "error_title": "Internal Server Error",
        "error_message": "An unexpected error occurred. Please try again later.",
    }, status_code=500)

    await secure_headers.set_headers_async(response)  # type: ignore[arg-type]  # secure's HeadersProtocol expects a settable headers attr; Starlette's MutableHeaders is read-only-attr but mutable-contents — works at runtime
    response.headers["Cache-Control"] = "no-store"
    rid = getattr(request.state, "request_id", None)
    if rid:
        response.headers["X-Request-ID"] = rid
    return response    