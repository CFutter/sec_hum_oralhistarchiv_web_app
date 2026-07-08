"""Health check endpoints.
 
/health        — Public, minimal. Safe to expose externally.
/health/detail — Internal diagnostics. Protected by HEALTH_DETAIL_TOKEN        
                 in production, open in debug mode. Returns 404 if             
                 production and no token is configured (fail-secure).          
"""
import hmac
import logging

from fastapi import APIRouter, Response, Request
from fastapi.responses import JSONResponse
from fastapi import status

from config import settings 
from ..services import get_db_cursor
from ..middleware import limiter

logger = logging.getLogger(__name__)
router = APIRouter()


def _is_health_detail_authorized(request: Request) -> bool:                 
    """Check if the request is authorized to access /health/detail.
    
    Authorization rules:
    - Debug mode: always allowed (development convenience).
    - Production/staging with HEALTH_DETAIL_TOKEN set: requires matching
      Bearer token in Authorization header.
    - Production/staging without token configured: always denied (fail-secure).
    """
    if settings.fastapi_debug:
        return True
 
    if settings.health_detail_token is None:
        return False
 
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    
    provided_token = auth_header[7:]  # Strip "Bearer " prefix
    expected_token = settings.health_detail_token.get_secret_value()
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(provided_token, expected_token)



@router.get("/health")
@limiter.exempt
async def health_check(request: Request) -> Response:
    """Liveness — is the process up and serving? Does NOT check dependencies."""
    return JSONResponse(content={"status": "alive"})


@router.get("/health/detail")
async def health_check_detail(request: Request) -> Response:
    """Detailed health check — requires authorization in production.

    Returns internal diagnostics: database connectivity plus the sync
    status (last harvest date and, if set, the last sync error and its
    timestamp). The overall status is "healthy", "degraded" (database ok
    but a sync error is recorded or the sync check failed), or "unhealthy"
    (database unreachable). The HTTP status is 200 unless the database is
    unreachable, in which case it is 503. Protected by a Bearer token
    matching HEALTH_DETAIL_TOKEN (constant-time compare), or open in debug
    mode. On a failed authorization check it returns 404, not 403, to
    avoid revealing that the endpoint exists.
    """
    if not _is_health_detail_authorized(request):                              
        return JSONResponse(                                                   
            status_code=status.HTTP_404_NOT_FOUND,                             
            content={"detail": "Not found"},                                   
        )

    checks = {}
    pool = request.app.state.db_pool

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute("SELECT 1")
            checks["database"] = "ok"
    except Exception:
        checks["database"] = "disconnected"
        logger.warning("Health check: database connection failed", exc_info=True)

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute(
                """SELECT last_harvest_date, last_sync_error, last_sync_error_at
                FROM sync_status WHERE id = 1"""
            )
            row = await cur.fetchone()
            if row:
                checks["sync"] = f"last harvest: {row['last_harvest_date']}"
                if row["last_sync_error"]:
                    checks["sync_error"] = row["last_sync_error"]
                    checks["sync_error_at"] = str(row["last_sync_error_at"])
            else:
                checks["sync"] = "no sync history"
    except Exception:
        checks["sync"] = "error"
        logger.warning("Health check: sync_status read failed", exc_info=True)

    service_ok = checks.get("database") == "ok"
    sync_degraded = checks.get("sync") == "error" or "sync_error" in checks

    if not service_ok:
        overall = "unhealthy"
    elif sync_degraded:
        overall = "degraded"
    else:
        overall = "healthy"

    code = status.HTTP_200_OK if service_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code,
                        content={"status": overall, "checks": checks})