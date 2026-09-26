"""Expose dependency-free /health and authorized /health/detail diagnostics."""

import hmac
import logging
from datetime import UTC, datetime

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from psycopg import InterfaceError, OperationalError
from psycopg.errors import QueryCanceled
from psycopg_pool import PoolClosed, PoolTimeout, TooManyRequests

from config import settings

from ..middleware import limiter
from ..route_security import RouteAccess, SecureAPIRouter
from ..services import get_db_cursor, get_outbox_metrics_cur, outbox_is_degraded

logger = logging.getLogger(__name__)

public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (public_router, capability_router)

_STALE_INTERVAL_MULTIPLIER = 2


def _is_health_detail_authorized(request: Request) -> bool:
    """Allow FASTAPI_DEBUG or an exact Bearer HEALTH_DETAIL_TOKEN; otherwise deny."""
    if settings.fastapi_debug:
        return True

    if settings.health_detail_token is None:
        return False

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False

    provided_token = auth_header[7:]
    expected_token = settings.health_detail_token.get_secret_value()

    return hmac.compare_digest(
        provided_token.encode("utf-8", "replace"),
        expected_token.encode("utf-8", "replace"),
    )


@public_router.get("/health")
@limiter.exempt
async def health_check(request: Request) -> Response:
    """Liveness — is the process up and serving? Does NOT check dependencies."""
    return JSONResponse(content={"status": "alive"})


# The endpoint intentionally aggregates independent diagnostic branches in
# one response so the complete health policy remains visible in one place.
@capability_router.get("/health/detail")
async def health_check_detail(request: Request) -> Response:  # noqa: PLR0912, PLR0915
    """Return authorized database/sync/outbox JSON, or 404 without diagnostics.

    A failed connection returns unhealthy/503. Reachable storage with missing,
    failed, or >2-interval-old harvest/rebuild state, or degraded/unreadable
    outbox diagnostics, returns degraded/200; otherwise healthy/200. Exceptions
    are logged and mapped by diagnostic stage. Monitor JSON status as well as
    HTTP status.
    """
    if not _is_health_detail_authorized(request):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not found"},
        )

    checks: dict[str, object] = {}
    diagnostic_stage = "database"
    pool = request.app.state.db_pool

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute("SELECT 1")
            checks["database"] = "ok"
            diagnostic_stage = "sync"
            await cur.execute(
                """SELECT last_harvest_date, last_full_rebuild_date,
                          last_sync_error, last_sync_error_at,
                          last_rebuild_error, last_rebuild_error_at
                FROM sync_status WHERE id = 1"""
            )

            row = await cur.fetchone()
            now = datetime.now(UTC)

            if row:
                harvested_at = row["last_harvest_date"]
                if harvested_at is None:
                    checks["sync"] = "last harvest: never"
                    checks["sync_stale"] = "no successful harvest recorded"
                else:
                    checks["sync"] = f"last harvest: {harvested_at}"
                    harvest_age = (now - harvested_at).total_seconds()
                    if harvest_age > _STALE_INTERVAL_MULTIPLIER * settings.sync_interval_seconds:
                        checks["sync_stale"] = f"{int(harvest_age)}s since last successful harvest"

                rebuilt_at = row["last_full_rebuild_date"]
                if rebuilt_at is None:
                    checks["full_rebuild"] = "last rebuild: never"
                    checks["full_rebuild_stale"] = "no successful full rebuild recorded"
                else:
                    checks["full_rebuild"] = f"last rebuild: {rebuilt_at}"
                    rebuild_age = (now - rebuilt_at).total_seconds()
                    interval = settings.full_rebuild_interval_seconds
                    if rebuild_age > _STALE_INTERVAL_MULTIPLIER * interval:
                        checks["full_rebuild_stale"] = (
                            f"{int(rebuild_age)}s since last successful rebuild"
                        )

                if row["last_sync_error"]:
                    checks["sync_error"] = row["last_sync_error"]
                    checks["sync_error_at"] = str(row["last_sync_error_at"])

                if row["last_rebuild_error"]:
                    checks["rebuild_error"] = row["last_rebuild_error"]
                    checks["rebuild_error_at"] = str(row["last_rebuild_error_at"])
            else:
                # The migration always creates id=1. Its absence means the
                # scheduler cannot read or update its watermark.
                checks["sync"] = "no sync history"
                checks["sync_status_missing"] = "sync_status row id=1 is missing"
            diagnostic_stage = "outbox"
            metrics = await get_outbox_metrics_cur(cur)
            checks["outbox"] = metrics
            if outbox_is_degraded(metrics):
                checks["outbox_degraded"] = True
    except Exception as exc:
        disconnected = isinstance(
            exc, (InterfaceError, PoolClosed, PoolTimeout, TooManyRequests)
        ) or (isinstance(exc, OperationalError) and not isinstance(exc, QueryCanceled))
        if disconnected:
            checks["database"] = "disconnected"
            checks["sync"] = "error"
            logger.warning("Health check: database connection failed", exc_info=True)
        elif diagnostic_stage == "outbox":
            checks["outbox_error"] = "Outbox diagnostics unavailable"
            logger.warning("Health check: outbox read failed", exc_info=True)
        elif checks.get("database") == "ok":
            checks["sync"] = "error"
            logger.warning("Health check: sync_status read failed", exc_info=True)
        else:
            checks["database"] = "disconnected"
            checks["sync"] = "error"
            logger.warning("Health check: database connection failed", exc_info=True)

    service_ok = checks.get("database") == "ok"
    sync_degraded = (
        checks.get("sync") == "error"
        or "sync_status_missing" in checks
        or "sync_stale" in checks
        or "sync_error" in checks
        or "rebuild_error" in checks
        or "full_rebuild_stale" in checks
    )

    if not service_ok:
        overall = "unhealthy"
    elif sync_degraded or "outbox_error" in checks or "outbox_degraded" in checks:
        overall = "degraded"
    else:
        overall = "healthy"

    code = status.HTTP_200_OK if service_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content={"status": overall, "checks": checks})
