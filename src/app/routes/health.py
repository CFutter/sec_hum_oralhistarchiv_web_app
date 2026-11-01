"""Expose dependency-free /health and authorized /health/detail diagnostics."""

import hmac
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import partial
from typing import Any

from anyio import CapacityLimiter
from anyio.lowlevel import RunVar
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from psycopg import InterfaceError, OperationalError
from psycopg.errors import QueryCanceled
from psycopg_pool import PoolClosed, PoolTimeout, TooManyRequests

from app.backup_status import BackupStatus, read_backup_status
from app.sources import SourceMetadata
from app.thread_work import ThreadWorkAdmissionTimeout, run_thread_work
from config import settings

from ..middleware import limiter
from ..route_security import RouteAccess, SecureAPIRouter
from ..services import get_db_cursor, get_outbox_metrics_cur, outbox_is_degraded

logger = logging.getLogger(__name__)

public_router = SecureAPIRouter(access=RouteAccess.PUBLIC)
capability_router = SecureAPIRouter(access=RouteAccess.CAPABILITY)
routers = (public_router, capability_router)

_STALE_INTERVAL_MULTIPLIER = 2
_BACKUP_READ_LIMITER: RunVar[CapacityLimiter] = RunVar("health_backup_read_limiter")


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


async def _backup_diagnostics() -> BackupStatus:
    """Read optional backup age in one of two loop-local blocking slots.

    Return unknown if unset or admission exceeds 0.2 seconds. Cancellation
    retains the slot until the read finishes; backup age does not change readiness.
    """
    path = settings.backup_status_file
    if path is None:
        return BackupStatus(status="unknown", age_seconds=None)
    try:
        capacity = _BACKUP_READ_LIMITER.get()
    except LookupError:
        capacity = CapacityLimiter(2)
        _BACKUP_READ_LIMITER.set(capacity)
    try:
        return await run_thread_work(
            partial(read_backup_status, path), capacity, admission_timeout_seconds=0.2
        )
    except ThreadWorkAdmissionTimeout:
        return BackupStatus(status="unknown", age_seconds=None)


def _source_diagnostics(
    source: SourceMetadata,
    row: Mapping[str, Any] | None,
    now: datetime,
) -> dict[str, object]:
    """Return source status/ages/errors; missing or >2-interval-old history is degraded.

    row supplies sync_status timestamps/error fields; now and stored timestamps
    must be timezone-aware. Harvest and rebuild ages use their own schedules.
    """
    checks: dict[str, object] = {
        "status": "healthy",
        "harvest_age_seconds": None,
        "rebuild_age_seconds": None,
    }
    if row is None:
        checks["status"] = "degraded"
        checks["sync"] = "no sync history"
        checks["sync_status_missing"] = f"sync_status row for source {source.name!r} is missing"
        return checks

    harvested_at = row["last_harvest_date"]
    if harvested_at is None:
        checks["sync"] = "last harvest: never"
        checks["sync_stale"] = "no successful harvest recorded"
    else:
        checks["sync"] = f"last harvest: {harvested_at}"
        harvest_age = (now - harvested_at).total_seconds()
        checks["harvest_age_seconds"] = harvest_age
        if harvest_age > _STALE_INTERVAL_MULTIPLIER * source.schedule.incremental_interval_seconds:
            checks["sync_stale"] = f"{int(harvest_age)}s since last successful harvest"

    rebuilt_at = row["last_full_rebuild_date"]
    if rebuilt_at is None:
        checks["full_rebuild"] = "last rebuild: never"
        checks["full_rebuild_stale"] = "no successful full rebuild recorded"
    else:
        checks["full_rebuild"] = f"last rebuild: {rebuilt_at}"
        rebuild_age = (now - rebuilt_at).total_seconds()
        checks["rebuild_age_seconds"] = rebuild_age
        if rebuild_age > _STALE_INTERVAL_MULTIPLIER * source.schedule.rebuild_interval_seconds:
            checks["full_rebuild_stale"] = f"{int(rebuild_age)}s since last successful rebuild"

    if row["last_sync_error"]:
        checks["sync_error"] = row["last_sync_error"]
        checks["sync_error_at"] = str(row["last_sync_error_at"])

    if row["last_rebuild_error"]:
        checks["rebuild_error"] = row["last_rebuild_error"]
        checks["rebuild_error_at"] = str(row["last_rebuild_error_at"])

    if any(
        key in checks for key in ("sync_stale", "full_rebuild_stale", "sync_error", "rebuild_error")
    ):
        checks["status"] = "degraded"
    return checks


@public_router.get("/health")
@limiter.exempt
async def health_check(request: Request) -> Response:
    """Return {"status": "alive"} without dependency checks."""
    return JSONResponse(content={"status": "alive"})


@capability_router.get("/health/detail")
async def health_check_detail(request: Request) -> Response:
    """Return authorized database/source/outbox/backup JSON, or an opaque 404.

    A failed connection returns unhealthy/503. Reachable storage with missing,
    failed, unreadable or >2-interval-old source state, or degraded/unreadable
    outbox diagnostics, returns degraded/200; otherwise healthy/200. Each source
    uses its own intervals. Optional local backup age is informational: unknown
    or old markers do not change these statuses. It does not establish off-host
    custody or recovery readiness. Monitor JSON status and backup age separately.
    """
    if not _is_health_detail_authorized(request):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not found"},
        )

    configured_sources: tuple[SourceMetadata, ...] = request.app.state.configured_sources
    source_checks: dict[str, dict[str, object]] = {
        source.name: {
            "status": "degraded",
            "sync": "error",
            "harvest_age_seconds": None,
            "rebuild_age_seconds": None,
        }
        for source in configured_sources
    }
    checks: dict[str, object] = {
        "sources": source_checks,
        "backup": await _backup_diagnostics(),
    }
    diagnostic_stage = "database"
    pool = request.app.state.db_pool

    try:
        async with get_db_cursor(pool) as cur:
            await cur.execute("SELECT 1")
            checks["database"] = "ok"
            diagnostic_stage = "sync"
            now = datetime.now(UTC)
            if configured_sources:
                await cur.execute(
                    """SELECT source, last_harvest_date, last_full_rebuild_date,
                              last_sync_error, last_sync_error_at,
                              last_rebuild_error, last_rebuild_error_at
                       FROM sync_status WHERE source = ANY(%s::text[])""",
                    ([source.name for source in configured_sources],),
                )
                rows_by_source = {row["source"]: row for row in await cur.fetchall()}
                for source in configured_sources:
                    source_checks[source.name] = _source_diagnostics(
                        source, rows_by_source.get(source.name), now
                    )

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
            logger.warning("Health check: database connection failed", exc_info=True)
        elif diagnostic_stage == "outbox":
            checks["outbox_error"] = "Outbox diagnostics unavailable"
            logger.warning("Health check: outbox read failed", exc_info=True)
        elif checks.get("database") == "ok":
            logger.warning("Health check: sync_status read failed", exc_info=True)
        else:
            checks["database"] = "disconnected"
            logger.warning("Health check: database connection failed", exc_info=True)

    service_ok = checks.get("database") == "ok"
    sync_degraded = any(source["status"] != "healthy" for source in source_checks.values())

    if not service_ok:
        overall = "unhealthy"
    elif sync_degraded or "outbox_error" in checks or "outbox_degraded" in checks:
        overall = "degraded"
    else:
        overall = "healthy"

    code = status.HTTP_200_OK if service_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content={"status": overall, "checks": checks})
