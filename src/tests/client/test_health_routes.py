"""HTTP-level contract for the health endpoints (`/health`, `/health/detail`).

`/health` is a pure liveness probe: it must return 200 {"status": "alive"}
without touching the database, so a database outage can never fail liveness
(which would otherwise put the orchestrator into a restart loop over a
database problem).

`/health/detail` is the readiness/diagnostics endpoint: token-gated in
production (404 on any authorization failure, never 403, so the endpoint's
existence is not revealed), open in debug mode, and the only place database,
synchronization and outbox state are checked. Database down -> 503
"unhealthy"; sync or outbox trouble -> HTTP 200 "degraded" (a monitor must
parse the JSON body, not rely on the HTTP status alone).

The route imports get_db_cursor into its own namespace, so database behavior
is controlled via patch("app.routes.health.get_db_cursor", ...).
"""

import datetime
from typing import Any
from unittest.mock import AsyncMock, create_autospec, patch

import pytest
from psycopg import OperationalError
from psycopg.errors import QueryCanceled

import app.middleware.rate_limiting as rl
from app.services.db import get_db_cursor as _real_get_db_cursor
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor


def _patch_get_db_cursor(**kwargs):
    """Autospecced replacement for app.routes.health.get_db_cursor.

    Specs against the real get_db_cursor(pool, row_factory=...) signature so a
    call site that drops or renames an argument fails here instead of
    returning a silently-wrong double.
    """
    return patch(
        "app.routes.health.get_db_cursor",
        new=create_autospec(_real_get_db_cursor, **kwargs),
    )


DETAIL_URL = "/health/detail"


def _bearer_header() -> dict[str, Any]:
    """Authorization header carrying the correct health-detail token."""
    assert settings.health_detail_token is not None  # set by the fixture
    token = settings.health_detail_token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}


def _outbox_row(**overrides: Any) -> dict[str, Any]:
    """A clean outbox diagnostics row, or one with named fields overridden."""
    return dict(
        {
            "pending_count": 0,
            "sending_count": 0,
            "dead_count": 0,
            "recent_failure_count": 0,
            "pending_age": None,
            "sending_age": None,
            "retention_overdue_count": 0,
        },
        **overrides,
    )


def _detail_cursor_ctxs(sync_row, outbox_row=None):
    """One connection serves database, sync, and outbox diagnostics in order."""
    cur = make_async_cursor(
        fetchone=[sync_row, _outbox_row() if outbox_row is None else outbox_row]
    )
    return [FakeCursorCtx(cur)]


_FRESH_REBUILD_AT = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)

_CLEAN_SYNC_ROW = {
    "last_harvest_date": (datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=5)),
    "last_full_rebuild_date": _FRESH_REBUILD_AT,
    "last_sync_error": None,
    "last_sync_error_at": None,
    # Channel split: the endpoint reads the rebuild channel columns
    # too — a row dict missing them KeyErrors inside the route's try block
    # and silently misreports a healthy install as degraded.
    "last_rebuild_error": None,
    "last_rebuild_error_at": None,
}


class TestLivenessProbe:
    """`/health` never inspects application dependencies."""

    def test_alive_response_never_touches_the_database(self, guest_client):
        """The liveness probe stays successful even when PostgreSQL is down."""
        guest_client.mock_pool.connection.side_effect = RuntimeError("db down")

        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
        guest_client.mock_pool.connection.assert_not_called()

    def test_response_is_not_cacheable(self, guest_client):
        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"


class TestLivenessHasNoBackendDependencies:
    """`/health` is declared `@limiter.exempt`: it reads no dependency at
    all, so its body carries no readiness claim of its own — that is
    `/health/detail`'s job."""

    def test_health_performs_no_redis_operation(self, guest_client):
        """The exemption means the limiter's storage backend is never
        touched for this route, not merely that its result is ignored."""
        storage_double = create_autospec(rl.limiter.limiter.storage, instance=True, spec_set=True)
        with patch.object(rl.limiter.limiter, "storage", new=storage_double):
            response = guest_client.get("/health")

        assert response.status_code == 200
        assert storage_double.mock_calls == []

    def test_health_detail_does_perform_a_redis_operation_as_the_positive_control(
        self, guest_client
    ):
        """Positive control: `/health/detail` is NOT exempt, so the same
        storage double style DOES record a call — proving the assertion
        above would catch a lost exemption, not just an always-quiet double."""
        storage_double = create_autospec(rl.limiter.limiter.storage, instance=True, spec_set=True)
        with patch.object(rl.limiter.limiter, "storage", new=storage_double):
            guest_client.get(DETAIL_URL)

        assert storage_double.mock_calls != []

    def test_health_body_makes_no_dependency_readiness_claim(self, guest_client):
        """Even with the database unreachable, /health's body stays the
        bare liveness payload — no "checks" or degraded/unhealthy claim,
        which is /health/detail's contract, not this route's."""
        guest_client.mock_pool.connection.side_effect = RuntimeError("db down")

        response = guest_client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
        guest_client.mock_pool.connection.assert_not_called()


class TestHealthDetailAuthorization:
    """`/health/detail` fails secure: any authorization failure is a 404,
    never a 403, so the endpoint's existence is never revealed."""

    def test_missing_authorization_header_is_rejected_as_not_found(self, guest_client):
        response = guest_client.get(DETAIL_URL)

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_wrong_bearer_token_is_rejected_as_not_found(self, guest_client):
        """A syntactically valid Bearer header with the wrong token is
        rejected with the same 404 as no header at all (constant-time
        compare, no existence leak)."""
        response = guest_client.get(DETAIL_URL, headers={"Authorization": "Bearer wrong-token"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_non_bearer_scheme_is_rejected_as_not_found(self, guest_client):
        """Only the 'Bearer ' scheme is accepted — the correct secret sent
        under another scheme (Basic) is still a 404."""
        token = settings.health_detail_token.get_secret_value()
        response = guest_client.get(DETAIL_URL, headers={"Authorization": f"Basic {token}"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_no_token_configured_fails_secure_even_with_a_header(self, guest_client, monkeypatch):
        """With no HEALTH_DETAIL_TOKEN configured (and debug off) the endpoint
        is always denied — even a request presenting a Bearer header gets
        404. Guards against 'no token' degrading to 'open access'."""
        monkeypatch.setattr(settings, "health_detail_token", None)

        response = guest_client.get(DETAIL_URL, headers={"Authorization": "Bearer anything-at-all"})

        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}

    def test_debug_mode_grants_open_access_without_any_token(self, guest_client, monkeypatch):
        """fastapi_debug=True opens /health/detail without any token
        (development convenience). Asserting a real 200 diagnostics payload
        proves authorization was granted, not merely a different error path.
        This is the positive control for the rejection cases above."""
        monkeypatch.setattr(settings, "fastapi_debug", True)

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL)  # no Authorization header

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_denied_response_is_not_cacheable(self, guest_client):
        response = guest_client.get(DETAIL_URL)

        assert response.status_code == 404
        assert response.headers["Cache-Control"] == "no-store"

    def test_authorized_response_is_not_cacheable(self, guest_client):
        """Positive control for the denial case above: a correctly
        authorized response also refuses caching."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"


class TestHealthDetailDatabaseAndSyncDiagnostics:
    """Authorized readiness diagnostics: database reachability and the
    incremental-sync / full-rebuild error and staleness channels."""

    def test_database_failure_reports_503_unhealthy(self, guest_client):
        """The database-down 503 contract lives on /health/detail. The
        single get_db_cursor call raises -> database 'disconnected', overall
        'unhealthy', HTTP 503 so a readiness probe pulls the instance."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=Exception("connection refused"),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "unhealthy"
        assert body["checks"]["database"] == "disconnected"

    def test_database_up_and_sync_clean_reports_healthy(self, guest_client):
        """Database reachable + clean sync row -> HTTP 200
        {"status": "healthy"} with database 'ok' and the last-harvest
        timestamp surfaced in checks.sync (a real JSONResponse)."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "healthy"
        assert body["checks"]["database"] == "ok"
        assert body["checks"]["sync"].startswith("last harvest:")
        assert "sync_error" not in body["checks"]

    def test_recorded_sync_error_reports_degraded_but_http_200(self, guest_client):
        """A recorded last_sync_error makes the status 'degraded' but the
        HTTP code stays 200 — sync lag is not a service outage, so the app
        stays in rotation and a monitor must parse the JSON status field,
        not just the HTTP code. Guards against 'degraded' being escalated to
        a non-200."""
        error_at = datetime.datetime(2026, 6, 2, 8, 30, tzinfo=datetime.UTC)
        sync_row = dict(
            _CLEAN_SYNC_ROW,
            last_sync_error="boom",
            last_sync_error_at=error_at,
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(sync_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200  # degraded is intentionally 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["sync_error"] == "boom"
        assert body["checks"]["sync_error_at"] == str(error_at)
        assert body["checks"]["database"] == "ok"
        # Channel independence: the incremental error must not bleed into the
        # rebuild channel's keys.
        assert "rebuild_error" not in body["checks"]

    def test_recorded_rebuild_error_reports_degraded_via_its_own_keys(self, guest_client):
        """A recorded last_rebuild_error alone (e.g. an aborted full rebuild)
        degrades the status via its own checks keys — rebuild_error /
        rebuild_error_at — with no sync_error key present, and the HTTP code
        stays 200. Guards against collapsing the two channels back into one
        column, which would lose the most important error in the system to
        the next hourly incremental."""
        error_at = datetime.datetime(2026, 6, 2, 9, 0, tzinfo=datetime.UTC)
        row = dict(
            _CLEAN_SYNC_ROW,
            last_rebuild_error="Full rebuild ABORTED — 0/2 inserted",
            last_rebuild_error_at=error_at,
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["rebuild_error"] == "Full rebuild ABORTED — 0/2 inserted"
        assert body["checks"]["rebuild_error_at"] == str(error_at)
        assert "sync_error" not in body["checks"]
        assert body["checks"]["database"] == "ok"

    def test_both_error_channels_surface_independently(self, guest_client):
        """Both channels set → both key pairs surface side by side: neither
        error masks the other."""
        row = dict(
            _CLEAN_SYNC_ROW,
            last_sync_error="Incremental sync (fetch): boom",
            last_sync_error_at=datetime.datetime(2026, 6, 2, 8, 30, tzinfo=datetime.UTC),
            last_rebuild_error="Full rebuild: upstream returned 0 live records",
            last_rebuild_error_at=datetime.datetime(2026, 6, 2, 3, 0, tzinfo=datetime.UTC),
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["sync_error"] == "Incremental sync (fetch): boom"
        assert body["checks"]["rebuild_error"] == "Full rebuild: upstream returned 0 live records"

    def test_missing_sync_history_reports_degraded_not_unhealthy(self, guest_client):
        """An empty sync_status table (fetchone -> None, e.g. a fresh
        deployment before the first harvest) is not a database outage: the
        database stays 'ok' and the HTTP code stays 200, but the overall
        status is 'degraded' — checks.sync says 'no sync history' and
        sync_status_missing names the missing watermark row so ops can act
        on it."""
        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(None),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        body = response.json()
        assert response.status_code == 200
        assert body["status"] == "degraded"
        assert "sync_status_missing" in body["checks"]

    def test_stale_harvest_reports_degraded_but_http_200(self, guest_client):
        """A scheduler that stops completing jobs must not remain healthy."""
        stale_row = dict(_CLEAN_SYNC_ROW)
        stale_row["last_harvest_date"] = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            seconds=2 * settings.sync_interval_seconds + 60
        )

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(stale_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert "sync_stale" in body["checks"]
        assert "sync_error" not in body["checks"]

    def test_stale_rebuild_reports_degraded_but_http_200(self, guest_client):
        """A rebuild older than 2x full_rebuild_interval_seconds degrades
        even with no last_sync_error: an upstream returning nothing usable
        leaves stale versions unreaped — a failed last_sync_error alone
        cannot see that."""
        stale_row = dict(_CLEAN_SYNC_ROW)
        stale_row["last_full_rebuild_date"] = datetime.datetime.now(
            datetime.UTC
        ) - datetime.timedelta(seconds=2 * settings.full_rebuild_interval_seconds + 3600)

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(stale_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        assert response.status_code == 200  # stale rebuild is not an outage
        body = response.json()
        assert body["status"] == "degraded"
        assert "full_rebuild_stale" in body["checks"]
        assert "sync_error" not in body["checks"]

    def test_never_rebuilt_reports_degraded_with_never_message(self, guest_client):
        """A never-yet-rebuilt install (NULL last_full_rebuild_date) reports
        'last rebuild: never' and degrades via full_rebuild_stale — a fresh
        install is expected to complete its first full rebuild promptly, so
        an unbounded wait must be visible to monitoring rather than silently
        reported as healthy."""
        fresh_install_row = dict(_CLEAN_SYNC_ROW)
        fresh_install_row["last_full_rebuild_date"] = None

        with patch(
            "app.routes.health.get_db_cursor",
            autospec=True,
            side_effect=_detail_cursor_ctxs(fresh_install_row),
        ):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())

        body = response.json()
        assert response.status_code == 200
        assert body["status"] == "degraded"
        assert body["checks"]["full_rebuild"] == "last rebuild: never"
        assert "full_rebuild_stale" in body["checks"]

    @pytest.mark.parametrize(
        "failure,expected_status_code",
        [
            (OperationalError("connection lost"), 503),
            (QueryCanceled("statement timeout"), 200),
        ],
        ids=["operational_error_after_select_one_is_unhealthy", "query_canceled_stays_degraded"],
    )
    def test_failure_after_a_successful_select_one_is_classified_by_exception_type(
        self, guest_client, failure, expected_status_code
    ):
        """The initial `SELECT 1` succeeding proves the connection itself is
        fine; a failure on the very next query is then classified by
        exception type — a generic `OperationalError` (connection-level) is
        'unhealthy' 503, while `QueryCanceled` (a statement timeout, a
        subclass of `OperationalError`) is treated as a sync-read failure and
        stays 'degraded' 200, since the connection is still usable."""
        cur = make_async_cursor()
        cur.execute = AsyncMock(side_effect=[None, failure])
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())
        assert response.status_code == expected_status_code
        assert response.json()["status"] in {"unhealthy", "degraded"}


class TestHealthDetailOutboxDiagnostics:
    """Authorized diagnostics include actionable aggregate outbox state,
    reported independently of the sync channels above."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"pending_count": 1, "pending_age": 900},
            {"sending_count": 1, "sending_age": 900},
            {"retention_overdue_count": 1},
        ],
        ids=["pending_delivery_stalled", "sending_delivery_stalled", "retention_cleanup_overdue"],
    )
    def test_outbox_problem_is_degraded_without_failing_liveness(self, guest_client, overrides):
        cur = make_async_cursor(fetchone=[_CLEAN_SYNC_ROW, _outbox_row(**overrides)])
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)) as cursor:
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["outbox_degraded"] is True
        assert set(body["checks"]["outbox"]) == {
            "counts_capped_at",
            "pending_count",
            "sending_count",
            "dead_count",
            "recent_failure_count",
            "oldest_pending_age_seconds",
            "oldest_sending_age_seconds",
            "retention_overdue_count",
        }
        cursor.assert_called_once()
        assert guest_client.get("/health").json() == {"status": "alive"}

    def test_dead_letters_are_visible_without_treating_cancellation_as_outage(self, guest_client):
        """Positive control for the degraded cases above: dead letters alone
        (no stalled/overdue counters) still report 'healthy', with the
        dead_count surfaced for visibility rather than hidden."""
        cur = make_async_cursor(fetchone=[_CLEAN_SYNC_ROW, _outbox_row(dead_count=3)])
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())
        assert response.json()["status"] == "healthy"
        assert response.json()["checks"]["outbox"]["dead_count"] == 3

    def test_recent_terminal_delivery_failures_keep_the_status_degraded(self, guest_client):
        """A nonzero `recent_failure_count` (terminal deliveries that failed
        recently, alongside dead letters) degrades the status the same way a
        stalled or overdue counter does — recent failures are actionable and
        must not be silently absorbed into a 'healthy' outbox summary."""
        cur = make_async_cursor(
            fetchone=[_CLEAN_SYNC_ROW, _outbox_row(dead_count=1, recent_failure_count=1)]
        )
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())
        assert response.status_code == 200
        assert response.json()["status"] == "degraded"

    def test_outbox_query_failure_is_not_misreported_as_sync_failure(self, guest_client):
        cur = make_async_cursor(fetchone=[_CLEAN_SYNC_ROW, RuntimeError("outbox query failed")])
        with _patch_get_db_cursor(return_value=FakeCursorCtx(cur)):
            response = guest_client.get(DETAIL_URL, headers=_bearer_header())
        assert response.status_code == 200
        checks = response.json()["checks"]
        assert response.json()["status"] == "degraded"
        assert checks["outbox_error"] == "Outbox diagnostics unavailable"
        assert checks["sync"].startswith("last harvest:")
