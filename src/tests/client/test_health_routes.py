"""Backlog §2.14 — liveness/readiness split (unit tier).

/health is a pure liveness probe: it must return 200 {"status": "alive"}
WITHOUT touching the database, so a DB outage can never fail liveness (which
would otherwise put the orchestrator into a restart loop over a DB problem).

/health/detail is the readiness/diagnostics endpoint: token-gated in
production (404 on any authorization failure — never 403, so the endpoint's
existence is not revealed), open in debug mode, and the ONLY place DB state
is checked. DB down -> 503 "unhealthy"; sync errors -> HTTP 200 with status
"degraded" (sync lag is not an outage — a monitor must parse the JSON).

The route imports get_db_cursor into its own namespace, so DB behavior is
controlled via patch("app.routes.health.get_db_cursor", ...).
"""
import datetime
from unittest.mock import patch

from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor

DETAIL_URL = "/health/detail"


def _bearer_header() -> dict:
    """Authorization header carrying the CORRECT health-detail token."""
    token = settings.health_detail_token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}


def _detail_cursor_ctxs(sync_row):
    """The two get_db_cursor entries /health/detail makes, in call order:
    first the SELECT 1 liveness probe, then the sync_status fetchone."""
    select_one_cur = make_async_cursor()
    sync_cur = make_async_cursor(fetchone=sync_row)
    return [FakeCursorCtx(select_one_cur), FakeCursorCtx(sync_cur)]


_CLEAN_SYNC_ROW = {
    "last_harvest_date": datetime.datetime(
        2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc
    ),
    "last_sync_error": None,
    "last_sync_error_at": None,
}


# ---------------------------------------------------------------------------
# /health — DB-free liveness (§2.14 key pin)
# ---------------------------------------------------------------------------

def test_health_liveness_is_200_alive_and_never_touches_the_db(guest_client):
    """§2.14 key pin: /health returns 200 {"status": "alive"} without any DB
    access — even when the pool is hard-down. Regression guard against
    re-adding a SELECT 1 to /health (which would restart the app over a DB
    blip). The pool is sabotaged FIRST so any DB touch would 500/503."""
    guest_client.mock_pool.connection.side_effect = RuntimeError("db down")

    response = guest_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    # The sharp assertion: liveness never even asked the pool for a connection.
    guest_client.mock_pool.connection.assert_not_called()


# ---------------------------------------------------------------------------
# /health/detail — authorization (fail-secure 404, never 403)
# ---------------------------------------------------------------------------

def test_health_detail_without_auth_header_returns_404(guest_client):
    """§2.14: unauthorized access returns 404 — not 403 — so probing does not
    reveal that the diagnostics endpoint exists (fastapi_debug is False and a
    token is configured in the test env)."""
    response = guest_client.get(DETAIL_URL)

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_health_detail_with_wrong_bearer_token_returns_404(guest_client):
    """§2.14: a syntactically valid Bearer header with the WRONG token is
    rejected with the same 404 as no header at all (constant-time compare,
    no existence leak)."""
    response = guest_client.get(
        DETAIL_URL, headers={"Authorization": "Bearer wrong-token"}
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_health_detail_with_non_bearer_scheme_returns_404(guest_client):
    """§2.14: only the 'Bearer ' scheme is accepted — the correct secret sent
    under another scheme (Basic) is still a 404."""
    token = settings.health_detail_token.get_secret_value()
    response = guest_client.get(
        DETAIL_URL, headers={"Authorization": f"Basic {token}"}
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_health_detail_fail_secure_when_no_token_configured(guest_client, monkeypatch):
    """§2.14 fail-secure pin: with no HEALTH_DETAIL_TOKEN configured (and debug
    off) the endpoint is ALWAYS denied — even a request presenting a Bearer
    header gets 404. Guards against 'no token' degrading to 'open access'."""
    monkeypatch.setattr(settings, "health_detail_token", None)

    response = guest_client.get(
        DETAIL_URL, headers={"Authorization": "Bearer anything-at-all"}
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_health_detail_debug_mode_grants_open_access(guest_client, monkeypatch):
    """§2.14: fastapi_debug=True opens /health/detail without any token
    (development convenience). Asserting a real 200 diagnostics payload proves
    authorization was granted, not merely a different error path."""
    monkeypatch.setattr(settings, "fastapi_debug", True)

    with patch(
        "app.routes.health.get_db_cursor",
        autospec=True,
        side_effect=_detail_cursor_ctxs(_CLEAN_SYNC_ROW),
    ):
        response = guest_client.get(DETAIL_URL)  # no Authorization header

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# /health/detail — readiness statuses (authorized with the real token)
# ---------------------------------------------------------------------------

def test_health_detail_db_down_returns_503_unhealthy(guest_client):
    """§2.14: the DB-down 503 contract lives on /health/detail (it moved here
    from /health). Both get_db_cursor calls raise -> database 'disconnected',
    overall 'unhealthy', HTTP 503 so a readiness probe pulls the instance."""
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


def test_health_detail_healthy_when_db_up_and_sync_clean(guest_client):
    """§2.14: DB reachable + clean sync row -> HTTP 200 {"status": "healthy"}
    with database 'ok' and the last-harvest timestamp surfaced in checks.sync
    (real JSONResponse — the earlier return-annotation fix)."""
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


def test_health_detail_sync_error_is_degraded_but_http_200(guest_client):
    """§2.14 monitoring contract: a recorded last_sync_error makes the status
    'degraded' but the HTTP code stays 200 — sync lag is NOT a service outage,
    so the app stays in rotation and a monitor must parse the JSON status
    field, not just the HTTP code. Regression guard against 'degraded' being
    escalated to a non-200."""
    error_at = datetime.datetime(2026, 6, 2, 8, 30, tzinfo=datetime.timezone.utc)
    sync_row = {
        "last_harvest_date": datetime.datetime(
            2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc
        ),
        "last_sync_error": "boom",
        "last_sync_error_at": error_at,
    }

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


def test_health_detail_no_sync_history_is_healthy(guest_client):
    """§2.14: an empty sync_status table (fetchone -> None, e.g. a fresh
    deployment before the first harvest) is NOT an error: checks.sync says
    'no sync history' and the overall status stays 'healthy' / 200."""
    with patch(
        "app.routes.health.get_db_cursor",
        autospec=True,
        side_effect=_detail_cursor_ctxs(None),
    ):
        response = guest_client.get(DETAIL_URL, headers=_bearer_header())

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["sync"] == "no sync history"
