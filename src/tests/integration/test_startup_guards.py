"""Integration tests — startup guards (backlog §8.1) + schema-drift mechanism.

Pins the prod-lifespan fail-closed behavior: `alembic_version.version_num` is
compared against `ScriptDirectory.get_current_head()` and startup RAISES on
mismatch or on a missing version row. The old check only confirmed a row
existed — a database behind by one migration booted fine and then 500'd
(UndefinedColumn) on the first request touching a new column. Load-bearing
the moment migration #2 lands.

Also pins the drift-check mechanism (app.services.db_drift): column-presence
verification against information_schema, and that validate_schema_against_db
covers the sessions table (flash/purpose columns referenced only by raw SQL).

OPS NOTE (by design, not a test): this guard makes *code rollback without
schema rollback* a startup failure — the rollback runbook must pair them.

WHY THE FAILURE TESTS ENTER THE LIFESPAN DIRECTLY (not via TestClient):
historically the lifespan opened the connection pool BEFORE the alembic guard
and did not close it when the guard raised; unwinding a failed startup through
TestClient's blocking portal then cancelled the leaked psycopg_pool worker
tasks, which nondeterministically deadlocked the portal's event-loop shutdown
(observed ~1 in 5 runs). The lifespan now closes the pool on a failed startup
(pinned by test_failed_startup_closes_the_pool_it_opened at the bottom);
entering `lifespan(app)` directly remains the simplest way to exercise the
guard, and the defensive pool-close in the helper is now a harmless no-op.

HYGIENE: alembic_version is NOT reset by clean_db. Every test that mutates it
restores the original value in try/finally, else the session migration breaks
on the next run.
"""
import contextlib
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.services.db_drift import (
    assert_table_columns_match,
    validate_schema_against_db,
)
from config import settings


# ---------------------------------------------------------------------------
# Prod-lifespan harness (built inline — NOT the e2e_client fixture, which
# patches Config/command and therefore skips the real alembic-head comparison)
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _prod_mode(monkeypatch):
    """Route the lifespan into the REAL prod branch (alembic-head comparison;
    it does NOT run migrations there). External side effects (security
    validation, SMTP probe, logging reconfig, admin seeding) are stubbed;
    Config/command/ScriptDirectory are deliberately left real."""
    monkeypatch.setattr(settings, "env_state", "production")
    with patch("app.main.validate_security_settings"), \
         patch("app.main.verify_smtp_tls"), \
         patch("app.main.setup_logging"), \
         patch("app.main.seed_admin_user"):
        yield


async def _enter_prod_lifespan_expecting(match: str) -> None:
    """Enter the real prod lifespan, assert it raises RuntimeError(match),
    then close the pool the failed startup leaked (opened before the guard,
    never closed on the raise) so its background tasks don't outlive the
    test's event loop."""
    from app.main import app, lifespan

    try:
        with pytest.raises(RuntimeError, match=match):
            async with lifespan(app):
                pass  # pragma: no cover — startup must raise before entry
    finally:
        pool = getattr(app.state, "db_pool", None)
        if pool is not None:
            await pool.close()


def _current_version(sync_conn) -> str:
    """Read the live alembic_version (equals the migration file's revision)."""
    row = sync_conn.execute("SELECT version_num FROM alembic_version").fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# §8.1 — schema version verified against migration head, FAIL-CLOSED
# ---------------------------------------------------------------------------

async def test_stale_schema_version_fails_closed(sync_conn, monkeypatch):
    """§8.1: DB at an older version_num than the scripted head → startup
    RAISES with the 'Schema at X but code expects head Y' message and does
    NOT boot. Regression guard: the old check only confirmed a version row
    existed, so a DB behind by one migration booted and 500'd later on the
    first new-column touch."""
    head = _current_version(sync_conn)
    sync_conn.execute(
        "UPDATE alembic_version SET version_num = '000000000000'"
    )
    sync_conn.commit()
    try:
        with _prod_mode(monkeypatch):
            await _enter_prod_lifespan_expecting(
                "Schema at '000000000000' but code expects head"
            )
    finally:
        # MUST restore: clean_db does not touch alembic_version.
        sync_conn.execute(
            "UPDATE alembic_version SET version_num = %s", (head,)
        )
        sync_conn.commit()


async def test_empty_alembic_version_fails_closed(sync_conn, monkeypatch):
    """§8.1: empty alembic_version (unmigrated DB) → the DISTINCT
    'no alembic_version' error (the `if not row` path), not the mismatch
    message and not a silent boot."""
    head = _current_version(sync_conn)
    sync_conn.execute("DELETE FROM alembic_version")
    sync_conn.commit()
    try:
        with _prod_mode(monkeypatch):
            await _enter_prod_lifespan_expecting("no alembic_version")
    finally:
        # MUST restore: clean_db does not touch alembic_version.
        sync_conn.execute(
            "INSERT INTO alembic_version (version_num) VALUES (%s)", (head,)
        )
        sync_conn.commit()


def test_matching_head_boots_and_serves(monkeypatch):
    """§8.1 positive control: DB at the matching head → the prod lifespan
    proceeds (including the real validate_schema_against_db pass over the
    migrated schema) and the app serves GET /health 200. Uses TestClient so
    the full startup/shutdown path (pool open AND close) runs for real."""
    with _prod_mode(monkeypatch):
        from app.main import app
        with TestClient(
            app, base_url="http://localhost", raise_server_exceptions=False
        ) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "alive"}


async def test_failed_startup_closes_the_pool_it_opened(sync_conn, monkeypatch):
    """§8.1 adjunct: when the fail-closed guard rejects a stale schema, the
    lifespan closes the pool it opened before re-raising — otherwise the
    leaked psycopg_pool worker tasks nondeterministically deadlock event-loop
    shutdown (TestClient portal hung in _cancel_all_tasks ~1 in 5 runs before
    the fix). Formerly an xfail documenting the live bug; now a hard pin on
    the lifespan's except-close-raise path."""
    head = _current_version(sync_conn)
    sync_conn.execute(
        "UPDATE alembic_version SET version_num = '000000000000'"
    )
    sync_conn.commit()
    try:
        from app.main import app, lifespan
        with _prod_mode(monkeypatch):
            with pytest.raises(RuntimeError):
                async with lifespan(app):
                    pass  # pragma: no cover — startup must raise before entry
        pool = app.state.db_pool
        try:
            assert pool.closed, (
                "failed startup left the connection pool open"
            )
        finally:
            await pool.close()
    finally:
        # MUST restore: clean_db does not touch alembic_version.
        sync_conn.execute(
            "UPDATE alembic_version SET version_num = %s", (head,)
        )
        sync_conn.commit()


# ---------------------------------------------------------------------------
# Drift-check mechanism (app.services.db_drift)
# ---------------------------------------------------------------------------

async def test_drift_check_raises_on_missing_column(db_pool):
    """assert_table_columns_match raises RuntimeError naming both the table
    ('sessions') and the missing column (bogus_col) when the code expects a
    column absent from the live schema — the signal a rename in a future
    migration must trip."""
    with pytest.raises(RuntimeError, match=r"'sessions'.*\['bogus_col'\]"):
        await assert_table_columns_match(
            db_pool, "sessions", {"flash_message", "bogus_col"}
        )


async def test_drift_check_passes_on_matching_columns(db_pool):
    """assert_table_columns_match is silent when every expected column exists
    on the live (migrated) table — the check is superset-based, so extra DB
    columns never fail it."""
    await assert_table_columns_match(
        db_pool, "sessions", {"flash_message", "purpose"}
    )  # no raise = pass


async def test_validate_schema_covers_sessions_users_datasets():
    """§ 'now covering the sessions table': validate_schema_against_db checks
    sessions, users AND oral_history_datasets, and the sessions expected-set
    includes the raw-SQL-only columns flash_message and purpose — so a rename
    of either in migration #2 fails startup instead of 500ing at runtime."""
    mock = AsyncMock()
    sentinel_pool = object()
    with patch("app.services.db_drift.assert_table_columns_match", mock):
        await validate_schema_against_db(sentinel_pool)

    tables = [call.args[1] for call in mock.await_args_list]
    assert {"sessions", "users", "oral_history_datasets"} <= set(tables)

    sessions_expected = next(
        call.args[2] for call in mock.await_args_list
        if call.args[1] == "sessions"
    )
    assert {"flash_message", "purpose"} <= sessions_expected
