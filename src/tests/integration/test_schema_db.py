"""Integration tests for the live schema contract and the startup guards
that enforce it.

The declared schema in ``app.services.db_schema_contract`` is the contract;
``app.services.db_drift`` verifies the live PostgreSQL catalogs against it
column by column, constraint by constraint, index by index, and trigger by
trigger. ``TestSchemaDriftDetection`` proves that verification: the
migrated database satisfies the contract exactly (positive control), and a
single mutated property in any dimension is rejected (negative controls).
``TestStartupGuards`` proves that the application's production lifespan
refuses to boot when the live schema is behind the code's migration head,
and that a failed boot leaves no resources open.

Negative controls that mutate schema objects restore them in ``finally``:
the integration fixtures truncate rows before every test but do not undo
DDL, and ``alembic_version`` is not touched by row truncation at all.
"""

import contextlib
from dataclasses import replace
from unittest.mock import create_autospec, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from psycopg import sql

from app.main import app, lifespan
from app.services import db_drift
from app.services.database_privileges import validate_runtime_database_role
from app.services.db_drift import (
    assert_table_column_contract,
    assert_table_constraint_contract,
    validate_schema_against_db,
)
from app.services.db_schema_contract import (
    DATASET_CONSTRAINT_CONTRACT,
    SESSION_COLUMN_CONTRACT,
    SESSION_CONSTRAINT_CONTRACT,
    ColumnSpec,
)
from config import settings

# ---------------------------------------------------------------------------
# Prod-lifespan harness (built inline — NOT the e2e_client fixture, which
# patches Config/command and therefore skips the real alembic-head
# comparison)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _prod_mode(monkeypatch):
    """Route the lifespan into the real production branch (alembic-head
    comparison; it does not run migrations there). External side effects
    (security validation, SMTP probe, logging reconfig, admin seeding) are
    stubbed; Config/command/ScriptDirectory are deliberately left real."""
    monkeypatch.setattr(settings, "env_state", "production")
    with (
        patch("app.main.validate_security_settings", autospec=True),
        patch("app.main.validate_rate_limit_backend", autospec=True),
        patch("app.main.setup_logging", autospec=True),
        patch("app.main.seed_admin_user", autospec=True),
        # Role ownership has its own real role-bound integration suite.
        # These tests isolate head/schema checks using the disposable
        # owner connection.
        patch(
            "app.runtime_preflight.validate_runtime_database_role",
            new=create_autospec(validate_runtime_database_role, spec_set=True),
        ),
    ):
        yield


async def _enter_prod_lifespan_expecting(match: str) -> None:
    """Enter the real prod lifespan and assert it raises RuntimeError."""
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


def _replace_search_function(sync_conn, source: str) -> None:
    """Replace the trigger function while preserving source bytes exactly."""
    statement = sql.SQL(
        """
        CREATE OR REPLACE FUNCTION update_search_text()
        RETURNS trigger
        AS {}
        LANGUAGE plpgsql
        """
    ).format(sql.Literal(source))
    sync_conn.execute(statement)
    sync_conn.commit()


def _restore_search_trigger(sync_conn) -> None:
    """Restore the trigger definition from the initial migration."""
    sync_conn.execute("DROP TRIGGER IF EXISTS trg_search_text ON oral_history_datasets")
    sync_conn.execute(
        "CREATE TRIGGER trg_search_text "
        "BEFORE INSERT OR UPDATE ON oral_history_datasets "
        "FOR EACH ROW EXECUTE FUNCTION update_search_text()"
    )
    sync_conn.commit()


class TestSchemaDriftDetection:
    """The live PostgreSQL catalogs are verified against the declarative
    schema contract, dimension by dimension."""

    async def test_migrated_schema_matches_the_complete_contract(self, db_pool):
        """The migrated database satisfies every current runtime contract
        exactly: every column, constraint, index and trigger contract
        covers exactly the tables and properties the live catalogs have."""
        await validate_schema_against_db(db_pool)

    async def test_changed_column_default_is_rejected(self, db_pool, sync_conn):
        """A retained column name cannot hide a changed default."""
        try:
            sync_conn.execute("ALTER TABLE users ALTER COLUMN access_tier SET DEFAULT 'registered'")
            sync_conn.commit()

            with pytest.raises(
                RuntimeError,
                match=r"Schema drift on 'users'.*column 'access_tier'",
            ):
                await validate_schema_against_db(db_pool)
        finally:
            sync_conn.execute("ALTER TABLE users ALTER COLUMN access_tier SET DEFAULT 'public'")
            sync_conn.commit()

    async def test_missing_index_is_rejected(self, db_pool, sync_conn):
        """Dropping a load-bearing trigram index fails full validation."""
        try:
            sync_conn.execute("DROP INDEX IF EXISTS idx_search_text_public_trgm")
            sync_conn.commit()

            with pytest.raises(
                RuntimeError,
                match=(
                    r"Schema drift on 'oral_history_datasets'.*"
                    r"missing indexes.*idx_search_text_public_trgm"
                ),
            ):
                await validate_schema_against_db(db_pool)
        finally:
            sync_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_search_text_public_trgm "
                "ON oral_history_datasets USING GIN "
                "(search_text_public gin_trgm_ops)"
            )
            sync_conn.commit()

    async def test_changed_index_definition_is_rejected(self, db_pool, sync_conn):
        """An index retaining its name cannot silently target another column."""
        try:
            sync_conn.execute("DROP INDEX IF EXISTS idx_search_text_public_trgm")
            sync_conn.execute(
                "CREATE INDEX idx_search_text_public_trgm "
                "ON oral_history_datasets USING GIN "
                "(search_text_full gin_trgm_ops)"
            )
            sync_conn.commit()

            with pytest.raises(
                RuntimeError,
                match=r"index 'idx_search_text_public_trgm'",
            ):
                await validate_schema_against_db(db_pool)
        finally:
            sync_conn.execute("DROP INDEX IF EXISTS idx_search_text_public_trgm")
            sync_conn.execute(
                "CREATE INDEX idx_search_text_public_trgm "
                "ON oral_history_datasets USING GIN "
                "(search_text_public gin_trgm_ops)"
            )
            sync_conn.commit()

    async def test_disabled_search_trigger_is_rejected(self, db_pool, sync_conn):
        """A present but disabled search trigger is structural drift."""
        try:
            sync_conn.execute("ALTER TABLE oral_history_datasets DISABLE TRIGGER trg_search_text")
            sync_conn.commit()

            with pytest.raises(
                RuntimeError,
                match=r"trigger 'trg_search_text'",
            ):
                await validate_schema_against_db(db_pool)
        finally:
            sync_conn.execute("ALTER TABLE oral_history_datasets ENABLE TRIGGER trg_search_text")
            sync_conn.commit()

    async def test_changed_search_trigger_events_are_rejected(self, db_pool, sync_conn):
        """A same-named trigger firing only on INSERT fails validation."""
        try:
            sync_conn.execute("DROP TRIGGER IF EXISTS trg_search_text ON oral_history_datasets")
            sync_conn.execute(
                "CREATE TRIGGER trg_search_text "
                "BEFORE INSERT ON oral_history_datasets "
                "FOR EACH ROW EXECUTE FUNCTION update_search_text()"
            )
            sync_conn.commit()

            with pytest.raises(
                RuntimeError,
                match=r"trigger 'trg_search_text'",
            ):
                await validate_schema_against_db(db_pool)
        finally:
            _restore_search_trigger(sync_conn)

    async def test_unique_constraint_with_nulls_not_distinct_is_rejected(self, db_pool, sync_conn):
        """The datasets (source, doi) unique constraint is declared with
        ordinary NULLS DISTINCT semantics (multiple NULL dois are allowed).
        A live constraint recreated with NULLS NOT DISTINCT is drift the
        contract must reject, not silently accept as "still unique"."""
        sync_conn.execute(
            "ALTER TABLE oral_history_datasets DROP CONSTRAINT datasets_source_doi_key"
        )
        sync_conn.execute(
            "ALTER TABLE oral_history_datasets ADD CONSTRAINT datasets_source_doi_key "
            "UNIQUE NULLS NOT DISTINCT (source, doi)"
        )
        sync_conn.commit()
        try:
            with pytest.raises(RuntimeError, match="nulls_not_distinct"):
                await assert_table_constraint_contract(
                    db_pool, "oral_history_datasets", DATASET_CONSTRAINT_CONTRACT
                )
        finally:
            sync_conn.execute(
                "ALTER TABLE oral_history_datasets DROP CONSTRAINT datasets_source_doi_key"
            )
            sync_conn.execute(
                "ALTER TABLE oral_history_datasets ADD CONSTRAINT datasets_source_doi_key "
                "UNIQUE (source, doi)"
            )
            sync_conn.commit()

    async def test_column_check_rejects_missing_columns(self, db_pool):
        """A column expected by Python but absent from PostgreSQL is drift."""
        expected = {
            **SESSION_COLUMN_CONTRACT,
            "bogus_col": ColumnSpec("text", nullable=True),
        }

        with pytest.raises(
            RuntimeError,
            match=r"'sessions'.*missing columns: \['bogus_col'\]",
        ):
            await assert_table_column_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_column_check_rejects_unexpected_columns(self, db_pool):
        """A database column absent from the declared contract is drift."""
        expected = {
            name: spec for name, spec in SESSION_COLUMN_CONTRACT.items() if name != "ip_address"
        }

        with pytest.raises(
            RuntimeError,
            match=r"'sessions'.*unexpected columns: \['ip_address'\]",
        ):
            await assert_table_column_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_column_check_allows_explicit_transitional_column(self, db_pool):
        """A specifically allowlisted legacy column does not cause drift."""
        expected = {
            name: spec for name, spec in SESSION_COLUMN_CONTRACT.items() if name != "ip_address"
        }

        await assert_table_column_contract(
            db_pool,
            "sessions",
            expected,
            allowed_extra_columns={"ip_address"},
        )

    async def test_column_check_accepts_exact_column_set(self, db_pool):
        """The migrated sessions table exactly matches its declared contract."""
        await assert_table_column_contract(
            db_pool,
            "sessions",
            SESSION_COLUMN_CONTRACT,
        )

    @pytest.mark.parametrize(
        ("column_name", "replacement"),
        [
            (
                "purpose",
                ColumnSpec("text", nullable=False),
            ),
            (
                "expires_at",
                ColumnSpec(
                    "timestamp with time zone",
                    nullable=True,
                ),
            ),
            (
                "created_at",
                ColumnSpec(
                    "timestamp with time zone",
                    nullable=False,
                ),
            ),
            (
                "id",
                ColumnSpec(
                    "text",
                    nullable=False,
                    identity="a",
                ),
            ),
        ],
        ids=[
            "type",
            "nullability",
            "default",
            "identity",
        ],
    )
    async def test_column_check_rejects_structural_drift(
        self,
        db_pool,
        column_name,
        replacement,
    ):
        """Type, nullability, default, and identity drift all fail closed."""
        expected = {
            **SESSION_COLUMN_CONTRACT,
            column_name: replacement,
        }

        with pytest.raises(
            RuntimeError,
            match=rf"'sessions'.*column {column_name!r}",
        ):
            await assert_table_column_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_validate_schema_against_db_catches_dropped_sync_status_column(
        self,
        db_pool,
        sync_conn,
    ):
        """The complete validator must detect a dropped sync-status column."""
        sync_conn.execute(
            """
            ALTER TABLE sync_status
            DROP COLUMN last_rebuild_error_at
            """
        )
        sync_conn.commit()

        try:
            with pytest.raises(
                RuntimeError,
                match=(
                    r"'sync_status'.*missing columns: "
                    r"\['last_rebuild_error_at'\]"
                ),
            ):
                await validate_schema_against_db(db_pool)
        finally:
            # clean_db truncates rows; it does not undo DDL.
            sync_conn.execute(
                """
                ALTER TABLE sync_status
                ADD COLUMN last_rebuild_error_at TIMESTAMPTZ
                """
            )
            sync_conn.commit()

    async def test_constraint_check_accepts_exact_contract(self, db_pool):
        """The migrated sessions constraints exactly match their contract."""
        await assert_table_constraint_contract(
            db_pool,
            "sessions",
            SESSION_CONSTRAINT_CONTRACT,
        )

    async def test_constraint_check_rejects_missing_constraint(self, db_pool):
        """A constraint expected by Python but absent from PostgreSQL is drift."""
        expected = {
            **SESSION_CONSTRAINT_CONTRACT,
            "bogus_constraint": (SESSION_CONSTRAINT_CONTRACT["sessions_purpose_check"]),
        }

        with pytest.raises(
            RuntimeError,
            match=(
                r"'sessions'.*missing constraints: "
                r"\['bogus_constraint'\]"
            ),
        ):
            await assert_table_constraint_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_constraint_check_rejects_unexpected_constraint(self, db_pool):
        """A database constraint absent from the contract is drift."""
        expected = {
            name: spec
            for name, spec in SESSION_CONSTRAINT_CONTRACT.items()
            if name != "sessions_purpose_check"
        }

        with pytest.raises(
            RuntimeError,
            match=(
                r"'sessions'.*unexpected constraints: "
                r"\['sessions_purpose_check'\]"
            ),
        ):
            await assert_table_constraint_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_constraint_check_allows_explicit_transitional_constraint(
        self,
        db_pool,
    ):
        """A specifically allowlisted transitional constraint is accepted."""
        expected = {
            name: spec
            for name, spec in SESSION_CONSTRAINT_CONTRACT.items()
            if name != "sessions_purpose_check"
        }

        await assert_table_constraint_contract(
            db_pool,
            "sessions",
            expected,
            allowed_extra_constraints={"sessions_purpose_check"},
        )

    @pytest.mark.parametrize(
        ("constraint_name", "replacement"),
        [
            (
                "sessions_purpose_check",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_purpose_check"],
                    check_definition="CHECK (false)",
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    on_delete="SET NULL",
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    referenced_table="email_outbox",
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    referenced_columns=("email",),
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    references_application_schema=False,
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    deferrable=True,
                ),
            ),
            (
                "sessions_user_id_fkey",
                replace(
                    SESSION_CONSTRAINT_CONTRACT["sessions_user_id_fkey"],
                    validated=False,
                ),
            ),
        ],
        ids=[
            "check-definition",
            "delete-action",
            "referenced-table",
            "referenced-column",
            "referenced-schema",
            "deferrability",
            "validation-state",
        ],
    )
    async def test_constraint_check_rejects_structural_drift(
        self,
        db_pool,
        constraint_name,
        replacement,
    ):
        """Changed CHECK and foreign-key properties all fail closed."""
        expected = {
            **SESSION_CONSTRAINT_CONTRACT,
            constraint_name: replacement,
        }

        with pytest.raises(
            RuntimeError,
            match=rf"'sessions'.*constraint {constraint_name!r}",
        ):
            await assert_table_constraint_contract(
                db_pool,
                "sessions",
                expected,
            )

    async def test_constraint_check_rejects_changed_unique_columns(
        self,
        db_pool,
    ):
        """Unique-constraint column order is part of the contract."""
        constraint_name = "datasets_source_uuid_key"
        replacement = replace(
            DATASET_CONSTRAINT_CONTRACT[constraint_name],
            columns=("uuid", "source"),
        )
        expected = {
            **DATASET_CONSTRAINT_CONTRACT,
            constraint_name: replacement,
        }

        with pytest.raises(
            RuntimeError,
            match=(
                r"'oral_history_datasets'.*constraint "
                r"'datasets_source_uuid_key'"
            ),
        ):
            await assert_table_constraint_contract(
                db_pool,
                "oral_history_datasets",
                expected,
            )

    async def test_validate_schema_rejects_contract_table_set_mismatch(self):
        """Column and constraint contracts must cover identical tables."""
        column_mock = create_autospec(db_drift.assert_table_column_contract, spec_set=True)
        constraint_mock = create_autospec(db_drift.assert_table_constraint_contract, spec_set=True)

        with (
            patch(
                "app.services.db_drift.TABLE_CONSTRAINT_CONTRACTS",
                {},
            ),
            patch(
                "app.services.db_drift.assert_table_column_contract",
                column_mock,
            ),
            patch(
                "app.services.db_drift.assert_table_constraint_contract",
                constraint_mock,
            ),
            pytest.raises(
                RuntimeError,
                match="Database contract table sets do not match",
            ),
        ):
            await validate_schema_against_db(object())

        column_mock.assert_not_awaited()
        constraint_mock.assert_not_awaited()


class TestStartupGuards:
    """The production lifespan (`app.main.lifespan`) refuses to boot when
    the live schema is behind the code's migration head, and leaves no
    resources open when it refuses.

    ``alembic_version`` is not reset by ``clean_db``. Every test that
    mutates it restores the original value in ``finally``, else the
    session migration breaks on the next run.
    """

    async def test_stale_schema_version_fails_closed(self, sync_conn, monkeypatch):
        """An older database revision must prevent application startup."""
        head = _current_version(sync_conn)
        sync_conn.execute("UPDATE alembic_version SET version_num = '000000000000'")
        sync_conn.commit()

        try:
            with _prod_mode(monkeypatch):
                await _enter_prod_lifespan_expecting(
                    r"Schema is at .*000000000000.*but code expects"
                )
        finally:
            sync_conn.execute(
                "UPDATE alembic_version SET version_num = %s",
                (head,),
            )
            sync_conn.commit()

    async def test_empty_alembic_version_fails_closed(self, sync_conn, monkeypatch):
        """An empty alembic_version table must prevent application startup."""
        head = _current_version(sync_conn)
        sync_conn.execute("DELETE FROM alembic_version")
        sync_conn.commit()

        try:
            with _prod_mode(monkeypatch):
                await _enter_prod_lifespan_expecting(r"empty alembic_version table")
        finally:
            sync_conn.execute(
                """
                INSERT INTO alembic_version (version_num)
                VALUES (%s)
                """,
                (head,),
            )
            sync_conn.commit()

    def test_matching_head_boots_and_serves(self, monkeypatch):
        """A database at the expected revision passes startup validation."""
        with (
            _prod_mode(monkeypatch),
            TestClient(
                app,
                base_url="http://localhost",
                raise_server_exceptions=False,
            ) as client,
        ):
            resp = client.get("/health")

            assert resp.status_code == status.HTTP_200_OK
            assert resp.json() == {"status": "alive"}

    async def test_failed_startup_closes_the_pool_it_opened(
        self,
        sync_conn,
        monkeypatch,
    ):
        """A failed startup must close the database pool it opened."""
        head = _current_version(sync_conn)
        sync_conn.execute("UPDATE alembic_version SET version_num = '000000000000'")
        sync_conn.commit()

        try:
            with _prod_mode(monkeypatch), pytest.raises(RuntimeError):
                async with lifespan(app):
                    pass  # pragma: no cover — startup must raise before entry

            pool = app.state.db_pool
            try:
                assert pool.closed, "failed startup left the connection pool open"
            finally:
                await pool.close()
        finally:
            sync_conn.execute(
                "UPDATE alembic_version SET version_num = %s",
                (head,),
            )
            sync_conn.commit()

    async def test_lifespan_invokes_tier_rank_guard(self, monkeypatch):
        """The shared runtime preflight must retain the tier-rank guard."""
        called = []

        monkeypatch.setattr(
            "app.runtime_preflight.assert_tier_rank_complete",
            lambda: called.append(True),
        )

        with _prod_mode(monkeypatch), contextlib.suppress(Exception):
            async with lifespan(app):
                pass

        assert called, "lifespan no longer runs the tier-rank drift guard"
