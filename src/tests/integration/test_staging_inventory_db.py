"""Collect retained-state evidence against PostgreSQL without exporting its data."""

import hashlib
import importlib.util
import json
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import ModuleType

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from app.paths import PROJECT_ROOT
from tests.integration.conftest import TEST_DATABASE_URL
from tests.source_fixtures import TEST_SOURCE_NAME

_STATE_TABLES = (
    "oral_history_datasets",
    "dataset_admin_state",
    "sync_status",
    "ingestion_failures",
    "users",
    "totp_recovery_codes",
    "admin_promotion_requests",
    "federation_policy_state",
    "email_outbox",
    "sessions",
    "pending_totp_rotations",
)


@pytest.fixture(scope="module")
def inventory_module() -> ModuleType:
    """Load the staging-inventory script directly from its repository path."""
    spec = importlib.util.spec_from_file_location(
        "staging_inventory_db_under_test", PROJECT_ROOT / "scripts" / "inventory_staging.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _collect(module: ModuleType):
    """Collect the staging inventory through an autocommit observer connection."""
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        return module.collect_inventory(conn, conn.info.dbname)


def _state_snapshot(conn):
    """Read every tracked staging table in deterministic JSON order."""
    return {
        table: conn.execute(
            sql.SQL(
                "SELECT to_jsonb(record) FROM public.{} AS record ORDER BY to_jsonb(record)::text"
            ).format(sql.Identifier(table))
        ).fetchall()
        for table in _STATE_TABLES
    }


@contextmanager
def _renamed_relation(conn, table: str) -> Iterator[None]:
    """Preserve an old fixture shape without dropping data or dependencies."""
    retained = "inventory_retained_" + secrets.token_hex(6)
    conn.execute(
        sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
            sql.Identifier(table), sql.Identifier(retained)
        )
    )
    conn.commit()
    try:
        yield
    finally:
        conn.rollback()
        conn.execute(
            sql.SQL("ALTER TABLE public.{} RENAME TO {}").format(
                sql.Identifier(retained), sql.Identifier(table)
            )
        )
        conn.commit()


@contextmanager
def _limited_login() -> Iterator[psycopg.Connection]:
    """An actual nonowner login, with SELECT but no RLS bypass, in this test DB."""
    role = "inventory_probe_" + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOINHERIT").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        try:
            admin.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(admin.info.dbname), sql.Identifier(role)
                )
            )
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
            )
            admin.execute(
                sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(
                    sql.Identifier(role)
                )
            )
            with psycopg.connect(
                make_conninfo(TEST_DATABASE_URL, user=role, password=password), autocommit=True
            ) as conn:
                yield conn
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_counts_and_source_progress_preserve_every_private_row(
    inventory_module, sync_conn, dataset_factory, user_factory
):
    """Verify counts and source progress preserve every private row."""
    canary = "INVENTORY_PRIVATE_" + secrets.token_hex(12)
    fingerprint = canary + "_fingerprint"
    staged = (canary + "_staged_token_and_ciphertext").encode()
    cursor = datetime(2026, 1, 4, 12, 30, tzinfo=UTC)
    dataset_factory(title=canary, data=Jsonb({"private_metadata": canary}))
    dataset_factory(visibility_tier="vetted", description=canary)
    user_factory(email=canary.lower() + "@example.org", display_name=canary, totp_secret=canary)
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) VALUES (%s, %s, %s)",
        (TEST_SOURCE_NAME, "retained-admin-state", cursor),
    )
    sync_conn.execute(
        "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
        (TEST_SOURCE_NAME, "retained-failure", canary),
    )
    sync_conn.execute(
        "UPDATE sync_status SET source_cursor = %s, source_fingerprint = %s, "
        "last_sync_error = %s, last_rebuild_error = %s, incremental_harvest = %s, "
        "incremental_started_at = %s, incremental_position = 2, incremental_affected = 1 "
        "WHERE source = %s",
        (cursor, fingerprint, canary, canary, staged, cursor, TEST_SOURCE_NAME),
    )
    sync_conn.commit()
    before = _state_snapshot(sync_conn)
    revisions = [
        row[0]
        for row in sync_conn.execute("SELECT version_num FROM alembic_version ORDER BY version_num")
    ]
    sync_conn.commit()

    report = _collect(inventory_module)

    tables = {row["table"]: row for row in report["managed_state"]["tables"]}
    assert set(_STATE_TABLES) <= tables.keys()
    assert {table: tables[table]["rows"] for table in _STATE_TABLES} == {
        table: len(rows) for table, rows in before.items()
    }
    assert all(tables[table]["present"] for table in _STATE_TABLES)
    assert report["managed_state"]["alembic_revision_status"] == "collected"
    assert report["managed_state"]["alembic_revisions"] == [
        {
            "version_num": revision,
            "version_num_sha256": hashlib.sha256(revision.encode()).hexdigest(),
        }
        for revision in revisions
    ]
    assert report["managed_state"]["missing_state_columns"] == []
    source = next(
        row for row in report["managed_state"]["sources"] if row["source"] == TEST_SOURCE_NAME
    )
    assert source["source_cursor"] == cursor.isoformat()
    assert source["stored_fingerprint_sha256"] == hashlib.sha256(fingerprint.encode()).hexdigest()
    assert source["staged_payload_present"] is True
    assert source["staged_payload_bytes"] == len(staged)
    assert source["incremental_started_at"] == cursor.isoformat()
    assert source["incremental_position"] == 2
    assert source["incremental_affected"] == 1
    assert canary not in json.dumps(report)
    assert canary.lower() not in json.dumps(report)
    assert fingerprint not in json.dumps(report)
    assert staged.hex() not in json.dumps(report)
    assert hashlib.sha256(fingerprint.encode()).hexdigest() in json.dumps(report)
    assert _state_snapshot(sync_conn) == before
    sync_conn.commit()


def test_catalogue_definitions_and_defaults_are_digest_only(inventory_module, sync_conn):
    """Verify catalogue definitions and defaults are digest only."""
    canary = "INVENTORY_SECRET_LITERAL_" + secrets.token_hex(12)
    function_body = "SELECT '" + canary + "'::text"
    probe = "inventory_schema_probe_" + secrets.token_hex(6)
    identifier = sql.Identifier(probe)
    sync_conn.execute(
        sql.SQL("CREATE TABLE public.{} (private_value text DEFAULT {})").format(
            identifier, sql.Literal(canary)
        )
    )
    sync_conn.execute(
        sql.SQL("CREATE FUNCTION public.{}() RETURNS text LANGUAGE sql AS {}").format(
            identifier, sql.Literal(function_body)
        )
    )
    sync_conn.execute(
        sql.SQL("CREATE VIEW public.{} AS SELECT {}::text AS private_value").format(
            sql.Identifier(probe + "_view"), sql.Literal(canary)
        )
    )
    sync_conn.commit()
    try:
        report = _collect(inventory_module)
        encoded = json.dumps(report)
        assert canary not in encoded
        assert probe in encoded
        column = next(row for row in report["catalog"]["columns"] if row["relation_name"] == probe)
        routine = next(row for row in report["catalog"]["routines"] if row["routine_name"] == probe)
        view = next(
            row for row in report["catalog"]["views"] if row["view_name"] == probe + "_view"
        )
        assert routine["source_sha256"] == hashlib.sha256(function_body.encode()).hexdigest()
        for digest in (
            column["default_sha256"],
            routine["definition_sha256"],
            view["definition_sha256"],
        ):
            assert len(digest) == 64
            assert int(digest, 16) >= 0
    finally:
        sync_conn.rollback()
        sync_conn.execute(sql.SQL("DROP VIEW public.{}").format(sql.Identifier(probe + "_view")))
        sync_conn.execute(sql.SQL("DROP FUNCTION public.{}()").format(identifier))
        sync_conn.execute(sql.SQL("DROP TABLE public.{}").format(identifier))
        sync_conn.commit()


def test_snapshot_is_read_only_repeatable_and_local_settings_do_not_escape(
    inventory_module, monkeypatch
):
    """Verify snapshot is read only repeatable and local settings do not escape."""
    bounded_rows = inventory_module._bounded_rows
    observed_settings = []

    def inspect_snapshot(connection, *args, **kwargs):
        """Check the inventory transaction is read-only and consistently configured before
        continuing.
        """
        if not observed_settings:
            observed_settings.append(
                connection.execute(
                    "SELECT current_setting('transaction_read_only'), "
                    "current_setting('transaction_isolation'), current_setting('row_security')"
                ).fetchone()
            )
            # A zero-row write has no retained-state effect even if the guard
            # breaks. Its rejection proves PostgreSQL enforces READ ONLY.
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), connection.transaction():
                connection.execute(
                    "UPDATE public.sync_status SET last_sync_error = last_sync_error WHERE false"
                )
        return bounded_rows(connection, *args, **kwargs)

    monkeypatch.setattr(inventory_module, "_bounded_rows", inspect_snapshot)
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        before = conn.execute(
            "SELECT current_setting('transaction_read_only'), "
            "current_setting('transaction_isolation'), current_setting('statement_timeout'), "
            "current_setting('lock_timeout'), current_setting('row_security')"
        ).fetchone()

        report = inventory_module.collect_inventory(conn, conn.info.dbname)

        assert observed_settings == [("on", "repeatable read", "off")]
        assert report["identity"]["transaction_read_only"] == "on"
        assert report["identity"]["transaction_isolation"] == "repeatable read"
        assert report["identity"]["row_security"] == "off"
        assert conn.info.transaction_status is TransactionStatus.IDLE
        assert (
            conn.execute(
                "SELECT current_setting('transaction_read_only'), "
                "current_setting('transaction_isolation'), current_setting('statement_timeout'), "
                "current_setting('lock_timeout'), current_setting('row_security')"
            ).fetchone()
            == before
        )


@pytest.mark.parametrize("table", ["ingestion_failures", "sync_status", "alembic_version"])
def test_missing_retained_table_is_explicit_instead_of_zero(inventory_module, sync_conn, table):
    """Verify missing retained table is explicit instead of zero."""
    with _renamed_relation(sync_conn, table):
        report = _collect(inventory_module)
        entry = next(row for row in report["managed_state"]["tables"] if row["table"] == table)
        assert entry["present"] is False
        assert "rows" not in entry
        assert entry["status"] != "complete"
        if table == "alembic_version":
            assert report["managed_state"]["alembic_revision_status"] == "missing"
            assert report["managed_state"]["alembic_revisions"] == []


def test_older_source_progress_column_is_reported_missing(inventory_module, sync_conn):
    """Verify older source progress column is reported missing."""
    sync_conn.execute(
        "ALTER TABLE public.sync_status RENAME COLUMN incremental_affected TO retained_affected"
    )
    sync_conn.commit()
    try:
        report = _collect(inventory_module)
        assert "incremental_affected" in json.dumps(
            report["managed_state"]["missing_state_columns"]
        )
        assert all(
            "incremental_affected" not in source for source in report["managed_state"]["sources"]
        )
    finally:
        sync_conn.rollback()
        sync_conn.execute(
            "ALTER TABLE public.sync_status RENAME COLUMN retained_affected TO incremental_affected"
        )
        sync_conn.commit()


def test_unexpected_source_cursor_type_is_not_exported_as_safe_state(inventory_module, sync_conn):
    """Verify unexpected source cursor type is not exported as safe state."""
    canary = "INVENTORY_UNTRUSTED_CURSOR_" + secrets.token_hex(12)
    sync_conn.execute(
        "ALTER TABLE public.sync_status RENAME COLUMN source_cursor TO retained_source_cursor"
    )
    sync_conn.execute(
        sql.SQL("ALTER TABLE public.sync_status ADD COLUMN source_cursor text DEFAULT {}").format(
            sql.Literal(canary)
        )
    )
    sync_conn.commit()
    try:
        report = _collect(inventory_module)
        assert canary not in json.dumps(report)
        assert "source_cursor" in json.dumps(report["managed_state"]["missing_state_columns"])
        assert all("source_cursor" not in source for source in report["managed_state"]["sources"])
    finally:
        sync_conn.rollback()
        sync_conn.execute("ALTER TABLE public.sync_status DROP COLUMN source_cursor")
        sync_conn.execute(
            "ALTER TABLE public.sync_status RENAME COLUMN retained_source_cursor TO source_cursor"
        )
        sync_conn.commit()


def test_database_identity_must_match_the_operator_target(inventory_module):
    """Verify database identity must match the operator target."""
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        with pytest.raises(inventory_module.InventoryRefusal):
            inventory_module.collect_inventory(conn, conn.info.dbname + "_wrong")
        assert conn.info.transaction_status is TransactionStatus.IDLE


@pytest.mark.parametrize("state", ["non_autocommit", "existing_transaction"])
def test_collector_refuses_to_reuse_an_operator_transaction(inventory_module, state):
    """Verify collector refuses to reuse an operator transaction."""
    with psycopg.connect(TEST_DATABASE_URL, autocommit=state != "non_autocommit") as conn:
        if state == "existing_transaction":
            conn.execute("BEGIN")
            conn.execute("SELECT 1")
        before = conn.info.transaction_status
        with pytest.raises(inventory_module.InventoryRefusal):
            inventory_module.collect_inventory(conn, conn.info.dbname)
        assert conn.info.transaction_status is before
        conn.rollback()


def test_rls_filtered_zero_is_refused_as_an_incomplete_baseline(inventory_module, dataset_factory):
    """Verify RLS filtered zero is refused as an incomplete baseline."""
    dataset_factory(title="Retained restricted catalogue", visibility_tier="vetted")
    with _limited_login() as conn:
        # This really is a separate session identity with SELECT: RLS, rather
        # than lack of table access, removes the retained catalogue row.
        assert conn.execute("SELECT current_user = session_user").fetchone() == (True,)
        assert conn.execute("SELECT count(*) FROM public.oral_history_datasets").fetchone() == (0,)
        with pytest.raises(inventory_module.InventoryRefusal, match="row security"):
            inventory_module.collect_inventory(conn, conn.info.dbname)
        assert conn.info.transaction_status is TransactionStatus.IDLE
