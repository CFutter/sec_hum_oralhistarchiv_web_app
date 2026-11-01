"""Reject historical PostgreSQL 16 upgrades without changing the current schema."""

import os
import re
import shutil
import subprocess

import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from app.paths import PROJECT_ROOT
from app.services.db_drift import validate_schema_against_db


def catalogue_snapshot(connection):
    """Snapshot stored catalogue, source, account and revision state."""
    result = {}
    for table in (
        "oral_history_datasets",
        "dataset_admin_state",
        "sync_status",
        "ingestion_failures",
        "users",
        "alembic_version",
    ):
        result[table] = connection.execute(
            sql.SQL(
                "SELECT to_jsonb(stored) FROM public.{} AS stored ORDER BY to_jsonb(stored)::text"
            ).format(sql.Identifier(table))
        ).fetchall()
    return result


def search_objects(connection):
    """Snapshot search definitions and view options/grants without rewriting them."""
    columns = connection.execute(
        """SELECT attname, atttypid::regtype::text, attnotnull
           FROM pg_attribute WHERE attrelid = 'public.oral_history_datasets'::regclass
             AND attname IN ('search_vector_public', 'search_vector_full')
             AND attnum > 0 AND NOT attisdropped ORDER BY attname"""
    ).fetchall()
    indexes = connection.execute(
        """SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'
           AND indexname IN ('idx_search_vector_public', 'idx_search_vector_full')
           ORDER BY indexname"""
    ).fetchall()
    view = connection.execute(
        """SELECT pg_get_viewdef(oid, false), reloptions, relacl::text
           FROM pg_class WHERE oid = 'public.catalogue_search_candidates'::regclass"""
    ).fetchone()
    function = connection.execute(
        "SELECT prosrc FROM pg_proc WHERE oid = 'public.update_search_text()'::regprocedure"
    ).fetchone()
    triggers = connection.execute(
        """SELECT pg_get_triggerdef(oid, false) FROM pg_trigger
           WHERE tgrelid = 'public.oral_history_datasets'::regclass AND NOT tgisinternal
           ORDER BY tgname"""
    ).fetchall()
    return columns, indexes, view, function, triggers


def run_upgrade(connection, *, expected_database=None):
    """Run historical SQL via psql against an explicitly disposable test database."""
    psql = shutil.which("psql")
    assert psql is not None, "Manual search-schema upgrade rehearsal requires native psql on PATH"
    selected = connection.info.dbname
    assert selected is not None and re.fullmatch(r".*_test(?:_gw\d+)?", selected), (
        "Manual upgrade rehearsal requires the explicitly disposable test database"
    )
    # psycopg's info.dsn never includes the password. Keep the cached password
    # in the child environment, matching the already-open fixture connection.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("PG")}
    environment.update(
        PGPASSWORD=connection.info.password, PGCONNECT_TIMEOUT="5", PGPASSFILE="/dev/null"
    )
    arguments = [psql, "--no-psqlrc", "--no-password", "--dbname", connection.info.dsn]
    if expected_database is not None:
        arguments.extend(["--set", f"expected_database={expected_database}"])
    arguments.extend(["--file", str(PROJECT_ROOT / "deploy/upgrade-search-k2.sql")])
    connection.commit()
    return subprocess.run(
        arguments, env=environment, capture_output=True, text=True, check=False, timeout=90
    )


async def test_historical_upgrade_refuses_postgresql18_without_changes(
    db_pool, sync_conn, dataset_factory
):
    """Refuse the PostgreSQL 16 upgrade before changing current data, definitions or grants."""
    assert sync_conn.info.server_version // 10000 == 18
    await validate_schema_against_db(db_pool)
    dataset_factory(
        source="upgrade_archive",
        uuid="retained",
        title="publicretainedtoken",
        description="privateretainedtoken",
        access_level="restricted",
        visibility_tier="registered",
        data=Jsonb({"raw": "preserved", "nested": [1, None]}),
    )
    dataset_factory(source="upgrade_archive", uuid="hidden", visibility_tier="vetted")
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at) VALUES ('upgrade_archive', 'retained', 'vetted', NULL), ('upgrade_archive', 'hidden', NULL, clock_timestamp())"
    )
    sync_conn.execute(
        """INSERT INTO sync_status (source, source_cursor, source_fingerprint, incremental_harvest,
                  incremental_started_at, incremental_position, incremental_affected)
           VALUES ('upgrade_archive', '2026-10-19T00:00:00Z', %s, %s, clock_timestamp(), 1, 1)""",
        ("a" * 64, b"opaque staged preservation canary"),
    )
    before = catalogue_snapshot(sync_conn), search_objects(sync_conn)
    result = run_upgrade(sync_conn, expected_database=sync_conn.info.dbname)
    assert result.returncode != 0
    assert "K2 upgrade requires PostgreSQL 16" in result.stderr
    assert (catalogue_snapshot(sync_conn), search_objects(sync_conn)) == before
    await validate_schema_against_db(db_pool)


@pytest.mark.parametrize("target", ["wrong_name", "missing_name"])
async def test_manual_upgrade_requires_explicit_matching_database_without_changes(
    db_pool, sync_conn, dataset_factory, target
):
    """Refuse missing or mismatched targets without changing current data or search objects."""
    await validate_schema_against_db(db_pool)
    dataset_factory(title="targetpreservationcanary")
    before = catalogue_snapshot(sync_conn), search_objects(sync_conn)
    result = run_upgrade(
        sync_conn,
        expected_database=(sync_conn.info.dbname + "_wrong") if target == "wrong_name" else None,
    )
    assert result.returncode != 0
    expected = (
        "K2 database name differs from the reviewed target"
        if target == "wrong_name"
        else "Refused: supply -v expected_database=the_reviewed_database_name"
    )
    assert expected in result.stderr
    assert (catalogue_snapshot(sync_conn), search_objects(sync_conn)) == before
    await validate_schema_against_db(db_pool)
