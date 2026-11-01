#!/usr/bin/env python3
"""Collect a restricted, read-only PostgreSQL 18 staging inventory.

Use libpq environment/service authentication and an explicit expected database.
The output records catalog facts and safe state aggregates, not a backup,
contract-validation result, configuration dump or permission to perform an
upgrade. Existing application preflights remain the contract authorities.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row


def _checkout_root(script: Path) -> Path | None:
    """Infer this checkout only from its layout; standalone copies have no inferred root."""
    script = script.resolve()
    candidate = script.parent.parent
    if (
        script.parent.name == "scripts"
        and (candidate / "pyproject.toml").is_file()
        and (candidate / "src/app").is_dir()
    ):
        return candidate
    return None


PROJECT_ROOT = _checkout_root(Path(__file__))
_MAX_ROWS = 10_000
_REPORT_VERSION = 1
_MIN_SERVER_VERSION = 180_000
_MAX_SERVER_VERSION = 190_000
_PRIVATE_DIRECTORY_MODE = 0o700
_CONNECTION_OPTIONS = (
    "-c default_transaction_read_only=on -c statement_timeout=30000 "
    "-c lock_timeout=5000 -c search_path=pg_catalog -c row_security=off"
)
_MANAGED_TABLES = (
    "alembic_version",
    "oral_history_datasets",
    "dataset_admin_state",
    "sync_status",
    "ingestion_failures",
    "ingestion_quarantine",
    "source_security_state",
    "source_binding_acknowledgements",
    "security_audit_events",
    "security_audit_receipts",
    "anonymous_mail_issuance",
    "catalogue_search_policy",
    "catalogue_search_public",
    "catalogue_search_registered",
    "catalogue_search_vetted",
    "users",
    "totp_recovery_codes",
    "admin_promotion_requests",
    "federation_policy_state",
    "email_outbox",
    "sessions",
    "pending_totp_rotations",
)
_SOURCE_COLUMNS = {
    "source": "text",
    "source_cursor": "timestamp with time zone",
    "source_fingerprint": "text",
    "source_fetch_cursor": "timestamp with time zone",
    "source_fetch_fingerprint": "text",
    "incremental_harvest": "bytea",
    "incremental_started_at": "timestamp with time zone",
    "incremental_position": "integer",
    "incremental_affected": "integer",
    "last_harvest_date": "timestamp with time zone",
    "last_full_rebuild_date": "timestamp with time zone",
}

# Hash arbitrary expression/source/configuration text inside PostgreSQL: its
# raw form must never enter the serialized inventory or an exception message.
_HASH = "pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to({value}, 'UTF8')), 'hex')"
_ROLE_SCOPE = """
WITH RECURSIVE relevant_roles(oid) AS (
    SELECT role.oid FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = CURRENT_USER
       OR role.rolname IN ('oralhistarchiv', 'oralhistarchiv_web',
                          'oralhistarchiv_scheduler', 'oralhistarchiv_backup')
       OR role.oid IN (
           SELECT relation.relowner FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = 'public'
           UNION SELECT routine.proowner FROM pg_catalog.pg_proc AS routine
           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
           WHERE namespace.nspname = 'public'
           UNION SELECT namespace.nspowner FROM pg_catalog.pg_namespace AS namespace
           WHERE namespace.nspname = 'public'
           UNION SELECT database.datdba FROM pg_catalog.pg_database AS database
           WHERE database.datname = pg_catalog.current_database()
       )
    UNION
    SELECT membership.roleid
    FROM pg_catalog.pg_auth_members AS membership
    JOIN relevant_roles AS relevant ON relevant.oid = membership.member
)
"""
_IDENTITY_QUERY = """
SELECT pg_catalog.current_database() AS database,
       CURRENT_USER::text AS current_user, SESSION_USER::text AS session_user,
       pg_catalog.current_setting('server_version_num')::integer AS server_version_num,
       pg_catalog.current_setting('transaction_read_only') AS transaction_read_only,
       pg_catalog.current_setting('transaction_isolation') AS transaction_isolation,
       pg_catalog.current_setting('row_security') AS row_security,
       pg_catalog.transaction_timestamp() AS captured_at,
       role.rolsuper AS is_superuser, role.rolbypassrls AS bypass_rls
FROM pg_catalog.pg_roles AS role WHERE role.rolname = CURRENT_USER
"""

_CATALOG_QUERIES = {
    "database": """
        SELECT database.datname AS database,
               pg_catalog.pg_get_userbyid(database.datdba) AS owner,
               pg_catalog.pg_encoding_to_char(database.encoding) AS encoding,
               database.datcollate AS collation, database.datctype AS character_type
        FROM pg_catalog.pg_database AS database
        WHERE database.datname = pg_catalog.current_database()
    """,
    "schema": """
        SELECT namespace.nspname AS schema,
               pg_catalog.pg_get_userbyid(namespace.nspowner) AS owner
        FROM pg_catalog.pg_namespace AS namespace WHERE namespace.nspname = 'public'
    """,
    "relations": """
        SELECT relation.relname AS relation_name, relation.relkind AS relation_kind,
               pg_catalog.pg_get_userbyid(relation.relowner) AS owner,
               relation.relrowsecurity AS rls_enabled,
               relation.relforcerowsecurity AS rls_forced,
               CASE WHEN relation.relkind = 'S' THEN
                   pg_catalog.has_sequence_privilege(CURRENT_USER, relation.oid, 'SELECT')
               ELSE pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'SELECT') END
                   AS select_granted
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public' AND relation.relkind IN ('r','p','v','m','f','S')
        ORDER BY relation.relname
    """,
    "columns": """
        SELECT relation.relname AS relation_name, attribute.attname AS column_name,
               attribute.attnum AS position,
               pg_catalog.format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
               attribute.attnotnull AS not_null, attribute.attidentity AS identity_mode,
               attribute.attgenerated AS generated_mode,
               CASE WHEN defaults.oid IS NULL THEN NULL ELSE {default_hash} END
                   AS default_sha256
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        LEFT JOIN pg_catalog.pg_attrdef AS defaults
            ON defaults.adrelid = relation.oid AND defaults.adnum = attribute.attnum
        WHERE namespace.nspname = 'public' AND relation.relkind IN ('r','p','v','m','f')
          AND attribute.attnum > 0 AND NOT attribute.attisdropped
        ORDER BY relation.relname, attribute.attnum
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        default_hash=_HASH.format(value="pg_catalog.pg_get_expr(defaults.adbin, defaults.adrelid)")
    ),
    "constraints": """
        SELECT relation.relname AS relation_name, constraint_record.conname AS constraint_name,
               constraint_record.contype AS constraint_type,
               constraint_record.convalidated AS validated,
               constraint_record.condeferrable AS deferrable,
               constraint_record.condeferred AS initially_deferred,
               {definition_hash} AS definition_sha256
        FROM pg_catalog.pg_constraint AS constraint_record
        JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_record.conrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
        ORDER BY relation.relname, constraint_record.conname
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        definition_hash=_HASH.format(
            value="pg_catalog.pg_get_constraintdef(constraint_record.oid, false)"
        )
    ),
    "indexes": """
        SELECT relation.relname AS relation_name, index_class.relname AS index_name,
               index_record.indisunique AS unique, index_record.indisprimary AS primary_key,
               index_record.indisvalid AS valid, index_record.indisready AS ready,
               index_record.indislive AS live, access_method.amname AS access_method,
               {definition_hash} AS definition_sha256
        FROM pg_catalog.pg_index AS index_record
        JOIN pg_catalog.pg_class AS relation ON relation.oid = index_record.indrelid
        JOIN pg_catalog.pg_class AS index_class ON index_class.oid = index_record.indexrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_class.relam
        WHERE namespace.nspname = 'public'
        ORDER BY relation.relname, index_class.relname
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        definition_hash=_HASH.format(value="pg_catalog.pg_get_indexdef(index_record.indexrelid)")
    ),
    "routines": """
        SELECT routine.proname AS routine_name,
               pg_catalog.pg_get_function_identity_arguments(routine.oid) AS identity_arguments,
               routine.prokind AS routine_kind,
               pg_catalog.pg_get_userbyid(routine.proowner) AS owner,
               language.lanname AS language, routine.provolatile AS volatility,
               routine.prosecdef AS security_definer, routine.proisstrict AS strict,
               routine.proparallel AS parallel_mode,
               {source_hash} AS source_sha256,
               CASE WHEN routine.prokind = 'a' THEN NULL ELSE {definition_hash} END
                   AS definition_sha256,
               CASE WHEN routine.proconfig IS NULL THEN NULL ELSE {config_hash} END
                   AS configuration_sha256
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        JOIN pg_catalog.pg_language AS language ON language.oid = routine.prolang
        WHERE namespace.nspname = 'public'
        ORDER BY routine.proname, identity_arguments
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        source_hash=_HASH.format(value="routine.prosrc"),
        definition_hash=_HASH.format(value="pg_catalog.pg_get_functiondef(routine.oid)"),
        config_hash=_HASH.format(value="pg_catalog.array_to_string(routine.proconfig, E'\\n')"),
    ),
    "triggers": """
        SELECT relation.relname AS relation_name, trigger_record.tgname AS trigger_name,
               trigger_record.tgenabled AS enabled, trigger_record.tgisinternal AS internal,
               {definition_hash} AS definition_sha256
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
        ORDER BY relation.relname, trigger_record.tgname
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        definition_hash=_HASH.format(
            value="pg_catalog.pg_get_triggerdef(trigger_record.oid, false)"
        )
    ),
    "views": """
        SELECT relation.relname AS view_name, relation.relkind AS relation_kind,
               pg_catalog.pg_get_userbyid(relation.relowner) AS owner,
               {definition_hash} AS definition_sha256,
               CASE WHEN relation.reloptions IS NULL THEN NULL ELSE {options_hash} END
                   AS options_sha256,
               pg_catalog.array_agg(attribute.attname::text ORDER BY attribute.attnum)
                   FILTER (WHERE attribute.attnum > 0 AND NOT attribute.attisdropped) AS columns
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        LEFT JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
        WHERE namespace.nspname = 'public' AND relation.relkind IN ('v','m')
        GROUP BY relation.oid, relation.relname, relation.relkind, relation.relowner,
                 relation.reloptions
        ORDER BY relation.relname
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        definition_hash=_HASH.format(value="pg_catalog.pg_get_viewdef(relation.oid, false)"),
        options_hash=_HASH.format(value="pg_catalog.array_to_string(relation.reloptions, E'\\n')"),
    ),
    "policies": """
        SELECT relation.relname AS relation_name, policy.polname AS policy_name,
               policy.polcmd AS command, policy.polpermissive AS permissive,
               ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC'
                                 ELSE pg_catalog.pg_get_userbyid(role_oid)::text END
                     FROM pg_catalog.unnest(policy.polroles) AS role_oid ORDER BY 1) AS roles,
               CASE WHEN policy.polqual IS NULL THEN NULL ELSE {using_hash} END AS using_sha256,
               CASE WHEN policy.polwithcheck IS NULL THEN NULL ELSE {check_hash} END
                   AS with_check_sha256
        FROM pg_catalog.pg_policy AS policy
        JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
        ORDER BY relation.relname, policy.polname
    """.format(  # nosec B608 # Fixed SHA256 fragments only; no external input.
        using_hash=_HASH.format(value="pg_catalog.pg_get_expr(policy.polqual, policy.polrelid)"),
        check_hash=_HASH.format(
            value="pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid)"
        ),
    ),
    "acls": """
        SELECT 'relation'::text AS object_kind, relation.relname::text AS object_name,
               pg_catalog.pg_get_userbyid(relation.relowner)::text AS owner,
               relation.relacl::text[] AS explicit_acl
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public' AND relation.relkind IN ('r','p','v','m','f','S')
        UNION ALL
        SELECT 'column', relation.relname::text || '.' || attribute.attname::text,
               pg_catalog.pg_get_userbyid(relation.relowner)::text, attribute.attacl::text[]
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public' AND attribute.attnum > 0
          AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
        UNION ALL
        SELECT 'routine', routine.proname::text || '(' ||
               pg_catalog.pg_get_function_identity_arguments(routine.oid) || ')',
               pg_catalog.pg_get_userbyid(routine.proowner)::text, routine.proacl::text[]
        FROM pg_catalog.pg_proc AS routine
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
        WHERE namespace.nspname = 'public'
        UNION ALL
        SELECT 'schema', namespace.nspname::text,
               pg_catalog.pg_get_userbyid(namespace.nspowner)::text, namespace.nspacl::text[]
        FROM pg_catalog.pg_namespace AS namespace WHERE namespace.nspname = 'public'
        UNION ALL
        SELECT 'database', database.datname::text,
               pg_catalog.pg_get_userbyid(database.datdba)::text, database.datacl::text[]
        FROM pg_catalog.pg_database AS database
        WHERE database.datname = pg_catalog.current_database()
        ORDER BY object_kind, object_name
    """,
    "default_acls": """
        SELECT pg_catalog.pg_get_userbyid(default_acl.defaclrole) AS owner,
               namespace.nspname AS schema, default_acl.defaclobjtype AS object_type,
               default_acl.defaclacl::text[] AS explicit_acl
        FROM pg_catalog.pg_default_acl AS default_acl
        LEFT JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = default_acl.defaclnamespace
        WHERE default_acl.defaclnamespace = 0 OR namespace.nspname = 'public'
        ORDER BY owner, schema, object_type
    """,
    "roles": _ROLE_SCOPE
    + """
        SELECT role.rolname AS role_name, role.rolsuper AS superuser,
               role.rolinherit AS inherits, role.rolcreaterole AS create_role,
               role.rolcreatedb AS create_database, role.rolcanlogin AS can_login,
               role.rolreplication AS replication, role.rolbypassrls AS bypass_rls,
               role.rolconnlimit AS connection_limit
        FROM pg_catalog.pg_roles AS role
        JOIN relevant_roles AS relevant ON relevant.oid = role.oid ORDER BY role.rolname
    """,  # nosec B608 # Fixed relevant-role SQL fragment only; no external input.
    "memberships": _ROLE_SCOPE
    + """
        SELECT role.rolname AS role_name, member.rolname AS member_name,
               membership.admin_option, membership.inherit_option, membership.set_option
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS role ON role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
        WHERE membership.roleid IN (SELECT oid FROM relevant_roles)
           OR membership.member IN (SELECT oid FROM relevant_roles)
        ORDER BY role.rolname, member.rolname
    """,  # nosec B608 # Fixed relevant-role SQL fragment only; no external input.
    "role_settings": _ROLE_SCOPE
    + """
        SELECT CASE WHEN setting.setrole = 0 THEN 'ALL' ELSE role.rolname::text END AS role_name,
               CASE WHEN setting.setdatabase = 0 THEN 'ALL'
                    ELSE database.datname::text END AS database,
               pg_catalog.split_part(entry.value, '=', 1) AS setting_name,
               {value_hash} AS value_sha256
        FROM pg_catalog.pg_db_role_setting AS setting
        LEFT JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
        LEFT JOIN pg_catalog.pg_database AS database ON database.oid = setting.setdatabase
        CROSS JOIN LATERAL pg_catalog.unnest(setting.setconfig) AS entry(value)
        WHERE (setting.setrole = 0 OR setting.setrole IN (SELECT oid FROM relevant_roles))
          AND (setting.setdatabase = 0 OR database.datname = pg_catalog.current_database())
        ORDER BY role_name, database, setting_name
    """.format(  # nosec B608 # Fixed role and SHA256 fragments; no external input.
        value_hash=_HASH.format(
            value="pg_catalog.substr(entry.value, pg_catalog.strpos(entry.value, '=') + 1)"
        )
    ),
    "extensions": """
        SELECT extension.extname AS extension_name, extension.extversion AS version,
               namespace.nspname AS schema,
               pg_catalog.pg_get_userbyid(extension.extowner) AS owner
        FROM pg_catalog.pg_extension AS extension
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = extension.extnamespace
        ORDER BY extension.extname
    """,
}


class InventoryRefusal(ValueError):
    """The inventory cannot establish its read-only or private-output boundary."""


def _bounded_rows(
    connection: psycopg.Connection[Any],
    label: str,
    query: str | sql.Composed,
    params: tuple[object, ...] | None = None,
) -> list[dict[str, Any]]:
    """Fetch a bounded named section; database errors propagate without serialization."""
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, params)
        rows = cursor.fetchmany(_MAX_ROWS + 1)
    if len(rows) > _MAX_ROWS:
        raise InventoryRefusal(f"Inventory section exceeds the row limit: {label}")
    return rows


def _identity(connection: psycopg.Connection[Any], label: str) -> dict[str, Any]:
    """Require exactly one database identity row; otherwise raise InventoryRefusal."""
    rows = _bounded_rows(connection, label, _IDENTITY_QUERY)
    if len(rows) != 1:
        raise InventoryRefusal("Database identity could not be established")
    return rows[0]


def _require_read_only(identity: dict[str, Any]) -> None:
    """Require read-only repeatable-read state with row_security off; otherwise raise
    InventoryRefusal.
    """
    if (
        identity.get("transaction_read_only") != "on"
        or identity.get("transaction_isolation") != "repeatable read"
        or identity.get("row_security") != "off"
    ):
        raise InventoryRefusal(
            "A read-only repeatable-read snapshot with row-security guard is required"
        )


def _safe_value(value: Any) -> Any:
    """Only JSON primitives and UTC datetimes enter the report; never stringify opaque values."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise InventoryRefusal("A timestamp without timezone cannot enter the inventory")
        return value.astimezone(UTC).isoformat()
    if isinstance(value, dict):
        return {key: _safe_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_safe_value(item) for item in value]
    raise InventoryRefusal("An unexpected value type cannot enter the inventory")


def _require_count_visibility(relation: dict[str, Any], identity: dict[str, Any]) -> None:
    """Require SELECT and unfiltered managed-table visibility; otherwise raise InventoryRefusal."""
    if relation.get("select_granted") is not True:
        raise InventoryRefusal("Full SELECT access to managed tables is required")
    bypass = identity.get("is_superuser") is True or identity.get("bypass_rls") is True
    owner_without_force = (
        relation.get("owner") == identity["current_user"] and relation.get("rls_forced") is False
    )
    if relation.get("rls_enabled") is True and not (bypass or owner_without_force):
        raise InventoryRefusal("Managed-table visibility may be filtered by row security")


def _source_state(
    connection: psycopg.Connection[Any],
    columns: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read supported sync columns as safe progress/hash aggregates; return rows and
    missing/wrong-type names.
    """
    present = {
        row["column_name"]: row["data_type"]
        for row in columns
        if row.get("relation_name") == "sync_status"
    }
    safe = {name for name, kind in _SOURCE_COLUMNS.items() if present.get(name) == kind}
    missing = sorted(set(_SOURCE_COLUMNS) - safe)
    if "source" not in safe:
        return [], missing
    expressions: list[sql.Composable] = [
        sql.SQL("CASE WHEN source ~ '^[a-z0-9_]{1,32}$' THEN source ELSE NULL END AS source"),
        sql.SQL(_HASH.format(value="source") + " AS source_sha256"),
    ]
    for name in _SOURCE_COLUMNS:
        if name not in safe or name == "source":
            continue
        if name in {"source_fingerprint", "source_fetch_fingerprint"}:
            alias = (
                "stored_fingerprint_sha256"
                if name == "source_fingerprint"
                else "fetched_fingerprint_sha256"
            )
            expression = (
                f"CASE WHEN {name} IS NULL THEN NULL ELSE "
                + _HASH.format(value=name)
                + f" END AS {alias}"
            )
        elif name == "incremental_harvest":
            expression = (
                "incremental_harvest IS NOT NULL AS staged_payload_present, "
                "pg_catalog.octet_length(incremental_harvest) AS staged_payload_bytes"
            )
        else:
            expressions.append(sql.Identifier(name))
            continue
        expressions.append(sql.SQL(expression))
    query = sql.SQL("SELECT {} FROM public.sync_status ORDER BY source").format(
        sql.SQL(", ").join(expressions)
    )
    return _bounded_rows(connection, "source_state", query), missing


def _alembic_state(
    connection: psycopg.Connection[Any],
    tables: list[dict[str, Any]],
    columns: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    """Return safe revision values/hashes and collection status; record missing/unsupported
    schema explicitly.
    """
    table = next(item for item in tables if item["table"] == "alembic_version")
    if table["status"] != "counted":
        return [], str(table["status"])
    revision = next(
        (
            row
            for row in columns
            if row.get("relation_name") == "alembic_version"
            and row.get("column_name") == "version_num"
        ),
        None,
    )
    if revision is None:
        return [], "missing_version_column"
    if revision.get("data_type") not in {"text", "character varying(32)"}:
        return [], "unsupported_version_type"
    query = """
        SELECT CASE WHEN version_num ~ '^[A-Za-z0-9_]{{1,64}}$'
                    THEN version_num::text ELSE NULL END AS version_num,
               {revision_hash} AS version_num_sha256
        FROM public.alembic_version ORDER BY version_num_sha256
    """.format(  # nosec B608 # Fixed SHA256 fragment only; no external input.
        revision_hash=_HASH.format(value="version_num")
    )
    return _bounded_rows(connection, "alembic_revisions", query), "collected"


def _managed_state(
    connection: psycopg.Connection[Any],
    identity: dict[str, Any],
    catalog: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Count readable managed tables and collect source/revision state, preserving
    missing/unsupported statuses.

    Use the caller's transaction; privilege/RLS ambiguity and invalid counts raise
    InventoryRefusal, database errors propagate.
    """
    relations = {row["relation_name"]: row for row in catalog["relations"]}
    tables = []
    for name in _MANAGED_TABLES:
        relation = relations.get(name)
        if relation is None:
            tables.append({"table": name, "present": False, "status": "missing"})
            continue
        if relation.get("relation_kind") not in {"r", "p"}:
            tables.append({"table": name, "present": True, "status": "unsupported_relation_kind"})
            continue
        _require_count_visibility(relation, identity)
        rows = _bounded_rows(
            connection,
            "count:" + name,
            sql.SQL("SELECT pg_catalog.count(*) AS row_count FROM {}.{}").format(
                sql.Identifier("public"), sql.Identifier(name)
            ),
        )
        if len(rows) != 1 or type(rows[0].get("row_count")) is not int:
            raise InventoryRefusal("A managed-table count could not be established")
        tables.append(
            {"table": name, "present": True, "status": "counted", "rows": rows[0]["row_count"]}
        )
    sync = next(item for item in tables if item["table"] == "sync_status")
    sources, missing = (
        _source_state(connection, catalog["columns"])
        if sync["status"] == "counted"
        else ([], sorted(_SOURCE_COLUMNS))
    )
    revisions, revision_status = _alembic_state(connection, tables, catalog["columns"])
    return {
        "tables": tables,
        "sources": sources,
        "missing_state_columns": missing,
        "alembic_revisions": revisions,
        "alembic_revision_status": revision_status,
    }


def collect_inventory(
    connection: psycopg.Connection[Any], expected_database: str
) -> dict[str, Any]:
    """Collect facts in one fresh read-only repeatable-read PostgreSQL 18 transaction.

    Requires autocommit and no existing transaction. A missing/old managed
    schema is recorded as incomplete state, never as zero rows or equivalence.
    Privilege/RLS ambiguity, malformed identity or size limits refuse the report.
    This function neither repairs nor validates candidate schema equivalence.
    """
    if not expected_database or "\x00" in expected_database:
        raise InventoryRefusal("An explicit expected database is required")
    if not connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise InventoryRefusal("An idle autocommit connection is required")
    with connection.transaction():
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '30s'")
        connection.execute("SET LOCAL lock_timeout = '5s'")
        connection.execute("SET LOCAL search_path = pg_catalog")
        connection.execute("SET LOCAL row_security = off")
        identity = _identity(connection, "identity")
        _require_read_only(identity)
        if identity.get("database") != expected_database:
            raise InventoryRefusal("The connected database differs from the reviewed target")
        if identity.get("current_user") != identity.get("session_user"):
            raise InventoryRefusal("Current and session database identities must match")
        version = identity.get("server_version_num")
        if type(version) is not int or not _MIN_SERVER_VERSION <= version < _MAX_SERVER_VERSION:
            raise InventoryRefusal("The inventory requires PostgreSQL 18")
        captured = identity.pop("captured_at", None)
        if not isinstance(captured, datetime) or captured.tzinfo is None:
            raise InventoryRefusal("The snapshot timestamp could not be established")
        catalog = {
            name: _bounded_rows(connection, name, query) for name, query in _CATALOG_QUERIES.items()
        }
        state = _managed_state(connection, identity, catalog)
        postcheck = _identity(connection, "read_only_postcheck")
        _require_read_only(postcheck)
        for name in ("database", "current_user", "session_user", "server_version_num"):
            if postcheck.get(name) != identity.get(name):
                raise InventoryRefusal("The database identity changed during inventory")
        report = {
            "report_version": _REPORT_VERSION,
            "captured_at_utc": captured,
            "identity": identity,
            "catalog": catalog,
            "managed_state": state,
            "limitations": [
                "Inventory facts are not candidate schema equivalence or deployment acceptance.",
                "Missing tables/columns are explicit incomplete state, not zero rows or a pass.",
                "Counts do not prove preservation of values or replace encrypted backup/restore.",
                "No runtime environment files, passwords, raw metadata, action values "
                "or staged bytes are collected.",
                "Expression/routine/view/policy/default/configuration text is SHA-256 only.",
                "ACL null means PostgreSQL default privileges; runtime preflights "
                "resolve effective access.",
                "Aggregate routine bodies are source-hashed; their full CREATE "
                "definitions are not reconstructed.",
                "Installed artifact/configuration identities and reviewed upgrade/recovery "
                "decisions remain separate records.",
            ],
        }
        safe_report = _safe_value(report)
        if not isinstance(safe_report, dict):
            raise InventoryRefusal("The inventory report must be a JSON object")
        return safe_report


def _require_private_parent(
    info: os.stat_result, destination: Path, roots: tuple[Path, ...]
) -> None:
    """Require this UID's mode-0700 parent outside excluded roots; otherwise raise
    InventoryRefusal.
    """
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise InventoryRefusal("The report parent must be owned by this UID with mode 0700")
    parent = destination.parent.resolve(strict=True)
    if any(parent.is_relative_to(root) for root in roots):
        raise InventoryRefusal("The report must be outside every excluded checkout or directory")


def _parent_descriptor(destination: Path, roots: tuple[Path, ...]) -> int:
    """Open/pin the absent destination's private parent without following symlinks.

    Require an absolute path without parent traversal outside excluded roots.
    Return a caller-owned FD; close it on failure. Validation/I/O errors propagate.
    """
    if not destination.is_absolute() or ".." in destination.parts:
        raise InventoryRefusal("Use an absolute report path without parent traversal")
    if any(destination.is_relative_to(root) for root in roots):
        raise InventoryRefusal("The report must be outside every excluded checkout or directory")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in destination.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        _require_private_parent(os.fstat(directory), destination, roots)
        try:
            os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InventoryRefusal("The report destination already exists")
        return directory
    except BaseException:
        os.close(directory)
        raise


@contextmanager
def _report_destination(
    destination: Path,
    repository_root: Path | None,
    exclude_roots: tuple[Path, ...] = (),
) -> Iterator[int]:
    """Validate exclusions and pin a private output parent before any database work."""
    roots = (() if repository_root is None else (repository_root,)) + exclude_roots
    checked_roots: list[Path] = []
    for root in roots:
        if not root.is_absolute() or ".." in root.parts:
            raise InventoryRefusal("Excluded roots must be absolute paths without parent traversal")
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            raise InventoryRefusal("Excluded roots must be existing directories")
        checked_roots.append(resolved)
    descriptor = _parent_descriptor(destination, tuple(checked_roots))
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _publish_report(report: dict[str, Any], name: str, descriptor: int) -> None:
    """Publish exclusively through an already validated parent; the caller owns its FD."""
    data = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    temporary = ".staging-inventory-" + secrets.token_hex(16)
    published = False
    identity: tuple[int, int] | None = None
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            info = os.fstat(stream.fileno())
            identity = (info.st_dev, info.st_ino)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(
            temporary,
            name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
            follow_symlinks=False,
        )
        published = True
        os.fsync(descriptor)
    except BaseException:
        if published:
            actual = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino) == identity:
                os.unlink(name, dir_fd=descriptor)
        raise
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=descriptor)


def write_report(
    report: dict[str, Any],
    destination: Path,
    repository_root: Path | None = PROJECT_ROOT,
    *,
    exclude_roots: tuple[Path, ...] = (),
) -> None:
    """Atomically publish mode-0600 JSON outside inferred and explicitly excluded roots.

    Standalone copies infer no checkout; callers can supply reviewed exclusions.
    Reject symlinks, existing targets and unsafe directories. Publication uses an
    exclusive hard link through a pinned directory descriptor; failures clean up
    temporary content and never overwrite prior evidence.
    """
    with _report_destination(destination, repository_root, exclude_roots) as descriptor:
        _publish_report(report, destination.name, descriptor)


class _Parser(argparse.ArgumentParser):
    """Convert argument errors to fixed inventory diagnostics without echoing submitted values."""

    def error(self, _message: str) -> NoReturn:
        """Raise InventoryRefusal with a fixed message instead of argparse's submitted-value
        diagnostic.
        """
        raise InventoryRefusal("Invalid command-line arguments")


def main(argv: list[str] | None = None) -> int:
    """Read libpq authentication, collect and privately publish; failures return 2.

    Diagnostics are static and never print server errors, DSNs, report content,
    passwords or tracebacks. Validate --output and repeatable --exclude-root paths
    before connecting; the validated parent descriptor stays pinned until publication.
    """
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--expected-database", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--exclude-root",
        action="append",
        type=Path,
        default=[],
        metavar="DIRECTORY",
        help="existing absolute checkout/directory forbidden for output; repeat for each root",
    )
    try:
        args = parser.parse_args(argv)
        with _report_destination(args.output, PROJECT_ROOT, tuple(args.exclude_root)) as descriptor:
            with psycopg.connect(
                "", autocommit=True, connect_timeout=5, options=_CONNECTION_OPTIONS
            ) as connection:
                report = collect_inventory(connection, args.expected_database)
            _publish_report(report, args.output.name, descriptor)
    except (Exception, KeyboardInterrupt):
        print(
            "Staging inventory did not complete; inspect the private destination. "
            "Review the target, privileges and private output directory.",
            file=sys.stderr,
        )
        return 2
    print("Restricted staging inventory written successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
