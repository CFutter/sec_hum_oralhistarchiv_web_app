"""Fail-closed PostgreSQL row-policy and narrow-view catalog contracts."""

from contextlib import asynccontextmanager
from dataclasses import replace
from unittest.mock import create_autospec

import pytest
from psycopg import AsyncCursor
from psycopg.rows import tuple_row

from app.services import database_privileges, db_drift
from app.services.db_schema_contract import (
    TABLE_COLUMN_CONTRACTS,
    TABLE_POLICY_CONTRACTS,
    TABLE_ROW_SECURITY_CONTRACTS,
    VIEW_CONTRACTS,
    PolicySpec,
    RowSecuritySpec,
)

_POOL = object()
_FLAGS = RowSecuritySpec(enabled=True, forced=False)
_POLICY = PolicySpec(
    command="r", permissive=True, roles=("PUBLIC",), using="(visible = true)", with_check=None
)
_VIEW = VIEW_CONTRACTS["catalogue_discovery"]


def _catalog_rows(monkeypatch, rows):
    """Install scripted schema-catalog rows and return the signature-checked cursor."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchall.side_effect = rows

    @asynccontextmanager
    async def context(pool, *, row_factory):
        """Yield the scripted cursor after checking the database boundary."""
        assert pool is _POOL
        assert row_factory is tuple_row
        yield cursor

    cursor_factory = create_autospec(db_drift.get_db_cursor, spec_set=True)
    cursor_factory.side_effect = context
    monkeypatch.setattr(db_drift, "get_db_cursor", cursor_factory)
    return cursor


def _view_row(spec=_VIEW):
    """Encode a view contract as the tuple returned by the catalog query."""
    return (
        [name for name, _ in spec.columns],
        [pg_type for _, pg_type in spec.columns],
        spec.definition,
        list(spec.options),
        spec.owner_matches_catalogue,
    )


def test_managed_tables_have_complete_fail_closed_policy_inventory():
    """Check managed tables have complete fail closed policy inventory."""
    assert set(TABLE_COLUMN_CONTRACTS) == set(TABLE_ROW_SECURITY_CONTRACTS)
    assert set(TABLE_COLUMN_CONTRACTS) == set(TABLE_POLICY_CONTRACTS)
    for table in TABLE_COLUMN_CONTRACTS:
        assert TABLE_ROW_SECURITY_CONTRACTS[table] == RowSecuritySpec(
            enabled=table == "oral_history_datasets", forced=False
        )
        if table != "oral_history_datasets":
            assert TABLE_POLICY_CONTRACTS[table] == {}
    assert set(TABLE_POLICY_CONTRACTS["oral_history_datasets"]) == {
        "catalogue_web_select",
        "catalogue_scheduler_all",
    }
    assert all(
        policy.roles == ("PUBLIC",)
        for policy in TABLE_POLICY_CONTRACTS["oral_history_datasets"].values()
    )


async def test_row_security_flags_are_read_without_assuming_table_presence(monkeypatch):
    """Check row security flags are read without assuming table presence."""
    cursor = _catalog_rows(monkeypatch, [[(True, False)], []])
    await db_drift.assert_table_row_security_contract(_POOL, "probe", _FLAGS, {})
    query, params = cursor.execute.await_args_list[0].args
    assert "relation.relrowsecurity" in query and "relation.relforcerowsecurity" in query
    assert params == ("probe",)


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [(True,)],
        [(True, False, False)],
        [(1, False)],
        [(True, None)],
        [(True, False), (True, False)],
    ],
)
async def test_missing_or_malformed_row_security_flags_refuse_startup(monkeypatch, rows):
    """Check missing or malformed row security flags refuse startup (RuntimeError)."""
    _catalog_rows(monkeypatch, [rows])
    with pytest.raises(RuntimeError, match="row-security flags"):
        await db_drift.assert_table_row_security_contract(_POOL, "probe", _FLAGS, {})


async def test_policy_probe_preserves_every_security_property(monkeypatch):
    """Check policy probe preserves every security property."""
    cursor = _catalog_rows(
        monkeypatch,
        [
            [(True, False)],
            [
                ("read", "r", True, ["PUBLIC"], "(visible = true)", None),
                ("write", "*", False, ["restricted_role"], None, "(allowed = true)"),
            ],
        ],
    )
    await db_drift.assert_table_row_security_contract(
        _POOL,
        "probe",
        _FLAGS,
        {
            "read": _POLICY,
            "write": PolicySpec(
                command="*",
                permissive=False,
                roles=("restricted_role",),
                using=None,
                with_check="(allowed = true)",
            ),
        },
    )
    query, params = cursor.execute.await_args_list[1].args
    assert "FROM pg_policy AS policy" in query
    assert "policy.polpermissive" in query
    assert "role_oid = 0 THEN 'PUBLIC'" in query
    assert "pg_get_expr(policy.polqual, policy.polrelid, false)" in query
    assert params == ("probe",)


@pytest.mark.parametrize(
    "row",
    [
        ("short",),
        (None, "r", True, ["PUBLIC"], None, None),
        ("read", "?", True, ["PUBLIC"], None, None),
        ("read", "r", 1, ["PUBLIC"], None, None),
        ("read", "r", True, None, None, None),
        ("read", "r", True, [], None, None),
        ("read", "r", True, [None], None, None),
        ("read", "r", True, ["PUBLIC"], True, None),
        ("read", "r", True, ["PUBLIC"], None, True),
    ],
)
async def test_malformed_policy_probe_cannot_be_accepted(monkeypatch, row):
    """Check malformed policy probe cannot be accepted (RuntimeError)."""
    _catalog_rows(monkeypatch, [[(True, False)], [row]])
    with pytest.raises(RuntimeError, match=r"pg_policy|policy properties"):
        await db_drift.assert_table_row_security_contract(_POOL, "probe", _FLAGS, {})


async def test_duplicate_policy_rows_fail_closed(monkeypatch):
    """Check duplicate policy rows fail closed (RuntimeError)."""
    row = ("read", "r", True, ["PUBLIC"], None, None)
    _catalog_rows(monkeypatch, [[(True, False)], [row, row]])
    with pytest.raises(RuntimeError, match="policy properties"):
        await db_drift.assert_table_row_security_contract(_POOL, "probe", _FLAGS, {})


@pytest.mark.parametrize(
    ("flags", "policies"),
    [
        (_FLAGS, {"read": _POLICY}),
        (replace(_FLAGS, enabled=False), {"read": _POLICY}),
        (replace(_FLAGS, forced=True), {"read": _POLICY}),
        (_FLAGS, {}),
        (_FLAGS, {"read": replace(_POLICY, permissive=False)}),
        (_FLAGS, {"read": replace(_POLICY, roles=("different_role",))}),
        (_FLAGS, {"read": replace(_POLICY, using="true")}),
        (_FLAGS, {"read": replace(_POLICY, with_check="true")}),
        (_FLAGS, {"read": replace(_POLICY, command="*")}),
        (_FLAGS, {"read": _POLICY, "unexpected_bypass": replace(_POLICY, using="true")}),
    ],
)
async def test_exact_policy_inventory_rejects_privilege_broadening(monkeypatch, flags, policies):
    """Check exact policy inventory rejects privilege broadening (RuntimeError)."""
    _catalog_rows(
        monkeypatch,
        [
            [(flags.enabled, flags.forced)],
            [
                (name, spec.command, spec.permissive, list(spec.roles), spec.using, spec.with_check)
                for name, spec in policies.items()
            ],
        ],
    )
    if flags == _FLAGS and policies == {"read": _POLICY}:
        await db_drift.assert_table_row_security_contract(_POOL, "probe", _FLAGS, {"read": _POLICY})
    else:
        with pytest.raises(RuntimeError, match="Row-security drift"):
            await db_drift.assert_table_row_security_contract(
                _POOL, "probe", _FLAGS, {"read": _POLICY}
            )


async def test_view_probe_includes_ordered_projection_options_and_owner(monkeypatch):
    """Check view probe includes ordered projection options and owner."""
    cursor = _catalog_rows(monkeypatch, [[_view_row()]])
    await db_drift.assert_view_contract(_POOL, "catalogue_discovery", _VIEW)
    query, params = cursor.execute.await_args.args
    assert "pg_get_viewdef(relation.oid, false)" in query
    assert "relation.relowner =" in query
    assert "relation.reloptions" in query
    assert "ORDER BY attribute.attnum" in query
    assert params == ("catalogue_discovery",)


@pytest.mark.parametrize("rows", [[], [("too short",)], [_view_row(), _view_row()]])
async def test_missing_or_wrong_shape_view_catalog_refuses_startup(monkeypatch, rows):
    """Check missing or wrong shape view catalog refuses startup (RuntimeError)."""
    _catalog_rows(monkeypatch, [rows])
    with pytest.raises(RuntimeError, match="Missing or malformed managed view"):
        await db_drift.assert_view_contract(_POOL, "catalogue_discovery", _VIEW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (0, None),
        (1, None),
        (0, []),
        (1, []),
        (0, [None] * len(_VIEW.columns)),
        (1, [None] * len(_VIEW.columns)),
        (2, None),
        (3, None),
        (3, [None]),
        (4, None),
    ],
)
async def test_malformed_view_properties_fail_closed(monkeypatch, field, value):
    """Check malformed view properties fail closed (RuntimeError)."""
    row = list(_view_row())
    row[field] = value
    _catalog_rows(monkeypatch, [[tuple(row)]])
    with pytest.raises(RuntimeError, match="Malformed managed view properties"):
        await db_drift.assert_view_contract(_POOL, "catalogue_discovery", _VIEW)


@pytest.mark.parametrize(
    "actual",
    [
        _VIEW,
        replace(_VIEW, columns=(*_VIEW.columns, ("description", "text"))),
        replace(_VIEW, columns=tuple(reversed(_VIEW.columns))),
        replace(_VIEW, definition=" SELECT * FROM oral_history_datasets;"),
        replace(_VIEW, options=("security_barrier=false", "security_invoker=false")),
        replace(_VIEW, options=("security_barrier=true", "security_invoker=true")),
        replace(_VIEW, owner_matches_catalogue=False),
    ],
)
async def test_narrow_view_contract_rejects_field_leaks_or_owner_drift(monkeypatch, actual):
    """Check narrow view contract rejects field leaks or owner drift (RuntimeError)."""
    _catalog_rows(monkeypatch, [[_view_row(actual)]])
    if actual == _VIEW:
        await db_drift.assert_view_contract(_POOL, "catalogue_discovery", _VIEW)
    else:
        with pytest.raises(RuntimeError, match="Schema drift on view"):
            await db_drift.assert_view_contract(_POOL, "catalogue_discovery", _VIEW)


@pytest.mark.parametrize("process", ["web", "scheduler"])
@pytest.mark.parametrize("legacy_write", [False, True])
async def test_view_column_grants_cannot_escape_select_only_runtime_matrix(
    monkeypatch, process, legacy_write
):
    """Check view column grants cannot escape select only runtime matrix (RuntimeError)."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    role_name = database_privileges.ROLE_BY_PROCESS[process]
    role = {
        "current_user": role_name,
        "session_user": role_name,
        "memberships": [],
        "unexpected_owners": [],
        "executable_application_functions": sorted(
            database_privileges.EXECUTABLE_APPLICATION_FUNCTIONS[process]
        ),
        **dict.fromkeys(
            (
                "rolsuper",
                "rolcreatedb",
                "rolcreaterole",
                "rolreplication",
                "rolbypassrls",
                "database_create",
                "database_temp",
                "schema_create",
            ),
            False,
        ),
    }
    relations = [
        f"public.{name}"
        for name, privileges in database_privileges.TABLE_PRIVILEGES[process].items()
        if privileges
    ]
    if legacy_write and process == "scheduler":
        relations.append("public.catalogue_discovery")
    inventory = {
        "accessible_relations": relations,
        "accessible_sequences": [
            f"public.{name}"
            for name, privileges in database_privileges.SEQUENCE_PRIVILEGES[process].items()
            if privileges
        ],
    }
    cursor.fetchone.side_effect = [role, inventory]
    answers = []
    for matrix, privileges in (
        (
            database_privileges.TABLE_PRIVILEGES[process],
            database_privileges._ALL_TABLE_PRIVILEGES,
        ),
        (database_privileges.SEQUENCE_PRIVILEGES[process], ("USAGE", "SELECT", "UPDATE")),
    ):
        answers.append(
            [
                {"object_name": name, "privilege": privilege, "allowed": privilege in allowed}
                for name, allowed in matrix.items()
                for privilege in privileges
            ]
        )
    answers.append(
        [
            {"object_name": column, "privilege": privilege, "allowed": column in allowed}
            for privilege, allowed in database_privileges.USER_COLUMN_PRIVILEGES[process].items()
            for column in database_privileges.USER_COLUMN_CONTRACT
        ]
    )
    if process == "scheduler":
        answers.append(
            [
                {"object_name": column, "privilege": privilege, "allowed": column in allowed}
                for privilege, allowed in database_privileges.SCHEDULER_SESSION_COLUMN_PRIVILEGES.items()
                for column in database_privileges.SESSION_COLUMN_CONTRACT
            ]
        )
    for view_name, view_spec in VIEW_CONTRACTS.items():
        answers.append(
            [
                {
                    "object_name": column,
                    "privilege": privilege,
                    "allowed": (privilege == "SELECT" and process == "web")
                    or (
                        legacy_write
                        and view_name == "catalogue_discovery"
                        and column == "title"
                        and privilege == "UPDATE"
                    ),
                }
                for column, _ in view_spec.columns
                for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES")
            ]
        )
    cursor.fetchall.side_effect = answers

    @asynccontextmanager
    async def context(pool):
        """Yield the scripted cursor after checking the database boundary."""
        assert pool is _POOL
        yield cursor

    factory = create_autospec(database_privileges.get_db_cursor, spec_set=True)
    factory.side_effect = context
    monkeypatch.setattr(database_privileges, "get_db_cursor", factory)
    monkeypatch.setattr(database_privileges.settings, "env_state", "staging")
    if legacy_write:
        with pytest.raises(RuntimeError, match=r"catalogue_discovery\.title UPDATE"):
            await database_privileges.validate_runtime_database_role(_POOL, process)
    else:
        await database_privileges.validate_runtime_database_role(_POOL, process)
