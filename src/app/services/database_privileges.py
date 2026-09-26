"""Read-only validation of hardened PostgreSQL runtime roles against explicit allowlists.

Catalog/database failures propagate; validation never changes privileges.
"""

from collections.abc import Mapping
from typing import Any, Final, Literal

from psycopg import AsyncCursor
from psycopg_pool import AsyncConnectionPool

from config import settings

from .db import get_db_cursor
from .db_schema_contract import SESSION_COLUMN_CONTRACT, USER_COLUMN_CONTRACT

RuntimeProcess = Literal["web", "scheduler"]

OWNER_ROLE: Final = "oralhistarchiv"
ROLE_BY_PROCESS: Final[dict[RuntimeProcess, str]] = {
    "web": "oralhistarchiv_web",
    "scheduler": "oralhistarchiv_scheduler",
}

_ALL_TABLE_PRIVILEGES: Final = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
_ALL_SEQUENCE_PRIVILEGES: Final = ("USAGE", "SELECT", "UPDATE")

TABLE_PRIVILEGES: Final[dict[RuntimeProcess, dict[str, frozenset[str]]]] = {
    "web": {
        "alembic_version": frozenset({"SELECT"}),
        "oral_history_datasets": frozenset({"SELECT"}),
        "sync_status": frozenset({"SELECT"}),
        "ingestion_failures": frozenset(),
        "users": frozenset({"SELECT", "INSERT", "UPDATE"}),
        "federation_policy_state": frozenset({"SELECT", "INSERT", "UPDATE"}),
        "email_outbox": frozenset({"SELECT", "INSERT", "UPDATE"}),
        "sessions": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
        "pending_totp_rotations": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
        "totp_recovery_codes": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
        "admin_promotion_requests": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
    },
    "scheduler": {
        "alembic_version": frozenset({"SELECT"}),
        "oral_history_datasets": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
        "sync_status": frozenset({"SELECT", "UPDATE"}),
        "ingestion_failures": frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"}),
        "users": frozenset({"SELECT", "DELETE"}),
        "federation_policy_state": frozenset(),
        "email_outbox": frozenset({"SELECT", "UPDATE", "DELETE"}),
        "sessions": frozenset({"SELECT", "DELETE"}),
        "pending_totp_rotations": frozenset(),
        "totp_recovery_codes": frozenset(),
        "admin_promotion_requests": frozenset(),
    },
}

USER_COLUMN_PRIVILEGES: Final[dict[RuntimeProcess, dict[str, frozenset[str]]]] = {
    "web": {
        "SELECT": frozenset(USER_COLUMN_CONTRACT),
        "INSERT": frozenset(USER_COLUMN_CONTRACT),
        "UPDATE": frozenset(USER_COLUMN_CONTRACT),
        "REFERENCES": frozenset(),
    },
    "scheduler": {
        "SELECT": frozenset(USER_COLUMN_CONTRACT),
        "INSERT": frozenset(),
        # PostgreSQL requires UPDATE on at least one column for SELECT ... FOR
        # UPDATE. Outbox delivery locks users but never changes authority data.
        "UPDATE": frozenset({"last_login"}),
        "REFERENCES": frozenset(),
    },
}

# The scheduler locks expired sessions before deleting them. PostgreSQL requires
# UPDATE on at least one column for SELECT ... FOR UPDATE, but granting UPDATE
# on an authority-bearing session column would enlarge its effective role.
SCHEDULER_SESSION_COLUMN_PRIVILEGES: Final[dict[str, frozenset[str]]] = {
    "INSERT": frozenset(),
    "UPDATE": frozenset({"flash_category"}),
    "REFERENCES": frozenset(),
}

SEQUENCE_PRIVILEGES: Final[dict[RuntimeProcess, dict[str, frozenset[str]]]] = {
    "web": {
        "oral_history_datasets_id_seq": frozenset(),
        "users_id_seq": frozenset({"USAGE"}),
        "email_outbox_id_seq": frozenset({"USAGE"}),
    },
    "scheduler": {
        "oral_history_datasets_id_seq": frozenset({"USAGE"}),
        "users_id_seq": frozenset(),
        "email_outbox_id_seq": frozenset(),
    },
}

# These are schema-qualified identity signatures returned by PostgreSQL. The
# current application calls no stored function directly; trigger functions do
# not belong in this allowlist.
EXECUTABLE_APPLICATION_FUNCTIONS: Final[dict[RuntimeProcess, frozenset[str]]] = {
    "web": frozenset(),
    "scheduler": frozenset(),
}


def _role_problems(role: Mapping[str, Any], process: RuntimeProcess) -> list[str]:
    """Return role identity, elevated privilege, membership, ownership,
    and function-EXECUTE mismatches.
    """
    expected_role = ROLE_BY_PROCESS[process]
    problems: list[str] = []
    if role["current_user"] != expected_role:
        problems.append(f"current_user={role['current_user']!r}; expected {expected_role!r}")
    if role["session_user"] != expected_role:
        problems.append(f"session_user={role['session_user']!r}; expected {expected_role!r}")

    problems.extend(
        f"{attribute}=true"
        for attribute in (
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
            "database_create",
            "database_temp",
            "schema_create",
        )
        if role[attribute]
    )
    if role["memberships"]:
        problems.append(f"role memberships={list(role['memberships'])!r}")
    if role["unexpected_owners"]:
        problems.append(
            "public/database objects are not owned exclusively by "
            f"{OWNER_ROLE!r}: {list(role['unexpected_owners'])!r}"
        )

    executable = frozenset(role["executable_application_functions"])
    expected_executable = EXECUTABLE_APPLICATION_FUNCTIONS[process]
    if executable != expected_executable:
        problems.append(
            f"application-function EXECUTE set={sorted(executable)!r}; "
            f"expected={sorted(expected_executable)!r}"
        )
    return problems


def _expected_relation_access(process: RuntimeProcess) -> frozenset[str]:
    """Return public-qualified relations accessible
    under the process's table/user-column contract.
    """
    return frozenset(
        f"public.{relation}"
        for relation, privileges in TABLE_PRIVILEGES[process].items()
        if privileges or (relation == "users" and any(USER_COLUMN_PRIVILEGES[process].values()))
    )


def _inventory_problems(inventory: Mapping[str, Any], process: RuntimeProcess) -> list[str]:
    """Return mismatches in the exact accessible public relation and sequence sets."""
    actual_relations = frozenset(inventory["accessible_relations"])
    expected_relations = _expected_relation_access(process)
    actual_sequences = frozenset(inventory["accessible_sequences"])
    expected_sequences = frozenset(
        f"public.{sequence}"
        for sequence, privileges in SEQUENCE_PRIVILEGES[process].items()
        if privileges
    )
    problems: list[str] = []
    if actual_relations != expected_relations:
        problems.append(
            f"accessible public relations={sorted(actual_relations)!r}; "
            f"expected={sorted(expected_relations)!r}"
        )
    if actual_sequences != expected_sequences:
        problems.append(
            f"accessible public sequences={sorted(actual_sequences)!r}; "
            f"expected={sorted(expected_sequences)!r}"
        )
    return problems


async def _required_row(
    cur: AsyncCursor[Mapping[str, Any]],
    error: str,
) -> Mapping[str, Any]:
    """Fetch one row or raise RuntimeError with error when the probe returned none."""
    row = await cur.fetchone()
    if row is None:
        raise RuntimeError(error)
    return row


async def _read_accessible_object_inventory(
    cur: AsyncCursor[Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Query accessible public relations/sequences,
    excluding extension members; require one result row.
    """
    await cur.execute(
        """
        SELECT COALESCE(
                   array_agg(format('%I.%I', namespace.nspname, relation.relname)
                             ORDER BY namespace.nspname, relation.relname)
                       FILTER (
                           WHERE relation.relkind <> 'S'
                             AND (
                                 has_table_privilege(
                                     current_user,
                                     relation.oid,
                                     'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
                                 )
                                 OR has_any_column_privilege(
                                     current_user,
                                     relation.oid,
                                     'SELECT,INSERT,UPDATE,REFERENCES'
                                 )
                             )
                       ),
                   ARRAY[]::text[]
               ) AS accessible_relations,
               COALESCE(
                   array_agg(format('%I.%I', namespace.nspname, relation.relname)
                             ORDER BY namespace.nspname, relation.relname)
                       FILTER (
                           WHERE relation.relkind = 'S'
                             AND has_sequence_privilege(
                                 current_user,
                                 relation.oid,
                                 'USAGE,SELECT,UPDATE'
                             )
                       ),
                   ARRAY[]::text[]
               ) AS accessible_sequences
        FROM pg_class AS relation
        JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend AS dependency
              WHERE dependency.classid = 'pg_class'::regclass
                AND dependency.objid = relation.oid
                AND dependency.deptype = 'e'
          )
        """
    )
    return await _required_row(cur, "PostgreSQL relation inventory returned no row")


async def _privilege_mismatches(
    cur: AsyncCursor[Mapping[str, Any]],
    expected: dict[tuple[str, str], bool],
    *,
    prefix: str = "",
) -> list[str]:
    """Fetch probe rows and return expected/actual privilege mismatches with prefix.

    Require exactly one boolean result per (object, privilege) key;
    otherwise raise RuntimeError.
    """
    rows = await cur.fetchall()
    actual = {(row["object_name"], row["privilege"]): row["allowed"] for row in rows}
    if (
        actual.keys() != expected.keys()
        or len(rows) != len(expected)
        or any(not isinstance(value, bool) for value in actual.values())
    ):
        raise RuntimeError("PostgreSQL privilege probe returned incomplete or malformed results")
    return [
        f"{prefix}{name} {privilege}: actual={actual[(name, privilege)]}, expected={allowed}"
        for (name, privilege), allowed in expected.items()
        if actual[(name, privilege)] != allowed
    ]


async def _table_privilege_problems(
    cur: AsyncCursor[Mapping[str, Any]], process: RuntimeProcess
) -> list[str]:
    """Query the process's table privilege matrix and return mismatches;
    malformed probes raise RuntimeError.
    """
    await cur.execute(
        """SELECT object_name, privilege,
                  has_table_privilege(current_user, 'public.' || object_name, privilege) AS allowed
           FROM unnest(%s::text[]) AS objects(object_name)
           CROSS JOIN unnest(%s::text[]) AS privileges(privilege)""",
        (list(TABLE_PRIVILEGES[process]), list(_ALL_TABLE_PRIVILEGES)),
    )
    return await _privilege_mismatches(
        cur,
        {
            (name, privilege): privilege in allowed
            for name, allowed in TABLE_PRIVILEGES[process].items()
            for privilege in _ALL_TABLE_PRIVILEGES
        },
    )


async def _sequence_privilege_problems(
    cur: AsyncCursor[Mapping[str, Any]], process: RuntimeProcess
) -> list[str]:
    """Query the process's sequence privilege matrix and return mismatches;
    malformed probes raise RuntimeError.
    """
    await cur.execute(
        """SELECT object_name, privilege,
                  has_sequence_privilege(
                      current_user, 'public.' || object_name, privilege
                  ) AS allowed
           FROM unnest(%s::text[]) AS objects(object_name)
           CROSS JOIN unnest(%s::text[]) AS privileges(privilege)""",
        (list(SEQUENCE_PRIVILEGES[process]), list(_ALL_SEQUENCE_PRIVILEGES)),
    )
    return await _privilege_mismatches(
        cur,
        {
            (name, privilege): privilege in allowed
            for name, allowed in SEQUENCE_PRIVILEGES[process].items()
            for privilege in _ALL_SEQUENCE_PRIVILEGES
        },
    )


async def _user_column_privilege_problems(
    cur: AsyncCursor[Mapping[str, Any]], process: RuntimeProcess
) -> list[str]:
    """Query effective users-column privileges and return mismatches;
    malformed probes raise RuntimeError.
    """
    await cur.execute(
        """SELECT object_name, privilege,
                  has_column_privilege(
                      current_user, 'public.users', object_name, privilege
                  ) AS allowed
           FROM unnest(%s::text[]) AS objects(object_name)
           CROSS JOIN unnest(%s::text[]) AS privileges(privilege)""",
        (list(USER_COLUMN_CONTRACT), list(USER_COLUMN_PRIVILEGES[process])),
    )
    return await _privilege_mismatches(
        cur,
        {
            (column, privilege): column in allowed
            for privilege, allowed in USER_COLUMN_PRIVILEGES[process].items()
            for column in USER_COLUMN_CONTRACT
        },
        prefix="users.",
    )


async def _scheduler_session_column_privilege_problems(
    cur: AsyncCursor[Mapping[str, Any]], process: RuntimeProcess
) -> list[str]:
    """Check scheduler session-column write grants; return an empty list for web."""
    if process != "scheduler":
        return []

    await cur.execute(
        """SELECT object_name, privilege,
                  has_column_privilege(
                      current_user, 'public.sessions', object_name, privilege
                  ) AS allowed
           FROM unnest(%s::text[]) AS objects(object_name)
           CROSS JOIN unnest(%s::text[]) AS privileges(privilege)""",
        (list(SESSION_COLUMN_CONTRACT), list(SCHEDULER_SESSION_COLUMN_PRIVILEGES)),
    )
    return await _privilege_mismatches(
        cur,
        {
            (column, privilege): column in allowed
            for privilege, allowed in SCHEDULER_SESSION_COLUMN_PRIVILEGES.items()
            for column in SESSION_COLUMN_CONTRACT
        },
        prefix="sessions.",
    )


async def validate_runtime_database_role(
    pool: AsyncConnectionPool,
    process: RuntimeProcess,
) -> None:
    """Check the web/scheduler role in staging or production; do nothing elsewhere.

    Require the configured role identity, restricted attributes/memberships,
    allowed ownership, exact accessible object inventory, and privilege
    matrices. Raise RuntimeError for mismatches or malformed probe results;
    database errors propagate.
    """
    if not settings.is_hardened:
        return

    async with get_db_cursor(pool) as cur:
        await cur.execute(
            """
            SELECT current_user AS current_user,
                   session_user AS session_user,
                   r.rolsuper,
                   r.rolcreatedb,
                   r.rolcreaterole,
                   r.rolreplication,
                   r.rolbypassrls,
                   has_database_privilege(current_user, current_database(), 'CREATE')
                       AS database_create,
                   has_database_privilege(current_user, current_database(), 'TEMP')
                       AS database_temp,
                   has_schema_privilege(current_user, 'public', 'CREATE')
                       AS schema_create,
                   COALESCE(
                       (
                           SELECT array_agg(parent.rolname ORDER BY parent.rolname)
                           FROM pg_auth_members AS membership
                           JOIN pg_roles AS parent ON parent.oid = membership.roleid
                           WHERE membership.member = r.oid
                       ),
                       ARRAY[]::name[]
                   ) AS memberships,
                   COALESCE(
                       (
                           SELECT array_agg(owner_name ORDER BY owner_name)
                           FROM (
                               SELECT pg_get_userbyid(d.datdba) AS owner_name
                               FROM pg_database AS d
                               WHERE d.datname = current_database()
                               UNION
                               SELECT pg_get_userbyid(n.nspowner)
                               FROM pg_namespace AS n
                               WHERE n.nspname = 'public'
                               UNION
                               SELECT pg_get_userbyid(c.relowner)
                               FROM pg_class AS c
                               JOIN pg_namespace AS n ON n.oid = c.relnamespace
                               WHERE n.nspname = 'public'
                                 AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
                               UNION
                               SELECT pg_get_userbyid(p.proowner)
                               FROM pg_proc AS p
                               JOIN pg_namespace AS n ON n.oid = p.pronamespace
                               WHERE n.nspname = 'public'
                                 AND NOT EXISTS (
                                     SELECT 1
                                     FROM pg_depend AS dependency
                                     WHERE dependency.classid = 'pg_proc'::regclass
                                       AND dependency.objid = p.oid
                                       AND dependency.deptype = 'e'
                                 )
                           ) AS owners
                           WHERE owner_name NOT IN (%s, 'pg_database_owner')
                       ),
                       ARRAY[]::name[]
                   ) AS unexpected_owners,
                   COALESCE(
                       (
                           SELECT array_agg(
                               format(
                                   '%%I.%%I(%%s)',
                                   function_namespace.nspname,
                                   function_definition.proname,
                                   pg_get_function_identity_arguments(
                                       function_definition.oid
                                   )
                               )
                               ORDER BY function_namespace.nspname,
                                        function_definition.proname,
                                        pg_get_function_identity_arguments(
                                            function_definition.oid
                                        )
                           )
                           FROM pg_proc AS function_definition
                           JOIN pg_namespace AS function_namespace
                             ON function_namespace.oid =
                                function_definition.pronamespace
                           WHERE function_namespace.nspname = 'public'
                             AND pg_get_userbyid(function_definition.proowner) = %s
                             AND NOT EXISTS (
                                 SELECT 1
                                 FROM pg_depend AS dependency
                                 WHERE dependency.classid = 'pg_proc'::regclass
                                   AND dependency.objid = function_definition.oid
                                   AND dependency.deptype = 'e'
                             )
                             AND has_function_privilege(
                                 current_user,
                                 function_definition.oid,
                                 'EXECUTE'
                             )
                       ),
                       ARRAY[]::text[]
                   ) AS executable_application_functions
            FROM pg_roles AS r
            WHERE r.rolname = current_user
            """,
            (OWNER_ROLE, OWNER_ROLE),
        )
        role = await _required_row(cur, "PostgreSQL current_user has no pg_roles row")

        problems = _role_problems(role, process)
        inventory = await _read_accessible_object_inventory(cur)
        problems.extend(_inventory_problems(inventory, process))
        problems.extend(await _table_privilege_problems(cur, process))
        problems.extend(await _sequence_privilege_problems(cur, process))
        problems.extend(await _user_column_privilege_problems(cur, process))
        problems.extend(await _scheduler_session_column_privilege_problems(cur, process))

    if problems:
        raise RuntimeError(f"Unsafe PostgreSQL role for {process}: " + "; ".join(problems))
