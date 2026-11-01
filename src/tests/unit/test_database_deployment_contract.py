"""Deployed systemd units, SQL role scripts, and the runtime privilege
contract those roles are checked against at startup."""

import fcntl
import re
import shlex
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from app.paths import PROJECT_ROOT
from app.services import database_privileges
from app.services.db_schema_contract import VIEW_CONTRACTS
from config import settings

WEB = PROJECT_ROOT / "oralhistarchiv.service"
SCHEDULER = PROJECT_ROOT / "oralhistarchiv-scheduler.service"
MIGRATE = PROJECT_ROOT / "oralhistarchiv-migrate.service"
BOOTSTRAP = PROJECT_ROOT / "deploy/bootstrap-database-roles.sql"
GRANTS = PROJECT_ROOT / "deploy/database-runtime-grants.sql"
ACCESS_VERIFY = PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"


def _directives(path: Path, name: str):
    """Return matching systemd directive values after stripping comments."""
    text = "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())
    return re.findall(rf"(?m)^\s*{re.escape(name)}=(.*?)\s*$", text)


class TestServiceUnitDeployment:
    """The deployed systemd units never run migrations inline and each
    process loads only the environment overlay for its own role."""

    def test_runtime_units_never_run_alembic(self):
        """Keep Alembic migration commands out of runtime systemd units."""
        for unit in (WEB, SCHEDULER):
            text = unit.read_text()
            commands = _directives(unit, "ExecStartPre") + _directives(unit, "ExecStart")
            assert commands, f"{unit.name} declares no start command"
            for command in commands:
                assert "alembic" not in command.lower()
                assert "migrate" not in command.lower()
            assert "alembic" not in text.lower()

    def test_runtime_units_load_distinct_database_overlays(self):
        """Runtime units load distinct database overlays."""
        assert _directives(WEB, "EnvironmentFile") == [
            "/etc/oralhistarchiv/common.env",
            "/etc/oralhistarchiv/web.env",
            "-/etc/oralhistarchiv/shibboleth.env",
        ]
        assert _directives(SCHEDULER, "EnvironmentFile") == [
            "/etc/oralhistarchiv/common.env",
            "/etc/oralhistarchiv/scheduler.env",
        ]

    def test_migration_unit_is_manual_quiescing_and_owner_only(self):
        """Migration unit is manual quiescing and owner only."""
        text = MIGRATE.read_text()
        assert "[Install]" not in text
        assert _directives(MIGRATE, "Type") == ["oneshot"]
        assert _directives(MIGRATE, "User") == ["oralhistarchiv-migrate"]
        assert _directives(MIGRATE, "Group") == ["oralhistarchiv-migrate"]
        assert _directives(MIGRATE, "EnvironmentFile") == ["/etc/oralhistarchiv/migration.env"]
        assert _directives(MIGRATE, "Conflicts") == [
            "oralhistarchiv.service oralhistarchiv-scheduler.service"
        ]
        assert _directives(MIGRATE, "Before") == [
            "oralhistarchiv.service oralhistarchiv-scheduler.service"
        ]
        assert _directives(MIGRATE, "RestrictAddressFamilies") == ["AF_UNIX"]
        assert _directives(MIGRATE, "ExecStart") == [
            "/usr/bin/flock --exclusive --timeout 60 --conflict-exit-code 75 --no-fork "
            "/run/lock/oralhistarchiv-deploy.lock "
            "/opt/oralhistarchiv/.venv/bin/python -I /opt/oralhistarchiv/deploy/migrate_release.py"
        ]
        assert _directives(MIGRATE, "ExecStartPost") == []
        wrapper = (PROJECT_ROOT / "deploy/migrate_release.py").read_text()
        assert "Path(__file__).resolve().parents[1]" in wrapper
        assert "deploy/database-runtime-grants.sql" in wrapper
        assert _directives(MIGRATE, "SyslogIdentifier") == ["oralhistarchiv-migrate"]


class TestRoleBootstrapAndGrantScripts:
    """The deployed SQL scripts create the runtime roles deny-first and
    enumerate every effective public object before granting anything back."""

    def test_role_bootstrap_and_grants_are_deny_first(self):
        """Role bootstrap and grants are deny first."""
        bootstrap = BOOTSTRAP.read_text()
        grants = GRANTS.read_text()
        normalized_grants = " ".join(grants.split())
        for role in ("oralhistarchiv_web", "oralhistarchiv_scheduler"):
            assert role in bootstrap
            assert role in grants
        assert bootstrap.count("NOBYPASSRLS") >= 3
        assert "PASSWORD NULL" in bootstrap
        assert "REVOKE ALL ON ALL TABLES" in grants
        assert "REVOKE ALL ON ALL SEQUENCES" in grants
        assert "REVOKE CREATE, TEMP ON DATABASE" in grants
        assert "GRANT USAGE ON SCHEMA public" in grants
        assert "ALTER SCHEMA public OWNER TO oralhistarchiv" in bootstrap
        assert "oralhistarchiv_backup" in bootstrap
        assert "GRANT SELECT ON ALL TABLES IN SCHEMA public TO oralhistarchiv_backup" in grants
        assert "'REVOKE %I FROM %I'" in bootstrap
        for role in (
            "'oralhistarchiv'",
            "'oralhistarchiv_web'",
            "'oralhistarchiv_scheduler'",
            "'oralhistarchiv_backup'",
        ):
            assert role in bootstrap
        runtime_roles = "oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup"
        assert f"REVOKE ALL ON DATABASE oralhistarchiv FROM {runtime_roles};" in normalized_grants
        assert f"REVOKE ALL ON SCHEMA public FROM {runtime_roles};" in normalized_grants
        assert (
            "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        assert (
            "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        column_revoke = (
            "REVOKE SELECT (%I), INSERT (%I), UPDATE (%I), REFERENCES (%I) "
            "ON TABLE %I.%I FROM PUBLIC, oralhistarchiv_web, "
            "oralhistarchiv_scheduler, oralhistarchiv_backup"
        )
        materialized_view_revoke = (
            "REVOKE SELECT (%I) ON TABLE %I.%I FROM PUBLIC, "
            "oralhistarchiv_web, oralhistarchiv_scheduler, oralhistarchiv_backup"
        )
        assert "DO $column_revoke$" in grants
        assert column_revoke in normalized_grants
        assert materialized_view_revoke in normalized_grants
        assert "REVOKE ALL ON ALL FUNCTIONS" not in normalized_grants
        assert (
            "REVOKE EXECUTE ON FUNCTION public.update_search_text() FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        catalogue_functions = (
            "public.catalogue_scan_ceiling(), "
            "public.catalogue_page_ids(integer, integer, boolean, integer, integer, jsonb)"
        )
        assert (
            f"REVOKE EXECUTE ON FUNCTION {catalogue_functions} FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        assert (
            f"GRANT EXECUTE ON FUNCTION {catalogue_functions} TO oralhistarchiv_web;"
            in normalized_grants
        )
        assert (
            "ALTER DEFAULT PRIVILEGES FOR ROLE oralhistarchiv "
            "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        assert normalized_grants.index("DO $column_revoke$") < normalized_grants.index(
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO oralhistarchiv_backup"
        )
        assert "GRANT DELETE ON TABLE users TO oralhistarchiv_scheduler;" in normalized_grants
        scheduler_select = re.search(
            r"GRANT SELECT \(([^)]+)\) ON TABLE users TO oralhistarchiv_scheduler;",
            normalized_grants,
        )
        assert scheduler_select is not None
        assert set(scheduler_select.group(1).split(", ")) == set(
            database_privileges.USER_COLUMN_PRIVILEGES["scheduler"]["SELECT"]
        )
        assert database_privileges.TABLE_PRIVILEGES["scheduler"]["users"] == frozenset({"DELETE"})
        assert {"password_hash", "totp_secret", "pending_totp_secret"}.isdisjoint(
            database_privileges.USER_COLUMN_PRIVILEGES["scheduler"]["SELECT"]
        )
        assert (
            "GRANT SELECT, DELETE ON TABLE users TO oralhistarchiv_scheduler;"
            not in normalized_grants
        )
        assert (
            "GRANT UPDATE (last_login) ON TABLE users TO oralhistarchiv_scheduler;"
            in normalized_grants
        )
        assert (
            "GRANT SELECT, UPDATE, DELETE ON TABLE users TO oralhistarchiv_scheduler;"
            not in normalized_grants
        )
        assert (
            "GRANT UPDATE (flash_category) ON TABLE sessions TO oralhistarchiv_scheduler;"
            in normalized_grants
        )
        assert (
            "GRANT SELECT, INSERT, UPDATE ON TABLE sync_status "
            "TO oralhistarchiv_scheduler;" in normalized_grants
        )
        assert database_privileges.TABLE_PRIVILEGES["scheduler"]["sync_status"] == frozenset(
            {"SELECT", "INSERT", "UPDATE"}
        )
        assert database_privileges.TABLE_PRIVILEGES["web"]["sync_status"] == frozenset({"SELECT"})
        catalogue_views = {
            "catalogue_discovery",
            "catalogue_search_candidates",
            "dataset_admin_catalogue",
        }
        web_select = re.search(
            r"GRANT SELECT ON TABLE ([^;]+) TO oralhistarchiv_web;", normalized_grants
        )
        assert web_select is not None
        assert catalogue_views <= set(web_select.group(1).split(", "))
        for view in catalogue_views:
            assert database_privileges.TABLE_PRIVILEGES["web"][view] == frozenset({"SELECT"})
            assert database_privileges.TABLE_PRIVILEGES["scheduler"][view] == frozenset()

    def test_live_access_verifier_enumerates_every_effective_public_object(self):
        """Live access verifier enumerates every effective public object."""
        verifier = ACCESS_VERIFY.read_text()
        normalized = " ".join(verifier.split())

        assert "has_table_privilege(" in verifier
        assert "has_any_column_privilege(" in verifier
        assert "has_sequence_privilege(" in verifier
        assert "relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')" in verifier
        assert "dependency.deptype = 'e'" in verifier
        assert "WHEN 'oralhistarchiv_web'" in verifier
        assert "WHEN 'oralhistarchiv_scheduler'" in verifier
        assert "public.federation_policy_state" in verifier
        assert "public.oral_history_datasets_id_seq" in verifier
        assert "actual_relations IS DISTINCT FROM expected_relations" in normalized
        assert "actual_sequences IS DISTINCT FROM expected_sequences" in normalized
        assert "DO $catalogue_function_access_contract$" in verifier
        assert "has_function_privilege(" in verifier
        assert "pg_get_function_identity_arguments(" in verifier
        assert "actual_functions IS DISTINCT FROM expected_functions" in normalized
        for signature in database_privileges.EXECUTABLE_APPLICATION_FUNCTIONS["web"]:
            assert f"'{signature}'" in verifier
        assert "DO $session_cleanup_lock_contract$" in verifier
        assert "ARRAY['flash_category']::text[]" in verifier
        assert "DO $scheduler_user_column_contract$" in verifier
        for process, role in database_privileges.ROLE_BY_PROCESS.items():
            inventory = re.search(
                rf"WHEN '{role}' THEN\s+expected_relations := ARRAY\[(.*?)\];",
                verifier,
                re.DOTALL,
            )
            assert inventory is not None
            assert set(re.findall(r"'([^']+)'", inventory.group(1))) == set(
                _inventory(process)["accessible_relations"]
            )


class _Cursor:
    """Fake async cursor answering the exact query shapes the validator issues."""

    def __init__(self, role, privilege_answers, inventory):
        """Store role, privilege answers and inventory for query-dependent responses."""
        self.role = role
        self.privilege_answers = iter(privilege_answers)
        self.inventory = inventory
        self.last_query = ""

    async def execute(self, query, params=None):
        """Capture the latest query and parameters and increment the query count."""
        self.last_query = str(query)
        self.params = params
        self.query_count = getattr(self, "query_count", 0) + 1

    async def fetchone(self):
        """Return role/inventory data or consume the next privilege answer."""
        if "FROM pg_roles AS r" in self.last_query:
            return self.role
        if "AS accessible_relations" in self.last_query:
            return self.inventory
        return {"allowed": next(self.privilege_answers)}

    async def fetchall(self):
        """Validate requested column names and consume one privilege answer per pair."""
        if len(self.params) == 3:
            relation, names, privileges = self.params
            assert names == [
                name for name, _ in VIEW_CONTRACTS[relation.removeprefix("public.")].columns
            ]
        else:
            names, privileges = self.params
        pairs = (
            [(name, privilege) for privilege in privileges for name in names]
            if "has_column_privilege" in self.last_query
            else [(name, privilege) for name in names for privilege in privileges]
        )
        return [
            {"object_name": name, "privilege": privilege, "allowed": next(self.privilege_answers)}
            for name, privilege in pairs
        ]


def _role(name):
    """Return a runtime-role row without dangerous attributes or unexpected ownership."""
    return {
        "current_user": name,
        "session_user": name,
        "rolsuper": False,
        "rolcreatedb": False,
        "rolcreaterole": False,
        "rolreplication": False,
        "rolbypassrls": False,
        "database_create": False,
        "database_temp": False,
        "schema_create": False,
        "memberships": [],
        "unexpected_owners": [],
        "executable_application_functions": sorted(
            database_privileges.EXECUTABLE_APPLICATION_FUNCTIONS["web"]
            if name == "oralhistarchiv_web"
            else database_privileges.EXECUTABLE_APPLICATION_FUNCTIONS["scheduler"]
        ),
    }


def _answers(process):
    """Expand the expected runtime privilege contract into ordered boolean answers."""
    answers = []
    for expected in database_privileges.TABLE_PRIVILEGES[process].values():
        answers.extend(
            privilege in expected for privilege in database_privileges._ALL_TABLE_PRIVILEGES
        )
    for expected in database_privileges.SEQUENCE_PRIVILEGES[process].values():
        answers.extend(
            privilege in expected for privilege in database_privileges._ALL_SEQUENCE_PRIVILEGES
        )
    for expected_columns in database_privileges.USER_COLUMN_PRIVILEGES[process].values():
        answers.extend(
            column in expected_columns for column in database_privileges.USER_COLUMN_CONTRACT
        )
    if process == "scheduler":
        for expected_columns in database_privileges.SCHEDULER_SESSION_COLUMN_PRIVILEGES.values():
            answers.extend(
                column in expected_columns for column in database_privileges.SESSION_COLUMN_CONTRACT
            )
    for view_name, view in VIEW_CONTRACTS.items():
        for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
            answers.extend(
                privilege in database_privileges.TABLE_PRIVILEGES[process][view_name]
                for _column in view.columns
            )
    return answers


def _inventory(process):
    """Return accessible relations and sequences implied by the process grants."""
    relation_names = {
        f"public.{name}"
        for name, privileges in database_privileges.TABLE_PRIVILEGES[process].items()
        if privileges
        or (name == "users" and any(database_privileges.USER_COLUMN_PRIVILEGES[process].values()))
    }
    sequence_names = {
        f"public.{name}"
        for name, privileges in database_privileges.SEQUENCE_PRIVILEGES[process].items()
        if privileges
    }
    return {
        "accessible_relations": sorted(relation_names),
        "accessible_sequences": sorted(sequence_names),
    }


def _install_cursor(monkeypatch, cursor):
    """Patch privilege-check database access to yield the configured cursor."""

    @asynccontextmanager
    async def fake_get_db_cursor(_pool):
        """Yield the configured cursor without opening PostgreSQL."""
        yield cursor

    spy = create_autospec(database_privileges.get_db_cursor, spec_set=True)
    spy.side_effect = fake_get_db_cursor
    monkeypatch.setattr(database_privileges, "get_db_cursor", spy)


class TestRuntimeDatabaseRoleContract:
    """Reject hardened runtime roles whose identity or privileges differ from the exact contract."""

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_exact_runtime_role_and_privileges_pass(self, monkeypatch, process):
        """Exact runtime role and privileges pass."""
        monkeypatch.setattr(settings, "env_state", "production")
        role_name = database_privileges.ROLE_BY_PROCESS[process]
        cursor = _Cursor(_role(role_name), _answers(process), _inventory(process))
        _install_cursor(monkeypatch, cursor)

        await database_privileges.validate_runtime_database_role(object(), process)
        assert cursor.query_count == (9 if process == "scheduler" else 8)

    async def test_development_skips_production_role_contract(self, monkeypatch):
        """Development skips production role contract."""
        monkeypatch.setattr(settings, "env_state", "dev")

        async def must_not_open(_pool):
            """Fail if development role validation opens PostgreSQL."""
            raise AssertionError("development role validation opened PostgreSQL")

        spy = create_autospec(database_privileges.get_db_cursor, spec_set=True)
        spy.side_effect = must_not_open
        monkeypatch.setattr(database_privileges, "get_db_cursor", spy)
        await database_privileges.validate_runtime_database_role(object(), "web")

    async def test_wrong_runtime_role_fails_startup(self, monkeypatch):
        """Wrong runtime role fails startup."""
        monkeypatch.setattr(settings, "env_state", "production")
        _install_cursor(
            monkeypatch,
            _Cursor(
                _role("oralhistarchiv"),
                _answers("web"),
                _inventory("web"),
            ),
        )

        with pytest.raises(RuntimeError, match="expected 'oralhistarchiv_web'"):
            await database_privileges.validate_runtime_database_role(object(), "web")

    @pytest.mark.parametrize(
        ("field", "value"),
        (
            ("rolsuper", True),
            ("rolbypassrls", True),
            ("database_create", True),
            ("database_temp", True),
            ("schema_create", True),
            ("memberships", ["oralhistarchiv"]),
            ("unexpected_owners", ["attacker_role"]),
            ("executable_application_functions", ["public.update_search_text()"]),
        ),
        ids=[
            "superuser_flag_is_set",
            "bypass_rls_flag_is_set",
            "database_create_privilege_is_granted",
            "database_temp_privilege_is_granted",
            "schema_create_privilege_is_granted",
            "role_has_unexpected_membership",
            "public_object_owned_outside_owner_role",
            "unexpected_application_function_is_executable",
        ],
    )
    async def test_dangerous_role_state_fails_startup(self, monkeypatch, field, value):
        """Dangerous role state fails startup."""
        monkeypatch.setattr(settings, "env_state", "production")
        role = _role("oralhistarchiv_web")
        role[field] = value
        _install_cursor(monkeypatch, _Cursor(role, _answers("web"), _inventory("web")))

        with pytest.raises(RuntimeError, match="Unsafe PostgreSQL role for web"):
            await database_privileges.validate_runtime_database_role(object(), "web")

    @pytest.mark.parametrize("process", ["web", "scheduler"])
    @pytest.mark.parametrize(
        "function", sorted(database_privileges.EXECUTABLE_APPLICATION_FUNCTIONS["web"])
    )
    async def test_catalogue_execute_grants_match_the_process(self, monkeypatch, process, function):
        """Catalogue execute grants match the process."""
        monkeypatch.setattr(settings, "env_state", "production")
        role = _role(database_privileges.ROLE_BY_PROCESS[process])
        functions = role["executable_application_functions"]
        if process == "web":
            functions.remove(function)
        else:
            functions.append(function)
        _install_cursor(monkeypatch, _Cursor(role, _answers(process), _inventory(process)))
        with pytest.raises(RuntimeError, match="application-function EXECUTE set"):
            await database_privileges.validate_runtime_database_role(object(), process)

    async def test_unexpected_accessible_relation_fails_startup(self, monkeypatch):
        """Unexpected accessible relation fails startup."""
        monkeypatch.setattr(settings, "env_state", "production")
        inventory = _inventory("web")
        inventory["accessible_relations"].append("public.unexpected_sensitive_table")
        cursor = _Cursor(
            _role("oralhistarchiv_web"),
            _answers("web"),
            inventory,
        )
        _install_cursor(monkeypatch, cursor)

        with pytest.raises(
            RuntimeError,
            match="unexpected_sensitive_table",
        ):
            await database_privileges.validate_runtime_database_role(object(), "web")

    async def test_missing_or_excess_table_privilege_fails_startup(self, monkeypatch):
        """Missing or excess table privilege fails startup."""
        monkeypatch.setattr(settings, "env_state", "production")
        answers = _answers("scheduler")
        answers[0] = not answers[0]
        _install_cursor(
            monkeypatch,
            _Cursor(
                _role("oralhistarchiv_scheduler"),
                answers,
                _inventory("scheduler"),
            ),
        )

        with pytest.raises(RuntimeError, match=r"actual=.*expected="):
            await database_privileges.validate_runtime_database_role(object(), "scheduler")

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_maintenance_authority_fails_startup(self, monkeypatch, process):
        """Reject PostgreSQL 18 maintenance grants even on an otherwise allowed table."""
        monkeypatch.setattr(settings, "env_state", "production")
        answers = _answers(process)
        tables = list(database_privileges.TABLE_PRIVILEGES[process])
        privileges = database_privileges._ALL_TABLE_PRIVILEGES
        answers[
            tables.index("oral_history_datasets") * len(privileges) + privileges.index("MAINTAIN")
        ] = True
        _install_cursor(
            monkeypatch,
            _Cursor(
                _role(database_privileges.ROLE_BY_PROCESS[process]),
                answers,
                _inventory(process),
            ),
        )

        with pytest.raises(
            RuntimeError, match="oral_history_datasets MAINTAIN: actual=True, expected=False"
        ):
            await database_privileges.validate_runtime_database_role(object(), process)

    async def test_scheduler_has_no_table_wide_users_update(self, monkeypatch):
        """Scheduler has no table wide users update."""
        monkeypatch.setattr(settings, "env_state", "production")
        answers = _answers("scheduler")
        tables = list(database_privileges.TABLE_PRIVILEGES["scheduler"])
        privilege_count = len(database_privileges._ALL_TABLE_PRIVILEGES)
        answer_index = tables.index(
            "users"
        ) * privilege_count + database_privileges._ALL_TABLE_PRIVILEGES.index("UPDATE")
        answers[answer_index] = True
        _install_cursor(
            monkeypatch,
            _Cursor(
                _role("oralhistarchiv_scheduler"),
                answers,
                _inventory("scheduler"),
            ),
        )

        with pytest.raises(RuntimeError, match="users UPDATE: actual=True, expected=False"):
            await database_privileges.validate_runtime_database_role(object(), "scheduler")

    @pytest.mark.parametrize(
        ("privilege", "column", "allowed"),
        (
            ("UPDATE", "last_login", False),
            ("UPDATE", "access_tier", True),
            ("UPDATE", "is_admin", True),
            ("UPDATE", "auth_revision", True),
            ("UPDATE", "totp_secret", True),
            ("INSERT", "access_tier", True),
            ("REFERENCES", "is_admin", True),
        ),
    )
    async def test_scheduler_user_column_privileges_are_exact(
        self,
        monkeypatch,
        privilege,
        column,
        allowed,
    ):
        """Scheduler user column privileges are exact."""
        monkeypatch.setattr(settings, "env_state", "production")
        answers = _answers("scheduler")
        table_answer_count = len(database_privileges.TABLE_PRIVILEGES["scheduler"]) * len(
            database_privileges._ALL_TABLE_PRIVILEGES
        )
        sequence_answer_count = len(database_privileges.SEQUENCE_PRIVILEGES["scheduler"]) * len(
            database_privileges._ALL_SEQUENCE_PRIVILEGES
        )
        columns = list(database_privileges.USER_COLUMN_CONTRACT)
        privileges = list(database_privileges.USER_COLUMN_PRIVILEGES["scheduler"])
        column_answer_offset = table_answer_count + sequence_answer_count
        answer_index = (
            column_answer_offset
            + privileges.index(privilege) * len(columns)
            + columns.index(column)
        )
        answers[answer_index] = allowed
        _install_cursor(
            monkeypatch,
            _Cursor(
                _role("oralhistarchiv_scheduler"),
                answers,
                _inventory("scheduler"),
            ),
        )

        with pytest.raises(RuntimeError, match=rf"users\.{column} {privilege}"):
            await database_privileges.validate_runtime_database_role(object(), "scheduler")

    @pytest.mark.parametrize(
        ("privilege", "column", "allowed"),
        (
            ("UPDATE", "flash_category", False),
            ("UPDATE", "user_id", True),
            ("INSERT", "flash_category", True),
            ("REFERENCES", "user_id", True),
        ),
    )
    async def test_scheduler_session_lock_grant_is_exact(
        self, monkeypatch, privilege, column, allowed
    ):
        """Scheduler session lock grant is exact."""
        monkeypatch.setattr(settings, "env_state", "production")
        answers = _answers("scheduler")
        table_count = len(database_privileges.TABLE_PRIVILEGES["scheduler"]) * len(
            database_privileges._ALL_TABLE_PRIVILEGES
        )
        sequence_count = len(database_privileges.SEQUENCE_PRIVILEGES["scheduler"]) * len(
            database_privileges._ALL_SEQUENCE_PRIVILEGES
        )
        user_column_count = len(database_privileges.USER_COLUMN_CONTRACT) * len(
            database_privileges.USER_COLUMN_PRIVILEGES["scheduler"]
        )
        columns = list(database_privileges.SESSION_COLUMN_CONTRACT)
        privileges = list(database_privileges.SCHEDULER_SESSION_COLUMN_PRIVILEGES)
        answer_index = (
            table_count
            + sequence_count
            + user_column_count
            + privileges.index(privilege) * len(columns)
            + columns.index(column)
        )
        answers[answer_index] = allowed
        _install_cursor(
            monkeypatch,
            _Cursor(_role("oralhistarchiv_scheduler"), answers, _inventory("scheduler")),
        )

        with pytest.raises(RuntimeError, match=rf"sessions\.{column} {privilege}"):
            await database_privileges.validate_runtime_database_role(object(), "scheduler")


class TestTotpRotationChallengeTableOwnership:
    """Grant TOTP-rotation challenge DML to web only."""

    def test_web_role_has_full_dml_on_pending_totp_rotations(self):
        """Web role has full dml on pending TOTP rotations."""
        assert database_privileges.TABLE_PRIVILEGES["web"]["pending_totp_rotations"] == {
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
        }

    def test_scheduler_role_has_no_privilege_on_pending_totp_rotations(self):
        """Scheduler role has no privilege on pending TOTP rotations."""
        assert (
            database_privileges.TABLE_PRIVILEGES["scheduler"]["pending_totp_rotations"]
            == frozenset()
        )


class TestLoginAttemptCounterColumnOwnership:
    """Grant login-failure counter mutation to web only."""

    def test_web_role_can_update_the_login_attempt_counter(self):
        """Web role can update the login attempt counter."""
        assert "failed_login_count" in database_privileges.USER_COLUMN_PRIVILEGES["web"]["UPDATE"]

    def test_scheduler_role_cannot_update_the_login_attempt_counter(self):
        """Scheduler role cannot update the login attempt counter."""
        assert (
            "failed_login_count"
            not in database_privileges.USER_COLUMN_PRIVILEGES["scheduler"]["UPDATE"]
        )


@pytest.mark.parametrize("process", ["web", "scheduler"])
def test_admin_state_privileges_match_process_ownership(process):
    """Web may administer restrictions; ingestion can only read them."""
    expected = {"SELECT", "INSERT", "UPDATE"} if process == "web" else {"SELECT"}
    assert database_privileges.TABLE_PRIVILEGES[process]["dataset_admin_state"] == expected
    grants = " ".join(GRANTS.read_text().split())
    statement = (
        "GRANT SELECT, INSERT, UPDATE ON TABLE dataset_admin_state TO oralhistarchiv_web;"
        if process == "web"
        else "GRANT SELECT ON TABLE alembic_version, dataset_admin_state "
        "TO oralhistarchiv_scheduler;"
    )
    assert statement in grants
    assert database_privileges.TABLE_PRIVILEGES["web"]["oral_history_datasets"] == {"SELECT"}


@pytest.mark.parametrize("unit", [WEB, SCHEDULER, MIGRATE])
def test_service_lock_conflicts_have_a_bounded_retryable_outcome(tmp_path, unit):
    """Execute each shipped flock prefix with an accelerated test deadline."""
    command = shlex.split(_directives(unit, "ExecStart")[0])
    lock_index = command.index("/run/lock/oralhistarchiv-deploy.lock")
    prefix = command[:lock_index]
    assert prefix[0] == "/usr/bin/flock"
    assert prefix[prefix.index("--timeout") + 1] == "60"
    assert prefix[prefix.index("--conflict-exit-code") + 1] == "75"
    assert "--no-fork" in prefix
    assert ("--exclusive" if unit == MIGRATE else "--shared") in prefix
    prefix[prefix.index("--timeout") + 1] = "0.05"
    lock_path = tmp_path / "deployment.lock"
    lock_path.touch()
    marker = tmp_path / "started"
    child = [
        *prefix,
        str(lock_path),
        sys.executable,
        "-I",
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
        str(marker),
    ]
    with lock_path.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rejected = subprocess.run(child, check=False, capture_output=True, timeout=5)
    assert rejected.returncode == 75
    assert not marker.exists()
    accepted = subprocess.run(child, check=False, capture_output=True, timeout=5)
    assert accepted.returncode == 0, accepted.stderr
    assert marker.exists()


def test_lock_access_is_limited_to_runtime_and_maintenance_participants():
    """All legitimate service identities receive read access; parser jobs do not."""
    tmpfiles = (PROJECT_ROOT / "deploy/oralhistarchiv-tmpfiles.conf").read_text()
    active = [line.split() for line in tmpfiles.splitlines() if line and not line.startswith("#")]
    assert active == [
        [
            "f",
            "/run/lock/oralhistarchiv-deploy.lock",
            "0640",
            "root",
            "oralhistarchiv-deploy-lock",
            "-",
        ]
    ]
    for unit in (WEB, SCHEDULER, MIGRATE, PROJECT_ROOT / "deploy/oralhistarchiv-backup.service"):
        assert (
            "oralhistarchiv-deploy-lock"
            in " ".join(_directives(unit, "SupplementaryGroups")).split()
        )
    assert (
        "oralhistarchiv-deploy-lock"
        not in (PROJECT_ROOT / "oralhistarchiv-parser@.service").read_text()
    )
