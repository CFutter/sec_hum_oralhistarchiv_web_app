"""Deployed systemd units, SQL role scripts, and the runtime privilege
contract those roles are checked against at startup."""

import re
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from app.paths import PROJECT_ROOT
from app.services import database_privileges
from config import settings

WEB = PROJECT_ROOT / "oralhistarchiv.service"
SCHEDULER = PROJECT_ROOT / "oralhistarchiv-scheduler.service"
MIGRATE = PROJECT_ROOT / "oralhistarchiv-migrate.service"
BOOTSTRAP = PROJECT_ROOT / "deploy/bootstrap-database-roles.sql"
GRANTS = PROJECT_ROOT / "deploy/database-runtime-grants.sql"
ACCESS_VERIFY = PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"


def _directives(path: Path, name: str):
    text = "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())
    return re.findall(rf"(?m)^\s*{re.escape(name)}=(.*?)\s*$", text)


class TestServiceUnitDeployment:
    """The deployed systemd units never run migrations inline and each
    process loads only the environment overlay for its own role."""

    def test_runtime_units_never_run_alembic(self):
        """Migrations are a reviewed release step of their own. The runtime
        units may run start checks (they gate on the deployment mode), but
        none of their commands may touch the migration tooling."""
        for unit in (WEB, SCHEDULER):
            text = unit.read_text()
            commands = _directives(unit, "ExecStartPre") + _directives(unit, "ExecStart")
            assert commands, f"{unit.name} declares no start command"
            for command in commands:
                assert "alembic" not in command.lower()
                assert "migrate" not in command.lower()
            assert "alembic" not in text.lower()

    def test_runtime_units_load_distinct_database_overlays(self):
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
            "/usr/bin/flock --exclusive --no-fork /run/lock/oralhistarchiv-deploy.lock "
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
        assert (
            "ALTER DEFAULT PRIVILEGES FOR ROLE oralhistarchiv IN SCHEMA public "
            "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, "
            f"{runtime_roles};" in normalized_grants
        )
        assert normalized_grants.index("DO $column_revoke$") < normalized_grants.index(
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO oralhistarchiv_backup"
        )
        assert (
            "GRANT SELECT, DELETE ON TABLE users TO oralhistarchiv_scheduler;" in normalized_grants
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

    def test_live_access_verifier_enumerates_every_effective_public_object(self):
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
        assert "DO $session_cleanup_lock_contract$" in verifier
        assert "ARRAY['flash_category']::text[]" in verifier


class _Cursor:
    """Fake async cursor answering the exact query shapes the validator issues."""

    def __init__(self, role, privilege_answers, inventory):
        self.role = role
        self.privilege_answers = iter(privilege_answers)
        self.inventory = inventory
        self.last_query = ""

    async def execute(self, query, params=None):
        self.last_query = str(query)
        self.params = params
        self.query_count = getattr(self, "query_count", 0) + 1

    async def fetchone(self):
        if "FROM pg_roles AS r" in self.last_query:
            return self.role
        if "AS accessible_relations" in self.last_query:
            return self.inventory
        return {"allowed": next(self.privilege_answers)}

    async def fetchall(self):
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
        "executable_application_functions": [],
    }


def _answers(process):
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
    return answers


def _inventory(process):
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
    @asynccontextmanager
    async def fake_get_db_cursor(_pool):
        yield cursor

    spy = create_autospec(database_privileges.get_db_cursor, spec_set=True)
    spy.side_effect = fake_get_db_cursor
    monkeypatch.setattr(database_privileges, "get_db_cursor", spy)


class TestRuntimeDatabaseRoleContract:
    """The role a hardened process connects as must match its declared
    privilege footprint exactly: right role name, no dangerous attributes,
    no extra accessible object, no missing or excess privilege. Anything
    off fails startup closed; in a non-hardened environment the check
    never runs at all."""

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_exact_runtime_role_and_privileges_pass(self, monkeypatch, process):
        monkeypatch.setattr(settings, "env_state", "production")
        role_name = database_privileges.ROLE_BY_PROCESS[process]
        cursor = _Cursor(_role(role_name), _answers(process), _inventory(process))
        _install_cursor(monkeypatch, cursor)

        await database_privileges.validate_runtime_database_role(object(), process)
        assert cursor.query_count == (6 if process == "scheduler" else 5)

    async def test_development_skips_production_role_contract(self, monkeypatch):
        monkeypatch.setattr(settings, "env_state", "dev")

        async def must_not_open(_pool):
            raise AssertionError("development role validation opened PostgreSQL")

        spy = create_autospec(database_privileges.get_db_cursor, spec_set=True)
        spy.side_effect = must_not_open
        monkeypatch.setattr(database_privileges, "get_db_cursor", spy)
        await database_privileges.validate_runtime_database_role(object(), "web")

    async def test_wrong_runtime_role_fails_startup(self, monkeypatch):
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
        monkeypatch.setattr(settings, "env_state", "production")
        role = _role("oralhistarchiv_web")
        role[field] = value
        _install_cursor(monkeypatch, _Cursor(role, _answers("web"), _inventory("web")))

        with pytest.raises(RuntimeError, match="Unsafe PostgreSQL role for web"):
            await database_privileges.validate_runtime_database_role(object(), "web")

    async def test_unexpected_accessible_relation_fails_startup(self, monkeypatch):
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

    async def test_scheduler_has_no_table_wide_users_update(self, monkeypatch):
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
    """`pending_totp_rotations` (the TOTP-rotation challenge table) is DML for
    web only; the scheduler never touches it, matching the design that
    rotation challenges are a web-request-lifecycle concern."""

    def test_web_role_has_full_dml_on_pending_totp_rotations(self):
        assert database_privileges.TABLE_PRIVILEGES["web"]["pending_totp_rotations"] == {
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
        }

    def test_scheduler_role_has_no_privilege_on_pending_totp_rotations(self):
        assert (
            database_privileges.TABLE_PRIVILEGES["scheduler"]["pending_totp_rotations"]
            == frozenset()
        )


class TestLoginAttemptCounterColumnOwnership:
    """The atomic login-lockout budget (`users.failed_login_count`) is
    mutated only by the web process; the scheduler's own `UPDATE` grant is
    exactly the outbox-locking column, never the counter itself."""

    def test_web_role_can_update_the_login_attempt_counter(self):
        assert "failed_login_count" in database_privileges.USER_COLUMN_PRIVILEGES["web"]["UPDATE"]

    def test_scheduler_role_cannot_update_the_login_attempt_counter(self):
        assert (
            "failed_login_count"
            not in database_privileges.USER_COLUMN_PRIVILEGES["scheduler"]["UPDATE"]
        )
