"""Unit tests for `app.runtime_preflight` and the assets it depends on."""

import ast
import fcntl
import os
import re
import shutil
import stat
import subprocess
import time
import tomllib
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest
from alembic.script import ScriptDirectory

from app import migrate, paths, runtime_preflight
from app.paths import ALEMBIC_DIR, ALEMBIC_INI, PROJECT_ROOT
from app.runtime_preflight import _alembic_config
from app.services.db_schema_contract import ColumnSpec


class TestApplicationColumnContracts:
    """`validate_application_column_contracts` accepts contracted columns and
    rejects uncontracted SQL columns or required inputs omitted from INSERT."""

    def test_application_column_contracts_accept_current_columns(self):
        """Check application column contracts accept current columns."""
        runtime_preflight.validate_application_column_contracts()

    @pytest.mark.parametrize("selected", [False, True])
    def test_new_required_column_must_be_in_insert_even_when_selected(self, monkeypatch, selected):
        """Check new required column must be in insert even when selected (RuntimeError)."""
        monkeypatch.setitem(
            runtime_preflight.DATASET_COLUMN_CONTRACT,
            "catalogue_revision",
            ColumnSpec("text", nullable=False),
        )
        if selected:
            monkeypatch.setattr(
                runtime_preflight,
                "DATASET_SELECT_COLUMNS",
                [*runtime_preflight.DATASET_SELECT_COLUMNS, "catalogue_revision"],
            )

        with pytest.raises(
            RuntimeError,
            match=r"Required dataset columns absent from INSERT: \['catalogue_revision'\]",
        ):
            runtime_preflight.validate_application_column_contracts()

    def test_new_required_column_is_covered_when_inserted(self, monkeypatch):
        """Check new required column is covered when inserted."""
        monkeypatch.setitem(
            runtime_preflight.DATASET_COLUMN_CONTRACT,
            "catalogue_revision",
            ColumnSpec("text", nullable=False),
        )
        monkeypatch.setattr(
            runtime_preflight,
            "DATASET_INSERT_COLUMNS",
            [*runtime_preflight.DATASET_INSERT_COLUMNS, "catalogue_revision"],
        )

        runtime_preflight.validate_application_column_contracts()

    @pytest.mark.parametrize(
        "spec",
        [
            ColumnSpec("text", nullable=True),
            ColumnSpec("text", nullable=False, default="'initial'::text"),
            ColumnSpec("integer", nullable=False, identity="a"),
            ColumnSpec("integer", nullable=False, identity="d"),
        ],
        ids=["nullable", "default", "identity-always", "identity-by-default"],
    )
    def test_server_supported_or_nullable_column_may_be_omitted(self, monkeypatch, spec):
        """Check server supported or nullable column may be omitted."""
        monkeypatch.setitem(runtime_preflight.DATASET_COLUMN_CONTRACT, "new_column", spec)

        runtime_preflight.validate_application_column_contracts()

    def test_explicitly_trigger_owned_required_column_may_be_omitted(self, monkeypatch):
        """Check explicitly trigger owned required column may be omitted."""
        monkeypatch.setitem(
            runtime_preflight.DATASET_COLUMN_CONTRACT,
            "trigger_value",
            ColumnSpec("text", nullable=False),
        )
        monkeypatch.setattr(
            runtime_preflight,
            "DATASET_TRIGGER_COLUMNS",
            [*runtime_preflight.DATASET_TRIGGER_COLUMNS, "trigger_value"],
        )

        runtime_preflight.validate_application_column_contracts()

    def test_required_input_errors_are_sorted_and_aggregated_with_existing_errors(
        self, monkeypatch
    ):
        """Check required input errors are sorted and aggregated with existing errors (RuntimeError)."""
        for name in ("z_required", "a_required"):
            monkeypatch.setitem(
                runtime_preflight.DATASET_COLUMN_CONTRACT, name, ColumnSpec("text", nullable=False)
            )
        monkeypatch.setattr(
            runtime_preflight,
            "DATASET_SELECT_COLUMNS",
            [*runtime_preflight.DATASET_SELECT_COLUMNS, "uuid"],
        )

        with pytest.raises(RuntimeError) as excinfo:
            runtime_preflight.validate_application_column_contracts()

        message = str(excinfo.value)
        assert "DATASET_SELECT_COLUMNS contains duplicate columns: ['uuid']" in message
        assert (
            "Required dataset columns absent from INSERT: ['a_required', 'z_required']" in message
        )

    @pytest.mark.parametrize(
        "column_list_name",
        (
            "DATASET_SELECT_COLUMNS",
            "DATASET_INSERT_COLUMNS",
            "DATASET_TRIGGER_COLUMNS",
            "USER_COLUMNS",
            "USER_COMPUTED_SOURCE_COLUMNS",
        ),
    )
    def test_application_column_contracts_reject_duplicate_columns(
        self, monkeypatch, column_list_name
    ):
        """Check application column contracts reject duplicate columns (RuntimeError)."""
        columns = list(getattr(runtime_preflight, column_list_name))
        monkeypatch.setattr(runtime_preflight, column_list_name, [*columns, columns[0]])

        with pytest.raises(RuntimeError, match=rf"{column_list_name}.*duplicate"):
            runtime_preflight.validate_application_column_contracts()

    def test_duplicate_and_missing_contract_errors_are_reported_together(self, monkeypatch):
        """Check duplicate and missing contract errors are reported together (RuntimeError)."""
        monkeypatch.setattr(
            runtime_preflight,
            "DATASET_SELECT_COLUMNS",
            [*runtime_preflight.DATASET_SELECT_COLUMNS, "uuid", "id", "uuid"],
        )
        monkeypatch.setattr(
            runtime_preflight,
            "USER_COLUMNS",
            [*runtime_preflight.USER_COLUMNS, "uncontracted_user_column"],
        )

        with pytest.raises(RuntimeError) as excinfo:
            runtime_preflight.validate_application_column_contracts()
        assert "DATASET_SELECT_COLUMNS contains duplicate columns: ['id', 'uuid']" in str(
            excinfo.value
        )
        assert "User SQL columns lack DB contracts: ['uncontracted_user_column']" in str(
            excinfo.value
        )

    @pytest.mark.parametrize(
        "column_list_name",
        (
            "DATASET_SELECT_COLUMNS",
            "DATASET_INSERT_COLUMNS",
            "DATASET_TRIGGER_COLUMNS",
        ),
    )
    def test_application_column_contracts_reject_dataset_column_without_contract(
        self,
        monkeypatch,
        column_list_name,
    ):
        """Check application column contracts reject dataset column without contract (RuntimeError)."""
        columns = getattr(runtime_preflight, column_list_name)
        monkeypatch.setattr(
            runtime_preflight,
            column_list_name,
            [*columns, "uncontracted_dataset_column"],
        )

        with pytest.raises(
            RuntimeError,
            match=r"Dataset SQL columns lack DB contracts:.*uncontracted_dataset_column",
        ):
            runtime_preflight.validate_application_column_contracts()

    @pytest.mark.parametrize(
        "column_list_name",
        ("USER_COLUMNS", "USER_COMPUTED_SOURCE_COLUMNS"),
    )
    def test_application_column_contracts_reject_user_column_without_contract(
        self,
        monkeypatch,
        column_list_name,
    ):
        """Check application column contracts reject user column without contract (RuntimeError)."""
        columns = getattr(runtime_preflight, column_list_name)
        monkeypatch.setattr(
            runtime_preflight,
            column_list_name,
            [*columns, "uncontracted_user_column"],
        )

        with pytest.raises(
            RuntimeError,
            match=r"User SQL columns lack DB contracts:.*uncontracted_user_column",
        ):
            runtime_preflight.validate_application_column_contracts()


class TestRuntimeSchemaCheckOrdering:
    """`validate_runtime_schema` fails closed at the first check and never
    reaches later, more expensive database checks once an earlier one fails."""

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_search_document_mismatch_stops_before_database_checks(
        self, monkeypatch, process
    ):
        """Check search document mismatch stops before database checks (RuntimeError)."""
        check = create_autospec(runtime_preflight.assert_search_document_contract, spec_set=True)
        check.side_effect = RuntimeError("search document sentinel")
        monkeypatch.setattr(runtime_preflight, "assert_search_document_contract", check)
        database_checks = []
        for name in (
            "validate_runtime_database_role",
            "validate_alembic_head",
            "validate_schema_against_db",
        ):
            database_check = create_autospec(getattr(runtime_preflight, name), spec_set=True)
            monkeypatch.setattr(runtime_preflight, name, database_check)
            database_checks.append(database_check)

        with pytest.raises(RuntimeError, match="search document sentinel"):
            await runtime_preflight.validate_runtime_schema(object(), process=process)
        check.assert_called_once_with()
        for database_check in database_checks:
            database_check.assert_not_awaited()

    @pytest.mark.parametrize(
        "column_list_name", ("DATASET_TRIGGER_COLUMNS", "USER_COMPUTED_SOURCE_COLUMNS")
    )
    async def test_duplicate_auxiliary_columns_fail_before_database_checks(
        self, monkeypatch, column_list_name
    ):
        """Check duplicate auxiliary columns fail before database checks (RuntimeError)."""
        columns = list(getattr(runtime_preflight, column_list_name))
        monkeypatch.setattr(runtime_preflight, column_list_name, [*columns, columns[0]])
        database_checks = []
        for name in (
            "validate_runtime_database_role",
            "validate_alembic_head",
            "validate_schema_against_db",
        ):
            check = create_autospec(getattr(runtime_preflight, name), spec_set=True)
            monkeypatch.setattr(runtime_preflight, name, check)
            database_checks.append(check)

        with pytest.raises(RuntimeError, match=rf"{column_list_name}.*duplicate"):
            await runtime_preflight.validate_runtime_schema(object(), process="web")
        for check in database_checks:
            check.assert_not_awaited()

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_required_dataset_input_fails_before_database_checks(self, monkeypatch, process):
        """Check required dataset input fails before database checks (RuntimeError)."""
        monkeypatch.setitem(
            runtime_preflight.DATASET_COLUMN_CONTRACT,
            "catalogue_revision",
            ColumnSpec("text", nullable=False),
        )
        database_checks = []
        for name in (
            "validate_runtime_database_role",
            "validate_alembic_head",
            "validate_schema_against_db",
        ):
            check = create_autospec(getattr(runtime_preflight, name), spec_set=True)
            monkeypatch.setattr(runtime_preflight, name, check)
            database_checks.append(check)

        with pytest.raises(
            RuntimeError, match=r"Required dataset columns absent from INSERT:.*catalogue_revision"
        ):
            await runtime_preflight.validate_runtime_schema(object(), process=process)
        for check in database_checks:
            check.assert_not_awaited()

    async def test_runtime_schema_runs_application_contract_before_database_checks(
        self,
        monkeypatch,
    ):
        """Check runtime schema runs application contract before database checks (RuntimeError)."""
        local_validators = (
            "validate_dataset_schema",
            "validate_dataset_insert_schema",
            "validate_user_schema",
            "assert_field_visibility_total",
            "assert_tier_rank_complete",
            "assert_search_mask_contract",
            "assert_search_document_contract",
        )
        for validator_name in local_validators:
            monkeypatch.setattr(
                runtime_preflight,
                validator_name,
                create_autospec(getattr(runtime_preflight, validator_name), spec_set=True),
            )

        contract_check = create_autospec(
            runtime_preflight.validate_application_column_contracts, spec_set=True
        )
        contract_check.side_effect = RuntimeError("application contract sentinel")
        role_check = create_autospec(
            runtime_preflight.validate_runtime_database_role, spec_set=True
        )
        alembic_check = create_autospec(runtime_preflight.validate_alembic_head, spec_set=True)
        database_check = create_autospec(
            runtime_preflight.validate_schema_against_db, spec_set=True
        )
        monkeypatch.setattr(
            runtime_preflight, "validate_application_column_contracts", contract_check
        )
        monkeypatch.setattr(runtime_preflight, "validate_runtime_database_role", role_check)
        monkeypatch.setattr(runtime_preflight, "validate_alembic_head", alembic_check)
        monkeypatch.setattr(runtime_preflight, "validate_schema_against_db", database_check)

        with pytest.raises(RuntimeError, match="application contract sentinel"):
            await runtime_preflight.validate_runtime_schema(object(), process="web")

        contract_check.assert_called_once_with()
        role_check.assert_not_awaited()
        alembic_check.assert_not_awaited()
        database_check.assert_not_awaited()

    @pytest.mark.parametrize("process", ("web", "scheduler"))
    async def test_runtime_schema_checks_exact_process_role_before_schema(
        self,
        monkeypatch,
        process,
    ):
        """Check runtime schema checks exact process role before schema (RuntimeError)."""
        for validator_name in (
            "validate_dataset_schema",
            "validate_dataset_insert_schema",
            "validate_user_schema",
            "assert_field_visibility_total",
            "assert_tier_rank_complete",
            "assert_search_mask_contract",
            "assert_search_document_contract",
            "validate_application_column_contracts",
        ):
            monkeypatch.setattr(
                runtime_preflight,
                validator_name,
                create_autospec(getattr(runtime_preflight, validator_name), spec_set=True),
            )

        role_check = create_autospec(
            runtime_preflight.validate_runtime_database_role, spec_set=True
        )
        role_check.side_effect = RuntimeError("role sentinel")
        alembic_check = create_autospec(runtime_preflight.validate_alembic_head, spec_set=True)
        database_check = create_autospec(
            runtime_preflight.validate_schema_against_db, spec_set=True
        )
        monkeypatch.setattr(runtime_preflight, "validate_runtime_database_role", role_check)
        monkeypatch.setattr(runtime_preflight, "validate_alembic_head", alembic_check)
        monkeypatch.setattr(runtime_preflight, "validate_schema_against_db", database_check)

        pool = object()
        with pytest.raises(RuntimeError, match="role sentinel"):
            await runtime_preflight.validate_runtime_schema(pool, process=process)

        role_check.assert_awaited_once_with(pool, process)
        alembic_check.assert_not_awaited()
        database_check.assert_not_awaited()


class TestPackagedMigrationAssets:
    """The Alembic assets packaged with the application wheel are complete,
    take precedence over any source-tree fallback, and the CLI wraps them."""

    def test_migration_repository_and_runtime_head_are_available(self):
        """Check migration repository and runtime head are available."""
        assert ALEMBIC_INI.is_file()
        assert (ALEMBIC_DIR / "env.py").is_file()
        assert (ALEMBIC_DIR / "script.py.mako").is_file()
        assert ScriptDirectory.from_config(_alembic_config()).get_heads() == ["4f73ae3ff827"]

    def test_packaged_migration_repository_contains_the_initial_migration(self):
        """Package the single reviewed fresh-schema baseline."""
        script_directory = ScriptDirectory.from_config(_alembic_config())
        revisions = list(script_directory.walk_revisions())
        assert [(revision.revision, revision.down_revision) for revision in revisions] == [
            ("4f73ae3ff827", None),
        ]

    def test_wheel_contains_both_migration_inputs(self):
        """Check wheel contains both migration inputs."""
        config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
        included = config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
        assert included["src/alembic"] == "app/_migration_assets/alembic"
        assert included["src/alembic.ini"] == "app/_migration_assets/alembic.ini"

    def test_missing_wheel_assets_fail_instead_of_using_dependency_directory(
        self, tmp_path, monkeypatch
    ):
        """Check missing wheel assets fail instead of using dependency directory (RuntimeError)."""
        monkeypatch.setattr(paths, "SRC_DIR", tmp_path / "site-packages")
        monkeypatch.setattr(paths, "files", lambda _package: tmp_path / "app")
        with pytest.raises(RuntimeError, match="migration assets are missing"):
            paths._migration_paths()

    def test_packaged_assets_take_precedence_over_source_fallback(self, tmp_path, monkeypatch):
        """Check packaged assets take precedence over source fallback."""
        bundled = tmp_path / "_migration_assets"
        scripts = bundled / "alembic"
        (scripts / "versions").mkdir(parents=True)
        (scripts / "env.py").write_text("# migration environment")
        (bundled / "alembic.ini").write_text("[alembic]")
        monkeypatch.setattr(paths, "files", lambda _package: tmp_path)
        assert paths._migration_paths() == (bundled / "alembic.ini", scripts)

    def test_migration_cli_uses_explicit_config(self, monkeypatch):
        """Check migration CLI uses explicit config."""
        monkeypatch.setattr(migrate.sys, "argv", ["app.migrate", "heads"])
        with patch.object(migrate, "CommandLine", autospec=True) as cli:
            migrate.main()
        cli.return_value.main.assert_called_once_with(argv=["-c", str(ALEMBIC_INI), "heads"])


# These doubles verify script behavior; deployed owners, ACLs, custody, and restores need host checks.

BACKUP_SCRIPT = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup.sh"
VERIFY_SCRIPT = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup-verify.sh"
BACKUP_SERVICE = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup.service"
BACKUP_TIMER = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup.timer"
BACKUP_CONFIG = PROJECT_ROOT / "deploy" / "oralhistarchiv-backup.conf.example"
DEPLOYMENT_RUNBOOK = PROJECT_ROOT / "Deployment.md"
DEPLOYMENT_OVERVIEW = PROJECT_ROOT / "docs" / "configuration" / "deployment.md"
SOURCE_B_CONTRACT = PROJECT_ROOT / "docs" / "architecture" / "source-b-ingestion-contract.md"
GITIGNORE = PROJECT_ROOT / ".gitignore"


def _write_executable(path: Path, content: str) -> None:
    """Write the selected script text and set owner-only executable permissions."""
    path.write_text(content)
    path.chmod(0o700)


def _fake_backup_tools(fake_bin: Path) -> None:
    """Write logging command doubles with environment-controlled backup failure points."""
    fake_bin.mkdir(mode=0o700)
    _write_executable(
        fake_bin / "flock",
        """#!/bin/bash
set -u
printf 'flock %s\n' "$*" >>"$CALL_LOG"
exit "${FAKE_FLOCK_EXIT:-0}"
""",
    )
    _write_executable(
        fake_bin / "pg_dump",
        """#!/bin/bash
set -u
printf 'pg_dump %s\n' "$*" >>"$CALL_LOG"
printf 'CUSTOM-ARCHIVE\n'
exit "${FAKE_PG_DUMP_EXIT:-0}"
""",
    )
    _write_executable(
        fake_bin / "psql",
        """#!/bin/bash
set -u
printf 'psql %s\n' "$*" >>"$CALL_LOG"
/bin/cat >"$CALL_LOG.psql.sql"
printf '%s\n' "${FAKE_PSQL_RESULT:-ready}"
exit "${FAKE_PSQL_EXIT:-0}"
""",
    )
    _write_executable(
        fake_bin / "pg_restore",
        """#!/bin/bash
set -u
printf 'pg_restore %s\n' "$*" >>"$CALL_LOG"
exit "${FAKE_PG_RESTORE_EXIT:-0}"
""",
    )
    _write_executable(
        fake_bin / "age",
        """#!/bin/bash
set -u
printf 'age %s\n' "$*" >>"$CALL_LOG"
if [[ ${FAKE_AGE_EXIT:-0} != 0 ]]; then
    printf 'PARTIAL-ENCRYPTED\n'
    exit "$FAKE_AGE_EXIT"
fi
if [[ $1 == --encrypt ]]; then
    printf 'AGE-ENCRYPTED\n'
    /bin/cat
else
    /bin/cat "${@: -1}"
fi
""",
    )
    _write_executable(
        fake_bin / "cat",
        """#!/bin/bash
set -u
/bin/cat >/dev/null
exit "${FAKE_CAT_EXIT:-0}"
""",
    )


def _patched_script(
    source: Path, destination: Path, fake_bin: Path, commands: tuple[str, ...]
) -> Path:
    """Copy a backup script with local lock and command paths, requiring every command reference."""
    text = source.read_text()
    deployment_lock = destination.parent / "deployment.lock"
    deployment_lock.touch(exist_ok=True)
    text = text.replace("/run/lock/oralhistarchiv-deploy.lock", str(deployment_lock))
    for command in commands:
        production_path = f"/usr/bin/{command}"
        replacement = str(fake_bin / command)
        assert text.count(production_path) >= 2
        text = text.replace(production_path, replacement)
    _write_executable(destination, text)
    return destination


def _backup_environment(tmp_path: Path, backup_dir: Path, call_log: Path) -> dict[str, str]:
    """Create a local PostgreSQL socket directory and return synthetic backup environment values."""
    socket_dir = tmp_path / "postgresql-socket"
    socket_dir.mkdir()
    return {
        **os.environ,
        "BACKUP_AGE_RECIPIENT": "age1testrecipient",
        "BACKUP_DIR": str(backup_dir),
        "BACKUP_RETENTION_DAYS": "30",
        "PGHOST": str(socket_dir),
        "PGDATABASE": "oralhistarchiv_test",
        "PGUSER": "oralhistarchiv_backup",
        "CALL_LOG": str(call_log),
    }


def _run_with_permissive_parent_umask(script: Path, env: dict[str, str]):
    """Run the backup under umask 022 and capture stdout, stderr, and exit status."""
    return subprocess.run(
        ["/bin/bash", "-c", 'umask 022; exec "$1"', "backup-test", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


class TestBackupScriptStaticContract:
    """The backup and verification scripts are valid and pin every security
    tool to an absolute, non-overridable path with the expected head."""

    def test_backup_scripts_have_valid_bash_syntax(self):
        """Check backup scripts have valid bash syntax."""
        subprocess.run(
            ["/bin/bash", "-n", str(BACKUP_SCRIPT), str(VERIFY_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_backup_script_pins_absolute_security_tool_paths(self):
        """Check backup script pins absolute security tool paths."""
        text = BACKUP_SCRIPT.read_text()
        for command in ("age", "flock", "pg_dump", "psql"):
            assert f"/usr/bin/{command}" in text
        assert "set -Eeuo pipefail" in text
        assert "umask 077" in text
        assert 'export PGPASSFILE="/dev/null"' in text
        assert "| /usr/bin/age --encrypt" in text
        assert "oralhistarchiv-plaintext" not in text
        assert "current_user = :'expected_user'" in text
        assert "session_user = :'expected_user'" in text
        for required_relation in (
            "alembic_version",
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
        ):
            assert f"to_regclass('public.{required_relation}') IS NOT NULL" in text
        assert "source " not in text
        assert "eval " not in text

        revision_match = re.search(
            r'^readonly EXPECTED_ALEMBIC_REVISION="([^"]+)"$', text, re.MULTILINE
        )
        assert revision_match is not None
        assert [revision_match.group(1)] == ScriptDirectory.from_config(
            _alembic_config()
        ).get_heads()

        verifier = VERIFY_SCRIPT.read_text()
        assert "/usr/bin/pg_restore --list" in verifier
        assert "/usr/bin/cat >/dev/null" in verifier
        assert "/usr/bin/mktemp" not in verifier


@pytest.mark.parametrize(
    ("server_version", "client_major", "accepted"),
    [
        (179999, 17, False),
        (180000, 18, True),
        (180006, 18, True),
        (189999, 18, True),
        (190000, 19, False),
        (180000, 17, False),
        (180000, 19, False),
    ],
)
def test_native_feed_backup_tool_gate_requires_postgresql_18(
    monkeypatch, server_version, client_major, accepted
):
    """Execute the recovery tool gate without importing destructive integration fixtures."""
    source = PROJECT_ROOT / "src/tests/integration/test_source_b_backup_db.py"
    helper = next(
        node
        for node in ast.parse(source.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name == "_tools"
    )
    namespace: dict[str, object] = {"shutil": shutil, "subprocess": subprocess, "re": re}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"), namespace)
    tool_gate = namespace["_tools"]
    assert callable(tool_gate)
    monkeypatch.setattr(
        shutil, "which", create_autospec(shutil.which, return_value="/synthetic/tool")
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        create_autospec(
            subprocess.run,
            return_value=subprocess.CompletedProcess(
                ["/synthetic/tool", "--version"], 0, f"tool (PostgreSQL) {client_major}.6\n"
            ),
        ),
    )

    if accepted:
        assert set(tool_gate(server_version)) == {"pg_dump", "pg_restore", "age", "age-keygen"}
    else:
        with pytest.raises(AssertionError, match="requires"):
            tool_gate(server_version)


def _run_backup_cleanup(
    targets: dict[str, Path], incoming_status: int, *, close_stderr: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run the shipped cleanup EXIT trap in Bash against temporary paths and capture its result."""
    match = re.search(r"(?ms)^cleanup\(\) \{.*?^\}\n", BACKUP_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None, "backup cleanup function is missing"
    program = (
        "set -Eeuo pipefail\n"
        'encrypted_tmp="$TEST_ENCRYPTED_TMP"\n'
        'status_tmp="$TEST_STATUS_TMP"\n'
        + match.group(0)
        + ("exec 2>&-\n" if close_stderr else "")
        + 'trap cleanup EXIT\nexit "$TEST_INCOMING_STATUS"\n'
    )
    return subprocess.run(
        ["bash", "-c", program],
        env={
            "PATH": os.defpath,
            "TEST_ENCRYPTED_TMP": str(targets["encrypted"]),
            "TEST_STATUS_TMP": str(targets["status"]),
            "TEST_INCOMING_STATUS": str(incoming_status),
        },
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


class TestBackupExecutionBehavior:
    """The backup script only publishes an encrypted, mode-0600 archive on a
    fully successful run, and fails closed without publishing or pruning
    anything when any stage of the run fails."""

    @pytest.mark.parametrize("arguments", [("unexpected",), ("--help",), ("--", "extra")])
    def test_positional_arguments_fail_before_backup_preflight(self, tmp_path, arguments):
        """Reject every positional argument with status 64 before tools or backup state are touched."""
        backup_dir = tmp_path / "unprovisioned"
        result = subprocess.run(
            ["bash", str(BACKUP_SCRIPT), *arguments],
            env={"PATH": os.defpath, "BACKUP_DIR": str(backup_dir), "BACKUP_AGE_RECIPIENT": ""},
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        assert result.returncode == 64
        assert "Usage:" in result.stderr and "no arguments" in result.stderr
        assert result.stdout == ""
        assert not backup_dir.exists()

    @pytest.mark.parametrize("incoming_status", [0, 7])
    @pytest.mark.parametrize(
        "failed_removals", [(), ("encrypted",), ("status",), ("encrypted", "status")]
    )
    def test_cleanup_attempts_each_output_and_preserves_the_original_failure(
        self, tmp_path, incoming_status, failed_removals
    ):
        """Cleanup attempts both outputs and changes only a successful incoming status on failure."""
        targets = {}
        for name in ("encrypted", "status"):
            target = tmp_path / name
            if name in failed_removals:
                target.mkdir()
                (target / "contents").write_text("retained", encoding="utf-8")
            else:
                target.write_text("partial output", encoding="utf-8")
            targets[name] = target
        unrelated = tmp_path / "published.dump.age"
        unrelated.write_text("published ciphertext", encoding="utf-8")

        result = _run_backup_cleanup(targets, incoming_status)

        assert result.returncode == (incoming_status or bool(failed_removals))
        assert result.stderr.count("backup cleanup failed:") == len(failed_removals)
        for name, target in targets.items():
            assert target.exists() is (name in failed_removals)
        assert unrelated.read_text(encoding="utf-8") == "published ciphertext"
        if result.returncode:
            assert f"backup failed with exit status {result.returncode}" in result.stderr

    def test_cleanup_continues_when_its_diagnostic_stream_is_closed(self, tmp_path):
        """A failed cleanup diagnostic cannot skip the next removal or replace an existing error."""
        encrypted = tmp_path / "unremovable"
        encrypted.mkdir()
        status = tmp_path / "status"
        status.write_text("partial marker", encoding="utf-8")

        result = _run_backup_cleanup(
            {"encrypted": encrypted, "status": status}, 23, close_stderr=True
        )

        assert result.returncode == 23
        assert encrypted.is_dir()
        assert not status.exists()

    def test_success_publishes_only_encrypted_mode_0600_archive_and_then_prunes(self, tmp_path):
        """Check success publishes only encrypted mode 0600 archive and then prunes."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql"),
        )

        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(mode=0o700)
        oldest_archive = backup_dir / "oralhistarchiv_19990101T000000Z.dump.age"
        oldest_archive.write_text("oldest encrypted backup")
        oldest_archive.chmod(0o600)
        previous_archive = backup_dir / "oralhistarchiv_20000101T000000Z.dump.age"
        previous_archive.write_text("previous encrypted backup")
        previous_archive.chmod(0o600)
        old_time = time.time() - (45 * 24 * 60 * 60)
        os.utime(oldest_archive, (old_time - 10, old_time - 10))
        os.utime(previous_archive, (old_time, old_time))
        call_log = tmp_path / "calls.log"

        result = _run_with_permissive_parent_umask(
            script,
            _backup_environment(tmp_path, backup_dir, call_log),
        )

        assert result.returncode == 0, result.stderr
        final_archives = list(backup_dir.glob("oralhistarchiv_*.dump.age"))
        assert len(final_archives) == 2
        assert previous_archive in final_archives
        assert oldest_archive not in final_archives
        final_archive = next(archive for archive in final_archives if archive != previous_archive)
        assert stat.S_IMODE(final_archive.stat().st_mode) == 0o600
        assert final_archive.read_text().startswith("AGE-ENCRYPTED\nCUSTOM-ARCHIVE\n")
        assert not list(backup_dir.glob(".oralhistarchiv-*"))
        assert not list(backup_dir.glob("*.dump"))

        calls = call_log.read_text()
        assert "flock -n 9" in calls
        assert "psql " in calls
        assert "pg_dump " in calls
        assert "age --encrypt --recipient age1testrecipient" in calls
        assert calls.index("psql ") < calls.index("pg_dump ")
        assert calls.index("psql ") < calls.index("age --encrypt")
        assert "completed" in result.stdout.lower()

    @pytest.mark.parametrize(
        ("failure_variable", "failure_code"),
        [
            ("FAKE_PSQL_EXIT", "22"),
            ("FAKE_PG_DUMP_EXIT", "23"),
            ("FAKE_AGE_EXIT", "25"),
        ],
        ids=["schema_check_fails", "dump_fails", "encryption_fails"],
    )
    def test_failed_stage_publishes_nothing_and_does_not_prune(
        self, tmp_path, failure_variable, failure_code
    ):
        """Check failed stage publishes nothing and does not prune."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql"),
        )

        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(mode=0o700)
        old_archive = backup_dir / "oralhistarchiv_20000101T000000Z.dump.age"
        old_archive.write_text("known-good old archive")
        old_archive.chmod(0o600)
        old_time = time.time() - (45 * 24 * 60 * 60)
        os.utime(old_archive, (old_time, old_time))

        env = _backup_environment(tmp_path, backup_dir, tmp_path / "calls.log")
        env[failure_variable] = failure_code
        result = _run_with_permissive_parent_umask(script, env)

        assert result.returncode == int(failure_code)
        assert old_archive.read_text() == "known-good old archive"
        assert list(backup_dir.glob("oralhistarchiv_*.dump.age")) == [old_archive]
        assert not list(backup_dir.glob(".oralhistarchiv-*"))
        assert "completed" not in result.stdout.lower()
        assert "failed" in result.stderr.lower()

    def test_backup_refuses_permissive_directory_mode(self, tmp_path):
        """Check backup refuses permissive directory mode."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql"),
        )
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(mode=0o755)

        result = _run_with_permissive_parent_umask(
            script,
            _backup_environment(tmp_path, backup_dir, tmp_path / "calls.log"),
        )

        assert result.returncode != 0
        assert "mode 0700" in result.stderr
        assert list(backup_dir.iterdir()) == []

    def test_schema_preflight_fails_closed_before_dumping(self, tmp_path):
        """SB-VIS-009: a rejected recovery schema cannot publish or prune archives."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql"),
        )
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(mode=0o700)
        old_archives = [
            backup_dir / "oralhistarchiv_19990101T000000Z.dump.age",
            backup_dir / "oralhistarchiv_20000101T000000Z.dump.age",
        ]
        old_time = time.time() - (45 * 24 * 60 * 60)
        for number, archive in enumerate(old_archives):
            archive.write_text(f"known-good encrypted archive {number}")
            archive.chmod(0o600)
            os.utime(archive, (old_time + number, old_time + number))
        call_log = tmp_path / "calls.log"
        env = _backup_environment(tmp_path, backup_dir, call_log)
        env["FAKE_PSQL_RESULT"] = "not-ready"

        result = _run_with_permissive_parent_umask(script, env)

        assert result.returncode != 0
        assert "schema preflight failed" in result.stderr
        calls = call_log.read_text()
        assert "psql " in calls
        assert "pg_dump " not in calls and "age --encrypt" not in calls
        submitted_sql = call_log.with_name(f"{call_log.name}.psql.sql").read_text()
        assert "to_regclass('public.ingestion_failures') IS NOT NULL" in submitted_sql
        assert set(backup_dir.iterdir()) == set(old_archives)
        for number, archive in enumerate(old_archives):
            assert archive.read_text() == f"known-good encrypted archive {number}"
        assert "completed" not in result.stdout.lower()

    def test_next_run_removes_interrupted_ciphertext_before_publication(self, tmp_path):
        """Check next run removes interrupted ciphertext before publication."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql"),
        )
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir(mode=0o700)
        residue = backup_dir / ".oralhistarchiv-encrypted.interrupted"
        residue.write_text("partial ciphertext")
        residue.chmod(0o600)

        result = _run_with_permissive_parent_umask(
            script,
            _backup_environment(tmp_path, backup_dir, tmp_path / "calls.log"),
        )

        assert result.returncode == 0, result.stderr
        assert not residue.exists()
        assert not list(backup_dir.glob(".oralhistarchiv-encrypted.*"))
        assert len(list(backup_dir.glob("oralhistarchiv_*.dump.age"))) == 1


class TestBackupDeploymentLockGating:
    """The backup script waits on the exclusive deployment lock before doing
    any preflight work, and fails closed if it cannot acquire it in time."""

    def test_manual_backup_waits_for_deployment_lock_before_preflight(self, tmp_path):
        """Check manual backup waits for deployment lock before preflight."""
        fake_bin = tmp_path / "bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            BACKUP_SCRIPT, tmp_path / "backup.sh", fake_bin, ("psql", "pg_dump", "age")
        )
        # The real flock, wherever this host installs it: /usr/bin on the
        # Debian/Ubuntu deployment target, elsewhere on e.g. NixOS.
        system_flock = shutil.which("flock")
        assert system_flock is not None, "this test needs the util-linux flock binary"
        script.write_text(
            script.read_text()
            .replace("--timeout 60", "--timeout 0.05")
            .replace("/usr/bin/flock", system_flock)
        )

        backup_dir = tmp_path / "archives"
        backup_dir.mkdir(mode=0o700)
        call_log = tmp_path / "calls"
        with (tmp_path / "deployment.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = _run_with_permissive_parent_umask(
                script, _backup_environment(tmp_path, backup_dir, call_log)
            )
        assert result.returncode != 0
        assert "deployment lock unavailable" in result.stderr
        assert not call_log.exists()
        assert not list(backup_dir.iterdir())


class TestOffHostVerifier:
    """The off-host verifier decrypts and inspects an archive without ever
    writing plaintext to disk, and propagates every stage's failure code."""

    @pytest.mark.parametrize(
        ("failure_variable", "expected_code"),
        [
            (None, 0),
            ("FAKE_AGE_EXIT", 31),
            ("FAKE_PG_RESTORE_EXIT", 32),
            ("FAKE_CAT_EXIT", 33),
        ],
        ids=["verifies_clean_archive", "decrypt_fails", "restore_list_fails", "drain_fails"],
    )
    def test_off_host_verifier_streams_without_plaintext_and_propagates_failures(
        self, tmp_path, failure_variable, expected_code
    ):
        """Check off host verifier streams without plaintext and propagates failures."""
        fake_bin = tmp_path / "fake-bin"
        _fake_backup_tools(fake_bin)
        script = _patched_script(
            VERIFY_SCRIPT,
            tmp_path / "verify.sh",
            fake_bin,
            ("age", "cat", "pg_restore"),
        )

        archive = tmp_path / "archive.dump.age"
        # Larger than a typical pipe buffer: the fake pg_restore exits without
        # reading, so this proves the verifier drains age's authenticated
        # stream.
        archive.write_bytes(b"encrypted archive\n" + (b"x" * 2 * 1024 * 1024))
        archive.chmod(0o600)
        identity = tmp_path / "backup.agekey"
        identity.write_text("AGE-SECRET-KEY-test")
        identity.chmod(0o600)
        verification_tmp = tmp_path / "verification-tmp"
        verification_tmp.mkdir(mode=0o700)

        env = {
            **os.environ,
            "CALL_LOG": str(tmp_path / "calls.log"),
            "TMPDIR": str(verification_tmp),
        }
        if failure_variable is not None:
            env[failure_variable] = str(expected_code)

        result = subprocess.run(
            [str(script), str(archive), str(identity)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

        assert result.returncode == expected_code
        assert list(verification_tmp.iterdir()) == []
        calls = (tmp_path / "calls.log").read_text()
        assert "age --decrypt --identity" in calls
        assert "pg_restore --list" in calls
        if expected_code == 0:
            assert "verified" in result.stdout.lower()
        else:
            assert "verified" not in result.stdout.lower()


class TestBackupDeploymentContract:
    """The backup service unit, timer, configuration example, documentation
    and `.gitignore` entries all match the hardened backup design."""

    def test_backup_systemd_unit_pins_separate_identity_and_sandbox(self):
        """Check backup systemd unit pins separate identity and sandbox."""
        unit = BACKUP_SERVICE.read_text()
        required_lines = {
            "User=oralhistarchiv_backup",
            "Group=oralhistarchiv_backup",
            "EnvironmentFile=/etc/oralhistarchiv-backup.conf",
            "ExecStart=/usr/local/libexec/oralhistarchiv-backup",
            "StateDirectory=oralhistarchiv-backup",
            "StateDirectoryMode=0700",
            "UMask=0077",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectHome=true",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/oralhistarchiv-backup",
            "InaccessiblePaths=/opt/oralhistarchiv",
            "RestrictAddressFamilies=AF_UNIX",
        }
        assert required_lines <= set(unit.splitlines())
        assert "PrivateUsers=" not in unit
        assert "/opt/oralhistarchiv/deploy/oralhistarchiv-backup.sh" not in unit

        config = BACKUP_CONFIG.read_text()
        assert "BACKUP_AGE_RECIPIENT=age1" in config
        assert "PRIVATE" not in config
        assert "IDENTITY" not in config

    def test_backup_timer_is_persistent_and_enabled_by_timers_target(self):
        """Check backup timer is persistent and enabled by timers target."""
        timer = BACKUP_TIMER.read_text()
        assert "Persistent=true" in timer
        assert "Unit=oralhistarchiv-backup.service" in timer
        assert "WantedBy=timers.target" in timer

    def test_documentation_replaces_backup_cron_with_encrypted_host_checks(self):
        """Check documentation replaces backup cron with encrypted host checks."""
        runbook = DEPLOYMENT_RUNBOOK.read_text()
        overview = DEPLOYMENT_OVERVIEW.read_text()
        source_b_contract = SOURCE_B_CONTRACT.read_text()
        normalized_runbook = " ".join(runbook.split())

        assert "sudo crontab -u oralhistarchiv" not in runbook
        assert "oralhistarchiv-backup.timer" in runbook
        assert "*.dump.age" in runbook
        assert "not encryption" in runbook
        assert "private identity" in runbook
        assert "off-host" in runbook
        assert "namei -l" in runbook
        assert "getfacl" in runbook
        assert "failure drill" in runbook
        assert "isolated, disposable PostgreSQL cluster" in runbook
        assert "--user-group" in runbook
        assert "local all oralhistarchiv_backup reject" in normalized_runbook
        assert "does **not** authenticate the producer" in runbook

        assert "pg_dump` cron" not in overview
        assert "encrypted systemd timer" in overview
        assert "private" in overview
        assert "held off-host" in overview

        assert "SB-VIS-009 — Recovery coverage" in source_b_contract
        assert "test_source_b_backup_db.py" in source_b_contract
        assert "one-database backup job is insufficient" in source_b_contract

    def test_gitignore_excludes_backup_and_private_identity_artifacts(self):
        """Check gitignore excludes backup and private identity artifacts."""
        ignored = set(GITIGNORE.read_text().splitlines())
        assert {
            "/backups/",
            "*.dump",
            "*.dump.*",
            "*.backup",
            "*.agekey",
            "*.agekey.*",
            ".oralhistarchiv-encrypted.*",
            ".pgpass",
            "pgpass.conf",
            "/pytest-of-root/",
        } <= ignored

    def _prepare(self, tmp_path):
        """Prepare backup tools, private archives, public status directory, and failure-injection
        environment.
        """
        fake_bin = tmp_path / "marker-tools"
        _fake_backup_tools(fake_bin)
        _write_executable(
            fake_bin / "find",
            """#!/bin/bash
set -eu
printf 'find %s\n' "$*" >>"$CALL_LOG"
if [[ " $* " == *" -mtime "* && ${FAKE_RETENTION_EXIT:-0} != 0 ]]; then
    exit "$FAKE_RETENTION_EXIT"
fi
exec /usr/bin/find "$@"
""",
        )
        _write_executable(
            fake_bin / "mv",
            """#!/bin/bash
set -eu
printf 'mv %s\n' "$*" >>"$CALL_LOG"
if [[ ${@: -1} == "$BACKUP_STATUS_DIR/last-success" && ${FAKE_MARKER_RENAME_EXIT:-0} != 0 ]]; then
    exit "$FAKE_MARKER_RENAME_EXIT"
fi
exec /usr/bin/mv "$@"
""",
        )
        _write_executable(
            fake_bin / "sync",
            """#!/bin/bash
set -eu
printf 'sync %s\n' "$*" >>"$CALL_LOG"
if [[ ${@: -1} == "$BACKUP_STATUS_DIR/".oralhistarchiv-backup-status.* && ${FAKE_MARKER_SYNC_EXIT:-0} != 0 ]]; then
    exit "$FAKE_MARKER_SYNC_EXIT"
fi
if [[ ${@: -1} == "$BACKUP_STATUS_DIR" && ${FAKE_STATUS_DIRECTORY_SYNC_EXIT:-0} != 0 ]]; then
    exit "$FAKE_STATUS_DIRECTORY_SYNC_EXIT"
fi
exec /usr/bin/sync "$@"
""",
        )
        script = _patched_script(
            BACKUP_SCRIPT,
            tmp_path / "backup-marker.sh",
            fake_bin,
            ("age", "flock", "pg_dump", "psql", "find", "mv", "sync"),
        )
        backup_dir = tmp_path / "archives"
        backup_dir.mkdir(mode=0o700)
        status_dir = tmp_path / "publication-status"
        status_dir.mkdir(mode=0o755)
        status_dir.chmod(0o755)
        call_log = tmp_path / "marker-calls.log"
        env = _backup_environment(tmp_path, backup_dir, call_log)
        env["BACKUP_STATUS_DIR"] = str(status_dir)
        return script, env, backup_dir, status_dir, call_log

    def _old_marker(self, status_dir):
        """Write and return an old world-readable backup-success marker."""
        marker = status_dir / "last-success"
        marker.write_bytes(b"OHA_BACKUP_SUCCESS_V1 1000000000\n")
        marker.chmod(0o644)
        return marker

    def test_success_publishes_nonsecret_readable_marker_after_durable_archive_and_retention(
        self, tmp_path
    ):
        """Check success publishes nonsecret readable marker after durable archive and retention."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        before = int(time.time())
        result = _run_with_permissive_parent_umask(script, env)
        after = int(time.time())

        assert result.returncode == 0, result.stderr
        marker = status_dir / "last-success"
        matched = re.fullmatch(rb"OHA_BACKUP_SUCCESS_V1 ([1-9][0-9]{0,11})\n", marker.read_bytes())
        assert matched is not None and before <= int(matched[1]) <= after
        assert len(marker.read_bytes()) <= 64
        assert stat.S_IMODE(marker.stat().st_mode) == 0o644
        assert stat.S_IMODE(status_dir.stat().st_mode) == 0o755
        assert list(status_dir.iterdir()) == [marker]
        archives = list(backup_dir.glob("*.dump.age"))
        assert len(archives) == 1 and stat.S_IMODE(archives[0].stat().st_mode) == 0o600
        assert stat.S_IMODE(backup_dir.stat().st_mode) == 0o700
        assert not list(backup_dir.glob("*.dump"))

        calls = call_log.read_text().splitlines()
        archive_rename = next(
            index
            for index, line in enumerate(calls)
            if line.startswith("mv ") and line.endswith(".dump.age")
        )
        retention = next(
            index
            for index, line in enumerate(calls)
            if line.startswith("find ") and " -mtime " in line
        )
        archive_syncs = [
            index for index, line in enumerate(calls) if line == f"sync -f {backup_dir}"
        ]
        marker_sync = next(
            index
            for index, line in enumerate(calls)
            if line.startswith(f"sync -f {status_dir}/.oralhistarchiv-backup-status.")
        )
        marker_rename = next(
            index
            for index, line in enumerate(calls)
            if line.startswith("mv ") and line.endswith("/last-success")
        )
        assert (
            archive_rename
            < archive_syncs[0]
            < retention
            < archive_syncs[-1]
            < marker_sync
            < marker_rename
        )
        assert marker_rename < calls.index(f"sync -f {status_dir}")

    @pytest.mark.parametrize("disabled", ["unset", "empty"])
    def test_disabled_marker_preserves_the_existing_backup_only_contract(self, tmp_path, disabled):
        """Check disabled marker preserves the existing backup only contract."""
        script, env, backup_dir, status_dir, _call_log = self._prepare(tmp_path)
        status_dir.rmdir()
        if disabled == "unset":
            env.pop("BACKUP_STATUS_DIR")
        else:
            env["BACKUP_STATUS_DIR"] = ""
        # The diagnostic substitutes need an empty default for their own logging.
        for tool in (script.parent / "marker-tools").iterdir():
            tool.write_text(
                tool.read_text().replace('"$BACKUP_STATUS_DIR', '"${BACKUP_STATUS_DIR:-}')
            )
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode == 0, result.stderr
        assert not status_dir.exists()
        assert len(list(backup_dir.glob("*.dump.age"))) == 1

    @pytest.mark.parametrize(
        ("variable", "failure_code"),
        [
            ("FAKE_PSQL_EXIT", "22"),
            ("FAKE_PG_DUMP_EXIT", "23"),
            ("FAKE_AGE_EXIT", "25"),
            ("FAKE_RETENTION_EXIT", "43"),
            ("FAKE_MARKER_RENAME_EXIT", "45"),
            ("FAKE_MARKER_SYNC_EXIT", "46"),
        ],
    )
    def test_failure_before_marker_rename_keeps_the_previous_timestamp(
        self, tmp_path, variable, failure_code
    ):
        """Check failure before marker rename keeps the previous timestamp."""
        script, env, _backup_dir, status_dir, _call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        env[variable] = failure_code
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode == int(failure_code), result.stderr
        assert marker.read_bytes() == original
        assert list(status_dir.iterdir()) == [marker]
        assert "completed" not in result.stdout.lower()

    def test_failure_after_marker_rename_still_requires_independent_unit_monitoring(self, tmp_path):
        """Check failure after marker rename still requires independent unit monitoring."""
        script, env, backup_dir, status_dir, _call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        env["FAKE_STATUS_DIRECTORY_SYNC_EXIT"] = "47"
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode == 47
        assert marker.read_bytes() != original
        assert re.fullmatch(rb"OHA_BACKUP_SUCCESS_V1 [1-9][0-9]{0,11}\n", marker.read_bytes())
        assert len(list(backup_dir.glob("*.dump.age"))) == 1
        assert list(status_dir.iterdir()) == [marker]
        assert "completed" not in result.stdout.lower()

    @pytest.mark.parametrize("mode", [0o700, 0o750, 0o775, 0o777])
    def test_status_directory_permissions_are_checked_before_database_access(self, tmp_path, mode):
        """Check status directory permissions are checked before database access."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        status_dir.chmod(mode)
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode != 0 and "mode 0755" in result.stderr
        assert marker.read_bytes() == original
        assert not call_log.exists()
        assert list(backup_dir.iterdir()) == []

    @pytest.mark.parametrize(
        "case", ["relative", "root", "trailing", "dot", "parent", "symlink", "ancestor"]
    )
    def test_unsafe_status_paths_are_refused_before_database_access(self, tmp_path, case):
        """Check unsafe status paths are refused before database access."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        if case in {"relative", "root", "trailing", "dot", "parent"}:
            env["BACKUP_STATUS_DIR"] = {
                "relative": "publication-status",
                "root": "/",
                "trailing": f"{status_dir}/",
                "dot": f"{status_dir}/.",
                "parent": f"{status_dir}/../publication-status",
            }[case]
        elif case == "symlink":
            link = tmp_path / "status-link"
            link.symlink_to(status_dir, target_is_directory=True)
            env["BACKUP_STATUS_DIR"] = str(link)
        else:
            link = tmp_path / "ancestor-link"
            link.symlink_to(tmp_path, target_is_directory=True)
            env["BACKUP_STATUS_DIR"] = str(link / status_dir.name)
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode != 0
        assert marker.read_bytes() == original
        assert not call_log.exists()
        assert list(backup_dir.iterdir()) == []

    @pytest.mark.parametrize(
        "case", ["symlink", "broken", "hardlink", "directory", "fifo", "writable", "private"]
    )
    def test_unexpected_existing_marker_is_preserved_without_starting_a_dump(self, tmp_path, case):
        """Check unexpected existing marker is preserved without starting a dump."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        marker = status_dir / "last-success"
        other = tmp_path / "unrelated-file"
        other.write_text("unrelated content must survive")
        other.chmod(0o644)
        if case == "symlink":
            marker.symlink_to(other)
        elif case == "broken":
            marker.symlink_to(tmp_path / "absent")
        elif case == "hardlink":
            os.link(other, marker)
        elif case == "directory":
            marker.mkdir()
        elif case == "fifo":
            os.mkfifo(marker)
        else:
            self._old_marker(status_dir)
            marker.chmod(0o666 if case == "writable" else 0o600)
        original = marker.lstat()
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode != 0
        current = marker.lstat()
        assert (current.st_ino, current.st_mode) == (original.st_ino, original.st_mode)
        assert other.read_text() == "unrelated content must survive"
        assert list(backup_dir.iterdir()) == []
        assert "psql " not in call_log.read_text()

    def test_shared_status_directory_lock_refuses_a_second_writer_before_sql(self, tmp_path):
        """Check shared status directory lock refuses a second writer before SQL."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        system_flock = shutil.which("flock")
        assert system_flock is not None
        script.write_text(
            script.read_text().replace(str(tmp_path / "marker-tools/flock"), system_flock)
        )
        descriptor = os.open(status_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = _run_with_permissive_parent_umask(script, env)
        finally:
            os.close(descriptor)
        assert result.returncode != 0 and "status-directory lock" in result.stderr
        assert marker.read_bytes() == original
        assert not call_log.exists()
        assert list(backup_dir.iterdir()) == []

    @pytest.mark.parametrize("target", ["directory", "marker"])
    def test_status_ownership_mismatch_refuses_before_database_access(self, tmp_path, target):
        """Check status ownership mismatch refuses before database access."""
        script, env, backup_dir, status_dir, call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        owner_probe = tmp_path / "marker-tools/stat"
        _write_executable(
            owner_probe,
            """#!/bin/bash
set -eu
if [[ $FAKE_OWNER_TARGET == directory && $2 == '%u' && ${@: -1} == "$BACKUP_STATUS_DIR" ]]; then
    printf '%s\n' "$FAKE_WRONG_OWNER"
elif [[ $FAKE_OWNER_TARGET == marker && ${@: -1} == "$BACKUP_STATUS_DIR/last-success" ]]; then
    printf '%s 644 1\n' "$FAKE_WRONG_OWNER"
else
    exec /usr/bin/stat "$@"
fi
""",
        )
        script.write_text(script.read_text().replace("/usr/bin/stat", str(owner_probe)))
        env["FAKE_OWNER_TARGET"] = target
        env["FAKE_WRONG_OWNER"] = str(os.getuid() + 1)
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode != 0
        assert marker.read_bytes() == original
        assert list(backup_dir.iterdir()) == []
        assert not call_log.exists() or "psql " not in call_log.read_text()

    @pytest.mark.parametrize("epoch", ["0", "-1", "00042", "not-an-epoch", "1000000000000"])
    def test_noncanonical_completion_clock_never_replaces_a_marker(self, tmp_path, epoch):
        """Check noncanonical completion clock never replaces a marker."""
        script, env, backup_dir, status_dir, _call_log = self._prepare(tmp_path)
        marker = self._old_marker(status_dir)
        original = marker.read_bytes()
        clock = tmp_path / "marker-tools/date"
        _write_executable(
            clock,
            """#!/bin/bash
set -eu
if [[ ${@: -1} == +%s ]]; then
    printf '%s\n' "$FAKE_STATUS_EPOCH"
else
    exec /usr/bin/date "$@"
fi
""",
        )
        script.write_text(script.read_text().replace("/usr/bin/date", str(clock)))
        env["FAKE_STATUS_EPOCH"] = epoch
        result = _run_with_permissive_parent_umask(script, env)
        assert result.returncode != 0 and "canonical positive Unix epoch" in result.stderr
        assert marker.read_bytes() == original
        assert list(status_dir.iterdir()) == [marker]
        assert len(list(backup_dir.glob("*.dump.age"))) == 1

    def test_reference_deployment_keeps_timestamp_access_separate_from_archive_access(self):
        """Check reference deployment keeps timestamp access separate from archive access."""
        unit = BACKUP_SERVICE.read_text()
        config = BACKUP_CONFIG.read_text()
        tmpfiles = (PROJECT_ROOT / "deploy/oralhistarchiv-backup-tmpfiles.conf").read_text()
        base_tmpfiles = (PROJECT_ROOT / "deploy/oralhistarchiv-tmpfiles.conf").read_text()
        assert "ReadWritePaths=-/var/lib/oralhistarchiv-backup-status" in unit.splitlines()
        assert "ReadWritePaths=/var/lib/oralhistarchiv-backup" in unit.splitlines()
        assert "StateDirectoryMode=0700" in unit.splitlines()
        assert "BACKUP_STATUS_DIR=/var/lib/oralhistarchiv-backup-status" in config.splitlines()
        assert (
            "d /var/lib/oralhistarchiv-backup-status 0755 oralhistarchiv_backup oralhistarchiv_backup -"
            in tmpfiles.splitlines()
        )
        assert (
            "f /run/lock/oralhistarchiv-deploy.lock 0640 root oralhistarchiv-deploy-lock -"
            in base_tmpfiles.splitlines()
        )
        assert not any(
            line.startswith("d /var/lib/oralhistarchiv-backup-status ")
            for line in base_tmpfiles.splitlines()
        )
        assert [line for line in unit.splitlines() if line.startswith("SupplementaryGroups=")] == [
            "SupplementaryGroups=oralhistarchiv-deploy-lock"
        ]
