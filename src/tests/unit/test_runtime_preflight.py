"""Unit tests for `app.runtime_preflight` and the assets it depends on.

Covers the column-contract and ordering checks `runtime_preflight` runs
itself, the packaged Alembic migration assets it points at, and the backup
script's hardening as preflight sees it (the script shares the same Alembic
head check via `_alembic_config`).
"""

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


class TestApplicationColumnContracts:
    """`validate_application_column_contracts` accepts contracted columns and
    rejects any application SQL column missing a matching DB contract."""

    def test_application_column_contracts_accept_current_columns(self):

        runtime_preflight.validate_application_column_contracts()

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

    async def test_runtime_schema_runs_application_contract_before_database_checks(
        self,
        monkeypatch,
    ):

        local_validators = (
            "validate_dataset_schema",
            "validate_dataset_insert_schema",
            "validate_user_schema",
            "assert_redaction_total",
            "assert_tier_rank_complete",
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

        for validator_name in (
            "validate_dataset_schema",
            "validate_dataset_insert_schema",
            "validate_user_schema",
            "assert_redaction_total",
            "assert_tier_rank_complete",
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
        assert ALEMBIC_INI.is_file()
        assert (ALEMBIC_DIR / "env.py").is_file()
        assert (ALEMBIC_DIR / "script.py.mako").is_file()
        assert ScriptDirectory.from_config(_alembic_config()).get_heads() == ["4f73ae3ff827"]

    def test_packaged_migration_repository_contains_the_initial_migration(self):
        """The force-included `src/alembic` directory (see
        `test_wheel_contains_both_migration_inputs`) is exactly one revision
        today, and that revision is both the runtime head and the initial
        migration (`down_revision is None`) — so the wheel cannot ship a head
        pointer without the schema-creating revision it points at."""
        script_directory = ScriptDirectory.from_config(_alembic_config())
        revisions = list(script_directory.walk_revisions())
        assert len(revisions) == 1
        (revision,) = revisions
        assert revision.revision == "4f73ae3ff827"
        assert revision.down_revision is None

    def test_wheel_contains_both_migration_inputs(self):
        config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
        included = config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
        assert included["src/alembic"] == "app/_migration_assets/alembic"
        assert included["src/alembic.ini"] == "app/_migration_assets/alembic.ini"

    def test_missing_wheel_assets_fail_instead_of_using_dependency_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(paths, "SRC_DIR", tmp_path / "site-packages")
        monkeypatch.setattr(paths, "files", lambda _package: tmp_path / "app")
        with pytest.raises(RuntimeError, match="migration assets are missing"):
            paths._migration_paths()

    def test_packaged_assets_take_precedence_over_source_fallback(self, tmp_path, monkeypatch):
        bundled = tmp_path / "_migration_assets"
        scripts = bundled / "alembic"
        (scripts / "versions").mkdir(parents=True)
        (scripts / "env.py").write_text("# migration environment")
        (bundled / "alembic.ini").write_text("[alembic]")
        monkeypatch.setattr(paths, "files", lambda _package: tmp_path)
        assert paths._migration_paths() == (bundled / "alembic.ini", scripts)

    def test_migration_cli_uses_explicit_config(self, monkeypatch):
        monkeypatch.setattr(migrate.sys, "argv", ["app.migrate", "heads"])
        with patch.object(migrate, "CommandLine", autospec=True) as cli:
            migrate.main()
        cli.return_value.main.assert_called_once_with(argv=["-c", str(ALEMBIC_INI), "heads"])


# --- Backup script hardening, as preflight sees it -------------------------
#
# These tests prove the repository-supplied backup and verification scripts
# fail closed. They cannot prove the deployed host's owners, modes, ACLs,
# recipient, off-host custody, monitoring, or restore results; Deployment.md
# requires those checks explicitly. The helpers below are module-level
# because every scenario class below (execution behavior, the off-host
# verifier, and deployment-lock gating) shares them.

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
    path.write_text(content)
    path.chmod(0o700)


def _fake_backup_tools(fake_bin: Path) -> None:
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
        subprocess.run(
            ["/bin/bash", "-n", str(BACKUP_SCRIPT), str(VERIFY_SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_backup_script_pins_absolute_security_tool_paths(self):
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
            "sync_status",
            "users",
            "email_outbox",
            "sessions",
        ):
            assert f"public.{required_relation}" in text
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


class TestBackupExecutionBehavior:
    """The backup script only publishes an encrypted, mode-0600 archive on a
    fully successful run, and fails closed without publishing or pruning
    anything when any stage of the run fails."""

    def test_success_publishes_only_encrypted_mode_0600_archive_and_then_prunes(self, tmp_path):
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
        call_log = tmp_path / "calls.log"
        env = _backup_environment(tmp_path, backup_dir, call_log)
        env["FAKE_PSQL_RESULT"] = "not-ready"

        result = _run_with_permissive_parent_umask(script, env)

        assert result.returncode != 0
        assert "schema preflight failed" in result.stderr
        assert "pg_dump " not in call_log.read_text()
        assert list(backup_dir.iterdir()) == []

    def test_next_run_removes_interrupted_ciphertext_before_publication(self, tmp_path):
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
        """With the deployment lock held exclusively by another process, the
        backup script must fail before running any preflight check or
        publishing anything — no psql/pg_dump/age invocation may start while
        that lock is held. Exercises the real system `flock` (only
        psql/pg_dump/age are faked) against a short test deadline."""
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
        timer = BACKUP_TIMER.read_text()
        assert "Persistent=true" in timer
        assert "Unit=oralhistarchiv-backup.service" in timer
        assert "WantedBy=timers.target" in timer

    def test_documentation_replaces_backup_cron_with_encrypted_host_checks(self):
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
