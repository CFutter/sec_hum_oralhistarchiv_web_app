"""Retained-database evidence is standalone, bounded and published privately."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import create_autospec, patch

import psycopg
import pytest
from psycopg.pq import TransactionStatus

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _PROJECT_ROOT / "scripts/inventory_staging.py"
_SECRET = "staging-inventory-secret-canary"


def _load_inventory(script=_SCRIPT):
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location("staging_inventory_under_test", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


inventory = _load_inventory()


@pytest.fixture
def private_output(tmp_path):
    """Create private output and checkout directories and return their intended paths."""
    parent = tmp_path / "private-evidence"
    parent.mkdir(mode=0o700)
    repository = tmp_path / "checkout"
    repository.mkdir(mode=0o700)
    return parent / "inventory.json", repository


def test_import_does_not_start_the_application_or_connect_to_a_database():
    """Check import does not start the application or connect to a database."""
    source = (
        "'''Load the inventory script at argv[1] without app imports or database connections.'''\n"
        "import runpy, sys\n"
        "from unittest.mock import patch\n"
        "import psycopg\n"
        "class RejectApplicationImports:\n"
        "    '''Reject application imports while delegating other module searches.'''\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        "        '''Raise AssertionError for app imports; otherwise return None.'''\n"
        "        if fullname == 'app' or fullname.startswith('app.'):\n"
        "            raise AssertionError('application import during inventory loading')\n"
        "sys.meta_path.insert(0, RejectApplicationImports())\n"
        "with patch.object(psycopg, 'connect', autospec=True) as connect:\n"
        "    runpy.run_path(sys.argv[1], run_name='inventory_import_probe')\n"
        "    connect.assert_not_called()\n"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-c", source, str(_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


def test_checkout_execution_infers_the_actual_project_root():
    """Check checkout execution infers the actual project root."""
    assert inventory.PROJECT_ROOT == _PROJECT_ROOT


@pytest.mark.parametrize("path", ["/tmp/inventory_staging.py", "/opt/tools/inventory_staging.py"])
def test_standalone_installation_prefix_is_not_mistaken_for_a_checkout(path):
    """Check standalone installation prefix is not mistaken for a checkout."""
    assert inventory._checkout_root(Path(path)) is None


def test_copied_standalone_script_publishes_outside_explicit_reviewed_roots(
    private_output, tmp_path
):
    """Check copied standalone script publishes outside explicit reviewed roots."""
    destination, repository = private_output
    script = tmp_path / "inventory_staging.py"
    shutil.copyfile(_SCRIPT, script)
    standalone = _load_inventory(script)
    second_repository = tmp_path / "other-checkout"
    second_repository.mkdir()
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.__enter__.return_value = connection
    report = {"report_version": 1}
    assert standalone.PROJECT_ROOT is None

    with (
        patch.object(standalone.psycopg, "connect", autospec=True, return_value=connection),
        patch.object(standalone, "collect_inventory", autospec=True, return_value=report),
    ):
        result = standalone.main(
            [
                "--expected-database",
                "retained_staging",
                "--output",
                str(destination),
                "--exclude-root",
                str(repository),
                "--exclude-root",
                str(second_repository),
            ]
        )

    assert result == 0
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_report_is_complete_private_json_and_cannot_replace_existing_evidence(private_output):
    """Check report is complete private JSON and cannot replace existing evidence."""
    destination, repository = private_output
    report = {"report_version": 1, "managed_state": {"tables": []}, "limitations": ["review"]}
    previous_umask = os.umask(0o022)
    try:
        inventory.write_report(report, destination, repository_root=repository)
    finally:
        os.umask(previous_umask)

    assert json.loads(destination.read_text(encoding="utf-8")) == report
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert destination.stat().st_uid == os.getuid()
    assert destination.stat().st_nlink == 1
    assert set(destination.parent.iterdir()) == {destination}
    original = destination.read_bytes()

    with pytest.raises((inventory.InventoryRefusal, OSError)):
        inventory.write_report({"replacement": True}, destination, repository_root=repository)

    assert destination.read_bytes() == original
    assert set(destination.parent.iterdir()) == {destination}


@pytest.mark.parametrize("mode", [0o755, 0o770])
def test_report_refuses_a_parent_readable_or_writable_by_other_users(private_output, mode):
    """Check report refuses a parent readable or writable by other users."""
    destination, repository = private_output
    destination.parent.chmod(mode)

    with pytest.raises((inventory.InventoryRefusal, OSError)):
        inventory.write_report({}, destination, repository_root=repository)

    assert list(destination.parent.iterdir()) == []


def test_report_refuses_a_parent_owned_by_another_uid(private_output):
    """Check report refuses a parent owned by another uid."""
    destination, repository = private_output
    current_uid = os.getuid()
    with (
        patch.object(inventory.os, "getuid", autospec=True, return_value=current_uid + 1),
        pytest.raises((inventory.InventoryRefusal, OSError)),
    ):
        inventory.write_report({}, destination, repository_root=repository)

    assert list(destination.parent.iterdir()) == []


@pytest.mark.parametrize("location", ["checkout", "relative", "missing-parent"])
def test_report_refuses_unprovisioned_or_repository_destinations(
    private_output, monkeypatch, location
):
    """Check report refuses unprovisioned or repository destinations."""
    destination, repository = private_output
    if location == "checkout":
        destination = repository / "inventory.json"
    elif location == "relative":
        monkeypatch.chdir(destination.parent)
        destination = Path("inventory.json")
    else:
        destination = destination.parent / "missing" / "inventory.json"

    with pytest.raises((inventory.InventoryRefusal, OSError)):
        inventory.write_report({}, destination, repository_root=repository)

    assert not destination.exists()


@pytest.mark.parametrize("symlink_location", ["target", "parent", "ancestor"])
def test_report_never_follows_a_symbolic_link(private_output, tmp_path, symlink_location):
    """Check report never follows a symbolic link."""
    destination, repository = private_output
    target = destination.parent / "existing-private-file"
    target.write_text("retain this evidence", encoding="utf-8")
    if symlink_location == "target":
        destination.symlink_to(target)
    elif symlink_location == "parent":
        link = tmp_path / "linked-parent"
        link.symlink_to(destination.parent, target_is_directory=True)
        destination = link / destination.name
    else:
        container = tmp_path / "container"
        container.mkdir(mode=0o700)
        nested = container / "private"
        nested.mkdir(mode=0o700)
        link = tmp_path / "linked-ancestor"
        link.symlink_to(container, target_is_directory=True)
        destination = link / "private" / destination.name

    with pytest.raises((inventory.InventoryRefusal, OSError)):
        inventory.write_report({}, destination, repository_root=repository)

    assert target.read_text(encoding="utf-8") == "retain this evidence"
    if symlink_location == "target":
        assert destination.is_symlink()
    else:
        assert not destination.exists()


def test_serialization_failure_creates_no_partial_evidence(private_output):
    """Check serialization failure creates no partial evidence."""
    destination, repository = private_output

    with pytest.raises((inventory.InventoryRefusal, TypeError)):
        inventory.write_report({"unsupported": object()}, destination, repository_root=repository)

    assert list(destination.parent.iterdir()) == []


def test_publish_race_preserves_the_winning_file_and_removes_the_temporary_file(private_output):
    """Check publish race preserves the winning file and removes the temporary file."""
    destination, repository = private_output
    real_link = os.link

    def competing_publisher(source, target, *, src_dir_fd, dst_dir_fd, follow_symlinks):
        """Publish competing evidence before attempting the original link operation."""
        destination.write_text("earlier evidence", encoding="utf-8")
        return real_link(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    with (
        patch.object(inventory.os, "link", autospec=True, side_effect=competing_publisher),
        pytest.raises((inventory.InventoryRefusal, OSError)),
    ):
        inventory.write_report({}, destination, repository_root=repository)

    assert destination.read_text(encoding="utf-8") == "earlier evidence"
    assert set(destination.parent.iterdir()) == {destination}


def test_file_sync_failure_publishes_nothing_and_cleans_the_temporary_file(private_output):
    """Check file sync failure publishes nothing and cleans the temporary file."""
    destination, repository = private_output
    with (
        patch.object(inventory.os, "fsync", autospec=True, side_effect=OSError(_SECRET)),
        pytest.raises((inventory.InventoryRefusal, OSError)),
    ):
        inventory.write_report({}, destination, repository_root=repository)

    assert list(destination.parent.iterdir()) == []


def test_cli_connects_using_libpq_environment_with_bounded_readonly_options(
    private_output, monkeypatch, capsys
):
    """Check CLI connects using libpq environment with bounded readonly options."""
    destination, repository = private_output
    monkeypatch.setattr(inventory, "PROJECT_ROOT", repository)
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.__enter__.return_value = connection
    report = {"report_version": 1, "canary": _SECRET}
    with (
        patch.object(
            inventory.psycopg, "connect", autospec=True, return_value=connection
        ) as connect,
        patch.object(inventory, "collect_inventory", autospec=True, return_value=report) as collect,
    ):
        result = inventory.main(
            ["--expected-database", "retained_staging", "--output", str(destination)]
        )

    assert result == 0
    connect.assert_called_once()
    arguments, keywords = connect.call_args
    assert arguments == ("",)
    assert keywords["autocommit"] is True
    assert keywords["connect_timeout"] == 5
    assert "default_transaction_read_only=on" in keywords["options"]
    assert "row_security=off" in keywords["options"]
    assert "statement_timeout=30000" in keywords["options"]
    assert "lock_timeout=5000" in keywords["options"]
    assert "search_path=pg_catalog" in keywords["options"]
    assert set(keywords) == {"autocommit", "connect_timeout", "options"}
    collect.assert_called_once_with(connection, "retained_staging")
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    captured = capsys.readouterr()
    assert _SECRET not in captured.out + captured.err


@pytest.mark.parametrize("failure_stage", ["connection", "collection", "publication"])
def test_cli_failures_are_redacted_and_do_not_publish_partial_evidence(
    private_output, monkeypatch, capsys, failure_stage
):
    """Check CLI failures are redacted and do not publish partial evidence."""
    destination, repository = private_output
    monkeypatch.setattr(inventory, "PROJECT_ROOT", repository)
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.__enter__.return_value = connection
    with (
        patch.object(
            inventory.psycopg, "connect", autospec=True, return_value=connection
        ) as connect,
        patch.object(inventory, "collect_inventory", autospec=True, return_value={}) as collect,
        patch.object(inventory, "_publish_report", autospec=True) as publish,
    ):
        if failure_stage == "connection":
            connect.side_effect = psycopg.OperationalError(_SECRET)
        elif failure_stage == "collection":
            collect.side_effect = inventory.InventoryRefusal(_SECRET)
        else:
            publish.side_effect = OSError(_SECRET)
        result = inventory.main(
            ["--expected-database", "retained_staging", "--output", str(destination)]
        )

    captured = capsys.readouterr()
    assert result == 2
    assert _SECRET not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert captured.err
    assert list(destination.parent.iterdir()) == []
    if failure_stage != "publication":
        publish.assert_not_called()


@pytest.mark.parametrize(
    "invalid_output", ["unsafe-parent", "existing", "symlink", "excluded", "missing-parent"]
)
def test_cli_refuses_invalid_output_before_connecting(private_output, monkeypatch, invalid_output):
    """Check CLI refuses invalid output before connecting."""
    destination, repository = private_output
    monkeypatch.setattr(inventory, "PROJECT_ROOT", None)
    arguments = ["--expected-database", "retained_staging", "--output", str(destination)]
    if invalid_output == "unsafe-parent":
        destination.parent.chmod(0o755)
    elif invalid_output == "existing":
        destination.write_text("retain this evidence", encoding="utf-8")
    elif invalid_output == "symlink":
        destination.symlink_to(destination.parent / "missing-target")
    elif invalid_output == "excluded":
        arguments.extend(["--exclude-root", str(repository)])
        arguments.extend(["--exclude-root", str(destination.parent)])
    else:
        arguments[-1] = str(destination.parent / "missing" / destination.name)

    with patch.object(inventory.psycopg, "connect", autospec=True) as connect:
        assert inventory.main(arguments) == 2
    connect.assert_not_called()
    if invalid_output == "existing":
        assert destination.read_text(encoding="utf-8") == "retain this evidence"
    elif invalid_output == "symlink":
        assert destination.is_symlink()
    else:
        assert not destination.exists()


@pytest.mark.parametrize("invalid_root", ["relative", "missing", "file", "parent-traversal"])
def test_cli_validates_explicit_exclusions_before_connecting(
    private_output, monkeypatch, invalid_root
):
    """Check CLI validates explicit exclusions before connecting."""
    destination, repository = private_output
    monkeypatch.setattr(inventory, "PROJECT_ROOT", None)
    if invalid_root == "relative":
        root = Path("checkout")
    elif invalid_root == "missing":
        root = repository / "missing"
    elif invalid_root == "file":
        root = repository / "file"
        root.touch()
    else:
        root = repository / ".."
    with patch.object(inventory.psycopg, "connect", autospec=True) as connect:
        result = inventory.main(
            [
                "--expected-database",
                "retained_staging",
                "--output",
                str(destination),
                "--exclude-root",
                str(root),
            ]
        )
    assert result == 2
    connect.assert_not_called()
    assert not destination.exists()


def test_cli_keeps_the_validated_directory_pinned_through_collection(private_output, monkeypatch):
    """Check CLI keeps the validated directory pinned through collection."""
    destination, repository = private_output
    monkeypatch.setattr(inventory, "PROJECT_ROOT", repository)
    original_parent = destination.parent.with_name("original-evidence-directory")
    report = {"report_version": 1}
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.__enter__.return_value = connection

    def relocate_output_parent(_connection, _expected_database):
        """Replace the output parent during collection and return the scripted inventory report."""
        destination.parent.rename(original_parent)
        destination.parent.mkdir(mode=0o700)
        return report

    with (
        patch.object(inventory.psycopg, "connect", autospec=True, return_value=connection),
        patch.object(
            inventory, "collect_inventory", autospec=True, side_effect=relocate_output_parent
        ),
    ):
        result = inventory.main(
            ["--expected-database", "retained_staging", "--output", str(destination)]
        )

    assert result == 0
    assert not destination.exists()
    assert json.loads((original_parent / destination.name).read_text(encoding="utf-8")) == report


@pytest.mark.parametrize("row_count", [10_000, 10_001])
def test_catalog_limit_refuses_oversized_evidence_instead_of_truncating_it(row_count):
    """Check catalog limit refuses oversized evidence instead of truncating it."""
    connection = create_autospec(psycopg.Connection, instance=True)
    cursor = create_autospec(psycopg.Cursor, instance=True)
    connection.cursor.return_value = cursor
    cursor.__enter__.return_value = cursor
    rows = [{"oid": number} for number in range(row_count)]
    cursor.fetchmany.return_value = rows

    if row_count == 10_000:
        assert inventory._bounded_rows(connection, "relations", "SELECT 1") == rows
    else:
        with pytest.raises(inventory.InventoryRefusal):
            inventory._bounded_rows(connection, "relations", "SELECT 1")

    cursor.fetchmany.assert_called_once_with(10_001)
    cursor.fetchall.assert_not_called()
    cursor.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("server_version_num", 170009),
        ("server_version_num", 190000),
        ("server_version_num", True),
        ("current_user", "different_set_role_identity"),
        ("transaction_read_only", "off"),
        ("transaction_isolation", "read committed"),
        ("captured_at", datetime(2026, 1, 1)),  # noqa: DTZ001 - refusal of a naive DB value
        ("row_security", "on"),
    ],
)
def test_unsupported_identity_refuses_before_catalogue_or_state_queries(field, invalid_value):
    """Check unsupported identity refuses before catalogue or state queries."""
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.autocommit = True
    connection.info.transaction_status = TransactionStatus.IDLE
    identity = {
        "database": "retained_staging",
        "current_user": "inventory_owner",
        "session_user": "inventory_owner",
        "server_version_num": 180006,
        "transaction_read_only": "on",
        "transaction_isolation": "repeatable read",
        "row_security": "off",
        "captured_at": datetime(2026, 1, 1, tzinfo=UTC),
        "is_superuser": False,
        "bypass_rls": False,
    }
    identity[field] = invalid_value
    with (
        patch.object(inventory, "_bounded_rows", autospec=True, return_value=[identity]) as query,
        pytest.raises(inventory.InventoryRefusal),
    ):
        inventory.collect_inventory(connection, "retained_staging")

    query.assert_called_once()
    assert query.call_args.args[1] == "identity"


@pytest.mark.parametrize("server_version", [180000, 189999])
def test_postgresql_18_versions_produce_an_inventory(server_version):
    """Admit the supported major's boundaries without widening compatibility."""
    connection = create_autospec(psycopg.Connection, instance=True)
    connection.autocommit = True
    connection.info.transaction_status = TransactionStatus.IDLE
    identity = {
        "database": "retained_staging",
        "current_user": "inventory_owner",
        "session_user": "inventory_owner",
        "server_version_num": server_version,
        "transaction_read_only": "on",
        "transaction_isolation": "repeatable read",
        "row_security": "off",
        "captured_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    with (
        patch.object(inventory, "_identity", autospec=True, side_effect=lambda *_: dict(identity)),
        patch.object(inventory, "_bounded_rows", autospec=True, return_value=[]),
        patch.object(inventory, "_managed_state", autospec=True, return_value={}),
    ):
        report = inventory.collect_inventory(connection, "retained_staging")

    assert report["identity"]["server_version_num"] == server_version
    assert report["managed_state"] == {}
