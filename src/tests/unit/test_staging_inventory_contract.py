"""Keep a standalone operational inventory current without removing old-schema support."""

import importlib.util
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT
from app.services.db_schema_contract import ColumnSpec

_SCRIPT = PROJECT_ROOT / "scripts/check_staging_inventory.py"
_INVENTORY = PROJECT_ROOT / "scripts/inventory_staging.py"


def _checker():
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location("staging_inventory_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_standalone_manifests_include_consumed_progress_fields():
    """Check current standalone manifests include consumed progress fields."""
    checker = _checker()
    checker.verify_inventory_contracts(_INVENTORY.read_text(encoding="utf-8"))
    assert checker.main() == 0


@pytest.mark.parametrize(
    ("before", "after", "error"),
    [
        ('    "users",', "", "managed tables"),
        ('    "users",', '    "users", "users",', "managed tables"),
        ('    "users",', '    "users", "unknown_table",', "managed tables"),
        ('    "source_fetch_cursor": "timestamp with time zone",', "", "source columns/types"),
        (
            '    "source_fetch_fingerprint": "text",',
            '    "source_fetch_fingerprint": "integer",',
            "source columns/types",
        ),
    ],
)
def test_gate_rejects_manifest_drift(before, after, error):
    """Check gate rejects manifest drift (ValueError)."""
    source = _INVENTORY.read_text(encoding="utf-8")
    assert before in source
    with pytest.raises(ValueError, match=error):
        _checker().verify_inventory_contracts(source.replace(before, after))


def test_new_table_or_sync_column_requires_inventory_classification(monkeypatch):
    """Check new table or sync column requires inventory classification (ValueError)."""
    checker = _checker()
    source = _INVENTORY.read_text(encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setitem(checker.TABLE_COLUMN_CONTRACTS, "new_table", {})
        with pytest.raises(ValueError, match="managed tables"):
            checker.verify_inventory_contracts(source)
    monkeypatch.setitem(checker.SYNC_STATUS_COLUMN_CONTRACT, "new_cursor", ColumnSpec("text", True))
    with pytest.raises(ValueError, match="source columns/types"):
        checker.verify_inventory_contracts(source)


def test_removed_excluded_diagnostic_must_be_reclassified(monkeypatch):
    """Check removed excluded diagnostic must be reclassified (ValueError)."""
    checker = _checker()
    monkeypatch.delitem(checker.SYNC_STATUS_COLUMN_CONTRACT, "last_sync_error")
    with pytest.raises(ValueError, match="omitted sync columns are obsolete"):
        checker.verify_inventory_contracts(_INVENTORY.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "source",
    [
        "",
        "_MANAGED_TABLES = tuple()\n_SOURCE_COLUMNS = {}",
        "_MANAGED_TABLES = ()\n_MANAGED_TABLES = ()\n_SOURCE_COLUMNS = {}",
    ],
)
def test_manifests_must_be_unique_literals(source):
    """Check manifests must be unique literals (ValueError)."""
    with pytest.raises(ValueError):
        _checker().verify_inventory_contracts(source)


def test_gate_reports_missing_inventory_file(monkeypatch, tmp_path):
    """Check gate reports missing inventory file."""
    checker = _checker()
    monkeypatch.setattr(checker, "_INVENTORY_PATH", Path(tmp_path / "missing.py"))
    assert checker.main() == 1
