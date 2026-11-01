"""Historical DDL remains independent of evolving runtime SQL and settings."""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

import app
from app import catalogue_sql
from app.paths import PROJECT_ROOT

_VERSIONS = PROJECT_ROOT / "src/alembic/versions"
_BASELINE = _VERSIONS / "4f73ae3ff827_initial_schema.py"
# Explicitly reviewed pre-deployment resets: consumed-progress fields and
# credential attempt/notification state live in the single fresh baseline.
# Freeze the complete SQL after the authorized database-recreation reset.
_BASELINE_SQL_DIGESTS = {
    "upgrade": "46788dc08d91c6fa167b453724a2ab417ab48a258b57ac134e7891e09b59e705",
    "downgrade": "4076b94792e164050c07d4515d981d05f011efdf5b310f19d477322babff5157",
}


def _load_baseline() -> ModuleType:
    # Read source directly: same-size edits within one second can leave a valid
    # timestamp-based .pyc for a different body during mutation checks.
    """Execute the baseline migration in an isolated module and return it."""
    module = ModuleType("migration_baseline_under_test")
    module.__file__ = str(_BASELINE)
    source = compile(_BASELINE.read_text(encoding="utf-8"), str(_BASELINE), "exec")
    exec(source, module.__dict__)
    return module


def _capture_sql(module: ModuleType, operation: str) -> tuple[str, ...]:
    """Run a migration operation with SQL execution replaced by a statement collector."""
    statements: list[str] = []
    with patch.object(module, "op", SimpleNamespace(execute=statements.append)):
        getattr(module, operation)()
    return tuple(statements)


def _sql_digest(statements: tuple[str, ...]) -> str:
    """Hash the compact ASCII JSON encoding of the ordered SQL statements."""
    payload = json.dumps(statements, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("path", sorted(_VERSIONS.glob("*.py")), ids=lambda path: path.stem)
def test_revisions_do_not_import_current_application_or_configuration(path: Path) -> None:
    """Check revisions do not import current application or configuration."""
    modules: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
    forbidden = [name for name in modules if name.split(".", 1)[0] in {"app", "config"}]
    assert not forbidden, f"{path.name} imports mutable runtime code: {forbidden}"


def test_baseline_revision_identity_is_unchanged() -> None:
    """Check baseline revision identity is unchanged."""
    baseline = _load_baseline()
    assert baseline.revision == "4f73ae3ff827"
    assert baseline.down_revision is None
    assert baseline.branch_labels is None
    assert baseline.depends_on is None


@pytest.mark.parametrize("operation", ["upgrade", "downgrade"])
def test_baseline_sql_matches_its_frozen_history(operation: str) -> None:
    """Check baseline SQL matches its frozen history."""
    assert (
        _sql_digest(_capture_sql(_load_baseline(), operation)) == _BASELINE_SQL_DIGESTS[operation]
    )


def test_baseline_drops_catalogue_policies_before_their_relations() -> None:
    """Check baseline drops catalogue policies before their relations."""
    statements = _capture_sql(_load_baseline(), "downgrade")
    sql = "\n".join(statements)

    policy_drop = sql.index(
        "DROP POLICY IF EXISTS catalogue_web_select ON public.oral_history_datasets"
    )
    admin_state_drop = sql.index("DROP TABLE IF EXISTS dataset_admin_state")
    dataset_drop = sql.index("DROP TABLE IF EXISTS oral_history_datasets")

    assert policy_drop < admin_state_drop
    assert policy_drop < dataset_drop


@pytest.mark.parametrize(
    "name",
    [
        "CATALOGUE_PAGE_IDS_SOURCE",
        "CATALOGUE_SCAN_CEILING_SOURCE",
        "CATALOGUE_SEARCH_CANDIDATES_DEFINITION",
    ],
)
def test_runtime_sql_changes_cannot_rewrite_baseline_history(name: str, monkeypatch) -> None:
    """Check runtime SQL changes cannot rewrite baseline history."""
    before = {
        operation: _capture_sql(_load_baseline(), operation)
        for operation in ("upgrade", "downgrade")
    }
    changed = getattr(catalogue_sql, name) + "\n-- synthetic future runtime SQL\n"
    monkeypatch.setattr(catalogue_sql, name, changed)
    if hasattr(app, name):
        monkeypatch.setattr(app, name, changed)
    for operation, statements in before.items():
        assert _capture_sql(_load_baseline(), operation) == statements


def test_baseline_can_load_and_replay_without_application_imports(monkeypatch) -> None:
    """Check baseline can load and replay without application imports."""
    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        """Reject runtime-package imports while delegating other imports unchanged."""
        if name.split(".", 1)[0] in {"app", "config"}:
            raise AssertionError(f"Historical revision imported runtime module {name}")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    baseline = _load_baseline()
    for operation, expected in _BASELINE_SQL_DIGESTS.items():
        assert _sql_digest(_capture_sql(baseline, operation)) == expected
