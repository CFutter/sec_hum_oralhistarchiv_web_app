"""Check standalone inventory manifests against current schema contracts offline.

Only this authoring/CI gate imports application contracts. The operator's
inventory script continues to inspect older/missing schemas without importing
application settings or claiming that an observed schema is compatible.
"""

import ast
from pathlib import Path

from app.services.db_schema_contract import SYNC_STATUS_COLUMN_CONTRACT, TABLE_COLUMN_CONTRACTS

_INVENTORY_PATH = Path(__file__).resolve().parent / "inventory_staging.py"
# Error content is deliberately omitted from safe source-progress evidence.
# Classify every new sync column here or in the operator manifest, rather than
# silently allowing a newly added progress field to escape inventory coverage.
_OMITTED_SOURCE_COLUMNS = frozenset(
    {"last_sync_error", "last_sync_error_at", "last_rebuild_error", "last_rebuild_error_at"}
)


def _manifest_literals(source: str) -> dict[str, object]:
    """Read literal manifests without importing or running the operator script."""
    names = {"_MANAGED_TABLES", "_SOURCE_COLUMNS"}
    values: dict[str, object] = {}
    for statement in ast.parse(source).body:
        if not isinstance(statement, ast.Assign):
            continue
        for target in statement.targets:
            if not isinstance(target, ast.Name) or target.id not in names:
                continue
            if target.id in values:
                raise ValueError(f"Duplicate inventory manifest: {target.id}")
            try:
                values[target.id] = ast.literal_eval(statement.value)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Inventory manifest must remain literal: {target.id}") from exc
    if set(values) != names:
        raise ValueError("Missing standalone inventory manifests")
    return values


def verify_inventory_contracts(source: str) -> None:
    """Reject table drift, sync-column/type drift and unclassified sync fields."""
    values = _manifest_literals(source)
    tables = values["_MANAGED_TABLES"]
    expected_tables = set(TABLE_COLUMN_CONTRACTS) | {"alembic_version"}
    if (
        not isinstance(tables, tuple)
        or not all(isinstance(name, str) for name in tables)
        or len(tables) != len(set(tables))
        or set(tables) != expected_tables
    ):
        raise ValueError("Standalone inventory managed tables differ from schema contracts")
    if not SYNC_STATUS_COLUMN_CONTRACT.keys() >= _OMITTED_SOURCE_COLUMNS:
        raise ValueError("Standalone inventory omitted sync columns are obsolete")
    expected_columns = {
        name: spec.pg_type
        for name, spec in SYNC_STATUS_COLUMN_CONTRACT.items()
        if name not in _OMITTED_SOURCE_COLUMNS
    }
    if values["_SOURCE_COLUMNS"] != expected_columns:
        raise ValueError("Standalone inventory source columns/types differ from schema contracts")


def main() -> int:
    """Return failure for unreadable, unsupported or drifting manifests."""
    try:
        verify_inventory_contracts(_INVENTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError) as exc:
        print(str(exc))
        return 1
    print("Standalone staging inventory manifests match current schema contracts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
