"""Check the shipped psql view contracts without settings or database access.

Run from the locked project environment: python scripts/check_runtime_verifier.py.
The deployment verifier remains standalone SQL; only this authoring gate imports
the current application contracts. Historical migrations are not rewritten.
"""

import re
from pathlib import Path

from app.services.db_schema_contract import VIEW_CONTRACTS

_VERIFIER_PATH = Path(__file__).resolve().parents[1] / "deploy/verify-runtime-database-access.sql"
_SQL_STRING = re.compile(r"'((?:[^']|'')*)'")
_VIEW_TUPLE = re.compile(r"\('([a-z_]+)', ARRAY\[([^\]]*)\]::text\[\], '((?:[^']|'')*)'\)")
ViewContract = tuple[tuple[str, ...], str]


def embedded_view_contracts(text: str) -> dict[str, ViewContract]:
    """Extract the verifier's literal projections/definitions; reject duplicate names."""
    contracts: dict[str, ViewContract] = {}
    for name, columns, definition in _VIEW_TUPLE.findall(text):
        if name in contracts:
            raise ValueError(f"Duplicate embedded view contract: {name}")
        if _SQL_STRING.sub("", columns).strip(" ,\n\t"):
            raise ValueError(f"Unsupported embedded projection for view: {name}")
        contracts[name] = (
            tuple(column.replace("''", "'") for column in _SQL_STRING.findall(columns)),
            definition.replace("''", "'"),
        )
    return contracts


def verify_view_contracts(text: str) -> None:
    """Raise ValueError for missing, extra, or changed views, including column order/types."""
    actual = embedded_view_contracts(text)
    expected = {
        name: (tuple(f"{column}:{kind}" for column, kind in spec.columns), spec.definition)
        for name, spec in VIEW_CONTRACTS.items()
    }
    changed = sorted(
        name for name in actual.keys() | expected.keys() if actual.get(name) != expected.get(name)
    )
    if changed:
        raise ValueError("Shipped runtime verifier view contracts differ: " + ", ".join(changed))


def main() -> int:
    """Return a failing exit status for unreadable or inconsistent verifier assets."""
    try:
        verify_view_contracts(_VERIFIER_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(str(exc))
        return 1
    print("Shipped runtime verifier view contracts match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
