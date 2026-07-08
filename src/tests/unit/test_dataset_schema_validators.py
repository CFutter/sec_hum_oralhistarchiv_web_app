"""Dataset column-list ⟷ dataclass sync validators + schema.py invariants.

These startup validators are the mechanism that makes "add a column in one
place, forget the other" fail at boot instead of as a NULL-column or
KeyError at runtime. The tests pin both the pass state and that drift is
actually detected (a validator that never fires is the fail-open shape §8
warns about).
"""
import pytest

from app.services import datasets as datasets_module
from app.services.datasets import (
    validate_dataset_schema,
    validate_dataset_insert_schema,
)
from app.services.schema import (
    DATASET_COLUMNS,
    DATASET_INSERT_COLUMNS,
    DATASET_INSERT_PLACEHOLDERS,
    DATASET_SELECT_COLUMNS,
)


def test_validators_pass_on_current_code():
    validate_dataset_schema()
    validate_dataset_insert_schema()


def test_select_drift_is_detected(monkeypatch):
    """A column added to the SELECT list but not the dataclass must raise."""
    monkeypatch.setattr(
        datasets_module, "DATASET_SELECT_COLUMNS", DATASET_SELECT_COLUMNS + ["bogus_col"]
    )
    with pytest.raises(AssertionError, match="bogus_col"):
        validate_dataset_schema()


def test_dataclass_drift_is_detected(monkeypatch):
    """A SELECT column removed while the dataclass still has the field."""
    monkeypatch.setattr(
        datasets_module,
        "DATASET_SELECT_COLUMNS",
        [c for c in DATASET_SELECT_COLUMNS if c != "doi"],
    )
    with pytest.raises(AssertionError, match="doi"):
        validate_dataset_schema()


def test_insert_column_order_drift_is_detected(monkeypatch):
    """_build_record_params emits values by iterating DATASET_INSERT_COLUMNS —
    a reorder would silently write values into wrong columns, so the
    validator pins the exact prefix/suffix structure."""
    reordered = list(reversed(DATASET_COLUMNS)) + ["data", "last_modified"]
    monkeypatch.setattr(datasets_module, "DATASET_INSERT_COLUMNS", reordered)
    with pytest.raises(AssertionError, match="must start with DATASET_COLUMNS"):
        validate_dataset_insert_schema()


def test_insert_trailing_columns_pinned(monkeypatch):
    monkeypatch.setattr(
        datasets_module, "DATASET_INSERT_COLUMNS", DATASET_COLUMNS + ["last_modified", "data"]
    )
    with pytest.raises(AssertionError, match="must end with"):
        validate_dataset_insert_schema()


def test_schema_module_invariants():
    """schema.py structural facts other modules rely on."""
    # 'id' is generated — never inserted; SELECTs include it for lookups.
    assert "id" not in DATASET_COLUMNS
    assert DATASET_SELECT_COLUMNS[0] == "id"
    # INSERT list = base columns + the write-only trailing pair, in order.
    assert DATASET_INSERT_COLUMNS == DATASET_COLUMNS + ["data", "last_modified"]
    # One placeholder per insert column (params tuple lines up positionally).
    assert DATASET_INSERT_PLACEHOLDERS.as_string(None).count("%s") == len(
        DATASET_INSERT_COLUMNS
    )
