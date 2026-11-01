"""Dataclass/column drift checks without service imports, avoiding import cycles."""

from collections import Counter
from collections.abc import Collection
from collections.abc import Set as AbstractSet
from dataclasses import fields as dataclass_fields
from typing import Any


def assert_unique_columns(columns: Collection[str], *, columns_label: str) -> None:
    """Raise AssertionError naming repeated columns within one SQL column list."""
    counts = Counter(columns)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if duplicates:
        raise AssertionError(f"{columns_label} contains duplicate columns: {duplicates}")


def assert_columns_match_dataclass(
    dataclass_type: type[Any],
    columns: Collection[str],
    computed_fields: AbstractSet[str],
    *,
    columns_label: str,
    dataclass_label: str,
) -> None:
    """Require unique columns equal to dataclass fields minus computed_fields, ignoring order.

    Raise AssertionError with the supplied labels on mismatch, or TypeError for
    a non-dataclass.
    """
    field_names = {f.name for f in dataclass_fields(dataclass_type)} - computed_fields
    assert_unique_columns(columns, columns_label=columns_label)
    column_set = set(columns)

    errors = []
    if extra := column_set - field_names:
        errors.append(f"Columns in {columns_label} but not on {dataclass_label}: {sorted(extra)}")
    if missing := field_names - column_set:
        errors.append(f"Fields on {dataclass_label} but not in {columns_label}: {sorted(missing)}")
    if errors:
        raise AssertionError(f"{columns_label} / {dataclass_label} mismatch: " + "; ".join(errors))
