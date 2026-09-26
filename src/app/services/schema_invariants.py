"""Dataclass/column drift checks without service imports, avoiding import cycles."""

from collections.abc import Collection
from collections.abc import Set as AbstractSet
from dataclasses import fields as dataclass_fields
from typing import Any


def assert_columns_match_dataclass(
    dataclass_type: type[Any],
    columns: Collection[str],
    computed_fields: AbstractSet[str],
    *,
    columns_label: str,
    dataclass_label: str,
) -> None:
    """Require columns to equal dataclass fields minus computed_fields,
    ignoring order and duplicates.

    Raise AssertionError with the supplied labels on mismatch; a non-dataclass
    raises TypeError.
    """
    field_names = {f.name for f in dataclass_fields(dataclass_type)} - computed_fields
    column_set = set(columns)

    errors = []
    if extra := column_set - field_names:
        errors.append(f"Columns in {columns_label} but not on {dataclass_label}: {sorted(extra)}")
    if missing := field_names - column_set:
        errors.append(f"Fields on {dataclass_label} but not in {columns_label}: {sorted(missing)}")
    if errors:
        raise AssertionError(f"{columns_label} / {dataclass_label} mismatch: " + "; ".join(errors))
