"""The catalogue classification document must match the public field contract."""

import re
from dataclasses import fields

from app.field_visibility import (
    PUBLIC_DISCOVERY_FIELDS,
    PUBLIC_SEARCH_FIELDS,
    RESOURCE_URL_FIELDS,
)
from app.paths import PROJECT_ROOT
from app.services import FIELD_VISIBILITY
from app.services.datasets import Dataset


def test_catalogue_classification_table_matches_the_public_field_contract():
    """Catalogue classification table matches the public field contract."""
    document = (PROJECT_ROOT / "docs/compliance/data-classification.md").read_text(encoding="utf-8")
    start = "<!-- DATASET_FIELD_CLASSIFICATION_START -->"
    end = "<!-- DATASET_FIELD_CLASSIFICATION_END -->"
    assert document.count(start) == document.count(end) == 1
    table = document.split(start, 1)[1].split(end, 1)[0]
    lines = [line.strip() for line in table.splitlines() if line.strip()]
    assert lines[:2] == [
        "| Field | Code minimum | Public discovery | Public search | Resource target group |",
        "|---|---|---|---|---|",
    ]
    rows = []
    for line in lines[2:]:
        assert line.startswith("|") and line.endswith("|"), line
        cells = [cell.strip() for cell in line[1:-1].split("|")]
        assert len(cells) == 5, line
        name = re.fullmatch(r"`([a-z_]+)`", cells[0])
        minimum = re.fullmatch(r"`([a-z]+)`", cells[1])
        assert name is not None and minimum is not None, line
        assert all(value in {"Yes", "No"} for value in cells[2:]), line
        rows.append((name[1], (minimum[1], *(value == "Yes" for value in cells[2:]))))
    names = [name for name, _classification in rows]
    assert len(names) == len(set(names)), "Duplicated catalogue classification field"
    model_fields = {field.name for field in fields(Dataset)}
    assert set(names) == model_fields == set(FIELD_VISIBILITY), (
        "Catalogue classification fields differ from the model or code matrix"
    )
    assert dict(rows) == {
        name: (
            FIELD_VISIBILITY[name],
            name in PUBLIC_DISCOVERY_FIELDS,
            name in PUBLIC_SEARCH_FIELDS,
            name in RESOURCE_URL_FIELDS,
        )
        for name in model_fields
    }
