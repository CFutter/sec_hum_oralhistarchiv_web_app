"""Versioned field-mask protocol shared by Python predicates and catalogue SQL."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Final


class SearchMaskBit(IntEnum):
    """Stable wire values; field order must never assign their meaning."""

    DESCRIPTION = 1
    PROJECT_TITLE = 2
    PROJECT_DESCRIPTION = 4
    KEYWORDS = 8
    AUTHORS = 16
    LANGUAGES = 32


@dataclass(frozen=True, slots=True)
class SearchMaskField:
    """One reviewed column, its explicit bit and its document representation."""

    name: str
    bit: SearchMaskBit
    array: bool

    def value_sql(self, *, table_alias: str | None) -> str:
        """Render this code-owned field as text; table_alias must also be trusted SQL."""
        column = f"{table_alias}.{self.name}" if table_alias else self.name
        return f"pg_catalog.array_to_string({column}, ' ')" if self.array else column


SEARCH_MASK_PROTOCOL_VERSION: Final = 1
SEARCH_DOCUMENT_FIELDS: Final = (
    SearchMaskField("description", SearchMaskBit.DESCRIPTION, array=False),
    SearchMaskField("project_title", SearchMaskBit.PROJECT_TITLE, array=False),
    SearchMaskField("project_description", SearchMaskBit.PROJECT_DESCRIPTION, array=False),
    SearchMaskField("keywords", SearchMaskBit.KEYWORDS, array=True),
    SearchMaskField("authors", SearchMaskBit.AUTHORS, array=True),
)
SEARCH_FILTER_FIELDS: Final = (
    *SEARCH_DOCUMENT_FIELDS,
    SearchMaskField("languages", SearchMaskBit.LANGUAGES, array=True),
)

# These historical profiles are deliberately explicit. Changing a field, bit,
# array interpretation or document order requires a new protocol version.
_PROFILES: Final = MappingProxyType(
    {
        1: (
            ("description", 1, False),
            ("project_title", 2, False),
            ("project_description", 4, False),
            ("keywords", 8, True),
            ("authors", 16, True),
            ("languages", 32, True),
        ),
    }
)


def assert_search_mask_contract() -> None:
    """Reject an unknown version or an independently edited field-map consumer."""
    actual = tuple((field.name, int(field.bit), field.array) for field in SEARCH_FILTER_FIELDS)
    if (
        type(SEARCH_MASK_PROTOCOL_VERSION) is not int
        or actual != _PROFILES.get(SEARCH_MASK_PROTOCOL_VERSION)
        or SEARCH_FILTER_FIELDS[:-1] != SEARCH_DOCUMENT_FIELDS
        or any(type(field.bit) is not SearchMaskBit for field in SEARCH_FILTER_FIELDS)
        or any(type(field.array) is not bool for field in SEARCH_FILTER_FIELDS)
    ):
        raise RuntimeError("Search-mask protocol fields do not match their registered version")


assert_search_mask_contract()
SEARCH_DOCUMENT_MASK: Final = sum(int(field.bit) for field in SEARCH_DOCUMENT_FIELDS)
SEARCH_FILTER_MASK: Final = sum(int(field.bit) for field in SEARCH_FILTER_FIELDS)
SEARCH_MASK_PROTOCOL_TAG: Final = (
    f"search-mask/v{SEARCH_MASK_PROTOCOL_VERSION}/"
    + hashlib.sha256(
        json.dumps(_PROFILES[SEARCH_MASK_PROTOCOL_VERSION], separators=(",", ":")).encode("ascii")
    ).hexdigest()
)


def _integer_pattern(maximum: int, *, include_zero: bool) -> str:
    """Render a compact ASCII decimal whitelist without integer casts in SQL."""

    def digit_range(lower: int, upper: int) -> str:
        """Return one decimal digit or an inclusive regex character range."""
        return str(lower) if lower == upper else f"[{lower}-{upper}]"

    digits = str(maximum)
    branches = ["0"] if include_zero else []
    branches.extend("[1-9]" + "[0-9]" * (width - 1) for width in range(1, len(digits)))
    for index, digit in enumerate(digits):
        lower = 1 if index == 0 else 0
        upper = int(digit) if index == len(digits) - 1 else int(digit) - 1
        if upper >= lower:
            branches.append(
                digits[:index] + digit_range(lower, upper) + "[0-9]" * (len(digits) - index - 1)
            )
    return "^(" + "|".join(branches) + ")$"


def _masked_document_sql() -> str:
    """Join field-mask-guarded text expressions in search document order."""
    return " || ' ' ||\n".join(
        f"                    (CASE WHEN (policy.field_mask & {int(field.bit)}) <> 0\n"
        f"                        THEN COALESCE({field.value_sql(table_alias='stored')}, '')\n"
        "                        ELSE '' END)"
        for field in SEARCH_DOCUMENT_FIELDS
    )


def render_search_mask_sql(template: str) -> str:
    """Expand protocol-owned SQL fragments; fail if a search placeholder is unknown."""
    assert_search_mask_contract()
    field_bits = {field.name: str(int(field.bit)) for field in SEARCH_FILTER_FIELDS}
    fragments = {
        "__SEARCH_PROTOCOL_TAG__": SEARCH_MASK_PROTOCOL_TAG,
        "__SEARCH_CONTEXT_CTE__": f"search_context_v{SEARCH_MASK_PROTOCOL_VERSION}",
        "__SEARCH_DOCUMENT_MASK__": str(SEARCH_DOCUMENT_MASK),
        "__SEARCH_PARTIAL_MASK_MAX__": str(SEARCH_DOCUMENT_MASK - 1),
        "__SEARCH_DOCUMENT_PATTERN__": _integer_pattern(SEARCH_DOCUMENT_MASK, include_zero=True),
        "__SEARCH_PARTIAL_PATTERN__": _integer_pattern(
            SEARCH_DOCUMENT_MASK - 1, include_zero=False
        ),
        "__SEARCH_FILTER_PATTERN__": _integer_pattern(SEARCH_FILTER_MASK, include_zero=True),
        "__SEARCH_KEYWORDS_BIT__": field_bits["keywords"],
        "__SEARCH_LANGUAGES_BIT__": field_bits["languages"],
        "__SEARCH_EXTRA_DOCUMENT__": _masked_document_sql(),
    }
    result = template
    for marker, fragment in fragments.items():
        result = result.replace(marker, fragment)
    if re.search(r"__SEARCH_[A-Z_]+__", result):
        raise RuntimeError("Unresolved search-mask SQL placeholder")
    return result
