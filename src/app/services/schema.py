"""Dataset column contracts and validated record-to-SQL parameter conversion."""

import json
import logging
from datetime import UTC, datetime
from typing import Any

from psycopg import sql

from app.doi import canonicalize_doi

from .access_tiers import AccessTier
from .parsed_record import FACET_LABEL_MAX_CHARS, validate_parsed_record

logger = logging.getLogger(__name__)
# Source and application fields written before raw data and sync time.
DATASET_COLUMNS = [
    "uuid",
    "title",
    "project_title",
    "description",
    "resource_description",
    "languages",
    "project_description",
    "authors",
    "keywords",
    "resource_proxies",
    "license_val",
    "license_url",
    "access_level",
    "institutions",
    "version",
    "doi",
    "resource_type",
    "main_disciplines",
    "bibliographical_citation",
    "source",
    "visibility_tier",
    "upstream_modified_at",
]

# Columns used in SELECT queries (no institutions/main_disciplines
# since they're not on the Dataset dataclass)
DATASET_SELECT_COLUMNS = [
    "id",
    "uuid",
    "title",
    "project_title",
    "description",
    "resource_description",
    "languages",
    "project_description",
    "authors",
    "keywords",
    "resource_proxies",
    "license_val",
    "license_url",
    "access_level",
    "version",
    "doi",
    "resource_type",
    "bibliographical_citation",
    "source",
    "visibility_tier",
]

DATASET_SELECT_SQL = sql.SQL(", ").join(map(sql.Identifier, DATASET_SELECT_COLUMNS))

# Trigger-maintained columns (trg_search_text). Referenced only in raw SQL
# (search_datasets) — never SELECTed into Dataset, never written by the app.
# Listed here so validate_application_column_contracts fails loudly if a migration
# renames one, instead of every search 500-ing at runtime.
DATASET_TRIGGER_COLUMNS = ["search_text_public", "search_text_full"]

DATASET_INSERT_COLUMNS = [*DATASET_COLUMNS, "data", "synced_at"]
DATASET_INSERT_SQL = sql.SQL(", ").join(map(sql.Identifier, DATASET_INSERT_COLUMNS))
DATASET_INSERT_PLACEHOLDERS = sql.SQL(", ").join([sql.Placeholder()] * len(DATASET_INSERT_COLUMNS))

# Fields on Dataset that are computed in _parse_dataset(),
# not read directly from a database column.
DATASET_COMPUTED_FIELDS = {"resource_access_url", "landing_page_url"}

PARSER_OWNED = set(DATASET_COLUMNS) - {"access_level", "source", "visibility_tier"}


_ARRAY_COLUMNS = (
    "languages",
    "authors",
    "keywords",
    "institutions",
    "main_disciplines",
)


def _json_default(value: Any) -> str:
    """Serialize datetimes as ISO 8601; raise TypeError for every other unsupported JSON value."""
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"record field is not JSON-serialisable: {type(value).__name__}")


def _canonicalize_doi(raw: str) -> str | None:
    """Canonicalize DOI names/URIs, preserving safe non-resolver HTTP(S) URLs.

    Return None and log up to 80 input characters when canonicalize_doi rejects it.
    """
    value = canonicalize_doi(raw)
    if value is None:
        logger.warning("Unrecognized DOI format from upstream: %s", raw[:80])
    return value


def build_record_params(
    record: dict[str, Any], access_level: str, source: str, visibility_tier: AccessTier
) -> tuple[Any, ...]:
    """Return values in DATASET_INSERT_COLUMNS order without mutating record.

    Require all PARSER_OWNED keys, then validate ParsedRecord without
    coercion. Serialize raw data and proxies as JSON, canonicalize DOI, use
    empty arrays for absent array content, and stamp synced_at with UTC now.
    access_level must contain 1-256 characters. source and visibility_tier
    are caller-owned overrides; this function does not validate their policy.

    Raises:
        KeyError: A parser-owned key is missing.
        pydantic.ValidationError: The record violates ParsedRecord.
        ValueError: access_level has an invalid length.
        TypeError: JSON serialization encounters an unsupported value.
        AssertionError: An insert column has no constructed value.
    """
    missing_keys = PARSER_OWNED - record.keys()
    if missing_keys:
        raise KeyError(
            f"record missing parser-emitted keys (CMDI profile drift?): {sorted(missing_keys)}"
        )

    raw_doi = record.get("doi")
    validate_parsed_record(record)
    if not access_level or len(access_level) > FACET_LABEL_MAX_CHARS:
        raise ValueError("access_level exceeds the facet label contract")

    values: dict[str, Any] = {
        "access_level": access_level,
        "resource_proxies": json.dumps(record.get("resource_proxies", [])),
        "source": source,
        "visibility_tier": visibility_tier,
        "data": json.dumps(record, default=_json_default),
        "doi": _canonicalize_doi(raw_doi) if raw_doi else None,
        "synced_at": datetime.now(UTC),
    }
    for col in DATASET_COLUMNS:
        if col in values:
            continue
        values[col] = (record.get(col) or []) if col in _ARRAY_COLUMNS else record.get(col)

    # Fail if an insert-only column was added without a value.
    missing = [c for c in DATASET_INSERT_COLUMNS if c not in values]
    if missing:
        raise AssertionError(f"build_record_params has no value for columns: {missing}")

    return tuple(values[col] for col in DATASET_INSERT_COLUMNS)
