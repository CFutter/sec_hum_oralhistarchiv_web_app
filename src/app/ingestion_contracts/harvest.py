"""Shared harvest classifications and validated wire-document conversion."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from .parsed_record import IDENTITY_MAX_CHARS, validate_parsed_record

HARVEST_RESULT_MAX_BYTES: Final = 16 * 1024 * 1024


class HarvestResultSizeError(ValueError):
    """A serialized harvest exceeds the caller's retained-result byte budget."""


def _string_list(value: object, field_name: str) -> list[str]:
    """Return the original unique-string list; raise ValueError for other values."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} cannot contain duplicates")
    return value


def _validate_uncertain_records(value: object) -> None:
    """Raise ValueError unless value is a dict mapping strings to strings."""
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(reason, str) for key, reason in value.items()
    ):
        raise ValueError("uncertain_records must map strings to strings")


@dataclass(slots=True)
class HarvestResult:
    """Mutable, disjoint harvest classifications plus an aware upstream response timestamp.

    Matching records satisfy ParsedRecord; deleted/nonmatching IDs authorize
    withdrawal, while uncertain IDs retain diagnostic reasons and require the
    engine to quarantine any existing serving copy. Construction
    does not validate. source_cursor=None is only an unfinished state.
    Durable staging re-encodes the current validated state.
    No synchronization protects concurrent mutation during staging or application.
    """

    matching_records: list[dict[str, Any]] = field(default_factory=list)
    deleted_uuids: set[str] = field(default_factory=set)
    nonmatching_uuids: set[str] = field(default_factory=set)
    uncertain_records: dict[str, str] = field(default_factory=dict)
    source_cursor: datetime | None = None

    def validate(self) -> datetime:
        """Validate disjoint normalized identities and parsed records; return the source cursor.

        Raise ValueError for a missing/naive cursor, invalid uncertainty mapping,
        or blank, oversized, untrimmed, repeated identities. Reasons must be strings, including
        empty strings; ParsedRecord violations raise pydantic.ValidationError.
        The cursor and reason text are not normalized.
        """
        if self.source_cursor is None or self.source_cursor.utcoffset() is None:
            raise ValueError("harvest source_cursor must be a timezone-aware source timestamp")

        _validate_uncertain_records(self.uncertain_records)
        seen: set[str] = set()
        identifiers = [record.get("uuid") for record in self.matching_records]
        identifiers.extend(self.deleted_uuids)
        identifiers.extend(self.nonmatching_uuids)
        identifiers.extend(self.uncertain_records)

        for identifier in identifiers:
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError("harvest identities must be nonempty strings")
            if len(identifier) > IDENTITY_MAX_CHARS:
                raise ValueError(
                    f"harvest identities must contain at most {IDENTITY_MAX_CHARS} characters"
                )
            if identifier != identifier.strip():
                raise ValueError("harvest identities must already be whitespace-normalized")
            if identifier in seen:
                raise ValueError("harvest contains repeated or conflicting identities")
            seen.add(identifier)

        for record in self.matching_records:
            validate_parsed_record(record)

        return self.source_cursor


def harvest_result_to_document(result: HarvestResult) -> dict[str, object]:
    """Validate and return a JSON-ready mapping with ISO timestamps and sorted ID lists.

    Record dictionaries are shallow copies; their nested values and the
    uncertain_records mapping remain shared. Validation errors propagate.
    """
    result.validate()
    records: list[dict[str, object]] = []

    for original in result.matching_records:
        record = dict(original)
        modified = record.get("upstream_modified_at")
        if isinstance(modified, datetime):
            record["upstream_modified_at"] = modified.isoformat()
        elif modified is not None:
            raise TypeError("upstream_modified_at must be datetime or None")
        records.append(record)

    return {
        "matching_records": records,
        "deleted_uuids": sorted(result.deleted_uuids),
        "nonmatching_uuids": sorted(result.nonmatching_uuids),
        "uncertain_records": result.uncertain_records,
        "source_cursor": (
            result.source_cursor.isoformat() if result.source_cursor is not None else None
        ),
    }


def harvest_result_from_document(raw: object) -> HarvestResult:
    """Reconstruct and validate the exact five-field wire document.

    Require aware ISO timestamps, unique string ID lists, and string-valued
    uncertainty reasons; copy record dictionaries and convert their dates.
    TypeError/ValueError, including pydantic.ValidationError, reject malformed data.
    """
    if not isinstance(raw, dict) or set(raw) != {
        "matching_records",
        "deleted_uuids",
        "nonmatching_uuids",
        "uncertain_records",
        "source_cursor",
    }:
        raise ValueError("harvest result has the wrong top-level schema")

    raw_records = raw["matching_records"]
    if not isinstance(raw_records, list):
        raise TypeError("matching_records must be a list")

    records: list[dict[str, Any]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or not all(isinstance(key, str) for key in raw_record):
            raise ValueError("matching_records entries must be string-keyed objects")

        record = dict(raw_record)
        modified = record.get("upstream_modified_at")
        if isinstance(modified, str):
            parsed = datetime.fromisoformat(modified)
            if parsed.tzinfo is None:
                raise ValueError("upstream_modified_at must include a timezone")
            record["upstream_modified_at"] = parsed
        elif modified is not None:
            raise ValueError("upstream_modified_at must be an ISO timestamp or null")
        records.append(record)

    deleted = _string_list(raw["deleted_uuids"], "deleted_uuids")
    nonmatching = _string_list(raw["nonmatching_uuids"], "nonmatching_uuids")
    uncertain = raw["uncertain_records"]
    _validate_uncertain_records(uncertain)

    source_cursor = raw["source_cursor"]
    if not isinstance(source_cursor, str):
        raise TypeError("source_cursor must be an ISO timestamp")

    result = HarvestResult(
        matching_records=records,
        deleted_uuids=set(deleted),
        nonmatching_uuids=set(nonmatching),
        uncertain_records=dict(uncertain),
        source_cursor=datetime.fromisoformat(source_cursor),
    )
    result.validate()
    return result


def harvest_result_to_json(result: HarvestResult) -> bytes:
    """Validate and encode compact UTF-8 JSON without applying a byte budget.

    Transport callers must enforce their own limit; durable staging uses
    encode_harvest_result instead.
    """
    return json.dumps(
        harvest_result_to_document(result),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_harvest_byte_budget(max_bytes: int) -> None:
    """Raise ValueError unless max_bytes is a positive int other than bool."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("Harvest max_bytes must be a positive integer")


def validate_harvest_payload_size(
    payload: bytes, *, max_bytes: int = HARVEST_RESULT_MAX_BYTES
) -> None:
    """Raise ValueError for invalid max_bytes, or HarvestResultSizeError if exceeded."""
    _validate_harvest_byte_budget(max_bytes)
    if len(payload) > max_bytes:
        raise HarvestResultSizeError("Serialized harvest exceeds the retained-result byte limit")


def encode_harvest_result(
    result: HarvestResult, *, max_bytes: int = HARVEST_RESULT_MAX_BYTES
) -> bytes:
    """Validate and encode compact UTF-8 JSON within max_bytes (default: 16 MiB).

    Raise ValueError for a nonpositive/noninteger budget, HarvestResultSizeError
    if exceeded, or propagate record-validation/JSON-encoding errors.
    """
    _validate_harvest_byte_budget(max_bytes)
    payload = harvest_result_to_json(result)
    validate_harvest_payload_size(payload, max_bytes=max_bytes)
    return payload
