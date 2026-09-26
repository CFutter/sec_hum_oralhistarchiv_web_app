"""Versioned serialization for resumable harvests persisted in PostgreSQL."""

import hashlib
import json
import string
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from .oai_client import (
    HarvestResult,
    encode_harvest_result,
    harvest_result_from_document,
)
from .parsed_record import PARSED_RECORD_CONTRACT_VERSION

RecoveryAction: TypeAlias = Literal["incremental_refetch", "full_reharvest"]

STORED_HARVEST_FORMAT_VERSION: Final = 1

_ENVELOPE_FIELDS: Final = frozenset(
    {
        "format_version",
        "parser_contract_version",
        "source_fingerprint",
        "harvest",
    }
)
_LEGACY_HARVEST_FIELDS: Final = frozenset(
    {
        "matching_records",
        "deleted_uuids",
        "nonmatching_uuids",
        "uncertain_records",
        "source_cursor",
    }
)
_SHA256_HEX_LENGTH: Final = 64
_ENVELOPE_SUFFIX: Final = b"}"


@dataclass(frozen=True, slots=True)
class StoredHarvestParts:
    """Bytea fragments persisted by PostgreSQL without a second full copy."""

    prefix: bytes
    harvest: bytes
    suffix: bytes = _ENVELOPE_SUFFIX

    def joined(self) -> bytes:
        """Concatenate envelope fragments into one bytes value."""
        return b"".join((self.prefix, self.harvest, self.suffix))


class StoredHarvestRecoveryRequired(ValueError):
    """Stored harvest cannot be resumed; recovery_action specifies refetch or full reharvest."""

    def __init__(
        self,
        message: str,
        *,
        recovery_action: RecoveryAction,
    ) -> None:
        """Store the diagnostic and caller-selected recovery action."""
        super().__init__(message)
        self.recovery_action = recovery_action


class IncompatibleStoredHarvest(StoredHarvestRecoveryRequired):
    """A stored format, parser version, or source binding requires recovery."""


class InvalidStoredHarvest(StoredHarvestRecoveryRequired):
    """Stored bytes are malformed or violate their declared contract."""

    def __init__(self, message: str) -> None:
        """Store the malformed-payload diagnostic and require a full reharvest."""
        super().__init__(message, recovery_action="full_reharvest")


def _decode_supported_stored_harvest(
    payload: bytes,
    *,
    expected_source_fingerprint: str,
) -> HarvestResult:
    """Decode a UTF-8 envelope and validate its versions, source binding, and harvest.

    Legacy payloads or compatible-source version changes require incremental
    refetch; changed/unknown source binding requires full reharvest. Raise
    IncompatibleStoredHarvest for these recovery cases; malformed values
    raise decoding, TypeError, ValueError, or RecursionError.
    """
    raw: object = json.loads(payload.decode("utf-8"))

    if not isinstance(raw, dict):
        raise TypeError("stored harvest envelope must be an object")

    fields = set(raw)
    if fields == _LEGACY_HARVEST_FIELDS:
        raise IncompatibleStoredHarvest(
            "stored harvest predates the versioned format",
            recovery_action="incremental_refetch",
        )
    if "format_version" not in raw:
        raise ValueError("stored harvest envelope has no format version")

    format_version = _require_version(raw["format_version"], "format_version")
    if format_version != STORED_HARVEST_FORMAT_VERSION:
        stored_fingerprint = raw.get("source_fingerprint")
        recovery_action: RecoveryAction = (
            "incremental_refetch"
            if _is_source_fingerprint(stored_fingerprint)
            and stored_fingerprint == expected_source_fingerprint
            else "full_reharvest"
        )
        raise IncompatibleStoredHarvest(
            f"unsupported stored-harvest format {format_version}",
            recovery_action=recovery_action,
        )

    if fields != _ENVELOPE_FIELDS:
        raise ValueError("stored harvest envelope has the wrong fields")

    parser_version = _require_version(
        raw["parser_contract_version"],
        "parser_contract_version",
    )
    source_fingerprint = raw["source_fingerprint"]
    _validate_source_fingerprint(source_fingerprint)

    if source_fingerprint != expected_source_fingerprint:
        raise IncompatibleStoredHarvest(
            "stored harvest belongs to a different source configuration",
            recovery_action="full_reharvest",
        )
    if parser_version != PARSED_RECORD_CONTRACT_VERSION:
        raise IncompatibleStoredHarvest(
            f"unsupported parser contract {parser_version}",
            recovery_action="incremental_refetch",
        )

    return harvest_result_from_document(raw["harvest"])


def build_source_fingerprint(
    *,
    source: str,
    oai_url: str,
    institution_filter: str,
) -> str:
    """Return SHA-256 hex of canonical JSON containing the three exact,
    unnormalized source settings.
    """
    document = {
        "source": source,
        "oai_url": oai_url,
        "institution_filter": institution_filter,
    }
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def encode_stored_harvest(
    harvest: HarvestResult,
    *,
    source_fingerprint: str,
) -> bytes:
    """Return a joined durable envelope; consume cached worker
    bytes as encode_stored_harvest_parts does.
    """
    return encode_stored_harvest_parts(
        harvest,
        source_fingerprint=source_fingerprint,
    ).joined()


def encode_stored_harvest_parts(
    harvest: HarvestResult,
    *,
    source_fingerprint: str,
) -> StoredHarvestParts:
    """Validate the harvest and return versioned UTF-8 JSON envelope fragments.

    Require a lowercase SHA-256 source_fingerprint or raise ValueError.
    Consume any cached serialized worker payload; otherwise encode under
    the harvest size limit. Harvest validation/encoding errors propagate.
    """
    _validate_source_fingerprint(source_fingerprint)
    harvest.validate()
    envelope_header = {
        "format_version": STORED_HARVEST_FORMAT_VERSION,
        "parser_contract_version": PARSED_RECORD_CONTRACT_VERSION,
        "source_fingerprint": source_fingerprint,
    }
    encoded_header = json.dumps(
        envelope_header,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if not encoded_header.endswith(_ENVELOPE_SUFFIX):
        raise RuntimeError("stored-harvest envelope header is not a JSON object")

    encoded_harvest = harvest.take_serialized_worker_payload()
    if encoded_harvest is None:
        encoded_harvest = encode_harvest_result(harvest)

    return StoredHarvestParts(
        prefix=encoded_header[:-1] + b',"harvest":',
        harvest=encoded_harvest,
    )


def decode_stored_harvest(
    payload: bytes,
    *,
    expected_source_fingerprint: str,
) -> HarvestResult:
    """Decode a harvest bound to expected_source_fingerprint.

    An invalid expected fingerprint raises ValueError before decoding.
    IncompatibleStoredHarvest prescribes version/source recovery; malformed
    payloads raise InvalidStoredHarvest, requiring a full reharvest.
    """
    _validate_source_fingerprint(expected_source_fingerprint)

    try:
        return _decode_supported_stored_harvest(
            payload,
            expected_source_fingerprint=expected_source_fingerprint,
        )
    except StoredHarvestRecoveryRequired:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidStoredHarvest(f"stored harvest is malformed ({type(exc).__name__})") from exc


def _require_version(value: object, field_name: str) -> int:
    """Return a positive non-boolean integer, otherwise raise ValueError naming the field."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _validate_source_fingerprint(value: object) -> None:
    """Raise ValueError unless value is a 64-character lowercase hexadecimal string."""
    if not _is_source_fingerprint(value):
        raise ValueError("source_fingerprint must be a lowercase SHA-256 digest")


def _is_source_fingerprint(value: object) -> bool:
    """Return whether value is a 64-character lowercase hexadecimal string."""
    return (
        isinstance(value, str)
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in string.hexdigits for character in value)
        and value == value.lower()
    )
