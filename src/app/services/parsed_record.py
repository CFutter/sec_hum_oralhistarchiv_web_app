"""Compatibility aliases for the canonical ingestion_contracts.parsed_record module."""

from app.ingestion_contracts import (
    FACET_LABEL_MAX_CHARS,
    PARSED_RECORD_CONTRACT_VERSION,
    ParsedRecord,
    ResourceProxy,
    validate_parsed_record,
)

__all__ = [
    "FACET_LABEL_MAX_CHARS",
    "PARSED_RECORD_CONTRACT_VERSION",
    "ParsedRecord",
    "ResourceProxy",
    "validate_parsed_record",
]
