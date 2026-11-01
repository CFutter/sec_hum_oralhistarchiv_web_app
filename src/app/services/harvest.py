"""Compatibility aliases for the canonical ingestion_contracts.harvest module."""

from app.ingestion_contracts import (
    HARVEST_RESULT_MAX_BYTES,
    HarvestResult,
    HarvestResultSizeError,
    encode_harvest_result,
    harvest_result_from_document,
    harvest_result_to_document,
    harvest_result_to_json,
    validate_harvest_payload_size,
)

__all__ = [
    "HARVEST_RESULT_MAX_BYTES",
    "HarvestResult",
    "HarvestResultSizeError",
    "encode_harvest_result",
    "harvest_result_from_document",
    "harvest_result_to_document",
    "harvest_result_to_json",
    "validate_harvest_payload_size",
]
