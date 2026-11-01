"""Indexed input limits reject poison keys before durable staging."""

import json

import pytest
from pydantic import ValidationError

from app.ingestion_contracts import (
    DOI_MAX_CHARS,
    IDENTITY_MAX_CHARS,
    HarvestResult,
    ParsedRecord,
)
from app.services import stored_harvest
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record

_FINGERPRINT = "a" * 64


@pytest.mark.parametrize("field,limit", [("uuid", IDENTITY_MAX_CHARS), ("doi", DOI_MAX_CHARS)])
@pytest.mark.parametrize("character", ["x", "\U0001f600"])
def test_record_indexed_values_accept_boundary_and_reject_one_character_over(
    field, limit, character
):
    """Record indexed values accept boundary and reject one character over."""
    accepted = parsed_record("record-1")
    accepted[field] = character * limit
    ParsedRecord.model_validate(accepted)
    assert len(accepted[field].encode("utf-8")) <= 2048

    rejected = {**accepted, field: character * (limit + 1)}
    with pytest.raises(ValidationError) as error:
        ParsedRecord.model_validate(rejected)
    assert error.value.errors()[0]["loc"] == (field,)
    assert error.value.errors()[0]["type"] == "string_too_long"


def test_doi_remains_nullable_but_required():
    """Doi remains nullable but required."""
    record = parsed_record("record-1", doi=None)
    assert ParsedRecord.model_validate(record).doi is None

    del record["doi"]
    with pytest.raises(ValidationError) as error:
        ParsedRecord.model_validate(record)
    assert error.value.errors()[0]["loc"] == ("doi",)
    assert error.value.errors()[0]["type"] == "missing"


def _classified_harvest(classification, identifier):
    """Place identifier in the selected outcome collection under the fixed source cursor."""
    result = HarvestResult(source_cursor=SOURCE_CURSOR)
    if classification == "matching":
        result.matching_records = [parsed_record(identifier)]
    elif classification == "uncertain":
        result.uncertain_records = {identifier: "metadata unavailable"}
    elif classification == "deleted":
        result.deleted_uuids = {identifier}
    else:
        result.nonmatching_uuids = {identifier}
    return result


@pytest.mark.parametrize("classification", ["matching", "uncertain", "deleted", "nonmatching"])
@pytest.mark.parametrize("character", ["x", "\U0001f600"])
def test_every_classification_has_the_same_identity_limit_before_staging(classification, character):
    """Every classification has the same identity limit before staging."""
    accepted = _classified_harvest(classification, character * IDENTITY_MAX_CHARS)
    parts = stored_harvest.encode_stored_harvest_parts(accepted, source_fingerprint=_FINGERPRINT)
    assert (
        stored_harvest.decode_stored_harvest(
            parts.joined(), expected_source_fingerprint=_FINGERPRINT
        )
        == accepted
    )

    rejected = _classified_harvest(classification, character * (IDENTITY_MAX_CHARS + 1))
    with pytest.raises(ValueError, match="harvest identities must contain at most"):
        stored_harvest.encode_stored_harvest_parts(rejected, source_fingerprint=_FINGERPRINT)


def test_version_one_payload_requests_refetch_before_validating_old_oversized_keys():
    # This models existing retained bytes, which cannot be created with the new
    # encoder. Version checking must happen before current record validation.
    """Version one payload requests refetch before validating old oversized keys."""
    document = {
        "format_version": stored_harvest.STORED_HARVEST_FORMAT_VERSION,
        "parser_contract_version": 1,
        "source_fingerprint": _FINGERPRINT,
        "harvest": {
            "matching_records": [],
            "deleted_uuids": [],
            "nonmatching_uuids": [],
            "uncertain_records": {"x" * (IDENTITY_MAX_CHARS + 1): "old metadata failure"},
            "source_cursor": SOURCE_CURSOR.isoformat(),
        },
    }

    with pytest.raises(stored_harvest.IncompatibleStoredHarvest) as error:
        stored_harvest.decode_stored_harvest(
            json.dumps(document).encode(), expected_source_fingerprint=_FINGERPRINT
        )

    assert error.value.recovery_action == "incremental_refetch"
