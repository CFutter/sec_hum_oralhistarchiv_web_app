"""Source-neutral serialization and durable-staging byte budgets."""

from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import patch

import pytest

from app.services import stored_harvest
from app.services.harvest import (
    HARVEST_RESULT_MAX_BYTES,
    HarvestResult,
    HarvestResultSizeError,
    encode_harvest_result,
)
from app.sources import FixtureAdapter, FixtureConfig, SourceDisplay, oai_client
from tests.oai_fixtures import parsed_record

FINGERPRINT = "a" * 64


def _harvest() -> HarvestResult:
    """Return a minimal harvest with a fixed cursor and one nonmatching identity."""
    return HarvestResult(
        source_cursor=datetime(2020, 1, 4, tzinfo=UTC),
        nonmatching_uuids={"fixture:removed"},
    )


def test_shared_wire_bytes_preserve_existing_oai_encoding() -> None:
    """Shared wire bytes preserve existing oai encoding."""
    expected = (
        b'{"matching_records":[],"deleted_uuids":[],"nonmatching_uuids":["fixture:removed"],'
        b'"uncertain_records":{},"source_cursor":"2020-01-04T00:00:00+00:00"}'
    )
    assert HARVEST_RESULT_MAX_BYTES == 16 * 1024 * 1024
    assert encode_harvest_result(_harvest()) == expected
    assert oai_client.encode_harvest_result(_harvest()) == expected


@pytest.mark.parametrize("max_bytes", [0, -1, True, "1", None])
def test_shared_encoder_rejects_invalid_budget(max_bytes: object) -> None:
    """Shared encoder rejects invalid budget."""
    with pytest.raises(ValueError, match="positive integer"):
        encode_harvest_result(_harvest(), max_bytes=max_bytes)  # type: ignore[arg-type]


def test_shared_encoder_accepts_exact_budget() -> None:
    """Shared encoder accepts exact budget."""
    harvest = _harvest()
    payload = oai_client.encode_harvest_result(harvest)
    assert encode_harvest_result(harvest, max_bytes=len(payload)) == payload


def test_shared_encoder_rejects_one_byte_over_budget() -> None:
    """Shared encoder rejects one byte over budget."""
    harvest = _harvest()
    payload = oai_client.encode_harvest_result(harvest)
    with pytest.raises(HarvestResultSizeError):
        encode_harvest_result(harvest, max_bytes=len(payload) - 1)


def test_fixture_harvest_stages_without_oai_encoder() -> None:
    """Fixture harvest stages without oai encoder."""
    adapter = FixtureAdapter.from_config(
        FixtureConfig(
            name="fixture_demo",
            display=SourceDisplay(label="Fixture"),
            max_visibility="public",
        )
    )
    harvest = adapter.fetch(since=None)
    fingerprint = adapter.config_fingerprint()
    with patch.object(
        oai_client,
        "encode_harvest_result",
        autospec=True,
        side_effect=AssertionError("Fixture staging called the OAI encoder"),
    ) as oai_encode:
        parts = stored_harvest.encode_stored_harvest_parts(
            harvest,
            source_fingerprint=fingerprint,
        )
    oai_encode.assert_not_called()
    decoded = stored_harvest.decode_stored_harvest(
        parts.joined(),
        expected_source_fingerprint=fingerprint,
    )
    assert decoded == harvest
    assert decoded.source_cursor == datetime(2020, 1, 4, tzinfo=UTC)
    assert [record["visibility_tier"] for record in decoded.matching_records] == [
        "public",
        "registered",
        "vetted",
    ]


def test_decoded_result_is_freshly_encoded_under_valid_budget() -> None:
    """Decoded result is freshly encoded under valid budget."""
    wire = oai_client.encode_harvest_result(_harvest())
    decoded = oai_client._decode_worker_harvest_result(wire)
    with patch.object(
        stored_harvest,
        "encode_harvest_result",
        autospec=True,
        side_effect=encode_harvest_result,
    ) as encode:
        parts = stored_harvest.encode_stored_harvest_parts(
            decoded,
            source_fingerprint=FINGERPRINT,
            max_bytes=len(wire),
        )
    encode.assert_called_once_with(decoded, max_bytes=len(wire))
    assert parts.harvest == wire


def test_current_payload_is_checked_against_staging_budget() -> None:
    """Current payload is checked against staging budget."""
    wire = oai_client.encode_harvest_result(_harvest())
    decoded = oai_client._decode_worker_harvest_result(wire)
    with pytest.raises(HarvestResultSizeError):
        stored_harvest.encode_stored_harvest_parts(
            decoded,
            source_fingerprint=FINGERPRINT,
            max_bytes=len(wire) - 1,
        )


def test_invalid_staging_budget_preserves_current_harvest() -> None:
    """Invalid staging budget preserves current harvest."""
    wire = oai_client.encode_harvest_result(_harvest())
    decoded = oai_client._decode_worker_harvest_result(wire)
    with pytest.raises(ValueError, match="positive integer"):
        stored_harvest.encode_stored_harvest_parts(
            decoded,
            source_fingerprint=FINGERPRINT,
            max_bytes=0,
        )
    assert decoded == _harvest()


def test_joined_envelope_forwards_staging_budget() -> None:
    """Joined envelope forwards staging budget."""
    harvest = _harvest()
    wire = oai_client.encode_harvest_result(harvest)
    with pytest.raises(HarvestResultSizeError):
        stored_harvest.encode_stored_harvest(
            harvest,
            source_fingerprint=FINGERPRINT,
            max_bytes=len(wire) - 1,
        )


def _stage(
    harvest: HarvestResult, encoder: str, *, max_bytes: int = HARVEST_RESULT_MAX_BYTES
) -> bytes:
    """Encode with parts for "parts", otherwise with the joined encoder, enforcing max_bytes."""
    if encoder == "parts":
        return stored_harvest.encode_stored_harvest_parts(
            harvest, source_fingerprint=FINGERPRINT, max_bytes=max_bytes
        ).joined()
    return stored_harvest.encode_stored_harvest(
        harvest, source_fingerprint=FINGERPRINT, max_bytes=max_bytes
    )


@pytest.mark.parametrize("encoder", ["parts", "joined"])
@pytest.mark.parametrize(
    "change",
    ["title", "authors", "resource_proxy", "deleted", "nonmatching", "uncertain", "cursor"],
)
def test_staging_reflects_mutations_after_worker_decoding(encoder: str, change: str) -> None:
    """Staging reflects mutations after worker decoding."""
    original = HarvestResult(
        source_cursor=datetime(2020, 1, 4, tzinfo=UTC),
        matching_records=[parsed_record("fixture:matching")],
        deleted_uuids={"fixture:deleted"},
        nonmatching_uuids={"fixture:nonmatching"},
        uncertain_records={"fixture:uncertain": "Original reason"},
    )
    wire = oai_client.encode_harvest_result(original)
    current = oai_client._decode_worker_harvest_result(wire)
    if change == "title":
        current.matching_records[0]["title"] = "Corrected title after worker decoding"
    elif change == "authors":
        current.matching_records[0]["authors"].append("Added author")
    elif change == "resource_proxy":
        current.matching_records[0]["resource_proxies"][0]["ref"] = (
            "https://archive.example.org/new"
        )
    elif change == "deleted":
        current.deleted_uuids.add("fixture:another-deleted")
    elif change == "nonmatching":
        current.nonmatching_uuids.add("fixture:another-nonmatching")
    elif change == "uncertain":
        current.uncertain_records["fixture:uncertain"] = "Corrected reason"
    else:
        current.source_cursor = original.validate() + timedelta(seconds=1)
    current.validate()

    payload = _stage(current, encoder)

    restored = stored_harvest.decode_stored_harvest(
        payload, expected_source_fingerprint=FINGERPRINT
    )
    assert restored == current
    assert restored != original


@pytest.mark.parametrize("encoder", ["parts", "joined"])
def test_staging_budget_checks_growth_after_worker_decoding(encoder: str) -> None:
    """Staging budget checks growth after worker decoding."""
    wire = oai_client.encode_harvest_result(_harvest())
    current = oai_client._decode_worker_harvest_result(wire)
    current.nonmatching_uuids.add("fixture:another-removed-identity")
    assert len(encode_harvest_result(current)) > len(wire)

    with pytest.raises(HarvestResultSizeError):
        _stage(current, encoder, max_bytes=len(wire))


@pytest.mark.parametrize("encoder", ["parts", "joined"])
def test_staging_budget_accepts_shrinkage_after_worker_decoding(encoder: str) -> None:
    """Staging budget accepts shrinkage after worker decoding."""
    original = _harvest()
    removed = "fixture:old-long-identifier-to-remove"
    original.nonmatching_uuids.add(removed)
    wire = oai_client.encode_harvest_result(original)
    current = oai_client._decode_worker_harvest_result(wire)
    current.nonmatching_uuids.remove(removed)
    expected = encode_harvest_result(current)
    assert len(expected) < len(wire)

    payload = _stage(current, encoder, max_bytes=len(expected))

    assert (
        stored_harvest.decode_stored_harvest(payload, expected_source_fingerprint=FINGERPRINT)
        == current
    )


@pytest.mark.parametrize("operation", ["validate", "encode"])
@pytest.mark.parametrize("reason", [None, False, 0, 1.5, [], {}, b"unavailable"])
def test_uncertainty_reasons_are_validated_before_serialization(
    operation: str, reason: object
) -> None:
    """Uncertainty reasons are validated before serialization."""
    harvest = _harvest()
    harvest.uncertain_records["fixture:uncertain"] = cast("str", reason)

    with pytest.raises(ValueError, match="uncertain_records must map strings to strings"):
        if operation == "validate":
            harvest.validate()
        else:
            encode_harvest_result(harvest)


@pytest.mark.parametrize("uncertain", [None, [], "unavailable", {1: "reason"}])
def test_invalid_uncertainty_mapping_has_a_contract_error(uncertain: object) -> None:
    """Invalid uncertainty mapping has a contract error."""
    harvest = _harvest()
    harvest.uncertain_records = cast("dict[str, str]", uncertain)

    with pytest.raises(ValueError, match="uncertain_records must map strings to strings"):
        encode_harvest_result(harvest)


@pytest.mark.parametrize("encoder", ["parts", "joined"])
@pytest.mark.parametrize("reason", [None, False, 0, [], {}])
def test_staging_rejects_invalid_reason_mutation_and_allows_correction(
    encoder: str, reason: object
) -> None:
    """Staging rejects invalid reason mutation and allows correction."""
    original = _harvest()
    original.uncertain_records["fixture:uncertain"] = "Original reason"
    wire = oai_client.encode_harvest_result(original)
    current = oai_client._decode_worker_harvest_result(wire)
    current.uncertain_records["fixture:uncertain"] = cast("str", reason)

    with pytest.raises(ValueError, match="uncertain_records must map strings to strings"):
        _stage(current, encoder)

    assert current.uncertain_records["fixture:uncertain"] is reason
    current.uncertain_records["fixture:uncertain"] = "Corrected reason"
    payload = _stage(current, encoder)
    restored = stored_harvest.decode_stored_harvest(
        payload, expected_source_fingerprint=FINGERPRINT
    )
    assert restored == current
    assert restored.uncertain_records == {"fixture:uncertain": "Corrected reason"}


@pytest.mark.parametrize("encoder", ["parts", "joined"])
@pytest.mark.parametrize("reason", ["", "Résumé: metadata unavailable ☃", "  reason\nunchanged  "])
def test_staging_preserves_all_valid_string_reason_mutations(encoder: str, reason: str) -> None:
    """Staging preserves all valid string reason mutations."""
    original = _harvest()
    original.uncertain_records["fixture:uncertain"] = "Original reason"
    wire = oai_client.encode_harvest_result(original)
    current = oai_client._decode_worker_harvest_result(wire)
    current.uncertain_records["fixture:uncertain"] = reason

    restored = stored_harvest.decode_stored_harvest(
        _stage(current, encoder), expected_source_fingerprint=FINGERPRINT
    )

    assert restored == current
    assert restored.uncertain_records == {"fixture:uncertain": reason}


@pytest.mark.parametrize("encoder", ["encode_stored_harvest_parts", "encode_stored_harvest"])
@pytest.mark.parametrize("invalid", ["fingerprint", "budget"])
def test_staging_argument_validation_precedes_invalid_reason_and_preserves_current_state(
    encoder: str, invalid: str
) -> None:
    """Staging argument validation precedes invalid reason and preserves current state."""
    wire = oai_client.encode_harvest_result(_harvest())
    current = oai_client._decode_worker_harvest_result(wire)
    current.uncertain_records["fixture:uncertain"] = cast("str", None)
    stage = getattr(stored_harvest, encoder)
    fingerprint = "invalid" if invalid == "fingerprint" else FINGERPRINT
    max_bytes = 0 if invalid == "budget" else HARVEST_RESULT_MAX_BYTES
    message = "fingerprint" if invalid == "fingerprint" else "positive integer"

    with pytest.raises(ValueError, match=message):
        stage(current, source_fingerprint=fingerprint, max_bytes=max_bytes)

    assert current.uncertain_records["fixture:uncertain"] is None
