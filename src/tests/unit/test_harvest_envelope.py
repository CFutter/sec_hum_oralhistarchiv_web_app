"""Worker harvest codecs, byte lifetime and durable stored-harvest envelopes."""

import gc
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.services import stored_harvest
from app.services.harvest import HarvestResult, harvest_result_to_document
from app.services.parsed_record import PARSED_RECORD_CONTRACT_VERSION
from app.sources import oai_client
from app.sources.oai_client import OAIProtocolError, encode_harvest_result
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record

FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64


class TestHarvestResultCanonicalEncoding:
    """`encode_harvest_result` must produce a wire form that survives
    Unicode, timestamps, and every outcome collection without loss."""

    def test_datetimes_and_non_ascii_text_round_trip_exactly(self):
        """Datetimes and non ascii text round trip exactly."""
        modified_at = datetime(2026, 9, 10, 12, 30, 45, tzinfo=UTC)
        record = parsed_record(
            "oai:x:é-café",
            title="Résumé of a naïve café ☃",
            upstream_modified_at=modified_at,
        )
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[record],
        )

        payload = encode_harvest_result(harvest)
        assert "café".encode() in payload
        assert b"\\u" not in payload

        decoded = oai_client._decode_worker_harvest_result(payload)
        assert decoded == harvest
        assert decoded.matching_records[0]["upstream_modified_at"] == modified_at

    def test_identity_sets_encode_byte_identically_regardless_of_insertion_order(self):
        """deleted_uuids and nonmatching_uuids are sets: the wire form must
        not depend on the order the caller happened to build them in."""
        first_order = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            deleted_uuids={"oai:x:1", "oai:x:2", "oai:x:3"},
            nonmatching_uuids={"oai:x:a", "oai:x:b"},
        )
        second_order = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            deleted_uuids=set(),
            nonmatching_uuids=set(),
        )
        for uuid in ("oai:x:3", "oai:x:1", "oai:x:2"):
            second_order.deleted_uuids.add(uuid)
        for uuid in ("oai:x:b", "oai:x:a"):
            second_order.nonmatching_uuids.add(uuid)

        assert encode_harvest_result(first_order) == encode_harvest_result(second_order)

    def test_empty_collections_round_trip_to_an_equal_empty_result(self):
        """Empty collections round trip to an equal empty result."""
        empty = HarvestResult(source_cursor=SOURCE_CURSOR)
        payload = encode_harvest_result(empty)
        decoded = oai_client._decode_worker_harvest_result(payload)
        assert decoded == empty
        assert decoded.matching_records == []
        assert decoded.deleted_uuids == set()
        assert decoded.nonmatching_uuids == set()
        assert decoded.uncertain_records == {}

    def test_every_outcome_collection_is_equivalent_regardless_of_build_order(self):
        """Every outcome collection is equivalent regardless of build order."""
        record = parsed_record("oai:x:m")
        built_forward = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[record],
            deleted_uuids={"oai:x:d1", "oai:x:d2"},
            nonmatching_uuids={"oai:x:n1", "oai:x:n2"},
            uncertain_records={"oai:x:u1": "reason one", "oai:x:u2": "reason two"},
        )
        built_backward = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[dict(record)],
            deleted_uuids={"oai:x:d2", "oai:x:d1"},
            nonmatching_uuids={"oai:x:n2", "oai:x:n1"},
            uncertain_records={"oai:x:u2": "reason two", "oai:x:u1": "reason one"},
        )

        decoded_forward = oai_client._decode_worker_harvest_result(
            encode_harvest_result(built_forward)
        )
        decoded_backward = oai_client._decode_worker_harvest_result(
            encode_harvest_result(built_backward)
        )
        assert decoded_forward == built_forward
        assert decoded_backward == built_backward
        assert decoded_forward.uncertain_records == decoded_backward.uncertain_records


class TestHarvestResultEncodedSizeLimit:
    """`encode_harvest_result` enforces the retained-result byte limit at
    exactly its boundary."""

    def test_encode_harvest_result_accepts_exactly_the_result_limit(self, monkeypatch):
        """Encode harvest result accepts exactly the result limit."""
        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        payload = oai_client._encode_worker_harvest_result(harvest)
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", len(payload))

        assert encode_harvest_result(harvest) == payload

    def test_encode_harvest_result_rejects_one_byte_over_the_result_limit(self, monkeypatch):
        """Encode harvest result rejects one byte over the result limit."""
        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        payload = oai_client._encode_worker_harvest_result(harvest)
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", len(payload) - 1)

        with pytest.raises(OAIProtocolError) as exc_info:
            encode_harvest_result(harvest)

        assert exc_info.value.error_code == "resource_limit"


class TestWorkerPayloadLifetime:
    """The decoded result must not extend the lifetime of the input byte buffer."""

    def test_decoded_result_releases_worker_bytes_while_remaining_usable(self):
        """Decoded result releases worker bytes while remaining usable."""
        released = []

        class TrackedPayload(bytes):
            """Track release of the decoded worker-payload byte buffer."""

            def __del__(self):
                """Record that the payload object was released."""
                released.append(True)

        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        payload = TrackedPayload(oai_client._encode_worker_harvest_result(harvest))
        decoded = oai_client._decode_worker_harvest_result(payload)
        del payload
        gc.collect()

        assert released == [True], "Decoded harvest retained its serialized worker payload"
        assert decoded == harvest
        assert decoded.validate() == SOURCE_CURSOR


class TestEncodeStoredHarvestPartsUsesCurrentState:
    """Durable staging encodes the current mutable result on every call."""

    def test_decoded_worker_result_is_freshly_encoded(self):
        """Decoded worker result is freshly encoded."""
        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        wire = oai_client._encode_worker_harvest_result(harvest)
        decoded = oai_client._decode_worker_harvest_result(wire)
        real_encode = stored_harvest.encode_harvest_result

        with patch.object(
            stored_harvest, "encode_harvest_result", autospec=True, side_effect=real_encode
        ) as encode_spy:
            parts = stored_harvest.encode_stored_harvest_parts(
                decoded, source_fingerprint=FINGERPRINT
            )

        encode_spy.assert_called_once_with(
            decoded,
            max_bytes=stored_harvest.HARVEST_RESULT_MAX_BYTES,
        )
        assert parts.harvest == wire

    def test_directly_constructed_harvest_is_encoded_exactly_once(self):
        """Adapter-created results use the same source-neutral encoder."""
        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        real_encode = stored_harvest.encode_harvest_result

        with patch.object(
            stored_harvest, "encode_harvest_result", autospec=True, side_effect=real_encode
        ) as encode_spy:
            parts = stored_harvest.encode_stored_harvest_parts(
                harvest, source_fingerprint=FINGERPRINT
            )

        encode_spy.assert_called_once_with(
            harvest,
            max_bytes=stored_harvest.HARVEST_RESULT_MAX_BYTES,
        )
        assert parts.harvest == real_encode(harvest)

    def test_each_staging_call_encodes_the_current_state(self):
        """A later mutation is reflected by a later staging attempt."""
        harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
        wire = oai_client._encode_worker_harvest_result(harvest)
        decoded = oai_client._decode_worker_harvest_result(wire)

        first = stored_harvest.encode_stored_harvest_parts(decoded, source_fingerprint=FINGERPRINT)
        assert first.harvest == wire
        decoded.nonmatching_uuids.add("oai:x:2")

        second = stored_harvest.encode_stored_harvest_parts(decoded, source_fingerprint=FINGERPRINT)
        assert second.harvest != first.harvest
        assert (
            stored_harvest.decode_stored_harvest(
                second.joined(), expected_source_fingerprint=FINGERPRINT
            )
            == decoded
        )


class TestStoredHarvestRoundTrip:
    """The joined envelope produced for persistence is valid JSON and
    decodes back to the exact harvest it was built from."""

    def test_joined_parts_round_trip_through_decode(self):
        """Joined parts round trip through decode."""
        harvest = HarvestResult(
            source_cursor=datetime(2026, 9, 10, 12, 30, tzinfo=UTC),
            matching_records=[parsed_record("oai:x:m", title="Résumé café ☃")],
            deleted_uuids={"oai:x:d"},
            nonmatching_uuids={"oai:x:n"},
            uncertain_records={"oai:x:u": "reason"},
        )

        parts = stored_harvest.encode_stored_harvest_parts(harvest, source_fingerprint=FINGERPRINT)
        joined = parts.joined()

        envelope = json.loads(joined)
        assert envelope["format_version"] == stored_harvest.STORED_HARVEST_FORMAT_VERSION
        assert envelope["parser_contract_version"] == PARSED_RECORD_CONTRACT_VERSION
        assert envelope["source_fingerprint"] == FINGERPRINT

        decoded = stored_harvest.decode_stored_harvest(
            joined, expected_source_fingerprint=FINGERPRINT
        )
        assert decoded == harvest


def _valid_envelope(**overrides: object) -> bytes:
    """Encode a valid stored harvest with explicit envelope overrides."""
    harvest = HarvestResult(source_cursor=SOURCE_CURSOR, nonmatching_uuids={"oai:x:1"})
    document: dict[str, object] = {
        "format_version": stored_harvest.STORED_HARVEST_FORMAT_VERSION,
        "parser_contract_version": PARSED_RECORD_CONTRACT_VERSION,
        "source_fingerprint": FINGERPRINT,
        "harvest": harvest_result_to_document(harvest),
    }
    document.update(overrides)
    return json.dumps(document).encode("utf-8")


class TestStoredHarvestRecoveryActions:
    """Every way a stored envelope can fail to decode prescribes exactly one
    documented recovery action."""

    def test_well_formed_envelope_decodes_without_recovery(self):
        """A well-formed envelope needs no recovery at all."""
        result = stored_harvest.decode_stored_harvest(
            _valid_envelope(), expected_source_fingerprint=FINGERPRINT
        )
        assert result.nonmatching_uuids == {"oai:x:1"}

    def test_malformed_bytes_prescribe_a_full_reharvest(self):
        """Malformed bytes prescribe a full reharvest."""
        with pytest.raises(stored_harvest.InvalidStoredHarvest) as exc_info:
            stored_harvest.decode_stored_harvest(
                b"not json at all", expected_source_fingerprint=FINGERPRINT
            )
        assert exc_info.value.recovery_action == "full_reharvest"

    def test_unsupported_format_version_with_matching_fingerprint_requests_incremental_refetch(
        self,
    ):
        """Unsupported format version with matching fingerprint requests incremental refetch."""
        payload = _valid_envelope(format_version=999)
        with pytest.raises(stored_harvest.IncompatibleStoredHarvest) as exc_info:
            stored_harvest.decode_stored_harvest(payload, expected_source_fingerprint=FINGERPRINT)
        assert exc_info.value.recovery_action == "incremental_refetch"

    def test_unsupported_format_version_with_mismatched_fingerprint_requests_full_reharvest(
        self,
    ):
        """Unsupported format version with mismatched fingerprint requests full reharvest."""
        payload = _valid_envelope(format_version=999, source_fingerprint=OTHER_FINGERPRINT)
        with pytest.raises(stored_harvest.IncompatibleStoredHarvest) as exc_info:
            stored_harvest.decode_stored_harvest(payload, expected_source_fingerprint=FINGERPRINT)
        assert exc_info.value.recovery_action == "full_reharvest"

    def test_parser_contract_drift_requests_incremental_refetch(self):
        """Parser contract drift requests incremental refetch."""
        payload = _valid_envelope(parser_contract_version=PARSED_RECORD_CONTRACT_VERSION + 1)
        with pytest.raises(stored_harvest.IncompatibleStoredHarvest) as exc_info:
            stored_harvest.decode_stored_harvest(payload, expected_source_fingerprint=FINGERPRINT)
        assert exc_info.value.recovery_action == "incremental_refetch"

    def test_source_fingerprint_mismatch_requests_full_reharvest(self):
        """Source fingerprint mismatch requests full reharvest."""
        payload = _valid_envelope(source_fingerprint=OTHER_FINGERPRINT)
        with pytest.raises(stored_harvest.IncompatibleStoredHarvest) as exc_info:
            stored_harvest.decode_stored_harvest(payload, expected_source_fingerprint=FINGERPRINT)
        assert exc_info.value.recovery_action == "full_reharvest"
