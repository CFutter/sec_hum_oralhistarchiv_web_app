"""Structural schema validation of synthetic wire examples; runtime authentication is separate."""

import json
from datetime import datetime
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from app.ingestion_contracts import DOI_MAX_CHARS
from app.paths import PROJECT_ROOT
from app.services import PUBLIC_DISCOVERY_FIELDS, PUBLIC_SEARCH_FIELDS
from app.services.parsed_record import ParsedRecord
from app.sources.json_feed_protocol import FEED_ACCESS_LABELS, FEED_CONTRACT_VERSION

_SOURCE_DOCS = PROJECT_ROOT / "docs" / "sources"
_EXAMPLES = _SOURCE_DOCS / "examples"
_EXAMPLE_NAMES = (
    "feed-v1-full-page-1.json",
    "feed-v1-full-page-2.json",
    "feed-v1-empty-incremental.json",
)
_ENVELOPE_FIELDS = {
    "feed_version",
    "snapshot_id",
    "generated_at",
    "request",
    "records",
    "withdrawn",
    "next_cursor",
    "complete",
}


@pytest.fixture(scope="module")
def validator():
    """Load the shipped Draft-2020-12 schema with format checking enabled."""
    schema = json.loads((_SOURCE_DOCS / "feed-contract-v1.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _example(name=_EXAMPLE_NAMES[0]) -> dict[str, Any]:
    """Decode the named synthetic feed example from disk."""
    return json.loads((_EXAMPLES / name).read_text(encoding="utf-8"))


def _replace(document, path, value):
    """Replace the value at the supplied nested document path in place."""
    parent = document
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value


def test_schema_is_valid_draft_2020_12(validator):
    """Schema is valid draft 2020 12."""
    assert validator.schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert validator.schema["$id"] == "urn:oralhistarchiv:feed-contract:v1"
    validator.check_schema(validator.schema)


def test_published_wire_version_and_labels_match_runtime_interpretation(validator):
    """The standalone publisher schema cannot silently drift from feed binding."""
    assert validator.schema["properties"]["feed_version"]["const"] == FEED_CONTRACT_VERSION
    labels = validator.schema["$defs"]["record"]["properties"]["license_val"]["enum"]
    assert set(labels) == set(FEED_ACCESS_LABELS)


@pytest.mark.parametrize("name", _EXAMPLE_NAMES)
def test_synthetic_pages_validate_and_records_fit_the_shared_boundary(validator, name):
    """Synthetic pages validate and records fit the shared boundary."""
    document = _example(name)
    validator.validate(document)
    for wire_record in document["records"]:
        parsed = dict(wire_record)
        parsed["upstream_modified_at"] = datetime.fromisoformat(parsed.pop("modified_at"))
        ParsedRecord.model_validate(parsed)


def test_every_committed_feed_example_is_exercised():
    """Every committed feed example is exercised."""
    assert {path.name for path in _EXAMPLES.glob("feed-v1-*.json")} == set(_EXAMPLE_NAMES)


def test_examples_cover_tiers_pagination_withdrawal_and_empty_incremental():
    """Examples cover tiers pagination withdrawal and empty incremental."""
    first, second, empty = map(_example, _EXAMPLE_NAMES)
    assert {
        record["visibility_tier"] for page in (first, second) for record in page["records"]
    } == {
        "public",
        "registered",
        "vetted",
    }
    assert first["snapshot_id"] == second["snapshot_id"]
    assert first["generated_at"] == second["generated_at"]
    assert first["next_cursor"] == second["request"]["cursor"]
    assert not first["complete"] and second["complete"]
    assert second["withdrawn"]
    assert empty["request"]["since"] == first["generated_at"]
    assert empty["snapshot_id"] != first["snapshot_id"]
    assert empty["records"] == empty["withdrawn"] == [] and empty["complete"]


def test_wire_fields_match_the_shared_record_and_public_policy(validator):
    """Wire fields match the shared record and public policy."""
    wire = validator.schema["$defs"]["record"]
    expected = (set(ParsedRecord.model_fields) - {"upstream_modified_at"}) | {"modified_at"}
    assert set(wire["properties"]) == set(wire["required"]) == expected
    assert (
        set(validator.schema["properties"]) == set(validator.schema["required"]) == _ENVELOPE_FIELDS
    )
    # Mapping is part of the reviewed wire contract; source/id are application-owned.
    public_wire_mapping = {
        "uuid": "uuid",
        "title": "title",
        "license_val": "access_level",
        "version": "version",
        "visibility_tier": "visibility_tier",
    }
    assert set(public_wire_mapping) <= expected
    assert set(public_wire_mapping.values()) | {"id", "source"} == PUBLIC_DISCOVERY_FIELDS
    assert {"title", "access_level"} == PUBLIC_SEARCH_FIELDS
    assert not {"id", "source", "access_level"} & expected


@pytest.mark.parametrize("field", sorted(_ENVELOPE_FIELDS))
def test_every_envelope_field_is_required(validator, field):
    """Every envelope field is required."""
    document = _example()
    del document[field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field", ["uuid", "title", "modified_at", "visibility_tier", "description", "institutions"]
)
def test_record_fields_are_required_even_when_nullable(validator, field):
    """Record fields are required even when nullable."""
    document = _example()
    del document["records"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path", [(), ("request",), ("records", 0), ("records", 0, "resource_proxies", 0)]
)
def test_unrecognized_object_properties_are_rejected(validator, path):
    """Unrecognized object properties are rejected."""
    document = _example()
    target = document
    for key in path:
        target = target[key]
    target["unreviewed"] = "not in this contract"
    with pytest.raises(ValidationError, match="Additional properties"):
        validator.validate(document)


@pytest.mark.parametrize("tier", [None, "", "Public", "VETTED", "secret", 1, True, []])
def test_classification_is_one_exact_canonical_tier(validator, tier):
    """Classification is one exact canonical tier."""
    document = _example()
    document["records"][0]["visibility_tier"] = tier
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("value", [None, True, "1", 0, 2])
def test_feed_version_is_integer_one_without_coercion(validator, value):
    """Feed version is integer one without coercion."""
    document = _example()
    document["feed_version"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("value", [None, 1, "true"])
def test_completion_flag_requires_a_boolean(validator, value):
    """Completion flag requires a boolean."""
    document = _example()
    document["complete"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("complete,next_cursor", [(False, None), (True, "another-page")])
def test_completion_flag_and_next_cursor_must_agree(validator, complete, next_cursor):
    """Completion flag and next cursor must agree."""
    document = _example()
    document.update(complete=complete, next_cursor=next_cursor)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("path", [("snapshot_id",), ("records", 0, "uuid"), ("withdrawn", 0)])
@pytest.mark.parametrize(
    "value",
    [
        "11111111-1111-4111-A111-111111111111",
        "11111111-1111-5111-8111-111111111111",
        "11111111-1111-4111-7111-111111111111",
        "11111111-1111-4111-8111-111111111111\n",
        "private/case-1",
    ],
)
def test_identifiers_are_lowercase_canonical_uuid4(validator, path, value):
    """Identifiers are lowercase canonical uuid4."""
    document = _example()
    document["withdrawn"] = ["44444444-4444-4444-8444-444444444444"]
    _replace(document, path, value)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path", [("generated_at",), ("request", "since"), ("records", 0, "modified_at")]
)
@pytest.mark.parametrize(
    "value",
    [
        "2030-01-02",
        "2030-01-02T03:04:05",
        "2030-01-02T03:04:05+00:00",
        "2030-01-02T03:04:05.000Z",
        "2030-02-29T03:04:05Z",
        "2030-13-02T03:04:05Z",
        "2030-01-02T24:04:05Z",
        "2030-01-02T03:04:60Z",
    ],
)
def test_timestamps_are_real_whole_utc_seconds(validator, path, value):
    """Timestamps are real whole UTC seconds."""
    document = _example()
    _replace(document, path, value)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_calendar_validation_is_active(validator):
    """Calendar validation is active."""
    document = _example()
    document["generated_at"] = "2032-02-29T00:00:00Z"
    validator.validate(document)


@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "\n", None])
def test_nonce_has_exact_lowercase_hex_shape(validator, value):
    """Nonce has exact lowercase hex shape."""
    document = _example()
    document["request"]["nonce"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("path", [("request", "cursor"), ("next_cursor",)])
@pytest.mark.parametrize("value", ["", "a" * 513, "page/2", "page=2", " page", "page\n", "é", True])
def test_cursor_is_a_bounded_opaque_token(validator, path, value):
    """Cursor is a bounded opaque token."""
    document = _example()
    _replace(document, path, value)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field", ["title", "languages", "authors", "keywords", "institutions", "main_disciplines"]
)
@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        " padded",
        "padded ",
        "line\nbreak",
        "suffix\n",
        "control\x00value",
        "control\x7fvalue",
        "x" * 257,
    ],
)
def test_discovery_and_list_labels_are_trimmed_bounded_and_control_free(validator, field, value):
    """Discovery and list labels are trimmed bounded and control free."""
    document = _example()
    document["records"][0][field] = value if field == "title" else [value]
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field,limit",
    [
        ("project_title", 16384),
        ("description", 16384),
        ("resource_description", 16384),
        ("project_description", 16384),
        ("bibliographical_citation", 16384),
        ("doi", DOI_MAX_CHARS),
        ("resource_type", 256),
    ],
)
def test_nullable_text_has_an_enforced_maximum(validator, field, limit):
    """Nullable text has an enforced maximum."""
    document = _example()
    document["records"][0][field] = "x" * limit
    validator.validate(document)
    document["records"][0][field] += "x"
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("value", ["Open access", "Restricted", None, 1])
def test_access_labels_use_the_reviewed_mapping(validator, value):
    """Access labels use the reviewed mapping."""
    document = _example()
    document["records"][0]["license_val"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("value", ["", "release-1", "1.2.3.4", "1234567", "1.2.3\n", True])
def test_public_version_is_nullable_or_a_bounded_numeric_label(validator, value):
    """Public version is nullable or a bounded numeric label."""
    document = _example()
    document["records"][0]["version"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "path", [("records", 0, "license_url"), ("records", 0, "resource_proxies", 0, "ref")]
)
@pytest.mark.parametrize(
    "value",
    [
        "ftp://archive.example.org/file",
        "javascript:alert(1)",
        "/relative",
        "https://",
        "https://archive.example.org/bad space",
        "https://archive.example.org/\n",
        "https://archive.example.org/" + "x" * 2048,
    ],
)
def test_links_require_bounded_absolute_http_uris(validator, path, value):
    """Links require bounded absolute HTTP uris."""
    document = _example()
    _replace(document, path, value)
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("value", ["File", "resource", None])
def test_resource_proxy_type_is_explicit(validator, value):
    """Resource proxy type is explicit."""
    document = _example()
    document["records"][0]["resource_proxies"][0]["type"] = value
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "field",
    ["languages", "authors", "keywords", "institutions", "main_disciplines", "resource_proxies"],
)
def test_metadata_lists_are_bounded(validator, field):
    """Metadata lists are bounded."""
    document = _example()
    item = {"type": "Resource", "ref": None} if field == "resource_proxies" else "Label"
    document["records"][0][field] = [item] * 101
    with pytest.raises(ValidationError) as error:
        validator.validate(document)
    assert error.value.validator == "maxItems"


def test_institutions_cannot_be_empty(validator):
    """Institutions cannot be empty."""
    document = _example()
    document["records"][0]["institutions"] = []
    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize("field", ["records", "withdrawn"])
def test_page_arrays_have_a_hard_record_count_bound(validator, field):
    """Page arrays have a hard record count bound."""
    document = _example()
    document[field] = (
        [document["records"][0]] * 10001
        if field == "records"
        else [f"{index:08x}-0000-4000-8000-000000000000" for index in range(10001)]
    )
    with pytest.raises(ValidationError) as error:
        validator.validate(document)
    assert error.value.validator == "maxItems"


def test_withdrawals_cannot_repeat_within_a_page(validator):
    """Withdrawals cannot repeat within a page."""
    document = _example()
    document["withdrawn"] = ["44444444-4444-4444-8444-444444444444"] * 2
    with pytest.raises(ValidationError) as error:
        validator.validate(document)
    assert error.value.validator == "uniqueItems"


def test_reviewed_string_boundaries_and_nullable_links_remain_valid(validator):
    """Reviewed string boundaries and nullable links remain valid."""
    document = _example()
    document["request"]["cursor"] = document["next_cursor"] = "A_9-" * 128
    record = document["records"][0]
    record["title"] = "x" * 256
    record["version"] = "123456.123456.123456"
    record["resource_proxies"] = [{"type": "LandingPage", "ref": None}]
    record["license_url"] = "http://archive.example.org/license"
    validator.validate(document)
