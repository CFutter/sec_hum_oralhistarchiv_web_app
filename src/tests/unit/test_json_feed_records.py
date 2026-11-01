"""Strict record metadata classification; no source-owner or persistence claims."""

import json
import traceback
from datetime import UTC, datetime, timedelta, timezone

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from app.ingestion_contracts import DOI_MAX_CHARS
from app.paths import PROJECT_ROOT
from app.services.parsed_record import ParsedRecord
from app.sources.json_feed_protocol import FeedProtocolError, FeedRecordInput, FeedRecordRejection
from app.sources.json_feed_records import classify_feed_record

_DOCS = PROJECT_ROOT / "docs" / "sources"
_UUID = "11111111-1111-4111-8111-111111111111"
_CUTOFF = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
_SINCE = datetime(2030, 1, 2, 2, 0, 0, tzinfo=UTC)
_TEXT_LIMITS = {
    "project_title": 4096,
    "description": 16384,
    "resource_description": 16384,
    "project_description": 16384,
    "bibliographical_citation": 16384,
    "doi": DOI_MAX_CHARS,
    "resource_type": 256,
}
_LABEL_FIELDS = ("title", "languages", "authors", "keywords", "institutions", "main_disciplines")


def _example():
    """Decode the first record of the committed full-feed example."""
    return json.loads((_DOCS / "examples" / "feed-v1-full-page-1.json").read_text())["records"][0]


@pytest.fixture
def wire_record():
    """Return a fresh copy of the committed example record."""
    return _example()


def _input(wire, identity=_UUID):
    """Wrap compact JSON bytes with the supplied feed-record identity."""
    return FeedRecordInput(identity, json.dumps(wire, separators=(",", ":")).encode())


def _classify(wire, **context):
    """Classify a wire record at _CUTOFF with explicit context/limit overrides."""
    return classify_feed_record(
        _input(wire),
        cutoff=_CUTOFF,
        since=context.pop("since", None),
        max_record_bytes=context.pop("max_record_bytes", 65536),
        **context,
    )


def _reject(wire, reason, **context):
    """Require the expected identity/reason and no retained private record body."""
    result = _classify(wire, **context)
    assert isinstance(result, FeedRecordRejection)
    assert result.uuid == _UUID and result.reason == reason
    assert not hasattr(result, "body") and "private-canary" not in repr(result)


def test_committed_records_at_all_tiers_fit_schema_and_the_shared_parsed_record_boundary():
    """Committed records at all tiers fit schema and the shared parsed record boundary."""
    schema = json.loads((_DOCS / "feed-contract-v1.schema.json").read_text())
    validator = Draft202012Validator(
        {"$ref": "#/$defs/record", "$defs": schema["$defs"]}, format_checker=FormatChecker()
    )
    tiers = []
    for name in ("feed-v1-full-page-1.json", "feed-v1-full-page-2.json"):
        for wire in json.loads((_DOCS / "examples" / name).read_text())["records"]:
            validator.validate(wire)
            result = classify_feed_record(
                _input(wire, wire["uuid"]), cutoff=_CUTOFF, since=None, max_record_bytes=65536
            )
            assert isinstance(result, dict)
            ParsedRecord.model_validate(result)
            assert set(result) == (set(wire) - {"modified_at"}) | {"upstream_modified_at"}
            assert result["upstream_modified_at"] == _SINCE
            assert result["resource_proxies"] == wire["resource_proxies"]
            tiers.append(result["visibility_tier"])
    assert tiers == ["public", "registered", "vetted"]


def test_null_optional_text_and_empty_lists_remain_valid_without_normalization(wire_record):
    """Null optional text and empty lists remain valid without normalization."""
    for field in (*_TEXT_LIMITS, "license_url", "version"):
        wire_record[field] = None
    for field in ("languages", "authors", "keywords", "main_disciplines"):
        wire_record[field] = []
    wire_record.update(
        title="Curated  public title", resource_proxies=[{"type": "Resource", "ref": None}]
    )
    result = _classify(wire_record)
    assert isinstance(result, dict)
    assert result["title"] == "Curated  public title" and result["languages"] == []
    assert result["description"] is None and result["resource_proxies"][0]["ref"] is None
    ParsedRecord.model_validate(result)


@pytest.mark.parametrize("field", sorted(set(_example()) - {"uuid"}))
def test_every_metadata_field_is_required_even_when_nullable(wire_record, field):
    """SB-DISC-007: incomplete incoming metadata protects its last-known-good identity."""
    del wire_record[field]
    _reject(wire_record, "record_shape")


def test_extra_fields_cannot_supply_source_or_administrative_state(wire_record):
    """Extra fields cannot supply source or administrative state."""
    wire_record.update(source="private-canary", access_level="public", hidden_at=None)
    _reject(wire_record, "record_shape")


@pytest.mark.parametrize("field", _LABEL_FIELDS)
@pytest.mark.parametrize(
    "value", ["", " ", " padded", "padded ", "line\nbreak", "\x00", "\x7f", "x" * 257, None, 1]
)
def test_discovery_and_list_labels_are_trimmed_bounded_and_control_free(wire_record, field, value):
    """SB-DISC-003 and SB-DISC-007: structural discovery defects are quarantined."""
    wire_record[field] = value if field == "title" else [value]
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize("field,limit", _TEXT_LIMITS.items())
def test_nullable_text_boundaries_count_characters_and_refuse_wrong_types(
    wire_record, field, limit
):
    """Nullable text boundaries count characters and refuse wrong types."""
    wire_record[field] = "x" * limit
    assert isinstance(_classify(wire_record), dict)
    for invalid in ("x" * (limit + 1), True, 7, []):
        wire_record[field] = invalid
        _reject(wire_record, "record_metadata")


@pytest.mark.parametrize("maximum", [1, 4096, 16384])
def test_project_title_uses_the_configured_character_cap_and_shared_wire_ceiling(
    wire_record, maximum
):
    """Accept inclusive Unicode character bounds and quarantine identifiable excess."""
    wire_record["project_title"] = "é" * maximum
    schema = json.loads((_DOCS / "feed-contract-v1.schema.json").read_text())
    validator = Draft202012Validator({"$ref": "#/$defs/record", "$defs": schema["$defs"]})
    validator.validate(wire_record)
    source = FeedRecordInput(
        _UUID, json.dumps(wire_record, ensure_ascii=False, separators=(",", ":")).encode()
    )
    accepted = classify_feed_record(
        source,
        cutoff=_CUTOFF,
        since=None,
        max_record_bytes=65536,
        max_project_title_chars=maximum,
    )
    assert isinstance(accepted, dict) and accepted["project_title"] == wire_record["project_title"]
    ParsedRecord.model_validate(accepted)
    wire_record["project_title"] = "x" * (maximum + 1)
    _reject(wire_record, "record_metadata", max_project_title_chars=maximum)
    assert validator.is_valid(wire_record) is (maximum < 16384)


@pytest.mark.parametrize(
    "invalid,error",
    [
        (True, TypeError),
        ("4096", TypeError),
        (4096.0, TypeError),
        (0, ValueError),
        (-1, ValueError),
        (16385, ValueError),
    ],
)
def test_direct_project_title_overrides_require_a_supported_integer(wire_record, invalid, error):
    """Reject invalid caller limits before classifying metadata."""
    with pytest.raises(error, match="project-title character limit"):
        _classify(wire_record, max_project_title_chars=invalid)


@pytest.mark.parametrize("field", (*_LABEL_FIELDS[1:], "resource_proxies"))
def test_lists_accept_one_hundred_entries_and_reject_excess_or_wrong_types(wire_record, field):
    """Lists accept one hundred entries and reject excess or wrong types."""
    entry = {"type": "LandingPage", "ref": None} if field == "resource_proxies" else "Label"
    wire_record[field] = [entry] * 100
    assert isinstance(_classify(wire_record), dict)
    for invalid in ([entry] * 101, None, "not-a-list", True):
        wire_record[field] = invalid
        _reject(wire_record, "record_metadata")


def test_institutions_need_at_least_one_label(wire_record):
    """Institutions need at least one label."""
    wire_record["institutions"] = []
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize("value", [None, "", "Public", "VETTED", "secret", True, 1])
def test_source_tier_is_exact_and_never_defaulted(wire_record, value):
    """SB-VIS-001 and SB-VIS-002: invalid source classifications cannot become public."""
    wire_record["visibility_tier"] = value
    _reject(wire_record, "record_tier")


@pytest.mark.parametrize(
    "value", [None, "Open access", "Restricted", "Public access ", True, [], {}, ["Public access"]]
)
def test_material_access_label_uses_only_the_reviewed_mapping(wire_record, value):
    """SB-DISC-005: material access labels cannot carry arbitrary public text."""
    wire_record["license_val"] = value
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize(
    "value", ["", "release-1", "1.2.3.4", "1234567", "1.2.3\n", "\u0661", True]
)
def test_public_version_is_nullable_or_an_ascii_numeric_release_label(wire_record, value):
    """Public version is nullable or an ascii numeric release label."""
    wire_record["version"] = value
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize(
    "proxy",
    [
        {},
        {"type": "Resource"},
        {"ref": None},
        {"type": "File", "ref": None},
        {"type": "Resource", "ref": None, "extra": 1},
        None,
        "url",
    ],
)
def test_resource_proxies_have_an_exact_type_reference_shape(wire_record, proxy):
    """Resource proxies have an exact type reference shape."""
    wire_record["resource_proxies"] = [proxy]
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize(
    "value",
    [
        "ftp://archive.example.org/file",
        "/relative",
        "https://",
        "https://user:private-canary@archive.example.org/x",
        "https://archive.example.org:65536/x",
        "https://archive.example.org/a b",
        "https://archive.example.org/a\\b",
        "HTTPS://archive.example.org/x",
        "https://archive.example.org/a\x7fb",
        "https://[broken/x",
        "https://archive.example.org/" + "x" * 2048,
    ],
)
@pytest.mark.parametrize("field", ["license_url", "proxy"])
def test_urls_are_bounded_absolute_http_without_userinfo_or_malformed_authorities(
    wire_record, field, value
):
    """URLs are bounded absolute HTTP without userinfo or malformed authorities."""
    if field == "proxy":
        wire_record["resource_proxies"][0]["ref"] = value
    else:
        wire_record[field] = value
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize("modified", ["2030-01-02T02:00:00Z", "2030-01-02T03:04:05Z"])
def test_record_timestamp_includes_both_selection_boundaries(wire_record, modified):
    """Record timestamp includes both selection boundaries."""
    wire_record["modified_at"] = modified
    result = _classify(wire_record, since=_SINCE)
    assert isinstance(result, dict)
    assert result["upstream_modified_at"] == datetime.fromisoformat(modified.replace("Z", "+00:00"))


@pytest.mark.parametrize(
    "modified",
    [
        None,
        True,
        "2030-01-02",
        "2030-01-02T02:00:00+00:00",
        "2030-01-02T02:00:00.000Z",
        "2030-02-29T02:00:00Z",
        "2030-01-02T02:00:60Z",
        "2030-01-02T01:59:59Z",
        "2030-01-02T03:04:06Z",
    ],
)
def test_invalid_or_out_of_selection_record_timestamps_are_quarantined(wire_record, modified):
    """Invalid or out of selection record timestamps are quarantined."""
    wire_record["modified_at"] = modified
    _reject(wire_record, "record_timestamp", since=_SINCE)


@pytest.mark.parametrize("field", ["title", "description", "authors", "proxy"])
@pytest.mark.parametrize("invalid", ["\ud800", "\x00"])
def test_lone_surrogates_and_nul_never_reach_persistence_parameters(wire_record, field, invalid):
    """Lone surrogates and NUL never reach persistence parameters."""
    if field == "authors":
        wire_record[field] = [invalid]
    elif field == "proxy":
        wire_record["resource_proxies"][0]["ref"] = "https://archive.example.org/" + invalid
    else:
        wire_record[field] = invalid
    _reject(wire_record, "record_metadata")


@pytest.mark.parametrize("literal", [b"1e999", b"9" * 5000])
def test_valid_json_numbers_are_metadata_errors_not_whole_fetch_failures(wire_record, literal):
    """Valid JSON numbers are metadata errors not whole fetch failures."""
    wire_record["description"] = "RAW_NUMERIC_VALUE"
    body = _input(wire_record).body.replace(b'"RAW_NUMERIC_VALUE"', literal)
    result = classify_feed_record(
        FeedRecordInput(_UUID, body), cutoff=_CUTOFF, since=None, max_record_bytes=65536
    )
    assert isinstance(result, FeedRecordRejection) and result.reason == "record_metadata"


@pytest.mark.parametrize("change", ["missing", "malformed", "mismatch", "duplicate"])
def test_identity_errors_abort_instead_of_quarantining_the_wrong_record(wire_record, change):
    """Identity errors abort instead of quarantining the wrong record."""
    source = _input(wire_record)
    if change == "missing":
        del wire_record["uuid"]
        source = _input(wire_record)
    elif change == "malformed":
        wire_record["uuid"] = "private-canary/case"
        source = _input(wire_record)
    elif change == "mismatch":
        source = FeedRecordInput("22222222-2222-4222-8222-222222222222", source.body)
    else:
        source = FeedRecordInput(
            _UUID, source.body.replace(b'{"uuid":', b'{"uuid":"' + _UUID.encode() + b'","uuid":')
        )
    with pytest.raises(FeedProtocolError) as error:
        classify_feed_record(source, cutoff=_CUTOFF, since=None, max_record_bytes=65536)
    assert error.value.error_code == "identity"
    assert "private-canary" not in "".join(traceback.format_exception(error.value))


def test_original_record_byte_budget_is_fatal_even_for_quarantinable_metadata(wire_record):
    """Original record byte budget is fatal even for quarantinable metadata."""
    wire_record["title"] = None
    source = _input(wire_record)
    with pytest.raises(FeedProtocolError) as error:
        classify_feed_record(
            source, cutoff=_CUTOFF, since=None, max_record_bytes=len(source.body) - 1
        )
    assert error.value.error_code == "resource_limit"


@pytest.mark.parametrize("field", ["visibility_tier", "proxy_type"])
def test_duplicate_nonidentity_keys_have_a_fixed_quarantine_reason(wire_record, field):
    """Duplicate nonidentity keys have a fixed quarantine reason."""
    source = _input(wire_record)
    if field == "visibility_tier":
        body = source.body.replace(
            b'"visibility_tier":"public"', b'"visibility_tier":"public","visibility_tier":"vetted"'
        )
    else:
        body = source.body.replace(b'"type":"Resource"', b'"type":"Resource","type":"Resource"')
    result = classify_feed_record(
        FeedRecordInput(_UUID, body), cutoff=_CUTOFF, since=None, max_record_bytes=65536
    )
    assert isinstance(result, FeedRecordRejection)
    assert result.uuid == _UUID and result.reason == "duplicate_record_key"
    assert not hasattr(result, "body")


def test_maximum_discovery_labels_release_version_and_urls_remain_valid(wire_record):
    """Maximum discovery labels release version and URLs remain valid."""
    wire_record["title"] = "x" * 256
    wire_record["authors"] = ["é" * 256]
    wire_record["version"] = "123456.123456.123456"
    prefix = "https://archive.example.org/"
    wire_record["license_url"] = prefix + "x" * (2048 - len(prefix))
    wire_record["resource_proxies"][0]["ref"] = "http://archive.example.org/resource"
    result = _classify(wire_record)
    assert isinstance(result, dict)
    assert result["title"] == wire_record["title"] and result["authors"] == wire_record["authors"]
    assert result["version"] == wire_record["version"]
    assert len(result["license_url"]) == 2048
    ParsedRecord.model_validate(result)


def test_incremental_lower_boundary_is_normalized_to_utc_whole_seconds(wire_record):
    """Incremental lower boundary is normalized to UTC whole seconds."""
    since = datetime(2030, 1, 2, 4, 0, 0, 987654, tzinfo=timezone(timedelta(hours=2)))
    result = _classify(wire_record, since=since)
    assert isinstance(result, dict) and result["upstream_modified_at"] == _SINCE
