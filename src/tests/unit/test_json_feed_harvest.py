"""Composes authenticated page chains, native records and validated harvest bytes."""

import json
import traceback
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import create_autospec

import pytest

from app import services
from app.ingestion_contracts import DOI_MAX_CHARS
from app.paths import PROJECT_ROOT
from app.sources import AuthenticatedFeedPage, FeedRequest, JsonFeedConfig, JsonFeedHarvestBuilder
from app.sources import json_feed_harvest as harvest_module
from app.sources.json_feed_protocol import FeedInternalError, FeedProtocolError

_NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
_SINCE = "2030-01-01T03:04:05Z"
_CANARY = "private-incoming-metadata-canary"
_WITHDRAWN = "55555555-5555-4555-8555-555555555555"


def _example(number=1):
    """Decode the numbered committed full-feed example."""
    path = PROJECT_ROOT / "docs/sources/examples" / f"feed-v1-full-page-{number}.json"
    return json.loads(path.read_text())


def _raw(record):
    """Encode compact UTF-8 JSON without ASCII-escaping Unicode."""
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()


def _page(document, records=None):
    """Wrap a copied envelope with optional verbatim record bytes for malformed-record tests."""
    document = dict(document)
    if records is not None:
        document["records"] = "RAW_RECORDS"
    body = _raw(document)
    if records is not None:
        body = body.replace(b'"RAW_RECORDS"', b"[" + b",".join(records) + b"]")
    return AuthenticatedFeedPage(FeedRequest(**document["request"]), body)


def _builder(*, since=None, **limits):
    """Construct a harvest builder with the selected since value and explicit limit overrides."""
    config = JsonFeedConfig.model_validate(
        {
            "name": "feed_test",
            "display": {"label": "Feed test"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "FEED_TOKEN",
            "signing_key_env": "FEED_KEY",
            **limits,
        }
    )
    return JsonFeedHarvestBuilder(config, since=since)


def _mixed():
    """Return one valid record alongside invalid metadata, tier and duplicate-key records."""
    document = _example()
    good = {**document["records"][0], "title": "café"}
    metadata = {**good, "uuid": document["records"][1]["uuid"], "title": [_CANARY]}
    tier = {**good, "uuid": _example(2)["records"][0]["uuid"], "visibility_tier": _CANARY}
    duplicate = _raw({**good, "uuid": _example(2)["withdrawn"][0]})
    duplicate = duplicate.replace(b'"title":', b'"title":"' + _CANARY.encode() + b'","title":')
    document.update(complete=True, next_cursor=None, withdrawn=[_WITHDRAWN])
    return _page(document, (_raw(metadata), _raw(tier), duplicate, _raw(good)))


def _finished(page, **limits):
    """Accept one terminal page at _NOW and return validated harvest bytes."""
    builder = _builder(**limits)
    assert builder.accept(page, now=_NOW) is None
    return builder.finish()


def _poisoned(builder):
    """Require a failed builder to reject both finish and subsequent pages."""
    assert not builder.complete
    with pytest.raises(FeedProtocolError, match="state is unavailable"):
        builder.finish()
    with pytest.raises(FeedProtocolError, match="state is unavailable"):
        builder.accept(_mixed(), now=_NOW)


def test_real_three_tier_chain_uses_validated_public_serializer(monkeypatch):
    """Real three tier chain uses validated public serializer."""
    real_encode = harvest_module.harvest_contract.encode_harvest_result
    encode = create_autospec(real_encode, spec_set=True, side_effect=real_encode)
    monkeypatch.setattr(harvest_module.harvest_contract, "encode_harvest_result", encode)
    since = datetime(2030, 1, 1, 5, 4, 5, 123456, tzinfo=timezone(timedelta(hours=2)))
    builder = _builder(since=since)
    assert builder.next_cursor is None and not builder.complete
    for number in (1, 2):
        document = _example(number)
        document["request"]["since"] = _SINCE
        assert builder.accept(_page(document), now=_NOW) is None
        assert builder.complete is (number == 2)
        assert builder.next_cursor == document["next_cursor"]
        encode.assert_not_called()
    payload = builder.finish()
    result = services.harvest_result_from_document(json.loads(payload))
    assert result.source_cursor == _NOW and result.source_cursor.utcoffset() == timedelta(0)
    assert [record["visibility_tier"] for record in result.matching_records] == [
        "public",
        "registered",
        "vetted",
    ]
    assert all(
        "modified_at" not in record
        and record["upstream_modified_at"] == _NOW.replace(hour=2, minute=0, second=0)
        for record in result.matching_records
    )
    assert result.deleted_uuids == set(_example(2)["withdrawn"])
    assert not result.nonmatching_uuids and not result.uncertain_records
    assert not {record["uuid"] for record in result.matching_records} & result.deleted_uuids
    encode.assert_called_once()
    assert encode.call_args.kwargs == {"max_bytes": 16777216}


@pytest.mark.parametrize("invalid_label", [[], {}, ["Public access"]])
def test_unhashable_access_label_quarantines_only_its_record(invalid_label):
    """Unhashable access label quarantines only its record."""
    document = _example()
    invalid = {**document["records"][0], "license_val": invalid_label}
    valid = document["records"][1]
    document.update(records=[invalid, valid], complete=True, next_cursor=None)
    payload = _finished(_page(document))
    result = services.harvest_result_from_document(json.loads(payload))
    assert [record["uuid"] for record in result.matching_records] == [valid["uuid"]]
    assert result.uncertain_records == {invalid["uuid"]: "record_metadata"}
    assert result.source_cursor == _NOW


@pytest.mark.parametrize("character", ["x", "\U0001f600"])
def test_oversized_doi_quarantines_only_its_record_and_retains_the_valid_record(character):
    """Oversized doi quarantines only its record and retains the valid record."""
    document = _example()
    invalid = {**document["records"][0], "doi": "10.1234/" + character * DOI_MAX_CHARS}
    valid = document["records"][1]
    document.update(records=[invalid, valid], complete=True, next_cursor=None)

    payload = _finished(_page(document))
    result = services.harvest_result_from_document(json.loads(payload))

    assert [record["uuid"] for record in result.matching_records] == [valid["uuid"]]
    assert result.uncertain_records == {invalid["uuid"]: "record_metadata"}
    assert invalid["doi"] not in payload.decode()
    assert result.source_cursor == _NOW


@pytest.mark.parametrize("maximum", [4096, 8192, 16384])
def test_project_title_cap_quarantines_only_excess_and_serializes_allowed_titles(maximum):
    """Apply the source cap before shared serialization, retaining valid neighbours."""
    document = _example()
    valid = {**document["records"][0], "project_title": "é" * maximum}
    invalid = {**document["records"][1], "project_title": "x" * (maximum + 1)}
    document.update(records=[invalid, valid], complete=True, next_cursor=None)
    limits = {} if maximum == 4096 else {"max_project_title_chars": maximum}

    payload = _finished(_page(document), **limits)
    result = services.harvest_result_from_document(json.loads(payload))

    assert [record["uuid"] for record in result.matching_records] == [valid["uuid"]]
    assert result.matching_records[0]["project_title"] == valid["project_title"]
    assert result.uncertain_records == {invalid["uuid"]: "record_metadata"}
    assert invalid["project_title"] not in payload.decode()
    assert result.validate() == _NOW


def test_mixed_invalid_records_quarantine_fixed_identities_and_keep_valid_metadata():
    """Mixed invalid records quarantine fixed identities and keep valid metadata."""
    payload = _finished(_mixed())
    result = services.harvest_result_from_document(json.loads(payload))
    assert [record["title"] for record in result.matching_records] == ["café"]
    assert result.uncertain_records == {
        _example()["records"][1]["uuid"]: "record_metadata",
        _example(2)["records"][0]["uuid"]: "record_tier",
        _example(2)["withdrawn"][0]: "duplicate_record_key",
    }
    assert result.deleted_uuids == {_WITHDRAWN} and not result.nonmatching_uuids
    assert _CANARY not in payload.decode() and b"caf\xc3\xa9" in payload
    assert result.validate() == _NOW


def test_empty_incremental_example_returns_only_its_validated_cutoff():
    """Empty incremental example returns only its validated cutoff."""
    path = PROJECT_ROOT / "docs/sources/examples/feed-v1-empty-incremental.json"
    document = json.loads(path.read_text())
    since = datetime.fromisoformat(document["request"]["since"].replace("Z", "+00:00"))
    cutoff = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
    builder = _builder(since=since)
    builder.accept(_page(document), now=cutoff)
    result = services.harvest_result_from_document(json.loads(builder.finish()))
    assert result.validate() == cutoff
    assert not result.matching_records and not result.uncertain_records
    assert not result.deleted_uuids and not result.nonmatching_uuids


def test_result_byte_budget_counts_utf8_quarantines_and_withdrawals_at_exact_boundary():
    """Result byte budget counts UTF-8 quarantines and withdrawals at exact boundary."""
    page = _mixed()
    payload = _finished(page)
    assert len(payload) > len(payload.decode())
    assert _finished(page, max_result_bytes=len(payload)) == payload
    builder = _builder(max_result_bytes=len(payload) - 1)
    builder.accept(page, now=_NOW)
    with pytest.raises(FeedProtocolError) as error:
        builder.finish()
    assert error.value.error_code == "resource_limit"
    _poisoned(builder)


@pytest.mark.parametrize("started", [False, True])
def test_incomplete_chain_never_releases_harvest_bytes_and_finish_poisoning_is_final(started):
    """Incomplete chain never releases harvest bytes and finish poisoning is final."""
    builder = _builder()
    if started:
        builder.accept(_page(_example()), now=_NOW)
    with pytest.raises(FeedProtocolError) as error:
        builder.finish()
    assert error.value.error_code == "pagination"
    _poisoned(builder)


@pytest.mark.parametrize("conflict,code", [("snapshot", "pagination"), ("identity", "identity")])
def test_late_chain_failure_discards_previously_accepted_metadata(conflict, code):
    """Late chain failure discards previously accepted metadata."""
    builder = _builder()
    builder.accept(_page(_example()), now=_NOW)
    following = _example(2)
    if conflict == "snapshot":
        following["snapshot_id"] = _WITHDRAWN
    else:
        following["records"][0]["uuid"] = _example()["records"][0]["uuid"]
    with pytest.raises(FeedProtocolError) as error:
        builder.accept(_page(following), now=_NOW)
    assert error.value.error_code == code
    _poisoned(builder)


@pytest.mark.parametrize("budget", ["page", "total", "record", "count", "pages"])
def test_raw_budgets_are_still_enforced_through_the_harvest_builder(budget):
    """Raw budgets are still enforced through the harvest builder."""
    first, last = _page(_example()), _page(_example(2))
    limits = {
        "page": {"max_page_bytes": len(first.body) - 1},
        "total": {"max_total_bytes": len(first.body) + len(last.body) - 1},
        "record": {"max_record_bytes": len(_raw(_example()["records"][0])) - 1},
        "count": {"max_records": 4},
        "pages": {"max_pages": 1},
    }[budget]
    builder = _builder(**limits)
    if budget in {"total", "pages"}:
        builder.accept(first, now=_NOW)
        first = last
    elif budget == "count":
        first = _mixed()
    with pytest.raises(FeedProtocolError) as error:
        builder.accept(first, now=_NOW)
    assert error.value.error_code == "resource_limit"
    _poisoned(builder)


@pytest.mark.parametrize(
    "fault", ["naive_clock", "missing_clock", "text_body", "request_type", "page_type"]
)
def test_invalid_caller_arguments_leave_the_builder_usable(fault):
    """Invalid caller arguments leave the builder usable."""
    builder = _builder()
    page, now = _mixed(), _NOW
    if fault == "naive_clock":
        now = _NOW.replace(tzinfo=None)
    elif fault == "missing_clock":
        now = None
    elif fault == "text_body":
        page = replace(page, body=page.body.decode())
    elif fault == "request_type":
        page = replace(page, request={})
    else:
        page = None
    with pytest.raises((TypeError, ValueError)):
        builder.accept(page, now=now)
    builder.accept(_mixed(), now=_NOW)
    assert services.harvest_result_from_document(json.loads(builder.finish())).matching_records


@pytest.mark.parametrize(
    "operation", ["finish_twice", "accept_after_finish", "accept_after_complete"]
)
def test_completion_and_serialization_are_single_use(operation):
    """Completion and serialization are single use."""
    builder = _builder()
    builder.accept(_mixed(), now=_NOW)
    if operation != "accept_after_complete":
        builder.finish()
    with pytest.raises(FeedProtocolError) as error:
        builder.finish() if operation == "finish_twice" else builder.accept(_mixed(), now=_NOW)
    assert error.value.error_code == "state"
    _poisoned(builder)


@pytest.mark.parametrize("seam", ["classifier", "serializer"])
@pytest.mark.parametrize(
    "fault,code",
    [
        (MemoryError, "resource_limit"),
        (RecursionError, "resource_limit"),
        (RuntimeError, None),
        (KeyError, None),
    ],
)
def test_internal_failures_are_fixed_and_redacted_including_traceback(
    monkeypatch, seam, fault, code
):
    """Internal failures are fixed and redacted including traceback."""
    owner, name = (
        (harvest_module, "classify_feed_record")
        if seam == "classifier"
        else (harvest_module.harvest_contract, "encode_harvest_result")
    )
    real = getattr(owner, name)
    work = create_autospec(real, spec_set=True, side_effect=fault(_CANARY))
    monkeypatch.setattr(owner, name, work)
    builder = _builder()
    with pytest.raises(FeedProtocolError if code else FeedInternalError) as error:
        builder.accept(_mixed(), now=_NOW)
        builder.finish()
    if code:
        assert error.value.error_code == code
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    work.assert_called_once()
    _poisoned(builder)


def test_inner_page_programming_failure_survives_outer_wrapper_as_internal(monkeypatch):
    """Inner page programming failure survives outer wrapper as internal."""
    builder = _builder()

    def broken_record_inputs(_self, _values):
        """Raise KeyError with a private canary during record extraction."""
        raise KeyError(_CANARY)

    monkeypatch.setattr(
        harvest_module.JsonFeedPageValidator, "_record_inputs", broken_record_inputs
    )
    with pytest.raises(FeedInternalError) as error:
        builder.accept(_mixed(), now=_NOW)
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    _poisoned(builder)
