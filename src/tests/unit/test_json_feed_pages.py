"""Pure signed-page structure and chain validation; record metadata is validated separately."""

import json
import traceback
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.paths import PROJECT_ROOT
from app.sources import AuthenticatedFeedPage, JsonFeedConfig
from app.sources.json_feed_http import FeedRequest
from app.sources.json_feed_pages import JsonFeedPageValidator
from app.sources.json_feed_protocol import FeedInternalError, FeedProtocolError

_NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
_CUTOFF = "2030-01-02T03:04:05Z"
_SINCE = "2030-01-01T03:04:05Z"
_SNAPSHOT = "00000000-0000-4000-8000-000000000001"
_IDS = tuple(f"{index:08x}-0000-4000-8000-000000000000" for index in range(1, 6))
_CANARY = "private-metadata-canary"


def _record(identifier=_IDS[0], **metadata):
    """Encode a canary-bearing record with explicit metadata overrides."""
    return json.dumps(
        {"uuid": identifier, "title": _CANARY, **metadata}, separators=(",", ":")
    ).encode()


def _page(*, records=None, nonce="a" * 64, since=None, cursor=None, **changes):
    """Build a page, optionally inserting raw record bytes or invalid non-array records."""
    request = FeedRequest(nonce, since, cursor)
    document = {
        "feed_version": 1,
        "snapshot_id": _SNAPSHOT,
        "generated_at": _CUTOFF,
        "request": asdict(request),
        "records": "RAW_RECORDS",
        "withdrawn": [],
        "next_cursor": None,
        "complete": True,
        **changes,
    }
    raw_records = (_record(),) if records is None else records
    if not isinstance(raw_records, tuple):
        document["records"] = raw_records
    body = json.dumps(document, separators=(",", ":")).encode()
    if isinstance(raw_records, tuple):
        body = body.replace(b'"RAW_RECORDS"', b"[" + b",".join(raw_records) + b"]")
    return AuthenticatedFeedPage(request, body)


def _validator(*, since=None, **changes):
    """Construct a page validator with explicit since and configuration overrides."""
    config = JsonFeedConfig.model_validate(
        {
            "name": "feed_test",
            "display": {"label": "Feed test"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "FEED_TOKEN",
            "signing_key_env": "FEED_KEY",
            **changes,
        }
    )
    return JsonFeedPageValidator(config, since=since)


def _reject(page, code, validator=None):
    """Require the safe error code and permanent validator invalidation after rejection."""
    validator = _validator() if validator is None else validator
    with pytest.raises(FeedProtocolError) as error:
        validator.accept(page, now=_NOW)
    assert error.value.error_code == code
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    with pytest.raises(FeedProtocolError) as failed:
        validator.finish()
    assert failed.value.error_code == "state"
    with pytest.raises(FeedProtocolError) as failed:
        validator.accept(_page(), now=_NOW)
    assert failed.value.error_code == "state"


def test_complete_page_preserves_exact_record_bytes_and_finishes_idempotently():
    """SB-DISC-007: page acceptance does not certify incoming record metadata."""
    raw = b'{  "uuid" : "' + _IDS[0].encode() + b'", "title":"caf\xc3\xa9" }'
    validator = _validator()
    result = validator.accept(_page(records=(raw,), withdrawn=[_IDS[1]]), now=_NOW)
    assert result.records[0].body == raw and result.records[0].uuid == _IDS[0]
    assert result.withdrawn == (_IDS[1],) and not result.quarantined
    assert result.generated_at == _NOW and result.snapshot_id == _SNAPSHOT
    assert validator.complete and validator.next_cursor is None
    assert validator.finish() == validator.finish() == _NOW
    assert "caf" not in repr(result.records[0])


def test_three_page_chain_accepts_empty_pages_and_fixed_incremental_binding():
    """Three page chain accepts empty pages and fixed incremental binding."""
    validator = _validator(since=datetime.fromisoformat(_SINCE.replace("Z", "+00:00")))
    first = _page(records=(), since=_SINCE, next_cursor="page_2", complete=False)
    assert not validator.accept(first, now=_NOW).complete
    assert not validator.complete and validator.next_cursor == "page_2"
    second = _page(
        records=(_record(),),
        nonce="b" * 64,
        since=_SINCE,
        cursor="page_2",
        next_cursor="page_3",
        complete=False,
    )
    assert validator.accept(second, now=_NOW).next_cursor == "page_3"
    final = _page(records=(), nonce="c" * 64, since=_SINCE, cursor="page_3")
    assert validator.accept(final, now=_NOW).complete
    assert validator.finish() == _NOW


@pytest.mark.parametrize("offset", [-600, 600])
def test_freshness_window_includes_both_exact_boundaries(offset):
    """Freshness window includes both exact boundaries."""
    validator = _validator()
    validator.accept(_page(), now=_NOW + timedelta(seconds=offset))
    assert validator.finish() == _NOW


@pytest.mark.parametrize("offset", [-601, 601])
def test_snapshot_outside_freshness_window_fails_closed(offset):
    """Snapshot outside freshness window fails closed."""
    validator = _validator()
    with pytest.raises(FeedProtocolError) as error:
        validator.accept(_page(), now=_NOW + timedelta(seconds=offset))
    assert error.value.error_code == "freshness"


def test_each_page_is_checked_against_its_actual_acceptance_time():
    """Each page is checked against its actual acceptance time."""
    validator = _validator()
    validator.accept(_page(records=(), complete=False, next_cursor="next"), now=_NOW)
    with pytest.raises(FeedProtocolError) as error:
        validator.accept(_page(nonce="b" * 64, cursor="next"), now=_NOW + timedelta(seconds=601))
    assert error.value.error_code == "freshness"


@pytest.mark.parametrize("field", sorted(json.loads(_page().body)))
def test_every_envelope_field_is_mandatory(field):
    """Every envelope field is mandatory."""
    page = _page()
    document = json.loads(page.body)
    del document[field]
    _reject(replace(page, body=json.dumps(document).encode()), "envelope")


@pytest.mark.parametrize(
    "changes",
    [
        {"unreviewed": True},
        {"feed_version": True},
        {"feed_version": 1.0},
        {"feed_version": "1"},
        {"complete": 1},
        {"complete": None},
        {"withdrawn": {}},
        {"snapshot_id": _SNAPSHOT.upper().replace("00000000", "AAAAAAAA", 1)},
        {"generated_at": "2030-02-29T03:04:05Z"},
        {"generated_at": "2030-01-02T03:04:05+00:00"},
        {"generated_at": "2030-01-02T03:04:05.000Z"},
    ],
)
def test_envelope_is_exact_and_uses_strict_canonical_values(changes):
    """Envelope is exact and uses strict canonical values."""
    _reject(_page(**changes), "envelope")


@pytest.mark.parametrize(
    "echo",
    [
        {},
        {"nonce": "a" * 64, "since": None, "cursor": None, "extra": True},
        {"nonce": "b" * 64, "since": None, "cursor": None},
        {"nonce": "a" * 64, "since": _SINCE, "cursor": None},
        {"nonce": "a" * 64, "since": None, "cursor": "next"},
    ],
)
def test_signed_request_echo_must_be_exact_and_match_the_actual_request(echo):
    """SB-VIS-005: another authenticated page cannot substitute for this request."""
    _reject(_page(request=echo), "request")


@pytest.mark.parametrize(
    "body",
    [
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"{}{}",
        b"[]",
        b'{"records": [}',
        b'{"feed_version":1,}',
        b'{"feed_version"\xc2\xa0:1}',
        _page().body.replace(b'"title":"' + _CANARY.encode() + b'"', b'"title":NaN'),
        _page().body.replace(b'"title":"' + _CANARY.encode() + b'"', b'"title":Infinity'),
    ],
)
def test_non_json_encoding_syntax_and_constants_never_escape_as_record_inputs(body):
    """Non JSON encoding syntax and constants never escape as record inputs."""
    _reject(replace(_page(), body=body), "json")


@pytest.mark.parametrize("location", ["envelope", "request"])
def test_duplicate_envelope_and_request_keys_abort_even_when_equal(location):
    """Duplicate envelope and request keys abort even when equal."""
    page = _page()
    if location == "envelope":
        body = page.body.replace(b'"feed_version":1', b'"feed_version":1,"feed_version":1')
    else:
        body = page.body.replace(
            b'"nonce":"' + b"a" * 64 + b'"',
            b'"nonce":"' + b"a" * 64 + b'","nonce":"' + b"a" * 64 + b'"',
        )
    _reject(replace(page, body=body), "envelope" if location == "envelope" else "request")


@pytest.mark.parametrize(
    "raw",
    [
        b"null",
        b"[]",
        b'"not an object"',
        b"1",
        b"true",
        b'{"title":"missing UUID"}',
        b'{"uuid":null}',
        b'{"uuid":true}',
        b'{"uuid":"private/case-1"}',
        b'{"uuid":"00000001-0000-5000-8000-000000000000"}',
        b'{"uuid":"00000001-0000-4000-7000-000000000000"}',
        b'{"uuid":"00000001-0000-4000-8000-000000000000","\\u0075uid":"00000001-0000-4000-8000-000000000000"}',
    ],
)
def test_record_identity_must_be_single_unambiguous_public_uuid4(raw):
    """SB-DISC-004: ambiguous identity cannot protect the correct last-known-good row."""
    _reject(_page(records=(raw,)), "identity")


@pytest.mark.parametrize(
    "suffix",
    [
        b',"title":"first","title":"second"',
        b',"title":"same","title":"same"',
        b',"visibility_tier":"public","visibility_tier":"vetted"',
        b',"extra":{"uuid":"one","uuid":"two"}',
        b',"resource_proxies":[{"type":"Resource","type":"LandingPage"}]',
    ],
)
def test_duplicate_nonidentity_keys_quarantine_only_the_identified_record(suffix):
    """SB-VIS-001 and SB-DISC-007: preserve identity while discarding ambiguous metadata."""
    raw = b'{"uuid":"' + _IDS[0].encode() + b'"' + suffix + b"}"
    result = _validator().accept(_page(records=(raw, _record(_IDS[1]))), now=_NOW)
    assert [record.uuid for record in result.records] == [_IDS[1]]
    assert [(item.uuid, item.reason) for item in result.quarantined] == [
        (_IDS[0], "duplicate_record_key")
    ]
    assert _CANARY not in repr(result)


@pytest.mark.parametrize("value", [b"1e999", b"9" * 5000, b'"\\ud800"', b"[]", b"null"])
def test_valid_json_with_invalid_metadata_is_retained_for_later_record_validation(value):
    """Valid JSON with invalid metadata is retained for later record validation."""
    raw = b'{"uuid":"' + _IDS[0].encode() + b'","title":' + value + b"}"
    result = _validator().accept(_page(records=(raw,)), now=_NOW)
    assert result.records[0].body == raw and not result.quarantined


@pytest.mark.parametrize(
    "withdrawn", [[None], [True], ["private/case-1"], [_IDS[1], _IDS[1]], [_IDS[0]]]
)
def test_withdrawals_are_valid_unique_and_disjoint_from_records(withdrawn):
    """Withdrawals are valid unique and disjoint from records."""
    _reject(_page(withdrawn=withdrawn), "identity")


@pytest.mark.parametrize("conflict", ["valid", "quarantined", "withdrawn"])
def test_cross_page_identity_uniqueness_includes_every_classification(conflict):
    """Cross page identity uniqueness includes every classification."""
    validator = _validator()
    duplicated = b'{"uuid":"' + _IDS[1].encode() + b'","title":"a","title":"b"}'
    validator.accept(
        _page(
            records=(_record(), duplicated), withdrawn=[_IDS[2]], next_cursor="next", complete=False
        ),
        now=_NOW,
    )
    identifier = {"valid": _IDS[0], "quarantined": _IDS[1], "withdrawn": _IDS[2]}[conflict]
    following = (
        _page(records=(_record(identifier),), nonce="b" * 64, cursor="next")
        if conflict == "withdrawn"
        else _page(records=(), withdrawn=[identifier], nonce="b" * 64, cursor="next")
    )
    _reject(following, "identity", validator)


@pytest.mark.parametrize("change", ["snapshot", "cutoff", "cursor", "since", "nonce", "loop"])
def test_page_chain_rejects_substitution_and_continuation_loops(change):
    """Page chain rejects substitution and continuation loops."""
    validator = _validator()
    validator.accept(_page(records=(), complete=False, next_cursor="next"), now=_NOW)
    kwargs = {"records": (), "nonce": "b" * 64, "cursor": "next"}
    kwargs.update(
        {
            "snapshot": {"snapshot_id": _IDS[4]},
            "cutoff": {"generated_at": "2030-01-02T03:04:06Z"},
            "cursor": {"cursor": "other"},
            "since": {"since": _SINCE},
            "nonce": {"nonce": "a" * 64},
            "loop": {"complete": False, "next_cursor": "next"},
        }[change]
    )
    _reject(_page(**kwargs), "request" if change in {"since", "nonce"} else "pagination", validator)


def test_first_page_cannot_be_a_continuation_and_incomplete_finish_poisoning_is_explicit():
    """First page cannot be a continuation and incomplete finish poisoning is explicit."""
    _reject(_page(cursor="next"), "pagination")
    validator = _validator()
    validator.accept(_page(records=(), complete=False, next_cursor="next"), now=_NOW)
    with pytest.raises(FeedProtocolError) as error:
        validator.finish()
    assert error.value.error_code == "pagination"
    with pytest.raises(FeedProtocolError) as failed:
        validator.finish()
    assert failed.value.error_code == "state"


def test_more_pages_after_completion_poison_the_finished_chain():
    """More pages after completion poison the finished chain."""
    validator = _validator()
    validator.accept(_page(), now=_NOW)
    _reject(_page(records=(), nonce="b" * 64), "state", validator)


@pytest.mark.parametrize("budget", ["page", "total", "record", "count", "pages"])
def test_raw_byte_entry_and_page_limits_abort_the_whole_chain(budget):
    """SB-TRANS-002 and SB-TRANS-004: quarantine consumes budgets and cannot hide excess input."""
    page = _page()
    changes = {
        "page": {"max_page_bytes": len(page.body) - 1},
        "total": {"max_total_bytes": len(page.body) - 1},
        "record": {"max_record_bytes": len(_record()) - 1},
        "count": {"max_records": 1},
        "pages": {"max_pages": 1},
    }[budget]
    validator = _validator(**changes)
    if budget == "pages":
        validator.accept(_page(records=(), complete=False, next_cursor="next"), now=_NOW)
        page = _page(nonce="b" * 64, cursor="next")
    elif budget == "count":
        page = _page(withdrawn=[_IDS[1]])
    _reject(page, "resource_limit", validator)


@pytest.mark.parametrize("variation", ["unicode_escape", "whitespace"])
def test_original_record_whitespace_and_unicode_escapes_count_toward_exact_byte_budget(variation):
    """Original record whitespace and unicode escapes count toward exact byte budget."""
    prefix = b'{"uuid":"' + _IDS[0].encode() + b'","title":'
    short = prefix + b'"\xc3\xa9"}'
    longer = prefix + (b'"\\u00e9"}' if variation == "unicode_escape" else b'   "\xc3\xa9" }')
    assert json.loads(short) == json.loads(longer) and len(longer) > len(short)
    _validator(max_record_bytes=len(short)).accept(_page(records=(short,)), now=_NOW)
    _reject(_page(records=(longer,)), "resource_limit", _validator(max_record_bytes=len(short)))


@pytest.mark.parametrize(
    "changes",
    [
        {"complete": False, "next_cursor": None},
        {"complete": True, "next_cursor": "next"},
        {"complete": False, "next_cursor": "https://elsewhere/page"},
    ],
)
def test_completion_and_continuation_must_agree(changes):
    """Completion and continuation must agree."""
    _reject(_page(**changes), "pagination")


@pytest.mark.parametrize("budget", ["total_bytes", "records"])
def test_aggregate_budgets_include_earlier_accepted_pages(budget):
    """Aggregate budgets include earlier accepted pages."""
    first = _page(complete=False, next_cursor="next")
    second = _page(records=(_record(_IDS[1]),), nonce="b" * 64, cursor="next")
    changes = (
        {"max_total_bytes": len(first.body) + len(second.body) - 1}
        if budget == "total_bytes"
        else {"max_records": 1}
    )
    validator = _validator(**changes)
    validator.accept(first, now=_NOW)
    _reject(second, "resource_limit", validator)


def test_quarantined_entries_and_withdrawals_both_consume_the_record_budget():
    """Quarantined entries and withdrawals both consume the record budget."""
    duplicate = b'{"uuid":"' + _IDS[1].encode() + b'","title":"a","title":"b"}'
    page = _page(records=(_record(), duplicate), withdrawn=[_IDS[2]])
    _reject(page, "resource_limit", _validator(max_records=2))


def test_cutoff_cannot_precede_the_fixed_incremental_lower_boundary():
    """Cutoff cannot precede the fixed incremental lower boundary."""
    future = "2030-01-02T03:04:06Z"
    validator = _validator(since=datetime.fromisoformat(future.replace("Z", "+00:00")))
    _reject(_page(since=future), "envelope", validator)


@pytest.mark.parametrize(
    "fault", ["naive_clock", "wrong_clock", "text_body", "request_type", "page_type"]
)
def test_invalid_caller_arguments_do_not_consume_or_poison_the_chain(fault):
    """Invalid caller arguments do not consume or poison the chain."""
    validator = _validator()
    page, now = _page(), _NOW
    if fault == "naive_clock":
        now = _NOW.replace(tzinfo=None)
    elif fault == "wrong_clock":
        now = "not a clock"
    elif fault == "text_body":
        page = replace(page, body=page.body.decode())
    elif fault == "request_type":
        page = replace(page, request={})
    else:
        page = None
    with pytest.raises((TypeError, ValueError)):
        validator.accept(page, now=now)
    assert validator.accept(_page(), now=_NOW).complete
    assert validator.finish() == _NOW


def test_incremental_boundary_uses_the_utc_instant_and_widens_fractional_seconds():
    """Incremental boundary uses the UTC instant and widens fractional seconds."""
    boundary = datetime(2030, 1, 1, 5, 4, 5, 123456, tzinfo=timezone(timedelta(hours=2)))
    validator = _validator(since=boundary)
    validator.accept(_page(since=_SINCE), now=_NOW)
    assert validator.finish() == _NOW


@pytest.mark.parametrize("quarantined", [False, True])
def test_same_page_record_identity_cannot_repeat_even_with_equal_or_quarantined_metadata(
    quarantined,
):
    """Same page record identity cannot repeat even with equal or quarantined metadata."""
    repeated = (
        b'{"uuid":"' + _IDS[0].encode() + b'","title":"a","title":"b"}'
        if quarantined
        else _record()
    )
    _reject(_page(records=(_record(), repeated)), "identity")


def _committed_example(name):
    """Read a committed example and return its authenticated-page wrapper plus decoded envelope."""
    body = (PROJECT_ROOT / "docs" / "sources" / "examples" / name).read_bytes()
    document = json.loads(body)
    return AuthenticatedFeedPage(FeedRequest(**document["request"]), body), document


def test_committed_full_harvest_examples_pass_the_real_page_chain_boundary():
    """Committed full harvest examples pass the real page chain boundary."""
    validator = _validator()
    records, withdrawn = [], []
    for name in ("feed-v1-full-page-1.json", "feed-v1-full-page-2.json"):
        page, document = _committed_example(name)
        cutoff = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
        result = validator.accept(page, now=cutoff)
        assert not result.quarantined
        records.extend(json.loads(record.body) for record in result.records)
        withdrawn.extend(result.withdrawn)
    assert [record["uuid"] for record in records] == [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
    ]
    assert [record["visibility_tier"] for record in records] == ["public", "registered", "vetted"]
    assert withdrawn == ["44444444-4444-4444-8444-444444444444"]
    assert validator.complete and validator.finish() == cutoff


def test_committed_empty_incremental_example_completes_without_inventing_entries():
    """Committed empty incremental example completes without inventing entries."""
    page, document = _committed_example("feed-v1-empty-incremental.json")
    since = datetime.fromisoformat(document["request"]["since"].replace("Z", "+00:00"))
    cutoff = datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00"))
    validator = _validator(since=since)
    result = validator.accept(page, now=cutoff)
    assert result.records == result.quarantined == result.withdrawn == ()
    assert result.complete and validator.finish() == cutoff


def test_feed_version_requires_integer_token_even_when_exponent_value_equals_one():
    """Feed version requires integer token even when exponent value equals one."""
    page = _page()
    _reject(
        replace(page, body=page.body.replace(b'"feed_version":1', b'"feed_version":1e0')),
        "envelope",
    )


def test_programming_failure_is_internal_and_permanently_invalidates_page_chain(monkeypatch):
    """Programming failure is internal and permanently invalidates page chain."""
    validator = _validator()

    def broken_record_inputs(_values):
        """Raise KeyError with a private canary during record extraction."""
        raise KeyError(_CANARY)

    monkeypatch.setattr(validator, "_record_inputs", broken_record_inputs)
    with pytest.raises(FeedInternalError) as error:
        validator.accept(_page(), now=_NOW)
    assert _CANARY not in "".join(traceback.format_exception(error.value))
    assert not validator.complete
    with pytest.raises(FeedProtocolError, match="state"):
        validator.finish()
