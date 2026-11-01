"""Lossless JSON structure and byte budgets before envelope/metadata validation."""

import json
import traceback
from dataclasses import FrozenInstanceError
from decimal import Decimal, InvalidOperation, localcontext
from unittest.mock import create_autospec

import pytest

from app.sources import json_feed_json as decoding
from app.sources.json_feed_json import JSONObject, RawJSONRecord, decode_feed_document
from app.sources.json_feed_protocol import FeedProtocolError


def _decode(body, **changes):
    """Decode with overridable page-byte, record-byte and record-count limits."""
    return decode_feed_document(
        body,
        max_page_bytes=changes.get("max_page_bytes", 1_048_576),
        max_record_bytes=changes.get("max_record_bytes", 65_536),
        max_records=changes.get("max_records", 10_000),
    )


def _records(document):
    """Return the records member from the lossless document pair sequence."""
    return next(value for key, value in document.pairs if key == "records")


def test_all_object_pairs_and_decoded_duplicate_aliases_survive():
    """All object pairs and decoded duplicate aliases survive."""
    document = _decode(
        b'{"a":1,"\\u0061":2,"records":[{"uuid":"public-id",'
        b'"meta":{"k":true,"\\u006b":false},"records":[{"nested":1}]}]}'
    )
    assert document.pairs[:2] == (("a", 1), ("a", 2))
    record = _records(document)[0]
    assert isinstance(record, RawJSONRecord) and isinstance(record.value, JSONObject)
    metadata = dict(record.value.pairs)["meta"]
    assert metadata == JSONObject((("k", True), ("k", False)))
    assert dict(record.value.pairs)["records"] == [JSONObject((("nested", 1),))]
    assert b'"\\u006b"' in record.body


def test_only_top_level_records_arrays_are_wrapped_and_duplicate_arrays_count_together():
    """Only top level records arrays are wrapped and duplicate arrays count together."""
    body = b'{"nested":{"records":[{}]},"records":[1],"\\u0072ecords":[2]}'
    document = _decode(body, max_records=2)
    assert document.pairs[0][1] == JSONObject((("records", [JSONObject(())]),))
    assert document.pairs[1][0] == document.pairs[2][0] == "records"
    assert all(isinstance(value[0], RawJSONRecord) for _, value in document.pairs[1:])
    with pytest.raises(FeedProtocolError) as error:
        _decode(body, max_records=1)
    assert error.value.error_code == "resource_limit"


@pytest.mark.parametrize(
    "record",
    [
        '{ "description" : "é😀" }'.encode(),
        b'{"description":"\\u00e9\\ud83d\\ude00"}',
        b'{"nested":[{"text":"brackets ] } and escaped quote \\""}],"x":null}',
        b' {"title":"synthetic"} '.strip(),
    ],
)
def test_original_record_slice_counts_utf8_and_escapes_but_excludes_surrounding_space(record):
    """Original record slice counts UTF-8 and escapes but excludes surrounding space."""
    body = b' \r\n{"records": [ \t' + record + b" \r\n]} \t"
    document = _decode(body, max_record_bytes=len(record))
    assert _records(document)[0].body == record
    with pytest.raises(FeedProtocolError) as error:
        _decode(body, max_record_bytes=len(record) - 1)
    assert error.value.error_code == "resource_limit"


def test_invalid_nonobject_entries_are_preserved_and_all_consume_the_record_budget():
    """Invalid nonobject entries are preserved and all consume the record budget."""
    body = b'{"records":[null,true,1,"text",[],{}]}'
    records = _records(_decode(body, max_records=6))
    assert [record.value for record in records] == [None, True, 1, "text", [], JSONObject(())]
    assert [record.body for record in records] == [b"null", b"true", b"1", b'"text"', b"[]", b"{}"]
    with pytest.raises(FeedProtocolError) as error:
        _decode(body, max_records=5)
    assert error.value.error_code == "resource_limit"


@pytest.mark.parametrize("value", [b"12345", b'"123"', b"[1,2]", b"false"])
def test_nonobject_record_entries_also_obey_the_byte_limit(value):
    """Nonobject record entries also obey the byte limit."""
    body = b'{"records":[' + value + b"]}"
    assert _records(_decode(body, max_record_bytes=len(value)))[0].body == value
    with pytest.raises(FeedProtocolError) as error:
        _decode(body, max_record_bytes=len(value) - 1)
    assert error.value.error_code == "resource_limit"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b" ",
        b"[]",
        b"null",
        b"true",
        b"1",
        b'"text"',
        b"{}{}",
        b"{} false",
        b"\xef\xbb\xbf{}",
        b"\xff{}",
        b"{}\xff",
        b"\xc0\x80{}",
        b"\xed\xa0\x80{}",
        b"\xc2\xa0{}",
        b"{}\xc2\xa0",
        b"\x0b{}",
        b"\x0c{}",
        b'{1:"value"}',
        b'{"a" 1}',
        b'{"a":}',
        b'{"a":1,}',
        b'{"records":[,]}',
        b'{"records":[{},]}',
        b'{"records":[{} {}]}',
        b'{"records":[{"x":]}]}',
        b'{"records":[{"x":"bad\nline"}]}',
        b'{"records":[{"x":"\\q"}]}',
        b'{"records":[{"x":"unterminated}]}',
        b'{"records":[{"x":1}',
        b'{"records":[tru]}',
        b'{"records":[1e]}',
    ],
)
def test_invalid_json_utf8_and_non_json_whitespace_fail_without_input_diagnostics(body, caplog):
    """Invalid JSON UTF-8 and non JSON whitespace fail without input diagnostics."""
    with pytest.raises(FeedProtocolError) as error:
        _decode(body)
    assert error.value.error_code == "json"
    assert str(error.value) == "JSON feed document was refused" and not caplog.records


@pytest.mark.parametrize("value", [b"NaN", b"Infinity", b"-Infinity"])
@pytest.mark.parametrize("location", ["envelope", "record", "nested"])
def test_non_json_numeric_constants_are_never_accepted(value, location):
    """Non JSON numeric constants are never accepted."""
    bodies = {
        "envelope": b'{"value":' + value + b"}",
        "record": b'{"records":[' + value + b"]}",
        "nested": b'{"records":[{"value":[' + value + b"]}]}",
    }
    with pytest.raises(FeedProtocolError) as error:
        _decode(bodies[location])
    assert error.value.error_code == "json"


def test_large_valid_numbers_remain_finite_exact_decimal_values_for_later_validation():
    """Large valid numbers remain finite exact decimal values for later validation."""
    digits = "9" * 5000
    body = (
        '{"records":[{"big":' + digits + ',"exponent":1e999,"fraction":0.1,"small":7}]}'
    ).encode()
    values = dict(_records(_decode(body))[0].value.pairs)
    assert values["big"] == Decimal(digits) and isinstance(values["big"], Decimal)
    assert values["exponent"] == Decimal("1e999") and values["exponent"].is_finite()
    assert values["fraction"] == Decimal("0.1") and type(values["small"]) is int


def test_escaped_lone_surrogate_is_metadata_to_quarantine_not_a_whole_page_failure():
    """Escaped lone surrogate is metadata to quarantine not a whole page failure."""
    raw = b'{"uuid":"public-id","title":"\\ud800"}'
    record = _records(_decode(b'{"records":[' + raw + b"]}"))[0]
    assert dict(record.value.pairs)["title"] == "\ud800" and record.body == raw


def test_page_limit_precedes_json_decoding_and_record_limit_precedes_metadata_construction(
    monkeypatch,
):
    """Page limit precedes JSON decoding and record limit precedes metadata construction."""
    real_decoder, real_integer = json.JSONDecoder, decoding._integer
    decoder = create_autospec(real_decoder, side_effect=real_decoder)
    monkeypatch.setattr(decoding.json, "JSONDecoder", decoder)
    with pytest.raises(FeedProtocolError) as error:
        _decode(b'{"records":[]}', max_page_bytes=1)
    assert error.value.error_code == "resource_limit"
    decoder.assert_not_called()
    integer = create_autospec(real_integer, side_effect=real_integer)
    monkeypatch.setattr(decoding, "_integer", integer)
    with pytest.raises(FeedProtocolError) as error:
        _decode(b'{"records":[{"n":1,"large":"' + b"x" * 100 + b'"}]}', max_record_bytes=20)
    assert error.value.error_code == "resource_limit"
    integer.assert_not_called()


@pytest.mark.parametrize("case", ["depth", "exponent"])
def test_interpreter_representation_limits_fail_as_resource_errors(case):
    # Python 3.12's C JSON decoder accepts deeper arrays than Python 3.11.
    """Interpreter representation limits fail as resource errors."""
    value = (
        b"[" * 15_000 + b"0" + b"]" * 15_000 if case == "depth" else b"1e999999999999999999999999"
    )
    with pytest.raises(FeedProtocolError) as error:
        _decode(b'{"records":[' + value + b"]}")
    assert error.value.error_code == "resource_limit"


def test_disabled_decimal_trap_cannot_turn_an_unrepresentable_json_number_into_nan():
    """Disabled decimal trap cannot turn an unrepresentable JSON number into nan."""
    with localcontext() as context:
        context.traps[InvalidOperation] = False
        with pytest.raises(FeedProtocolError) as error:
            _decode(b'{"records":[{"number":1e999999999999999999999999}]}')
        assert error.value.error_code == "resource_limit"
        record = _records(_decode(b'{"records":[{"number":1e999}]}'))[0]
        assert dict(record.value.pairs)["number"] == Decimal("1e999")
        assert dict(record.value.pairs)["number"].is_finite()
        assert context.traps[InvalidOperation] is False


def test_allocation_failure_has_a_fixed_suppressed_error(monkeypatch, caplog):
    """Allocation failure has a fixed suppressed error."""
    real_decoder = json.JSONDecoder
    decoder = create_autospec(real_decoder, side_effect=MemoryError("private-input-canary"))
    monkeypatch.setattr(decoding.json, "JSONDecoder", decoder)
    with pytest.raises(FeedProtocolError) as error:
        _decode(b"{}")
    assert error.value.error_code == "resource_limit"
    assert "private-input-canary" not in "".join(traceback.format_exception(error.value))
    assert error.value.__suppress_context__ and not caplog.records


@pytest.mark.parametrize("field", ["max_page_bytes", "max_record_bytes", "max_records"])
@pytest.mark.parametrize(
    "value,error_type",
    [(True, TypeError), ("1", TypeError), (1.0, TypeError), (0, ValueError), (-1, ValueError)],
)
def test_programming_budgets_require_strict_positive_integers(field, value, error_type):
    """Programming budgets require strict positive integers."""
    with pytest.raises(error_type):
        _decode(b"{}", **{field: value})


def test_empty_object_nonarray_records_and_immutable_wrappers_are_left_for_envelope_validation():
    """Empty object nonarray records and immutable wrappers are left for envelope validation."""
    assert _decode(b" \t\r\n{} \t\r\n") == JSONObject(())
    assert _decode(b'{"records":null}') == JSONObject((("records", None),))
    record = _records(_decode(b'{"records":[{  "title":"synthetic"  }]}'))[0]
    assert "body=" not in repr(record)
    with pytest.raises(FrozenInstanceError):
        record.body = b"changed"
    with pytest.raises(FrozenInstanceError):
        record.value.pairs = ()
