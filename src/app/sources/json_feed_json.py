"""Strict JSON decoding that preserves duplicate keys and original record bytes."""

import json
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from .json_feed_protocol import FeedProtocolError

_JSON_WS = " \t\r\n"
_NATIVE_INTEGER_CHARS = 20


@dataclass(frozen=True, slots=True)
class JSONObject:
    """An ordered object whose decoded keys retain all duplicate evidence."""

    pairs: tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class RawJSONRecord:
    """One top-level record entry and its exact original UTF-8 value slice."""

    value: object
    body: bytes = field(repr=False)


def _decimal(value: str) -> Decimal:
    """Parse a finite Decimal; reject nonfinite values with FeedProtocolError(resource_limit)."""
    parsed = Decimal(value)
    if not parsed.is_finite():
        raise FeedProtocolError("resource_limit")
    return parsed


def _integer(value: str) -> int | Decimal:
    """Use int for at most 20 digits excluding the sign, otherwise a finite Decimal."""
    return int(value) if len(value.lstrip("-")) <= _NATIVE_INTEGER_CHARS else _decimal(value)


def _constant(_value: str) -> object:
    """Reject JSON NaN/Infinity with FeedProtocolError(json)."""
    raise FeedProtocolError("json")


def _skip_ws(text: str, index: int) -> int:
    """Return the first index at or after index outside JSON whitespace, or len(text)."""
    while index < len(text) and text[index] in _JSON_WS:
        index += 1
    return index


def _record_end(text: str, start: int, max_bytes: int) -> int:
    """Bound a value's original bytes before constructing its decoded metadata.

    This recognizes boundaries only; JSONDecoder remains the syntax authority.
    UTF-8 was decoded strictly, so every raw character can be encoded safely even
    when the eventual JSON value contains an escaped lone surrogate.
    """
    quoted = escaped = False
    depth = size = 0
    for index in range(start, len(text)):
        character = text[index]
        if not quoted and depth == 0 and character in _JSON_WS + ",]":
            return index
        size += len(character.encode("utf-8"))
        if size > max_bytes:
            raise FeedProtocolError("resource_limit")
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
                if depth == 0:
                    return index + 1
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
        elif character in "}]":
            depth -= 1
            if depth == 0:
                return index + 1
    if quoted or depth:
        raise FeedProtocolError("json")
    return len(text)


def _decode_object(
    text: str, decoder: json.JSONDecoder, *, max_record_bytes: int, max_records: int
) -> JSONObject:
    """Decode one complete object, preserving pairs and bounding top-level records arrays."""
    count = 0

    def records(index: int) -> tuple[list[RawJSONRecord], int]:
        """Decode a records array from its opening bracket; count entries across duplicate
        arrays.
        """
        nonlocal count
        values: list[RawJSONRecord] = []
        index = _skip_ws(text, index + 1)
        if index < len(text) and text[index] == "]":
            return values, index + 1
        while True:
            count += 1
            if count > max_records:
                raise FeedProtocolError("resource_limit")
            end = _record_end(text, index, max_record_bytes)
            raw = text[index:end]
            value, decoded_end = decoder.raw_decode(raw)
            if decoded_end != len(raw):
                raise FeedProtocolError("json")
            values.append(RawJSONRecord(value, raw.encode("utf-8")))
            index = _skip_ws(text, end)
            if index >= len(text):
                raise FeedProtocolError("json")
            if text[index] == "]":
                return values, index + 1
            if text[index] != ",":
                raise FeedProtocolError("json")
            index = _skip_ws(text, index + 1)

    index = _skip_ws(text, 0)
    if index >= len(text) or text[index] != "{":
        raise FeedProtocolError("json")
    index = _skip_ws(text, index + 1)
    pairs: list[tuple[str, object]] = []
    if index < len(text) and text[index] == "}":
        index += 1
    else:
        while True:
            key, index = decoder.raw_decode(text, index)
            index = _skip_ws(text, index)
            if not isinstance(key, str) or index >= len(text) or text[index] != ":":
                raise FeedProtocolError("json")
            index = _skip_ws(text, index + 1)
            if key == "records" and index < len(text) and text[index] == "[":
                value, index = records(index)
            else:
                value, index = decoder.raw_decode(text, index)
            pairs.append((key, value))
            index = _skip_ws(text, index)
            if index >= len(text):
                raise FeedProtocolError("json")
            if text[index] == "}":
                index += 1
                break
            if text[index] != ",":
                raise FeedProtocolError("json")
            index = _skip_ws(text, index + 1)
    if _skip_ws(text, index) != len(text):
        raise FeedProtocolError("json")
    return JSONObject(tuple(pairs))


def decode_feed_document(
    body: bytes, *, max_page_bytes: int, max_record_bytes: int, max_records: int
) -> JSONObject:
    """Decode bounded UTF-8 JSON while retaining duplicate keys and original record bytes.

    Positive integer budgets bound page bytes, each record and total record entries
    (including invalid entries and duplicate top-level arrays). Invalid arguments raise
    TypeError/ValueError; syntax/UTF-8 errors raise FeedProtocolError(json), exhausted
    resources raise resource_limit. Only top-level records arrays receive wrappers;
    ordinary objects become JSONObject; integers longer than 20 digits and all floats become
    Decimal.
    """
    budgets = (max_page_bytes, max_record_bytes, max_records)
    if any(type(value) is not int for value in budgets):
        raise TypeError("JSON feed decoding budgets must be integers")
    if any(value <= 0 for value in budgets):
        raise ValueError("JSON feed decoding budgets must be positive")
    if not isinstance(body, bytes):
        raise TypeError("JSON feed document must be bytes")
    if len(body) > max_page_bytes:
        raise FeedProtocolError("resource_limit")
    try:
        text = body.decode("utf-8", errors="strict")
        decoder = json.JSONDecoder(
            object_pairs_hook=lambda pairs: JSONObject(tuple(pairs)),
            parse_int=_integer,
            parse_float=_decimal,
            parse_constant=_constant,
        )
        return _decode_object(
            text, decoder, max_record_bytes=max_record_bytes, max_records=max_records
        )
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise FeedProtocolError("json") from None
    except (RecursionError, MemoryError, InvalidOperation):
        raise FeedProtocolError("resource_limit") from None
