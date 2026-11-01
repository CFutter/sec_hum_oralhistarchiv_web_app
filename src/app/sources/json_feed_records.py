"""Strict v1 metadata classification after authenticated envelope/identity checks."""

import re
from datetime import UTC, datetime
from typing import Any

from app.ingestion_contracts import DOI_MAX_CHARS, PROJECT_TITLE_MAX_CHARS
from app.url_safety import parse_http_url

from .base import normalize_harvest_since
from .json_feed_json import JSONObject, RawJSONRecord, decode_feed_document
from .json_feed_lexical import FEED_UTC_SECOND_PATTERN, FEED_UUID_PATTERN
from .json_feed_protocol import (
    FEED_ACCESS_LABELS,
    FeedProtocolError,
    FeedRecordInput,
    FeedRecordRejection,
)

_TEXT_FIELDS = {
    "description",
    "resource_description",
    "project_description",
    "bibliographical_citation",
}
_LABEL_FIELDS = {"languages", "authors", "keywords", "institutions", "main_disciplines"}
_FIELDS = (
    _TEXT_FIELDS
    | _LABEL_FIELDS
    | {
        "uuid",
        "title",
        "project_title",
        "resource_proxies",
        "license_val",
        "license_url",
        "version",
        "doi",
        "resource_type",
        "modified_at",
        "visibility_tier",
    }
)
_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}\Z")
_HTTP_URI = re.compile(r"https?://[^/?#\s\x00-\x1f\x7f]+[^\s\x00-\x1f\x7f]*\Z")
_LABEL_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_TEXT = 16_384
_MAX_LABEL = 256
_MAX_URL = 2048
_MAX_LIST = 100
_SURROGATE_START = 0xD800
_SURROGATE_END = 0xDFFF


def _walk_flags(value: object) -> tuple[bool, bool]:
    """Inspect keys and values without recursing through untrusted nested input."""
    pending = [value]
    duplicate = invalid_unicode = False
    while pending:
        item = pending.pop()
        if isinstance(item, JSONObject):
            keys: set[str] = set()
            for key, child in item.pairs:
                duplicate |= key in keys
                keys.add(key)
                pending.extend((key, child))
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            invalid_unicode |= "\x00" in item or any(
                _SURROGATE_START <= ord(character) <= _SURROGATE_END for character in item
            )
    return duplicate, invalid_unicode


def _nullable_text(value: object, maximum: int) -> bool:
    """Accept None or a string of at most maximum characters."""
    return value is None or (isinstance(value, str) and len(value) <= maximum)


def _label(value: object) -> bool:
    """Accept 1..256 characters without edge whitespace or ASCII controls."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= _MAX_LABEL
        and value == value.strip()
        and _LABEL_CONTROL.search(value) is None
    )


def _labels(value: object, *, required: bool = False) -> bool:
    """Accept up to 100 valid labels; required forbids an empty list."""
    return (
        isinstance(value, list)
        and int(required) <= len(value) <= _MAX_LIST
        and all(_label(item) for item in value)
    )


def _url(value: object) -> bool:
    """Accept None or a credential-free HTTP(S) URL of at most 2048 characters."""
    if value is None:
        return True
    if (
        not isinstance(value, str)
        or len(value) > _MAX_URL
        or "\\" in value
        or _HTTP_URI.fullmatch(value) is None
    ):
        return False
    try:
        parse_http_url(value)
    except ValueError:
        return False
    return True


def _proxies(value: object) -> list[dict[str, Any]] | None:
    """Return up to 100 type/ref mappings, permitting null refs; return None for invalid input."""
    if not isinstance(value, list) or len(value) > _MAX_LIST:
        return None
    proxies: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, JSONObject):
            return None
        fields = dict(item.pairs)
        if (
            set(fields) != {"type", "ref"}
            or fields["type"] not in ("Resource", "LandingPage")
            or not _url(fields["ref"])
        ):
            return None
        proxies.append(fields)
    return proxies


def _timestamp(value: object) -> datetime | None:
    """Parse a UTC whole-second wire timestamp; return None for invalid input."""
    if not isinstance(value, str) or FEED_UTC_SECOND_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def _record_object(record: FeedRecordInput, max_record_bytes: int) -> JSONObject:
    """Decode bounded original object bytes and verify their sole UUID matches the claimed
    identity.

    Invalid budgets raise TypeError/ValueError; decoding, resource and identity
    failures raise FeedProtocolError.
    """
    if type(max_record_bytes) is not int:
        raise TypeError("JSON feed record byte budget must be an integer")
    if max_record_bytes <= 0:
        raise ValueError("JSON feed record byte budget must be positive")
    if len(record.body) > max_record_bytes:
        raise FeedProtocolError("resource_limit")
    if not isinstance(record.uuid, str) or FEED_UUID_PATTERN.fullmatch(record.uuid) is None:
        raise FeedProtocolError("identity")
    wrapper = b'{"records":[' + record.body + b"]}"
    document = decode_feed_document(
        wrapper,
        max_page_bytes=max_record_bytes + len(b'{"records":[]}'),
        max_record_bytes=max_record_bytes,
        max_records=1,
    )
    if len(document.pairs) != 1 or document.pairs[0][0] != "records":
        raise FeedProtocolError("identity")
    records = document.pairs[0][1]
    if not isinstance(records, list) or len(records) != 1:
        raise FeedProtocolError("identity")
    raw = records[0]
    if not isinstance(raw, RawJSONRecord) or not isinstance(raw.value, JSONObject):
        raise FeedProtocolError("identity")
    identities = [value for key, value in raw.value.pairs if key == "uuid"]
    if len(identities) != 1 or identities[0] != record.uuid or raw.body != record.body:
        raise FeedProtocolError("identity")
    return raw.value


def classify_feed_record(
    record: FeedRecordInput,
    *,
    cutoff: datetime,
    since: datetime | None,
    max_record_bytes: int,
    max_project_title_chars: int = 4096,
) -> dict[str, Any] | FeedRecordRejection:
    """Return native-v1 metadata with modified_at renamed to upstream_modified_at, or a
    quarantine reason.

    Require positive integer max_record_bytes and an integer project-title cap in
    1..16384; invalid limits raise TypeError/ValueError.
    Syntax/resource/identity failures raise FeedProtocolError; identifiable invalid metadata
    returns a metadata-free FeedRecordRejection. cutoff must be aware; since=None
    selects all, otherwise normalize to UTC and truncate to inclusive whole seconds.
    Proxy objects become mappings; no partial mapping escapes a rejection.
    """
    if not isinstance(cutoff, datetime):
        raise TypeError("JSON feed record cutoff must be a datetime")
    if cutoff.utcoffset() is None:
        raise ValueError("JSON feed record cutoff must be timezone-aware")
    cutoff = cutoff.astimezone(UTC)
    since = normalize_harvest_since(since)
    if since is not None:
        since = since.replace(microsecond=0)
    if type(max_project_title_chars) is not int:
        raise TypeError("JSON feed project-title character limit must be an integer")
    if not 1 <= max_project_title_chars <= PROJECT_TITLE_MAX_CHARS:
        raise ValueError("JSON feed project-title character limit must be between 1 and 16384")
    value = _record_object(record, max_record_bytes)
    duplicate, invalid_unicode = _walk_flags(value)
    if duplicate:
        return FeedRecordRejection(record.uuid, "duplicate_record_key")
    values = dict(value.pairs)
    if set(values) != _FIELDS:
        return FeedRecordRejection(record.uuid, "record_shape")
    if values["visibility_tier"] not in ("public", "registered", "vetted"):
        return FeedRecordRejection(record.uuid, "record_tier")
    modified = _timestamp(values["modified_at"])
    if modified is None or modified > cutoff or (since is not None and modified < since):
        return FeedRecordRejection(record.uuid, "record_timestamp")
    proxies = _proxies(values["resource_proxies"])
    version = values["version"]
    if (
        invalid_unicode
        or not _label(values["title"])
        or not _nullable_text(values["project_title"], max_project_title_chars)
        or not all(_nullable_text(values[field], _MAX_TEXT) for field in _TEXT_FIELDS)
        or not all(
            _labels(values[field], required=field == "institutions") for field in _LABEL_FIELDS
        )
        or not _nullable_text(values["doi"], DOI_MAX_CHARS)
        or not _nullable_text(values["resource_type"], _MAX_LABEL)
        or not _url(values["license_url"])
        or not isinstance(values["license_val"], str)
        or values["license_val"] not in FEED_ACCESS_LABELS
        or (
            version is not None
            and (not isinstance(version, str) or _VERSION.fullmatch(version) is None)
        )
        or proxies is None
    ):
        return FeedRecordRejection(record.uuid, "record_metadata")
    values["resource_proxies"] = proxies
    values["upstream_modified_at"] = modified
    del values["modified_at"]
    return values
