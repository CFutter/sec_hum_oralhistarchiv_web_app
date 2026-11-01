"""Synchronous OAI-PMH harvesting and CMDI parsing; no database writes.

Use fetch_updates_isolated for a terminating child-process watchdog.
Limits: caller-supplied max_pages, 4 MiB/page, 32 MiB received, 1 MiB/record,
20,000 records, 16 MiB retained result, and a 240-second deadline.
HTTP uses 10-second connect/read timeouts, up to three retries, no
redirects, and identity encoding. XML structure/text are bounded during tree
construction; entities, document types and network loading are disabled there.
"""

from __future__ import annotations

import contextlib
import json
import logging
import multiprocessing
import os
import sys
import threading
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from multiprocessing.connection import Connection
from typing import Any

import requests
from lxml import etree
from pydantic import Field, ValidationError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app import escape_log_controls
from app.ingestion_contracts import (
    HarvestResult,
    ParsedRecord,
    harvest_result_from_document,
    harvest_result_to_json,
)
from app.ingestion_contracts.cancellation import (
    check_harvest_cancellation,
    wait_for_harvest_step,
)
from app.source_contract import SOURCE_NAME_PATTERN

from ..url_safety import is_safe_http_url
from .parser_transport import ParserServiceError, request_parser, use_parser_service

logger = logging.getLogger(__name__)

OAI_REQUEST_TIMEOUT = (10, 10)
OAI_DEFAULT_MAX_PAGES = 500
OAI_NS = "http://www.openarchives.org/OAI/2.0/"

_OAI_CHUNK_BYTES = 64 * 1024
_OAI_MAX_PAGE_BYTES = 4 * 1024 * 1024
_OAI_MAX_HARVEST_BYTES = 32 * 1024 * 1024
_OAI_MAX_RECORD_BYTES = 1024 * 1024
_OAI_MAX_RECORDS = 20_000
_OAI_MAX_RESULT_BYTES = 16 * 1024 * 1024
_OAI_MAX_RESUMPTION_TOKEN_CHARS = 4096
_OAI_MAX_XML_ELEMENTS = 100_000
_OAI_MAX_XML_DEPTH = 64
_OAI_MAX_XML_TEXT_CHARS = 3 * 1024 * 1024
_OAI_MAX_XML_ATTRIBUTES = 200_000
_OAI_MAX_CLOCK_SKEW = timedelta(minutes=5)
_OAI_MIN_SOURCE_CURSOR = datetime.min.replace(tzinfo=UTC) + timedelta(days=2)
_OAI_TOTAL_TIMEOUT_SECONDS = 240.0
_OAI_WORKER_SHUTDOWN_SECONDS = 1.0
_OAI_WORKER_ERROR_CHARS = 500
_OAI_WORKER_WIRE_OVERHEAD_BYTES = 4096

_WORKER_SUCCESS = b"S"
_WORKER_ERROR = b"E"

_EXPECTED_CMDI_PROFILE = "clarin.eu:cr1:p_1696338267562"
_CMDI_NAMESPACES = {
    "oai": OAI_NS,
    "cmd": "http://www.clarin.eu/cmd/1",
    "cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562",
}
_BASE_CMDI_NAMESPACES = {
    "oai": OAI_NS,
    "cmd": "http://www.clarin.eu/cmd/1",
}
_EXPECTED_CMDP_NAMESPACE = _CMDI_NAMESPACES["cmdp"]
_CMDIParser = Callable[[etree._Element], dict[str, Any]]


class _CmdiParsedRecord(ParsedRecord):
    """Retain the CMDI project-title cap independently of larger shared feed titles."""

    project_title: str | None = Field(max_length=4096)


class OAIProtocolError(Exception):
    """A structured OAI-PMH protocol error."""

    def __init__(self, error_code: str, message: str) -> None:
        """Store a protocol code and diagnostic and include both in the exception message."""
        self.error_code = error_code
        self.message = message
        super().__init__(f"OAI-PMH [{error_code}]: {message}")


class OAIContinuationError(OAIProtocolError):
    """The endpoint rejected a continuation token after page one."""


class _BudgetedXMLTarget:
    """Count XML structure before forwarding callbacks to the page tree builder."""

    def __init__(self) -> None:
        """Initialize a fresh tree builder, counters and remembered failure."""
        self._builder = etree.TreeBuilder()
        self._elements = 0
        self._depth = 0
        self._text_chars = 0
        self._attributes = 0
        self._failure: OAIProtocolError | None = None

    def _reject(self, reason: str) -> None:
        """Remember and raise OAIProtocolError(xml_budget_exceeded)."""
        self._failure = OAIProtocolError("xml_budget_exceeded", reason)
        raise self._failure

    def start(self, tag: str | bytes, attrib: dict[str | bytes, str | bytes]) -> None:
        """Count elements, depth, attributes and text before forwarding an allowed start tag."""
        self._elements += 1
        self._depth += 1
        self._attributes += len(attrib)
        self._text_chars += sum(len(key) + len(value) for key, value in attrib.items())
        if self._elements > _OAI_MAX_XML_ELEMENTS:
            self._reject("OAI XML exceeds the element limit")
        if self._depth > _OAI_MAX_XML_DEPTH:
            self._reject("OAI XML exceeds the nesting limit")
        if self._attributes > _OAI_MAX_XML_ATTRIBUTES:
            self._reject("OAI XML exceeds the attribute limit")
        if self._text_chars > _OAI_MAX_XML_TEXT_CHARS:
            self._reject("OAI XML exceeds the text limit")
        self._builder.start(tag, attrib)

    def end(self, tag: str | bytes) -> None:
        """Decrease depth and forward the closing tag to the tree builder."""
        self._depth -= 1
        self._builder.end(tag)

    def data(self, data: str | bytes) -> None:
        """Count text and forward it unless the text budget is exceeded."""
        self._text_chars += len(data)
        if self._text_chars > _OAI_MAX_XML_TEXT_CHARS:
            self._reject("OAI XML exceeds the text limit")
        self._builder.data(data)

    def comment(self, text: str | bytes) -> None:
        """Discard comments rather than allowing them into the retained tree."""
        del text

    def doctype(self, _name: str, _public_id: str | None, _system_id: str | None) -> None:
        """Reject every document type declaration as xml_budget_exceeded."""
        self._reject("OAI XML must not contain a document type declaration")

    def close(self) -> etree._Element:
        """Return the built tree, re-raising any remembered budget failure."""
        if self._failure is not None:
            raise self._failure
        return self._builder.close()


def _make_safe_parser(*, target: _BudgetedXMLTarget | None = None) -> etree.XMLParser:
    """Return a fresh parser with entity resolution, DTD loading and network access disabled."""
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
        remove_comments=True,
        remove_pis=True,
        target=target,
    )


_retry_strategy = Retry(
    total=3,
    backoff_factor=1.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
)


def _first_text(
    record_xml: etree._Element,
    xpath: str,
    namespaces: dict[str, str],
) -> str | None:
    """Return the first XPath element's trimmed direct text, or None if unusable."""
    nodes = record_xml.xpath(xpath, namespaces=namespaces)
    if not isinstance(nodes, list) or not nodes:
        return None

    first = nodes[0]
    if not isinstance(first, etree._Element):
        return None

    text = (first.text or "").strip()
    return text or None


def _component_profile_namespaces(record_xml: etree._Element) -> set[str]:
    """Return non-base namespaces used by elements below CMDI Components."""
    component_nodes = record_xml.xpath(
        ".//cmd:Components//*",
        namespaces=_BASE_CMDI_NAMESPACES,
    )
    if not isinstance(component_nodes, list):
        return set()

    return {
        namespace
        for element in component_nodes
        if isinstance(element, etree._Element) and isinstance(element.tag, str)
        if (namespace := etree.QName(element).namespace)
        and namespace != _BASE_CMDI_NAMESPACES["cmd"]
    }


def _detect_cmdi_profile(record_xml: etree._Element) -> str | None:
    """Return explicit MdProfile, infer the supported profile from its sole component namespace,
    or None.

    Raise OAIProtocolError when the supported explicit profile conflicts
    with component namespaces.
    """
    explicit_profile = _first_text(
        record_xml,
        ".//cmd:MdProfile",
        _BASE_CMDI_NAMESPACES,
    )
    uses_expected_namespace = _component_profile_namespaces(record_xml) == {
        _EXPECTED_CMDP_NAMESPACE
    }

    if explicit_profile is not None:
        if explicit_profile == _EXPECTED_CMDI_PROFILE and not uses_expected_namespace:
            raise OAIProtocolError(
                "metadata_profile_mismatch",
                "CMDI MdProfile identifies the supported profile, "
                "but its component namespace does not match",
            )
        return explicit_profile

    if uses_expected_namespace:
        return _EXPECTED_CMDI_PROFILE

    return None


def _build_session() -> requests.Session:
    """Return a caller-owned HTTP session with GET retries for connection errors
    and 429/500/502/503/504.
    """
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=_retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


@dataclass(slots=True)
class _HarvestBudget:
    """Mutable per-harvest counters and monotonic deadline; use only from one thread."""

    deadline: float
    response_bytes: int = 0
    record_count: int = 0
    result_bytes: int = 0
    source_cursor: datetime | None = None

    @classmethod
    def start(cls) -> _HarvestBudget:
        """Create empty counters with a monotonic deadline 240 seconds from now."""
        return cls(deadline=time.monotonic() + _OAI_TOTAL_TIMEOUT_SECONDS)

    def begin_attempt(self) -> None:
        """Reset retained output/cursor; preserve cumulative transport work and deadline."""
        self.result_bytes = 0
        self.source_cursor = None

    def check_deadline(self) -> None:
        """Raise OAIProtocolError(resource_limit) once the monotonic deadline is reached."""
        if time.monotonic() >= self.deadline:
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeded its total wall-clock deadline",
            )

    def validate_content_length(self, response: requests.Response) -> None:
        """Check an optional Content-Length against remaining page/harvest byte budgets.

        Malformed/negative values raise OAIProtocolError(malformed_response);
        oversized values raise OAIProtocolError(resource_limit). Counters are unchanged.
        """
        raw_length = response.headers.get("Content-Length")
        if raw_length is None:
            return
        try:
            length = int(raw_length, 10)
        except ValueError as exc:
            raise OAIProtocolError(
                "malformed_response",
                "OAI response has an invalid Content-Length header",
            ) from exc
        if length < 0:
            raise OAIProtocolError(
                "malformed_response",
                "OAI response has a negative Content-Length header",
            )
        if length > _OAI_MAX_PAGE_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI response page exceeds the byte limit",
            )
        if self.response_bytes + length > _OAI_MAX_HARVEST_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeds the aggregate response-byte limit",
            )

    def consume_response_chunk(self, page_bytes: int, chunk: bytes) -> int:
        """Check deadline and byte limits, increment aggregate bytes, and return the new page total.

        page_bytes is this page's prior total. OAIProtocolError rejects deadline
        or limit violations before updating the aggregate.
        """
        self.check_deadline()
        next_page_bytes = page_bytes + len(chunk)
        next_harvest_bytes = self.response_bytes + len(chunk)
        if next_page_bytes > _OAI_MAX_PAGE_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI response page exceeds the byte limit",
            )
        if next_harvest_bytes > _OAI_MAX_HARVEST_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeds the aggregate response-byte limit",
            )
        self.response_bytes = next_harvest_bytes
        return next_page_bytes

    def consume_record(self, record: etree._Element) -> None:
        """Check deadline, increment record count,
        then enforce count and serialized XML byte limits.

        OAIProtocolError(resource_limit) may leave the count incremented.
        """
        self.check_deadline()
        self.record_count += 1
        if self.record_count > _OAI_MAX_RECORDS:
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeds the record-count limit",
            )
        if len(etree.tostring(record, encoding="utf-8")) > _OAI_MAX_RECORD_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI record exceeds the per-record byte limit",
            )

    def consume_result(self, value: object) -> None:
        """Count compact UTF-8 JSON bytes and reject totals over 16 MiB or an expired deadline.

        The counter remains incremented on size failure. Serialization errors
        propagate; limit failures raise OAIProtocolError(resource_limit).
        """
        self.check_deadline()
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            default=_json_size_default,
        ).encode("utf-8")
        self.result_bytes += len(encoded)
        if self.result_bytes > _OAI_MAX_RESULT_BYTES:
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeds the retained-result byte limit",
            )


def _json_size_default(value: object) -> str:
    """Serialize datetimes as ISO 8601; raise TypeError for other unsupported JSON values."""
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Unsupported harvested value type: {type(value).__name__}")


def _read_bounded_response(
    response: requests.Response,
    budget: _HarvestBudget,
) -> bytes:
    """Read identity-encoded HTTP bytes and update budget counters.

    Raise OAIProtocolError for other encodings, invalid lengths/chunks, or
    resource limits; HTTP streaming errors propagate.
    """
    content_encoding = response.headers.get("Content-Encoding", "").strip().casefold()
    if content_encoding not in {"", "identity"}:
        raise OAIProtocolError(
            "unsupported_content_encoding",
            "OAI endpoint ignored Accept-Encoding: identity",
        )

    budget.validate_content_length(response)
    body = bytearray()
    page_bytes = 0
    for chunk in response.iter_content(chunk_size=_OAI_CHUNK_BYTES):
        if not chunk:
            continue
        if not isinstance(chunk, bytes):
            raise OAIProtocolError(
                "malformed_response",
                "OAI response yielded a non-bytes body chunk",
            )
        page_bytes = budget.consume_response_chunk(page_bytes, chunk)
        body.extend(chunk)

    budget.check_deadline()
    return bytes(body)


def _source_response_date(root: etree._Element) -> datetime:
    """Parse a UTC responseDate usable as an incremental checkpoint.

    Allow at most five minutes of upstream clock lead and require enough
    range for the ingestion engine's two-day overlap. Invalid dates or
    unusable checkpoints raise OAIProtocolError.
    """
    dates = root.findall(f"{{{OAI_NS}}}responseDate")
    raw_date = dates[0].text if len(dates) == 1 else None
    try:
        cursor = datetime.strptime(raw_date or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise OAIProtocolError(
            "malformed_response",
            "Missing or invalid source responseDate",
        ) from exc

    if cursor < _OAI_MIN_SOURCE_CURSOR:
        raise OAIProtocolError(
            "source_clock",
            "Source responseDate is too early for the incremental overlap",
        )
    if cursor - datetime.now(UTC) > _OAI_MAX_CLOCK_SKEW:
        raise OAIProtocolError(
            "source_clock",
            "Source responseDate exceeds the allowed clock skew",
        )
    return cursor


def _validate_max_pages(max_pages: int) -> None:
    """Reject invalid page caps before creating HTTP or process resources."""
    if type(max_pages) is not int or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")


def _response_payload(root: etree._Element, page_number: int) -> etree._Element:
    """Select one unambiguous result/error before any records or cursor escape.

    Multiple error elements remain a failed response; never infer empty success
    or continuation recovery from only the first of several reported errors.
    """
    errors = root.findall(f"{{{OAI_NS}}}error")
    results = root.findall(f"{{{OAI_NS}}}ListRecords")
    if errors and results:
        raise OAIProtocolError("malformed_response", "Mixed OAI result and error response")
    if errors:
        if len(errors) != 1:
            raise OAIProtocolError("upstream_error", "OAI endpoint reported multiple errors")
        return errors[0]
    if len(results) != 1:
        raise OAIProtocolError(
            "malformed_response",
            f"Expected exactly one ListRecords element on page {page_number}",
        )
    return results[0]


def _resumption_token(list_records: etree._Element, page_number: int) -> str | None:
    """Reject ambiguous tokens before selecting the next page or completion."""
    tokens = list_records.findall(f"{{{OAI_NS}}}resumptionToken")
    if len(tokens) > 1:
        raise OAIProtocolError("malformed_response", "Multiple OAI resumption tokens")
    if page_number > 1 and not tokens:
        raise OAIProtocolError(
            "malformed_response", "Continuation omitted its terminal resumption token"
        )
    raw_token = tokens[0].text if tokens else None
    return raw_token.strip() if raw_token and raw_token.strip() else None


def _oai_list_records(  # noqa: PLR0912
    oai_url: str,
    metadata_prefix: str,
    since: str | None,
    *,
    max_pages: int = OAI_DEFAULT_MAX_PAGES,
    budget: _HarvestBudget | None = None,
) -> Generator[etree._Element, None, None]:
    """Yield OAI record elements across bounded ListRecords pages, closing the HTTP session on exit.

    since is forwarded as from; None omits it. A supplied budget is updated
    in place, including the first page's responseDate. First-page
    noRecordsMatch is empty success; rejected continuation tokens raise
    OAIContinuationError. Other protocol/limit failures raise OAIProtocolError;
    requests and XML errors propagate. Results and errors must be exclusive;
    results require one ListRecords and at most one resumptionToken element.
    Continuations must include a terminal token; tokens may not repeat or exceed
    4,096 characters. Ambiguous pages never yield records or establish a cursor.
    """
    _validate_max_pages(max_pages)
    active_budget = budget if budget is not None else _HarvestBudget.start()

    request_params: dict[str, str] = {
        "verb": "ListRecords",
        "metadataPrefix": metadata_prefix,
    }
    if since is not None:
        request_params["from"] = since

    session = _build_session()
    seen_tokens: set[str] = set()

    try:
        for page_number in range(1, max_pages + 1):
            active_budget.check_deadline()

            with session.get(
                oai_url,
                params=request_params,
                timeout=OAI_REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
                headers={"Accept-Encoding": "identity"},
            ) as response:
                if HTTPStatus.MULTIPLE_CHOICES <= response.status_code < HTTPStatus.BAD_REQUEST:
                    raise OAIProtocolError(
                        "redirect_disallowed",
                        f"OAI endpoint returned HTTP {response.status_code} on "
                        f"page {page_number}; redirects are not followed",
                    )
                if not (HTTPStatus.OK <= response.status_code < HTTPStatus.MULTIPLE_CHOICES):
                    raise OAIProtocolError(
                        "http_status",
                        f"OAI endpoint returned HTTP {response.status_code} on page {page_number}",
                    )
                body = _read_bounded_response(response, active_budget)

            root = etree.fromstring(body, parser=_make_safe_parser(target=_BudgetedXMLTarget()))
            if root.tag != f"{{{OAI_NS}}}OAI-PMH":
                raise OAIProtocolError(
                    "malformed_response",
                    f"Expected OAI-PMH response root on page {page_number}",
                )

            payload = _response_payload(root, page_number)
            if payload.tag == f"{{{OAI_NS}}}error":
                raw_error_code = payload.get("code")
                error_code = (
                    raw_error_code
                    if raw_error_code
                    in {
                        "badArgument",
                        "badResumptionToken",
                        "badVerb",
                        "cannotDisseminateFormat",
                        "idDoesNotExist",
                        "noMetadataFormats",
                        "noRecordsMatch",
                        "noSetHierarchy",
                    }
                    else "upstream_error"
                )

                if error_code == "noRecordsMatch" and page_number == 1:
                    active_budget.source_cursor = _source_response_date(root)
                    return
                if error_code == "badResumptionToken" and page_number > 1:
                    raise OAIContinuationError(
                        error_code,
                        f"OAI endpoint reported {error_code} on page {page_number}",
                    )
                if error_code == "noRecordsMatch":
                    raise OAIProtocolError(
                        "malformed_response",
                        f"Unexpected noRecordsMatch on page {page_number}",
                    )

                raise OAIProtocolError(
                    error_code,
                    f"OAI endpoint reported {error_code} on page {page_number}",
                )

            next_token = _resumption_token(payload, page_number)

            if next_token is not None:
                if len(next_token) > _OAI_MAX_RESUMPTION_TOKEN_CHARS:
                    raise OAIProtocolError(
                        "resource_limit",
                        "OAI resumption token exceeds the length limit",
                    )

                if next_token in seen_tokens:
                    raise OAIProtocolError(
                        "pagination_loop",
                        f"Repeated resumption token on page {page_number}",
                    )

                seen_tokens.add(next_token)

            if page_number == 1:
                active_budget.source_cursor = _source_response_date(root)

            records = payload.findall(f"{{{OAI_NS}}}record")
            for record in records:
                active_budget.consume_record(record)
            if records:
                del record

            yield from records

            # Drop our page references without mutating elements retained by a caller.
            del records, payload, root, body

            if next_token is None:
                return

            request_params = {
                "verb": "ListRecords",
                "resumptionToken": next_token,
            }
        raise OAIProtocolError(
            "pagination_loop",
            f"OAI harvest exceeded {max_pages} pages; possible upstream pagination loop",
        )
    finally:
        session.close()


def _since_boundary(since: str) -> datetime:
    """Parse the inclusive local cutoff once; treat a naive boundary as UTC."""
    try:
        boundary = datetime.fromisoformat(since)
    except ValueError as exc:
        raise OAIProtocolError(
            "malformed_request",
            "Incremental boundary is not a valid ISO date",
        ) from exc

    return boundary.replace(tzinfo=UTC) if boundary.tzinfo is None else boundary.astimezone(UTC)


def _record_is_since(record: etree._Element, boundary: datetime) -> bool:
    """Apply the fallback cutoff before identity classification or result accounting."""
    raw_datestamp = _first_text(
        record,
        "./oai:header/oai:datestamp",
        _BASE_CMDI_NAMESPACES,
    )
    datestamp = _parse_oai_datestamp(raw_datestamp)
    if datestamp is None:
        raise OAIProtocolError(
            "malformed_record",
            "Fallback record has no valid OAI datestamp",
        )
    return datestamp.astimezone(UTC) >= boundary


def _parse_oai_datestamp(raw: str | None) -> datetime | None:
    """Parse an ISO date/time; assign UTC only when naive and preserve supplied offsets.

    Return None for absent/blank/invalid input, logging invalid values.
    """
    if not raw or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except ValueError:
        logger.warning("Unrecognized OAI datestamp from upstream: %s", raw[:40])
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _record_identifier(record_xml: etree._Element) -> str:
    """Return the trimmed identifier from exactly one header/identifier;
    otherwise raise OAIProtocolError."""
    headers = record_xml.findall(f"{{{OAI_NS}}}header")
    if len(headers) != 1 or len(headers[0].findall(f"{{{OAI_NS}}}identifier")) != 1:
        raise OAIProtocolError(
            "malformed_record",
            "OAI record must have exactly one identifier",
        )
    identifier = _first_text(
        record_xml,
        "./oai:header/oai:identifier",
        _BASE_CMDI_NAMESPACES,
    )
    if identifier is None:
        raise OAIProtocolError(
            "malformed_record",
            "OAI record has no usable identifier",
        )
    return identifier


def _parse_supported_cmdi_profile(record_xml: etree._Element) -> dict[str, Any]:
    """Return validated metadata for the supported CMDI profile.

    Require one Dataset and nonblank titles with distinct language tags;
    use the first validated dataset title, English project title/language/resource-type labels,
    sorted unique facets, and ordered authors/institutions. Unsafe URLs
    become None; malformed proxies are logged and skipped. Invalid metadata
    raises OAIProtocolError or pydantic.ValidationError; project titles retain a
    4096-character CMDI cap.
    """
    ns = _CMDI_NAMESPACES
    datasets = record_xml.xpath(".//cmdp:Dataset", namespaces=ns)
    if not isinstance(datasets, list) or len(datasets) != 1:
        raise OAIProtocolError("malformed_record", "Expected exactly one CMDI Dataset")

    titles = record_xml.xpath(
        ".//cmdp:Dataset/cmdp:Overview/cmdp:Dataset_title",
        namespaces=ns,
    )
    if not isinstance(titles, list) or not titles:
        raise OAIProtocolError(
            "malformed_record",
            "Missing required CMDI dataset title",
        )

    title_nodes = [node for node in titles if isinstance(node, etree._Element)]
    if len(title_nodes) != len(titles):
        raise OAIProtocolError(
            "malformed_record",
            "Invalid CMDI dataset title element",
        )

    languages = [node.get("{http://www.w3.org/XML/1998/namespace}lang", "") for node in title_nodes]
    if len(languages) != len(set(languages)) or any(
        not (node.text or "").strip() for node in title_nodes
    ):
        raise OAIProtocolError(
            "malformed_record",
            "Blank or duplicate CMDI dataset title",
        )

    def _get_text(xpath: str) -> str | None:
        """Return the first matching element's trimmed direct text, or None."""
        return _first_text(record_xml, xpath, ns)

    def _get_list(xpath: str) -> list[str]:
        """Return sorted unique nonblank direct texts from matching elements."""
        nodes = record_xml.xpath(xpath, namespaces=ns)
        if not isinstance(nodes, list):
            return []
        return sorted(
            {
                text
                for node in nodes
                if isinstance(node, etree._Element) and node.text and (text := node.text.strip())
            }
        )

    def _get_list_ordered(xpath: str) -> list[str]:
        """Return nonblank matching direct texts in document order, retaining duplicates."""
        nodes = record_xml.xpath(xpath, namespaces=ns)
        if not isinstance(nodes, list):
            return []
        return [
            text
            for node in nodes
            if isinstance(node, etree._Element) and node.text and (text := node.text.strip())
        ]

    def _safe_url(url: str | None) -> str | None:
        """Return a trimmed safe HTTP(S) URL; log rejected nonempty values and return None."""
        if url and is_safe_http_url(url):
            return url.strip()
        if url:
            logger.warning(
                "Rejected unsafe URL from upstream data",
                extra={"event_type": "upstream_resource_rejected", "reason": "unsafe_url"},
            )
        return None

    def _get_url(xpath: str) -> str | None:
        """Return the first matching text as a safe HTTP(S) URL, or None."""
        return _safe_url(_get_text(xpath))

    resource_proxies = []
    proxy_nodes = record_xml.xpath(".//cmd:ResourceProxy", namespaces=ns)
    if isinstance(proxy_nodes, list):
        for proxy in proxy_nodes:
            if not isinstance(proxy, etree._Element):
                continue
            try:
                res_type_nodes = proxy.xpath(".//cmd:ResourceType", namespaces=ns)
                res_ref_nodes = proxy.xpath(".//cmd:ResourceRef", namespaces=ns)

                if (
                    not isinstance(res_type_nodes, list)
                    or not res_type_nodes
                    or not isinstance(res_ref_nodes, list)
                    or not res_ref_nodes
                ):
                    logger.warning(
                        "Skipping malformed ResourceProxy (missing type or ref) in record."
                    )
                    continue

                type_node = res_type_nodes[0]
                ref_node = res_ref_nodes[0]
                if not isinstance(type_node, etree._Element) or not isinstance(
                    ref_node, etree._Element
                ):
                    logger.warning("Skipping ResourceProxy with non-element type/ref.")
                    continue

                resource_proxies.append(
                    {
                        "type": (type_node.text or "").strip(),
                        "ref": _safe_url(ref_node.text),
                    }
                )
            except Exception as exc:
                logger.warning("Failed to parse ResourceProxy: %s", exc)
                continue

    record: dict[str, Any] = {
        "uuid": _record_identifier(record_xml),
        "title": (title_nodes[0].text or "").strip(),
        "project_title": _get_text(".//cmdp:Project_title[@xml:lang='en']"),
        "description": _get_text(".//cmdp:Dataset_description"),
        "resource_description": _get_text(".//cmdp:Resource_description"),
        "languages": _get_list(".//cmdp:Language_name[@xml:lang='en']"),
        "project_description": _get_text(".//cmdp:Abstract"),
        "authors": _get_list_ordered(".//cmdp:Author"),
        "keywords": sorted(
            {
                keyword.strip()
                for text in _get_list_ordered(".//cmdp:Keywords")
                for keyword in text.split(",")
                if keyword.strip()
            }
        ),
        "resource_proxies": resource_proxies,
        "license_val": _get_text(".//cmdp:License/cmdp:License"),
        "license_url": _get_url(".//cmdp:LicenseURL"),
        "version": _get_text(".//cmdp:Dataset_version"),
        "doi": _get_text(".//cmdp:DOI"),
        "resource_type": _get_text(".//cmdp:Resource_type[@xml:lang='en']"),
        "institutions": _get_list_ordered(".//cmdp:Institution"),
        "main_disciplines": _get_list(".//cmdp:Main_discipline"),
        "bibliographical_citation": _get_text(".//cmdp:Bibliographical_citation"),
        "upstream_modified_at": _parse_oai_datestamp(_get_text("./oai:header/oai:datestamp")),
    }
    _CmdiParsedRecord.model_validate(record)
    return record


_CMDI_PARSERS: dict[str, _CMDIParser] = {
    _EXPECTED_CMDI_PROFILE: _parse_supported_cmdi_profile,
}


def _parse_cmdi_to_dict(record_xml: etree._Element) -> dict[str, Any]:
    """Dispatch by detected CMDI profile;
    unsupported profiles raise OAIProtocolError and parser errors propagate."""
    profile = _detect_cmdi_profile(record_xml)
    parser = _CMDI_PARSERS.get(profile) if profile is not None else None

    if parser is None:
        raise OAIProtocolError(
            "unsupported_metadata_profile",
            f"Unsupported or undetectable CMDI profile: {profile!r}",
        )

    return parser(record_xml)


def _record_institutions(record_xml: etree._Element) -> list[str]:
    """Return ordered institution texts from one supported Dataset.

    Unsupported profiles or Dataset cardinality raise OAIProtocolError;
    missing, blank, nonprintable, or nested institution content yields [].
    """
    if _detect_cmdi_profile(record_xml) != _EXPECTED_CMDI_PROFILE:
        raise OAIProtocolError(
            "unsupported_metadata_profile",
            "Unsupported or undetectable CMDI profile",
        )

    datasets = record_xml.xpath(".//cmdp:Dataset", namespaces=_CMDI_NAMESPACES)
    if not isinstance(datasets, list) or len(datasets) != 1:
        raise OAIProtocolError("malformed_record", "Expected exactly one CMDI Dataset")

    nodes = record_xml.xpath(".//cmdp:Institution", namespaces=_CMDI_NAMESPACES)
    if not isinstance(nodes, list):
        return []

    institutions = []
    for node in nodes:
        if not isinstance(node, etree._Element) or len(node):
            return []
        value = (node.text or "").strip()
        if not value or not value.isprintable():
            return []
        institutions.append(value)

    return institutions


def _metadata_diagnostic(exc: OAIProtocolError | ValueError) -> str:
    """Return a parser diagnostic capped at 500 characters.

    Protocol diagnostics include the supplied code/message; validation
    diagnostics include at most ten locations/types, excluding input values.
    """
    if isinstance(exc, OAIProtocolError):
        return " ".join(f"{exc.error_code}: {exc.message}".split())[:500]
    if isinstance(exc, ValidationError):
        details = [
            f"{'.'.join(str(part) for part in error['loc'])}: {error['type']}"
            for error in exc.errors(
                include_input=False,
                include_context=False,
                include_url=False,
            )[:10]
        ]
        return ("record_validation: " + "; ".join(details))[:500]
    return "invalid_record_value: record metadata failed validation"


def _encode_worker_harvest_result(result: HarvestResult) -> bytes:
    """Validate and encode the shared wire representation before OAI size checks."""
    return harvest_result_to_json(result)


def encode_harvest_result(result: HarvestResult) -> bytes:
    """Validate and return compact UTF-8 JSON; raise OAIProtocolError above 16 MiB.

    Record/schema and serialization errors propagate.
    """
    payload = _encode_worker_harvest_result(result)
    _validate_worker_payload_size(payload)
    return payload


def _classify_oai_record(
    record_xml: etree._Element,
    result: HarvestResult,
    seen_identifiers: set[str],
    institution_filter: str,
    budget: _HarvestBudget,
) -> None:
    """Mutate result, seen IDs and budget using exact identity and casefolded institution
    substrings.

    Deleted records become withdrawals; missing/unusable metadata is quarantined,
    valid matching metadata retained and other institutions marked nonmatching.
    Duplicate/missing identities and resource failures abort with OAIProtocolError.
    """
    identifier = _record_identifier(record_xml)
    if identifier in seen_identifiers:
        raise OAIProtocolError("duplicate_identifier", "Harvest repeated a record identifier")
    seen_identifiers.add(identifier)

    header = record_xml.find(f"{{{OAI_NS}}}header")
    if header is not None and header.get("status") == "deleted":
        budget.consume_result({"deleted_uuid": identifier})
        result.deleted_uuids.add(identifier)
        return

    try:
        institutions = _record_institutions(record_xml)
        matches = any(
            institution_filter.casefold() in institution.casefold() for institution in institutions
        )
        parsed = _parse_cmdi_to_dict(record_xml) if matches else None
    except (OAIProtocolError, ValueError) as exc:
        reason = _metadata_diagnostic(exc)
        logger.warning("OAI record %s rejected: %s", identifier, reason)
        budget.consume_result({"uncertain_uuid": identifier, "reason": reason})
        result.uncertain_records[identifier] = reason
        return

    if not institutions:
        reason = "missing or unusable institution metadata"
        budget.consume_result({"uncertain_uuid": identifier, "reason": reason})
        result.uncertain_records[identifier] = reason
        return

    if parsed is not None:
        parsed["uuid"] = identifier
        budget.consume_result(parsed)
        result.matching_records.append(parsed)
    else:
        budget.consume_result({"nonmatching_uuid": identifier})
        result.nonmatching_uuids.add(identifier)


def _collect_oai_attempt(
    oai_url: str,
    since: str | None,
    institution_filter: str,
    *,
    max_pages: int,
    budget: _HarvestBudget,
    local_since: str | None = None,
) -> HarvestResult:
    """Stream one attempt into native records, retaining no completed XML pages.

    Defer classification failures until transport completes: a later rejected
    token must still discard this attempt and permit the existing fallback.
    Drop failed output before propagating so a retry cannot retain it through
    an exception traceback. Always close the HTTP generator.
    """
    budget.begin_attempt()
    boundary = _since_boundary(local_since) if local_since is not None else None
    result = HarvestResult()
    seen_identifiers: set[str] = set()
    failure: OAIProtocolError | ValueError | None = None

    try:
        with contextlib.closing(
            _oai_list_records(oai_url, "oai_cmdi12", since, max_pages=max_pages, budget=budget)
        ) as records:
            for record_xml in records:
                try:
                    if failure is not None:
                        continue
                    budget.check_deadline()
                    if boundary is not None and not _record_is_since(record_xml, boundary):
                        continue
                    _classify_oai_record(
                        record_xml, result, seen_identifiers, institution_filter, budget
                    )
                except (OAIProtocolError, ValueError) as exc:
                    # Tracebacks and chained exceptions can retain completed XML pages.
                    failure = exc.with_traceback(None)
                    failure.__cause__ = None
                    failure.__context__ = None
                    result = HarvestResult()
                    seen_identifiers.clear()
                finally:
                    del record_xml
    except BaseException:
        # In particular, a continuation exception is live while fetch_updates retries.
        result.matching_records.clear()
        result.deleted_uuids.clear()
        result.nonmatching_uuids.clear()
        result.uncertain_records.clear()
        seen_identifiers.clear()
        raise

    if failure is not None:
        raise failure
    budget.check_deadline()
    result.source_cursor = budget.source_cursor
    result.validate()
    return result


def fetch_updates(
    oai_url: str,
    since: str,
    institution_filter: str,
    *,
    max_pages: int = OAI_DEFAULT_MAX_PAGES,
) -> HarvestResult:
    """Stream and classify a complete harvest before returning it for database writes.

    A rejected continuation triggers one fresh attempt without from, applying
    the inclusive since cutoff locally. Transport bytes, examined records and
    the deadline stay cumulative; retained output and cursor are per attempt.
    Both attempts use the same positive max_pages cap (default 500).

    Metadata validation failures are quarantined. Identity, protocol, resource,
    HTTP and XML failures abort; no partial HarvestResult is returned.
    Direct calls check deadlines cooperatively; the isolated wrapper supplies
    the terminating watchdog.
    """
    _validate_max_pages(max_pages)
    budget = _HarvestBudget.start()
    try:
        result = _collect_oai_attempt(
            oai_url, since, institution_filter, max_pages=max_pages, budget=budget
        )
    except OAIContinuationError:
        logger.warning(
            "OAI continuation token rejected; "
            "retrying unbounded harvest with local datestamp filtering",
            extra={"event_type": "oai_continuation_fallback", "since": since},
        )
        result = _collect_oai_attempt(
            oai_url,
            None,
            institution_filter,
            max_pages=max_pages,
            budget=budget,
            local_since=since,
        )

    logger.info(
        "OAI-PMH harvest: %d matching, %d deleted, %d nonmatching, %d uncertain",
        len(result.matching_records),
        len(result.deleted_uuids),
        len(result.nonmatching_uuids),
        len(result.uncertain_records),
    )
    return result


def _worker_error_bytes(exc: BaseException) -> bytes:
    """Encode exception type, protocol code,
    and a whitespace-flattened 500-character message as ASCII JSON.
    """
    error_code = exc.error_code if isinstance(exc, OAIProtocolError) else "harvest_worker"
    message = " ".join(str(exc).split())[:_OAI_WORKER_ERROR_CHARS]
    return json.dumps(
        {
            "error_code": error_code,
            "exception_type": type(exc).__name__,
            "message": message,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_worker_harvest_result(payload: bytes) -> HarvestResult:
    """Decode and validate a worker result without retaining the serialized bytes.

    Decoding and schema errors propagate; the transport enforces the byte limit.
    """
    return harvest_result_from_document(json.loads(payload.decode("utf-8")))


class _HarvestLogContext(logging.Filter):
    """Attach the configured source identity and child PID to every worker record."""

    def __init__(self, source: str) -> None:
        """Capture process identity once in the child."""
        super().__init__()
        self.source = source
        self.worker_pid = os.getpid()

    def filter(self, record: logging.LogRecord) -> bool:
        """Keep context without rendering upstream arguments or exception values."""
        record.source = self.source
        record.worker_pid = self.worker_pid
        if record.args or not isinstance(record.msg, str):
            record.msg = "Worker diagnostic (upstream details omitted)"
            record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _validate_worker_logging(*, source: str, log_level: str, log_format: str) -> None:
    """Reject invalid context before process setup or logging's fallback defaults."""
    if not isinstance(source, str) or SOURCE_NAME_PATTERN.fullmatch(source) is None:
        raise ValueError("OAI worker source must be a configured source name")
    if not isinstance(log_level, str) or log_level not in logging.getLevelNamesMapping():
        raise ValueError("OAI worker log_level must be a supported uppercase logging level")
    if not isinstance(log_format, str) or log_format not in {"json", "text"}:
        raise ValueError("OAI worker log_format must be json or text")


class _WorkerJSONFormatter(logging.Formatter):
    """Settings-free operational context; never expand exception objects or extras."""

    def format(self, record: logging.LogRecord) -> str:
        """Render message, level, logger and source/PID context as ASCII JSON."""
        return json.dumps(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "source": record.__dict__.get("source"),
                "worker_pid": record.__dict__.get("worker_pid"),
            },
            ensure_ascii=True,
        )


class _WorkerTextFormatter(logging.Formatter):
    """Keep settings-free worker text, context and tracebacks on one escaped line."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the record and escape control characters onto one line."""
        return escape_log_controls(super().format(record))


def _configure_worker_logging(*, source: str, log_level: str, log_format: str) -> None:
    """Initialize worker-owned logging without importing application settings."""
    _validate_worker_logging(source=source, log_level=log_level, log_format=log_format)
    root = logging.getLogger()
    context = _HarvestLogContext(source)
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(context)
    handler.setFormatter(_WorkerJSONFormatter())
    if log_format == "text":
        handler.setFormatter(
            _WorkerTextFormatter(
                "%(levelname)s | %(name)s | source=%(source)s "
                "worker_pid=%(worker_pid)s | %(message)s"
            )
        )
    root.handlers[:] = [handler]
    root.setLevel(log_level)
    audit = logging.getLogger("audit")
    audit_handler = logging.StreamHandler(sys.stdout)
    audit_handler.addFilter(context)
    audit_handler.setFormatter(_WorkerJSONFormatter())
    audit.handlers[:] = [audit_handler]
    audit.setLevel(logging.INFO)
    audit.propagate = False


def _harvest_worker(
    connection: Connection,
    oai_url: str,
    since: str,
    institution_filter: str,
    max_pages: int,
    *,
    source: str,
    log_level: str,
    log_format: str,
) -> None:
    """Harvest and send one success/error frame, then close the pipe.

    Configure logging before harvesting. Catch BaseException from setup,
    harvesting or encoding and send a bounded diagnostic when the parent pipe
    remains writable.
    """
    try:
        _configure_worker_logging(source=source, log_level=log_level, log_format=log_format)
        result = fetch_updates(oai_url, since, institution_filter, max_pages=max_pages)
        payload = encode_harvest_result(result)
        connection.send_bytes(_WORKER_SUCCESS + payload)
    except BaseException as exc:
        with contextlib.suppress(BrokenPipeError, EOFError, OSError):
            connection.send_bytes(_WORKER_ERROR + _worker_error_bytes(exc))
    finally:
        connection.close()


def _validate_worker_payload_size(payload: bytes) -> None:
    """Raise OAIProtocolError(resource_limit) when payload exceeds 16 MiB."""
    if len(payload) > _OAI_MAX_RESULT_BYTES:
        raise OAIProtocolError(
            "resource_limit",
            "Serialized OAI harvest exceeds the retained-result byte limit",
        )


def _stop_harvest_process(process: Any) -> None:
    """Join the child, then terminate and kill if needed, waiting one second at each stage.

    Close its process handle; reject abnormal exits, including forced termination.
    """
    process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.terminate()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.kill()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        raise OAIProtocolError(
            "resource_limit",
            "OAI harvest worker could not be terminated after SIGKILL",
        )
    exitcode = process.exitcode
    process.close()
    if exitcode != 0:
        raise OAIProtocolError(
            "harvest_worker",
            "OAI harvest worker did not exit cleanly after sending its result",
        )


def _abort_harvest_process(process: Any) -> None:
    """Terminate the child immediately, then kill if needed, with one-second waits.

    Close its process handle; raise OAIProtocolError if it survives SIGKILL.
    """
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.terminate()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        with contextlib.suppress(OSError):
            process.kill()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        raise OAIProtocolError(
            "resource_limit",
            "OAI harvest worker could not be terminated after SIGKILL",
        )
    process.close()


def _cleanup_harvest_process(
    process: Any,
    *,
    completed: bool,
    primary_exception: BaseException | None,
) -> None:
    """Reap the child while retaining any exception already in flight."""
    try:
        if completed:
            _stop_harvest_process(process)
        else:
            _abort_harvest_process(process)
    except Exception as cleanup_error:
        if primary_exception is None:
            raise
        primary_exception.add_note(str(cleanup_error))
        logger.critical(
            "OAI worker cleanup failed while preserving the active harvest error: %s",
            cleanup_error,
        )


@dataclass(slots=True)
class _WorkerReceiveState:
    """Publish a receiver thread's message/error before setting done; read after done is set."""

    done: threading.Event = field(default_factory=threading.Event)
    message: bytes | None = None
    error: BaseException | None = None
    receiver: threading.Thread | None = field(default=None, repr=False)


def _receive_worker_message(
    connection: Connection,
    state: _WorkerReceiveState,
) -> None:
    """Receive one frame capped at 16 MiB + 4 KiB into state and always signal done.

    Store EOFError/OSError instead of raising them; run in the receiver thread.
    """
    try:
        state.message = connection.recv_bytes(
            _OAI_MAX_RESULT_BYTES + _OAI_WORKER_WIRE_OVERHEAD_BYTES
        )
    except (EOFError, OSError) as exc:
        state.error = exc
    finally:
        state.done.set()


def _check_parent_deadline(deadline: float) -> None:
    """Raise OAIProtocolError(resource_limit) when an absolute monotonic deadline has elapsed."""
    if time.monotonic() >= deadline:
        raise OAIProtocolError(
            "resource_limit",
            "OAI harvest exceeded its hard wall-clock deadline",
        )


def _wait_for_worker_message(
    connection: Connection,
    state: _WorkerReceiveState,
    *,
    deadline: float,
    cancel_event: threading.Event | None,
) -> None:
    """Wait for a complete frame, retaining the receiver for cleanup on failure."""
    if not wait_for_harvest_step(connection.poll, deadline=deadline, cancel_event=cancel_event):
        raise OAIProtocolError(
            "resource_limit", "OAI harvest exceeded its hard wall-clock deadline"
        )
    state.receiver = threading.Thread(
        target=_receive_worker_message,
        args=(connection, state),
        name="oai-harvest-result-receiver",
        daemon=True,
    )
    state.receiver.start()
    if not wait_for_harvest_step(state.done.wait, deadline=deadline, cancel_event=cancel_event):
        raise OAIProtocolError(
            "resource_limit", "OAI harvest exceeded its hard wall-clock deadline"
        )
    if state.error is not None:
        raise OAIProtocolError(
            "harvest_worker", "OAI harvest worker exited without a valid bounded result"
        ) from state.error


def _fetch_updates_local(
    oai_url: str,
    since: str,
    institution_filter: str,
    *,
    source: str,
    log_level: str,
    log_format: str,
    max_pages: int = OAI_DEFAULT_MAX_PAGES,
    cancel_event: threading.Event | None = None,
) -> HarvestResult:
    """Run fetch_updates in a spawned process and return its validated result.

    Pass max_pages explicitly into the worker; invalid caps raise ValueError
    before process setup. Direct calls default to 500. Logging context is
    required and validated before creating pipes; the child installs its own
    handlers with the supplied level/format and source/PID context.
    A 240-second parent watchdog bounds waiting for the child/result; cleanup
    and synchronous parent decoding can extend elapsed time, with deadline checks before
    return. Worker/protocol/decoding failures become OAIProtocolError;
    process-start failures propagate. Always clean up pipes and started
    children. Call from an import-safe, non-daemon process; this call blocks.
    """
    _validate_max_pages(max_pages)
    _validate_worker_logging(source=source, log_level=log_level, log_format=log_format)
    check_harvest_cancellation(cancel_event)
    context = multiprocessing.get_context("spawn")
    receive_connection, send_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_harvest_worker,
        args=(send_connection, oai_url, since, institution_filter, max_pages),
        kwargs={"source": source, "log_level": log_level, "log_format": log_format},
        name="oralhistarchiv-oai-harvest",
        daemon=True,
    )
    started = False
    receive_state = _WorkerReceiveState()
    deadline = time.monotonic() + _OAI_TOTAL_TIMEOUT_SECONDS
    primary_exception: BaseException | None = None

    try:
        process.start()
        started = True
        send_connection.close()

        _wait_for_worker_message(
            receive_connection,
            receive_state,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except BaseException as exc:
        primary_exception = exc
        raise
    finally:
        try:
            if started:
                _cleanup_harvest_process(
                    process,
                    completed=(
                        primary_exception is None
                        and receive_state.done.is_set()
                        and receive_state.message is not None
                    ),
                    primary_exception=primary_exception,
                )
        finally:
            receive_connection.close()
            with contextlib.suppress(OSError):
                send_connection.close()
            if receive_state.receiver is not None:
                receive_state.receiver.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)

    return _decode_isolated_result(receive_state.message, deadline, cancel_event)


def _decode_isolated_result(
    message: bytes | None, deadline: float, cancel_event: threading.Event | None
) -> HarvestResult:
    """Validate a success/error frame under the monotonic deadline; return a reconstructed
    harvest.

    Recognized malformed frames/results, worker diagnostics and expiry raise
    OAIProtocolError; resource exhaustion can propagate. Check cooperative
    cancellation before returning a successful result.
    """
    if not message:
        raise OAIProtocolError(
            "harvest_worker",
            "OAI harvest worker returned no result",
        )

    _check_parent_deadline(deadline)
    kind, payload = message[:1], message[1:]

    if kind == _WORKER_ERROR:
        try:
            failure = json.loads(payload.decode("utf-8"))
            error_code = str(failure["error_code"])
            exception_type = str(failure["exception_type"])
            error_message = str(failure["message"])
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise OAIProtocolError(
                "harvest_worker",
                "OAI harvest worker returned a malformed error",
            ) from exc

        _check_parent_deadline(deadline)
        raise OAIProtocolError(
            error_code,
            f"Harvest worker {exception_type}: {error_message}",
        )

    if kind != _WORKER_SUCCESS:
        raise OAIProtocolError(
            "harvest_worker",
            "OAI harvest worker returned an unknown message type",
        )

    try:
        result = _decode_worker_harvest_result(payload)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise OAIProtocolError(
            "harvest_worker",
            "OAI harvest worker returned a malformed result",
        ) from exc

    _check_parent_deadline(deadline)
    check_harvest_cancellation(cancel_event)
    return result


def fetch_updates_isolated(
    oai_url: str,
    since: str,
    institution_filter: str,
    *,
    source: str,
    log_level: str,
    log_format: str,
    max_pages: int = OAI_DEFAULT_MAX_PAGES,
    cancel_event: threading.Event | None = None,
) -> HarvestResult:
    """Return a complete OAI harvest through service mode or explicitly selected dev local mode.

    since is an inclusive ISO date/time; institution_filter matches case-insensitive
    substrings. A rejected continuation retries once without from, filtering locally.
    Invalid page/logging arguments raise ValueError; worker/protocol/deadline failures
    raise OAIProtocolError and cancellation raises HarvestCancelled. Invalid parser
    mode selection raises ParserServiceError; local process-start errors propagate.
    Local mode blocks
    and needs an import-safe non-daemon caller; cleanup/parent decoding may outlast
    the 240-second deadline. Service workers use WARNING/json rather than supplied
    log_level/log_format; those are validated in both modes.
    """
    _validate_max_pages(max_pages)
    _validate_worker_logging(source=source, log_level=log_level, log_format=log_format)
    check_harvest_cancellation(cancel_event)
    if not use_parser_service():
        return _fetch_updates_local(
            oai_url,
            since,
            institution_filter,
            source=source,
            log_level=log_level,
            log_format=log_format,
            max_pages=max_pages,
            cancel_event=cancel_event,
        )
    deadline = time.monotonic() + _OAI_TOTAL_TIMEOUT_SECONDS
    try:
        message = request_parser(
            {
                "operation": "oai",
                "url": oai_url,
                "since": since,
                "institution": institution_filter,
                "source": source,
                "max_pages": max_pages,
            },
            maximum=_OAI_MAX_RESULT_BYTES + _OAI_WORKER_WIRE_OVERHEAD_BYTES,
            deadline=deadline,
            cancel_event=cancel_event,
        )
    except ParserServiceError:
        raise OAIProtocolError("harvest_worker", "Isolated parser service failed") from None
    return _decode_isolated_result(message, deadline, cancel_event)
