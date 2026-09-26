"""Synchronous SWISSUbase OAI-PMH harvesting and CMDI parsing; no database writes.

Use fetch_updates_isolated for a terminating child-process watchdog.
Limits: OAI_MAX_PAGES, 4 MiB/page, 32 MiB received, 1 MiB/record,
20,000 records, 16 MiB retained result, and a 240-second deadline.
HTTP uses 10-second connect/read timeouts, up to three retries, no
redirects, and identity encoding. XML entities and network loading are disabled.
"""

import contextlib
import json
import logging
import multiprocessing
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from multiprocessing.connection import Connection
from typing import Any

import requests
from lxml import etree
from pydantic import ValidationError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import settings

from ..url_safety import is_safe_http_url
from .parsed_record import validate_parsed_record

logger = logging.getLogger(__name__)

OAI_REQUEST_TIMEOUT = (10, 10)
OAI_NS = "http://www.openarchives.org/OAI/2.0/"

_OAI_CHUNK_BYTES = 64 * 1024
_OAI_MAX_PAGE_BYTES = 4 * 1024 * 1024
_OAI_MAX_HARVEST_BYTES = 32 * 1024 * 1024
_OAI_MAX_RECORD_BYTES = 1024 * 1024
_OAI_MAX_RECORDS = 20_000
_OAI_MAX_RESULT_BYTES = 16 * 1024 * 1024
_OAI_MAX_RESUMPTION_TOKEN_CHARS = 4096
_OAI_TOTAL_TIMEOUT_SECONDS = 240.0
_OAI_WORKER_SHUTDOWN_SECONDS = 2.0
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


class OAIProtocolError(Exception):
    """A structured OAI-PMH protocol error."""

    def __init__(self, error_code: str, message: str) -> None:
        """Store a protocol code and diagnostic and include both in the exception message."""
        self.error_code = error_code
        self.message = message
        super().__init__(f"OAI-PMH [{error_code}]: {message}")


class OAIContinuationError(OAIProtocolError):
    """The endpoint rejected a continuation token after page one."""


@dataclass(slots=True)
class HarvestResult:
    """Mutable, disjoint harvest classifications plus an aware upstream response timestamp.

    Matching records satisfy ParsedRecord; deleted/nonmatching IDs authorize
    withdrawal, while uncertain IDs retain diagnostic reasons. Construction
    does not validate. source_cursor=None is only an unfinished state.
    After mutating a decoded result, discard cached worker bytes before
    serialization; no synchronization protects concurrent access.
    """

    matching_records: list[dict[str, Any]] = field(default_factory=list)
    deleted_uuids: set[str] = field(default_factory=set)
    nonmatching_uuids: set[str] = field(default_factory=set)
    uncertain_records: dict[str, str] = field(default_factory=dict)
    source_cursor: datetime | None = None
    _serialized_worker_payload: bytes | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def take_serialized_worker_payload(self) -> bytes | None:
        """Return and clear the cached worker payload, or None if absent."""
        payload = self._serialized_worker_payload
        self._serialized_worker_payload = None
        return payload

    def discard_serialized_worker_payload(self) -> None:
        """Clear cached bytes so later serialization uses current record state."""
        self._serialized_worker_payload = None

    def _attach_serialized_worker_payload(self, payload: bytes) -> None:
        """Cache validated worker bytes; raise RuntimeError if bytes are already attached."""
        if self._serialized_worker_payload is not None:
            raise RuntimeError("serialized worker payload is already attached")
        self._serialized_worker_payload = payload

    def validate(self) -> datetime:
        """Validate disjoint normalized identities and parsed records; return the source cursor.

        Raise ValueError for a missing/naive cursor or blank, untrimmed, repeated
        identities; ParsedRecord violations raise pydantic.ValidationError.
        Does not validate uncertain-record reason values or normalize the cursor.
        """
        if self.source_cursor is None or self.source_cursor.utcoffset() is None:
            raise ValueError("harvest source_cursor must be a timezone-aware source timestamp")

        seen: set[str] = set()
        identifiers = [record.get("uuid") for record in self.matching_records]
        identifiers.extend(self.deleted_uuids)
        identifiers.extend(self.nonmatching_uuids)
        identifiers.extend(self.uncertain_records)

        for identifier in identifiers:
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError("harvest identities must be nonempty strings")
            if identifier != identifier.strip():
                raise ValueError("harvest identities must already be whitespace-normalized")
            if identifier in seen:
                raise ValueError("harvest contains repeated or conflicting identities")
            seen.add(identifier)

        for record in self.matching_records:
            validate_parsed_record(record)

        return self.source_cursor


def _make_safe_parser() -> etree.XMLParser:
    """Return a fresh XML parser with entity resolution, DTD loading,
    and network access disabled.
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
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
    """Return trimmed direct text of the first XPath element,
    or None for no usable first element.
    """
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
    def start(cls) -> "_HarvestBudget":
        """Create empty counters with a monotonic deadline 240 seconds from now."""
        return cls(deadline=time.monotonic() + _OAI_TOTAL_TIMEOUT_SECONDS)

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
    """Parse the sole direct responseDate as YYYY-MM-DDTHH:MM:SSZ in UTC;
    otherwise raise OAIProtocolError."""
    dates = root.findall(f"{{{OAI_NS}}}responseDate")
    raw_date = dates[0].text if len(dates) == 1 else None
    try:
        return datetime.strptime(raw_date or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise OAIProtocolError(
            "malformed_response",
            "Missing or invalid source responseDate",
        ) from exc


def _oai_list_records(  # noqa: PLR0912
    oai_url: str,
    metadata_prefix: str,
    since: str | None,
    *,
    budget: _HarvestBudget | None = None,
) -> Iterator[etree._Element]:
    """Yield OAI record elements across bounded ListRecords pages, closing the HTTP session on exit.

    since is forwarded as from; None omits it. A supplied budget is updated
    in place, including the first page's responseDate. First-page
    noRecordsMatch is empty success; rejected continuation tokens raise
    OAIContinuationError. Other protocol/limit failures raise OAIProtocolError;
    requests and XML errors propagate. Continuations must include a terminal
    token element; tokens may not repeat or exceed 4,096 characters.
    """
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
        for page_number in range(1, settings.oai_max_pages + 1):
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

            root = etree.fromstring(body, parser=_make_safe_parser())
            if root.tag != f"{{{OAI_NS}}}OAI-PMH":
                raise OAIProtocolError(
                    "malformed_response",
                    f"Expected OAI-PMH response root on page {page_number}",
                )

            error = root.find(f"{{{OAI_NS}}}error")
            if error is not None:
                raw_error_code = error.get("code")
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

            if page_number == 1:
                active_budget.source_cursor = _source_response_date(root)

            list_records = root.find(f"{{{OAI_NS}}}ListRecords")
            if list_records is None:
                raise OAIProtocolError(
                    "malformed_response",
                    f"ListRecords missing on page {page_number}",
                )

            token_element = list_records.find(f"{{{OAI_NS}}}resumptionToken")
            if page_number > 1 and token_element is None:
                raise OAIProtocolError(
                    "malformed_response",
                    "Continuation omitted its terminal resumption token",
                )

            raw_token = token_element.text if token_element is not None else None
            next_token = raw_token.strip() if raw_token and raw_token.strip() else None

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

            records = list_records.findall(f"{{{OAI_NS}}}record")
            for record in records:
                active_budget.consume_record(record)

            yield from records

            if next_token is None:
                return

            request_params = {
                "verb": "ListRecords",
                "resumptionToken": next_token,
            }
        raise OAIProtocolError(
            "pagination_loop",
            f"OAI harvest exceeded {settings.oai_max_pages} pages; "
            "possible upstream pagination loop",
        )
    finally:
        session.close()


def _filter_records_since(
    records: list[etree._Element],
    since: str,
    budget: _HarvestBudget,
) -> list[etree._Element]:
    """Return records with valid OAI datestamps at or after the ISO since boundary.

    Treat naive boundaries as UTC and check budget deadlines. Invalid
    boundaries/datestamps raise OAIProtocolError; preserve input order.
    """
    try:
        boundary = datetime.fromisoformat(since)
    except ValueError as exc:
        raise OAIProtocolError(
            "malformed_request",
            "Incremental boundary is not a valid ISO date",
        ) from exc

    boundary = boundary.replace(tzinfo=UTC) if boundary.tzinfo is None else boundary.astimezone(UTC)

    selected: list[etree._Element] = []

    for record in records:
        budget.check_deadline()

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

        if datestamp.astimezone(UTC) >= boundary:
            selected.append(record)

    return selected


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


def _parse_swissubase_cmdi_profile(record_xml: etree._Element) -> dict[str, Any]:
    """Return validated metadata for the supported CMDI profile.

    Require one Dataset and nonblank titles with distinct language tags;
    use the first title, English project title/language/resource-type labels,
    sorted unique facets, and ordered authors/institutions. Unsafe URLs
    become None; malformed proxies are logged and skipped. Invalid metadata
    raises OAIProtocolError or pydantic.ValidationError.
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
            logger.warning("Rejected unsafe URL from upstream data: %s", url[:80])
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
        "title": _get_text(".//cmdp:Dataset_title"),
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
    validate_parsed_record(record)
    return record


_CMDI_PARSERS: dict[str, _CMDIParser] = {
    _EXPECTED_CMDI_PROFILE: _parse_swissubase_cmdi_profile,
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


def encode_harvest_result(result: HarvestResult) -> bytes:
    """Validate and return compact UTF-8 JSON; raise OAIProtocolError above 16 MiB.

    Record/schema and serialization errors propagate.
    """
    payload = _encode_worker_harvest_result(result)
    _validate_worker_payload_size(payload)
    return payload


def fetch_updates(
    oai_url: str,
    since: str,
    institution_filter: str,
) -> HarvestResult:
    """Fetch and classify a complete harvest from the configured endpoint.

    since is the OAI from boundary; institution_filter matches case-insensitive
    substrings. A rejected continuation triggers one full fetch with local
    inclusive ISO datestamp filtering, sharing the original resource budget.

    Return disjoint matches, withdrawals, nonmatches, and uncertain metadata
    with the completed attempt's first responseDate. Metadata validation
    failures are logged/quarantined; duplicate or unusable identities and
    protocol/resource failures abort. HTTP/XML errors propagate. This direct
    call checks deadlines cooperatively and does not forcibly stop blocked work.
    """
    result = HarvestResult()
    budget = _HarvestBudget.start()
    seen_identifiers: set[str] = set()

    try:
        record_xmls = list(
            _oai_list_records(
                oai_url,
                "oai_cmdi12",
                since,
                budget=budget,
            )
        )
    except OAIContinuationError:
        logger.warning(
            "Source A continuation token rejected; "
            "retrying unbounded harvest with local datestamp filtering",
            extra={
                "event_type": "oai_continuation_fallback",
                "since": since,
            },
        )

        record_xmls = list(
            _oai_list_records(
                oai_url,
                "oai_cmdi12",
                None,  # Omit the OAI "from" argument.
                budget=budget,
            )
        )
        record_xmls = _filter_records_since(
            record_xmls,
            since,
            budget,
        )

    # Classify exactly the successfully completed attempt. Do not make
    # another request here.
    for record_xml in record_xmls:
        identifier = _record_identifier(record_xml)

        if identifier in seen_identifiers:
            raise OAIProtocolError(
                "duplicate_identifier",
                "Harvest repeated a record identifier",
            )
        seen_identifiers.add(identifier)

        header = record_xml.find(f"{{{OAI_NS}}}header")

        if header is not None and header.get("status") == "deleted":
            budget.consume_result({"deleted_uuid": identifier})
            result.deleted_uuids.add(identifier)
            continue

        try:
            institutions = _record_institutions(record_xml)
            matches = any(
                institution_filter.casefold() in institution.casefold()
                for institution in institutions
            )
            parsed = _parse_cmdi_to_dict(record_xml) if matches else None
        except (OAIProtocolError, ValueError) as exc:
            reason = _metadata_diagnostic(exc)
            logger.warning("OAI record %s rejected: %s", identifier, reason)
            budget.consume_result(
                {
                    "uncertain_uuid": identifier,
                    "reason": reason,
                }
            )
            result.uncertain_records[identifier] = reason
            continue

        if not institutions:
            reason = "missing or unusable institution metadata"
            budget.consume_result(
                {
                    "uncertain_uuid": identifier,
                    "reason": reason,
                }
            )
            result.uncertain_records[identifier] = reason
            continue

        if parsed is not None:
            parsed["uuid"] = identifier
            budget.consume_result(parsed)
            result.matching_records.append(parsed)
        else:
            budget.consume_result({"nonmatching_uuid": identifier})
            result.nonmatching_uuids.add(identifier)

    budget.check_deadline()
    result.source_cursor = budget.source_cursor
    result.validate()

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


def harvest_result_to_document(result: HarvestResult) -> dict[str, object]:
    """Validate and return a JSON-ready mapping with ISO timestamps and sorted ID lists.

    Record dictionaries are shallow copies; their nested values and the
    uncertain_records mapping remain shared. Validation errors propagate.
    """
    result.validate()
    records: list[dict[str, object]] = []

    for original in result.matching_records:
        record = dict(original)
        modified = record.get("upstream_modified_at")
        if isinstance(modified, datetime):
            record["upstream_modified_at"] = modified.isoformat()
        elif modified is not None:
            raise TypeError("upstream_modified_at must be datetime or None")
        records.append(record)

    return {
        "matching_records": records,
        "deleted_uuids": sorted(result.deleted_uuids),
        "nonmatching_uuids": sorted(result.nonmatching_uuids),
        "uncertain_records": result.uncertain_records,
        "source_cursor": (
            result.source_cursor.isoformat() if result.source_cursor is not None else None
        ),
    }


def _string_list(value: object, field_name: str) -> list[str]:
    """Return the original list of unique strings;
    raise ValueError for wrong types or duplicates.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} cannot contain duplicates")
    return value


def harvest_result_from_document(raw: object) -> HarvestResult:
    """Reconstruct and validate the exact five-field wire document.

    Require aware ISO timestamps, unique string ID lists, and string-valued
    uncertainty reasons; copy record dictionaries and convert their dates.
    TypeError/ValueError, including pydantic.ValidationError, reject malformed data.
    """
    if not isinstance(raw, dict) or set(raw) != {
        "matching_records",
        "deleted_uuids",
        "nonmatching_uuids",
        "uncertain_records",
        "source_cursor",
    }:
        raise ValueError("harvest result has the wrong top-level schema")

    raw_records = raw["matching_records"]
    if not isinstance(raw_records, list):
        raise TypeError("matching_records must be a list")

    records: list[dict[str, Any]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or not all(isinstance(key, str) for key in raw_record):
            raise ValueError("matching_records entries must be string-keyed objects")

        record = dict(raw_record)
        modified = record.get("upstream_modified_at")
        if isinstance(modified, str):
            parsed = datetime.fromisoformat(modified)
            if parsed.tzinfo is None:
                raise ValueError("upstream_modified_at must include a timezone")
            record["upstream_modified_at"] = parsed
        elif modified is not None:
            raise ValueError("upstream_modified_at must be an ISO timestamp or null")
        records.append(record)

    deleted = _string_list(raw["deleted_uuids"], "deleted_uuids")
    nonmatching = _string_list(raw["nonmatching_uuids"], "nonmatching_uuids")
    uncertain = raw["uncertain_records"]
    if not isinstance(uncertain, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in uncertain.items()
    ):
        raise ValueError("uncertain_records must map strings to strings")

    source_cursor = raw["source_cursor"]
    if not isinstance(source_cursor, str):
        raise TypeError("source_cursor must be an ISO timestamp")

    result = HarvestResult(
        matching_records=records,
        deleted_uuids=set(deleted),
        nonmatching_uuids=set(nonmatching),
        uncertain_records=dict(uncertain),
        source_cursor=datetime.fromisoformat(source_cursor),
    )
    result.validate()
    return result


def _encode_worker_harvest_result(result: HarvestResult) -> bytes:
    """Validate and encode compact UTF-8 JSON without checking payload size."""
    return json.dumps(
        harvest_result_to_document(result),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_worker_harvest_result(payload: bytes) -> HarvestResult:
    """Decode and validate UTF-8 JSON, attaching its original bytes for one-time reuse.

    Decoding and schema errors propagate; this helper does not enforce size.
    """
    result = harvest_result_from_document(json.loads(payload.decode("utf-8")))
    result._attach_serialized_worker_payload(payload)
    return result


def _harvest_worker(
    connection: Connection,
    oai_url: str,
    since: str,
    institution_filter: str,
) -> None:
    """Harvest and send one success/error frame, then close the pipe.

    Catch BaseException from harvesting/encoding and send a bounded
    diagnostic when the parent pipe remains writable.
    """
    try:
        result = fetch_updates(oai_url, since, institution_filter)
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
    """Join the child, then terminate and kill if needed, waiting two seconds at each stage.

    Close its process handle; raise OAIProtocolError if it survives SIGKILL.
    """
    process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
        raise OAIProtocolError(
            "resource_limit",
            "OAI harvest worker could not be terminated after SIGKILL",
        )
    process.close()


def _abort_harvest_process(process: Any) -> None:
    """Terminate the child immediately, then kill if needed, with two-second waits.

    Close its process handle; raise OAIProtocolError if it survives SIGKILL.
    """
    if process.is_alive():
        process.terminate()
        process.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)
    if process.is_alive():
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
    except OAIProtocolError as cleanup_error:
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


def fetch_updates_isolated(
    oai_url: str,
    since: str,
    institution_filter: str,
) -> HarvestResult:
    """Run fetch_updates in a spawned process and return its validated, cached-byte result.

    Use the same arguments/classification policy. A 240-second parent
    watchdog bounds waiting for the child/result; cleanup and synchronous
    parent decoding can extend elapsed time, with deadline checks before
    return. Worker/protocol/decoding failures become OAIProtocolError;
    process-start failures propagate. Always clean up pipes and started
    children. Call from an import-safe, non-daemon process; this call blocks.
    """
    context = multiprocessing.get_context("spawn")
    receive_connection, send_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_harvest_worker,
        args=(send_connection, oai_url, since, institution_filter),
        name="oralhistarchiv-oai-harvest",
        daemon=True,
    )
    started = False
    receiver: threading.Thread | None = None
    receive_state = _WorkerReceiveState()
    deadline = time.monotonic() + _OAI_TOTAL_TIMEOUT_SECONDS

    try:
        process.start()
        started = True
        send_connection.close()

        remaining = max(0.0, deadline - time.monotonic())
        if not receive_connection.poll(remaining):
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeded its hard wall-clock deadline",
            )

        receiver = threading.Thread(
            target=_receive_worker_message,
            args=(receive_connection, receive_state),
            name="oai-harvest-result-receiver",
            daemon=True,
        )
        receiver.start()

        remaining = max(0.0, deadline - time.monotonic())
        if not receive_state.done.wait(remaining):
            raise OAIProtocolError(
                "resource_limit",
                "OAI harvest exceeded its hard wall-clock deadline",
            )
        if receive_state.error is not None:
            raise OAIProtocolError(
                "harvest_worker",
                "OAI harvest worker exited without a valid bounded result",
            ) from receive_state.error
    finally:
        primary_exception = sys.exception()
        try:
            if started:
                _cleanup_harvest_process(
                    process,
                    completed=(receive_state.done.is_set() and receive_state.message is not None),
                    primary_exception=primary_exception,
                )
        finally:
            receive_connection.close()
            with contextlib.suppress(OSError):
                send_connection.close()
            if receiver is not None:
                receiver.join(timeout=_OAI_WORKER_SHUTDOWN_SECONDS)

    message = receive_state.message
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
    return result
