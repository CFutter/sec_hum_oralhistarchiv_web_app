"""OAI-PMH client for SWISSUbase.

Implements OAI-PMH ListRecords with resumption token handling
using requests + lxml. Handles protocol communication and 
CMDI XML parsing. Returns plain dicts — no database awareness.
"""

import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from lxml import etree
from collections.abc import Iterator
from typing import Any

from ..url_safety import is_safe_http_url
from config import settings

logger = logging.getLogger(__name__)

OAI_REQUEST_TIMEOUT = 30

OAI_NS = "http://www.openarchives.org/OAI/2.0/"

_EXPECTED_CMDI_PROFILE = "clarin.eu:cr1:p_1696338267562"
_CMDI_NAMESPACES = {
    "oai": OAI_NS,
    "cmd": "http://www.clarin.eu/cmd/1",
    "cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562",
}

def _make_safe_parser() -> etree.XMLParser:
    """Fresh XXE-hardened parser. Per-call because lxml parsers aren't thread-safe."""
    return etree.XMLParser(
        resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False,
    )

_session = requests.Session()
_retry_strategy = Retry(
    total=3,
    backoff_factor=1.0,   # 1s, 2s, 4s between attempts
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
)
_session.mount("https://", HTTPAdapter(max_retries=_retry_strategy))
_session.mount("http://", HTTPAdapter(max_retries=_retry_strategy))



class OAIProtocolError(Exception):
    """Raised when the OAI-PMH endpoint returns a structured error response.
    
    Distinguishes upstream-protocol failures (e.g., bad metadata prefix,
    pagination errors) from infrastructure failures (e.g., network timeouts).
    Callers can catch this to handle protocol issues distinctly.
    """
    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(f"OAI-PMH [{error_code}]: {message}")

# =============================================================================
# OAI-PMH protocol layer
# =============================================================================

def _oai_list_records(oai_url: str, metadata_prefix: str, since: str) -> Iterator[etree._Element]:
    """Generator that yields lxml record elements from an OAI-PMH endpoint.

    Handles resumption tokens for paginated result sets automatically.
    Each yielded element is a <record> element containing <header>
    and (optionally) <metadata> children.

    Terminates after at most settings.oai_max_pages pages as a safety
    cap against malformed upstream pagination (a buggy server that
    returns resumption tokens indefinitely).

    Raises:
        requests.exceptions.HTTPError: If the endpoint returns a non-2xx status.
        OAIProtocolError: If the endpoint returns an OAI-PMH error other than
            noRecordsMatch (which returns an empty iterator), or if the
            harvest exceeds settings.oai_max_pages.
    """
    params = {
        "verb": "ListRecords",
        "metadataPrefix": metadata_prefix,
        "from": since,
    }
    last_token: str | None = None
    parser = _make_safe_parser()

    for _ in range(settings.oai_max_pages):
        response = _session.get(oai_url, params=params, timeout=OAI_REQUEST_TIMEOUT)
        response.raise_for_status()

        root = etree.fromstring(response.content, parser=parser)

        error = root.find(f"{{{OAI_NS}}}error")
        if error is not None:
            error_code = error.get("code", "unknown")
            if error_code == "noRecordsMatch":
                return
            raise OAIProtocolError(error_code, error.text or "no details")

        list_records = root.find(f"{{{OAI_NS}}}ListRecords")
        if list_records is None:
            return

        yield from list_records.findall(f"{{{OAI_NS}}}record")

        token_el = list_records.find(f"{{{OAI_NS}}}resumptionToken")
        raw_token = token_el.text if token_el is not None else None
        if raw_token is None or not raw_token.strip():
            break
        resumption_token = raw_token.strip()
        last_token = resumption_token
        params = {
            "verb": "ListRecords", 
            "resumptionToken": resumption_token
        }

    else:
        # Reached oai_max_pages without exhausting the resumption-token chain.
        # Upstream is still offering more pages — abort with a structured error.
        raise OAIProtocolError(
            "pagination_loop",
            f"OAI harvest exceeded {settings.oai_max_pages} pages — "
            f"possible upstream pagination loop. "
            f"Last resumption_token: {last_token!r}"
        )

# =============================================================================
# CMDI XML parsing
# =============================================================================

def parse_cmdi_to_dict(record_xml: etree._Element) -> dict[str, Any]:
    """Converts a CMDI XML record element into a dictionary for JSONB storage."""

    ns = _CMDI_NAMESPACES

    profile_nodes = record_xml.xpath(".//cmd:MdProfile", namespaces=ns)
    if isinstance(profile_nodes, list) and profile_nodes:
        first_profile = profile_nodes[0]
        if isinstance(first_profile, etree._Element) and first_profile.text:
            profile = first_profile.text.strip()
            if profile != _EXPECTED_CMDI_PROFILE:
                logger.warning(
                    "CMDI profile drift detected: got %r, expected %r. "
                    "Field extraction may be incomplete.",
                    profile, _EXPECTED_CMDI_PROFILE,
                )

    def _get_text(xpath: str) -> str | None:
        nodes = record_xml.xpath(xpath, namespaces=ns)
        if not isinstance(nodes, list) or not nodes:
            return None
        first = nodes[0]
        if not isinstance(first, etree._Element):
            return None
        return first.text.strip() if first.text else None

    def _get_list(xpath: str) -> list[str]:
        nodes = record_xml.xpath(xpath, namespaces=ns)
        if not isinstance(nodes, list):
            return []
        return sorted({
            t for n in nodes
            if isinstance(n, etree._Element) and n.text and (t := n.text.strip())
        })

    def _get_list_ordered(xpath: str) -> list[str]:
        """Extract matched text values in source order, without deduping.

        Unlike _get_list (which sorts and dedupes for order-free fields like
        languages), this preserves the upstream ordering — so an author list
        mirrors the citation and the lead author stays first, regardless of
        alphabetical position. Blank/whitespace-only nodes are skipped.

        Duplicates are intentionally kept: two entries with the same name are
        both returned, on the assumption that they are distinct people the
        source listed separately, not a data-entry error. Source data quality
        is treated as authoritative and left to the upstream repository — this
        function represents the record, it does not correct it.
        """
        nodes = record_xml.xpath(xpath, namespaces=ns)
        if not isinstance(nodes, list):
            return []
        return [t for n in nodes if isinstance(n, etree._Element) and n.text and (t := n.text.strip())]

    def _safe_url(url: str | None) -> str | None:
        """Reject URLs with dangerous schemes (e.g. javascript:, data:).

        Only allows http:// and https:// URLs. Returns None for anything
        else, preventing injection of executable URIs into href attributes.
        """
        if url and is_safe_http_url(url):
            return url.strip()
        if url:
            logger.warning("Rejected unsafe URL from upstream data: %s", url[:80])
        return None

    def _get_url(xpath: str) -> str | None:
        """Extract a URL from XML and validate its scheme."""
        return _safe_url(_get_text(xpath))
    
    def _get_doi(xpath: str) -> str | None:
        """Normalize an upstream DOI to a bare DOI or an http(s) URL.

        Accepts a bare DOI (10.x/...), a doi:-prefixed value (the prefix is
        stripped), or an http(s) DOI URL. Returns the normalized value, or
        None (with a warning) for anything else.
        """
        raw = _get_text(xpath)
        if not raw:
            return None
        raw = raw.strip()
        if raw.lower().startswith("doi:"):
            raw = raw[4:]                          
        low = raw.lower()
        if low.startswith(("http://", "https://")) or raw.startswith("10."):
            return raw
        logger.warning("Unrecognized DOI format from upstream: %s", raw[:80])
        return None

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
                    not isinstance(res_type_nodes, list) or not res_type_nodes
                    or not isinstance(res_ref_nodes, list) or not res_ref_nodes
                ):
                    logger.warning(
                        "Skipping malformed ResourceProxy (missing type or ref) in record."
                    )
                    continue

                type_node = res_type_nodes[0]
                ref_node = res_ref_nodes[0]
                if not isinstance(type_node, etree._Element) or not isinstance(ref_node, etree._Element):
                    logger.warning("Skipping ResourceProxy with non-element type/ref.")
                    continue

                res_type = (type_node.text or "").strip()
                resource_proxies.append({
                    "type": res_type,
                    "ref": _safe_url(ref_node.text),
                })
            except Exception as e:  # noqa: BLE001  # per-proxy resilience
                logger.warning("Failed to parse ResourceProxy: %s", e)
                continue

    return {
        "uuid": _get_text("./oai:header/oai:identifier"),
        "title": _get_text(".//cmdp:Dataset_title"),
        "project_title": _get_text(".//cmdp:Project_title[@xml:lang='en']"),
        "description": _get_text(".//cmdp:Dataset_description"),
        "resource_description": _get_text(".//cmdp:Resource_description"),
        "languages": _get_list(".//cmdp:Language_name[@xml:lang='en']"),
        "project_description": _get_text(".//cmdp:Abstract"),
        "authors": _get_list_ordered(".//cmdp:Author"),
        "keywords": [k.strip() for k in (_get_text(".//cmdp:Keywords") or "").split(",") if k.strip()],
        "resource_proxies": resource_proxies,
        "license_val": _get_text(".//cmdp:License/cmdp:License"),
        "license_url": _get_url(".//cmdp:LicenseURL"),
        "version": _get_text(".//cmdp:Dataset_version"),
        "doi": _get_doi(".//cmdp:DOI"),
        "resource_type": _get_text(".//cmdp:Resource_type[@xml:lang='en']"),
        "institutions": _get_list_ordered(".//cmdp:Institution"),
        "main_disciplines": _get_list(".//cmdp:Main_discipline"),
        "bibliographical_citation": _get_text(".//cmdp:Bibliographical_citation"),
    }


# =============================================================================
# Public API
# =============================================================================

def fetch_updates(oai_url: str, since: str, institution_filter: str) -> list[dict[str, Any]]:
    """Fetch new/updated records from OAI-PMH endpoint since given date.

    Returns a list of parsed record dicts filtered by institution.
    Deleted record identifiers are returned as {"_deleted": True, "uuid": ...}.

    Raises:
        OAIProtocolError: On OAI-PMH protocol errors (bad error code,
            pagination loop, etc.).
        requests.exceptions.RequestException: On network/HTTP errors.
    """
    results: list[dict[str, Any]] = []
    filtered_out = 0

    for record_xml in _oai_list_records(oai_url, "oai_cmdi12", since):
        header = record_xml.find(f"{{{OAI_NS}}}header")
        if header is not None and header.get("status") == "deleted":
            identifier = header.find(f"{{{OAI_NS}}}identifier")
            if identifier is not None and identifier.text:
                results.append({"_deleted": True, "uuid": identifier.text})
            continue
        
        parsed = parse_cmdi_to_dict(record_xml)

        institutions = parsed.get("institutions") or []
        if not institutions:
            logger.warning(
                "Record has no institutions — excluded by filter (possible profile drift). uuid=%r",
                parsed.get("uuid"),
            )
            filtered_out += 1
            continue

        if any(institution_filter.casefold() in inst.casefold() for inst in institutions):
            results.append(parsed)
        else:
            filtered_out += 1

    logger.info("OAI-PMH: fetched %d records, %d excluded by institution filter.",
                len(results), filtered_out)
    return results