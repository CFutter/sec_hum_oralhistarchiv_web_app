"""Unit tests for the OAI-PMH client — app/services/oai_client.py.

Backlog §3.7 (fetch_updates institution filter + the parsed-defined path) and
the _oai_list_records protocol layer (resumption tokens, OAI error handling,
pagination-loop cap, HTTP error propagation).

No database, no network: fetch_updates tests patch
app.services.oai_client._oai_list_records with hand-built lxml elements;
protocol tests patch app.services.oai_client._session.get with fake response
objects carrying .content bytes and .raise_for_status().
"""

import logging
from unittest.mock import patch

import pytest
import requests
from lxml import etree

from app.services.oai_client import OAI_NS, OAIProtocolError, _oai_list_records, fetch_updates
from config import settings

# ---------------------------------------------------------------------------
# Sample CMDI record.
#
# Copied verbatim from src/tests_legacy/conftest.py::SAMPLE_CMDI_XML (that
# module cannot be imported: it does `from app.middleware.cookies import
# get_signer`, a function the current code base no longer exposes). Its
# institutions include 'Universität Kassel', which matches the test-env
# OAI_INSTITUTION_FILTER set by src/tests/conftest.py.
# ---------------------------------------------------------------------------

SAMPLE_CMDI_XML = """\
<record xmlns:oai="http://www.openarchives.org/OAI/2.0/">
<oai:header>
<oai:identifier>oai:swissubase.ch:test-uuid-xml</oai:identifier>
<oai:datestamp>2026-03-06T13:38:02Z</oai:datestamp>
</oai:header>
<metadata>
<cmd:CMD xmlns:cmd="http://www.clarin.eu/cmd/1"
         xmlns:cmdp="http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562">
<cmd:Resources>
<cmd:ResourceProxyList>
<cmd:ResourceProxy id="lp_1">
<cmd:ResourceType>LandingPage</cmd:ResourceType>
<cmd:ResourceRef>https://example.com/doi/10.1234</cmd:ResourceRef>
</cmd:ResourceProxy>
<cmd:ResourceProxy id="res_1">
<cmd:ResourceType>Resource</cmd:ResourceType>
<cmd:ResourceRef>https://example.com/download</cmd:ResourceRef>
</cmd:ResourceProxy>
</cmd:ResourceProxyList>
</cmd:Resources>
<cmd:Components>
<cmdp:SWISSUbase>
<cmdp:Project>
<cmdp:Overview>
<cmdp:Author>Müller, Urs</cmdp:Author>
<cmdp:Author>Keller, Anna</cmdp:Author>
<cmdp:Institution>Universität Kassel</cmdp:Institution>
<cmdp:Institution>University of Zurich</cmdp:Institution>
<cmdp:Project_title xml:lang="en">Test Project Title</cmdp:Project_title>
<cmdp:Project_title xml:lang="de">Test Projekttitel</cmdp:Project_title>
<cmdp:Main_discipline xml:lang="en">Linguistics</cmdp:Main_discipline>
<cmdp:Main_discipline xml:lang="de">Linguistik</cmdp:Main_discipline>
</cmdp:Overview>
<cmdp:General_description>
<cmdp:Abstract xml:lang="en">This is the project abstract.</cmdp:Abstract>
</cmdp:General_description>
<cmdp:Dataset>
<cmdp:Overview>
<cmdp:Dataset_title xml:lang="en">Test Dataset Title</cmdp:Dataset_title>
<cmdp:DOI>https://doi.org/10.48656/test-xml</cmdp:DOI>
<cmdp:Dataset_description>A test dataset description.</cmdp:Dataset_description>
<cmdp:Bibliographical_citation>Müller, U. &amp; Keller, A. (2026). Test Dataset (Version 2.5) [Data set]. https://doi.org/10.48656/test-xml</cmdp:Bibliographical_citation>
<cmdp:Dataset_version>2.5</cmdp:Dataset_version>
</cmdp:Overview>
<cmdp:Resource>
<cmdp:Resource_type xml:lang="en">Corpus</cmdp:Resource_type>
<cmdp:Resource_description>Audio recordings from field research.</cmdp:Resource_description>
<cmdp:Keywords>keyword1, keyword2, keyword3</cmdp:Keywords>
<cmdp:Language_name xml:lang="en">English</cmdp:Language_name>
<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>
</cmdp:Resource>
<cmdp:License>
<cmdp:License>Restricted access</cmdp:License>
<cmdp:LicenseURL>https://example.com/license</cmdp:LicenseURL>
</cmdp:License>
</cmdp:Dataset>
</cmdp:Project>
</cmdp:SWISSUbase>
</cmd:Components>
</cmd:CMD>
</metadata>
</record>
"""

_CMDP_NS = {"cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562"}

OAI_URL = "http://oai.example/oai"
SINCE = "2026-01-01"

SAMPLE_UUID = "oai:swissubase.ch:test-uuid-xml"


def _cmdi_record(institutions: list[str] | None = None) -> etree._Element:
    """Parse SAMPLE_CMDI_XML; optionally replace its <cmdp:Institution> list.

    institutions=None keeps the sample's originals ('Universität Kassel',
    'University of Zurich'); [] removes them all; a list swaps them out.
    """
    rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
    if institutions is not None:
        nodes = rec.xpath(".//cmdp:Institution", namespaces=_CMDP_NS)
        parent = nodes[0].getparent()
        for node in nodes:
            parent.remove(node)
        for name in institutions:
            el = etree.SubElement(parent, f"{{{_CMDP_NS['cmdp']}}}Institution")
            el.text = name
    return rec


def _deleted_record() -> etree._Element:
    """A deleted-status OAI record (header/identifier in the OAI namespace)."""
    xml = (
        f'<record xmlns="{OAI_NS}">'
        '<header status="deleted"><identifier>oai:x:1</identifier></header>'
        "</record>"
    )
    return etree.fromstring(xml.encode())


# ---------------------------------------------------------------------------
# OAI-PMH response page builders + fake HTTP response for _oai_list_records
# ---------------------------------------------------------------------------


def _oai_page(record_ids: list[str], token: str | None) -> bytes:
    """A ListRecords response page. token=None omits <resumptionToken>;
    token='' emits an empty element (both terminate pagination)."""
    records = "".join(
        f"<record><header><identifier>{rid}</identifier></header></record>"
        for rid in record_ids
    )
    token_xml = f"<resumptionToken>{token}</resumptionToken>" if token is not None else ""
    return (
        f'<OAI-PMH xmlns="{OAI_NS}"><ListRecords>{records}{token_xml}</ListRecords></OAI-PMH>'
    ).encode()


def _oai_error_page(code: str, text: str = "upstream details") -> bytes:
    return f'<OAI-PMH xmlns="{OAI_NS}"><error code="{code}">{text}</error></OAI-PMH>'.encode()


class _FakeResponse:
    """Stand-in for requests.Response: .content bytes + .raise_for_status()."""

    def __init__(self, content: bytes = b"", status_error: Exception | None = None):
        self.content = content
        self._status_error = status_error

    def raise_for_status(self) -> None:
        if self._status_error is not None:
            raise self._status_error


# ===========================================================================
# fetch_updates — institution filter + parsed-defined path (backlog §3.7)
# ===========================================================================


def test_fetch_updates_excludes_and_counts_record_with_no_institutions(caplog):
    """§3.7: a record whose parsed institutions list is empty is EXCLUDED,
    counted in filtered_out, and logged on the 'no institutions' warning path
    (possible profile drift must not silently pass the filter)."""
    record = _cmdi_record(institutions=[])
    with (
        patch("app.services.oai_client._oai_list_records", return_value=[record]),
        caplog.at_level(logging.INFO, logger="app.services.oai_client"),
    ):
        results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

    assert results == []
    assert "no institutions" in caplog.text
    # The uuid of the offending record is named in the warning.
    assert SAMPLE_UUID in caplog.text
    # filtered_out counter reflects the exclusion in the summary line.
    assert "fetched 0 records, 1 excluded" in caplog.text


def test_fetch_updates_keeps_record_matching_filter_case_insensitively():
    """§3.7: an institution matching the filter via casefold substring keeps
    the record — and the returned dict having 'title'/'uuid' proves the
    non-deleted path assigns parsed = parse_cmdi_to_dict(...) before use
    (regression guard for the NameError when that line was briefly deleted)."""
    record = _cmdi_record()  # institutions include 'Universität Kassel'
    # Upper-cased filter still matches 'Universität Kassel' via casefold.
    shouty_filter = settings.oai_institution_filter.upper()

    with patch(
        "app.services.oai_client._oai_list_records", return_value=[record]
    ) as mock_list:
        results = fetch_updates(OAI_URL, SINCE, shouty_filter)

    assert len(results) == 1
    parsed = results[0]
    # parsed-defined path (§3.7 NameError regression): real parse output.
    assert parsed["uuid"] == SAMPLE_UUID
    assert parsed["title"] == "Test Dataset Title"
    # Order-preserving institutions straight from the sample record.
    assert parsed["institutions"] == ["Universität Kassel", "University of Zurich"]
    # fetch_updates harvests with the CMDI 1.2 metadata prefix.
    mock_list.assert_called_once_with(OAI_URL, "oai_cmdi12", SINCE)


def test_fetch_updates_excludes_record_with_non_matching_institution(caplog):
    """§3.7: a record whose institutions do NOT contain the filter substring
    is excluded and counted in filtered_out (no warning path — just filtered)."""
    record = _cmdi_record(institutions=["Elsewhere Institute"])
    with (
        patch("app.services.oai_client._oai_list_records", return_value=[record]),
        caplog.at_level(logging.INFO, logger="app.services.oai_client"),
    ):
        results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

    assert results == []
    assert "fetched 0 records, 1 excluded" in caplog.text


def test_fetch_updates_returns_deleted_marker_for_deleted_record():
    """§3.7: a header status='deleted' record is returned as the tombstone
    dict {'_deleted': True, 'uuid': <identifier>} and never parsed as CMDI."""
    with patch(
        "app.services.oai_client._oai_list_records", return_value=[_deleted_record()]
    ):
        results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

    assert results == [{"_deleted": True, "uuid": "oai:x:1"}]


def test_fetch_updates_mixed_stream_keeps_order_and_counts_exclusions(caplog):
    """§3.7 end-to-end over one stream: kept + deleted records come back in
    harvest order; the no-institutions and non-matching records are both
    excluded and both counted in the summary line."""
    stream = [
        _cmdi_record(),                                    # matching -> kept
        _cmdi_record(institutions=["Elsewhere Institute"]),  # non-match -> out
        _cmdi_record(institutions=[]),                     # empty -> out + warn
        _deleted_record(),                                 # deleted -> tombstone
    ]
    with (
        patch("app.services.oai_client._oai_list_records", return_value=stream),
        caplog.at_level(logging.INFO, logger="app.services.oai_client"),
    ):
        results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

    assert len(results) == 2
    assert results[0]["uuid"] == SAMPLE_UUID
    assert results[1] == {"_deleted": True, "uuid": "oai:x:1"}
    assert "no institutions" in caplog.text
    assert "fetched 2 records, 2 excluded" in caplog.text


# ===========================================================================
# _oai_list_records — OAI-PMH protocol layer
# ===========================================================================


def test_list_records_no_records_match_yields_nothing_without_raising():
    """The benign noRecordsMatch OAI error means 'empty result set': the
    generator terminates cleanly instead of raising OAIProtocolError."""
    response = _FakeResponse(_oai_error_page("noRecordsMatch", "no matches"))
    with patch("app.services.oai_client._session.get", return_value=response) as mock_get:
        records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    assert records == []
    assert mock_get.call_count == 1


def test_list_records_other_oai_error_raises_protocol_error_with_code():
    """Any non-noRecordsMatch OAI error is a structured protocol failure:
    OAIProtocolError carries the upstream error code and detail text."""
    response = _FakeResponse(_oai_error_page("badResumptionToken", "token expired"))
    with (
        patch("app.services.oai_client._session.get", return_value=response),
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    assert exc_info.value.error_code == "badResumptionToken"
    assert "token expired" in str(exc_info.value)


def test_list_records_follows_resumption_token_across_pages():
    """Pagination: page 1 yields its record and its resumptionToken becomes
    the ONLY selector of page 2 (verb + resumptionToken, no metadataPrefix —
    the OAI-PMH exclusive-argument rule); an empty token ends the harvest."""
    pages = [
        _FakeResponse(_oai_page(["oai:x:p1"], token="T1")),
        _FakeResponse(_oai_page(["oai:x:p2"], token="")),  # empty token: stop
    ]
    with patch("app.services.oai_client._session.get", side_effect=pages) as mock_get:
        records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    ids = [r.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier").text for r in records]
    assert ids == ["oai:x:p1", "oai:x:p2"]
    assert mock_get.call_count == 2

    first_params = mock_get.call_args_list[0].kwargs["params"]
    assert first_params["metadataPrefix"] == "oai_cmdi12"
    assert first_params["from"] == SINCE

    second_params = mock_get.call_args_list[1].kwargs["params"]
    assert second_params["resumptionToken"] == "T1"
    assert second_params["verb"] == "ListRecords"
    assert "metadataPrefix" not in second_params


def test_list_records_pagination_cap_raises_after_max_pages(monkeypatch):
    """Safety cap: when every page keeps offering a resumptionToken, the
    harvest stops after settings.oai_max_pages GETs with a structured
    'pagination_loop' error naming the last token (buggy-upstream guard)."""
    monkeypatch.setattr(settings, "oai_max_pages", 3)
    pages = [
        _FakeResponse(_oai_page(["oai:x:p1"], token="T1")),
        _FakeResponse(_oai_page(["oai:x:p2"], token="T2")),
        _FakeResponse(_oai_page(["oai:x:p3"], token="T3")),
    ]
    with (
        patch("app.services.oai_client._session.get", side_effect=pages) as mock_get,
        pytest.raises(OAIProtocolError) as exc_info,
    ):
        list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    assert exc_info.value.error_code == "pagination_loop"
    assert "T3" in str(exc_info.value)  # the last token is named
    assert mock_get.call_count == 3  # exactly max_pages GETs, no fourth


def test_list_records_http_error_propagates():
    """A non-2xx response propagates as requests.HTTPError (infrastructure
    failure), distinct from the structured OAIProtocolError channel."""
    response = _FakeResponse(status_error=requests.HTTPError("503 Service Unavailable"))
    with (
        patch("app.services.oai_client._session.get", return_value=response),
        pytest.raises(requests.HTTPError),
    ):
        list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))


# ===========================================================================
# Robustness — timeout, non-OAI bodies, retry adapter, unsafe URLs, XXE
# ===========================================================================


def test_list_records_passes_timeout_on_every_page():
    """TEST-035: every _session.get carries timeout=OAI_REQUEST_TIMEOUT — the
    only bound on a stalled upstream socket. Dropping it means one hung
    connection blocks the harvest thread forever WHILE HOLDING the sync mutex,
    freezing every future sync and rebuild (catalogue silently frozen until
    restart). Asserted across a two-page run so a per-page regression can't
    hide on the continuation request."""
    from app.services.oai_client import OAI_REQUEST_TIMEOUT

    pages = [
        _FakeResponse(_oai_page(["oai:x:p1"], token="T1")),
        _FakeResponse(_oai_page(["oai:x:p2"], token="")),
    ]
    with patch("app.services.oai_client._session.get", side_effect=pages) as mock_get:
        list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    assert mock_get.call_count == 2
    for call in mock_get.call_args_list:
        assert call.kwargs.get("timeout") == OAI_REQUEST_TIMEOUT


def test_list_records_non_oai_200_body_yields_nothing_without_raising():
    """TEST-036: a 200 whose XML parses but has neither <error> nor
    <ListRecords> (a captive-portal / maintenance page that happens to be
    well-formed XML) yields zero records and does NOT raise — characterising
    the silent-empty-harvest path so the sync-side watermark/error behaviour
    (test_sync_db.py) can be pinned on top of it."""
    body = b'<html><body>Service temporarily unavailable</body></html>'
    with patch("app.services.oai_client._session.get",
               return_value=_FakeResponse(body)):
        records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))
    assert records == []


def test_list_records_truncated_body_raises_into_failure_path():
    """TEST-036 companion: truncated/garbage bytes are NOT swallowed — they
    raise lxml.etree.XMLSyntaxError, which surfaces as a fetch failure (so the
    watermark is NOT advanced over a corrupt page). Positive control that the
    'empty result' path above is specific to well-formed non-OAI XML."""
    with patch("app.services.oai_client._session.get",
               return_value=_FakeResponse(b"<OAI-PMH><ListReco")):
        with pytest.raises(etree.XMLSyntaxError):
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))


def test_retry_adapter_config_is_load_bearing():
    """TEST-050: the session's HTTPAdapter retries transient upstream blips
    (429/5xx) rather than failing a whole sync run on the first hiccup.
    Dropping 503 from the forcelist or setting total=0 would turn every
    momentary upstream wobble into a failed harvest — pin the mounted
    Retry's shape for both schemes."""
    from app.services.oai_client import _session

    for scheme in ("https://", "http://"):
        adapter = _session.get_adapter(scheme)
        retry = adapter.max_retries
        assert retry.total == 3
        assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
        assert list(retry.allowed_methods) == ["GET"]


def test_parse_rejects_unsafe_urls_at_ingest():
    """TEST-051: javascript:/data: URLs from upstream data are stored as None,
    not persisted verbatim (stored-XSS defence-in-depth). Both the license URL
    and the resource-proxy ref go through _safe_url; a benign https link
    survives (positive control)."""
    from app.services.oai_client import parse_cmdi_to_dict

    xml = SAMPLE_CMDI_XML.replace(
        "https://example.com/license", "javascript:alert(1)"
    ).replace(
        "https://example.com/download", "data:text/html,<script>alert(1)</script>"
    )
    parsed = parse_cmdi_to_dict(etree.fromstring(xml.encode()))

    assert parsed["license_url"] is None  # javascript: rejected
    resource_refs = [p["ref"] for p in parsed["resource_proxies"]
                     if p["type"] == "Resource"]
    assert resource_refs == [None]  # data: rejected, proxy still present
    # Positive control: the untouched landing-page https URL survives.
    landing = [p["ref"] for p in parsed["resource_proxies"]
               if p["type"] == "LandingPage"]
    assert landing == ["https://example.com/doi/10.1234"]


def test_malformed_resource_proxy_does_not_crash_whole_record():
    """TEST-051 companion: a ResourceProxy missing its ResourceType/ResourceRef
    is skipped with a warning, and the rest of the record still parses — one
    bad proxy must not sink an entire dataset's ingest."""
    from app.services.oai_client import parse_cmdi_to_dict

    broken = (
        '<cmd:ResourceProxy id="bad" '
        'xmlns:cmd="http://www.clarin.eu/cmd/1">'
        '<cmd:ResourceType>Resource</cmd:ResourceType>'
        '</cmd:ResourceProxy>'  # no ResourceRef
    )
    xml = SAMPLE_CMDI_XML.replace(
        '<cmd:ResourceProxy id="res_1">', broken + '<cmd:ResourceProxy id="res_1">'
    )
    parsed = parse_cmdi_to_dict(etree.fromstring(xml.encode()))

    assert parsed["uuid"] == SAMPLE_UUID  # record still parsed
    # The valid proxies survive; the malformed one was dropped.
    types = [p["type"] for p in parsed["resource_proxies"]]
    assert "Resource" in types and "LandingPage" in types


def test_xxe_external_entity_is_not_resolved():
    """THE XXE security property behind resolve_entities=False: a document
    declaring an external SYSTEM entity must NOT have that entity resolved
    (no local-file read, no SSRF). Only the benign parse was tested before;
    this drives the actual attack shape and asserts the secret file contents
    never reach the parsed record.

    Uses _make_safe_parser directly (the parser _oai_list_records builds per
    harvest) — the property lives in that parser's construction."""
    import os
    import tempfile

    from app.services.oai_client import _make_safe_parser

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("TOP-SECRET-XXE-PAYLOAD")
        secret_path = f.name
    try:
        malicious = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{secret_path}">]>'
            '<root><value>&xxe;</value></root>'
        ).encode()
        parser = _make_safe_parser()
        tree = etree.fromstring(malicious, parser=parser)
        # The external entity must be unresolved — the secret never appears.
        assert "TOP-SECRET-XXE-PAYLOAD" not in (tree.findtext("value") or "")
        assert "TOP-SECRET-XXE-PAYLOAD" not in etree.tostring(tree, encoding="unicode")
    finally:
        os.unlink(secret_path)
