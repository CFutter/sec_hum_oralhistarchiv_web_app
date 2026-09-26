"""Unit tests for the bounded OAI-PMH client's HTTP/protocol layer.

No database and no network are used. Protocol tests patch the Session
factory with streaming FakeOAIResponse objects so redirect, encoding, byte,
record, pagination, and retained-result limits execute deterministically.
"""

import time
from http import HTTPStatus

import pytest
from lxml import etree

from app.services import oai_client
from app.services.oai_client import (
    OAI_NS,
    OAI_REQUEST_TIMEOUT,
    OAIProtocolError,
    _build_session,
    _make_safe_parser,
    _oai_list_records,
    fetch_updates,
)
from config import settings
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    FakeOAIResponse,
    patch_records,
    patch_session_get,
)

OAI_URL = "http://oai.example/oai"
SINCE = "2026-01-01"

SAMPLE_UUID = "oai:swissubase.ch:test-uuid-xml"


def _cmdi_record(identifier: str = SAMPLE_UUID) -> etree._Element:
    """Parse SAMPLE_CMDI_XML with its identifier replaced."""
    rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
    identifier_node = rec.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier")
    assert identifier_node is not None
    identifier_node.text = identifier
    return rec


# ---------------------------------------------------------------------------
# OAI-PMH response page builders for _oai_list_records (the fake HTTP
# response + session patcher live in tests.oai_fixtures)
# ---------------------------------------------------------------------------


def _oai_page(record_ids: list[str], token: str | None) -> bytes:
    """A ListRecords response page. token=None omits <resumptionToken>;
    token='' emits an empty element (both terminate pagination)."""
    records = "".join(
        f"<record><header><identifier>{rid}</identifier></header></record>" for rid in record_ids
    )
    token_xml = f"<resumptionToken>{token}</resumptionToken>" if token is not None else ""
    return (
        f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate><ListRecords>{records}{token_xml}</ListRecords></OAI-PMH>'
    ).encode()


def _oai_error_page(code: str, text: str = "upstream details") -> bytes:
    return (
        f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate><error code="{code}">{text}</error></OAI-PMH>'
    ).encode()


def _page_with_records(record_elements: list[etree._Element], token: str | None) -> bytes:
    """A ListRecords response page embedding fully-built CMDI record
    elements (rather than bare identifiers), so a page can carry real
    child content, institutions and datestamps."""
    records = "".join(etree.tostring(record, encoding="unicode") for record in record_elements)
    token_xml = f"<resumptionToken>{token}</resumptionToken>" if token is not None else ""
    return (
        f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate><ListRecords>{records}{token_xml}</ListRecords></OAI-PMH>'
    ).encode()


def _deleted_record(identifier: str = "oai:x:deleted") -> etree._Element:
    """A deleted-status OAI record (header/identifier only, no metadata)."""
    xml = (
        f'<record xmlns="{OAI_NS}">'
        f'<header status="deleted"><identifier>{identifier}</identifier></header>'
        "</record>"
    )
    return etree.fromstring(xml.encode())


def _set_datestamp(record: etree._Element, value: str) -> etree._Element:
    """Overwrite a CMDI record's OAI header datestamp in place."""
    node = record.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}datestamp")
    assert node is not None
    node.text = value
    return record


class TestSessionRetryConfiguration:
    """The session's transport must survive transient upstream blips."""

    def test_retry_adapter_config_is_load_bearing(self):
        """The session's HTTPAdapter retries transient upstream blips
        (429/5xx) rather than failing a whole sync run on the first hiccup.
        Dropping 503 from the forcelist or setting total=0 would turn every
        momentary upstream wobble into a failed harvest — pin the mounted
        Retry's shape for both schemes."""
        session = _build_session()

        try:
            for scheme in ("https://", "http://"):
                adapter = session.get_adapter(scheme)
                retry = adapter.max_retries
                assert retry.total == 3
                assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
                assert list(retry.allowed_methods) == ["GET"]
        finally:
            session.close()


class TestSafeXmlParsing:
    """The XML parser that reads each harvested page must not resolve
    external entities."""

    def test_xxe_external_entity_is_not_resolved(self, tmp_path):
        """The XXE security property behind resolve_entities=False: a document
        declaring an external SYSTEM entity must NOT have that entity resolved
        (no local-file read, no SSRF). This drives the actual attack shape and
        asserts the secret file contents never reach the parsed record.

        Uses _make_safe_parser directly (the parser _oai_list_records builds
        per harvest) — the property lives in that parser's construction."""
        secret_path = tmp_path / "secret.txt"
        secret_path.write_text("TOP-SECRET-XXE-PAYLOAD")
        malicious = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{secret_path}">]>'
            "<root><value>&xxe;</value></root>"
        ).encode()
        parser = _make_safe_parser()
        tree = etree.fromstring(malicious, parser=parser)
        # The external entity must be unresolved — the secret never appears.
        assert "TOP-SECRET-XXE-PAYLOAD" not in (tree.findtext("value") or "")
        assert "TOP-SECRET-XXE-PAYLOAD" not in etree.tostring(tree, encoding="unicode")


class TestProtocolErrorMapping:
    """Upstream OAI-PMH errors and malformed bodies become a structured
    OAIProtocolError without disclosing upstream detail text."""

    def test_pagination_cap_does_not_disclose_last_token(self, monkeypatch):
        monkeypatch.setattr(settings, "oai_max_pages", 1)
        secret_token = "upstream-secret-token"
        response = FakeOAIResponse(
            _oai_page(["oai:x:p1"], token=secret_token),
        )
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "pagination_loop"
        assert secret_token not in str(exc_info.value)

    def test_oai_error_text_is_not_propagated(self):
        secret = "attacker-controlled-sensitive-value"
        response = FakeOAIResponse(
            _oai_error_page("badArgument", secret),
        )
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "badArgument"
        assert secret not in str(exc_info.value)

    def test_list_records_no_records_match_yields_nothing_without_raising(self):
        """The benign noRecordsMatch OAI error means 'empty result set': the
        generator terminates cleanly instead of raising OAIProtocolError."""
        response = FakeOAIResponse(_oai_error_page("noRecordsMatch", "no matches"))
        patcher, mock_get = patch_session_get(return_value=response)
        with patcher:
            records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert records == []
        assert mock_get.call_count == 1

    def test_list_records_other_oai_error_raises_protocol_error_with_code(self):
        """Any non-noRecordsMatch OAI error is a structured protocol failure:
        OAIProtocolError carries the upstream error code and detail text."""
        response = FakeOAIResponse(_oai_error_page("badResumptionToken", "token expired"))
        patcher, _mock_get = patch_session_get(return_value=response)
        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))
        assert exc_info.value.error_code == "badResumptionToken"
        assert "token expired" not in str(exc_info.value)

    def test_list_records_no_records_match_on_continuation_raises(self):
        """noRecordsMatch is benign only for the initial request."""
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_error_page("noRecordsMatch", "no matches")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            records = _oai_list_records(OAI_URL, "oai_cmdi12", SINCE)

            first = next(records)
            identifier = first.find(
                f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier",
            )
            assert identifier is not None
            assert identifier.text == "oai:x:p1"

            with pytest.raises(OAIProtocolError) as exc_info:
                next(records)

        assert exc_info.value.error_code == "malformed_response"
        assert "page 2" in str(exc_info.value)
        assert mock_get.call_count == 2

    def test_list_records_http_error_is_sanitized(self):
        """A non-2xx response becomes a sanitized OAIProtocolError."""
        response = FakeOAIResponse(
            b"attacker-controlled upstream diagnostic",
            status_code=503,
        )
        patcher, mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "http_status"
        assert "503" in str(exc_info.value)
        assert "attacker-controlled upstream diagnostic" not in str(exc_info.value)
        assert OAI_URL not in str(exc_info.value)
        assert response.closed is True
        mock_get.assert_called_once()

    def test_list_records_non_oai_200_body_raises_protocol_error(self):
        """A 200 whose XML parses but has neither <error> nor
        <ListRecords> (a captive-portal / maintenance page that happens to be
        well-formed XML) raises OAIProtocolError instead of being treated as
        a successful empty result."""
        body = b"<html><body>Service temporarily unavailable</body></html>"
        patcher, _mock_get = patch_session_get(
            return_value=FakeOAIResponse(body),
        )

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "malformed_response"

    def test_list_records_malformed_second_page_raises(self):
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(b"<html><body>maintenance</body></html>"),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "malformed_response"
        assert "page 2" in str(exc_info.value)
        assert mock_get.call_count == 2

    def test_list_records_truncated_body_raises_into_failure_path(self):
        """Truncated/garbage bytes are NOT swallowed — they
        raise lxml.etree.XMLSyntaxError, which surfaces as a fetch failure (so
        the watermark is NOT advanced over a corrupt page). Positive control
        that the 'empty result' path above is specific to well-formed non-OAI
        XML."""
        body = b'<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/"><ListRec'  # truncated
        patcher, _mock_get = patch_session_get(return_value=FakeOAIResponse(body))
        with patcher, pytest.raises(etree.XMLSyntaxError):
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))


class TestPagination:
    """Resumption-token pagination and its safety cap."""

    def test_list_records_follows_resumption_token_across_pages(self):
        """Pagination: page 1 yields its record and its resumptionToken becomes
        the ONLY selector of page 2 (verb + resumptionToken, no metadataPrefix —
        the OAI-PMH exclusive-argument rule); an empty token ends the harvest."""
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="")),  # empty token: stop
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)
        with patcher:
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

    def test_list_records_pagination_cap_raises_after_max_pages(self, monkeypatch):
        """Safety cap: when every page keeps offering a resumptionToken, the
        harvest stops after settings.oai_max_pages GETs with a structured
        'pagination_loop' error without disclosing upstream tokens
        (buggy-upstream guard)."""
        monkeypatch.setattr(settings, "oai_max_pages", 3)
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="T2")),
            FakeOAIResponse(_oai_page(["oai:x:p3"], token="T3")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)
        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "pagination_loop"
        assert "T3" not in str(exc_info.value)  # resumption tokens are not disclosed
        assert mock_get.call_count == 3  # exactly max_pages GETs, no fourth

    def test_list_records_repeated_resumption_token_raises_before_yielding_page(self):
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="T1")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            records = _oai_list_records(OAI_URL, "oai_cmdi12", SINCE)

            first = next(records)
            identifier = first.find(
                f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier",
            )
            assert identifier is not None
            assert identifier.text == "oai:x:p1"

            # Page 2 must not be exposed to a future streaming caller.
            with pytest.raises(OAIProtocolError) as exc_info:
                next(records)

        assert exc_info.value.error_code == "pagination_loop"
        assert "Repeated resumption token" in str(exc_info.value)
        assert mock_get.call_count == 2

    def test_list_records_requires_an_explicit_terminating_token(self):
        """A page that offers a resumption token followed by a page with NO
        resumptionToken element at all is a malformed continuation, not a
        silent stop: only an explicit empty token may end pagination."""
        pages = [
            FakeOAIResponse(_oai_page(["one"], "next")),
            FakeOAIResponse(_oai_page(["two"], None)),
        ]
        patcher, _mock_get = patch_session_get(side_effect=pages)
        with patcher, pytest.raises(OAIProtocolError, match="resumption token"):
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))


class TestResponseClock:
    """The harvest budget's source_cursor comes from the OAI responseDate,
    captured once from the FIRST page — never from a later or local clock."""

    def test_missing_source_clock_is_rejected(self):
        """A page with no <responseDate> at all cannot supply a source
        clock, so pagination must fail rather than proceed clockless."""
        body = _oai_page(["one"], None).replace(
            b"<responseDate>2026-09-10T12:00:00Z</responseDate>", b""
        )
        patcher, _mock_get = patch_session_get(return_value=FakeOAIResponse(body))
        with patcher, pytest.raises(OAIProtocolError, match="responseDate"):
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

    def test_response_clock_comes_from_first_page_not_local_or_last_clock(self):
        """budget.source_cursor is stamped from page ONE's responseDate, even
        though a later page's responseDate has since drifted far into the
        future — the watermark must not silently adopt a later or local
        clock."""
        first = _oai_page(["one"], "next")
        second = _oai_page(["two"], "").replace(b"2026-09-10T12:00:00Z", b"2099-01-01T00:00:00Z")
        patcher, _mock_get = patch_session_get(
            side_effect=[FakeOAIResponse(first), FakeOAIResponse(second)]
        )
        budget = oai_client._HarvestBudget(deadline=time.monotonic() + 30)
        with patcher:
            records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE, budget=budget))
        assert len(records) == 2
        assert budget.source_cursor == SOURCE_CURSOR


# `301-moved-permanently` for an assigned 3xx code, `309-unassigned-3xx` otherwise.
_ASSIGNED_3XX = {s.value: s.phrase.lower().replace(" ", "-") for s in HTTPStatus if 300 <= s < 400}
_REDIRECT_IDS = [f"{code}-{_ASSIGNED_3XX.get(code, 'unassigned-3xx')}" for code in range(300, 400)]


class TestTransportPolicy:
    """Every request enforces the same non-negotiable transport policy:
    no redirects, no compression, fixed timeout and headers."""

    @pytest.mark.parametrize("status_code", range(300, 400), ids=_REDIRECT_IDS)
    def test_list_records_rejects_redirect_without_following(self, status_code):
        response = FakeOAIResponse(
            status_code=status_code,
            headers={"Location": "http://127.0.0.1:5432/private"},
        )
        patcher, mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "redirect_disallowed"
        assert str(status_code) in str(exc_info.value)
        assert "127.0.0.1" not in str(exc_info.value)
        assert mock_get.call_count == 1
        assert mock_get.call_args.kwargs["allow_redirects"] is False
        assert response.closed is True

    @pytest.mark.parametrize(
        "destination",
        [
            pytest.param("http://127.0.0.1:5432/", id="loopback"),
            pytest.param("http://[::1]:6379/", id="loopback-over-ipv6"),
            pytest.param("http://169.254.169.254/latest/meta-data/", id="link-local"),
            pytest.param("http://10.1.2.3/internal-admin", id="private-network"),
            pytest.param("http://oai.example/oai", id="plaintext-downgrade"),
            pytest.param("https://somewhere-else.example/oai", id="unrelated-host"),
            pytest.param("file:///etc/passwd", id="non-http-scheme"),
        ],
    )
    def test_no_redirect_destination_is_ever_requested(self, destination):
        """A redirect turns the upstream catalogue into a way of choosing
        where the archive's server sends requests. Whatever it names —
        a service on the loopback interface, the cloud metadata address, a
        machine on the internal network, a plaintext downgrade of the
        configured endpoint, an unrelated host, or a scheme that is not HTTP
        at all — the harvest stops at the redirect and the destination is
        never fetched or written into a log line."""
        response = FakeOAIResponse(
            status_code=HTTPStatus.FOUND,
            headers={"Location": destination},
        )
        patcher, mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as refusal:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert refusal.value.error_code == "redirect_disallowed"
        assert mock_get.call_count == 1, "the redirect destination was requested"
        assert mock_get.call_args.args[0] == OAI_URL
        assert destination not in str(refusal.value)
        assert response.iterated is False
        assert response.closed is True

    def test_list_records_applies_transport_policy_on_every_page(self):
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)
        with patcher:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert mock_get.call_count == 2
        for call in mock_get.call_args_list:
            assert call.kwargs["timeout"] == OAI_REQUEST_TIMEOUT
            assert call.kwargs["allow_redirects"] is False
            assert call.kwargs["stream"] is True
            assert call.kwargs["headers"] == {"Accept-Encoding": "identity"}

    def test_list_records_rejects_compression_before_reading_body(self):
        response = FakeOAIResponse(
            _oai_page(["oai:x:1"], token=None),
            headers={"Content-Encoding": "gzip"},
        )
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "unsupported_content_encoding"
        assert response.iterated is False
        assert response.closed is True


class TestResourceLimits:
    """The harvest budget bounds page bytes, aggregate bytes, record count,
    per-record size, resumption-token size, and retained-result size."""

    def test_list_records_rejects_page_over_byte_limit(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_PAGE_BYTES", 8)
        response = FakeOAIResponse(chunks=[b"12345", b"6789"])
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "page" in str(exc_info.value)
        assert response.closed is True

    def test_list_records_rejects_content_length_over_page_limit(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_PAGE_BYTES", 8)
        response = FakeOAIResponse(
            headers={"Content-Length": "9"},
            chunks=[b"not-read"],
        )
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert response.iterated is False

    def test_list_records_rejects_aggregate_response_bytes(self, monkeypatch):
        first_body = _oai_page(["oai:x:p1"], token="T1")
        second_body = _oai_page(["oai:x:p2"], token=None)
        monkeypatch.setattr(
            oai_client, "_OAI_MAX_PAGE_BYTES", max(len(first_body), len(second_body))
        )
        monkeypatch.setattr(
            oai_client,
            "_OAI_MAX_HARVEST_BYTES",
            len(first_body) + len(second_body) - 1,
        )
        patcher, mock_get = patch_session_get(
            side_effect=[FakeOAIResponse(first_body), FakeOAIResponse(second_body)]
        )

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "aggregate" in str(exc_info.value)
        assert mock_get.call_count == 2

    def test_list_records_rejects_too_many_records(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_RECORDS", 1)
        response = FakeOAIResponse(_oai_page(["oai:x:1", "oai:x:2"], token=None))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "record-count" in str(exc_info.value)

    def test_list_records_rejects_oversized_record(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_RECORD_BYTES", 32)
        response = FakeOAIResponse(_oai_page(["oai:x:" + "x" * 100], token=None))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "per-record" in str(exc_info.value)

    def test_list_records_rejects_oversized_resumption_token(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESUMPTION_TOKEN_CHARS", 4)
        response = FakeOAIResponse(_oai_page(["oai:x:1"], token="12345"))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "resumption token" in str(exc_info.value)

    def test_fetch_updates_rejects_retained_result_over_limit(self, monkeypatch):
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", 1)
        record = _cmdi_record(identifier="oai:x:matching")

        with (
            patch_records(
                return_value=[record],
            ),
            pytest.raises(OAIProtocolError) as exc_info,
        ):
            fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert exc_info.value.error_code == "resource_limit"
        assert "retained-result" in str(exc_info.value)


class TestPageRecordRelease:
    """Each page's lxml records should be released before the next page is
    requested, so a multi-thousand-record harvest does not retain every
    prior page's parsed tree in memory for the whole run."""

    def test_second_page_record_is_still_usable_once_requested(self):
        """Positive control: releasing an earlier page must not corrupt the
        record the caller is actually reading now."""
        first_record = _cmdi_record(identifier="oai:x:p1")
        second_record = _cmdi_record(identifier="oai:x:p2")
        pages = [
            FakeOAIResponse(_page_with_records([first_record], token="T1")),
            FakeOAIResponse(_page_with_records([second_record], token="")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            records = list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        ids = [r.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier").text for r in records]
        assert ids == ["oai:x:p1", "oai:x:p2"]
        assert mock_get.call_count == 2


class TestContinuationFallbackClassification:
    """When the primary attempt's continuation token is rejected, only the
    fallback attempt's classifications may appear in the final result."""

    def test_fallback_discards_every_primary_classification(self):
        primary_matching = _cmdi_record(identifier="oai:x:primary-match")
        primary_deleted = _deleted_record("oai:x:primary-deleted")
        primary_nonmatching = _cmdi_record(identifier="oai:x:primary-nonmatch")
        for node in primary_nonmatching.xpath(".//*[local-name()='Institution']"):
            node.text = "Elsewhere University"
        primary_uncertain = _cmdi_record(identifier="oai:x:primary-uncertain")
        for node in primary_uncertain.xpath(".//*[local-name()='Institution']"):
            parent = node.getparent()
            assert parent is not None
            parent.remove(node)
        fallback_matching = _cmdi_record(identifier="oai:x:fallback-match")

        pages = [
            FakeOAIResponse(
                _page_with_records(
                    [
                        primary_matching,
                        primary_deleted,
                        primary_nonmatching,
                        primary_uncertain,
                    ],
                    token="T-bad",
                )
            ),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(_page_with_records([fallback_matching], token=None)),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:fallback-match"]
        assert result.deleted_uuids == set()
        assert result.nonmatching_uuids == set()
        assert result.uncertain_records == {}
        assert mock_get.call_count == 3

    def test_uninterrupted_harvest_keeps_its_own_classifications(self):
        """Positive control: without a continuation rejection, a single
        successful attempt's classifications are exactly what is returned."""
        matching = _cmdi_record(identifier="oai:x:only-match")
        pages = [FakeOAIResponse(_page_with_records([matching], token=None))]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:only-match"]
        assert mock_get.call_count == 1


class TestContinuationFallbackBudgetAccounting:
    """The fallback attempt shares one _HarvestBudget with the discarded
    primary attempt: response bytes, record count and the absolute deadline
    stay cumulative, but the retained-result budget only ever sees the
    surviving attempt's records."""

    def test_response_bytes_record_count_and_deadline_stay_cumulative(self, monkeypatch):
        primary_record = _cmdi_record(identifier="oai:x:primary")
        fallback_record = _cmdi_record(identifier="oai:x:fallback")
        primary_page = _page_with_records([primary_record], token="T-bad")
        error_page = _oai_error_page("badResumptionToken", "rejected")
        fallback_page = _page_with_records([fallback_record], token=None)
        pages = [
            FakeOAIResponse(primary_page),
            FakeOAIResponse(error_page),
            FakeOAIResponse(fallback_page),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        captured_budget = oai_client._HarvestBudget.start()
        monkeypatch.setattr(oai_client._HarvestBudget, "start", lambda: captured_budget)
        deadline_before = captured_budget.deadline

        with patcher:
            fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert mock_get.call_count == 3
        assert captured_budget.record_count == 2
        assert captured_budget.response_bytes == (
            len(primary_page) + len(error_page) + len(fallback_page)
        )
        assert captured_budget.deadline == deadline_before

    def test_discarded_primary_result_bytes_are_never_counted_against_the_fallback(
        self, monkeypatch
    ):
        """A retained-result limit sized for exactly one matching record's
        encoded bytes is not exceeded by the fallback attempt — proving the
        discarded primary attempt's would-be result bytes were never added."""
        primary_record = _cmdi_record(identifier="oai:x:primary")
        fallback_record = _cmdi_record(identifier="oai:x:fallback")
        pages = [
            FakeOAIResponse(_page_with_records([primary_record], token="T-bad")),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(_page_with_records([fallback_record], token=None)),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        probe_budget = oai_client._HarvestBudget.start()
        parsed = oai_client._parse_cmdi_to_dict(fallback_record)
        parsed["uuid"] = "oai:x:fallback"
        probe_budget.consume_result(parsed)
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", probe_budget.result_bytes)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:fallback"]
        assert mock_get.call_count == 3

    def test_discarded_primary_result_bytes_would_overflow_a_limit_sized_for_one(self, monkeypatch):
        """Positive control for the assertion above: a limit sized for one
        record really is exceeded once two records' worth are counted, so
        the passing test above is not just a generously large limit."""
        record_a = _cmdi_record(identifier="oai:x:a")
        record_b = _cmdi_record(identifier="oai:x:b")
        probe_budget = oai_client._HarvestBudget.start()
        parsed_a = oai_client._parse_cmdi_to_dict(record_a)
        parsed_a["uuid"] = "oai:x:a"
        probe_budget.consume_result(parsed_a)
        one_record_limit = probe_budget.result_bytes
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", one_record_limit)

        pages = [
            FakeOAIResponse(_page_with_records([record_a, record_b], token=None)),
        ]
        patcher, _mock_get = patch_session_get(side_effect=pages)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert exc_info.value.error_code == "resource_limit"


class TestContinuationFallbackPerRecordFiltering:
    """The since-boundary filter applied to the fallback attempt's records
    rejects each record independently, before duplicate-identity or result
    accounting ever sees it."""

    def test_a_stale_duplicate_is_filtered_before_duplicate_identity_accounting(self):
        stale_duplicate = _set_datestamp(
            _cmdi_record(identifier="oai:x:dup"), "2020-01-01T00:00:00Z"
        )
        kept = _cmdi_record(identifier="oai:x:dup")  # sample's own later datestamp
        pages = [
            FakeOAIResponse(
                _page_with_records([_cmdi_record(identifier="oai:x:primary")], token="T-bad")
            ),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(_page_with_records([stale_duplicate, kept], token=None)),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:dup"]
        assert mock_get.call_count == 3

    def test_two_surviving_duplicates_still_raise(self):
        """Positive control: the filter itself is not what suppresses
        duplicate-identity accounting in general — two records that both
        survive the since-boundary and share an identity still raise."""
        first = _cmdi_record(identifier="oai:x:dup2")
        second = _cmdi_record(identifier="oai:x:dup2")
        pages = [
            FakeOAIResponse(
                _page_with_records([_cmdi_record(identifier="oai:x:primary")], token="T-bad")
            ),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(_page_with_records([first, second], token=None)),
        ]
        patcher, _mock_get = patch_session_get(side_effect=pages)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert exc_info.value.error_code == "duplicate_identifier"
