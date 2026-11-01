"""Unit tests for the bounded OAI-PMH client's HTTP/protocol layer."""

import time
from datetime import timedelta
from http import HTTPStatus

import pytest
from lxml import etree

from app.sources import oai_client
from app.sources.oai_client import (
    OAI_NS,
    OAI_REQUEST_TIMEOUT,
    OAIProtocolError,
    _build_session,
    _make_safe_parser,
    _oai_list_records,
    fetch_updates,
)
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    FakeOAIResponse,
    patch_records,
    patch_session_get,
)
from tests.source_fixtures import TEST_INSTITUTION_FILTER

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
    """Build an OAI error-response page with the selected code and message."""
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
        """The session's HTTPAdapter retries transient upstream blips (429/5xx) rather than failing a
        whole sync run on the first hiccup.
        """
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
        """Check xxe external entity is not resolved."""
        secret_path = tmp_path / "secret.txt"
        secret_path.write_text("TOP-SECRET-XXE-PAYLOAD")
        malicious = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{secret_path}">]>'
            "<root><value>&xxe;</value></root>"
        ).encode()
        parser = _make_safe_parser()
        tree = etree.fromstring(malicious, parser=parser)
        assert "TOP-SECRET-XXE-PAYLOAD" not in (tree.findtext("value") or "")
        assert "TOP-SECRET-XXE-PAYLOAD" not in etree.tostring(tree, encoding="unicode")


class TestProtocolErrorMapping:
    """Upstream OAI-PMH errors and malformed bodies become a structured
    OAIProtocolError without disclosing upstream detail text."""

    def test_pagination_cap_does_not_disclose_last_token(self):
        """Check pagination cap does not disclose last token (OAIProtocolError)."""
        secret_token = "upstream-secret-token"
        response = FakeOAIResponse(
            _oai_page(["oai:x:p1"], token=secret_token),
        )
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE, max_pages=1))

        assert exc_info.value.error_code == "pagination_loop"
        assert secret_token not in str(exc_info.value)

    def test_oai_error_text_is_not_propagated(self):
        """Check OAI error text is not propagated (OAIProtocolError)."""
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
        """Check list records non OAI 200 body raises protocol error (OAIProtocolError)."""
        body = b"<html><body>Service temporarily unavailable</body></html>"
        patcher, _mock_get = patch_session_get(
            return_value=FakeOAIResponse(body),
        )

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "malformed_response"

    def test_list_records_malformed_second_page_raises(self):
        """Check list records malformed second page raises (OAIProtocolError)."""
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
        """Check list records truncated body raises into failure path."""
        body = b'<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/"><ListRec'
        patcher, _mock_get = patch_session_get(return_value=FakeOAIResponse(body))
        with patcher, pytest.raises(etree.XMLSyntaxError):
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))


@pytest.mark.parametrize(
    "payload,error_code",
    [
        ("<ListRecords/><ListRecords/>", "malformed_response"),
        ('<error code="noRecordsMatch"/><ListRecords/>', "malformed_response"),
        (
            '<error code="noRecordsMatch"/><error code="badArgument"/>',
            "upstream_error",
        ),
        (
            "<ListRecords><record/><resumptionToken/>"
            "<resumptionToken>next-page</resumptionToken></ListRecords>",
            "malformed_response",
        ),
    ],
)
def test_ambiguous_first_page_never_yields_records_or_establishes_cursor(payload, error_code):
    """Check ambiguous first page never yields records or establishes cursor (OAIProtocolError)."""
    body = (
        f'<OAI-PMH xmlns="{OAI_NS}">'
        "<responseDate>2026-09-10T12:00:00Z</responseDate>"
        f"{payload}</OAI-PMH>"
    ).encode()
    budget = oai_client._HarvestBudget.start()
    patcher, get = patch_session_get(return_value=FakeOAIResponse(body))
    with patcher, pytest.raises(OAIProtocolError) as error:
        next(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE, budget=budget))
    assert error.value.error_code == error_code
    assert budget.source_cursor is None
    assert budget.record_count == 0
    assert get.call_count == 1


def test_ambiguous_continuation_never_yields_its_records_or_replaces_cursor():
    """Check ambiguous continuation never yields its records or replaces cursor (OAIProtocolError)."""
    ambiguous = _oai_page(["lost"], "").replace(
        b"</ListRecords>", b"<resumptionToken>next-page</resumptionToken></ListRecords>"
    )
    pages = [FakeOAIResponse(_oai_page(["first"], "next")), FakeOAIResponse(ambiguous)]
    budget = oai_client._HarvestBudget.start()
    patcher, get = patch_session_get(side_effect=pages)
    with patcher:
        records = _oai_list_records(OAI_URL, "oai_cmdi12", SINCE, budget=budget)
        assert next(records).findtext(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier") == "first"
        with pytest.raises(OAIProtocolError, match="Multiple OAI resumption tokens"):
            next(records)
    assert budget.source_cursor == SOURCE_CURSOR
    assert budget.record_count == 1
    assert get.call_count == 2


class TestPagination:
    """Resumption-token pagination and its safety cap."""

    def test_list_records_follows_resumption_token_across_pages(self):
        """Check list records follows resumption token across pages."""
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="")),
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

    def test_list_records_pagination_cap_raises_after_max_pages(self):
        """Check list records pagination cap raises after max pages (OAIProtocolError)."""
        pages = [
            FakeOAIResponse(_oai_page(["oai:x:p1"], token="T1")),
            FakeOAIResponse(_oai_page(["oai:x:p2"], token="T2")),
            FakeOAIResponse(_oai_page(["oai:x:p3"], token="T3")),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)
        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE, max_pages=3))

        assert exc_info.value.error_code == "pagination_loop"
        assert "T3" not in str(exc_info.value)
        assert mock_get.call_count == 3

    def test_list_records_repeated_resumption_token_raises_before_yielding_page(self):
        """Check list records repeated resumption token raises before yielding page (OAIProtocolError)."""
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
        """Check list records requires an explicit terminating token (OAIProtocolError)."""
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
        """Check response clock comes from first page not local or last clock."""
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
        """Check list records rejects redirect without following (OAIProtocolError)."""
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
        """A redirect turns the upstream catalogue into a way of choosing where the archive's server
        sends requests.
        """
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
        """Check list records applies transport policy on every page."""
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
        """Check list records rejects compression before reading body (OAIProtocolError)."""
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
        """Check list records rejects page over byte limit (OAIProtocolError)."""
        monkeypatch.setattr(oai_client, "_OAI_MAX_PAGE_BYTES", 8)
        response = FakeOAIResponse(chunks=[b"12345", b"6789"])
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "page" in str(exc_info.value)
        assert response.closed is True

    def test_list_records_rejects_content_length_over_page_limit(self, monkeypatch):
        """Check list records rejects content length over page limit (OAIProtocolError)."""
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
        """Check list records rejects aggregate response bytes (OAIProtocolError)."""
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
        """Check list records rejects too many records (OAIProtocolError)."""
        monkeypatch.setattr(oai_client, "_OAI_MAX_RECORDS", 1)
        response = FakeOAIResponse(_oai_page(["oai:x:1", "oai:x:2"], token=None))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "record-count" in str(exc_info.value)

    def test_list_records_rejects_oversized_record(self, monkeypatch):
        """Check list records rejects oversized record (OAIProtocolError)."""
        monkeypatch.setattr(oai_client, "_OAI_MAX_RECORD_BYTES", 32)
        response = FakeOAIResponse(_oai_page(["oai:x:" + "x" * 100], token=None))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "per-record" in str(exc_info.value)

    def test_list_records_rejects_oversized_resumption_token(self, monkeypatch):
        """Check list records rejects oversized resumption token (OAIProtocolError)."""
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESUMPTION_TOKEN_CHARS", 4)
        response = FakeOAIResponse(_oai_page(["oai:x:1"], token="12345"))
        patcher, _mock_get = patch_session_get(return_value=response)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            list(_oai_list_records(OAI_URL, "oai_cmdi12", SINCE))

        assert exc_info.value.error_code == "resource_limit"
        assert "resumption token" in str(exc_info.value)

    def test_fetch_updates_rejects_retained_result_over_limit(self, monkeypatch):
        """Check fetch updates rejects retained result over limit (OAIProtocolError)."""
        monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", 1)
        record = _cmdi_record(identifier="oai:x:matching")

        with (
            patch_records(
                return_value=[record],
            ),
            pytest.raises(OAIProtocolError) as exc_info,
        ):
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert exc_info.value.error_code == "resource_limit"
        assert "retained-result" in str(exc_info.value)


class TestPageRecordRelease:
    """Cover page record release."""

    def test_second_page_record_is_still_usable_once_requested(self):
        """Check second page record is still usable once requested."""
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


class TestExplicitPageLimits:
    """Public harvest calls own their pagination cap, including fallback."""

    def test_each_harvest_uses_its_own_page_limit(self) -> None:
        """Check each harvest uses its own page limit (OAIProtocolError)."""
        first_page = _page_with_records([_deleted_record("oai:x:first")], token="T1")
        final_page = _page_with_records([_deleted_record("oai:x:second")], token="")
        patcher, limited_get = patch_session_get(
            side_effect=[FakeOAIResponse(first_page), FakeOAIResponse(final_page)],
        )

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            fetch_updates(OAI_URL, SINCE, "Example University", max_pages=1)

        assert exc_info.value.error_code == "pagination_loop"
        assert limited_get.call_count == 1

        patcher, complete_get = patch_session_get(
            side_effect=[FakeOAIResponse(first_page), FakeOAIResponse(final_page)],
        )
        with patcher:
            result = fetch_updates(OAI_URL, SINCE, "Example University", max_pages=2)

        assert result.deleted_uuids == {"oai:x:first", "oai:x:second"}
        assert result.source_cursor == SOURCE_CURSOR
        assert complete_get.call_count == 2

    def test_fallback_uses_the_same_explicit_page_limit(self) -> None:
        """Check fallback uses the same explicit page limit (OAIProtocolError)."""
        pages = [
            FakeOAIResponse(
                _page_with_records([_deleted_record("oai:x:primary")], token="T-bad"),
            ),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(
                _page_with_records([_deleted_record("oai:x:fallback-one")], token="T1"),
            ),
            FakeOAIResponse(
                _page_with_records([_deleted_record("oai:x:fallback-two")], token="T2"),
            ),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher, pytest.raises(OAIProtocolError) as exc_info:
            fetch_updates(OAI_URL, SINCE, "Example University", max_pages=2)

        assert exc_info.value.error_code == "pagination_loop"
        assert mock_get.call_count == 4
        assert "from" not in mock_get.call_args_list[2].kwargs["params"]


class TestContinuationFallbackClassification:
    """When the primary attempt's continuation token is rejected, only the
    fallback attempt's classifications may appear in the final result."""

    def test_fallback_discards_every_primary_classification(self):
        """Check fallback discards every primary classification."""
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
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:fallback-match"]
        assert result.deleted_uuids == set()
        assert result.nonmatching_uuids == set()
        assert result.uncertain_records == {}
        assert mock_get.call_count == 3

    def test_uninterrupted_harvest_keeps_its_own_classifications(self):
        """Check uninterrupted harvest keeps its own classifications."""
        matching = _cmdi_record(identifier="oai:x:only-match")
        pages = [FakeOAIResponse(_page_with_records([matching], token=None))]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:only-match"]
        assert mock_get.call_count == 1


class TestContinuationFallbackBudgetAccounting:
    """Cover continuation fallback budget accounting."""

    def test_response_bytes_record_count_and_deadline_stay_cumulative(self, monkeypatch):
        """Check response bytes record count and deadline stay cumulative."""
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
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert mock_get.call_count == 3
        assert captured_budget.record_count == 2
        assert captured_budget.response_bytes == (
            len(primary_page) + len(error_page) + len(fallback_page)
        )
        assert captured_budget.deadline == deadline_before

    def test_discarded_primary_result_bytes_are_never_counted_against_the_fallback(
        self, monkeypatch
    ):
        """Check discarded primary result bytes are never counted against the fallback."""
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
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:fallback"]
        assert mock_get.call_count == 3

    def test_discarded_primary_result_bytes_would_overflow_a_limit_sized_for_one(self, monkeypatch):
        """Check discarded primary result bytes would overflow a limit sized for one
        (OAIProtocolError).
        """
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
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert exc_info.value.error_code == "resource_limit"


class TestContinuationFallbackPerRecordFiltering:
    """The since-boundary filter applied to the fallback attempt's records
    rejects each record independently, before duplicate-identity or result
    accounting ever sees it."""

    def test_a_stale_duplicate_is_filtered_before_duplicate_identity_accounting(self):
        """Check a stale duplicate is filtered before duplicate identity accounting."""
        stale_duplicate = _set_datestamp(
            _cmdi_record(identifier="oai:x:dup"), "2020-01-01T00:00:00Z"
        )
        kept = _cmdi_record(identifier="oai:x:dup")
        pages = [
            FakeOAIResponse(
                _page_with_records([_cmdi_record(identifier="oai:x:primary")], token="T-bad")
            ),
            FakeOAIResponse(_oai_error_page("badResumptionToken", "rejected")),
            FakeOAIResponse(_page_with_records([stale_duplicate, kept], token=None)),
        ]
        patcher, mock_get = patch_session_get(side_effect=pages)

        with patcher:
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert [r["uuid"] for r in result.matching_records] == ["oai:x:dup"]
        assert mock_get.call_count == 3

    def test_two_surviving_duplicates_still_raise(self):
        """Check two surviving duplicates still raise (OAIProtocolError)."""
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
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert exc_info.value.error_code == "duplicate_identifier"


class TestStreamingHarvest:
    """Protect page-by-page consumption and complete-attempt fallback semantics."""

    def test_first_page_is_classified_before_the_second_request(self, monkeypatch):
        """Check first page is classified before the second request."""
        parsed_ids = []
        parse = oai_client._parse_cmdi_to_dict

        def observed_parse(record):
            """Parse the record and retain its UUID to observe streaming progress."""
            parsed = parse(record)
            parsed_ids.append(parsed["uuid"])
            return parsed

        monkeypatch.setattr(oai_client, "_parse_cmdi_to_dict", observed_parse)
        pages = iter(
            [
                FakeOAIResponse(_page_with_records([_cmdi_record("first")], token="next")),
                FakeOAIResponse(_page_with_records([_cmdi_record("second")], token="")),
            ]
        )

        def get_page(*_args, **kwargs):
            """Return the next page, requiring first-page parsing before token continuation."""
            if "resumptionToken" in kwargs["params"]:
                assert parsed_ids == ["first"]
            return next(pages)

        patcher, _ = patch_session_get(side_effect=get_page)
        with patcher:
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)
        assert [record["uuid"] for record in result.matching_records] == ["first", "second"]

    @pytest.mark.parametrize("failure", ["duplicate", "missing_identifier", "result_limit"])
    def test_late_token_rejection_discards_classification_failure(self, monkeypatch, failure):
        """Check late token rejection discards classification failure."""
        primary = _cmdi_record("primary")
        fallback = _cmdi_record("fallback")
        primary_records = [primary]
        if failure == "duplicate":
            primary_records.append(_cmdi_record("primary"))
        elif failure == "missing_identifier":
            header = primary.find(f"{{{OAI_NS}}}header")
            assert header is not None
            identifier = header.find(f"{{{OAI_NS}}}identifier")
            assert identifier is not None
            header.remove(identifier)
        else:
            description = primary.find(
                f".//{{{oai_client._CMDI_NAMESPACES['cmdp']}}}Dataset_description"
            )
            assert description is not None
            description.text = "x" * 10000
            probe = oai_client._HarvestBudget.start()
            parsed = oai_client._parse_cmdi_to_dict(fallback)
            probe.consume_result(parsed)
            monkeypatch.setattr(oai_client, "_OAI_MAX_RESULT_BYTES", probe.result_bytes)

        fallback_page = _page_with_records([fallback], token=None).replace(
            b"2026-09-10T12:00:00Z", b"2026-09-11T12:00:00Z"
        )
        pages = [
            FakeOAIResponse(_page_with_records(primary_records, token="bad")),
            FakeOAIResponse(_oai_error_page("badResumptionToken")),
            FakeOAIResponse(fallback_page),
        ]
        patcher, get = patch_session_get(side_effect=pages)
        with patcher:
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)
        assert [record["uuid"] for record in result.matching_records] == ["fallback"]
        assert result.source_cursor == SOURCE_CURSOR + timedelta(days=1)
        assert get.call_count == 3

    def test_failed_attempt_output_is_released_before_retry(self, monkeypatch):
        """Check failed attempt output is released before retry."""
        attempts = []
        classify = oai_client._classify_oai_record

        def observed_classify(record, result, *args):
            """Retain each classification result before delegating to the real classifier."""
            attempts.append(result)
            return classify(record, result, *args)

        monkeypatch.setattr(oai_client, "_classify_oai_record", observed_classify)
        pages = iter(
            [
                FakeOAIResponse(_page_with_records([_cmdi_record("primary")], token="bad")),
                FakeOAIResponse(_oai_error_page("badResumptionToken")),
                FakeOAIResponse(_page_with_records([_cmdi_record("fallback")], token=None)),
            ]
        )
        requests = 0

        def get_page(*_args, **_kwargs):
            """Count requests and require failed-attempt output release before the third request."""
            nonlocal requests
            requests += 1
            if requests == 3:
                assert not attempts[0].matching_records
            return next(pages)

        patcher, _ = patch_session_get(side_effect=get_page)
        with patcher:
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)
        assert [record["uuid"] for record in result.matching_records] == ["fallback"]

    def test_unexpected_classification_error_closes_the_http_session(self, monkeypatch):
        """Check unexpected classification error closes the HTTP session (RuntimeError)."""

        def broken_classification(*_args):
            """Raise an unexpected classifier failure for session-cleanup testing."""
            raise RuntimeError("classification failed")

        monkeypatch.setattr(oai_client, "_classify_oai_record", broken_classification)
        patcher, get = patch_session_get(
            return_value=FakeOAIResponse(_page_with_records([_cmdi_record("first")], token="next"))
        )
        with patcher as factory, pytest.raises(RuntimeError, match="classification failed"):
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)
        factory.return_value.close.assert_called_once()
        assert get.call_count == 1

    def test_deferred_failure_drops_exception_chains_that_can_retain_xml(self, monkeypatch):
        """Check deferred failure drops exception chains that can retain XML (OAIProtocolError)."""

        def inner_failure():
            """Raise the inner parsing error used to build a retained exception chain."""
            raise ValueError("inner metadata failure")

        def broken_classification(*_args):
            """Wrap the inner parsing failure in a protocol error with an explicit cause."""
            try:
                inner_failure()
            except ValueError as cause:
                raise OAIProtocolError("malformed_record", "classification failed") from cause

        monkeypatch.setattr(oai_client, "_classify_oai_record", broken_classification)
        with (
            patch_records(return_value=[_cmdi_record("first")]),
            pytest.raises(OAIProtocolError) as failure,
        ):
            fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)
        assert failure.value.__cause__ is None
        assert failure.value.__context__ is None


@pytest.mark.parametrize(
    "field_path",
    [
        pytest.param("./oai:header/oai:identifier", id="identifier"),
        pytest.param(".//cmdp:Dataset_title", id="title"),
        pytest.param(".//cmdp:Dataset_description", id="description"),
        pytest.param(".//cmdp:Institution", id="institution"),
        pytest.param(".//cmdp:Author", id="author"),
        pytest.param(".//cmdp:Language_name", id="language"),
        pytest.param(".//cmdp:Keywords", id="keywords"),
        pytest.param(".//cmd:ResourceRef", id="resource-url"),
    ],
)
@pytest.mark.parametrize("kind", ["comment", "pi"])
@pytest.mark.parametrize("position", ["leading", "middle"])
def test_xml_comments_and_pis_preserve_catalogue_record(
    field_path: str, kind: str, position: str
) -> None:
    """Check XML comments and pis preserve catalogue record."""
    record = _cmdi_record()
    expected = oai_client._parse_cmdi_to_dict(record)
    namespaces = {
        "oai": OAI_NS,
        "cmd": "http://www.clarin.eu/cmd/1",
        "cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562",
    }
    node = record.find(field_path, namespaces)
    assert node is not None
    assert node.text
    text = node.text
    split_at = 0 if position == "leading" else len(text) // 2
    marker = (
        etree.Comment("editorial note")
        if kind == "comment"
        else etree.ProcessingInstruction("editor", "note")
    )
    node.text = text[:split_at]
    marker.tail = text[split_at:]
    node.insert(0, marker)

    response = FakeOAIResponse(_page_with_records([record], token=None))
    patcher, _ = patch_session_get(return_value=response)
    with patcher:
        result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

    assert result.matching_records == [expected]
    assert result.uncertain_records == {}
    assert result.nonmatching_uuids == set()
    assert result.deleted_uuids == set()
