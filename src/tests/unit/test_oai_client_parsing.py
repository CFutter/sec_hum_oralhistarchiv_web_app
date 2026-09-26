"""Unit tests for the OAI-PMH client's classification and CMDI-record
parsing surface.

No database and no network are used. Classification tests patch the record
iterator with hand-built lxml elements; parsing tests feed hand-built or
mutated CMDI XML straight into the record parser.
"""

import logging
from unittest.mock import ANY, create_autospec, patch

import pytest
from lxml import etree

from app.services import oai_client
from app.services.oai_client import (
    _CMDI_PARSERS,
    _EXPECTED_CMDI_PROFILE,
    OAI_NS,
    HarvestResult,
    OAIProtocolError,
    _parse_cmdi_to_dict,
    fetch_updates,
)
from config import settings
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    patch_records,
)

_CMDP_NS = {"cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562"}

OAI_URL = "http://oai.example/oai"
SINCE = "2026-01-01"

SAMPLE_UUID = "oai:swissubase.ch:test-uuid-xml"


def _elements(node: etree._Element, xpath: str, namespaces: dict[str, str]) -> list[etree._Element]:
    """xpath() returning elements, narrowed.

    lxml types xpath() as bool|float|str|bytes|list[...] because XPath can
    evaluate to a scalar. Every call in this file selects element nodes, so
    narrow once here instead of casting at each site.
    """
    result = node.xpath(xpath, namespaces=namespaces)
    assert isinstance(result, list)
    return [n for n in result if isinstance(n, etree._Element)]


def _cmdi_record(
    institutions: list[str] | None = None,
    *,
    identifier: str = SAMPLE_UUID,
) -> etree._Element:
    """Parse SAMPLE_CMDI_XML; optionally replace its <cmdp:Institution> list.

    institutions=None keeps the sample's originals ('Universität Kassel',
    'University of Zurich'); [] removes them all; a list swaps them out.
    """
    rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
    identifier_node = rec.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier")
    assert identifier_node is not None
    identifier_node.text = identifier
    if institutions is not None:
        nodes = _elements(rec, ".//cmdp:Institution", namespaces=_CMDP_NS)
        parent = nodes[0].getparent()
        assert parent is not None  # Institution nodes always have a parent here
        for node in nodes:
            parent.remove(node)
        for name in institutions:
            el = etree.SubElement(parent, f"{{{_CMDP_NS['cmdp']}}}Institution")
            el.text = name
    return rec


def _deleted_record(identifier: str = "oai:x:1") -> etree._Element:
    """A deleted-status OAI record (header/identifier in the OAI namespace)."""
    xml = (
        f'<record xmlns="{OAI_NS}">'
        f'<header status="deleted"><identifier>{identifier}</identifier></header>'
        "</record>"
    )
    return etree.fromstring(xml.encode())


def _record(
    *,
    deleted: bool = False,
    identifier: str | None = "  oai:test:spaced \n",
) -> etree._Element:
    """A record for exercising identifier extraction: a missing identifier
    element, a blank one, or a normal one, live or deleted."""
    record = etree.fromstring(SAMPLE_CMDI_XML.encode())
    header = record.find(f"{{{oai_client.OAI_NS}}}header")
    assert header is not None
    element = header.find(f"{{{oai_client.OAI_NS}}}identifier")
    assert element is not None

    if identifier is None:
        header.remove(element)
    else:
        element.text = identifier

    if deleted:
        header.set("status", "deleted")

    return record


class TestInstitutionClassification:
    """fetch_updates classifies each harvested record as matching,
    nonmatching, deleted, or uncertain based on its institution metadata."""

    @pytest.mark.parametrize(
        "institutions",
        [[], [""], [" \t "]],
        ids=["missing", "empty", "whitespace"],
    )
    def test_fetch_updates_classifies_missing_or_blank_institutions_as_uncertain(
        self,
        institutions,
        caplog,
    ):
        record = _cmdi_record(institutions=institutions)

        with (
            patch_records(
                return_value=[record],
            ),
            caplog.at_level(
                logging.INFO,
                logger="app.services.oai_client",
            ),
        ):
            results = fetch_updates(
                OAI_URL,
                SINCE,
                settings.oai_institution_filter,
            )

        assert results == HarvestResult(
            source_cursor=SOURCE_CURSOR,
            uncertain_records={
                SAMPLE_UUID: "missing or unusable institution metadata",
            },
        )
        assert "0 matching, 0 deleted, 0 nonmatching, 1 uncertain" in caplog.text

    def test_fetch_updates_classifies_a_mixed_stream(self, caplog):
        stream = [
            _cmdi_record(identifier="oai:x:matching"),
            _cmdi_record(
                institutions=["Elsewhere Institute"],
                identifier="oai:x:nonmatching",
            ),
            _cmdi_record(institutions=[], identifier="oai:x:missing"),
            _cmdi_record(institutions=[" \t "], identifier="oai:x:blank"),
            _deleted_record("oai:x:deleted"),
        ]

        with (
            patch_records(
                return_value=stream,
            ),
            caplog.at_level(
                logging.INFO,
                logger="app.services.oai_client",
            ),
        ):
            results = fetch_updates(
                OAI_URL,
                SINCE,
                settings.oai_institution_filter,
            )

        assert [record["uuid"] for record in results.matching_records] == ["oai:x:matching"]
        assert results.deleted_uuids == {"oai:x:deleted"}
        assert results.nonmatching_uuids == {"oai:x:nonmatching"}
        assert results.uncertain_records == {
            "oai:x:missing": "missing or unusable institution metadata",
            "oai:x:blank": "missing or unusable institution metadata",
        }
        assert "1 matching, 1 deleted, 1 nonmatching, 2 uncertain" in caplog.text

    def test_fetch_updates_classifies_nonmatching_institution(self, caplog):
        """A definite nonmatch remains distinguishable from uncertain metadata."""
        record = _cmdi_record(institutions=["Elsewhere Institute"])
        with (
            patch_records(return_value=[record]),
            caplog.at_level(logging.INFO, logger="app.services.oai_client"),
        ):
            results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert results == HarvestResult(
            source_cursor=SOURCE_CURSOR, nonmatching_uuids={SAMPLE_UUID}
        )
        assert "0 matching, 0 deleted, 1 nonmatching, 0 uncertain" in caplog.text

    def test_fetch_updates_classifies_deleted_record_without_parsing_metadata(self):
        with (
            patch_records(
                return_value=[_deleted_record()],
            ),
            patch("app.services.oai_client._parse_cmdi_to_dict", autospec=True) as parse,
        ):
            results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert results == HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"oai:x:1"})
        parse.assert_not_called()

    def test_fetch_updates_keeps_record_matching_filter_case_insensitively(self):
        """An institution matching the filter via casefold substring keeps
        the record — and the returned dict having 'title'/'uuid' proves the
        non-deleted path assigns parsed = _parse_cmdi_to_dict(...) before use."""
        record = _cmdi_record()  # institutions include 'Universität Kassel'
        # Upper-cased filter still matches 'Universität Kassel' via casefold.
        shouty_filter = settings.oai_institution_filter.upper()

        with patch_records(return_value=[record]) as mock_list:
            results = fetch_updates(OAI_URL, SINCE, shouty_filter)

        assert results.deleted_uuids == set()
        assert results.nonmatching_uuids == set()
        assert results.uncertain_records == {}
        assert len(results.matching_records) == 1
        parsed = results.matching_records[0]
        assert parsed["uuid"] == SAMPLE_UUID
        assert parsed["title"] == "Test Dataset Title"
        # Order-preserving institutions straight from the sample record.
        assert parsed["institutions"] == ["Universität Kassel", "University of Zurich"]
        # fetch_updates harvests with the CMDI 1.2 metadata prefix.
        mock_list.assert_called_once_with(OAI_URL, "oai_cmdi12", SINCE, budget=ANY)

    @pytest.mark.parametrize(
        "institution_matches",
        [False, True],
        ids=[
            "nonmatching_institution_skips_title_validation",
            "matching_institution_runs_title_validation",
        ],
    )
    def test_institution_match_is_decided_before_title_validation_runs(
        self, institution_matches, caplog
    ):
        """A blank/duplicate title only turns a record uncertain when its
        institution matched the filter first — for a nonmatching institution
        the record is classified nonmatching, and `_parse_cmdi_to_dict` (so
        the title validator) never runs at all."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        for node in record.xpath(".//*[local-name()='Institution']"):
            node.text = (
                settings.oai_institution_filter if institution_matches else "Elsewhere University"
            )
        for node in record.xpath(".//*[local-name()='Dataset_title']"):
            node.text = " "

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        if institution_matches:
            assert results.nonmatching_uuids == set()
            assert results.uncertain_records[SAMPLE_UUID] == (
                "malformed_record: Blank or duplicate CMDI dataset title"
            )
            assert results.uncertain_records[SAMPLE_UUID] in caplog.text
        else:
            assert results.nonmatching_uuids == {SAMPLE_UUID}
            assert results.uncertain_records == {}


class TestUncertainRecordDiagnostics:
    """`fetch_updates` never raises out of its per-record classification
    loop: any `OAIProtocolError`/`ValueError` from institution detection or
    record parsing is caught and turned into a bounded, value-free entry in
    `uncertain_records` via `_metadata_diagnostic`."""

    def test_unrecognized_profile_is_uncertain_not_authoritative(self):
        """A record carrying metadata from an unrelated, unrecognized CMDI
        profile is quarantined as uncertain — it must not be treated as a
        confident nonmatch (which would let a full rebuild delete it as no
        longer offered) nor silently dropped."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        for node in record.xpath(".//*[local-name()='Institution']"):
            node.text = "Elsewhere University"
        components = record.xpath(".//*[local-name()='Components']")[0]
        etree.SubElement(components, "{urn:unknown-profile}Dataset")

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        assert results.nonmatching_uuids == set()
        assert "unsupported_metadata_profile" in next(iter(results.uncertain_records.values()))

    def test_validation_diagnostic_reports_field_and_type_without_record_values(self, caplog):
        """`_metadata_diagnostic` reports the failing field path and pydantic
        error type, bounded to 500 characters, but never the offending field
        value — a record value can be arbitrarily long or sensitive and must
        not leak into logs or the stored diagnostic."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        canary = "CONFIDENTIAL-CONTENT-" * 30
        for node in record.xpath(".//*[local-name()='Keywords']"):
            node.text = canary

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, settings.oai_institution_filter)

        reason = next(iter(results.uncertain_records.values()))
        assert "keywords: value_error" in reason
        assert len(reason) <= 500
        assert reason in caplog.text
        assert canary not in reason + caplog.text


class TestIdentifierHandling:
    """Every record in a harvest must carry exactly one usable identifier,
    and no identifier may repeat within a harvest — live or deleted."""

    def test_live_and_deleted_duplicate_identity_rejects_whole_harvest(self, monkeypatch):
        monkeypatch.setattr(
            oai_client,
            "_oai_list_records",
            create_autospec(
                oai_client._oai_list_records,
                side_effect=lambda *_args, **_kwargs: iter([_record(), _record(deleted=True)]),
            ),
        )

        with pytest.raises(oai_client.OAIProtocolError, match="duplicate_identifier"):
            oai_client.fetch_updates("https://example.test/oai", "1900-01-01", "Kassel")

    @pytest.mark.parametrize("deleted", [False, True], ids=["live", "deleted"])
    @pytest.mark.parametrize(
        "identifier",
        [None, "", " \t\n"],
        ids=["missing_element", "empty_text", "whitespace_only"],
    )
    def test_missing_identity_rejects_the_whole_harvest(self, monkeypatch, deleted, identifier):
        records = [
            _record(identifier="valid"),
            _record(deleted=deleted, identifier=identifier),
        ]
        monkeypatch.setattr(
            oai_client,
            "_oai_list_records",
            create_autospec(
                oai_client._oai_list_records,
                side_effect=lambda *_args, **_kwargs: iter(records),
            ),
        )

        with pytest.raises(oai_client.OAIProtocolError) as caught:
            oai_client.fetch_updates(
                "https://example.test/oai",
                "1900-01-01",
                "Kassel",
            )

        assert caught.value.error_code == "malformed_record"


class TestResourceProxyUrlSafety:
    """Upstream URLs feeding an href (license, resource-proxy ref) go through
    _safe_url before being stored; unsafe schemes become None."""

    def test_parse_rejects_unsafe_urls_at_ingest(self):
        """javascript:/data: URLs from upstream data are stored as None,
        not persisted verbatim (stored-XSS defence-in-depth). Both the license
        URL and the resource-proxy ref go through _safe_url; a benign https
        link survives (positive control)."""
        xml = SAMPLE_CMDI_XML.replace("https://example.com/license", "javascript:alert(1)").replace(
            "https://example.com/download", "data:text/html,<script>alert(1)</script>"
        )
        parsed = _parse_cmdi_to_dict(etree.fromstring(xml.encode()))

        assert parsed["license_url"] is None  # javascript: rejected
        resource_refs = [p["ref"] for p in parsed["resource_proxies"] if p["type"] == "Resource"]
        assert resource_refs == [None]  # data: rejected, proxy still present
        # Positive control: the untouched landing-page https URL survives.
        landing = [p["ref"] for p in parsed["resource_proxies"] if p["type"] == "LandingPage"]
        assert landing == ["https://example.com/doi/10.1234"]

    def _cmdi_with_license_url(self, license_url: str):
        """Sample record with the LicenseURL swapped, to drive _safe_url (the
        upstream-URL guard feeding the 'license_url' output field). The
        sibling DOI-ingest guard (_get_doi) is pinned in
        tests/unit/test_parsing_units.py."""
        rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
        node = _elements(rec, ".//cmdp:LicenseURL", namespaces=_CMDP_NS)[0]
        node.text = license_url
        return rec

    def test_parse_rejects_unsafe_license_url(self, caplog):
        """A javascript: (or any non-http[s]) LicenseURL must be rejected by
        _safe_url -> the license_url field is None, and the rejection is
        logged. Prevents an executable URI reaching an href in the template."""
        rec = self._cmdi_with_license_url("javascript:alert(document.cookie)")
        with caplog.at_level(logging.WARNING, logger="app.services.oai_client"):
            parsed = _parse_cmdi_to_dict(rec)

        assert parsed.get("license_url") is None
        assert any("unsafe url" in r.getMessage().lower() for r in caplog.records)


class TestResourceProxyParsing:
    """A single malformed <ResourceProxy> must not sink parsing of the rest
    of the record."""

    def test_malformed_resource_proxy_does_not_crash_whole_record(self):
        """A ResourceProxy missing its ResourceType/ResourceRef
        is skipped with a warning, and the rest of the record still parses —
        one bad proxy must not sink an entire dataset's ingest."""
        broken = (
            '<cmd:ResourceProxy id="bad" '
            'xmlns:cmd="http://www.clarin.eu/cmd/1">'
            "<cmd:ResourceType>Resource</cmd:ResourceType>"
            "</cmd:ResourceProxy>"  # no ResourceRef
        )
        xml = SAMPLE_CMDI_XML.replace(
            '<cmd:ResourceProxy id="res_1">', broken + '<cmd:ResourceProxy id="res_1">'
        )
        parsed = _parse_cmdi_to_dict(etree.fromstring(xml.encode()))

        assert parsed["uuid"] == SAMPLE_UUID  # record still parsed
        # The valid proxies survive; the malformed one was dropped.
        types = [p["type"] for p in parsed["resource_proxies"]]
        assert "Resource" in types and "LandingPage" in types

    def test_parse_skips_malformed_resource_proxy(self, caplog):
        """A ResourceProxy missing its ResourceType or ResourceRef is skipped
        (logged), and parsing continues for the well-formed proxies — a single
        malformed upstream node must not abort the whole record."""
        rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
        proxy_list = _elements(rec, ".//*[local-name()='ResourceProxyList']", namespaces={})[0]
        cmd_ns = proxy_list.nsmap.get("cmd", "http://www.clarin.eu/cmd/1")
        etree.SubElement(proxy_list, f"{{{cmd_ns}}}ResourceProxy")

        with caplog.at_level(logging.WARNING, logger="app.services.oai_client"):
            parsed = _parse_cmdi_to_dict(rec)

        # The record still parses (well-formed proxies preserved), and the
        # malformed one produced a skip warning rather than an exception.
        assert "resource_proxies" in parsed
        assert any("malformed resourceproxy" in r.getMessage().lower() for r in caplog.records)


class TestCmdiProfileDrift:
    """Upstream silently changing its CMDI profile must raise instead of
    degrading field extraction, but the expected profile stays silent."""

    def _cmdi_with_profile(self, profile: str) -> etree._Element:
        """SAMPLE_CMDI_XML ships without a <cmd:MdProfile>; insert a
        <cmd:Header><cmd:MdProfile> block immediately after the <cmd:CMD ...>
        opening tag (where the cmd: prefix is declared) so the drift check in
        _parse_cmdi_to_dict has a node to inspect."""
        header = f"<cmd:Header><cmd:MdProfile>{profile}</cmd:MdProfile></cmd:Header>"
        xml = SAMPLE_CMDI_XML.replace("<cmd:Resources>", header + "<cmd:Resources>", 1)
        return etree.fromstring(xml.encode())

    def test_unsupported_cmdi_profile_raises(self):
        """Upstream changing its CMDI profile silently degrades field
        extraction — the drift needs to raise."""
        drifted = "clarin.eu:cr1:p_9999999999999"

        with pytest.raises(OAIProtocolError) as exc_info:
            _parse_cmdi_to_dict(self._cmdi_with_profile(drifted))

        assert exc_info.value.error_code == "unsupported_metadata_profile"
        assert drifted in str(exc_info.value)

    def test_expected_cmdi_profile_is_silent(self, caplog):
        """The shipped profile must NOT warn —
        otherwise every harvested record floods the log and operators learn to
        ignore the drift signal (alarm-fatigue: a warning that always fires
        becomes noise exactly when it matters)."""
        with caplog.at_level(logging.WARNING, logger="app.services.oai_client"):
            parsed = _parse_cmdi_to_dict(self._cmdi_with_profile(_EXPECTED_CMDI_PROFILE))

        assert not any("profile drift" in r.getMessage() for r in caplog.records)
        # The helper produced a normally-parseable record (guards the control
        # itself against silently exercising a broken document).
        assert parsed["uuid"] == SAMPLE_UUID

    def test_absent_profile_uses_recognized_profile_namespace(self):
        parsed = _parse_cmdi_to_dict(
            etree.fromstring(SAMPLE_CMDI_XML.encode()),
        )

        assert parsed["uuid"] == SAMPLE_UUID
        assert parsed["title"] == "Test Dataset Title"

    def test_profile_dispatch_returns_selected_parser_result(self, monkeypatch):
        expected = {
            "uuid": "dispatched-record",
            "institutions": ["Test Institution"],
        }

        parser = create_autospec(
            oai_client._parse_swissubase_cmdi_profile, spec_set=True, return_value=expected
        )
        monkeypatch.setitem(
            _CMDI_PARSERS,
            _EXPECTED_CMDI_PROFILE,
            parser,
        )

        record = self._cmdi_with_profile(_EXPECTED_CMDI_PROFILE)
        result = _parse_cmdi_to_dict(record)

        parser.assert_called_once_with(record)
        assert result is expected
