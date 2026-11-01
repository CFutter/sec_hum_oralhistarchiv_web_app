"""Unit tests for the OAI-PMH client's classification and CMDI-record parsing surface."""

import logging
from unittest.mock import ANY, create_autospec, patch

import pytest
from lxml import etree
from pydantic import ValidationError

from app.services.harvest import HarvestResult
from app.sources import oai_client
from app.sources.oai_client import (
    _CMDI_PARSERS,
    _EXPECTED_CMDI_PROFILE,
    OAI_NS,
    OAIProtocolError,
    _parse_cmdi_to_dict,
    fetch_updates,
)
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    patch_records,
)
from tests.source_fixtures import TEST_INSTITUTION_FILTER

_CMDP_NS = {"cmdp": "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562"}

OAI_URL = "http://oai.example/oai"
SINCE = "2026-01-01"

SAMPLE_UUID = "oai:swissubase.ch:test-uuid-xml"


def _elements(node: etree._Element, xpath: str, namespaces: dict[str, str]) -> list[etree._Element]:
    """Return XPath-selected elements, excluding scalar or non-element results."""
    result = node.xpath(xpath, namespaces=namespaces)
    assert isinstance(result, list)
    return [n for n in result if isinstance(n, etree._Element)]


def _cmdi_record(
    institutions: list[str] | None = None,
    *,
    identifier: str = SAMPLE_UUID,
) -> etree._Element:
    """Parse the sample CMDI; institutions=None preserves originals, while [] removes them."""
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
        """Check fetch updates classifies missing or blank institutions as uncertain."""
        record = _cmdi_record(institutions=institutions)

        with (
            patch_records(
                return_value=[record],
            ),
            caplog.at_level(
                logging.INFO,
                logger="app.sources.oai_client",
            ),
        ):
            results = fetch_updates(
                OAI_URL,
                SINCE,
                TEST_INSTITUTION_FILTER,
            )

        assert results == HarvestResult(
            source_cursor=SOURCE_CURSOR,
            uncertain_records={
                SAMPLE_UUID: "missing or unusable institution metadata",
            },
        )
        assert "0 matching, 0 deleted, 0 nonmatching, 1 uncertain" in caplog.text

    def test_fetch_updates_classifies_a_mixed_stream(self, caplog):
        """Check fetch updates classifies a mixed stream."""
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
                logger="app.sources.oai_client",
            ),
        ):
            results = fetch_updates(
                OAI_URL,
                SINCE,
                TEST_INSTITUTION_FILTER,
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
            caplog.at_level(logging.INFO, logger="app.sources.oai_client"),
        ):
            results = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert results == HarvestResult(
            source_cursor=SOURCE_CURSOR, nonmatching_uuids={SAMPLE_UUID}
        )
        assert "0 matching, 0 deleted, 1 nonmatching, 0 uncertain" in caplog.text

    def test_fetch_updates_classifies_deleted_record_without_parsing_metadata(self):
        """Check fetch updates classifies deleted record without parsing metadata."""
        with (
            patch_records(
                return_value=[_deleted_record()],
            ),
            patch("app.sources.oai_client._parse_cmdi_to_dict", autospec=True) as parse,
        ):
            results = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert results == HarvestResult(source_cursor=SOURCE_CURSOR, deleted_uuids={"oai:x:1"})
        parse.assert_not_called()

    def test_fetch_updates_keeps_record_matching_filter_case_insensitively(self):
        """Check fetch updates keeps record matching filter case insensitively."""
        record = _cmdi_record()
        shouty_filter = TEST_INSTITUTION_FILTER.upper()

        with patch_records(return_value=[record]) as mock_list:
            results = fetch_updates(OAI_URL, SINCE, shouty_filter)

        assert results.deleted_uuids == set()
        assert results.nonmatching_uuids == set()
        assert results.uncertain_records == {}
        assert len(results.matching_records) == 1
        parsed = results.matching_records[0]
        assert parsed["uuid"] == SAMPLE_UUID
        assert parsed["title"] == "Test Dataset Title"
        assert parsed["institutions"] == ["Universität Beispielstadt", "Example University"]
        mock_list.assert_called_once_with(
            OAI_URL,
            "oai_cmdi12",
            SINCE,
            max_pages=oai_client.OAI_DEFAULT_MAX_PAGES,
            budget=ANY,
        )

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
        """Check institution match is decided before title validation runs."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        for node in record.xpath(".//*[local-name()='Institution']"):
            node.text = TEST_INSTITUTION_FILTER if institution_matches else "Elsewhere University"
        for node in record.xpath(".//*[local-name()='Dataset_title']"):
            node.text = " "

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

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
    """Cover uncertain record diagnostics."""

    def test_unrecognized_profile_is_uncertain_not_authoritative(self):
        """Check unrecognized profile is uncertain not authoritative."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        for node in record.xpath(".//*[local-name()='Institution']"):
            node.text = "Elsewhere University"
        components = record.xpath(".//*[local-name()='Components']")[0]
        etree.SubElement(components, "{urn:unknown-profile}Dataset")

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert results.nonmatching_uuids == set()
        assert "unsupported_metadata_profile" in next(iter(results.uncertain_records.values()))

    def test_validation_diagnostic_reports_field_and_type_without_record_values(self, caplog):
        """Check validation diagnostic reports field and type without record values."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        canary = "CONFIDENTIAL-CONTENT-" * 30
        for node in record.xpath(".//*[local-name()='Keywords']"):
            node.text = canary

        with patch_records(return_value=[record]):
            results = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        reason = next(iter(results.uncertain_records.values()))
        assert "keywords: value_error" in reason
        assert len(reason) <= 500
        assert reason in caplog.text
        assert canary not in reason + caplog.text


class TestIdentifierHandling:
    """Every record in a harvest must carry exactly one usable identifier,
    and no identifier may repeat within a harvest — live or deleted."""

    def test_live_and_deleted_duplicate_identity_rejects_whole_harvest(self):
        """Check live and deleted duplicate identity rejects whole harvest."""
        with (
            patch_records(return_value=[_record(), _record(deleted=True)]),
            pytest.raises(oai_client.OAIProtocolError, match="duplicate_identifier"),
        ):
            oai_client.fetch_updates("https://example.test/oai", "1900-01-01", "Beispielstadt")

    @pytest.mark.parametrize("deleted", [False, True], ids=["live", "deleted"])
    @pytest.mark.parametrize(
        "identifier",
        [None, "", " \t\n"],
        ids=["missing_element", "empty_text", "whitespace_only"],
    )
    def test_missing_identity_rejects_the_whole_harvest(self, deleted, identifier):
        """Check missing identity rejects the whole harvest."""
        records = [
            _record(identifier="valid"),
            _record(deleted=deleted, identifier=identifier),
        ]
        with (
            patch_records(return_value=records),
            pytest.raises(oai_client.OAIProtocolError) as caught,
        ):
            oai_client.fetch_updates(
                "https://example.test/oai",
                "1900-01-01",
                "Beispielstadt",
            )

        assert caught.value.error_code == "malformed_record"


class TestResourceProxyUrlSafety:
    """Upstream URLs feeding an href (license, resource-proxy ref) go through
    _safe_url before being stored; unsafe schemes become None."""

    def test_parse_rejects_unsafe_urls_at_ingest(self):
        """Check parse rejects unsafe URLs at ingest."""
        xml = SAMPLE_CMDI_XML.replace("https://example.com/license", "javascript:alert(1)").replace(
            "https://example.com/download", "data:text/html,<script>alert(1)</script>"
        )
        parsed = _parse_cmdi_to_dict(etree.fromstring(xml.encode()))

        assert parsed["license_url"] is None
        resource_refs = [p["ref"] for p in parsed["resource_proxies"] if p["type"] == "Resource"]
        assert resource_refs == [None]
        landing = [p["ref"] for p in parsed["resource_proxies"] if p["type"] == "LandingPage"]
        assert landing == ["https://example.com/doi/10.1234"]

    def _cmdi_with_license_url(self, license_url: str):
        """Parse the sample CMDI with the selected LicenseURL replacement."""
        rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
        node = _elements(rec, ".//cmdp:LicenseURL", namespaces=_CMDP_NS)[0]
        node.text = license_url
        return rec

    def test_parse_rejects_unsafe_license_url(self, caplog):
        """A javascript: (or any non-http[s]) LicenseURL must be rejected by _safe_url -> the
        license_url field is None, and the rejection is logged.
        """
        rec = self._cmdi_with_license_url("javascript:alert(document.cookie)")
        with caplog.at_level(logging.WARNING, logger="app.sources.oai_client"):
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
            "</cmd:ResourceProxy>"
        )
        xml = SAMPLE_CMDI_XML.replace(
            '<cmd:ResourceProxy id="res_1">', broken + '<cmd:ResourceProxy id="res_1">'
        )
        parsed = _parse_cmdi_to_dict(etree.fromstring(xml.encode()))

        assert parsed["uuid"] == SAMPLE_UUID
        types = [p["type"] for p in parsed["resource_proxies"]]
        assert "Resource" in types and "LandingPage" in types

    def test_parse_skips_malformed_resource_proxy(self, caplog):
        """Check parse skips malformed resource proxy."""
        rec = etree.fromstring(SAMPLE_CMDI_XML.encode())
        proxy_list = _elements(rec, ".//*[local-name()='ResourceProxyList']", namespaces={})[0]
        cmd_ns = proxy_list.nsmap.get("cmd", "http://www.clarin.eu/cmd/1")
        etree.SubElement(proxy_list, f"{{{cmd_ns}}}ResourceProxy")

        with caplog.at_level(logging.WARNING, logger="app.sources.oai_client"):
            parsed = _parse_cmdi_to_dict(rec)

        assert "resource_proxies" in parsed
        assert any("malformed resourceproxy" in r.getMessage().lower() for r in caplog.records)


class TestCmdiProfileDrift:
    """Upstream silently changing its CMDI profile must raise instead of
    degrading field extraction, but the expected profile stays silent."""

    def _cmdi_with_profile(self, profile: str) -> etree._Element:
        """Insert the selected MdProfile into a new CMDI Header in the sample record."""
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
        """Check expected CMDI profile is silent."""
        with caplog.at_level(logging.WARNING, logger="app.sources.oai_client"):
            parsed = _parse_cmdi_to_dict(self._cmdi_with_profile(_EXPECTED_CMDI_PROFILE))

        assert not any("profile drift" in r.getMessage() for r in caplog.records)
        # The helper produced a normally-parseable record (guards the control
        # itself against silently exercising a broken document).
        assert parsed["uuid"] == SAMPLE_UUID

    def test_absent_profile_uses_recognized_profile_namespace(self):
        """Check absent profile uses recognized profile namespace."""
        parsed = _parse_cmdi_to_dict(
            etree.fromstring(SAMPLE_CMDI_XML.encode()),
        )

        assert parsed["uuid"] == SAMPLE_UUID
        assert parsed["title"] == "Test Dataset Title"

    def test_profile_dispatch_returns_selected_parser_result(self, monkeypatch):
        """Check profile dispatch returns selected parser result."""
        expected = {
            "uuid": "dispatched-record",
            "institutions": ["Test Institution"],
        }

        parser = create_autospec(
            oai_client._parse_supported_cmdi_profile, spec_set=True, return_value=expected
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


class TestValidatedDatasetTitle:
    """Extraction must use the dataset-title nodes that passed validation."""

    @pytest.mark.parametrize("parent_xpath", [".//cmdp:Project/cmdp:Overview", ".//cmdp:Dataset"])
    def test_misplaced_title_cannot_replace_the_validated_title(self, parent_xpath):
        """Check misplaced title cannot replace the validated title."""
        record = _cmdi_record()
        parent = _elements(record, parent_xpath, _CMDP_NS)[0]
        stray = etree.Element(f"{{{_CMDP_NS['cmdp']}}}Dataset_title")
        stray.text = "WRONG PROJECT LABEL"
        parent.insert(0, stray)

        parsed = _parse_cmdi_to_dict(record)

        assert parsed["title"] == "Test Dataset Title"

    @pytest.mark.parametrize("first_language", ["de", "en"], ids=["german-first", "english-first"])
    def test_first_validated_title_wins_and_is_trimmed(self, first_language):
        """Check first validated title wins and is trimmed."""
        record = _cmdi_record()
        title = _elements(record, ".//cmdp:Dataset/cmdp:Overview/cmdp:Dataset_title", _CMDP_NS)[0]
        title.text = "  First dataset title  "
        title.set("{http://www.w3.org/XML/1998/namespace}lang", first_language)
        second = etree.Element(f"{{{_CMDP_NS['cmdp']}}}Dataset_title")
        second.text = "Second dataset title"
        second.set(
            "{http://www.w3.org/XML/1998/namespace}lang", "en" if first_language == "de" else "de"
        )
        title.addnext(second)

        assert _parse_cmdi_to_dict(record)["title"] == "First dataset title"

    @pytest.mark.parametrize("damage", ["missing", "blank", "duplicate_language"])
    def test_misplaced_title_cannot_rescue_invalid_dataset_titles(self, damage):
        """Check misplaced title cannot rescue invalid dataset titles (OAIProtocolError)."""
        record = _cmdi_record()
        parent = _elements(record, ".//cmdp:Project/cmdp:Overview", _CMDP_NS)[0]
        stray = etree.Element(f"{{{_CMDP_NS['cmdp']}}}Dataset_title")
        stray.text = "Misplaced title"
        parent.insert(0, stray)
        title = _elements(record, ".//cmdp:Dataset/cmdp:Overview/cmdp:Dataset_title", _CMDP_NS)[0]
        if damage == "missing":
            title.getparent().remove(title)
        elif damage == "blank":
            title.text = "   "
        else:
            title.addnext(etree.fromstring(etree.tostring(title)))

        with pytest.raises(OAIProtocolError) as failure:
            _parse_cmdi_to_dict(record)
        assert failure.value.error_code == "malformed_record"

    def test_fetch_returns_the_validated_title(self):
        """Check fetch returns the validated title."""
        record = _cmdi_record()
        parent = _elements(record, ".//cmdp:Project/cmdp:Overview", _CMDP_NS)[0]
        stray = etree.Element(f"{{{_CMDP_NS['cmdp']}}}Dataset_title")
        stray.text = "WRONG PROJECT LABEL"
        parent.insert(0, stray)

        with patch_records(return_value=[record]):
            result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

        assert result.matching_records[0]["title"] == "Test Dataset Title"
        assert result.uncertain_records == {}


@pytest.mark.parametrize("length", [4096, 4097])
def test_cmdi_project_titles_retain_the_source_character_cap(length):
    """Keep the CMDI 4096-character boundary despite the shared feed ceiling."""
    record = _cmdi_record()
    project_title = _elements(record, ".//cmdp:Project_title[@xml:lang='en']", _CMDP_NS)[0]
    project_title.text = "é" * length
    if length == 4096:
        assert _parse_cmdi_to_dict(record)["project_title"] == project_title.text
    else:
        with pytest.raises(ValidationError) as rejected:
            _parse_cmdi_to_dict(record)
        assert oai_client._metadata_diagnostic(rejected.value) == (
            "record_validation: project_title: string_too_long"
        )


def test_oversized_cmdi_project_title_quarantines_only_its_record(caplog):
    """Preserve the metadata-validation reason and valid neighbouring OAI records."""
    invalid = _cmdi_record(identifier="oai:x:oversized")
    title = _elements(invalid, ".//cmdp:Project_title[@xml:lang='en']", _CMDP_NS)[0]
    title.text = "private-project-title-canary" * 200
    valid = _cmdi_record(identifier="oai:x:valid")

    with patch_records(return_value=[invalid, valid]):
        result = fetch_updates(OAI_URL, SINCE, TEST_INSTITUTION_FILTER)

    assert [record["uuid"] for record in result.matching_records] == ["oai:x:valid"]
    assert result.uncertain_records == {
        "oai:x:oversized": "record_validation: project_title: string_too_long"
    }
    assert "private-project-title-canary" not in caplog.text
