"""Unit tests for the harvested-record-to-dataset-row pipeline.

Covers `app.services.schema` (`build_record_params`, `_canonicalize_doi`, the
column-list/dataclass sync validators), `app.services.datasets` (`_parse_dataset`
row robustness), and `app.services.oai_client` (CMDI parsing and OAI datestamp
decoding) as used on the ingest path.

Pure unit tier: no DB, no TestClient — everything here is a plain function
call on parsed XML / dict rows.
"""

import logging
from dataclasses import make_dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from lxml import etree
from pydantic import ValidationError

from app.doi import canonicalize_doi, doi_url
from app.services import datasets as datasets_module
from app.services import schema as schema_module
from app.services.datasets import (
    Author,
    _parse_dataset,
    validate_dataset_insert_schema,
    validate_dataset_schema,
)
from app.services.oai_client import OAIProtocolError, _parse_cmdi_to_dict, _parse_oai_datestamp
from app.services.parsed_record import validate_parsed_record
from app.services.schema import (
    DATASET_COLUMNS,
    DATASET_INSERT_COLUMNS,
    DATASET_INSERT_PLACEHOLDERS,
    DATASET_SELECT_COLUMNS,
    PARSER_OWNED,
    _canonicalize_doi,
    build_record_params,
)
from tests.oai_fixtures import SAMPLE_CMDI_XML, parsed_record

_DATESTAMP_ELEMENT = "<oai:datestamp>2026-03-06T13:38:02Z</oai:datestamp>"
# Unique substrings of the shared sample (tests.oai_fixtures.SAMPLE_CMDI_XML)
# used to splice in variants.
_DOI_ELEMENT = "<cmdp:DOI>https://doi.org/10.48656/test-xml</cmdp:DOI>"
_AUTHOR_BLOCK = "<cmdp:Author>Müller, Urs</cmdp:Author>\n<cmdp:Author>Keller, Anna</cmdp:Author>"
_INSTITUTION_BLOCK = (
    "<cmdp:Institution>Universität Kassel</cmdp:Institution>\n"
    "<cmdp:Institution>University of Zurich</cmdp:Institution>"
)
_LANGUAGE_BLOCK = (
    '<cmdp:Language_name xml:lang="en">English</cmdp:Language_name>\n'
    '<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>'
)
_DISCIPLINE_BLOCK = (
    '<cmdp:Main_discipline xml:lang="en">Linguistics</cmdp:Main_discipline>\n'
    '<cmdp:Main_discipline xml:lang="de">Linguistik</cmdp:Main_discipline>'
)


def _parse_xml(xml: str = SAMPLE_CMDI_XML) -> dict[str, Any]:
    """Parse a CMDI XML string exactly as the OAI client does."""
    return _parse_cmdi_to_dict(etree.fromstring(xml.encode()))


def _variant(old: str, new: str) -> dict[str, Any]:
    """Parse the sample with one unique block swapped for a variant."""
    assert old in SAMPLE_CMDI_XML  # guard against silent no-op replaces
    return _parse_xml(SAMPLE_CMDI_XML.replace(old, new))


def make_row(**overrides) -> dict[str, Any]:
    """A plausible oral_history_datasets row (psycopg dict_row shape)."""
    row = {
        "id": 1,
        "uuid": "row-uuid-1",
        "title": "A Title",
        "project_title": "A Project",
        "description": "desc",
        "resource_description": None,
        "languages": ["German"],
        "project_description": None,
        "authors": ["Jane Doe"],
        "keywords": ["kw"],
        "resource_proxies": [],
        "license_val": "License CC BY",
        "license_url": None,
        "access_level": "public",
        "version": "1.0",
        "doi": "10.1/x",
        "resource_type": "Corpus",
        "bibliographical_citation": None,
        "source": "swissubase",
        "visibility_tier": "public",
    }
    row.update(overrides)
    return row


class TestRecordParamsPresenceContract:
    """`build_record_params` distinguishes a MISSING parser key (a
    parser/profile drift bug) from a PRESENT key holding `None` (a
    legitimate optional field) — and the parser's actual output is exactly
    the key set `build_record_params` expects."""

    def test_missing_parser_key_raises_keyerror(self):
        """A record dict MISSING a PARSER_OWNED key (parser/profile drift)
        raises KeyError naming the missing key, instead of silently nulling
        the column across the catalogue."""
        rec = _parse_xml()
        del rec["license_val"]
        with pytest.raises(KeyError, match="license_val"):
            build_record_params(
                rec, access_level="public", source="swissubase", visibility_tier="public"
            )

    def test_none_value_on_a_present_key_is_null_not_error(self):
        """An optional field emitted as `None` (key PRESENT) is legitimate —
        no raise, and the doi slot of the params tuple (ordered by
        DATASET_INSERT_COLUMNS) is None, i.e. a NULL column."""
        rec = _parse_xml()
        rec["doi"] = None
        params = build_record_params(
            rec, access_level="public", source="swissubase", visibility_tier="public"
        )
        assert len(params) == len(DATASET_INSERT_COLUMNS)
        assert params[DATASET_INSERT_COLUMNS.index("doi")] is None

    def test_parser_owned_contract_matches_parser_output(self):
        """Import-time contract: PARSER_OWNED is exactly the key set that
        _parse_cmdi_to_dict emits. Confirmed directly against the source:
        resource_proxies IS in DATASET_COLUMNS, IS in schema.PARSER_OWNED
        (only access_level/source/visibility_tier are app-owned), and IS
        emitted by the parser — so the sets are equal with NO subtraction.
        Guards schema/parser divergence."""
        rec = _parse_xml()
        assert set(rec.keys()) == PARSER_OWNED
        # Redundant-but-explicit form of the invariant this test protects:
        # every parser-owned column is actually emitted by the parser.
        assert PARSER_OWNED - rec.keys() == set()


class TestCmdiParserRejectsStructuralDamage:
    """`_parse_cmdi_to_dict` only accepts a known-good CMDI profile: a
    Dataset/title that goes missing, duplicates or turns blank must fail the
    parse loudly rather than emit a partial or ambiguous record."""

    @pytest.mark.parametrize(
        "change",
        ["missing_dataset", "missing_title", "duplicate_title", "blank_title"],
        ids=["missing_dataset", "missing_title", "duplicate_title", "blank_title"],
    )
    def test_structurally_damaged_known_profile_record_is_rejected(self, change):
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        tag = "Dataset" if change == "missing_dataset" else "Dataset_title"
        node = record.xpath(f".//*[local-name()='{tag}']")[0]
        if change.startswith("missing"):
            node.getparent().remove(node)
        elif change == "duplicate_title":
            node.getparent().append(etree.fromstring(etree.tostring(node)))
        else:
            node.text = "   "

        with pytest.raises(OAIProtocolError):
            _parse_cmdi_to_dict(record)

    def test_undamaged_known_profile_record_parses(self):
        """Positive control: the unmodified sample record parses cleanly, so
        the rejections above are proven by the damage, not by a parser that
        rejects everything."""
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        parsed = _parse_cmdi_to_dict(record)
        assert parsed["title"]


class TestParsedRecordShapeContract:
    """`validate_parsed_record` (the `ParsedRecord` pydantic contract shared
    by ingestion and worker decoding) rejects structural drift in any
    parser-owned field."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("languages", "German"),
            ("authors", [123]),
            ("resource_proxies", [{}]),
            ("title", None),
            ("keywords", ["x" * 257]),
        ],
        ids=[
            "languages-not-a-list",
            "authors-non-string-entry",
            "resource_proxies-missing-required-keys",
            "title-none",
            "keywords-entry-over-max-length",
        ],
    )
    def test_shape_drift_in_a_parser_owned_field_is_rejected(self, field, value):
        record = parsed_record("id", **{field: value})
        with pytest.raises(ValidationError):
            validate_parsed_record(record)

    def test_well_formed_record_validates(self):
        """Positive control: an unmodified parser output validates cleanly."""
        validate_parsed_record(parsed_record("id"))


class TestDatasetColumnSchemaContract:
    """The dataset column-list <-> dataclass sync validators.

    These startup validators are the mechanism that makes "add a column in
    one place, forget the other" fail at boot instead of as a NULL-column or
    KeyError at runtime. The tests pin both the pass state and that drift is
    actually detected (a validator that never fires is a fail-open shape)."""

    def test_validators_pass_on_current_code(self):
        validate_dataset_schema()
        validate_dataset_insert_schema()

    def test_select_drift_is_detected(self, monkeypatch):
        """A column added to the SELECT list but not the dataclass must raise."""
        monkeypatch.setattr(
            datasets_module,
            "DATASET_SELECT_COLUMNS",
            [*DATASET_SELECT_COLUMNS, "bogus_col"],
        )
        with pytest.raises(AssertionError, match="bogus_col"):
            validate_dataset_schema()

    def test_dataclass_drift_is_detected(self, monkeypatch):
        """A SELECT column removed while the dataclass still has the field."""
        monkeypatch.setattr(
            datasets_module,
            "DATASET_SELECT_COLUMNS",
            [c for c in DATASET_SELECT_COLUMNS if c != "doi"],
        )
        with pytest.raises(AssertionError, match="doi"):
            validate_dataset_schema()

    def test_insert_constructor_drift_is_detected(self, monkeypatch):
        """A column added to the INSERT list without a corresponding value in
        build_record_params must fail at startup — the validator executes the
        real constructor, so its missing-column assertion fires (the
        record→tuple seam this validator exists for).

        Patches the SCHEMA module's DATASET_INSERT_COLUMNS (build_record_params
        lives there): the constructor iterates that list, finds no value for
        the bogus column, and raises its own defensive AssertionError naming
        it."""
        monkeypatch.setattr(
            schema_module,
            "DATASET_INSERT_COLUMNS",
            [*DATASET_INSERT_COLUMNS, "bogus_col"],
        )
        with pytest.raises(AssertionError, match="bogus_col"):
            validate_dataset_insert_schema()

    def test_insert_length_drift_is_detected(self, monkeypatch):
        """The emitted tuple must line up 1:1 with the column/placeholder list
        the rest of the code believes in — a length mismatch must raise.

        Patches the DATASETS module's DATASET_INSERT_COLUMNS: the validator's
        own length comparison (len(params) != len(DATASET_INSERT_COLUMNS))
        reads that namespace, so the tuple built from schema's unpatched list
        comes up one short and the "record→tuple drift" arm fires."""
        monkeypatch.setattr(
            datasets_module,
            "DATASET_INSERT_COLUMNS",
            [*DATASET_INSERT_COLUMNS, "bogus_col"],
        )
        with pytest.raises(AssertionError, match="drift"):
            validate_dataset_insert_schema()

    def test_schema_module_invariants(self):
        """schema.py structural facts other modules rely on."""
        # 'id' is generated — never inserted; SELECTs include it for lookups.
        assert "id" not in DATASET_COLUMNS
        assert DATASET_SELECT_COLUMNS[0] == "id"
        # INSERT list = base columns + the write-only trailing pair, in order.
        assert [*DATASET_COLUMNS, "data", "synced_at"] == DATASET_INSERT_COLUMNS
        # One placeholder per insert column (params tuple lines up positionally).
        assert DATASET_INSERT_PLACEHOLDERS.as_string(None).count("%s") == len(
            DATASET_INSERT_COLUMNS
        )

    def test_a_column_added_in_sync_is_forwarded_while_a_missing_one_still_fails(self, monkeypatch):
        """The positive control for the drift-detection tests above: a new
        column added to BOTH `DATASET_SELECT_COLUMNS` and the `Dataset`
        dataclass validates cleanly and its value is forwarded by
        `_parse_dataset`. A row that is instead missing a required column
        raises `KeyError` naming it, rather than silently producing a
        dataset with a missing field."""
        expanded = make_dataclass(
            "ExpandedDataset", [("extra_field", str | None, None)], bases=(datasets_module.Dataset,)
        )
        monkeypatch.setattr(datasets_module, "Dataset", expanded)
        monkeypatch.setattr(
            datasets_module,
            "DATASET_SELECT_COLUMNS",
            [*DATASET_SELECT_COLUMNS, "extra_field"],
        )
        validate_dataset_schema()
        row = dict.fromkeys(DATASET_SELECT_COLUMNS)
        row.update(id=1, uuid="test", title="Title", extra_field="retained")
        assert _parse_dataset(row).extra_field == "retained"
        del row["description"]
        with pytest.raises(KeyError, match="description"):
            _parse_dataset(row)


class TestDatasetRowParsing:
    """`_parse_dataset` robustness against NULL and malformed database rows —
    a per-row crash here 500s every page that touches the row."""

    def test_null_authors_becomes_empty_list(self):
        """authors=None (NULL array column) parses to [] — iterating None
        would raise TypeError and 500 every page touching the row."""
        ds = _parse_dataset(make_row(authors=None))
        assert ds.authors == []

    def test_null_title_renders_untitled(self):
        """title=None becomes '(untitled)', not the literal string 'None'."""
        ds = _parse_dataset(make_row(title=None))
        assert ds.title == "(untitled)"
        assert ds.title != "None"

    def test_malformed_author_entries_skipped_with_warning(self, caplog):
        """Malformed author entries (None, dict without 'name', non-dict
        non-str) are skipped with a warning; valid str and {'name': ...}
        entries survive. Guards the else:-log-and-skip against a per-row
        crash."""
        row = make_row(authors=[None, {"no_name": 1}, "Jane", {"name": "Bob"}, 42])
        with caplog.at_level(logging.WARNING, logger="app.services.datasets"):
            ds = _parse_dataset(row)
        assert ds.authors == [Author(name="Jane"), Author(name="Bob")]
        skip_warnings = [r for r in caplog.records if "malformed author" in r.getMessage().lower()]
        assert len(skip_warnings) == 3  # one per bad entry

    def test_null_languages_becomes_empty_list(self):
        """languages=None (NULL array column) parses to []."""
        ds = _parse_dataset(make_row(languages=None))
        assert ds.languages == []

    def test_null_doi_and_license_are_graceful(self):
        """doi=None and license_val=None both stay None. license_val used to
        be coerced to '' by a read-side `or ""` guard that contradicted the
        dataclass's `str | None` annotation; templates test truthiness, so
        None and '' render identically. Neither raises."""
        ds = _parse_dataset(make_row(doi=None, license_val=None))
        assert ds.doi is None
        assert ds.license_val is None

    def test_null_access_level_defaults_restricted(self):
        """access_level=None defaults to 'restricted' (fail-closed)."""
        ds = _parse_dataset(make_row(access_level=None))
        assert ds.access_level == "restricted"

    def test_null_visibility_tier_defaults_vetted(self):
        """visibility_tier=None defaults to 'vetted' (most restrictive)."""
        ds = _parse_dataset(make_row(visibility_tier=None))
        assert ds.visibility_tier == "vetted"

    def test_resource_proxies_extracted_first_wins(self):
        """resource_access_url comes from the first 'Resource' proxy and
        landing_page_url from the first 'LandingPage' proxy — later proxies
        of the same type do not overwrite (first-wins)."""
        proxies = [
            {"type": "LandingPage", "ref": "https://example.com/lp-first"},
            {"type": "Resource", "ref": "https://example.com/dl-first"},
            {"type": "Resource", "ref": "https://example.com/dl-second"},
            {"type": "LandingPage", "ref": "https://example.com/lp-second"},
        ]
        ds = _parse_dataset(make_row(resource_proxies=proxies))
        assert ds.resource_access_url == "https://example.com/dl-first"
        assert ds.landing_page_url == "https://example.com/lp-first"
        assert ds.resource_proxies == proxies  # raw list is preserved as-is


class TestDoiCanonicalizationAtIngest:
    """DOI canonicalization at the write seam (`_canonicalize_doi`, applied
    inside `build_record_params`) — as opposed to at render time, which is
    `app.template_setup.doi_url_filter` (see test_templates.py)."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("doi:10.48656/x", "10.48656/x"),
            ("10.48656/x", "10.48656/x"),
            ("  10.48656/x  ", "10.48656/x"),
            ("https://doi.org/10.48656/x", "10.48656/x"),
            ("http://doi.org/10.48656/x", "10.48656/x"),
            ("https://dx.doi.org/10.48656/x", "10.48656/x"),
            ("http://dx.doi.org/10.48656/x", "10.48656/x"),
            ("https://example.org/10.48656/x", "https://example.org/10.48656/x"),
        ],
        ids=[
            "doi-prefix-stripped",
            "bare-doi-unchanged",
            "surrounding-whitespace-trimmed",
            "https-doi-org-resolver-stripped",
            "http-doi-org-resolver-stripped",
            "https-dx-doi-org-resolver-stripped",
            "http-dx-doi-org-resolver-stripped",
            "non-doi-url-passes-through",
        ],
    )
    def test_canonicalize_doi_forms(self, raw, expected):
        """Every accepted spelling of the same logical DOI collapses to one
        stored form — the property the doi UNIQUE constraint's dedupe
        depends on."""
        assert _canonicalize_doi(raw) == expected

    def test_canonicalize_doi_garbage_returns_none_with_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="app.services.schema"):
            assert _canonicalize_doi("garbage") is None
        assert any("Unrecognized DOI format" in r.getMessage() for r in caplog.records)

    def test_ingest_doi_canonicalized_at_the_write_seam(self):
        """The parser passes the DOI through raw; build_record_params
        canonicalizes it, so EVERY source (OAI, mock seeder, future second
        source) lands the same bare form and the doi UNIQUE constraint can
        dedupe."""
        rec = _variant(_DOI_ELEMENT, "<cmdp:DOI>doi:10.48656/x</cmdp:DOI>")
        assert rec["doi"] == "doi:10.48656/x"  # parser does not normalize

        params = build_record_params(rec, "public", "swissubase", "public")
        assert params[DATASET_INSERT_COLUMNS.index("doi")] == "10.48656/x"

    def test_build_record_params_canonicalizes_doi_for_every_source(self):
        """Canonicalization lives at the write seam, not in the OAI parser, so
        the mock seeder and any future additional source get it too — a
        source-specific parser can't forget it."""
        rec = _variant(_DOI_ELEMENT, "<cmdp:DOI>https://doi.org/10.48656/x</cmdp:DOI>")
        assert rec["doi"] == "https://doi.org/10.48656/x"  # parser passes through raw
        params = build_record_params(rec, "public", "swissubase", "public")
        assert params[DATASET_INSERT_COLUMNS.index("doi")] == "10.48656/x"


class TestDoiUriFormCanonicalization:
    """`app.doi` — the DOI name/URI boundary used at render time (as opposed
    to `_canonicalize_doi`/`build_record_params` above, the ingest write
    seam): a DOI is decoded from its URI form exactly once and reserved name
    characters are re-encoded when turned back into a resolver URL; a
    resolver URL carrying credentials or a query is not a DOI at all."""

    @pytest.mark.parametrize(
        ("raw", "canonical", "url"),
        [
            ("doi:10.1234/ABC%3FQ%23F", "10.1234/abc?q#f", "https://doi.org/10.1234/abc%3Fq%23f"),
            (
                "https://doi.org/10.1234/ABC%252F",
                "10.1234/abc%2f",
                "https://doi.org/10.1234/abc%252f",
            ),
            ("10.1234/ABC%2F", "10.1234/abc%2f", "https://doi.org/10.1234/abc%252f"),
            ("10.1234/ÄBC", "10.1234/Äbc", "https://doi.org/10.1234/%C3%84bc"),
            # A percent-encoded path separator in the resolver URL form decodes
            # and folds; a resolver URL carrying credentials or a query is not
            # a DOI.
            (
                "https://doi.org/10.1234/UPPER%2FPath",
                "10.1234/upper/path",
                "https://doi.org/10.1234/upper/path",
            ),
            ("https://user:pass@doi.org/10.1234/ID", None, ""),
            ("https://doi.org/10.1234/ID?query=1", None, ""),
        ],
        ids=[
            "doi-scheme-percent-encoded-reserved-chars",
            "resolver-url-double-percent-encoded-slash",
            "bare-name-percent-encoded-slash",
            "non-ascii-name-case-folds-ascii-only",
            "resolver-url-uppercase-path-segment",
            "resolver-url-with-credentials-is-not-a-doi",
            "resolver-url-with-query-is-not-a-doi",
        ],
    )
    def test_doi_decodes_only_uri_forms_and_encodes_reserved_name_characters(
        self, raw, canonical, url
    ):
        assert canonicalize_doi(raw) == canonical
        assert doi_url(raw) == url


class TestAuthorInstitutionLanguageOrdering:
    """Order fidelity: authors/institutions stay in upstream order,
    languages/disciplines are sorted and deduped."""

    def test_authors_preserve_source_order_keep_duplicates_drop_blank(self):
        """Authors keep upstream order (Steinberg stays lead author even
        though Kovačević sorts first), an exact duplicate is kept twice
        (distinct people can share a name), and a whitespace-only node is
        dropped. Pins authors staying routed through _get_list_ordered, not
        sorted()."""
        rec = _variant(
            _AUTHOR_BLOCK,
            "<cmdp:Author>Steinberg, Max</cmdp:Author>\n"
            "<cmdp:Author>Kovačević, Ana</cmdp:Author>\n"
            "<cmdp:Author>Steinberg, Max</cmdp:Author>\n"
            "<cmdp:Author>   </cmdp:Author>",
        )
        assert rec["authors"] == ["Steinberg, Max", "Kovačević, Ana", "Steinberg, Max"]
        assert rec["authors"] != sorted(rec["authors"])  # genuinely not alphabetized

    def test_institutions_preserve_source_order(self):
        """Institutions are order-preserving too (lead institution is a
        citation-bearing fact) — 'Zeta' stays before 'Alpha'."""
        rec = _variant(
            _INSTITUTION_BLOCK,
            "<cmdp:Institution>Zeta Institute</cmdp:Institution>\n"
            "<cmdp:Institution>Alpha University</cmdp:Institution>",
        )
        assert rec["institutions"] == ["Zeta Institute", "Alpha University"]

    def test_languages_sorted_and_deduped(self):
        """Contrast: languages remain order-free — sorted and deduped via
        _get_list ('German','English','German' nodes → ['English','German'])."""
        rec = _variant(
            _LANGUAGE_BLOCK,
            '<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>\n'
            '<cmdp:Language_name xml:lang="en">English</cmdp:Language_name>\n'
            '<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>',
        )
        assert rec["languages"] == ["English", "German"]

    def test_main_disciplines_sorted(self):
        """Contrast: main_disciplines stay sorted (order-free field) — a
        future edit can't silently reroute them through the ordered helper."""
        rec = _variant(
            _DISCIPLINE_BLOCK,
            '<cmdp:Main_discipline xml:lang="en">Sociology</cmdp:Main_discipline>\n'
            '<cmdp:Main_discipline xml:lang="en">Anthropology</cmdp:Main_discipline>',
        )
        assert rec["main_disciplines"] == ["Anthropology", "Sociology"]


class TestOaiDatestampIngestion:
    """`upstream_modified_at` — OAI datestamp decoding at ingest. The seam
    contract: parsers hand build_record_params a datetime, not a string."""

    def test_ingest_datestamp_parsed_to_aware_utc(self):
        rec = _parse_xml()
        assert rec["upstream_modified_at"] == datetime(2026, 3, 6, 13, 38, 2, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("2026-03-06T13:38:02Z", datetime(2026, 3, 6, 13, 38, 2, tzinfo=UTC)),
            ("2026-03-06", datetime(2026, 3, 6, tzinfo=UTC)),  # day granularity — OAI permits it
            ("2026-03-06T13:38:02", datetime(2026, 3, 6, 13, 38, 2, tzinfo=UTC)),  # naive -> UTC
            ("", None),
            (None, None),
        ],
        ids=[
            "full-utc-instant",
            "day-granularity",
            "naive-datetime-treated-as-utc",
            "empty-string",
            "none",
        ],
    )
    def test_parse_oai_datestamp_variants(self, raw, expected):
        assert _parse_oai_datestamp(raw) == expected

    def test_parse_oai_datestamp_garbage_returns_none_with_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            assert _parse_oai_datestamp("last Tuesday") is None
        assert "datestamp" in caplog.text.lower()

    def test_ingest_datestamp_day_granularity_lands_at_utc_midnight(self):
        rec = _variant(_DATESTAMP_ELEMENT, "<oai:datestamp>2026-03-06</oai:datestamp>")
        assert rec["upstream_modified_at"] == datetime(2026, 3, 6, tzinfo=UTC)
