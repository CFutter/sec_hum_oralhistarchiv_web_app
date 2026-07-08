"""Unit tests for the parsing/classification/sanitization seams.

Covers TESTING_BACKLOG §3.3 (_build_record_params presence-not-nullness),
§3.6 (_parse_dataset NULL/malformed-row robustness), §3.9 (DOI canonical at
ingest AND render), §3.10 (author/institution order fidelity), plus
_classify_access_level and _sanitize_error_message.

Pure unit tier: no DB, no TestClient — everything here is a plain function
call on parsed XML / dict rows.
"""
import logging

import pytest
from lxml import etree

from app.services import sync
from app.services.datasets import Author, _parse_dataset
from app.services.oai_client import parse_cmdi_to_dict
from app.services.schema import DATASET_INSERT_COLUMNS
from app.services.sync import (
    _build_record_params,
    _classify_access_level,
    _sanitize_error_message,
)
from app.template_setup import doi_url_filter

# ---------------------------------------------------------------------------
# Sample CMDI record (copied from src/tests_legacy/conftest.py SAMPLE_CMDI_XML)
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

# Unique substrings of the sample used to splice in variants.
_DOI_ELEMENT = "<cmdp:DOI>https://doi.org/10.48656/test-xml</cmdp:DOI>"
_AUTHOR_BLOCK = (
    "<cmdp:Author>Müller, Urs</cmdp:Author>\n"
    "<cmdp:Author>Keller, Anna</cmdp:Author>"
)
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


def _parse_xml(xml: str = SAMPLE_CMDI_XML) -> dict:
    """Parse a CMDI XML string exactly as the OAI client does."""
    return parse_cmdi_to_dict(etree.fromstring(xml.encode()))


def _variant(old: str, new: str) -> dict:
    """Parse the sample with one unique block swapped for a variant."""
    assert old in SAMPLE_CMDI_XML  # guard against silent no-op replaces
    return _parse_xml(SAMPLE_CMDI_XML.replace(old, new))


# ---------------------------------------------------------------------------
# §3.3 — _build_record_params: presence-not-nullness
# ---------------------------------------------------------------------------

def test_build_record_params_missing_parser_key_raises_keyerror():
    """§3.3: a record dict MISSING a _PARSER_OWNED key (parser/profile drift)
    raises KeyError naming the missing key, instead of silently nulling the
    column across the catalogue."""
    rec = _parse_xml()
    del rec["license_val"]
    with pytest.raises(KeyError, match="license_val"):
        _build_record_params(
            rec, access_level="public", source="swissubase", visibility_tier="public"
        )


def test_build_record_params_none_value_present_key_is_null_not_error():
    """§3.3: an optional field emitted as None (key PRESENT) is legitimate —
    no raise, and the doi slot of the params tuple (ordered by
    DATASET_INSERT_COLUMNS) is None, i.e. a NULL column."""
    rec = _parse_xml()
    rec["doi"] = None
    params = _build_record_params(
        rec, access_level="public", source="swissubase", visibility_tier="public"
    )
    assert len(params) == len(DATASET_INSERT_COLUMNS)
    assert params[DATASET_INSERT_COLUMNS.index("doi")] is None


def test_parser_owned_contract_matches_parser_output():
    """§3.3 import-time contract: _PARSER_OWNED is exactly the key set that
    parse_cmdi_to_dict emits. Verified against the code: resource_proxies IS
    in DATASET_COLUMNS, IS in _PARSER_OWNED (only access_level/source/
    visibility_tier are app-owned), and IS emitted by the parser — so the
    sets are equal with NO subtraction. Guards schema/parser divergence."""
    rec = _parse_xml()
    assert sync._PARSER_OWNED == set(rec.keys())
    # Redundant-but-explicit form of the invariant the backlog cares about:
    # every parser-owned column is actually emitted by the parser.
    assert sync._PARSER_OWNED - rec.keys() == set()


# ---------------------------------------------------------------------------
# §3.6 — _parse_dataset robustness (per-row 500 guard on /search)
# ---------------------------------------------------------------------------

def make_row(**overrides) -> dict:
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


def test_parse_dataset_null_authors_becomes_empty_list():
    """§3.6: authors=None (NULL array column) parses to [] — the old code
    TypeError'd on iteration, 500ing every page touching the row."""
    ds = _parse_dataset(make_row(authors=None))
    assert ds.authors == []


def test_parse_dataset_null_title_renders_untitled():
    """§3.6: title=None becomes '(untitled)', not the literal string 'None'."""
    ds = _parse_dataset(make_row(title=None))
    assert ds.title == "(untitled)"
    assert ds.title != "None"


def test_parse_dataset_malformed_author_entries_skipped_with_warning(caplog):
    """§3.6: malformed author entries (None, dict without 'name', non-dict
    non-str) are skipped with a warning; valid str and {'name': ...} entries
    survive. Guards the else:-log-and-skip against a per-row crash."""
    row = make_row(authors=[None, {"no_name": 1}, "Jane", {"name": "Bob"}, 42])
    with caplog.at_level(logging.WARNING, logger="app.services.datasets"):
        ds = _parse_dataset(row)
    assert ds.authors == [Author(name="Jane"), Author(name="Bob")]
    skip_warnings = [
        r for r in caplog.records if "malformed author" in r.getMessage().lower()
    ]
    assert len(skip_warnings) == 3  # one per bad entry


def test_parse_dataset_null_languages_becomes_empty_list():
    """§3.6: languages=None (NULL array column) parses to []."""
    ds = _parse_dataset(make_row(languages=None))
    assert ds.languages == []


def test_parse_dataset_null_doi_and_license_are_graceful():
    """§3.6: doi=None stays None; license_val=None becomes '' (the `or ""`
    read guard). Neither raises."""
    ds = _parse_dataset(make_row(doi=None, license_val=None))
    assert ds.doi is None
    assert ds.license_val == ""


def test_parse_dataset_null_access_level_defaults_restricted():
    """§3.6: access_level=None defaults to 'restricted' (fail-closed)."""
    ds = _parse_dataset(make_row(access_level=None))
    assert ds.access_level == "restricted"


def test_parse_dataset_null_visibility_tier_defaults_vetted():
    """§3.6: visibility_tier=None defaults to 'vetted' (most restrictive)."""
    ds = _parse_dataset(make_row(visibility_tier=None))
    assert ds.visibility_tier == "vetted"


def test_parse_dataset_resource_proxies_extracted_first_wins():
    """§3.6: download_url comes from the first 'Resource' proxy and
    landing_page_url from the first 'LandingPage' proxy — later proxies of
    the same type do not overwrite (first-wins)."""
    proxies = [
        {"type": "LandingPage", "ref": "https://example.com/lp-first"},
        {"type": "Resource", "ref": "https://example.com/dl-first"},
        {"type": "Resource", "ref": "https://example.com/dl-second"},
        {"type": "LandingPage", "ref": "https://example.com/lp-second"},
    ]
    ds = _parse_dataset(make_row(resource_proxies=proxies))
    assert ds.download_url == "https://example.com/dl-first"
    assert ds.landing_page_url == "https://example.com/lp-first"
    assert ds.resource_proxies == proxies  # raw list is preserved as-is


# ---------------------------------------------------------------------------
# §3.9 — DOI canonical at RENDER (doi_url_filter)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # doi:-prefixed → prefix stripped THEN resolver added: closes the
        # doubled-prefix 404 https://doi.org/doi:10.1/x.
        ("doi:10.1/x", "https://doi.org/10.1/x"),
        # 'DOI:' uppercase — code lowercases before the startswith check.
        ("DOI:10.1/x", "https://doi.org/10.1/x"),
        # Bare DOI → resolver prefix added.
        ("10.1/x", "https://doi.org/10.1/x"),
        # Existing http(s) URL passes through unchanged.
        ("https://doi.org/10.1/x", "https://doi.org/10.1/x"),
        # XSS guard: non-http(s) scheme → empty string, never an href.
        ("javascript:alert(1)", ""),
        # Empty input → empty output.
        ("", ""),
    ],
)
def test_doi_url_filter_render_canonicalization(value, expected):
    """§3.9 render side: doi_url_filter always yields an http(s) href or ''."""
    assert doi_url_filter(value) == expected


# ---------------------------------------------------------------------------
# §3.9 — DOI canonical at INGEST (_get_doi via parse_cmdi_to_dict)
# ---------------------------------------------------------------------------

def test_ingest_doi_prefix_stripped():
    """§3.9 ingest: 'doi:10.48656/x' is stored as bare '10.48656/x' — storage
    only ever holds bare 10.x or a full http(s) URL."""
    rec = _variant(_DOI_ELEMENT, "<cmdp:DOI>doi:10.48656/x</cmdp:DOI>")
    assert rec["doi"] == "10.48656/x"


def test_ingest_doi_garbage_rejected_with_warning(caplog):
    """§3.9 ingest: an unrecognized DOI value is stored as None and warned
    about, instead of poisoning the doi column."""
    with caplog.at_level(logging.WARNING, logger="app.services.oai_client"):
        rec = _variant(_DOI_ELEMENT, "<cmdp:DOI>garbage</cmdp:DOI>")
    assert rec["doi"] is None
    assert any(
        "Unrecognized DOI format" in r.getMessage() for r in caplog.records
    )


def test_ingest_doi_https_url_passes_through():
    """§3.9 ingest: a full https DOI URL is stored unchanged (the sample's
    own DOI element)."""
    rec = _parse_xml()
    assert rec["doi"] == "https://doi.org/10.48656/test-xml"


# ---------------------------------------------------------------------------
# §3.10 — order fidelity: authors/institutions ordered, languages/disciplines sorted
# ---------------------------------------------------------------------------

def test_authors_preserve_source_order_keep_duplicates_drop_blank():
    """§3.10: authors keep upstream order (Steinberg stays lead author even
    though Kovačević sorts first), an exact duplicate is kept twice (distinct
    people can share a name), and a whitespace-only node is dropped. Pins
    authors staying routed through _get_list_ordered, not sorted()."""
    rec = _variant(
        _AUTHOR_BLOCK,
        "<cmdp:Author>Steinberg, Max</cmdp:Author>\n"
        "<cmdp:Author>Kovačević, Ana</cmdp:Author>\n"
        "<cmdp:Author>Steinberg, Max</cmdp:Author>\n"
        "<cmdp:Author>   </cmdp:Author>",
    )
    assert rec["authors"] == ["Steinberg, Max", "Kovačević, Ana", "Steinberg, Max"]
    assert rec["authors"] != sorted(rec["authors"])  # genuinely not alphabetized


def test_institutions_preserve_source_order():
    """§3.10: institutions are order-preserving too (lead institution is a
    citation-bearing fact) — 'Zeta' stays before 'Alpha'."""
    rec = _variant(
        _INSTITUTION_BLOCK,
        "<cmdp:Institution>Zeta Institute</cmdp:Institution>\n"
        "<cmdp:Institution>Alpha University</cmdp:Institution>",
    )
    assert rec["institutions"] == ["Zeta Institute", "Alpha University"]


def test_languages_sorted_and_deduped():
    """§3.10 contrast: languages remain order-free — sorted and deduped via
    _get_list ('German','English','German' nodes → ['English','German'])."""
    rec = _variant(
        _LANGUAGE_BLOCK,
        '<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>\n'
        '<cmdp:Language_name xml:lang="en">English</cmdp:Language_name>\n'
        '<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>',
    )
    assert rec["languages"] == ["English", "German"]


def test_main_disciplines_sorted():
    """§3.10 contrast: main_disciplines stay sorted (order-free field) — a
    future edit can't silently reroute them through the ordered helper."""
    rec = _variant(
        _DISCIPLINE_BLOCK,
        '<cmdp:Main_discipline xml:lang="en">Sociology</cmdp:Main_discipline>\n'
        '<cmdp:Main_discipline xml:lang="en">Anthropology</cmdp:Main_discipline>',
    )
    assert rec["main_disciplines"] == ["Anthropology", "Sociology"]


# ---------------------------------------------------------------------------
# _classify_access_level
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("license_val", "expected"),
    [
        # Case-insensitive prefix match on "restricted access".
        ("Restricted access — ethics approval", "restricted"),
        ("RESTRICTED ACCESS: contact the depositor", "restricted"),
        # Anything else is public (fail-open by choice for SWISSUbase).
        ("License CC BY", "public"),
        (None, "public"),
    ],
)
def test_classify_access_level_swissubase(license_val, expected):
    """Classifier: 'restricted access*' (any case) → restricted; everything
    else (incl. None) → public for source='swissubase'."""
    assert _classify_access_level(license_val, source="swissubase") == expected


def test_classify_access_level_other_source_not_implemented():
    """Classifier is only validated for SWISSUbase — any other source must
    set access_level explicitly, so it raises NotImplementedError instead of
    silently fail-opening a restricted catalogue."""
    with pytest.raises(NotImplementedError):
        _classify_access_level("Restricted access", source="other")


# ---------------------------------------------------------------------------
# _sanitize_error_message
# ---------------------------------------------------------------------------

def test_sanitize_error_message_strips_file_paths():
    """Absolute .py paths are replaced with '<file>' so internal layout never
    leaks into sync_status / /health/detail."""
    msg = "ValueError: boom in /opt/app/services/sync.py while syncing"
    out = _sanitize_error_message(msg)
    assert "/opt/app/services/sync.py" not in out
    assert "<file>" in out
    assert out == "ValueError: boom in <file> while syncing"


def test_sanitize_error_message_truncates_long_messages():
    """Messages longer than 500 chars are truncated to 500 + '...'."""
    out = _sanitize_error_message("x" * 600)
    assert out == "x" * 500 + "..."
    assert len(out) == 503
