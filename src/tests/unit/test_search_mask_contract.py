"""Python mask production and generated SQL share a stable versioned field map."""

import json
import re
from dataclasses import replace
from enum import IntEnum
from unittest.mock import patch

import pytest

from app import catalogue_sql, runtime_preflight
from app import search_mask_contract as masks
from app.services import datasets, db_drift, db_schema_contract
from app.services.db_schema_contract import FUNCTION_CONTRACTS
from app.services.search_query import parse_search_query
from tests.source_fixtures import fixture_source

_EXPECTED_BITS = {
    "description": 1,
    "project_title": 2,
    "project_description": 4,
    "keywords": 8,
    "authors": 16,
    "languages": 32,
}
_FILTERS = {"keyword": "", "language": "", "access_level": ""}


def _source(mask):
    """Build a source whose public fields correspond exactly to the selected bit mask."""
    return fixture_source(
        name="mask_archive",
        max_visibility="public",
        field_visibility={
            name: "public" if mask & bit else "vetted" for name, bit in _EXPECTED_BITS.items()
        },
    )


def test_v1_field_map_and_filter_only_language_bit_are_explicit():
    """Check v1 field map and filter only language bit are explicit."""
    assert masks.SEARCH_MASK_PROTOCOL_VERSION == 1
    assert {field.name: int(field.bit) for field in masks.SEARCH_FILTER_FIELDS} == _EXPECTED_BITS
    assert [field.name for field in masks.SEARCH_DOCUMENT_FIELDS] == list(_EXPECTED_BITS)[:-1]
    assert masks.SEARCH_DOCUMENT_MASK == 31
    assert masks.SEARCH_FILTER_MASK == 63
    masks.assert_search_mask_contract()


def _rewrite_search_assignment(monkeypatch, column, transform):
    """Replace one trigger assignment in the function contract using the supplied transform."""
    signature = "update_search_text()"
    spec = FUNCTION_CONTRACTS[signature]
    source, count = re.subn(
        rf"(NEW\.{column}\s*:=\s*)(.*?)(;)",
        lambda match: match[1] + transform(match[2]) + match[3],
        spec.source,
        flags=re.S,
    )
    assert count == 1
    monkeypatch.setitem(FUNCTION_CONTRACTS, signature, replace(spec, source=source))


def test_current_trigger_documents_match_the_shared_field_map():
    """Check current trigger documents match the shared field map."""
    db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("column", ["search_text_full", "search_vector_full"])
@pytest.mark.parametrize(
    "field_sql",
    [
        "COALESCE(NEW.description, '')",
        "COALESCE(NEW.project_title, '')",
        "COALESCE(NEW.project_description, '')",
        "COALESCE(array_to_string(NEW.keywords, ' '), '')",
        "COALESCE(array_to_string(NEW.authors, ' '), '')",
    ],
)
def test_each_full_document_rejects_a_missing_field(monkeypatch, column, field_sql):
    """Check each full document rejects a missing field (RuntimeError)."""

    def remove_field(expression):
        """Remove exactly one occurrence of the selected search field from the SQL expression."""
        expression, count = re.subn(
            re.escape(field_sql) + r"\s*\|\| ' ' \|\|\s*", "", expression, count=1
        )
        if not count:
            expression, count = re.subn(
                r"\s*\|\| ' ' \|\|\s*" + re.escape(field_sql), "", expression, count=1
            )
        assert count == 1
        return expression

    _rewrite_search_assignment(monkeypatch, column, remove_field)
    with pytest.raises(RuntimeError, match=rf"mismatch for NEW\.{column}"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("column", ["search_text_full", "search_vector_full"])
@pytest.mark.parametrize(
    "before,after",
    [
        ("array_to_string(NEW.authors, ' ')", "NEW.authors"),
        ("array_to_string(NEW.keywords, ' ')", "NEW.keywords"),
        ("NEW.description", "array_to_string(NEW.description, ' ')"),
        ("NEW.description", "NEW.summary"),
        ("COALESCE(NEW.description, '')", "COALESCE(NEW.description, '') || ' ' || NEW.summary"),
        ("' '", "'  '"),
    ],
)
def test_each_full_document_rejects_changed_expressions(monkeypatch, column, before, after):
    """Check each full document rejects changed expressions (RuntimeError)."""
    _rewrite_search_assignment(monkeypatch, column, lambda sql: sql.replace(before, after, 1))
    with pytest.raises(RuntimeError, match=rf"mismatch for NEW\.{column}"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("column", ["search_text_full", "search_vector_full"])
def test_document_field_order_is_enforced(monkeypatch, column):
    """Check document field order is enforced (RuntimeError)."""
    _rewrite_search_assignment(
        monkeypatch,
        column,
        lambda sql: (
            sql.replace("NEW.description", "NEW.swap")
            .replace("NEW.project_title", "NEW.description")
            .replace("NEW.swap", "NEW.project_title")
        ),
    )
    with pytest.raises(RuntimeError, match=rf"mismatch for NEW\.{column}"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize(
    "column,before,after",
    [
        ("search_text_public", "NEW.access_level", "NEW.description"),
        ("search_text_full", "COALESCE(NEW.title, '')", "NEW.search_text_public"),
        ("search_vector_full", "NEW.search_text_public", "COALESCE(NEW.title, '')"),
    ],
)
def test_intentional_document_prefixes_are_enforced(monkeypatch, column, before, after):
    """Check intentional document prefixes are enforced (RuntimeError)."""
    _rewrite_search_assignment(monkeypatch, column, lambda sql: sql.replace(before, after, 1))
    with pytest.raises(RuntimeError, match=rf"mismatch for NEW\.{column}"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("column", ["search_text_full", "search_vector_full"])
def test_a_commented_valid_assignment_cannot_hide_a_stale_document(monkeypatch, column):
    """Check a commented valid assignment cannot hide a stale document (RuntimeError)."""
    original = FUNCTION_CONTRACTS["update_search_text()"]
    assignment = re.search(rf"NEW\.{column}\s*:=.*?;", original.source, re.S)[0]
    _rewrite_search_assignment(
        monkeypatch, column, lambda sql: sql.replace("NEW.authors", "NEW.old_authors")
    )
    stale = FUNCTION_CONTRACTS["update_search_text()"]
    monkeypatch.setitem(
        FUNCTION_CONTRACTS,
        "update_search_text()",
        replace(stale, source=f"/* {assignment} */\n{stale.source}"),
    )
    with pytest.raises(RuntimeError, match=rf"mismatch for NEW\.{column}"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("change", ["missing", "duplicate"])
def test_document_assignment_must_exist_exactly_once(monkeypatch, change):
    """Check document assignment must exist exactly once (RuntimeError)."""
    spec = FUNCTION_CONTRACTS["update_search_text()"]
    pattern = r"NEW\.search_text_full\s*:=.*?;"
    assignment = re.search(pattern, spec.source, re.S)[0]
    source = (
        re.sub(pattern, "", spec.source, flags=re.S)
        if change == "missing"
        else spec.source + assignment
    )
    monkeypatch.setitem(FUNCTION_CONTRACTS, "update_search_text()", replace(spec, source=source))
    with pytest.raises(RuntimeError, match=r"one assignment to NEW\.search_text_full"):
        db_schema_contract.assert_search_document_contract()


def test_layout_comments_and_keyword_case_do_not_change_the_document_contract(monkeypatch):
    """Check layout comments and keyword case do not change the document contract."""
    _rewrite_search_assignment(
        monkeypatch,
        "search_text_full",
        lambda sql: sql.replace("COALESCE(", "coalesce(\n/* document field */ "),
    )
    db_schema_contract.assert_search_document_contract()


def test_registered_future_field_cannot_leave_the_trigger_unchanged(monkeypatch):
    """Check registered future field cannot leave the trigger unchanged (RuntimeError)."""
    future_bits = IntEnum("FutureSearchMaskBit", {**masks.SearchMaskBit.__members__, "SUMMARY": 64})
    documents = tuple(
        replace(field, bit=future_bits(field.bit)) for field in masks.SEARCH_DOCUMENT_FIELDS
    )
    documents += (masks.SearchMaskField("summary", future_bits.SUMMARY, array=False),)
    filters = (*documents, replace(masks.SEARCH_FILTER_FIELDS[-1], bit=future_bits.LANGUAGES))
    profile = tuple((field.name, int(field.bit), field.array) for field in filters)
    monkeypatch.setattr(masks, "SearchMaskBit", future_bits)
    monkeypatch.setattr(masks, "SEARCH_DOCUMENT_FIELDS", documents)
    monkeypatch.setattr(masks, "SEARCH_FILTER_FIELDS", filters)
    monkeypatch.setattr(masks, "SEARCH_MASK_PROTOCOL_VERSION", 2)
    monkeypatch.setattr(masks, "_PROFILES", {**masks._PROFILES, 2: profile})

    # This is a registered protocol change, so the existing guard accepts it.
    masks.assert_search_mask_contract()
    with pytest.raises(RuntimeError, match=r"mismatch for NEW\.search_text_full"):
        db_schema_contract.assert_search_document_contract()


@pytest.mark.parametrize("mask", range(64))
@pytest.mark.parametrize("compiled", (False, True))
def test_both_python_producers_encode_every_field_subset_by_name(mask, compiled):
    """Check both python producers encode every field subset by name."""
    sources = (_source(mask),)
    if compiled:
        sources = datasets.build_catalogue_policy(sources)
    query = parse_search_query("needle")
    count_masks = json.loads(
        datasets._search_policy_context(query, 0, sources)["app.search_field_masks"]
    )
    page_masks = datasets._page_query_context(query, 0, _FILTERS, sources).obj["masks"]
    assert count_masks == {"*": 0, "mask_archive": mask & 31}
    assert page_masks == {"*": 0, "mask_archive": mask}


def test_reordering_document_fields_cannot_reassign_bits_and_startup_rejects_the_order(monkeypatch):
    """Check reordering document fields cannot reassign bits and startup rejects the order
    (RuntimeError).
    """
    original = masks.SEARCH_DOCUMENT_FIELDS
    reordered = (original[1], original[0], *original[2:])
    monkeypatch.setattr(masks, "SEARCH_DOCUMENT_FIELDS", reordered)
    monkeypatch.setattr(masks, "SEARCH_FILTER_FIELDS", (*reordered, masks.SEARCH_FILTER_FIELDS[-1]))
    query = parse_search_query("needle")
    sources = (_source(62),)
    assert (
        datasets._page_query_context(query, 0, _FILTERS, sources).obj["masks"]["mask_archive"] == 62
    )
    assert (
        json.loads(datasets._search_policy_context(query, 0, sources)["app.search_field_masks"])[
            "mask_archive"
        ]
        == 30
    )
    with pytest.raises(RuntimeError, match="registered version"):
        masks.assert_search_mask_contract()


@pytest.mark.parametrize(
    "change", ["bit", "name", "array", "missing_language", "version", "boolean_version"]
)
def test_independent_contract_edits_fail_closed(change, monkeypatch):
    """Check independent contract edits fail closed (RuntimeError)."""
    fields = list(masks.SEARCH_FILTER_FIELDS)
    if change == "bit":
        fields[0] = replace(fields[0], bit=masks.SearchMaskBit.PROJECT_TITLE)
    elif change == "name":
        fields[0] = replace(fields[0], name="resource_description")
    elif change == "array":
        fields[0] = replace(fields[0], array=True)
    elif change == "missing_language":
        fields.pop()
    else:
        monkeypatch.setattr(
            masks, "SEARCH_MASK_PROTOCOL_VERSION", 2 if change == "version" else True
        )
    monkeypatch.setattr(masks, "SEARCH_FILTER_FIELDS", tuple(fields))
    with pytest.raises(RuntimeError, match="registered version"):
        masks.assert_search_mask_contract()


@pytest.mark.parametrize(
    "marker,maximum,minimum",
    [
        ("__SEARCH_DOCUMENT_PATTERN__", 31, 0),
        ("__SEARCH_FILTER_PATTERN__", 63, 0),
        ("__SEARCH_PARTIAL_PATTERN__", 30, 1),
    ],
)
def test_sql_numeric_whitelists_accept_exactly_the_supported_ascii_values(marker, maximum, minimum):
    """Check SQL numeric whitelists accept exactly the supported ascii values."""
    pattern = masks.render_search_mask_sql(marker)
    for value in range(200):
        assert bool(re.fullmatch(pattern, str(value))) == (minimum <= value <= maximum)
    for malformed in ("-1", "01", "1.0", "1e1", "\u0661", "1\n", "9" * 5000):
        assert re.fullmatch(pattern, malformed) is None


def test_generated_sql_carries_the_version_and_has_no_unexpanded_protocol_markers():
    """Check generated SQL carries the version and has no unexpanded protocol markers (RuntimeError)."""
    assert "-- " + masks.SEARCH_MASK_PROTOCOL_TAG in catalogue_sql.CATALOGUE_PAGE_IDS_SOURCE
    assert catalogue_sql.CATALOGUE_SEARCH_CANDIDATES_DEFINITION == (
        " SELECT catalogue_search_candidates() AS id;"
    )
    for source in (
        catalogue_sql.CATALOGUE_PAGE_IDS_SOURCE,
        catalogue_sql.CATALOGUE_SEARCH_CANDIDATES_DEFINITION,
    ):
        assert "__SEARCH_" not in source
        assert "__CATALOGUE_" not in source
    with pytest.raises(RuntimeError, match="Unresolved"):
        masks.render_search_mask_sql("__SEARCH_UNREGISTERED__")


def test_bookmarks_are_bound_to_the_mask_protocol(monkeypatch):
    """Check bookmarks are bound to the mask protocol."""
    arguments = (parse_search_query("needle"), "public", _FILTERS, 20, "guest", (_source(63),))
    before = datasets._search_bookmark_context(*arguments)
    monkeypatch.setattr(masks, "SEARCH_MASK_PROTOCOL_TAG", "synthetic-future-protocol")
    assert datasets._search_bookmark_context(*arguments) != before


@pytest.mark.parametrize("process", ["web", "scheduler"])
async def test_mask_contract_failure_prevents_every_database_preflight(process):
    """Check mask contract failure prevents every database preflight (RuntimeError)."""
    with (
        patch.object(runtime_preflight, "assert_search_mask_contract", autospec=True) as check,
        patch.object(runtime_preflight, "validate_runtime_database_role", autospec=True) as role,
        patch.object(runtime_preflight, "validate_alembic_head", autospec=True) as head,
        patch.object(runtime_preflight, "validate_schema_against_db", autospec=True) as schema,
    ):
        check.side_effect = RuntimeError("mask contract sentinel")
        with pytest.raises(RuntimeError, match="mask contract sentinel"):
            await runtime_preflight.validate_runtime_schema(object(), process=process)
    role.assert_not_awaited()
    head.assert_not_awaited()
    schema.assert_not_awaited()


@pytest.mark.parametrize("consumer", ["catalogue_page_ids", "catalogue_match_ids"])
async def test_live_schema_checks_reject_a_different_mask_protocol(consumer):
    """Check live schema checks reject a different mask protocol (RuntimeError)."""
    signature = next(name for name in FUNCTION_CONTRACTS if name.startswith(consumer + "("))
    expected = FUNCTION_CONTRACTS[signature]
    assert masks.SEARCH_MASK_PROTOCOL_TAG in expected.source
    stale = replace(
        expected,
        source=expected.source.replace(masks.SEARCH_MASK_PROTOCOL_TAG, "search-mask/v0/old"),
    )
    with (
        patch.object(
            db_drift, "_get_function_specs", autospec=True, return_value={signature: stale}
        ),
        pytest.raises(RuntimeError),
    ):
        await db_drift.assert_function_contract(object(), {signature: expected})
