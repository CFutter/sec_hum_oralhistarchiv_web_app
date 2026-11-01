"""Query intent keeps literal metacharacters distinct from web-search syntax."""

from dataclasses import is_dataclass

import pytest

from app.services.search_query import SearchQuery, parse_search_query


@pytest.mark.parametrize(
    "raw,mode",
    [
        ("", "empty"),
        (" \t\n ", "empty"),
        ("history", "auto"),
        ("OR", "auto"),
        ("or", "auto"),
        ("oral history", "auto"),
        ("  Oral   History  ", "auto"),
        ('"oral history"', "web"),
        ('"unterminated phrase', "web"),
        ("oral OR testimony", "web"),
        ("oral or testimony", "web"),
        ("-confidential", "web"),
        ("oral -confidential", "web"),
        ("oral-history", "literal"),
        ("O'Brien", "literal"),
        ('"100%" OR history', "literal"),
        ("oral_ -confidential", "literal"),
        (r"C:\data OR history", "literal"),
    ],
)
def test_query_mode_precedence_and_whitespace(raw, mode):
    """Check query mode precedence and whitespace."""
    query = parse_search_query(raw)
    assert isinstance(query, SearchQuery)
    assert query.mode == mode
    assert query.term == raw.strip()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", "%%"),
        ("100%", r"%100\%%"),
        ("100_", r"%100\_%"),
        (r"C:\data", r"%C:\\data%"),
        ("  100%_\\path  ", "%100\\%\\_\\\\path%"),
    ],
)
def test_literal_pattern_escapes_backslash_before_sql_wildcards(raw, expected):
    """Check literal pattern escapes backslash before SQL wildcards."""
    assert parse_search_query(raw).pattern == expected


def test_query_model_preserves_unicode_and_case_without_stemming_or_accent_changes():
    """Check query model preserves unicode and case without stemming or accent changes."""
    query = parse_search_query("  Café Walked  ")
    assert is_dataclass(query)
    assert query.term == "Café Walked"
    assert query.pattern == "%Café Walked%"
    assert query.mode == "auto"


@pytest.mark.parametrize("raw", [None, True, b"history", ["history"]])
def test_query_parser_rejects_nontext_without_exposing_input(raw):
    """Check query parser rejects nontext without exposing input (TypeError)."""
    with pytest.raises(TypeError) as error:
        parse_search_query(raw)
    assert str(error.value) == "Search text must be a string"
