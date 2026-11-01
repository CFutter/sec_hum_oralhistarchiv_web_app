"""Classify catalogue search intent without interpreting protected metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

__all__ = ["SearchQuery", "parse_search_query", "validate_search_string"]

_WEB_SYNTAX = re.compile(r'"|(?<=\S)\s+OR\s+(?=\S)|(?:^|\s)-\S', re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """A bound search term, escaped substring pattern and explicit query mode."""

    term: str
    pattern: str
    mode: Literal["empty", "auto", "web", "literal"]


def validate_search_string(value: str) -> str:
    """Reject NUL before PostgreSQL adaptation without rewriting search input."""
    if not isinstance(value, str):
        raise TypeError("Search text must be a string")
    if "\x00" in value:
        raise ValueError("Search text contains an unsupported character")
    return value


def parse_search_query(raw: str) -> SearchQuery:
    """Keep literal punctuation while recognizing deliberate web-search syntax.

    Plain words use full-text matching with the former literal substring as a
    fallback. Quotes, OR between terms and a leading/separated minus select only
    web-search semantics. Percent, underscore and backslash always stay literal;
    other punctuation is literal unless explicit web syntax was requested.
    Trimming preserves the term's case, spelling and internal whitespace.
    """
    term = validate_search_string(raw).strip()
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    if not term:
        return SearchQuery(term, pattern, "empty")
    if any(character in term for character in "%_\\"):
        return SearchQuery(term, pattern, "literal")
    if _WEB_SYNTAX.search(term):
        return SearchQuery(term, pattern, "web")
    if all(character.isalnum() or character.isspace() for character in term):
        return SearchQuery(term, pattern, "auto")
    return SearchQuery(term, pattern, "literal")
