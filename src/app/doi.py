"""DOI name/URI boundary; DOI case equivalence is ASCII-only.

URI input is decoded exactly once. Bare names retain literal percent signs.
Non-resolver HTTP resource URLs remain a separate legacy compatibility form.
See https://www.doi.org/resources/DOI_URI_Scheme.pdf (sections 2-3).
"""

import re
from string import ascii_lowercase, ascii_uppercase
from urllib.parse import quote, unquote, urlsplit

from .url_safety import is_safe_http_url

_ASCII_FOLD = str.maketrans(ascii_uppercase, ascii_lowercase)
_NAME = re.compile(r"10\.[0-9]+(?:\.[0-9]+)*/[^\s]+\Z")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def canonicalize_doi(value: str) -> str | None:
    """Return an ASCII-case-folded DOI name, a legacy HTTP(S) resource URL, or None.

    Strip surrounding whitespace; percent-decode doi: and doi.org/dx.doi.org URLs
    exactly once as UTF-8. Resolver queries/fragments and malformed DOI names are
    rejected; bare names keep percent signs. Other structurally safe HTTP(S) URLs
    pass through unchanged. No network lookup occurs.
    """
    raw = value.strip()
    encoded = raw.lower().startswith("doi:")
    if encoded:
        raw = raw[4:]
    elif is_safe_http_url(raw):
        parsed = urlsplit(raw)
        if parsed.hostname not in {"doi.org", "dx.doi.org"}:
            return raw
        if parsed.query or parsed.fragment:
            return None
        raw = parsed.path.removeprefix("/")
        encoded = True
    if encoded:
        if _BAD_ESCAPE.search(raw):
            return None
        try:
            raw = unquote(raw, encoding="utf-8", errors="strict")
        except UnicodeError:
            return None
    if not _NAME.fullmatch(raw) or not raw.isprintable():
        return None
    return raw.translate(_ASCII_FOLD)


def doi_url(value: str) -> str:
    """Return an escaped https://doi.org/ URL, a legacy HTTP(S) resource URL, or empty string."""
    canonical = canonicalize_doi(value)
    if canonical is None:
        return ""
    if canonical.startswith("10."):
        return "https://doi.org/" + quote(canonical, safe="/")
    return canonical
