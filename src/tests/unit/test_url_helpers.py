"""URL safety + template URL helpers (unit tier, no DB).

Pins the behavior of:
- app.routes.auth.helpers.safe_redirect_url — the open-redirect guard on the
  post-login `next` parameter, including the path-internal-colon regression
  (the old blanket ':' ban rejected legitimate '/search?q=time:1990' targets).
- app.url_safety.is_safe_http_url — the single-source http(s) scheme allowlist
  shared by ingest and render.
- app.template_setup.safe_url_filter — the render-time last-line XSS guard.
- app.jinja_helpers.url_for_query — filter/pagination link builder, including
  the reset-pagination contract (page=None drops the key).

doi_url_filter is covered elsewhere (backlog §3.9) and intentionally skipped.
"""
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode

import pytest
from fastapi import Request

from app.jinja_helpers import url_for_query
from app.routes.auth.helpers import safe_redirect_url
from app.template_setup import safe_url_filter
from app.url_safety import is_safe_http_url


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------

def _request(query_string: bytes = b"") -> Request:
    """A real fastapi Request built from a minimal ASGI scope.

    safe_redirect_url only touches request.query_params, which Starlette
    parses lazily from scope['query_string'] — no app or client needed.
    """
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/login",
        "query_string": query_string,
        "headers": [],
    }
    return Request(scope)


def _request_with_next(value: str) -> Request:
    """Request whose query string carries next=<value>, percent-encoded the
    way a browser would submit it (so CR/NUL/etc. survive the round trip)."""
    return _request(urlencode({"next": value}).encode())


def _page_request(path: str = "/search", params: dict | None = None):
    """Duck-typed request for url_for_query: only .url.path and .query_params
    (dict-convertible) are read by the helper."""
    return SimpleNamespace(url=SimpleNamespace(path=path), query_params=dict(params or {}))


# ---------------------------------------------------------------------------
# safe_redirect_url — open-redirect guard
# ---------------------------------------------------------------------------

def test_safe_redirect_allows_plain_relative_path():
    """Happy path: a same-site absolute path passes through unchanged."""
    assert safe_redirect_url(_request(b"next=%2Faccount")) == "/account"


def test_safe_redirect_missing_next_returns_fallback():
    """No `next` parameter at all -> the default '/' fallback."""
    assert safe_redirect_url(_request(b"")) == "/"


@pytest.mark.parametrize("value", ["", "   "], ids=["empty", "whitespace-only"])
def test_safe_redirect_empty_or_whitespace_next_returns_fallback(value):
    """Empty / whitespace-only values are stripped to '' and fall back to '/'."""
    assert safe_redirect_url(_request_with_next(value)) == "/"


def test_safe_redirect_blocks_absolute_url():
    """Off-site absolute URL (has a scheme, no leading '/') -> fallback.
    The classic open-redirect payload."""
    assert safe_redirect_url(_request_with_next("https://evil.com")) == "/"


def test_safe_redirect_blocks_protocol_relative_url():
    """'//evil.com' resolves off-site against the current scheme -> fallback."""
    assert safe_redirect_url(_request_with_next("//evil.com")) == "/"


def test_safe_redirect_blocks_backslash_protocol_relative_variant():
    r"""'/\evil.com': browsers normalise '\' to '/', turning it into
    protocol-relative '//evil.com' -> fallback."""
    assert safe_redirect_url(_request_with_next("/\\evil.com")) == "/"


@pytest.mark.parametrize(
    "value",
    ["/foo\rbar", "/foo\nbar", "/foo\0bar"],
    ids=["carriage-return", "newline", "null-byte"],
)
def test_safe_redirect_blocks_crlf_and_null_injection(value):
    """Defense-in-depth: CR/LF (header-splitting) and NUL bytes -> fallback."""
    assert safe_redirect_url(_request_with_next(value)) == "/"


def test_safe_redirect_allows_path_internal_colon():
    """THE regression this helper exists for: '/search?q=time:1990' must be
    ALLOWED. The old implementation's blanket ':' ban rejected legitimate
    same-site search links containing colons; the structural urlsplit check
    (no scheme, no netloc) lets them through."""
    target = "/search?q=time:1990"
    assert safe_redirect_url(_request_with_next(target)) == target


def test_safe_redirect_blocks_javascript_scheme():
    """'javascript:alert(1)' has no leading '/' (and a scheme) -> fallback."""
    assert safe_redirect_url(_request_with_next("javascript:alert(1)")) == "/"


def test_safe_redirect_at_sign_in_path_passes_through():
    """'/foo@evil.com' is RETURNED AS-IS by the code as written.

    urlsplit('/foo@evil.com') yields no scheme and no netloc (netloc is only
    parsed after a leading '//'), so the structural backstop does not fire.
    NOTE: the docstring's "Rejects: URLs with embedded credentials
    (/foo@evil.com)" claim does NOT hold — but the behavior is still safe:
    a Location of '/foo@evil.com' is a same-origin path ('@' is a legal path
    character), not a redirect to evil.com. Pinning the actual (safe) code
    behavior; the docstring inaccuracy is reported as a deviation, not a bug.
    """
    assert safe_redirect_url(_request_with_next("/foo@evil.com")) == "/foo@evil.com"


def test_safe_redirect_unsafe_value_returns_custom_fallback():
    """The caller-supplied fallback (not hardcoded '/') is used on rejection."""
    req = _request_with_next("https://evil.com")
    assert safe_redirect_url(req, fallback="/account") == "/account"


# ---------------------------------------------------------------------------
# is_safe_http_url — scheme allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value",
    ["http://example.com", "https://example.com/page?a=1", "HTTPS://X"],
    ids=["http", "https", "uppercase-scheme"],
)
def test_is_safe_http_url_accepts_http_schemes(value):
    """http:// and https:// pass; the check lowercases first, so scheme
    matching is case-insensitive (HTTPS://X is fine)."""
    assert is_safe_http_url(value) is True


def test_is_safe_http_url_strips_padding_before_check():
    """' https://x ' -> True: the code strips BEFORE startswith, so leading/
    trailing whitespace does not defeat the allowlist. Pinned from the code
    (value.strip().lower().startswith(...))."""
    assert is_safe_http_url(" https://x ") is True


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "data:text/html;base64,PGI+",
        "//host/path",
        "https:foo",   # scheme-only form without '//' — not an absolute URL
        "ftp://example.com",
        None,
        "",
    ],
    ids=["javascript", "data", "protocol-relative", "scheme-only", "ftp", "none", "empty"],
)
def test_is_safe_http_url_rejects_non_http(value):
    """Everything that isn't an absolute http(s):// URL is False — including
    None and '' (the `bool(value and ...)` guard)."""
    assert is_safe_http_url(value) is False


# ---------------------------------------------------------------------------
# safe_url_filter — render-time guard
# ---------------------------------------------------------------------------

def test_safe_url_filter_strips_and_returns_safe_url():
    """A safe URL is returned stripped of surrounding whitespace, so padded
    DB values don't produce ' https://...' hrefs."""
    assert safe_url_filter("  https://example.com/doc  ") == "https://example.com/doc"


@pytest.mark.parametrize(
    "value",
    ["javascript:alert(1)", "//evil.com", "data:text/html,x", ""],
    ids=["javascript", "protocol-relative", "data", "empty"],
)
def test_safe_url_filter_returns_empty_for_unsafe(value):
    """Unsafe / empty values render as '' — the last-line XSS defense drops
    the href entirely instead of emitting an executable scheme."""
    assert safe_url_filter(value) == ""


# ---------------------------------------------------------------------------
# url_for_query — filter/pagination link builder
# ---------------------------------------------------------------------------

def test_url_for_query_preserves_existing_params():
    """Existing query params survive when a new one is added (active filters
    must not be lost when a pagination link is built)."""
    req = _page_request(params={"q": "migration"})
    assert url_for_query(req, page="2") == "/search?q=migration&page=2"


def test_url_for_query_overrides_on_collision():
    """A new value for an existing key overwrites it (clicking page 1 while on
    page 3 must not produce two page params)."""
    req = _page_request(params={"q": "migration", "page": "3"})
    url = url_for_query(req, page="1")
    path, _, query = url.partition("?")
    assert path == "/search"
    assert parse_qs(query) == {"q": ["migration"], "page": ["1"]}


def test_url_for_query_none_removes_key():
    """THE reset-pagination contract: page=None DROPS the page param so the
    next request defaults to page 1, while other filters are preserved."""
    req = _page_request(params={"q": "migration", "page": "5"})
    assert url_for_query(req, page=None) == "/search?q=migration"


def test_url_for_query_empty_string_removes_key():
    """Empty string is treated like None (falsy) — the key is removed, not
    emitted as 'page=' noise."""
    req = _page_request(params={"q": "migration", "page": "5"})
    assert url_for_query(req, page="") == "/search?q=migration"


def test_url_for_query_removing_absent_key_is_a_noop():
    """Removing a key that isn't present must not raise (params.pop(key, None))."""
    req = _page_request(params={"q": "migration"})
    assert url_for_query(req, page=None) == "/search?q=migration"


def test_url_for_query_encodes_spaces():
    """Values are urlencoded: a space becomes '+' (quote_plus), so template
    output is a valid href and round-trips back to the original value."""
    req = _page_request(params={})
    url = url_for_query(req, keyword="oral history")
    assert url == "/search?keyword=oral+history"
    assert parse_qs(url.partition("?")[2]) == {"keyword": ["oral history"]}
