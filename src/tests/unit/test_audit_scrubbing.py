"""Audit-log scrubbing helpers and middleware wiring.

Pins the behavior of app.middleware.audit_logging:

- _scrub_path replaces the token segment of the three sensitive URL prefixes
  (/reset-password, /verify-email, /account/confirm-email) with '<token>' so
  one-time credentials never persist in 1-year audit logs.
- _scrub_query redacts every non-allowlisted query value (free-text search,
  email addresses = PII) while keeping the four categorical analytics params.
- AuditLoggingMiddleware stamps X-Request-ID on every response, emits exactly
  one 'request' audit record whose request_id matches the header, carries the
  scrubbed path and the session user id, and picks the log level from the
  response status (2xx→INFO, 4xx→WARNING).

Backlog tie-in: §2.16 documents X-Request-ID as the log↔response correlation
key; §8.2/§8.3 rely on these audit records surviving with scrubbed-but-useful
content.
"""
import logging
import re

import pytest

from app.middleware.audit_logging import _scrub_path, _scrub_query


# ---------------------------------------------------------------------------
# _scrub_path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/reset-password/abc.123_tok", "/reset-password/<token>"),
        ("/verify-email/x", "/verify-email/<token>"),
        ("/account/confirm-email/x", "/account/confirm-email/<token>"),
    ],
)
def test_scrub_path_replaces_token_segment(path, expected):
    """Each sensitive prefix has its token segment replaced with '<token>'.

    Guards against a regex edit dropping one of the three prefixes: a raw
    reset/verify/confirm token in the audit log is a credential leak.
    Note: the middleware passes request.url.path (query split off), so
    '/reset-password/tok?x=1' never reaches this function — only the bare
    path does; the query string goes through _scrub_query separately.
    """
    assert _scrub_path(path) == expected


def test_scrub_path_only_first_segment_after_prefix():
    """The regex `[^/?]+` stops at the next '/': only the FIRST segment after
    the prefix is treated as the token; a trailing sub-path survives verbatim.

    Pins the current (intentional) regex shape so a rewrite to a greedy match
    or a full-path replacement is caught.
    """
    assert (
        _scrub_path("/reset-password/abc.123_tok/extra")
        == "/reset-password/<token>/extra"
    )


def test_scrub_path_leaves_non_token_paths_unchanged():
    """Unrelated paths and a bare prefix with NO token segment pass through
    untouched — the regex requires '/<something>' after the prefix.

    Guards against over-eager scrubbing that would destroy analytics value
    of ordinary paths.
    """
    assert _scrub_path("/search") == "/search"
    assert _scrub_path("/reset-password") == "/reset-password"


# ---------------------------------------------------------------------------
# _scrub_query
# ---------------------------------------------------------------------------

def test_scrub_query_redacts_free_text_search():
    """Non-allowlisted values ('q' free-text search) are redacted; the
    allowlisted 'page' survives. PII typed into search boxes must not persist
    in 1-year audit logs."""
    assert _scrub_query("page=2&q=find+me") == "page=2&q=<redacted>"


def test_scrub_query_preserves_all_allowlisted_keys_verbatim():
    """All four allowlisted categorical keys (page/keyword/language/
    access_level) keep their values byte-for-byte — they are the analytics
    payload the scrubber exists to protect. Guards against a key being
    dropped from _SAFE_QUERY_PARAMS."""
    query = "page=3&keyword=oral+history&language=German&access_level=public"
    assert _scrub_query(query) == query


def test_scrub_query_redacts_email_param():
    """An 'email' parameter (URL-encoded PII) is redacted — emails must never
    persist in the audit trail via query strings."""
    assert _scrub_query("email=a%40b.com") == "email=<redacted>"


def test_scrub_query_bare_token_passes_through():
    """A valueless parameter ('flag', no '=') is appended as-is: there is no
    value to redact, and dropping it would corrupt the logged query shape."""
    assert _scrub_query("flag") == "flag"


def test_scrub_query_empty_string_returns_empty():
    """Empty query string short-circuits to '' (no stray separators)."""
    assert _scrub_query("") == ""


# ---------------------------------------------------------------------------
# Middleware wiring (real app + middleware stack, mocked pool)
# ---------------------------------------------------------------------------

def _request_records(caplog):
    """Audit-channel records of the per-request event type only (excludes
    other audit events, e.g. rate-limit warnings)."""
    return [
        r
        for r in caplog.records
        if r.name == "audit" and getattr(r, "event_type", None) == "request"
    ]


def test_guest_request_gets_request_id_and_audit_record(guest_client, caplog):
    """Every response carries X-Request-ID (16 hex chars) and one 'request'
    audit record whose .request_id matches the header — the correlation key
    that lets ops find the log line for a user-reported error (backlog §2.16).
    Guests log .user_id None (no session user)."""
    with caplog.at_level(logging.INFO, logger="audit"):
        response = guest_client.get("/about")

    assert response.status_code == 200
    header = response.headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{16}", header)

    records = _request_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.request_id == header
    assert record.event_type == "request"
    assert record.path == "/about"
    assert record.user_id is None


def test_audit_record_path_is_scrubbed_by_middleware(guest_client, caplog):
    """The middleware logs the SCRUBBED path: a real reset-password URL is
    recorded as '/reset-password/<token>' and the raw token never appears.
    Guards the wiring — _scrub_path being correct is useless if dispatch()
    stops calling it."""
    with caplog.at_level(logging.INFO, logger="audit"):
        response = guest_client.get("/reset-password/secret-token-value")

    # Bad token → error page (422), but the request is still audited.
    assert response.status_code == 422
    records = _request_records(caplog)
    assert len(records) == 1
    assert records[0].path == "/reset-password/<token>"
    assert "secret-token-value" not in records[0].path


def test_authenticated_request_logs_user_id(authenticated_client, caplog):
    """For an authenticated session the audit record carries the session
    user's id (request.state.user.id == 1 for the alice fixture) — the
    accountability half of the audit trail."""
    with caplog.at_level(logging.INFO, logger="audit"):
        response = authenticated_client.get("/about")

    assert response.status_code == 200
    records = _request_records(caplog)
    assert len(records) == 1
    assert records[0].user_id == 1


def test_request_id_is_unique_across_requests(guest_client, caplog):
    """TEST-054: request_id is minted per request (uuid4().hex[:16]), so two
    requests get DISTINCT ids — the property that makes log↔response
    correlation work. Hoisting the uuid4() to module scope would make every
    response share one id, and this fails."""
    with caplog.at_level(logging.INFO, logger="audit"):
        r1 = guest_client.get("/about")
        r2 = guest_client.get("/about")

    id1, id2 = r1.headers["X-Request-ID"], r2.headers["X-Request-ID"]
    assert id1 != id2, "two requests shared one request_id — correlation is dead"

    records = _request_records(caplog)
    logged_ids = {rec.request_id for rec in records}
    assert {id1, id2} <= logged_ids


def test_status_maps_to_log_level_4xx_warning_2xx_info(guest_client, caplog):
    """Level selection from status: 2xx logs at INFO, 4xx at WARNING — so
    error traffic is visible at operator log levels while routine traffic
    stays at INFO. Compares a 200 (/about) and a 404 (unknown path) record."""
    with caplog.at_level(logging.INFO, logger="audit"):
        ok = guest_client.get("/about")
        missing = guest_client.get("/no-such-page-anywhere")

    assert ok.status_code == 200
    assert missing.status_code == 404

    records = _request_records(caplog)
    assert len(records) == 2
    by_status = {r.status_code: r for r in records}
    assert by_status[200].levelno == logging.INFO
    assert by_status[404].levelno == logging.WARNING
