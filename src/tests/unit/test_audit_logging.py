"""Audit-log request-target safety, middleware wiring, and event helpers.

Covers the boundary shared by `app.request_utils` and the audit-log
middleware/helpers in `app.middleware.audit_logging` and
`app.services.audit`:

- scrub_sensitive_path replaces capability-bearing segments in the three
  sensitive URL prefixes
  (/reset-password, /verify-email, /account/confirm-email) with '<token>' so
  one-time credentials never persist in long-lived audit logs.
- safe_request_path prefers the matched route template and falls back to path
  scrubbing when routing has not completed.
- scrub_sensitive_query retains bounded query structure/presence only. No
  request-supplied query name or value may persist as audit data.
- AuditLoggingMiddleware stamps X-Request-ID on every response, emits exactly
  one 'request' audit record whose request_id matches the header, carries the
  scrubbed path and the session user id, and picks the log level from the
  response status (2xx to INFO, 4xx to WARNING).
- audit_admin_action and audit_user_event (the two structured-event helpers)
  stamp consistent fields onto every record, and audit_admin_action refuses
  to log an unattributable admin action.

X-Request-ID is the log-to-response correlation key that lets operators find
the log line for a user-reported error; the audit records must survive with
scrubbed-but-useful content.
"""

import logging
import re
from http import HTTPStatus
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.types import Scope

from app.main import app
from app.request_utils import (
    safe_request_path,
    scrub_sensitive_path,
    scrub_sensitive_query,
)
from app.services import audit
from config.logging import JSONFormatter

# ---------------------------------------------------------------------------
# Request-path safety
# ---------------------------------------------------------------------------


class TestScrubSensitivePath:
    """`scrub_sensitive_path` removes capability tokens from request paths."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/reset-password/abc.123_tok", "/reset-password/<token>"),
            ("/verify-email/x", "/verify-email/<token>"),
            ("/account/confirm-email/x", "/account/confirm-email/<token>"),
        ],
        ids=[
            "reset_password_token_segment_replaced",
            "verify_email_token_segment_replaced",
            "confirm_email_token_segment_replaced",
        ],
    )
    def test_replaces_token_segment(self, path, expected):
        """Each sensitive prefix has its token segment replaced with '<token>'.

        Guards against a regex edit dropping one of the three prefixes: a raw
        reset/verify/confirm token in the audit log is a credential leak.
        Note: the middleware passes request.url.path (query split off), so
        '/reset-password/tok?x=1' never reaches this function — only the bare
        path does; the query string goes through scrub_sensitive_query
        separately.
        """
        assert scrub_sensitive_path(path) == expected

    def test_only_first_segment_after_prefix_is_treated_as_token(self):
        """The regex `[^/?]+` stops at the next '/': only the FIRST segment
        after the prefix is treated as the token; a trailing sub-path
        survives verbatim.

        Pins the current (intentional) regex shape so a rewrite to a greedy
        match or a full-path replacement is caught.
        """
        assert (
            scrub_sensitive_path("/reset-password/abc.123_tok/extra")
            == "/reset-password/<token>/extra"
        )

    def test_leaves_non_token_paths_unchanged(self):
        """Unrelated paths and a bare prefix with NO token segment pass
        through untouched — the regex requires '/<something>' after the
        prefix.

        Guards against over-eager scrubbing that would destroy analytics
        value of ordinary paths.
        """
        assert scrub_sensitive_path("/search") == "/search"
        assert scrub_sensitive_path("/reset-password") == "/reset-password"

    def test_every_token_route_template_is_scrubbed(self):
        """For each token-bearing route, rendering the template with a probe
        token and passing the resulting path through scrub_sensitive_path
        must remove the probe. If someone adds a new '/x/{token}' route
        without extending _TOKEN_PATH_REGEX, its probe survives and this
        fails.
        """
        routes = _token_bearing_routes()
        # Sanity: the app really does have token routes — a zero here would
        # make the invariant vacuously pass (e.g. after a refactor renamed
        # the param).
        assert routes, "no {token} routes found — has the param naming changed?"

        probe = "PROBE-RAW-TOKEN-must-not-survive-1234567890"
        unscrubbed = []
        for template in routes:
            concrete = template.replace("{token}", probe)
            if probe in scrub_sensitive_path(concrete):
                unscrubbed.append(template)

        assert not unscrubbed, (
            "these token-bearing routes are NOT covered by _TOKEN_PATH_REGEX, "
            f"so raw tokens would persist in the audit log: {unscrubbed}. "
            "Add the prefix to _TOKEN_PATH_REGEX in app/request_utils.py."
        )


def _token_bearing_routes():
    """Every registered route whose path template carries a {token}-like
    parameter. 'token-like' = a path parameter named 'token' (the current
    convention for one-time capability URLs: reset-password, verify-email,
    account/confirm-email)."""
    out = []
    for route in app.routes:
        template = getattr(route, "path", None)
        if template and "{token}" in template:
            out.append(template)
    return out


def _request(path: str, *, route_template: str | None = None) -> Request:
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("192.0.2.1", 12345),
        "server": ("archive.example", 443),
    }
    if route_template is not None:
        scope["route"] = SimpleNamespace(path=route_template)
    return Request(scope)


class TestSafeRequestPath:
    """`safe_request_path` picks a log-safe path whether or not routing has
    matched yet."""

    def test_prefers_matched_route_template(self):
        """A routed request must log its static template, never its token
        value."""
        canary = "LIVE-CAPABILITY-CANARY"
        request = _request(
            f"/reset-password/{canary}",
            route_template="/reset-password/{token}",
        )

        safe_path = safe_request_path(request)

        assert safe_path == "/reset-password/{token}"
        assert canary not in safe_path

    def test_scrubs_before_or_without_route_match(self):
        """Early middleware and unmatched requests still get a safe
        fallback."""
        canary = "EARLY-MIDDLEWARE-CANARY"
        safe_path = safe_request_path(_request(f"/verify-email/{canary}"))

        assert safe_path == "/verify-email/<token>"
        assert canary not in safe_path


# ---------------------------------------------------------------------------
# Query-string safety
# ---------------------------------------------------------------------------


class TestScrubSensitiveQuery:
    """`scrub_sensitive_query` preserves structure only, never values."""

    def test_redacts_free_text_search(self):
        """Even known parameter values are represented only by their
        presence."""
        query = "page=2&q=sensitive-participant-name"
        scrubbed = scrub_sensitive_query(query)

        assert scrubbed == "page=<present>&q=<present>"
        assert "2" not in scrubbed
        assert "sensitive-participant-name" not in scrubbed

    def test_legacy_semicolon_separator_does_not_smuggle_pii(self):
        """A second parameter after legacy ';' cannot ride inside the
        first."""
        assert scrub_sensitive_query("page=1;q=secret") == "page=<present>&q=<present>"

    def test_known_keys_are_presence_only(self):
        """Categorical filters can carry PII and must not survive
        verbatim."""
        values = ("3", "participant-name", "rare-language", "vetted")
        query = (
            f"page={values[0]}&keyword={values[1]}&language={values[2]}&access_level={values[3]}"
        )

        scrubbed = scrub_sensitive_query(query)

        assert scrubbed == (
            "page=<present>&keyword=<present>&language=<present>&access_level=<present>"
        )
        assert all(value not in scrubbed for value in values)

    def test_redacts_unknown_name_and_value(self):
        """Unknown names are untrusted too, so neither half reaches the
        log."""
        scrubbed = scrub_sensitive_query("participant-name=person%40example.org")

        assert scrubbed == "<parameter>=<redacted>"
        assert "participant-name" not in scrubbed
        assert "person%40example.org" not in scrubbed

    def test_bare_unknown_parameter_hides_its_name(self):
        """A bare parameter name remains attacker-controlled and is
        hidden."""
        assert scrub_sensitive_query("participant-name") == "<parameter>"

    def test_empty_string_returns_empty(self):
        """Empty query string short-circuits to '' (no stray separators)."""
        assert scrub_sensitive_query("") == ""

    def test_output_is_bounded(self):
        """Many separators cannot amplify a small request into an unbounded
        log."""
        query = "&".join(f"unknown-{index}=value-{index}" for index in range(100))

        scrubbed = scrub_sensitive_query(query)

        assert scrubbed.endswith("<truncated>")
        assert len(scrubbed) < len(query)
        assert "unknown-99" not in scrubbed
        assert "value-99" not in scrubbed


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


class TestAuditLoggingMiddleware:
    """`AuditLoggingMiddleware` stamps a correlation id and emits exactly one
    scrubbed audit record per request."""

    def test_guest_request_gets_request_id_and_audit_record(self, guest_client, caplog):
        """Every response carries X-Request-ID (16 hex chars) and one
        'request' audit record whose .request_id matches the header — the
        correlation key that lets operators find the log line for a
        user-reported error. Guests log .user_id None (no session user)."""
        with caplog.at_level(logging.INFO, logger="audit"):
            response = guest_client.get("/about")

        assert response.status_code == HTTPStatus.OK
        header = response.headers["X-Request-ID"]
        assert re.fullmatch(r"[0-9a-f]{16}", header)

        records = _request_records(caplog)
        assert len(records) == 1
        record = records[0]
        assert record.request_id == header
        assert record.event_type == "request"
        assert record.path == "/about"
        assert record.user_id is None

    def test_record_path_is_scrubbed_by_middleware(self, guest_client, caplog):
        """After routing, audit records use the token-free route
        template."""
        canary = "AUDIT-PATH-CANARY"
        with caplog.at_level(logging.INFO, logger="audit"):
            response = guest_client.get(f"/reset-password/{canary}")

        # Bad token → error page (422), but the request is still audited.
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
        records = _request_records(caplog)
        assert len(records) == 1
        assert records[0].path == "/reset-password/{token}"
        assert canary not in records[0].getMessage()
        assert canary not in repr(records[0].__dict__)

    def test_query_record_never_contains_query_values(self, guest_client, caplog):
        """The middleware may record filter presence, but never submitted
        values."""
        canaries = (
            "Q-CANARY",
            "KEYWORD-CANARY",
            "UNKNOWN-NAME",
            "UNKNOWN-VALUE",
        )
        query = f"q={canaries[0]}&keyword={canaries[1]}&{canaries[2]}={canaries[3]}"

        with caplog.at_level(logging.INFO, logger="audit"):
            response = guest_client.get(f"/about?{query}")

        assert response.status_code == HTTPStatus.OK
        records = _request_records(caplog)
        assert len(records) == 1
        assert records[0].query_string == ("q=<present>&keyword=<present>&<parameter>=<redacted>")
        serialized_record = repr(records[0].__dict__)
        assert all(canary not in serialized_record for canary in canaries)

    def test_authenticated_request_logs_user_id(self, authenticated_client, caplog):
        """For an authenticated session the audit record carries the session
        user's id (request.state.user.id == 1 for the alice fixture) — the
        accountability half of the audit trail."""
        with caplog.at_level(logging.INFO, logger="audit"):
            response = authenticated_client.get("/about")

        assert response.status_code == HTTPStatus.OK
        records = _request_records(caplog)
        assert len(records) == 1
        assert records[0].user_id == 1

    def test_request_id_is_unique_across_requests(self, guest_client, caplog):
        """request_id is minted per request (uuid4().hex[:16]), so two
        requests get DISTINCT ids — the property that makes log-to-response
        correlation work. Hoisting the uuid4() to module scope would make
        every response share one id, and this fails."""
        with caplog.at_level(logging.INFO, logger="audit"):
            r1 = guest_client.get("/about")
            r2 = guest_client.get("/about")

        id1, id2 = r1.headers["X-Request-ID"], r2.headers["X-Request-ID"]
        assert id1 != id2, "two requests shared one request_id — correlation is dead"

        records = _request_records(caplog)
        logged_ids = {rec.request_id for rec in records}
        assert {id1, id2} <= logged_ids

    def test_status_maps_to_log_level_4xx_warning_2xx_info(self, guest_client, caplog):
        """Level selection from status: 2xx logs at INFO, 4xx at WARNING —
        so error traffic is visible at operator log levels while routine
        traffic stays at INFO. Compares a 200 (/about) and a 404 (unknown
        path) record."""
        with caplog.at_level(logging.INFO, logger="audit"):
            ok = guest_client.get("/about")
            missing = guest_client.get("/no-such-page-anywhere")

        assert ok.status_code == HTTPStatus.OK
        assert missing.status_code == HTTPStatus.NOT_FOUND

        records = _request_records(caplog)
        assert len(records) == 2
        by_status = {r.status_code: r for r in records}
        assert by_status[HTTPStatus.OK].levelno == logging.INFO
        assert by_status[HTTPStatus.NOT_FOUND].levelno == logging.WARNING


# ---------------------------------------------------------------------------
# Event helpers (services/audit.py)
# ---------------------------------------------------------------------------
#
# Route-level tests above pin the canonical events end-to-end; these pin the
# two helper functions' own branch logic — in particular the tamper-evidence
# branch that no route can easily reach.
#
# The audit logger has propagate=False after setup_logging runs, so caplog
# (root-attached) can miss it; these attach a handler to the 'audit' logger
# directly, exercised via a minimal fake Request (the helpers only read
# request.state, request.client, request.scope and request.headers).


class TestCapabilityTokensStayOutOfEveryApplicationLogLine:
    """Password-reset, verification, and email-change links carry a live,
    single-use credential in the URL itself. Anyone who can read the archive's
    logs could otherwise use one before its owner does, so no log line the
    application writes while serving such a request may contain the token —
    not just the audit record, and whichever module did the logging.
    """

    CAPABILITY_ROUTE_PREFIXES = ("/reset-password", "/verify-email", "/account/confirm-email")

    def test_serving_capability_requests_writes_no_line_containing_the_token(
        self, guest_client, caplog
    ):
        """Every record emitted while the three capability requests are served
        is rendered exactly as the configured handler would render it, then
        searched for the credential."""
        token = "CAPABILITY-LINK-CANARY-must-not-be-logged-8f21c0"

        with caplog.at_level(logging.DEBUG):
            for prefix in self.CAPABILITY_ROUTE_PREFIXES:
                guest_client.get(f"{prefix}/{token}", follow_redirects=False)

        assert caplog.records, "the requests produced no log records to inspect"
        formatter = JSONFormatter()
        leaking = [record.name for record in caplog.records if token in formatter.format(record)]
        assert not leaking, f"these loggers wrote the capability token: {sorted(set(leaking))}"

    def test_a_throttled_capability_request_is_logged_by_route_not_by_token(
        self, guest_client, caplog
    ):
        """The throttling path logs the request target too. It must name the
        route, so operators can still see which endpoint is under pressure
        without the log becoming a list of live credentials."""
        token = "THROTTLED-CAPABILITY-CANARY-must-not-be-logged-3ad917"

        with caplog.at_level(logging.WARNING):
            for _ in range(11):
                response = guest_client.get(f"/reset-password/{token}", follow_redirects=False)

        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        throttle_records = [
            record for record in caplog.records if record.getMessage() == "Rate limit exceeded"
        ]
        assert len(throttle_records) == 1
        throttled_path = throttle_records[0].path
        assert throttled_path.startswith("/reset-password/"), (
            "the throttle log no longer says which endpoint was under pressure"
        )
        assert token not in throttled_path

        formatter = JSONFormatter()
        assert all(token not in formatter.format(record) for record in caplog.records)


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def audit_capture():
    """Attach a capturing handler straight to the 'audit' logger (propagate
    is False, so caplog on root would miss these records), and force its
    level to INFO for the duration (setup_logging hasn't run in the unit
    tier, so the logger defaults to WARNING and would drop .info records)."""
    handler = _Capture()
    logger = logging.getLogger("audit")
    saved_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved_level)


def _fake_request(user):
    """Minimal Request stand-in: the helpers read request.state.user,
    request.state.request_id, request.client and (via get_client_ip)
    request.scope['server'] + request.headers."""
    return SimpleNamespace(
        state=SimpleNamespace(user=user, request_id="req-abc123"),
        client=SimpleNamespace(host="203.0.113.7"),
        scope={"server": ("testserver", 80)},
        headers={},
    )


class TestAuditAdminAction:
    """`audit_admin_action` requires an attributable actor before it will log
    the intended event."""

    def test_records_normal_event_with_actor(self, audit_capture):
        """Baseline: with an admin actor present, the intended event is
        logged at INFO with actor_admin_id + target_user_id + the extra
        fields."""
        admin = SimpleNamespace(id=42)
        audit.audit_admin_action(
            level=logging.INFO,
            request=_fake_request(admin),
            event_type="admin_user_tier_changed",
            target_user_id=7,
            old_value="public",
            new_value="vetted",
        )

        assert len(audit_capture.records) == 1
        rec = audit_capture.records[0]
        assert rec.levelno == logging.INFO
        assert rec.event_type == "admin_user_tier_changed"
        assert rec.actor_admin_id == 42
        assert rec.target_user_id == 7
        assert rec.new_value == "vetted"

    def test_no_actor_is_critical_and_suppresses_event(self, audit_capture):
        """request.state.user is None → a CRITICAL 'admin_action_no_actor'
        record (attempted_event names the suppressed event), and the
        intended event is NOT logged. Logging the real event with actor=None
        would put an unattributable privilege change in the audit trail;
        raising instead would 500 the admin route mid-action."""
        audit.audit_admin_action(
            level=logging.INFO,
            request=_fake_request(None),
            event_type="admin_user_admin_changed",
            target_user_id=7,
            old_value=False,
            new_value=True,
        )

        assert len(audit_capture.records) == 1
        rec = audit_capture.records[0]
        assert rec.levelno == logging.CRITICAL
        assert rec.event_type == "admin_action_no_actor"
        assert rec.attempted_event == "admin_user_admin_changed"
        assert rec.target_user_id == 7
        # The real event's own name must NOT have been logged.
        assert not any(r.event_type == "admin_user_admin_changed" for r in audit_capture.records)


class TestAuditUserEvent:
    """`audit_user_event` stamps identity and correlation fields onto
    self-service account events."""

    def test_carries_ip_and_request_id(self, audit_capture):
        """audit_user_event stamps event_type, user_id, the resolved client
        ip, and request_id, plus caller-supplied fields."""
        audit.audit_user_event(
            level=logging.INFO,
            request=_fake_request(None),
            event_type="password_reset_requested",
            user_id=None,
            email_attempted_hash="abcd",
        )

        assert len(audit_capture.records) == 1
        rec = audit_capture.records[0]
        assert rec.event_type == "password_reset_requested"
        assert rec.user_id is None
        assert rec.request_id == "req-abc123"
        assert rec.email_attempted_hash == "abcd"
        # get_client_ip resolves from the peer when proxy trust is off.
        assert rec.client_ip == "203.0.113.7"
