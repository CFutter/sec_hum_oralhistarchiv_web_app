"""Audit request-target scrubbing, middleware correlation and attributed event helpers."""

import logging
import re
from http import HTTPStatus
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.types import Scope

from app.main import app
from app.request_log_contract import RATE_LIMIT_LOG_PATH_STATE
from app.request_utils import (
    safe_request_path,
    scrub_sensitive_path,
    scrub_sensitive_query,
)
from app.services import audit
from app.services.tokens import action_token_public_id, action_token_url
from config.logging import JSONFormatter


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
        """Each sensitive prefix has its token segment replaced with '<token>'."""
        assert scrub_sensitive_path(path) == expected

    def test_only_first_segment_after_prefix_is_treated_as_token(self):
        """Scrub only the first capability segment, preserving a trailing subpath."""
        assert (
            scrub_sensitive_path("/reset-password/abc.123_tok/extra")
            == "/reset-password/<token>/extra"
        )

    def test_leaves_non_token_paths_unchanged(self):
        """Preserve unrelated paths and bare action prefixes."""
        assert scrub_sensitive_path("/search") == "/search"
        assert scrub_sensitive_path("/reset-password") == "/reset-password"

    def test_every_token_route_template_is_scrubbed(self):
        """Every action landing path stays scrubbed, including legacy input."""
        routes = _token_bearing_routes()
        assert set(routes) == {
            "/reset-password/{public_id}",
            "/verify-email/{public_id}",
            "/account/confirm-email/{public_id}",
        }
        assert not any("{token}" in getattr(route, "path", "") for route in app.routes)

        probe = "PROBE-RAW-TOKEN-must-not-survive-1234567890"
        unscrubbed = []
        for template in routes:
            concrete = template.replace("{public_id}", probe)
            if probe in scrub_sensitive_path(concrete):
                unscrubbed.append(template)

        assert not unscrubbed, (
            "these action routes are NOT covered by _TOKEN_PATH_REGEX, "
            f"so raw tokens would persist in the audit log: {unscrubbed}. "
            "Add the prefix to _TOKEN_PATH_REGEX in app/request_utils.py."
        )


def _token_bearing_routes():
    """Return the three public-ID landing routes protected by legacy scrubbing."""
    out = []
    for route in app.routes:
        template = getattr(route, "path", None)
        if template and "{public_id}" in template:
            out.append(template)
    return out


def _request(path: str, *, route_template: str | None = None) -> Request:
    """Build an HTTPS request with an optional matched route template."""
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
            route_template="/reset-password/{public_id}",
        )
        setattr(request.state, RATE_LIMIT_LOG_PATH_STATE, "/<unresolved>")

        safe_path = safe_request_path(request)

        assert safe_path == "/reset-password/{public_id}"
        assert canary not in safe_path

    @pytest.mark.parametrize("label", ["/dataset/{dataset_id}", "/<unmatched>", "/<unresolved>"])
    def test_uses_admission_label_before_routing(self, label):
        """Uses admission label before routing."""
        request = _request("/dataset/123456")
        setattr(request.state, RATE_LIMIT_LOG_PATH_STATE, label)

        assert safe_request_path(request) == label

    @pytest.mark.parametrize("label", [None, 123, {"path": "/forged-label"}])
    def test_non_string_admission_state_keeps_the_scrubbed_fallback(self, label):
        """Non string admission state keeps the scrubbed fallback."""
        request = _request("/verify-email/capability-canary")
        setattr(request.state, RATE_LIMIT_LOG_PATH_STATE, label)

        assert safe_request_path(request) == "/verify-email/<token>"

    def test_similarly_named_request_inputs_do_not_supply_an_internal_label(self):
        """Similarly named request inputs do not supply an internal label."""
        request = _request("/verify-email/capability-canary")
        request.scope["headers"] = [
            (b"rate_limit_log_path", b"/forged-header-label"),
            (b"x-rate-limit-log-path", b"/forged-header-label"),
        ]
        request.scope["query_string"] = b"rate_limit_log_path=/forged-query-label"

        assert safe_request_path(request) == "/verify-email/<token>"

    def test_scrubs_before_or_without_route_match(self):
        """Early middleware and unmatched requests still get a safe
        fallback."""
        canary = "EARLY-MIDDLEWARE-CANARY"
        safe_path = safe_request_path(_request(f"/verify-email/{canary}"))

        assert safe_path == "/verify-email/<token>"
        assert canary not in safe_path


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
        """Correlate the response with one guest audit event using a 16-hex-digit request ID."""
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

        assert response.status_code == HTTPStatus.NOT_FOUND
        records = _request_records(caplog)
        assert len(records) == 1
        assert records[0].path == "/reset-password/{public_id}"
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
        """Attribute the request audit event to the session user."""
        with caplog.at_level(logging.INFO, logger="audit"):
            response = authenticated_client.get("/about")

        assert response.status_code == HTTPStatus.OK
        records = _request_records(caplog)
        assert len(records) == 1
        assert records[0].user_id == 1

    def test_request_id_is_unique_across_requests(self, guest_client, caplog):
        """Generate a distinct correlation ID for each request."""
        with caplog.at_level(logging.INFO, logger="audit"):
            r1 = guest_client.get("/about")
            r2 = guest_client.get("/about")

        id1, id2 = r1.headers["X-Request-ID"], r2.headers["X-Request-ID"]
        assert id1 != id2, "two requests shared one request_id — correlation is dead"

        records = _request_records(caplog)
        logged_ids = {rec.request_id for rec in records}
        assert {id1, id2} <= logged_ids

    def test_status_maps_to_log_level_4xx_warning_2xx_info(self, guest_client, caplog):
        """Log successful requests at INFO and client errors at WARNING."""
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


class TestCapabilityTokensStayOutOfEveryApplicationLogLine:
    """Keep current action identifiers and legacy capabilities out of application logs."""

    CAPABILITY_ROUTE_PREFIXES = ("/reset-password", "/verify-email", "/account/confirm-email")

    def test_serving_capability_requests_writes_no_line_containing_the_token(
        self, guest_client, caplog
    ):
        """Keep capability bytes out of every formatted application record."""
        token = "CAPABILITY-LINK-CANARY-must-not-be-logged-8f21c0"

        with caplog.at_level(logging.DEBUG):
            for prefix in self.CAPABILITY_ROUTE_PREFIXES:
                legacy = guest_client.get(f"{prefix}/{token}", follow_redirects=False)
                assert legacy.status_code == HTTPStatus.NOT_FOUND
                current = guest_client.get(action_token_url(prefix, token), follow_redirects=False)
                assert current.status_code == HTTPStatus.OK

        assert caplog.records, "the requests produced no log records to inspect"
        formatter = JSONFormatter()
        leaking = [record.name for record in caplog.records if token in formatter.format(record)]
        assert not leaking, f"these loggers wrote the capability token: {sorted(set(leaking))}"

    def test_a_throttled_capability_request_is_logged_by_route_not_by_token(
        self, guest_client, caplog
    ):
        """Identify throttled action requests by route while omitting credential bytes."""
        token = "THROTTLED-CAPABILITY-CANARY-must-not-be-logged-3ad917"
        public_id = action_token_public_id(token)

        with caplog.at_level(logging.WARNING):
            for _ in range(11):
                response = guest_client.get(f"/reset-password/{public_id}", follow_redirects=False)

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
    """Capture emitted records without formatting them."""

    def __init__(self):
        """Initialize the logging handler with an empty record buffer."""
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        """Append the record to the capture buffer."""
        self.records.append(record)


@pytest.fixture
def audit_capture():
    """Capture INFO audit records directly; restore logger state after the test."""
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
    """Build the minimal request state read by audit helpers."""
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
        """Log admin_action_no_actor at CRITICAL and suppress an unattributable action."""
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
