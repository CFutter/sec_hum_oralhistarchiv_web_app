"""Unit tests for `setup_logging` in src/config/logging.py: handler wiring,
audit-logger levels and propagation, and text/JSON format selection.

Pins, against src/config/logging.py:
- the audit logger keeps its own INFO level and a dedicated handler with no
  level filter, so raising the app LOG_LEVEL to WARNING cannot silently
  discard audit events, and audit records never double-emit through root's
  handlers;
- `setup_logging(log_format=...)` wires the app handler to the requested
  formatter (JSON or text) while the audit handler always gets `JSONFormatter`
  regardless of the app's chosen format;
- `AuditEmailAutoHash` is attached to the audit logger exactly once even
  across repeated `setup_logging()` calls.

No database is touched anywhere in this file.
"""

import json
import logging

import pytest

import config.logging as config_logging
from config.logging import (
    AuditEmailAutoHash,
    JSONFormatter,
    RedactingFormatter,
    setup_logging,
)
from config.settings import settings


class _ListHandler(logging.Handler):
    """Minimal capture handler: appends every record that reaches it."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestAuditLoggerLevelAndHandlerIsolation:
    """The audit logger is configured independently of the app's LOG_LEVEL
    and does not propagate into root's handlers."""

    @pytest.mark.usefixtures("restore_logging")
    def test_audit_info_survives_app_log_level_raised_to_warning(self):
        """With the app configured at WARNING, an INFO audit event must still
        reach the audit logger's handlers.

        With the audit logger's level left at NOTSET, its effective level
        would inherit root's WARNING and the record would die BEFORE handler
        dispatch — a silent compliance hole triggered by an ordinary
        quiet-the-app move.
        """
        setup_logging(log_level="WARNING", log_format="json")

        audit_logger = logging.getLogger("audit")
        capture = _ListHandler()
        audit_logger.addHandler(capture)
        try:
            audit_logger.info("login_success", extra={"event_type": "login_success"})
        finally:
            audit_logger.removeHandler(capture)

        assert len(capture.records) == 1
        assert capture.records[0].event_type == "login_success"

        # Both halves of the split: audit stays at INFO, the app side really is
        # at WARNING (proving the test exercised the dangerous configuration).
        assert audit_logger.isEnabledFor(logging.INFO)
        assert logging.getLogger().level == logging.WARNING

    @pytest.mark.usefixtures("restore_logging")
    def test_audit_logger_has_dedicated_handler_and_no_propagation(self):
        """setup_logging gives 'audit' its own handler (no LOG_LEVEL-derived
        handler level) and propagate=False, so audit records neither
        re-couple to root's level nor double-emit through root handlers."""
        setup_logging(log_level="WARNING", log_format="json")

        audit_logger = logging.getLogger("audit")
        assert audit_logger.propagate is False
        assert audit_logger.level == logging.INFO
        assert len(audit_logger.handlers) == 1
        # The dedicated handler must not filter by level (NOTSET = 0) and must
        # carry the audit-channel redactor, not the app one.
        handler = audit_logger.handlers[0]
        assert handler.level == logging.NOTSET
        assert config_logging._audit_redactor in handler.filters


class TestFormatSelection:
    """setup_logging(log_format=...) selects the app handler's formatter; the
    audit handler's format is not affected by that choice."""

    @pytest.mark.usefixtures("restore_logging")
    @pytest.mark.parametrize(
        ("log_format", "formatter_type"),
        (("json", JSONFormatter), ("text", RedactingFormatter)),
        ids=["json_format_selects_json_formatter", "text_format_selects_text_formatter"],
    )
    def test_setup_logging_wires_requested_formatter_to_app_handler(
        self,
        log_format,
        formatter_type,
    ):
        """The safe formatter contract must be active, not merely available."""
        setup_logging(log_format=log_format)

        root_handler = logging.getLogger().handlers[0]
        audit_handler = logging.getLogger("audit").handlers[0]
        assert type(root_handler.formatter) is formatter_type
        assert type(audit_handler.formatter) is JSONFormatter

    @pytest.mark.usefixtures("restore_logging")
    def test_audit_channel_stays_json_when_app_format_is_text(self, capsys):
        """The audit handler always carries `JSONFormatter` (never the text
        formatter), so an audit record logs as one JSON object with its extra
        fields intact even when `setup_logging(log_format="text")` switches
        the app channel to text — and a secret value placed in `extra` is
        still never reproduced in the output."""
        setup_logging(log_format="text")
        logging.getLogger("audit").info(
            "admin_user_tier_changed",
            extra={
                "actor_admin_id": 123,
                "target_user_id": 456,
                "request_id": "request-1",
                "old_value": "registered",
                "new_value": "vetted",
                "password": settings.secret_key.get_secret_value(),
            },
        )
        output = capsys.readouterr().out
        event = json.loads(output)
        assert event["actor_admin_id"] == 123
        assert event["target_user_id"] == 456
        assert event["request_id"] == "request-1"
        assert event["old_value"] == "registered"
        assert event["new_value"] == "vetted"
        assert settings.secret_key.get_secret_value() not in output


class TestSetupIdempotency:
    """Repeated setup_logging() calls must not accumulate duplicate state."""

    @pytest.mark.usefixtures("restore_logging")
    def test_repeated_setup_logging_does_not_duplicate_audit_email_autohash(self):
        """setup_logging registers the singleton on the audit LOGGER (so it
        runs before every handler, including test-capture handlers), and
        repeated setup_logging calls don't stack duplicate filters."""
        setup_logging()
        setup_logging()
        hits = [f for f in logging.getLogger("audit").filters if isinstance(f, AuditEmailAutoHash)]
        assert len(hits) == 1
