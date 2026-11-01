"""Logging handler wiring, audit levels and text/JSON formatter selection."""

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
        """Initialize the logging handler with an empty record buffer."""
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Append the record to the capture buffer."""
        self.records.append(record)


class TestAuditLoggerLevelAndHandlerIsolation:
    """The audit logger is configured independently of the app's LOG_LEVEL
    and does not propagate into root's handlers."""

    @pytest.mark.usefixtures("restore_logging")
    def test_audit_info_survives_app_log_level_raised_to_warning(self):
        """Retain INFO audit events when application logging is WARNING."""
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

        assert audit_logger.isEnabledFor(logging.INFO)
        assert logging.getLogger().level == logging.WARNING

    @pytest.mark.usefixtures("restore_logging")
    def test_audit_logger_has_dedicated_handler_and_no_propagation(self):
        """Use a dedicated unfiltered audit handler without root propagation."""
        setup_logging(log_level="WARNING", log_format="json")

        audit_logger = logging.getLogger("audit")
        assert audit_logger.propagate is False
        assert audit_logger.level == logging.INFO
        assert len(audit_logger.handlers) == 1
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
        """Keep audit output JSON and redact secrets when application output is text."""
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
        """Attach the audit-email hashing filter exactly once across repeated setup."""
        setup_logging()
        setup_logging()
        hits = [f for f in logging.getLogger("audit").filters if isinstance(f, AuditEmailAutoHash)]
        assert len(hits) == 1
