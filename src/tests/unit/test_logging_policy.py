"""Formatting failures and policy boundaries remain safe through real handlers."""

import gc
import io
import json
import logging
import smtplib
import warnings
import weakref
from unittest.mock import create_autospec

import pytest
from pydantic import SecretStr

import app.services.email as email_service
import config.logging as log_config
from config.settings import settings


@pytest.mark.parametrize("audit", [False, True])
def test_malformed_call_survives_filters_and_emits_following_event(audit, monkeypatch):
    """Malformed call survives filters and emits following event."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(log_config.JSONFormatter(audit=audit))
    if audit:
        handler.addFilter(log_config._audit_email_autohash)
    handler.addFilter(log_config._audit_redactor if audit else log_config._redactor)
    logger = logging.getLogger("format-fault")
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "level", logging.INFO)

    logger.error("invalid %d", "sensitive@example.org")
    logger.info("following event")

    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [event["message"] for event in events] == [
        "<log formatting failed>",
        "following event",
    ]
    assert "sensitive@example.org" not in stream.getvalue()


def test_empty_optional_secret_does_not_warn_but_short_present_secret_does(monkeypatch):
    """Empty optional secret does not warn but short present secret does."""
    monkeypatch.setattr(settings, "smtp_password", SecretStr(""))
    monkeypatch.setattr(settings, "rate_limit_redis_url", SecretStr(""))
    monkeypatch.setattr(settings, "session_secret", SecretStr("short"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _ = log_config.SensitiveDataFilter().patterns
    messages = [str(warning.message) for warning in caught]
    assert any("session_secret" in message for message in messages)
    assert not any("smtp_password" in message for message in messages)
    assert not any("rate_limit_redis_url" in message for message in messages)


def test_json_formatter_reuses_filter_work_and_redacts_generated_diagnostics(monkeypatch):
    """JSON formatter reuses filter work and redacts generated diagnostics."""
    calls = []
    original = log_config._redactor.apply

    def track(value):
        """Record each transformed value before invoking the real transformer."""
        calls.append(value)
        return original(value)

    monkeypatch.setattr(log_config._redactor, "apply", track)
    record = logging.makeLogRecord({"msg": "unique submitted payload", "nested": {"item": "x"}})
    log_config._redactor.filter(record)
    formatter = log_config.JSONFormatter()
    # Diagnostics are generated after the submitted message/extras were filtered.
    record.exc_info = (ValueError, ValueError("omitted"), None)
    monkeypatch.setattr(
        formatter,
        "_exception_diagnostic",
        lambda _info: {"type": "ValueError", "frames": ["sensitive@example.org"]},
    )
    payload = json.loads(formatter.format(record))
    assert calls.count("unique submitted payload") == 1
    assert payload["exception"]["frames"] == ["[REDACTED:email]"]
    assert "_oha_redaction_applied" not in payload
    assert "_oha_audit_hash_applied" not in payload


@pytest.mark.parametrize("filtered", [False, True])
def test_audit_formatter_keeps_hash_policy_for_payload_and_generated_metadata(
    monkeypatch, filtered
):
    """Audit formatter keeps hash policy for payload and generated metadata."""
    monkeypatch.setattr(log_config, "_audit_email_hasher", lambda _value: "stable-hash")
    record = logging.makeLogRecord(
        {"msg": "actor@example.org", "actor": "actor@example.org", "funcName": "actor@example.org"}
    )
    if filtered:
        log_config._audit_email_autohash.filter(record)
        log_config._audit_redactor.filter(record)
    payload = json.loads(log_config.JSONFormatter(audit=True).format(record))
    assert payload["message"] == "[email:stable-hash]"
    assert payload["actor"] == "[email:stable-hash]"
    assert payload["function"] == "[email:stable-hash]"


@pytest.mark.parametrize(
    "failure",
    [
        smtplib.SMTPRecipientsRefused({"actor@example.org": (550, b"rejected")}),
        smtplib.SMTPResponseException(451, b"actor@example.org"),
        smtplib.SMTPException("actor@example.org"),
        OSError("actor@example.org"),
        RuntimeError("actor@example.org"),
    ],
)
def test_smtp_failure_records_do_not_capture_free_form_error_fragments(
    monkeypatch, caplog, failure
):
    """SMTP failure records do not capture free form error fragments."""
    monkeypatch.setattr(settings, "smtp_enabled", True)
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    monkeypatch.setattr(settings, "smtp_user", "")
    smtp_class = create_autospec(smtplib.SMTP, spec_set=True)
    server = smtp_class.return_value
    server.send_message.side_effect = failure
    monkeypatch.setattr(email_service.smtplib, "SMTP", smtp_class)
    with caplog.at_level(logging.ERROR, logger=email_service.__name__):
        result = email_service.send_email("actor@example.org", "subject", "body")
    assert result.status != "sent"
    record = next(record for record in caplog.records if record.name == email_service.__name__)
    assert not hasattr(record, "error")
    assert record.exception_type == type(failure).__name__
    payload = log_config.JSONFormatter().format(record)
    assert "actor@example.org" not in payload
    assert "actor@example." not in payload


@pytest.mark.parametrize("value", [None, True, "actor@example.org", -1, 99, 600])
def test_smtp_diagnostic_code_rejects_non_codes(value):
    """SMTP diagnostic code rejects non codes."""
    assert email_service._diagnostic_smtp_code(value) is None


def test_late_added_and_mutated_extras_are_sanitized_again():
    """Late added and mutated extras are sanitized again."""
    record = logging.makeLogRecord({"msg": "event", "nested": {"item": "initial"}})
    log_config._redactor.filter(record)
    record.nested["item"] = "sensitive@example.org"
    record.late = "sensitive@example.org"
    payload = json.loads(log_config.JSONFormatter().format(record))
    assert payload["nested"]["item"] == "[REDACTED:email]"
    assert payload["late"] == "[REDACTED:email]"


def test_filter_optimization_preserves_exact_public_record_fields():
    """Filter optimization preserves exact public record fields."""
    record = logging.makeLogRecord({"msg": "actor@example.org", "event_type": "event"})
    fields_before = set(vars(record))
    log_config._audit_email_autohash.filter(record)
    log_config._audit_redactor.filter(record)
    assert set(vars(record)) == fields_before
    assert vars(record)["event_type"] == "event"


def test_filter_snapshot_does_not_keep_completed_log_records_alive():
    """Filter snapshot does not keep completed log records alive."""
    redactor = log_config.SensitiveDataFilter()
    record = logging.makeLogRecord({"msg": "event", "event_type": "event"})
    reference = weakref.ref(record)
    redactor.filter(record)
    assert redactor.already_sanitized(record, "msg", "event")
    del record
    gc.collect()
    assert reference() is None
    assert not redactor._sanitized_records
