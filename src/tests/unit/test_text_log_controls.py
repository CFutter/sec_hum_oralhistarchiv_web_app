"""Untrusted diagnostics cannot create extra text-log entries or terminal commands."""

import json
import logging
import unicodedata

import pytest

from app.sources.oai_client import _parse_oai_datestamp
from config.logging import JSONFormatter, RedactingFormatter


@pytest.mark.parametrize(
    "control", ["\n", "\r", "\t", "\x00", "\x1b", "\x85", "\u2028", "\u2029", "\u202e"]
)
def test_final_text_message_context_and_logger_name_escape_controls(control):
    """Check final text message context and logger name escape controls."""
    record = logging.LogRecord(
        "source" + control + "forged",
        logging.WARNING,
        __file__,
        1,
        "Rejected value %s",
        ("upstream" + control + "second entry",),
        None,
    )
    record.source_name = "archive" + control + "context"
    output = RedactingFormatter("%(name)s %(message)s source=%(source_name)s").format(record)
    assert not any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in output)
    assert "second entry" in output and "context" in output
    assert "\\" in output


def _raise_untrusted_error():
    """Raise an error containing newline and terminal-control characters for log sanitization."""
    raise ValueError("untrusted\n\x1b[2Jsecret")


def test_text_exception_and_stack_are_one_physical_record():
    """Check text exception and stack are one physical record (ValueError)."""
    with pytest.raises(ValueError) as captured:
        _raise_untrusted_error()
    info = (type(captured.value), captured.value, captured.tb)
    record = logging.LogRecord("worker", logging.ERROR, __file__, 1, "Failed", (), info)
    record.stack_info = "stack\nsecond\x1b[2J"
    output = RedactingFormatter("%(levelname)s %(message)s").format(record)
    assert "\n" not in output and "\r" not in output and "\x1b" not in output
    assert r"\n" in output and r"\x1b" in output


def test_json_message_keeps_structured_value_without_physical_controls():
    """Check JSON message keeps structured value without physical controls."""
    record = logging.LogRecord("worker", logging.WARNING, __file__, 1, "value\n\x1b[2J", (), None)
    output = JSONFormatter().format(record)
    assert "\n" not in output and "\x1b" not in output
    assert json.loads(output)["message"] == "value\n\x1b[2J"


def test_actual_upstream_datestamp_warning_escapes_text(caplog):
    """Check actual upstream datestamp warning escapes text."""
    with caplog.at_level(logging.WARNING, logger="app.sources.oai_client"):
        assert _parse_oai_datestamp("invalid\nforged\x1b[2J") is None
    records = [record for record in caplog.records if record.name == "app.sources.oai_client"]
    assert len(records) == 1
    output = RedactingFormatter("%(message)s").format(records[0])
    assert "\n" not in output and "\r" not in output and "\x1b" not in output
