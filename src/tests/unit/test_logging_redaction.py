"""Unit tests for the audit/logging fail-open cluster (backlog §8.2–§8.4).

Pins, against src/config/logging.py:
- §8.2: the audit logger keeps its own INFO level, so raising the app
  LOG_LEVEL to WARNING cannot silently discard audit events (the old NOTSET
  bug made getEffectiveLevel() walk up to root and drop INFO audit records).
- §8.3: the split redactor — `_redactor` (app channel, redacts secrets AND
  email PII) vs `_audit_redactor` (audit channel, keeps email, still redacts
  secrets/auth headers). The old shared redactor amputated the audit trail by
  turning `email_changed` subjects into `[REDACTED:email]`.
- §8.4: `SensitiveDataFilter._redact_any` recurses into dict/list extras and
  stringify-then-redacts arbitrary objects, closing the old
  `json.dumps(default=str)` bypass — and it recurses via `self.apply`, so the
  per-channel PII policy holds for non-string extras too.
- JSONFormatter emits one JSON object per record, carrying extras, with
  `default=str` absorbing non-serializable values.
- The short-secret guard warns (RuntimeWarning) and skips values < 8 chars
  instead of installing a useless/over-matching redaction pattern.

No database is touched anywhere in this file.
"""
import json
import logging

import pytest
from pydantic import SecretStr

import config.logging as config_logging
from config import settings
from config.logging import JSONFormatter, SensitiveDataFilter, setup_logging


class _ListHandler(logging.Handler):
    """Minimal capture handler: appends every record that reaches it."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _LeakyObject:
    """An object whose __str__ embeds a secret — the default=str bypass shape."""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def __str__(self) -> str:
        return f"token={self._secret}"


class _Unserializable:
    """Not JSON-serializable; json.dumps must fall back to default=str."""

    def __str__(self) -> str:
        return "opaque-object"


def _make_record(msg: str, name: str = "app.test", **extras) -> logging.LogRecord:
    """Hand-build a LogRecord (as the logging machinery would) plus extras."""
    record = logging.LogRecord(
        name=name,
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )
    for key, value in extras.items():
        setattr(record, key, value)
    return record


# Channel parametrization: the two module-level filters ARE the channels
# (setup_logging attaches _redactor to the root handler and _audit_redactor
# to the audit handler).
_BOTH_CHANNELS = pytest.mark.parametrize(
    "channel_filter",
    [config_logging._redactor, config_logging._audit_redactor],
    ids=["app", "audit"],
)


# ---------------------------------------------------------------------------
# §8.2 — audit trail survives LOG_LEVEL above INFO
# ---------------------------------------------------------------------------

def test_audit_info_survives_warning_log_level(restore_logging):
    """§8.2: with the app configured at WARNING, an INFO audit event must
    still reach the audit logger's handlers.

    Regression guarded: the audit logger's level was NOTSET, so its effective
    level inherited root's WARNING and the record died BEFORE handler dispatch
    — a silent compliance hole triggered by an ordinary quiet-the-app move.
    """
    setup_logging(log_level="WARNING", log_format="json")

    audit_logger = logging.getLogger("audit")
    capture = _ListHandler()
    audit_logger.addHandler(capture)
    try:
        audit_logger.info("login_success", extra={"event_type": "login_success"})
    finally:
        audit_logger.removeHandler(capture)

    # The record reached the handler — with the old NOTSET bug this list is
    # empty because isEnabledFor(INFO) resolved to False.
    assert len(capture.records) == 1
    assert capture.records[0].event_type == "login_success"

    # Both halves of the split: audit stays at INFO, the app side really is
    # at WARNING (proving the test exercised the dangerous configuration).
    assert audit_logger.isEnabledFor(logging.INFO)
    assert logging.getLogger().level == logging.WARNING


def test_audit_logger_has_dedicated_handler_and_no_propagation(restore_logging):
    """§8.2 companion: setup_logging gives 'audit' its own handler (no
    LOG_LEVEL-derived handler level) and propagate=False, so audit records
    neither re-couple to root's level nor double-emit through root handlers."""
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


# ---------------------------------------------------------------------------
# §8.3 — split redactor: app redacts PII, audit keeps it, secrets always die
# ---------------------------------------------------------------------------

def test_app_channel_redacts_email_from_message():
    """§8.3(a): the app-channel filter replaces email addresses in the
    message with [REDACTED:email] — PII must not reach app logs."""
    record = _make_record("user bob@uzh.ch did X")

    assert config_logging._redactor.filter(record) is True

    assert "[REDACTED:email]" in record.msg
    assert "bob@uzh.ch" not in record.msg


def test_audit_channel_keeps_email_in_message():
    """§8.3(b): the audit-channel filter keeps the email intact — the address
    IS the audit subject (e.g. email_changed old→new values).

    Regression guarded: the old single shared redactor recorded
    '[REDACTED:email] → [REDACTED:email]' in audit events, useless for
    compliance/forensics."""
    record = _make_record("user bob@uzh.ch did X", name="audit")

    assert config_logging._audit_redactor.filter(record) is True

    assert "bob@uzh.ch" in record.msg
    assert "[REDACTED:email]" not in record.msg


@_BOTH_CHANNELS
def test_secret_key_redacted_on_both_channels(channel_filter):
    """§8.3(c): the secrets-always invariant — a settings SecretStr value in
    a message is redacted on BOTH channels; the PII split never loosens
    secret redaction."""
    secret = settings.secret_key.get_secret_value()
    record = _make_record(f"boot used key {secret} just now")

    channel_filter.filter(record)

    assert secret not in record.msg
    assert "[REDACTED:secret_key]" in record.msg


@_BOTH_CHANNELS
def test_bearer_token_redacted_on_both_channels(channel_filter):
    """§8.3(d): auth headers are a static always-redacted pattern —
    'Bearer <token>' becomes 'Bearer ***' on both channels."""
    record = _make_record("rejected auth header Bearer abc123token from client")

    channel_filter.filter(record)

    assert "abc123token" not in record.msg
    assert "Bearer ***" in record.msg


# ---------------------------------------------------------------------------
# §8.4 — non-string extras are redacted (no type-shaped bypass)
# ---------------------------------------------------------------------------

@_BOTH_CHANNELS
def test_nested_dict_extra_redacts_session_secret(channel_filter):
    """§8.4: a secret buried in a nested dict extra is redacted (recursion
    reaches nested values) — on both channels, per the secrets-always
    invariant.

    Regression guarded: filter() used to touch only isinstance(str) extras,
    so dict extras sailed through to json.dumps un-redacted."""
    secret = settings.session_secret.get_secret_value()
    record = _make_record("session event", details={"nested": {"value": secret}})

    channel_filter.filter(record)

    assert record.details == {"nested": {"value": "[REDACTED:session_secret]"}}


def test_list_extra_with_leaky_object_str_is_redacted():
    """§8.4: an object inside a list extra whose __str__ embeds a secret is
    stringified THEN redacted, closing the json.dumps(default=str) bypass
    (default=str used to run AFTER the filter, leaking the secret)."""
    secret = settings.session_secret.get_secret_value()
    record = _make_record("payload event", payload=[_LeakyObject(secret)])

    config_logging._redactor.filter(record)

    assert record.payload == ["token=[REDACTED:session_secret]"]
    assert secret not in record.payload[0]


def test_scalar_extras_pass_through_unchanged():
    """§8.4: scalar extras keep value AND type — redaction must not stringify
    numbers/bools/None (that would corrupt structured log fields)."""
    record = _make_record("scalars", count=42, flag=True, nothing=None)

    config_logging._redactor.filter(record)

    assert record.count == 42 and type(record.count) is int
    assert record.flag is True
    assert record.nothing is None


def test_channel_consistency_for_nested_email_extra():
    """§8.4 sharp pin (ties to §8.3): the SAME nested {'email': ...} extra
    keeps the address through the AUDIT filter but is redacted through the
    APP filter — proving _redact_any recurses via self.apply (per-channel),
    not via a module-global redactor.

    Regression guarded: the 'put _redact_any in the formatter with the global
    _redact' variant would have redacted email out of non-string audit extras
    while §8.3 keeps it in string ones."""
    audit_record = _make_record("email_changed", name="audit",
                                details={"email": "bob@uzh.ch"})
    app_record = _make_record("email_changed", details={"email": "bob@uzh.ch"})

    config_logging._audit_redactor.filter(audit_record)
    config_logging._redactor.filter(app_record)

    assert audit_record.details == {"email": "bob@uzh.ch"}
    assert app_record.details == {"email": "[REDACTED:email]"}


# ---------------------------------------------------------------------------
# JSONFormatter — one JSON object per record, extras carried, default=str
# ---------------------------------------------------------------------------

def test_json_formatter_emits_single_object_with_extras():
    """JSONFormatter: a filtered record formats to ONE parseable JSON object
    (single line) with timestamp/level/message plus the extra keys, and the
    filter's redaction is visible in the serialized output."""
    record = _make_record(
        "user bob@uzh.ch did X",
        request_id="req-1",
        details={"email": "bob@uzh.ch"},
    )
    config_logging._redactor.filter(record)

    output = JSONFormatter().format(record)

    assert "\n" not in output  # one object per line — aggregator contract
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert "timestamp" in parsed
    assert parsed["message"] == "user [REDACTED:email] did X"
    assert parsed["request_id"] == "req-1"
    assert parsed["details"] == {"email": "[REDACTED:email]"}
    # Formatter-independence bottom line: the PII never reaches the wire.
    assert "bob@uzh.ch" not in output


def test_json_formatter_handles_non_serializable_extra():
    """JSONFormatter: a non-JSON-serializable extra object must not raise —
    json.dumps(default=str) stringifies it (the extra is set AFTER filtering
    to exercise the formatter's own fallback, not the filter's)."""
    record = _make_record("weird payload")
    config_logging._redactor.filter(record)
    record.weird = _Unserializable()  # bypass the filter on purpose

    output = JSONFormatter().format(record)  # must not raise

    parsed = json.loads(output)
    assert parsed["weird"] == "opaque-object"


# ---------------------------------------------------------------------------
# Short-secret guard — warn and skip, never install an unreliable pattern
# ---------------------------------------------------------------------------

def test_short_secret_warns_and_is_excluded_from_patterns(monkeypatch):
    """A sensitive value shorter than 8 chars cannot be reliably redacted
    (it would over-match ordinary text): building patterns must emit a
    RuntimeWarning naming the field and SKIP it — no pattern, no replacement.

    A FRESH SensitiveDataFilter is required: the module-level filters cache
    their patterns on first use, so mutating settings has no effect on them.
    """
    monkeypatch.setattr(settings, "session_secret", SecretStr("short"))

    fresh = SensitiveDataFilter(include_pii=True)
    with pytest.warns(RuntimeWarning, match="session_secret"):
        patterns = fresh.patterns

    # No pattern was installed for the short value...
    assert all(repl != "[REDACTED:session_secret]" for _, repl in patterns)
    # ...so the literal value passes through untouched (nothing else in the
    # pattern set may accidentally match it either).
    assert fresh.apply("short") == "short"
