"""Unit tests for redaction in src/config/logging.py: what the JSON and text
formatters redact, how records and custom objects are scrubbed, and how the
audit channel treats email addresses differently from the app channel.

Pins, against src/config/logging.py:
- the audit logger keeps its own INFO level, so raising the app LOG_LEVEL to
  WARNING cannot silently discard audit events (handler/level wiring itself
  lives in test_logging_setup.py; this file pins the redaction it carries);
- the split redactor — `_redactor` (app channel, redacts secrets AND email
  PII) vs `_audit_redactor` (audit channel, keeps email, still redacts
  secrets/auth headers). A single shared redactor would amputate the audit
  trail by turning `email_changed` subjects into `[REDACTED:email]`;
- `SensitiveDataFilter._redact_any` recurses into dict/list extras and
  stringify-then-redacts arbitrary objects, so a `json.dumps(default=str)`
  fallback cannot bypass it — and it recurses via `self.apply`, so the
  per-channel PII policy holds for non-string extras too;
- JSONFormatter emits one JSON object per record, carrying extras, with
  `default=str` absorbing non-serializable values;
- the short-secret guard warns (RuntimeWarning) and skips values < 8 chars
  instead of installing a useless/over-matching redaction pattern.

No database is touched anywhere in this file.
"""

import json
import logging
import smtplib
import sys
import types
from typing import Never, get_origin
from unittest.mock import create_autospec

import pytest
from pydantic import SecretStr

import config.logging as config_logging
import config.logging as logging_module
from app.services.crypto import audit_email_hash
from config import settings
from config.logging import (
    AuditEmailAutoHash,
    JSONFormatter,
    RedactingFormatter,
    SensitiveDataFilter,
    _annotation_contains_secretstr,
    _iter_secret_values,
)
from config.settings import Settings


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


def _smtp_refusal_record(recipient: str) -> logging.LogRecord:
    """Build a real SMTP exception record whose value contains recipient PII."""
    try:
        _raise_smtp_recipients_refused(recipient)
    except smtplib.SMTPRecipientsRefused:
        exc_info = sys.exc_info()

    return logging.LogRecord(
        name="app.services.email",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="smtp_recipient_refused",
        args=(),
        exc_info=exc_info,
    )


def _raise_runtime_error(message: str) -> None:
    raise RuntimeError(message)


def _raise_smtp_recipients_refused(recipient: str) -> Never:
    raise smtplib.SMTPRecipientsRefused({recipient: (550, b"Mailbox unavailable")})


def _exception_record(message: str) -> logging.LogRecord:
    """Build a record carrying a real traceback whose value is attacker-controlled."""
    try:
        _raise_runtime_error(message)
    except RuntimeError:
        exc_info = sys.exc_info()

    return logging.LogRecord(
        name="app.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="request failed",
        args=(),
        exc_info=exc_info,
    )


def _is_secret_bearing(field_info) -> bool:
    """The SAME gate _build_sensitive_patterns applies — kept in lockstep so
    the totality test below enumerates exactly what production redacts."""
    return _annotation_contains_secretstr(field_info.annotation) or (
        isinstance(field_info.json_schema_extra, dict)
        and field_info.json_schema_extra.get("sensitive", False)
    )


SECRET_FIELDS = [name for name, f in Settings.model_fields.items() if _is_secret_bearing(f)]


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


def _probe(field: str, suffix: str = "V") -> str:
    """A unique, >=8-char probe per field, inert w.r.t. the static
    Bearer/email patterns so only the field's own pattern can remove it."""
    return f"PROBE-{field}-{suffix}-0123456789abcdef"


# Channel parametrization: the two module-level filters ARE the channels
# (setup_logging attaches _redactor to the root handler and _audit_redactor
# to the audit handler).
_BOTH_CHANNELS = pytest.mark.parametrize(
    "channel_filter",
    [config_logging._redactor, config_logging._audit_redactor],
    ids=["app", "audit"],
)

_ACTION_ROUTE_PREFIXES = (
    "/reset-password",
    "/verify-email",
    "/account/confirm-email",
)


def _audit_record(msg, **extra):
    return logging.getLogger("audit").makeRecord(
        "audit", logging.INFO, __file__, 1, msg, (), None, extra=extra
    )


class TestSettingsInstanceBinding:
    """Settings-derived redaction patterns can only be built if
    `config.logging.settings` is the Settings INSTANCE, not the
    `config.settings` submodule; bound to the module, redaction is inert."""

    def test_config_logging_binds_settings_instance_not_module(self):
        """The name `settings` inside config/logging.py must be the Settings
        INSTANCE. config/__init__.py imports `.logging` before `.settings`,
        so a `from config import settings` in logging.py would execute while
        the package attribute does not exist yet and Python's from-import
        fallback would bind the config.settings SUBMODULE instead.
        Consequence: _build_sensitive_patterns would read
        getattr(<module>, field_name, None) → None for every Settings field
        and install ZERO settings-derived redaction patterns — SECRET_KEY,
        SESSION_SECRET, DATABASE_URL, TOTP_ENCRYPTION_KEYS etc. would all
        reach log output verbatim. logging.py therefore imports
        `from config.settings import settings` directly; this test fails if
        either the import or the package order changes so that the module is
        bound."""
        assert not isinstance(config_logging.settings, types.ModuleType), (
            "config.logging.settings is bound to the config.settings MODULE — "
            "the from-import ran before config/__init__.py bound the instance"
        )
        assert isinstance(config_logging.settings, Settings)

        # Consequence pin: a fresh filter must build more than the 2 static
        # patterns (Bearer + email) when the binding is right — the test env sets
        # 5 required secrets, so settings-derived patterns cannot be empty.
        fresh = SensitiveDataFilter(include_pii=True)
        assert len(fresh.patterns) > 2, (
            f"only {len(fresh.patterns)} patterns built — settings-derived redaction is inert"
        )


class TestSecretFieldRedaction:
    """Every secret-bearing Settings field is redacted from log text, and
    ordinary values are left alone."""

    @pytest.fixture
    def rotation_state_settings(self, monkeypatch):
        """Every secret-bearing Settings field set to a unique probe value.

        - list-shaped fields get TWO entries — the MultiFernet rotation state
          [new, old] — so per-element pattern building is what's under test.
        - Optional secrets that default to None in the test env are set, so the
          parametrized test has a value to assert on for every field.
        Introspection-driven: a new secret field is enrolled automatically; an
        annotation shape this fixture can't synthesize fails loudly.
        """
        for field in SECRET_FIELDS:
            annotation = Settings.model_fields[field].annotation
            origin = get_origin(annotation)
            if origin is dict:
                pytest.fail(f"{field}: dict-shaped secret fields need a probe rule here")
            if origin in (list, tuple, set, frozenset):
                monkeypatch.setattr(
                    settings,
                    field,
                    [
                        SecretStr(_probe(field, "NEW")),
                        SecretStr(_probe(field, "OLD")),
                    ],
                )
            elif _annotation_contains_secretstr(annotation):
                monkeypatch.setattr(settings, field, SecretStr(_probe(field)))
            else:  # json_schema_extra={"sensitive": True} on a plain field
                monkeypatch.setattr(settings, field, _probe(field))

    @pytest.mark.usefixtures("rotation_state_settings")
    @pytest.mark.parametrize("field", SECRET_FIELDS)
    def test_every_secret_bearing_field_is_redacted(self, field):
        """An exact-type check silently dropped
        Optional[SecretStr] and list[SecretStr] fields while the mechanism looked
        complete. Fresh filter per test — the singletons cache patterns."""
        values = list(_iter_secret_values(getattr(settings, field)))
        assert values, f"rotation_state_settings left {field} unset"

        fresh = SensitiveDataFilter(include_pii=False)
        for value in values:
            redacted = fresh.apply(f"boot log: {value} tail")
            assert value not in redacted, f"{field!r} survived: {redacted!r}"
            assert f"[REDACTED:{field}]" in redacted

    @pytest.mark.usefixtures("rotation_state_settings")
    def test_non_secret_values_survive_redaction(self, monkeypatch):
        """Negative control: the totality test cannot pass vacuously because
        apply() nukes everything."""
        monkeypatch.setattr(settings, "smtp_host", "PROBE-plain-nonsecret-host")
        fresh = SensitiveDataFilter(include_pii=False)
        assert "PROBE-plain-nonsecret-host" in fresh.apply(
            "connecting to PROBE-plain-nonsecret-host now"
        )


class TestChannelSplitBetweenAppAndAudit:
    """The app channel redacts email PII; the audit channel keeps it (the
    address is the audit subject). Secrets and auth headers are always
    redacted on both channels regardless of the PII split."""

    def test_app_channel_redacts_email_from_message(self):
        """The app-channel filter replaces email addresses in the message
        with [REDACTED:email] — PII must not reach app logs."""
        record = _make_record("user bob@uzh.ch did X")

        assert config_logging._redactor.filter(record) is True

        assert "[REDACTED:email]" in record.msg
        assert "bob@uzh.ch" not in record.msg

    def test_audit_channel_keeps_email_in_message(self):
        """The audit-channel filter keeps the email intact — the address IS
        the audit subject (e.g. email_changed old→new values).

        A single shared redactor would record
        '[REDACTED:email] → [REDACTED:email]' in audit events, useless for
        compliance/forensics."""
        record = _make_record("user bob@uzh.ch did X", name="audit")

        assert config_logging._audit_redactor.filter(record) is True

        assert "bob@uzh.ch" in record.msg
        assert "[REDACTED:email]" not in record.msg

    @_BOTH_CHANNELS
    def test_secret_key_redacted_on_both_channels(self, channel_filter):
        """The secrets-always invariant — a settings SecretStr value in a
        message is redacted on BOTH channels; the PII split never loosens
        secret redaction."""
        secret = settings.secret_key.get_secret_value()
        record = _make_record(f"boot used key {secret} just now")

        channel_filter.filter(record)

        assert secret not in record.msg
        assert "[REDACTED:secret_key]" in record.msg

    @_BOTH_CHANNELS
    def test_bearer_token_redacted_on_both_channels(self, channel_filter):
        """Auth headers are a static always-redacted pattern — 'Bearer
        <token>' becomes 'Bearer ***' on both channels."""
        record = _make_record("rejected auth header Bearer abc123token from client")

        channel_filter.filter(record)

        assert "abc123token" not in record.msg
        assert "Bearer ***" in record.msg


class TestStructuredExtraRedaction:
    """Non-string extras (dicts, lists, custom objects, scalars) are
    redacted with the same recursion and per-channel policy as messages —
    no type-shaped bypass."""

    @_BOTH_CHANNELS
    def test_nested_dict_extra_redacts_session_secret(self, channel_filter):
        """A secret buried in a nested dict extra is redacted (recursion
        reaches nested values) — on both channels, per the secrets-always
        invariant.

        A filter() that touched only isinstance(str) extras would let dict
        extras sail through to json.dumps un-redacted."""
        secret = settings.session_secret.get_secret_value()
        record = _make_record("session event", details={"nested": {"value": secret}})

        channel_filter.filter(record)

        assert record.details == {"nested": {"value": "[REDACTED:session_secret]"}}

    def test_list_extra_with_leaky_object_str_is_redacted(self):
        """An object inside a list extra whose __str__ embeds a secret is
        stringified THEN redacted, closing the json.dumps(default=str) bypass
        (default=str runs AFTER the filter, so an unstringified object would
        leak the secret)."""
        secret = settings.session_secret.get_secret_value()
        record = _make_record("payload event", payload=[_LeakyObject(secret)])

        config_logging._redactor.filter(record)

        assert record.payload == ["token=[REDACTED:session_secret]"]
        assert secret not in record.payload[0]

    def test_scalar_extras_pass_through_unchanged(self):
        """Scalar extras keep value AND type — redaction must not stringify
        numbers/bools/None (that would corrupt structured log fields)."""
        record = _make_record("scalars", count=42, flag=True, nothing=None)

        config_logging._redactor.filter(record)

        assert record.count == 42 and type(record.count) is int
        assert record.flag is True
        assert record.nothing is None

    def test_channel_consistency_for_nested_email_extra(self):
        """A sharp pin tying the extra-recursion behaviour to the channel
        split: the SAME nested {'email': ...} extra keeps the address
        through the AUDIT filter but is redacted through the APP filter,
        proving `_redact_any` recurses via self.apply (per-channel), not via
        a module-global redactor.

        A variant that put _redact_any in the formatter with the global
        _redact would redact email out of non-string audit extras while
        the app channel still keeps it in string ones."""
        audit_record = _make_record("email_changed", name="audit", details={"email": "bob@uzh.ch"})
        app_record = _make_record("email_changed", details={"email": "bob@uzh.ch"})

        config_logging._audit_redactor.filter(audit_record)
        config_logging._redactor.filter(app_record)

        assert audit_record.details == {"email": "bob@uzh.ch"}
        assert app_record.details == {"email": "[REDACTED:email]"}


_SECRET_VALUE_CLASSES = [
    pytest.param(
        "a per-user base32 TOTP seed",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        id="totp-base32-seed",
    ),
    pytest.param(
        "a QR data: URI payload embedding the seed",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA",
        id="qr-data-image-payload",
    ),
    pytest.param(
        "a Fernet-style ciphertext",
        "gAAAAABkY3XyZ1w2b3J9F00PROBE-CIPHERTEXT-CANARY==",
        id="fernet-ciphertext",
    ),
    pytest.param(
        "a display-format TOTP recovery code",
        "7F3D9-C2A1E-5B8F0-4ABCD",
        id="totp-recovery-code",
    ),
]


class TestRuntimeSecretValueClassesNeverReachStoredLogs:
    """A value that is secret BY KIND — never equal to a configured Settings
    value, so no settings-derived pattern can match it — must still never
    reach a stored log line, in the message or in a nested extra, on either
    channel. Each class listed here has a distinctive shape matched by
    `_RUNTIME_SECRET_SHAPE_PATTERNS`. Secrets without such a shape (submitted
    passwords, 6-digit TOTP codes, raw session ids) cannot be redacted by
    value without destroying ordinary log content; they must never be passed
    to a logger in the first place."""

    @_BOTH_CHANNELS
    @pytest.mark.parametrize(("kind", "secret_value"), _SECRET_VALUE_CLASSES)
    def test_value_is_redacted_from_message_and_nested_extras(
        self, channel_filter, kind, secret_value
    ):
        record = _make_record(
            f"handling event carrying {kind}: {secret_value}",
            payload={"nested": {"value": secret_value}},
        )

        channel_filter.filter(record)

        assert secret_value not in record.getMessage()
        assert secret_value not in json.dumps(record.payload, default=str)

    @_BOTH_CHANNELS
    def test_an_ordinary_identifier_survives_redaction(self, channel_filter):
        """Positive control: the missing patterns above are not a filter
        that redacts everything — an ordinary, non-secret identifier must
        still reach the log unchanged."""
        identifier = "dataset-catalogue-entry-00482"
        record = _make_record(
            f"handling event carrying identifier: {identifier}",
            payload={"nested": {"value": identifier}},
        )

        channel_filter.filter(record)

        assert identifier in record.getMessage()
        assert record.payload == {"nested": {"value": identifier}}


class TestJSONFormatterOutput:
    """JSONFormatter emits one JSON object per record, carries extras, and
    sanitizes the whole entry (even a custom __str__) whether or not the
    record passed through a SensitiveDataFilter first."""

    def test_json_formatter_emits_single_object_with_extras(self):
        """A filtered record formats to ONE parseable JSON object (single
        line) with timestamp/level/message plus the extra keys, and the
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

    def test_json_formatter_handles_non_serializable_extra(self):
        """A non-JSON-serializable extra object must not raise —
        json.dumps(default=str) stringifies it (the extra is set AFTER filtering
        to exercise the formatter's own fallback, not the filter's)."""
        record = _make_record("weird payload")
        config_logging._redactor.filter(record)
        record.weird = _Unserializable()  # bypass the filter on purpose

        output = JSONFormatter().format(record)  # must not raise

        parsed = json.loads(output)
        assert parsed["weird"] == "opaque-object"

    @pytest.mark.parametrize(
        "secret",
        ["/reset-password/private-token", "Bearer private-token"],
        ids=["path-shaped-secret", "bearer-header-shaped-secret"],
    )
    def test_json_formatter_redacts_top_level_and_nested_secrets_without_a_filter(self, secret):
        """`_format_json` calls `_redactor.sanitize(log_entry)` on every field
        unconditionally — a record that reached the formatter WITHOUT going
        through a `SensitiveDataFilter.filter()` call first still has the secret
        stripped everywhere it appears, and every non-secret field survives
        untouched (the sanitize step does not corrupt structure)."""
        record = logging.makeLogRecord({"msg": secret, "nested": {"url": secret}, "tail": "intact"})

        output = JSONFormatter().format(record)

        decoded = json.loads(output)
        assert decoded["tail"] == "intact"
        assert isinstance(decoded["nested"], dict)
        assert "private-token" not in output

    def test_json_formatter_redacts_a_custom_object_before_serialization(self):
        """An extra object whose `__str__` embeds a secret is stringified THEN
        redacted by the formatter's own sanitize step — the same
        default=str-then-redact guarantee as the filtered path, so an
        unfiltered record can't leak via a custom `__str__`."""

        class SensitiveObject:
            def __str__(self):
                return "Bearer custom-secret"

        output = JSONFormatter().format(
            logging.makeLogRecord({"msg": "ok", "obj": SensitiveObject()})
        )

        assert "custom-secret" not in output
        assert "obj" in json.loads(output)


class TestActionTokenPathRedaction:
    """Action-route path tokens (reset-password, verify-email,
    confirm-email) are secret on both logging channels and both formats,
    with or without a filter — the route list is deliberately explicit: adding
    or renaming an action route requires updating the logging defense and
    this test."""

    @_BOTH_CHANNELS
    @pytest.mark.parametrize("route_prefix", _ACTION_ROUTE_PREFIXES)
    def test_action_token_path_is_redacted_from_message_and_nested_extras(
        self,
        channel_filter,
        route_prefix,
    ):
        """Every URL-path action credential is secret on both logging channels."""
        token = f"ACTION-TOKEN-CANARY-{route_prefix.rsplit('/', 1)[-1]}-0123456789"
        path = f"{route_prefix}/{token}"
        record = _make_record(
            f"rejected request to {path}",
            path=path,
            details={"absolute_url": f"https://archive.example.test{path}"},
        )

        channel_filter.filter(record)

        serialized = json.dumps(
            {
                "message": record.getMessage(),
                "path": record.path,
                "details": record.details,
            }
        )
        assert token not in serialized
        assert f"{route_prefix}/<token>" in serialized

    @pytest.mark.parametrize("route_prefix", _ACTION_ROUTE_PREFIXES)
    def test_json_formatter_scrubs_action_path_without_filter(self, route_prefix):
        """JSON formatting is a second boundary if a handler omits its filter."""
        token = "ACTION-TOKEN-JSON-FORMATTER-CANARY-0123456789"
        path = f"{route_prefix}/{token}"
        record = _make_record(
            f"failed URL https://archive.example.test{path}",
            path=path,
        )

        output = JSONFormatter().format(record)

        assert token not in output
        assert f"{route_prefix}/<token>" in output

    @pytest.mark.parametrize("route_prefix", _ACTION_ROUTE_PREFIXES)
    def test_text_formatter_scrubs_action_path_without_filter(self, route_prefix):
        """Development text logs enforce the same credential boundary as JSON."""
        token = "ACTION-TOKEN-TEXT-FORMATTER-CANARY-0123456789"
        path = f"{route_prefix}/{token}"
        record = _make_record(
            f"failed URL https://archive.example.test{path}",
            path=path,
        )
        formatter = RedactingFormatter("%(message)s path=%(path)s")

        output = formatter.format(record)

        assert token not in output
        assert f"{route_prefix}/<token>" in output


class TestExceptionValueRedaction:
    """Traceback diagnostics may retain frames and type, never the raw
    exception value/message, on both formats and even when a formatter
    fault or a cached exc_text tries to smuggle it through."""

    def test_json_exception_output_omits_raw_exception_value(self):
        """Traceback diagnostics may retain frames and type, never ``str(exc)``."""
        canary = "RAW-JSON-EXCEPTION-VALUE-CANARY-0123456789"
        record = _exception_record(canary)

        output = JSONFormatter().format(record)

        parsed = json.loads(output)
        assert canary not in output
        assert parsed["exception"]["type"] == "builtins.RuntimeError"

    def test_text_exception_output_omits_raw_exception_value(self):
        """Text formatting must not bypass the JSON exception-value policy."""
        canary = "RAW-TEXT-EXCEPTION-VALUE-CANARY-0123456789"
        record = _exception_record(canary)

        output = RedactingFormatter("%(levelname)s %(message)s").format(record)

        assert canary not in output
        assert "RuntimeError" in output

    def test_json_exception_formatting_failure_is_constant_and_fail_closed(self, monkeypatch):
        """A formatter fault cannot reproduce the raw exception tuple or fault text."""
        exception_canary = "RAW-EXCEPTION-VALUE-CANARY-0123456789"
        formatter_canary = "FORMATTER-FAILURE-CANARY-0123456789"
        record = _exception_record(exception_canary)
        formatter = JSONFormatter()

        def fail_formatting(_exc_info):
            raise TypeError(formatter_canary)

        spy = create_autospec(formatter._exception_diagnostic, spec_set=True)
        spy.side_effect = fail_formatting
        monkeypatch.setattr(formatter, "_exception_diagnostic", spy)

        output = formatter.format(record)

        parsed = json.loads(output)
        assert parsed["exception"] == {"type": "<exception formatting failed>"}
        assert exception_canary not in output
        assert formatter_canary not in output

    @pytest.mark.parametrize(
        "formatter",
        (
            JSONFormatter(),
            RedactingFormatter("%(levelname)s %(name)s %(message)s"),
        ),
        ids=("json", "text"),
    )
    def test_exception_value_never_discloses_smtp_recipient(self, formatter):
        """Both supported formats omit the value of a real SMTP refusal."""
        recipient = '"victim+case"@research.example'
        output = formatter.format(_smtp_refusal_record(recipient))

        assert recipient not in output
        assert "victim+case" not in output
        assert "SMTPRecipientsRefused" in output

    def test_text_formatter_discards_exception_text_cached_by_an_earlier_formatter(self):
        """A pre-populated LogRecord.exc_text cannot bypass safe text formatting."""
        canary = "CACHED-EXCEPTION-VALUE-CANARY-0123456789"
        record = _exception_record("safe value which must also be omitted")
        record.exc_text = f"RuntimeError: {canary}"

        output = RedactingFormatter("%(levelname)s %(message)s").format(record)

        assert canary not in output
        assert "<cached exception text omitted>" not in output
        assert "RuntimeError" in output

    def test_text_formatter_discards_orphaned_cached_exception_text(self):
        """An exc_text-only record cannot reproduce an earlier unsafe rendering."""
        canary = "ORPHANED-EXCEPTION-VALUE-CANARY-0123456789"
        record = _make_record("delivery failed")
        record.exc_text = f"SMTPRecipientsRefused: {canary}"

        output = RedactingFormatter("%(levelname)s %(message)s").format(record)

        assert canary not in output
        assert "<cached exception text omitted>" in output


class TestShortSecretGuard:
    """A sensitive value shorter than the minimum redaction length cannot be
    reliably matched, so building patterns must warn and skip it rather than
    install an over-matching pattern."""

    def test_short_secret_warns_and_is_excluded_from_patterns(self, monkeypatch):
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

    def test_short_secret_warning_states_actual_min_length(self, monkeypatch):
        """The operator-facing warning must state the actual numeric
        threshold, not an un-interpolated placeholder."""
        monkeypatch.setattr(settings, "session_secret", SecretStr("short"))

        fresh = SensitiveDataFilter(include_pii=True)
        with pytest.warns(RuntimeWarning, match="session_secret") as caught:
            # Touching the lazy property is what compiles the pattern set and
            # emits the warning; the value itself is irrelevant here.
            _ = fresh.patterns

        messages = [str(w.message) for w in caught if "session_secret" in str(w.message)]
        assert messages  # positive control: the guard fired for the short value
        for msg in messages:
            # Correct behaviour: the actual threshold number appears...
            assert str(config_logging._MIN_REDACTION_VALUE_LENGTH) in msg
            # ...and the raw un-interpolated placeholder does not.
            assert "{_MIN_REDACTION_VALUE_LENGTH}" not in msg


class TestAuditEmailAutoHash:
    """The audit channel replaces raw email addresses with a hash-preserving
    marker, leaves email-named categorical fields alone, and fails closed to
    a non-correlatable marker before a hasher is registered."""

    def test_audit_email_autohash_rewrites_raw_addresses_to_keyed_hash(self):
        """A raw address in the message OR an extra becomes [email:<hash>] with the
        keyed audit hash — same address, same marker, so correlation survives a
        forgotten audit_email_hash() at the call site."""
        expected = f"[email:{audit_email_hash('alice@example.org')}]"
        r1 = _audit_record("reset for alice@example.org", email="alice@example.org")
        r2 = _audit_record("second event", email="alice@example.org")
        f = AuditEmailAutoHash()
        f.filter(r1)
        f.filter(r2)
        assert r1.getMessage() == f"reset for {expected}"
        assert r1.email == expected
        assert r2.email == expected  # deterministic → correlatable across events

    def test_audit_email_autohash_leaves_email_named_categoricals_alone(self):
        """Shape-based, not key-based: fields that merely have 'email' in the KEY
        (email_type, email_was_registered) and existing *_hash hex values pass
        through untouched — the over-match a key-name denylist would cause."""
        r = _audit_record(
            "login_failed",
            email_type="password_reset",
            email_was_registered=True,
            recipient_hash=audit_email_hash("alice@example.org"),
        )
        AuditEmailAutoHash().filter(r)
        assert r.email_type == "password_reset"
        assert r.email_was_registered is True
        assert r.recipient_hash == audit_email_hash("alice@example.org")

    def test_audit_email_autohash_fails_closed_before_registration(self, monkeypatch):
        """Without a registered hasher (a process that configures logging but never
        imports app.services.crypto), addresses degrade to [REDACTED:email] — the
        non-correlatable marker — never to the raw address."""
        monkeypatch.setattr(logging_module, "_audit_email_hasher", None)
        r = _audit_record("x", email="alice@example.org")
        logging_module.AuditEmailAutoHash().filter(r)
        assert r.email == "[REDACTED:email]"
        assert "alice@example.org" not in r.getMessage() + str(r.email)
