"""App/audit secret filters, recursive redaction and separate audit-email hashing."""

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
        """Retain the supplied secret for text conversion."""
        self._secret = secret

    def __str__(self) -> str:
        """Expose the retained secret in a token-shaped string."""
        return f"token={self._secret}"


class _Unserializable:
    """Not JSON-serializable; json.dumps must fall back to default=str."""

    def __str__(self) -> str:
        """Return a fixed nonsensitive string for JSON fallback."""
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
    """Raise RuntimeError carrying the supplied diagnostic canary."""
    raise RuntimeError(message)


def _raise_smtp_recipients_refused(recipient: str) -> Never:
    """Raise SMTPRecipientsRefused containing the supplied recipient."""
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
    """Build an unhandled INFO audit record with the supplied extra attributes."""
    return logging.getLogger("audit").makeRecord(
        "audit", logging.INFO, __file__, 1, msg, (), None, extra=extra
    )


class TestSettingsInstanceBinding:
    """Bind redaction to the Settings instance rather than its module."""

    def test_config_logging_binds_settings_instance_not_module(self):
        """Build Settings-derived redaction patterns from the configured instance."""
        assert not isinstance(config_logging.settings, types.ModuleType), (
            "config.logging.settings is bound to the config.settings MODULE — "
            "the from-import ran before config/__init__.py bound the instance"
        )
        assert isinstance(config_logging.settings, Settings)

        fresh = SensitiveDataFilter(include_pii=True)
        assert len(fresh.patterns) > 2, (
            f"only {len(fresh.patterns)} patterns built — settings-derived redaction is inert"
        )


class TestSecretFieldRedaction:
    """Every secret-bearing Settings field is redacted from log text, and
    ordinary values are left alone."""

    @pytest.fixture
    def rotation_state_settings(self, monkeypatch):
        """Patch every sensitive field with distinct probes, including rotation lists and optional
        values.
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
            else:
                monkeypatch.setattr(settings, field, _probe(field))

    @pytest.mark.usefixtures("rotation_state_settings")
    @pytest.mark.parametrize("field", SECRET_FIELDS)
    def test_every_secret_bearing_field_is_redacted(self, field):
        """Redact every sensitive Settings field, including optional and rotation-list values."""
        values = list(_iter_secret_values(getattr(settings, field)))
        assert values, f"rotation_state_settings left {field} unset"

        fresh = SensitiveDataFilter(include_pii=False)
        for value in values:
            redacted = fresh.apply(f"boot log: {value} tail")
            assert value not in redacted, f"{field!r} survived: {redacted!r}"
            assert f"[REDACTED:{field}]" in redacted

    @pytest.mark.usefixtures("rotation_state_settings")
    def test_non_secret_values_survive_redaction(self, monkeypatch):
        """Preserve nonsensitive Settings values through secret filtering."""
        monkeypatch.setattr(settings, "smtp_host", "PROBE-plain-nonsecret-host")
        fresh = SensitiveDataFilter(include_pii=False)
        assert "PROBE-plain-nonsecret-host" in fresh.apply(
            "connecting to PROBE-plain-nonsecret-host now"
        )


class TestChannelSplitBetweenAppAndAudit:
    """App filtering redacts email; audit filtering preserves it for the later hashing filter."""

    def test_app_channel_redacts_email_from_message(self):
        """The app-channel filter replaces email addresses in the message
        with [REDACTED:email] — PII must not reach app logs."""
        record = _make_record("user bob@example.org did X")

        assert config_logging._redactor.filter(record) is True

        assert "[REDACTED:email]" in record.msg
        assert "bob@example.org" not in record.msg

    def test_audit_channel_keeps_email_in_message(self):
        """Preserve raw email through the audit secret filter before audit hashing."""
        record = _make_record("user bob@example.org did X", name="audit")

        assert config_logging._audit_redactor.filter(record) is True

        assert "bob@example.org" in record.msg
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
    """Apply channel-specific redaction recursively to structured extras."""

    @_BOTH_CHANNELS
    def test_nested_dict_extra_redacts_session_secret(self, channel_filter):
        """Redact secrets nested inside extra dictionaries on both channels."""
        secret = settings.session_secret.get_secret_value()
        record = _make_record("session event", details={"nested": {"value": secret}})

        channel_filter.filter(record)

        assert record.details == {"nested": {"value": "[REDACTED:session_secret]"}}

    def test_list_extra_with_leaky_object_str_is_redacted(self):
        """Stringify and redact secret-bearing objects inside extra lists."""
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
        """Apply the channel email policy recursively to nested extras."""
        audit_record = _make_record(
            "email_changed", name="audit", details={"email": "bob@example.org"}
        )
        app_record = _make_record("email_changed", details={"email": "bob@example.org"})

        config_logging._audit_redactor.filter(audit_record)
        config_logging._redactor.filter(app_record)

        assert audit_record.details == {"email": "bob@example.org"}
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
    """Redact recognized runtime-secret shapes without requiring Settings-value equality."""

    @_BOTH_CHANNELS
    @pytest.mark.parametrize(("kind", "secret_value"), _SECRET_VALUE_CLASSES)
    def test_value_is_redacted_from_message_and_nested_extras(
        self, channel_filter, kind, secret_value
    ):
        """Value is redacted from message and nested extras."""
        record = _make_record(
            f"handling event carrying {kind}: {secret_value}",
            payload={"nested": {"value": secret_value}},
        )

        channel_filter.filter(record)

        assert secret_value not in record.getMessage()
        assert secret_value not in json.dumps(record.payload, default=str)

    @_BOTH_CHANNELS
    def test_an_ordinary_identifier_survives_redaction(self, channel_filter):
        """The missing patterns above are not a filter that redacts everything — an ordinary,
        non-secret identifier must still reach the log unchanged.
        """
        identifier = "dataset-catalogue-entry-00482"
        record = _make_record(
            f"handling event carrying identifier: {identifier}",
            payload={"nested": {"value": identifier}},
        )

        channel_filter.filter(record)

        assert identifier in record.getMessage()
        assert record.payload == {"nested": {"value": identifier}}


class TestJSONFormatterOutput:
    """Sanitize messages/extras into one JSON object even without a preceding filter."""

    def test_json_formatter_emits_single_object_with_extras(self):
        """JSON formatter emits single object with extras."""
        record = _make_record(
            "user bob@example.org did X",
            request_id="req-1",
            details={"email": "bob@example.org"},
        )
        config_logging._redactor.filter(record)

        output = JSONFormatter().format(record)

        assert "\n" not in output
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert "timestamp" in parsed
        assert parsed["message"] == "user [REDACTED:email] did X"
        assert parsed["request_id"] == "req-1"
        assert parsed["details"] == {"email": "[REDACTED:email]"}
        assert "bob@example.org" not in output

    def test_json_formatter_handles_non_serializable_extra(self):
        """Stringify non-JSON extra objects without leaking secrets or raising."""
        record = _make_record("weird payload")
        config_logging._redactor.filter(record)
        record.weird = _Unserializable()

        output = JSONFormatter().format(record)

        parsed = json.loads(output)
        assert parsed["weird"] == "opaque-object"

    @pytest.mark.parametrize(
        "secret",
        ["/reset-password/private-token", "Bearer private-token"],
        ids=["path-shaped-secret", "bearer-header-shaped-secret"],
    )
    def test_json_formatter_redacts_top_level_and_nested_secrets_without_a_filter(self, secret):
        """JSON formatter redacts top level and nested secrets without a filter."""
        record = logging.makeLogRecord({"msg": secret, "nested": {"url": secret}, "tail": "intact"})

        output = JSONFormatter().format(record)

        decoded = json.loads(output)
        assert decoded["tail"] == "intact"
        assert isinstance(decoded["nested"], dict)
        assert "private-token" not in output

    def test_json_formatter_redacts_a_custom_object_before_serialization(self):
        """JSON formatter redacts a custom object before serialization."""

        class SensitiveObject:
            """Expose a bearer-token canary through text conversion."""

            def __str__(self):
                """Return a bearer-token canary for formatter redaction."""
                return "Bearer custom-secret"

        output = JSONFormatter().format(
            logging.makeLogRecord({"msg": "ok", "obj": SensitiveObject()})
        )

        assert "custom-secret" not in output
        assert "obj" in json.loads(output)


class TestActionTokenPathRedaction:
    """Scrub action capabilities from paths on both channels and formatter paths."""

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
    """Keep exception frames/types while omitting raw exception values."""

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
            """Raise TypeError carrying the formatter-failure canary."""
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
    """Warn and omit redaction patterns for values shorter than eight characters."""

    def test_short_secret_warns_and_is_excluded_from_patterns(self, monkeypatch):
        """Warn without compiling an overmatching pattern for a short sensitive value."""
        monkeypatch.setattr(settings, "session_secret", SecretStr("short"))

        fresh = SensitiveDataFilter(include_pii=True)
        with pytest.warns(RuntimeWarning, match="session_secret"):
            patterns = fresh.patterns

        assert all(repl != "[REDACTED:session_secret]" for _, repl in patterns)
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
        assert messages
        for msg in messages:
            assert str(config_logging._MIN_REDACTION_VALUE_LENGTH) in msg
            assert "{_MIN_REDACTION_VALUE_LENGTH}" not in msg


class TestAuditEmailAutoHash:
    """Hash raw audit emails, preserve categorical fields and fail closed without a hasher."""

    def test_audit_email_autohash_rewrites_raw_addresses_to_keyed_hash(self):
        """Replace raw audit emails in messages/extras with stable keyed-hash markers."""
        expected = f"[email:{audit_email_hash('alice@example.org')}]"
        r1 = _audit_record("reset for alice@example.org", email="alice@example.org")
        r2 = _audit_record("second event", email="alice@example.org")
        f = AuditEmailAutoHash()
        f.filter(r1)
        f.filter(r2)
        assert r1.getMessage() == f"reset for {expected}"
        assert r1.email == expected
        assert r2.email == expected

    def test_audit_email_autohash_leaves_email_named_categoricals_alone(self):
        """Preserve email-named categories and existing hash values."""
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
        """Replace emails with an uncorrelatable marker before hasher registration."""
        monkeypatch.setattr(logging_module, "_audit_email_hasher", None)
        r = _audit_record("x", email="alice@example.org")
        logging_module.AuditEmailAutoHash().filter(r)
        assert r.email == "[REDACTED:email]"
        assert "alice@example.org" not in r.getMessage() + str(r.email)
