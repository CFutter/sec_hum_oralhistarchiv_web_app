"""
Structured logging configuration.

Provides:
- JSON format for production (machine-parseable, suitable for log aggregation)
- Human-readable format for development
- Sensitive data redaction on all handlers
- All logs go to stdout for systemd-journald to capture

Multi-process safety: this module uses StreamHandler (which is multi-process
safe) rather than file handlers. Earlier versions used TimedRotatingFileHandler,
which is NOT safe across gunicorn workers — concurrent rotation can corrupt
logs. journald handles rotation/retention via SystemMaxUse and
MaxRetentionSec in /etc/systemd/journald.conf.
"""

import copy
import json
import logging
import re
import sys
import traceback
import types
import warnings
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, TypedDict, Union, get_args, get_origin

from pydantic import SecretStr

from config.settings import settings

RedactionPattern = tuple[re.Pattern[str], str]

_STD_LOGRECORD_ATTRS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
    "message",
    "asctime",
}

_MIN_REDACTION_VALUE_LENGTH = 8

# One email pattern shared by the app channel's [REDACTED:email] rule and the
# audit channel's hash-preserving AuditEmailAutoHash — a single definition so
# the two channels can never disagree about what counts as an address.
_EMAIL_PATTERN = re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.\w{2,}\b")

_ACTION_TOKEN_PATH_PATTERN = re.compile(
    r"(?P<prefix>/(?:reset-password|verify-email|account/confirm-email)/)"
    r"[^/?#\s]+"
)

_RUNTIME_SECRET_SHAPE_PATTERNS: tuple[RedactionPattern, ...] = (
    # Fernet tokens: version byte 0x80 always base64-encodes to "gAAAAA".
    (re.compile(r"gAAAAA[A-Za-z0-9_\-]{20,}={0,2}"), "[REDACTED:fernet]"),
    # data: URIs such as the enrollment QR code (the image embeds the seed).
    (re.compile(r"(?i)data:image/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+"), "[REDACTED:data-uri]"),
    # pyotp.random_base32() seeds: exactly 32 RFC 4648 base32 characters.
    (re.compile(r"(?<![A-Za-z0-9])[A-Z2-7]{32}(?![A-Za-z0-9])"), "[REDACTED:totp-seed]"),
    # Real display-format recovery codes: 4 groups of 5 upper-case hex.
    (
        re.compile(r"(?<![0-9A-Za-z-])[0-9A-F]{5}(?:-[0-9A-F]{5}){3}(?![0-9A-Za-z-])"),
        "[REDACTED:recovery-code]",
    ),
)


def _annotation_contains_secretstr(annotation: Any) -> bool:
    """True if a field annotation is SecretStr or contains it.

    Recurses through Optional/Union (both ``Optional[SecretStr]`` and the
    PEP-604 ``SecretStr | None`` spelling) and container generics
    (list/tuple/set/frozenset/dict), so ``list[SecretStr]`` and
    ``SecretStr | None`` count as secret-bearing. The type-side mirror of
    ``_iter_secret_values`` — extend BOTH when adding a new shape.
    """
    if annotation is SecretStr:
        return True
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType, list, tuple, set, frozenset, dict):
        return any(_annotation_contains_secretstr(a) for a in get_args(annotation))
    return False


def _iter_secret_values(value: Any) -> Iterator[str]:
    """Yield the raw string leaves of a possibly wrapped/collection value.

    The runtime mirror of ``_annotation_contains_secretstr``: unwraps
    SecretStr, walks list/tuple/set/frozenset elements and dict *values*,
    and stringifies plain leaves (fields marked
    ``json_schema_extra={"sensitive": True}`` without SecretStr typing).
    ``None`` yields nothing, so an unset optional secret produces neither
    a pattern nor a short-value warning.
    """
    if value is None:
        return
    if isinstance(value, SecretStr):
        yield value.get_secret_value()
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_secret_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_secret_values(item)
    else:
        yield str(value)  # plain fields marked json_schema_extra={"sensitive": True}


def _build_sensitive_patterns(include_pii: bool = True) -> list[RedactionPattern]:
    """Build redaction patterns from Settings field metadata.

    Covers fields marked ``json_schema_extra={"sensitive": True}`` and every
    field whose annotation CONTAINS SecretStr — plain, ``SecretStr | None``,
    or inside a container such as ``list[SecretStr]``. Collection fields get
    ONE PATTERN PER ELEMENT (all sharing the ``[REDACTED:<field_name>]``
    marker), so during a MultiFernet rotation both the new and the old
    TOTP_ENCRYPTION_KEYS entries are redacted. Values shorter than the
    minimum supported redaction length are skipped with a RuntimeWarning
    because they would over-match ordinary text.
    """

    patterns: list[RedactionPattern] = []

    from config.settings import Settings  # noqa: PLC0415 - Lazy import to avoid circular dependency

    for field_name, field_info in Settings.model_fields.items():
        is_secret_type = _annotation_contains_secretstr(field_info.annotation)
        is_marked_sensitive = isinstance(
            field_info.json_schema_extra, dict
        ) and field_info.json_schema_extra.get("sensitive", False)

        if not (is_secret_type or is_marked_sensitive):
            continue

        for row in _iter_secret_values(getattr(settings, field_name)):
            if len(row) < _MIN_REDACTION_VALUE_LENGTH:
                warnings.warn(
                    f"Sensitive field '{field_name}' has a value shorter than "
                    f"'{_MIN_REDACTION_VALUE_LENGTH}' characters and cannot "
                    "be reliably redacted from logs. "
                    "Consider using a stronger value.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue

            patterns.append(
                (
                    re.compile(re.escape(row)),
                    f"[REDACTED:{field_name}]",
                )
            )

    patterns.extend(_RUNTIME_SECRET_SHAPE_PATTERNS)
    patterns.append(
        (
            _ACTION_TOKEN_PATH_PATTERN,
            r"\g<prefix><token>",
        )
    )
    patterns.append(
        (
            re.compile(r"(?i)bearer\s+\S+"),
            "Bearer ***",
        )
    )
    if include_pii:
        patterns.append((_EMAIL_PATTERN, "[REDACTED:email]"))  # PII — app logs only;
        # the audit channel gets hash-preserving treatment via AuditEmailAutoHash instead

    return patterns


class SensitiveDataFilter(logging.Filter):
    """Redact secrets and PII from all log output.

    Patterns are built from Settings field metadata:
    - Fields whose annotation contains SecretStr (plain, Optional,
    or inside a container — one pattern per element)
    - Fields with json_schema_extra={"sensitive": True}

    Plus static patterns for auth headers and other non-settings secrets.
    """

    def __init__(self, include_pii: bool = True) -> None:
        super().__init__()
        self._patterns: list[RedactionPattern] | None = None
        self._include_pii = include_pii

    @property
    def patterns(self) -> list[RedactionPattern]:
        if self._patterns is None:
            self._patterns = _build_sensitive_patterns(include_pii=self._include_pii)
        return self._patterns

    def apply(self, text: str) -> str:
        """Run all redaction patterns over a string."""
        for pattern, replacement in self.patterns:
            text = pattern.sub(replacement, text)
        return text

    def sanitize(self, value: Any) -> Any:
        """Redact structured values before a formatter serializes them."""
        if isinstance(value, str):
            return self.apply(value)
        if isinstance(value, dict):
            return {self.apply(str(k)): self.sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.sanitize(v) for v in value]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self.apply(str(value))

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data in the message and in string-valued extra
        fields, so redaction is formatter-independent (text and JSON alike)."""
        record.msg = self.apply(record.getMessage())
        record.args = ()
        for key, value in list(record.__dict__.items()):
            if key not in _STD_LOGRECORD_ATTRS:
                record.__dict__[key] = self.sanitize(value)
        return True


# Registered by app.services.crypto at import time. config cannot import app
# (layering; and mypy resolves the resulting cycle by binding config.settings
# to the submodule, breaking crypto's own types) — so the dependency is
# inverted: the crypto layer hands its keyed hasher up via
# set_audit_email_hasher(). Until registration, addresses fall back to the
# non-correlatable [REDACTED:email] marker — fail-closed, never raw.
_audit_email_hasher: Callable[[str], str] | None = None


def set_audit_email_hasher(hasher: Callable[[str], str]) -> None:
    """Register the keyed hasher AuditEmailAutoHash rewrites addresses with."""
    global _audit_email_hasher  # noqa: PLW0603 - module-level singleton state is intentional here
    _audit_email_hasher = hasher


class AuditEmailAutoHash(logging.Filter):
    """Replace raw email addresses on the audit channel with their keyed hash.

    The audit channel deliberately skips the app channel's blanket
    [REDACTED:email] regex (include_pii=False on _audit_redactor) because
    audit events correlate actors via audit_email_hash(). That makes the
    channel's safety purely conventional: every call site must remember to
    hash. This filter is the mechanism behind that convention — any address
    that reaches the channel raw (in the message or an extra value) is
    swapped for "[email:<hash>]", so a forgotten hash degrades to a
    correlatable marker instead of PII in the retained audit stream.

    Value-shape based, NOT key-name based: only strings matching
    _EMAIL_PATTERN are rewritten, so categorical fields that merely have
    "email" in their key (email_type="password_reset",
    email_was_registered=True) pass through unchanged, and *_hash fields
    (bare hex) never match.
    """

    def _hash_match(self, m: "re.Match[str]") -> str:
        if _audit_email_hasher is None:
            return "[REDACTED:email]"
        return f"[email:{_audit_email_hasher(m.group(0))}]"

    def _apply(self, text: str) -> str:
        return _EMAIL_PATTERN.sub(self._hash_match, text)

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._apply(value)
        if isinstance(value, dict):
            return {k: self._sanitize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._sanitize(v) for v in value]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self._apply(str(value))

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._apply(record.getMessage())
        record.args = ()
        for key, value in list(record.__dict__.items()):
            if key not in _STD_LOGRECORD_ATTRS:
                record.__dict__[key] = self._sanitize(value)
        return True


_redactor = SensitiveDataFilter(include_pii=True)
_audit_redactor = SensitiveDataFilter(include_pii=False)
_audit_email_autohash = AuditEmailAutoHash()


def _redact(text: str) -> str:
    return _redactor.apply(text)


class _ExceptionDiagnostic(TypedDict, total=False):
    type: str
    frames: list[str]
    errno: int
    sqlstate: str
    cause: "_ExceptionDiagnostic"
    cause_omitted: str
    context: "_ExceptionDiagnostic"
    context_omitted: str
    members: list["_ExceptionDiagnostic"]
    members_omitted: int
    truncated: str


_MAX_EXCEPTION_TREE_DEPTH = 4
_MAX_EXCEPTION_TREE_NODES = 16
_MAX_EXCEPTION_FRAMES_PER_NODE = 25
_EXCEPTION_NODE_BUDGET_REASON = "maximum node count reached"
_SQLSTATE_PATTERN = re.compile(r"[0-9A-Z]{5}\Z")


def _truncated_exception(reason: str) -> _ExceptionDiagnostic:
    return {
        "type": "<exception details truncated>",
        "truncated": reason,
    }


def _safe_traceback_frames(
    traceback_object: types.TracebackType | None,
) -> list[str]:
    try:
        return traceback.format_tb(
            traceback_object,
            limit=-_MAX_EXCEPTION_FRAMES_PER_NODE,
        )
    except Exception:
        return ["<traceback unavailable>"]


def _safe_sqlstate(exc: BaseException) -> str | None:
    """Return only a valid, categorical database SQLSTATE."""
    try:
        sqlstate = getattr(exc, "sqlstate", None)
    except Exception:
        return None

    if isinstance(sqlstate, str) and _SQLSTATE_PATTERN.fullmatch(sqlstate):
        return sqlstate
    return None


def _safe_exception_tree(
    exc: BaseException,
    *,
    root_traceback: types.TracebackType | None,
) -> _ExceptionDiagnostic:
    """Render bounded exception metadata without values, messages, or arguments.

    Every emitted diagnostic object, including a depth/cycle placeholder, consumes
    one slot from the shared node budget. Exception-group traversal stops when the
    budget is exhausted and records how many members were omitted.
    """
    visited: set[int] = set()
    node_count = 0

    def build(
        current: BaseException,
        *,
        depth: int,
        traceback_override: types.TracebackType | None = None,
    ) -> _ExceptionDiagnostic | None:
        nonlocal node_count

        # Claim the slot before testing depth or cycles: the placeholder emitted
        # for either condition is still a node in the serialized result.
        if node_count >= _MAX_EXCEPTION_TREE_NODES:
            return None
        node_count += 1

        if depth >= _MAX_EXCEPTION_TREE_DEPTH:
            return _truncated_exception("maximum depth reached")
        if id(current) in visited:
            return _truncated_exception("cycle detected")

        visited.add(id(current))

        node: _ExceptionDiagnostic = {
            "type": f"{type(current).__module__}.{type(current).__qualname__}",
            "frames": _safe_traceback_frames(
                current.__traceback__ if traceback_override is None else traceback_override
            ),
        }

        if isinstance(current, OSError) and type(current.errno) is int:
            node["errno"] = current.errno

        if sqlstate := _safe_sqlstate(current):
            node["sqlstate"] = sqlstate

        # Preserve the causal chain before spending the remaining budget on
        # siblings from a potentially very wide ExceptionGroup.
        if current.__cause__ is not None:
            cause = build(current.__cause__, depth=depth + 1)
            if cause is None:
                node["cause_omitted"] = _EXCEPTION_NODE_BUDGET_REASON
            else:
                node["cause"] = cause
        elif not current.__suppress_context__ and current.__context__ is not None:
            context = build(current.__context__, depth=depth + 1)
            if context is None:
                node["context_omitted"] = _EXCEPTION_NODE_BUDGET_REASON
            else:
                node["context"] = context

        if isinstance(current, BaseExceptionGroup):
            members: list[_ExceptionDiagnostic] = []
            total_members = len(current.exceptions)

            for index, member in enumerate(current.exceptions):
                rendered_member = build(member, depth=depth + 1)
                if rendered_member is None:
                    node["members_omitted"] = total_members - index
                    break
                members.append(rendered_member)

            if members:
                node["members"] = members

        return node

    root = build(exc, depth=0, traceback_override=root_traceback)
    if root is None:
        raise RuntimeError("exception-tree node budget does not allow a root node")
    return root


def _render_exception_text(node: _ExceptionDiagnostic) -> str:
    """Render the safe tree for the development text formatter."""
    lines: list[str] = []

    def render(current: _ExceptionDiagnostic, indent: str) -> None:
        exception_type = current.get("type", "<exception unavailable>")
        diagnostics: list[str] = []

        if "errno" in current:
            diagnostics.append(f"errno={current['errno']}")
        if "sqlstate" in current:
            diagnostics.append(f"sqlstate={current['sqlstate']}")
        if "truncated" in current:
            diagnostics.append(f"truncated={current['truncated']}")

        suffix = f" [{', '.join(diagnostics)}]" if diagnostics else ""
        lines.append(f"{indent}{exception_type}{suffix}")

        for frame in current.get("frames", []):
            lines.extend(f"{indent}{frame_line}" for frame_line in frame.rstrip("\n").splitlines())

        cause = current.get("cause")
        if isinstance(cause, dict):
            lines.append(f"{indent}caused by:")
            render(cause, f"{indent}  ")
        elif cause_omitted := current.get("cause_omitted"):
            lines.append(f"{indent}caused by: <omitted: {cause_omitted}>")

        context = current.get("context")
        if isinstance(context, dict):
            lines.append(f"{indent}during handling of:")
            render(context, f"{indent}  ")
        elif context_omitted := current.get("context_omitted"):
            lines.append(f"{indent}during handling of: <omitted: {context_omitted}>")

        for index, member in enumerate(current.get("members", []), start=1):
            lines.append(f"{indent}exception-group member {index}:")
            render(member, f"{indent}  ")

        if members_omitted := current.get("members_omitted"):
            lines.append(f"{indent}exception-group members omitted: {members_omitted}")

    render(node, "")
    return "\n".join(lines)


class RedactingFormatter(logging.Formatter):
    """Render diagnostics without rendering exception values or messages."""

    _EXCEPTION_FORMATTING_FAILED = "<exception formatting failed>"
    _CACHED_EXCEPTION_OMITTED = "<cached exception text omitted>"
    _LOG_FORMATTING_FAILED = "<log formatting failed>"

    @staticmethod
    def _exception_diagnostic(
        exc_info: (
            tuple[type[BaseException], BaseException, types.TracebackType | None]
            | tuple[None, None, None]
        ),
    ) -> _ExceptionDiagnostic:
        exc_type, exc_value, traceback_object = exc_info
        if exc_type is None or exc_value is None:
            return {"type": "<exception unavailable>"}

        return _safe_exception_tree(
            exc_value,
            root_traceback=traceback_object,
        )

    def formatException(
        self,
        exc_info: (
            tuple[type[BaseException], BaseException, types.TracebackType | None]
            | tuple[None, None, None]
        ),
    ) -> str:
        try:
            return _redact(_render_exception_text(self._exception_diagnostic(exc_info)))
        except Exception:
            return self._EXCEPTION_FORMATTING_FAILED

    def formatStack(self, stack_info: str) -> str:
        return _redact(super().formatStack(stack_info))

    def format(self, record: logging.LogRecord) -> str:
        safe_record = copy.copy(record)

        if safe_record.exc_info:
            safe_record.exc_text = self.formatException(safe_record.exc_info)
        elif safe_record.exc_text:
            safe_record.exc_text = self._CACHED_EXCEPTION_OMITTED

        try:
            return _redact(logging.Formatter.format(self, safe_record))
        except Exception:
            return self._LOG_FORMATTING_FAILED


class JSONFormatter(RedactingFormatter):
    """Structured JSON logging with bounded, message-free exception trees."""

    def format(self, record: logging.LogRecord) -> str:
        try:
            return self._format_json(record)
        except Exception:
            return json.dumps({"message": self._LOG_FORMATTING_FAILED})

    def _format_json(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        for key, value in record.__dict__.items():
            if key not in _STD_LOGRECORD_ATTRS and key not in log_entry:
                log_entry[key] = value

        if record.exc_info:
            try:
                log_entry["exception"] = self._exception_diagnostic(record.exc_info)
            except Exception:
                log_entry["exception"] = {
                    "type": self._EXCEPTION_FORMATTING_FAILED,
                }

        return json.dumps(_redactor.sanitize(log_entry))


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure application-wide logging.

    All logs go to stdout for systemd-journald to capture. journald handles
    rotation and retention (configured in /etc/systemd/journald.conf via
    SystemMaxUse= and MaxRetentionSec=).

    Logs are emitted to stdout for journald capture. Off-host shipping
    (when required) is handled by a host-level agent (rsyslog over RELP/TLS)
    reading from journald — not by the application. See Deployment.md.

    Args:
        log_level: Minimum level for application logs.
        log_format: "json" for structured output, "text" for human-readable.

    Call once during application startup (in lifespan handler).
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    root_logger.handlers.clear()

    audit_logger = logging.getLogger("audit")
    audit_logger.handlers.clear()
    audit_logger.propagate = False
    audit_logger.setLevel(logging.INFO)
    # On the LOGGER, not the handler: runs once per record, before every
    # present and future handler (including pytest's caplog). addFilter is
    # idempotent for the same instance across repeated setup_logging calls.
    audit_logger.addFilter(_audit_email_autohash)

    formatter: logging.Formatter

    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = RedactingFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_redactor)
    root_logger.addHandler(console_handler)

    audit_handler = logging.StreamHandler(sys.stdout)
    # Audit context must survive even when application logs use text display.
    audit_handler.setFormatter(JSONFormatter())
    audit_handler.addFilter(_audit_redactor)
    audit_logger.addHandler(audit_handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
