"""Configure stdout app/audit logging with bounded redaction and exception diagnostics.

App output uses JSON or text; audit output always uses JSON. Host logging
owns rotation, retention and shipping. StreamHandler serializes threads per
handler; separate worker processes may interleave stdout writes. Patterns
are cached from settings on first use, so restart after secret changes.
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
from threading import RLock
from typing import Any, TypedDict, Union, get_args, get_origin
from weakref import WeakKeyDictionary

from pydantic import SecretStr

from app import escape_log_controls
from app.bootstrap_logging import route_server_logs
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
_LOG_FORMATTING_FAILED = "<log formatting failed>"
_LOG_SANITIZATION_FAILED = "<log sanitization failed>"
_MAX_LOG_CONTEXT_DEPTH = 16
_MAX_LOG_CONTEXT_NODES = 512
_LOG_CONTEXT_CYCLE = "<cycle>"
_LOG_CONTEXT_TRUNCATED = "<truncated>"
_LOG_CONTEXT_UNPRINTABLE = "<unprintable>"


def _safe_log_message(record: logging.LogRecord) -> str:
    """Return the formatted message or a fixed marker if interpolation raises Exception."""
    try:
        return record.getMessage()
    except Exception:
        return _LOG_FORMATTING_FAILED


class _StructuredValueSanitizer:
    """Copy JSON-like values within 16 container levels and 512 visited nodes.

    Replace ancestor cycles, unprintable objects and exhausted traversal with
    markers. Repeated sibling references are allowed. Instances carry mutable
    traversal state and must not be shared concurrently.
    """

    def __init__(self, transform: Callable[[str], str], *, transform_keys: bool = True) -> None:
        """Set string/key transforms and initialize one traversal budget."""
        self._transform = transform
        self._transform_keys = transform_keys
        self._active: set[int] = set()
        self._remaining_nodes = _MAX_LOG_CONTEXT_NODES

    @property
    def exhausted(self) -> bool:
        """Return whether the shared visited-node budget is exhausted."""
        return self._remaining_nodes <= 0

    def _text(self, value: Any, *, transform: bool = True) -> str:
        """Stringify or return an unprintable marker; optionally transform the text."""
        try:
            text = str(value)
        except Exception:
            return _LOG_CONTEXT_UNPRINTABLE
        return self._transform(text) if transform else text

    def sanitize(self, value: Any, *, depth: int = 0) -> Any:
        """Return a bounded normalized copy, consuming this instance's shared traversal budget."""
        if self.exhausted:
            return _LOG_CONTEXT_TRUNCATED
        self._remaining_nodes -= 1

        if isinstance(value, (dict, list, tuple)):
            if id(value) in self._active:
                return _LOG_CONTEXT_CYCLE
            if depth >= _MAX_LOG_CONTEXT_DEPTH:
                return _LOG_CONTEXT_TRUNCATED
            self._active.add(id(value))
            try:
                return self._container(value, depth=depth)
            finally:
                self._active.remove(id(value))

        # Keep numeric JSON types while discarding subclass hooks that could
        # otherwise run later during serialization or snapshot deepcopy.
        if value is None or type(value) in (int, float, bool):
            return value
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            return float(value)
        return self._text(value)

    def _container(self, value: Any, *, depth: int) -> Any:
        """Copy container children into a string-keyed dict/list within the remaining budget."""
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in value.items():
                if self.exhausted:
                    result[_LOG_CONTEXT_TRUNCATED] = _LOG_CONTEXT_TRUNCATED
                    break
                safe_key = self._text(key, transform=self._transform_keys)
                result[safe_key] = self.sanitize(item, depth=depth + 1)
            return result

        items: list[Any] = []
        for item in value:
            if self.exhausted:
                items.append(_LOG_CONTEXT_TRUNCATED)
                break
            items.append(self.sanitize(item, depth=depth + 1))
        return items


def _replace_record_extras(record: logging.LogRecord, extras: dict[str, Any]) -> None:
    """Replace every nonstandard LogRecord field in place with extras."""
    for key in list(record.__dict__):
        if key not in _STD_LOGRECORD_ATTRS:
            del record.__dict__[key]
    record.__dict__.update(extras)


def _sanitize_record_extras(
    record: logging.LogRecord, sanitizer: _StructuredValueSanitizer
) -> None:
    """Replace nonstandard record fields using one shared bounded traversal."""
    extras: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _STD_LOGRECORD_ATTRS:
            continue
        if sanitizer.exhausted:
            extras["log_context_truncated"] = True
            break
        extras[key] = sanitizer.sanitize(value)
    _replace_record_extras(record, extras)


def _replace_failed_log_context(record: logging.LogRecord) -> None:
    """Contain filter faults without logging again or exposing partial work."""
    record.msg = _LOG_SANITIZATION_FAILED
    record.args = ()
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    _replace_record_extras(record, {"log_sanitization_failed": True})


# Share email matching so application redaction and audit hashing cannot diverge.
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
    """Return whether SecretStr occurs in the annotation or a supported union/container.

    Support Union, PEP 604 unions, list, tuple, set, frozenset and dict; keep this
    in sync with _iter_secret_values when adding shapes.
    """
    if annotation is SecretStr:
        return True
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType, list, tuple, set, frozenset, dict):
        return any(_annotation_contains_secretstr(a) for a in get_args(annotation))
    return False


def _iter_secret_values(value: Any) -> Iterator[str]:
    """Yield raw SecretStr leaves or stringified values; skip None.

    Recurse through list/tuple/set/frozenset elements and dict values. This is
    the runtime counterpart of _annotation_contains_secretstr.
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
    """Return literal setting-secret and runtime credential redaction patterns.

    Inspect SecretStr-containing/sensitive-marked fields; warn and skip nonempty
    values shorter than eight characters. include_pii adds email redaction;
    audit uses a separate hash filter. Snapshot current settings values.
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
            if not row:
                continue  # Optional unset credentials have nothing to redact.
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

    return patterns


class SensitiveDataFilter(logging.Filter):
    """Redact configured/runtime secret patterns and optionally email in messages/extras.

    Pattern matching is not a guarantee for arbitrary secrets or PII; formatters
    handle exception diagnostics separately.
    """

    def __init__(self, include_pii: bool = True) -> None:
        """Select email policy and initialize a lazy pattern cache plus locked record snapshots."""
        super().__init__()
        self._patterns: list[RedactionPattern] | None = None
        self._include_pii = include_pii
        # Keep optimization state outside LogRecord's public structured fields.
        # Weak keys retain it only while a handler/capture still owns the record.
        self._sanitized_records: WeakKeyDictionary[logging.LogRecord, dict[str, Any]] = (
            WeakKeyDictionary()
        )
        self._snapshot_lock = RLock()

    def _remember_sanitization(self, record: logging.LogRecord) -> None:
        """Deep-copy sanitized message/extras into a weak-key, lock-protected record snapshot."""
        fields = {"msg": record.msg}
        fields.update({k: v for k, v in record.__dict__.items() if k not in _STD_LOGRECORD_ATTRS})
        # Sanitization has reduced values to JSON-like containers/scalars.
        snapshot = copy.deepcopy(fields)
        with self._snapshot_lock:
            self._sanitized_records[record] = snapshot

    def already_sanitized(self, record: logging.LogRecord | None, field: str, value: Any) -> bool:
        """Return whether this field still matches its last sanitized snapshot."""
        if record is None:
            return False
        with self._snapshot_lock:
            snapshot = self._sanitized_records.get(record)
        if snapshot is None or field not in snapshot:
            return False
        try:
            return bool(snapshot[field] == value)
        except Exception:
            return False

    @property
    def patterns(self) -> list[RedactionPattern]:
        """Build once and return the mutable patterns cached from current settings."""
        if self._patterns is None:
            self._patterns = _build_sensitive_patterns(include_pii=self._include_pii)
        return self._patterns

    def apply(self, text: str) -> str:
        """Run all redaction patterns over a string."""
        for pattern, replacement in self.patterns:
            text = pattern.sub(replacement, text)
        return text

    def sanitize(self, value: Any) -> Any:
        """Redact one structured value with cycle, depth, and node bounds."""
        return _StructuredValueSanitizer(self.apply).sanitize(value)

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact message/extras; return True, replacing failed context with safe markers."""
        try:
            record.msg = self.apply(_safe_log_message(record))
            record.args = ()
            _sanitize_record_extras(record, _StructuredValueSanitizer(self.apply))
            self._remember_sanitization(record)
        except Exception:
            _replace_failed_log_context(record)
        return True


# Crypto registers its hasher to avoid a config/app import cycle; unset means redacted.
_audit_email_hasher: Callable[[str], str] | None = None


def set_audit_email_hasher(hasher: Callable[[str], str]) -> None:
    """Replace the process-wide audit email hasher; configure before concurrent logging."""
    global _audit_email_hasher  # noqa: PLW0603 - module-level singleton state is intentional here
    _audit_email_hasher = hasher


class AuditEmailAutoHash(logging.Filter):
    """Replace email-pattern matches in audit messages/extras with [email:<hash>].

    Without a registered hasher use [REDACTED:email]. Match values rather than
    field names; categorical email fields and existing bare hashes remain intact.
    """

    def _hash_match(self, m: "re.Match[str]") -> str:
        """Return the registered email hash marker, or a redacted marker before registration."""
        if _audit_email_hasher is None:
            return "[REDACTED:email]"
        return f"[email:{_audit_email_hasher(m.group(0))}]"

    def _apply(self, text: str) -> str:
        """Replace all matching email substrings using the current audit hasher."""
        return _EMAIL_PATTERN.sub(self._hash_match, text)

    def _sanitize(self, value: Any) -> Any:
        """Hash email in bounded structured values while preserving mapping keys."""
        return _StructuredValueSanitizer(self._apply, transform_keys=False).sanitize(value)

    def filter(self, record: logging.LogRecord) -> bool:
        """Hash email in message/extras; return True, replacing failed context with safe markers."""
        try:
            record.msg = self._apply(_safe_log_message(record))
            record.args = ()
            _sanitize_record_extras(
                record, _StructuredValueSanitizer(self._apply, transform_keys=False)
            )
        except Exception:
            _replace_failed_log_context(record)
        return True


_redactor = SensitiveDataFilter(include_pii=True)
_audit_redactor = SensitiveDataFilter(include_pii=False)
_audit_email_autohash = AuditEmailAutoHash()


def _redact(text: str) -> str:
    """Apply the process-wide application redaction patterns to text."""
    return _redactor.apply(text)


class _ExceptionDiagnostic(TypedDict, total=False):
    """Optional bounded exception-tree metadata; exception messages/arguments are omitted."""

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
    """Return an exception-tree placeholder carrying the truncation reason."""
    return {
        "type": "<exception details truncated>",
        "truncated": reason,
    }


def _safe_traceback_frames(
    traceback_object: types.TracebackType | None,
) -> list[str]:
    """Return up to 25 trailing formatted traceback frames, or an unavailable marker.

    Frames may include source lines; exception values and locals are not rendered.
    """
    try:
        return traceback.format_tb(
            traceback_object,
            limit=-_MAX_EXCEPTION_FRAMES_PER_NODE,
        )
    except Exception:
        return ["<traceback unavailable>"]


def _safe_sqlstate(exc: BaseException) -> str | None:
    """Return an uppercase five-character SQLSTATE, or None for absent/invalid/failing values."""
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
    """Return exception type/frame/errno/SQLSTATE metadata without exception messages or arguments.

    Traverse causes/contexts and groups within depth 4 and 16 total nodes,
    including placeholders. Keep at most 25 trailing frames per node; frames
    may contain source text. Mark cycles and omitted members.
    """
    visited: set[int] = set()
    node_count = 0

    def build(
        current: BaseException,
        *,
        depth: int,
        traceback_override: types.TracebackType | None = None,
    ) -> _ExceptionDiagnostic | None:
        """Consume one shared node slot and recursively render current; return None if exhausted."""
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
        """Append this diagnostic and its nested causes/groups to the shared output lines."""
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
    _LOG_FORMATTING_FAILED = _LOG_FORMATTING_FAILED

    @staticmethod
    def _exception_diagnostic(
        exc_info: (
            tuple[type[BaseException], BaseException, types.TracebackType | None]
            | tuple[None, None, None]
        ),
    ) -> _ExceptionDiagnostic:
        """Return bounded metadata for exc_info, or an unavailable-type marker if empty."""
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
        """Return redacted diagnostic text, or a fixed marker on formatting failure."""
        try:
            return _redact(_render_exception_text(self._exception_diagnostic(exc_info)))
        except Exception:
            return self._EXCEPTION_FORMATTING_FAILED

    def formatStack(self, stack_info: str) -> str:
        """Format/redact supplied stack text; formatting errors propagate."""
        return _redact(super().formatStack(stack_info))

    def format(self, record: logging.LogRecord) -> str:
        """Format a record copy with safe exceptions, redaction and one-line control escaping.

        Discard untrusted cached exception text; return a fixed marker if final
        formatting fails. The original record is not modified.
        """
        safe_record = copy.copy(record)

        if safe_record.exc_info:
            safe_record.exc_text = self.formatException(safe_record.exc_info)
        elif safe_record.exc_text:
            safe_record.exc_text = self._CACHED_EXCEPTION_OMITTED

        try:
            return escape_log_controls(_redact(logging.Formatter.format(self, safe_record)))
        except Exception:
            return self._LOG_FORMATTING_FAILED


class JSONFormatter(RedactingFormatter):
    """Policy-aware JSON logging with bounded, message-free exception trees.

    Filters own sanitization of submitted messages/extras; the formatter
    sanitizes generated diagnostics and metadata. A standalone formatter also
    sanitizes submitted fields, using the same explicit app/audit policy.
    """

    def __init__(self, *, audit: bool = False) -> None:
        """Select application or audit hashing/redaction policy."""
        super().__init__()
        self._audit = audit
        self._redactor = _audit_redactor if audit else _redactor

    def _sanitize(
        self, value: Any, record: logging.LogRecord | None = None, field: str = ""
    ) -> Any:
        """Hash audit emails, then redact fields unless their sanitized snapshot is unchanged."""
        if self._audit:
            value = _audit_email_autohash._sanitize(value)
        if not self._redactor.already_sanitized(record, field, value):
            value = self._redactor.sanitize(value)
        return value

    def format(self, record: logging.LogRecord) -> str:
        """Return JSON or a fixed JSON message marker if any formatting step fails."""
        try:
            return self._format_json(record)
        except Exception:
            return json.dumps({"message": self._LOG_FORMATTING_FAILED})

    def _format_json(self, record: logging.LogRecord) -> str:
        """Serialize UTC metadata, sanitized message/extras and bounded exception diagnostics."""
        log_entry: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": self._sanitize(_safe_log_message(record), record, "msg"),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # These fields were generated here, rather than processed by a filter.
        for key in ("level", "logger", "module", "function"):
            log_entry[key] = self._sanitize(log_entry[key])

        for key, value in record.__dict__.items():
            if key not in _STD_LOGRECORD_ATTRS and key not in log_entry:
                log_entry[self._sanitize(key)] = self._sanitize(value, record, key)

        if record.exc_info:
            try:
                log_entry["exception"] = self._sanitize(self._exception_diagnostic(record.exc_info))
            except Exception:
                log_entry["exception"] = {
                    "type": self._EXCEPTION_FORMATTING_FAILED,
                }

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Replace root/audit handlers with redacting stdout handlers and reroute server logs.

    log_level is case-insensitive; unknown names fall back to INFO. Only the
    exact log_format="json" selects app JSON; other values select escaped text.
    Audit remains JSON at INFO without propagation. Set uvicorn.access and
    sqlalchemy.engine to WARNING. Call during startup, before concurrent logging;
    host logging owns retention/rotation/shipping.
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
    # UvicornWorker installs Gunicorn's plain handlers with propagation off.
    # Lifespan setup must take ownership after that worker-side wiring.
    route_server_logs()

    audit_handler = logging.StreamHandler(sys.stdout)
    # Audit context must survive even when application logs use text display.
    audit_handler.setFormatter(JSONFormatter(audit=True))
    audit_handler.addFilter(_audit_redactor)
    audit_logger.addHandler(audit_handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
