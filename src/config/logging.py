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

import logging
import re
import sys
import warnings
import json
from typing import Any

from config import settings
from datetime import datetime, timezone
from pydantic import SecretStr


_STD_LOGRECORD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}



def _build_sensitive_patterns(include_pii: bool = True) -> list[tuple[re.Pattern, str]]:
    """Build redaction patterns from Settings field metadata.
    
    Reads fields marked with json_schema_extra={"sensitive": True}
    and fields typed as SecretStr, then builds regex patterns
    from their actual values.
    """

    patterns = []

    # Lazy import to avoid circular dependency
    from config.settings import Settings

    for field_name, field_info in Settings.model_fields.items():
        is_secret_type = field_info.annotation is SecretStr
        is_marked_sensitive = (
            isinstance(field_info.json_schema_extra, dict)
            and field_info.json_schema_extra.get("sensitive", False)
        )

        if not (is_secret_type or is_marked_sensitive):
            continue

        value = getattr(settings, field_name, None)
        if value is None:
            continue

        if isinstance(value, SecretStr):
            value = value.get_secret_value()

        row = str(value)

        if len(row) < 8:
            warnings.warn(
                f"Sensitive field '{field_name}' is shorter than 8 characters "
                "and cannot be reliably redacted from logs. "
                "Consider using a stronger value.",
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        patterns.append((
            re.compile(re.escape(row)),
            f"[REDACTED:{field_name}]",
        ))

    patterns.append((
        re.compile(r"(?i)bearer\s+\S+"),
        "Bearer ***",
    ))
    if include_pii:
        patterns.append((re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.\w{2,}\b"), 
        "[REDACTED:email]"))  # PII — app logs only

    return patterns

class SensitiveDataFilter(logging.Filter):
    """Redact secrets and PII from all log output.
    
    Patterns are built from Settings field metadata:
    - Fields typed as SecretStr
    - Fields with json_schema_extra={"sensitive": True}
    
    Plus static patterns for auth headers and other non-settings secrets.
    """

    def __init__(self, include_pii: bool = True) -> None:
        super().__init__()
        self._patterns = None
        self._include_pii = include_pii

    @property
    def patterns(self):
        if self._patterns is None:
            self._patterns = _build_sensitive_patterns(include_pii=self._include_pii)
        return self._patterns


    def apply(self, text: str) -> str:
        """Run all redaction patterns over a string."""
        for pattern, replacement in self.patterns:
            text = pattern.sub(replacement, text)
        return text
    
    def _redact_any(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.apply(value)                                  
        if isinstance(value, dict):
            return {k: self._redact_any(v) for k, v in value.items()}  
        if isinstance(value, (list, tuple)):
            return [self._redact_any(v) for v in value]                
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
                record.__dict__[key] = self._redact_any(value)      
        return True

_redactor = SensitiveDataFilter(include_pii=True)         
_audit_redactor = SensitiveDataFilter(include_pii=False) 

def _redact(text: str) -> str:
    return _redactor.apply(text)


class JSONFormatter(logging.Formatter):
    """Structured JSON log output for production.
    
    Outputs one JSON object per line — compatible with most
    log aggregation tools (ELK, Loki, CloudWatch, etc.)
    """

    def format(self, record: logging.LogRecord) -> str:
        """Render a log record as a single-line JSON object, redacting string
        values of non-standard extra fields and any formatted exception text."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
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
                log_entry["exception"] = _redact(self.formatException(record.exc_info))
            except (AttributeError, TypeError) as e:
                log_entry["exception"] = f"<formatter error: {e}; raw exc_info: {record.exc_info!r}>"

        return json.dumps(log_entry, default=str)


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

    formatter: logging.Formatter
    
    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_redactor)            
    root_logger.addHandler(console_handler)

    audit_handler = logging.StreamHandler(sys.stdout)
    audit_handler.setFormatter(formatter)
    audit_handler.addFilter(_audit_redactor)      
    audit_logger.addHandler(audit_handler)  

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)