"""Shared helper function for http url checks"""

def is_safe_http_url(value: str | None) -> bool:
    """Single source of truth for the http(s) scheme allowlist.

    True if and only if `value` is a non-empty absolute http:// or https:// URL. Rejects
    javascript:, data:, protocol-relative //host, and scheme-only forms
    (https:foo). Used at ingest (_safe_url) and at render (safe_url filter)
    so the two can't drift.
    """
    return bool(value and value.strip().lower().startswith(("http://", "https://")))