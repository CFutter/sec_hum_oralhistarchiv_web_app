"""Structural validation for externally supplied HTTP(S) URLs."""

from urllib.parse import SplitResult, urlsplit


def parse_http_url(
    value: str,
    *,
    require_https: bool = False,
) -> SplitResult:
    """Parse an absolute HTTP(S) URL with a host and no userinfo."""
    candidate = value.strip()
    allowed_schemes = {"https"} if require_https else {"http", "https"}

    try:
        parsed = urlsplit(candidate)

        # Accessing these properties also detects malformed ports, IPv6
        # brackets, and other invalid netloc forms.
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        _ = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("absolute HTTP(S) URL with a valid host required") from exc

    if parsed.scheme.casefold() not in allowed_schemes or not hostname:
        raise ValueError("absolute HTTP(S) URL with a host required")

    if username is not None or password is not None:
        raise ValueError("URL userinfo is not allowed")

    return parsed


def is_safe_http_url(value: str | None) -> bool:
    """Return whether value is an absolute, credential-free HTTP(S) URL."""
    if not isinstance(value, str):
        return False

    try:
        parse_http_url(value)
    except ValueError:
        return False

    return True
