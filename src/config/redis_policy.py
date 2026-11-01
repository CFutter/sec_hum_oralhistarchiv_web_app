"""Pure Redis URL and effective connection-policy validation.

Errors describe the policy violation without returning credential-bearing input.
The constructor's options and the resulting connection pool are separate checks.
"""

import ipaddress
import math
import ssl
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit

from redis.backoff import NoBackoff
from redis.connection import Connection, SSLConnection, UnixDomainSocketConnection
from redis.retry import Retry


def redis_url_policy_issues(
    value: str, *, hardened: bool = False, dedicated: bool = False
) -> list[str]:
    """Return safe Redis URL-policy errors, or [] when valid, without DNS/network I/O.

    General URLs accept redis/rediss/unix; dedicated URLs use redis+unix instead
    of unix. Reject whitespace, queries/fragments and invalid destinations.
    Hardened remote TCP requires TLS; hardened dedicated URLs require database 0
    and a named non-default ACL user/password.
    """
    issues: list[str] = []
    if not value or not value.isprintable() or any(char.isspace() for char in value):
        return ["Redis URL must be nonempty and contain no whitespace or control characters"]
    try:
        parsed = urlsplit(value)
        port = parsed.port
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
    except (ValueError, UnicodeError):
        return ["Redis URL is malformed"]
    schemes = {"redis", "rediss", "redis+unix" if dedicated else "unix"}
    if parsed.scheme not in schemes:
        issues.append("Redis URL uses an unsupported transport")
    if "?" in value or "#" in value:
        issues.append("Redis URL must not contain query parameters or a fragment")
    is_unix = parsed.scheme in {"unix", "redis+unix"}
    if is_unix:
        if (
            parsed.hostname
            or port is not None
            or not parsed.path.startswith("/")
            or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:])
        ):
            issues.append("Redis Unix socket must be an unambiguous absolute local path")
    else:
        if not parsed.hostname or port == 0:
            issues.append("Redis TCP URL requires a host and a valid port")
        if parsed.path not in {"", "/"} and (
            not parsed.path.startswith("/")
            or not parsed.path[1:].isascii()
            or not parsed.path[1:].isdigit()
        ):
            issues.append("Redis database must be a nonnegative integer path")
        if hardened and dedicated and parsed.path not in {"", "/", "/0"}:
            issues.append("Dedicated Redis must use database 0")
        if hardened and parsed.scheme == "redis" and not _is_loopback(parsed.hostname):
            issues.append("Remote Redis requires verified TLS")
    if hardened and dedicated and (not username or username == "default" or not password):
        issues.append("Dedicated Redis requires a named non-default ACL user and password")
    return issues


def _is_loopback(host: str | None) -> bool:
    """Return whether host is localhost or a literal loopback IPv4/IPv6 address."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def redis_connection_policy_issues(
    options: Mapping[str, Any], *, maximum_timeout: float
) -> list[str]:
    """Return effective connection-policy errors, or [] when valid.

    Require finite connect/read seconds in (0, maximum_timeout], disabled retries,
    reviewed connection classes, verified TLS when used and a Unix socket path.
    Inspect already-parsed options without network I/O.
    """
    issues: list[str] = []
    for name in ("socket_connect_timeout", "socket_timeout"):
        value = options.get(name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 < value <= maximum_timeout
            or not math.isfinite(value)
        ):
            issues.append(f"Effective Redis {name} exceeds its supported bound")
    retry = options.get("retry")
    if (
        not isinstance(retry, Retry)
        or retry.get_retries() != 0
        or not isinstance(retry._backoff, NoBackoff)
    ):
        issues.append("Effective Redis retries must be disabled")
    if options.get("retry_on_timeout", False) is not False or options.get("retry_on_error"):
        issues.append("Effective Redis error retries must be disabled")
    connection_class = options.get("connection_class")
    if connection_class not in {Connection, SSLConnection, UnixDomainSocketConnection}:
        issues.append("Redis connection uses an unsupported connection class")
    if isinstance(connection_class, type) and issubclass(connection_class, SSLConnection):
        if options.get("ssl_cert_reqs", "required") not in {"required", ssl.CERT_REQUIRED}:
            issues.append("Redis TLS certificate verification must be required")
        if options.get("ssl_check_hostname", True) is not True:
            issues.append("Redis TLS hostname verification must be enabled")
    elif options.get("ssl_cert_reqs") is not None or options.get("ssl_check_hostname") is not None:
        issues.append("Redis TLS options require a TLS connection")
    if (
        isinstance(connection_class, type)
        and issubclass(connection_class, UnixDomainSocketConnection)
        and not options.get("path")
    ):
        issues.append("Redis Unix connection has no socket path")
    return issues
