"""Shared security-sensitive request utilities."""

import ipaddress
import logging
import re

from fastapi import Request

from config import settings

logger = logging.getLogger(__name__)

_TRUSTED_UPSTREAM_IPS = frozenset(settings.trusted_proxy_ips)

_TOKEN_PATH_REGEX = re.compile(r"^(/(?:reset-password|verify-email|account/confirm-email))/[^/?]+")
_QUERY_SEPARATORS = re.compile(r"[&;]")
_KNOWN_QUERY_PARAMETERS = frozenset(
    {
        "q",
        "page",
        "keyword",
        "language",
        "access_level",
    }
)
_MAX_LOGGED_QUERY_COMPONENTS = 20


def _is_valid_ip(value: str) -> bool:
    """Return True if value parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Return attribution IP: trusted X-Real-IP, then first X-Forwarded-For, then peer.

    Forwarded values require RATE_LIMIT_TRUST_PROXY and a configured TCP peer or
    a scope consistent with a Unix socket. Valid IP spellings are returned as-is;
    unusable headers are logged and skipped. With no peer/fallback return "unknown".
    TRUSTED_PROXY_IPS is captured on import; this is not an authorization check.
    """
    peer = request.client.host if request.client else None
    server = request.scope.get("server")
    is_unix_socket = peer is None and (
        not server or len(server) < 2 or server[1] is None  # noqa: PLR2004
    )
    peer_is_trusted = peer in _TRUSTED_UPSTREAM_IPS or is_unix_socket

    if settings.rate_limit_trust_proxy and peer_is_trusted:
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            real_ip = real_ip.strip()
            if _is_valid_ip(real_ip):
                return real_ip
            logger.warning("Invalid X-Real-IP header — falling back to peer address")

        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if _is_valid_ip(first):
                return first
            logger.warning("Invalid first X-Forwarded-For entry — falling back to peer address")

    return peer or "unknown"


def scrub_sensitive_path(path: str) -> str:
    """Replace the first credential segment on reset/verification/email-confirmation paths."""
    return _TOKEN_PATH_REGEX.sub(r"\1/<token>", path)


def safe_request_path(request: Request) -> str:
    """Return a matched route template, otherwise scrub the three known capability paths."""
    route = request.scope.get("route")
    route_template = getattr(route, "path", None)

    if isinstance(route_template, str):
        return route_template

    return scrub_sensitive_path(request.url.path)


def scrub_sensitive_query(query_string: str) -> str:
    """Return at most 20 query components with all values hidden and overflow marked.

    Only q/page/keyword/language/access_level names survive; split on & or ;.
    """
    if not query_string:
        return ""

    components = _QUERY_SEPARATORS.split(query_string)
    output: list[str] = []

    for component in components[:_MAX_LOGGED_QUERY_COMPONENTS]:
        key, separator, _value = component.partition("=")

        if not separator:
            output.append("<parameter>")
        elif key in _KNOWN_QUERY_PARAMETERS:
            output.append(f"{key}=<present>")
        else:
            output.append("<parameter>=<redacted>")

    if len(components) > _MAX_LOGGED_QUERY_COMPONENTS:
        output.append("<truncated>")

    return "&".join(output)
