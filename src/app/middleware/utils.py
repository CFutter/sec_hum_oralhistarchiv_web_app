"""Shared utilities for middleware components."""

import ipaddress
import logging

from fastapi import Request
from config import settings

logger = logging.getLogger(__name__)

_TRUSTED_UPSTREAM_IPS = frozenset(settings.trusted_proxy_ips)


def _is_valid_ip(value: str) -> bool:
    """Return True if value parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limiting keys and audit logs.

    Forwarded headers (X-Real-IP, then X-Forwarded-For) are trusted ONLY when
    the request reached us through a trusted upstream — either:
      * the TCP peer is in _TRUSTED_UPSTREAM_IPS, or
      * the connection arrived over the Unix socket (no TCP peer), which under
        our deployment means it came from nginx (the socket is the only
        entrypoint; see gunicorn.conf.py).
    Trusting a forwarded header without that precondition would let any client
    forge their apparent IP and evade per-IP rate limits, so the precondition
    is the security boundary — do not read these headers unconditionally.

    Header values are validated as parseable IPs; malformed values fall back to
    the peer. Requires rate_limit_trust_proxy=True (the production validator
    blocks rate_limit_trust_proxy=False in prod, so all requests don't collapse
    onto nginx's single IP).

    NOTE: this is attribution/throttling input, not an authorization control.
    Never gate access on it.
    """
    peer = request.client.host if request.client else None
    server = request.scope.get("server")
    is_unix_socket = peer is None and (not server or len(server) < 2 or server[1] is None)
    peer_is_trusted = peer in _TRUSTED_UPSTREAM_IPS or is_unix_socket
    
    if settings.rate_limit_trust_proxy and peer_is_trusted:
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            real_ip = real_ip.strip()
            if _is_valid_ip(real_ip):
                return real_ip
            logger.warning("X-Real-IP not a valid IP: %r — falling back", real_ip[:50])

        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if _is_valid_ip(first):
                return first
            logger.warning("X-Forwarded-For first hop not a valid IP: %r — falling back", first[:50])

    return peer or "unknown"