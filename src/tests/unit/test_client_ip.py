"""Trust-gated client IP extraction — app.middleware.utils.get_client_ip.

Forwarded headers (X-Real-IP, then X-Forwarded-For) must be honored ONLY when
the request came through a trusted upstream (TCP peer in the import-frozen
_TRUSTED_UPSTREAM_IPS, or a Unix-socket connection) AND
settings.rate_limit_trust_proxy is True. Reading them unconditionally would
let any client forge its apparent IP and evade per-IP rate limits, so the
untrusted-peer cases here pin THE security boundary of this function.

No backlog section covers this directly; behaviors are pinned straight from
the source docstring/implementation in src/app/middleware/utils.py.

Pure unit tier: requests are built from raw ASGI scopes; no app, no DB.
"""

from fastapi import Request

from app.middleware.utils import get_client_ip
from config import settings


def make_request(
    peer: str | None = "127.0.0.1",
    server: tuple | None = ("127.0.0.1", 8000),
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    """Build a starlette Request from a raw ASGI scope.

    peer=None means no TCP client (Unix-socket style); combine with
    server=None or server=(host, None) to make the scope socket-shaped.
    """
    return Request(
        {
            "type": "http",
            "client": (peer, 1234) if peer is not None else None,
            "server": server,
            "headers": headers or [],
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "scheme": "http",
        }
    )


def test_trusted_peer_with_trust_on_honors_x_real_ip(monkeypatch):
    """Happy path: trusted peer 127.0.0.1 + rate_limit_trust_proxy=True means
    X-Real-IP wins. Regression guard: losing this collapses every client onto
    nginx's IP and per-IP rate limits throttle everyone together."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(peer="127.0.0.1", headers=[(b"x-real-ip", b"9.9.9.9")])
    assert get_client_ip(request) == "9.9.9.9"


def test_x_real_ip_whitespace_is_stripped(monkeypatch):
    """X-Real-IP is stripped before validation, so a padded-but-valid value is
    still honored rather than falling back to the peer."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(peer="127.0.0.1", headers=[(b"x-real-ip", b"  9.9.9.9  ")])
    assert get_client_ip(request) == "9.9.9.9"


def test_invalid_x_real_ip_falls_through_to_first_xff_hop(monkeypatch):
    """A non-IP X-Real-IP must not be returned verbatim (it would poison rate-limit
    keys and audit logs); the function falls through to X-Forwarded-For and takes
    the FIRST hop of the comma list."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(
        peer="127.0.0.1",
        headers=[
            (b"x-real-ip", b"not-an-ip"),
            (b"x-forwarded-for", b"8.8.8.8, 1.1.1.1"),
        ],
    )
    assert get_client_ip(request) == "8.8.8.8"


def test_malformed_xff_first_hop_falls_back_to_peer(monkeypatch):
    """When both forwarded headers are garbage, the function must fall back to
    the TCP peer — never echo an unparseable header value."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(
        peer="127.0.0.1",
        headers=[
            (b"x-real-ip", b"not-an-ip"),
            (b"x-forwarded-for", b"also-garbage, 1.1.1.1"),
        ],
    )
    assert get_client_ip(request) == "127.0.0.1"


def test_untrusted_peer_ignores_forwarded_headers(monkeypatch):
    """THE security boundary: a direct (untrusted) peer 5.5.5.5 sending both
    forwarded headers gets attributed to 5.5.5.5, not the header values.
    Regression guard: honoring these headers from arbitrary peers lets any
    client spoof its IP and evade per-IP rate limiting."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(
        peer="5.5.5.5",
        headers=[
            (b"x-real-ip", b"9.9.9.9"),
            (b"x-forwarded-for", b"8.8.8.8"),
        ],
    )
    assert get_client_ip(request) == "5.5.5.5"


def test_trust_proxy_off_ignores_headers_even_from_trusted_peer():
    """Config gate: rate_limit_trust_proxy=False (the test-env default) means
    forwarded headers are ignored even when the peer IS a trusted upstream.
    Guards the settings.rate_limit_trust_proxy check being read at call time."""
    assert settings.rate_limit_trust_proxy is False  # test-env default
    request = make_request(
        peer="127.0.0.1",
        headers=[
            (b"x-real-ip", b"9.9.9.9"),
            (b"x-forwarded-for", b"8.8.8.8"),
        ],
    )
    assert get_client_ip(request) == "127.0.0.1"


def test_unix_socket_no_server_counts_as_trusted_upstream(monkeypatch):
    """Unix-socket connection (client=None, server=None) counts as a trusted
    upstream — under our deployment the socket is nginx's only entrypoint —
    so X-Real-IP is honored when trust is on."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(peer=None, server=None, headers=[(b"x-real-ip", b"9.9.9.9")])
    assert get_client_ip(request) == "9.9.9.9"


def test_unix_socket_server_port_none_counts_as_trusted_upstream(monkeypatch):
    """ASGI servers report Unix sockets as server=(path, None); that shape must
    also be recognized as the trusted socket upstream (utils.py checks
    server[1] is None)."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(
        peer=None,
        server=("/run/oha/gunicorn.sock", None),
        headers=[(b"x-real-ip", b"9.9.9.9")],
    )
    assert get_client_ip(request) == "9.9.9.9"


def test_no_client_no_server_no_headers_returns_unknown(monkeypatch):
    """Total absence of attribution inputs yields the literal 'unknown' — the
    final `peer or "unknown"` fallback — never None or an exception."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(peer=None, server=None, headers=[])
    assert get_client_ip(request) == "unknown"


def test_ipv6_x_real_ip_is_accepted(monkeypatch):
    """_is_valid_ip accepts IPv6, so an IPv6 X-Real-IP from a trusted upstream
    is returned as-is (peer '::1' also pins the second frozen trusted IP)."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    request = make_request(peer="::1", headers=[(b"x-real-ip", b"2001:db8::1")])
    assert get_client_ip(request) == "2001:db8::1"


def test_trusted_upstream_set_is_frozen_at_import(monkeypatch):
    """_TRUSTED_UPSTREAM_IPS is frozen from settings.trusted_proxy_ips at module
    import; mutating the setting afterwards must NOT widen the trust set.
    Guards against a refactor that re-reads the setting at call time and lets a
    runtime config mutation open the spoofing boundary."""
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_ips", ["5.5.5.5"])
    request = make_request(peer="5.5.5.5", headers=[(b"x-real-ip", b"9.9.9.9")])
    assert get_client_ip(request) == "5.5.5.5"
