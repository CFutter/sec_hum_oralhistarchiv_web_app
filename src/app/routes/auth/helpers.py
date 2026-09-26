"""Shared helpers for auth routes."""

import base64
import io
import logging
from typing import cast
from urllib.parse import urlsplit

import qrcode
from fastapi import Request
from qrcode.image.pil import PilImage

logger = logging.getLogger(__name__)


def generate_totp_qr(provisioning_uri: str) -> str:
    """Return PNG bytes as base64 text, without a data-URL prefix.

    QR generation is local and blocking; async callers should offload it.
    """
    qr_img = cast(PilImage, qrcode.make(provisioning_uri))
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def safe_redirect_url(request: Request, fallback: str = "/") -> str:
    """Return stripped next if it is a single-slash same-site path, else fallback.

    Reject protocol-relative/backslash prefixes, CR/LF/NUL, schemes, and hosts;
    log rejected nonempty values. Query/fragment text is retained. fallback is
    returned without validation and must be trusted.
    """
    url = request.query_params.get("next", "").strip()

    if not url:
        return fallback

    # Browsers can interpret a leading backslash as a host separator.
    if not url.startswith("/") or url.startswith(("//", "/\\")):
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    # Defense-in-depth against CRLF / null injection.
    if any(c in url for c in ("\r", "\n", "\0")):
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    # Parse structure so colons inside paths/query strings remain allowed.
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    return url
