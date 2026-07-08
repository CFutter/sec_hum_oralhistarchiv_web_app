"""Shared helpers for auth routes."""
import base64
import io
import logging
import qrcode
from qrcode.image.pil import PilImage
from typing import cast

from fastapi import Request, HTTPException
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

def generate_totp_qr(provisioning_uri: str) -> str:
    """Generate a QR code as a base64-encoded PNG data string.

    Returns a string suitable for use in an <img src="data:image/png;base64,..."> tag.
    Generated locally — no external API calls, no privacy concerns.
    """
    qr_img = cast(PilImage, qrcode.make(provisioning_uri))
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def safe_redirect_url(request: Request, fallback: str = "/") -> str:
    """Extract and validate the 'next' query parameter for post-login redirect.

    Prevents open-redirect attacks by rejecting any value that could send
    the user off-site. Only relative paths on the same host are accepted.

    Rejects:
    - Absolute URLs with a scheme        (https://evil.com)
    - Protocol-relative URLs              (//evil.com)
    - Backslash variants                  (\\\\evil.com — treated as // by some browsers)
    - URLs with embedded credentials      (/foo@evil.com)
    - Empty or whitespace-only values

    Returns the validated path, or `fallback` if the value is missing or unsafe.
    """
    url = request.query_params.get("next", "").strip()

    if not url:
        return fallback

    # Must be an absolute same-site path: starts with a single '/', and not
    # '//' or '/\' (protocol-relative — browsers normalise '\' to '/').
    if not url.startswith("/") or url.startswith(("//", "/\\")):
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    # Defense-in-depth against CRLF / null injection.
    if any(c in url for c in ("\r", "\n", "\0")):
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    # Structural backstop: reject any scheme (javascript:, https:) or host
    # (user@host) that slipped past the prefix check. This is what lets a
    # legitimate path-internal colon (/search?q=time:1990) through, instead
    # of the old blanket ':' ban.
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        logger.warning("Blocked unsafe redirect target: %r", url)
        return fallback

    return url


def require_local_auth(request: Request) -> None:
    """Reject the request if the current user isn't a local-auth account.

    Self-service profile changes (display name, email) don't apply to
    Shibboleth users — their attributes come from the IdP and are
    overwritten on the next login via the COALESCE upsert in
    create_shibboleth_user. Raises 403 for non-local users.

    Assumes require_login has already run (request.state.user is set).
    """
    user = request.state.user
    if not user or user.auth_method != "local":
        logger.warning(
            "Local-auth-only action attempted by non-local user on %s",
            request.url.path,
        )
        raise HTTPException(
            status_code=403,
            detail="This action is not available for your account type.",
        )