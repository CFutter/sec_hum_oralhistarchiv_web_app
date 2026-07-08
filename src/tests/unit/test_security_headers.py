"""Security-header configuration values (ported from the legacy suite's
legitimate cases). Guards: silent weakening of CSP/HSTS/XFO — nothing else
fails when a directive is dropped, so the values are pinned here.
"""
from starlette.responses import Response

from app.middleware.security_headers import build_secure_headers


async def _headers_for(is_production: bool) -> dict:
    response = Response()
    secure = build_secure_headers(is_production)
    await secure.set_headers_async(response)
    return dict(response.headers)


async def test_production_sets_hsts_with_preload():
    """HSTS only makes sense over TLS → production-only, 1 year, subdomains,
    preload (the deploy docs warn about the preload-list consequence)."""
    headers = await _headers_for(is_production=True)
    hsts = headers["strict-transport-security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts


async def test_dev_has_no_hsts():
    """Local plaintext-HTTP dev must not lock browsers onto https."""
    headers = await _headers_for(is_production=False)
    assert "strict-transport-security" not in headers


async def test_csp_directives_are_strict():
    """CSP pins: self-only sources, no framing, no plugins, no inline script.

    Each directive is explicit rather than relying on default-src fallback
    (see security_headers.py) — a dropped directive silently widens the
    policy, which is why the full set is asserted."""
    headers = await _headers_for(is_production=True)
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "form-action 'self'" in csp
    assert "base-uri 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


async def test_clickjacking_and_sniffing_headers():
    headers = await _headers_for(is_production=True)
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"


async def test_permissions_policy_disables_unused_features():
    """Defense-in-depth: injected content can't invoke camera/mic/etc."""
    headers = await _headers_for(is_production=True)
    policy = headers["permissions-policy"]
    for feature in ("camera", "microphone", "geolocation", "payment", "usb"):
        assert f"{feature}=()" in policy
