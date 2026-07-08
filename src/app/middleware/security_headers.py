"""
=============================================================================
Security Headers Configuration
=============================================================================
Using explicit configuration for audit clarity.

Note: The secure library documents SecureASGIMiddleware, but it is not
present in PyPI release 1.0.1. Using set_headers_async() as the documented
alternative. See: https://github.com/TypeError/secure
"""

from secure import Secure
from secure.headers import (
    ContentSecurityPolicy,
    StrictTransportSecurity,
    ReferrerPolicy,
    XContentTypeOptions,
    XFrameOptions,
    PermissionsPolicy, 
)

_HSTS_MAX_AGE = 31536000  # 1 year in seconds


def build_secure_headers(is_production: bool) -> Secure:
    """Build the security headers configuration.

    Configures Content-Security-Policy, X-Frame-Options, Referrer-Policy,
    X-Content-Type-Options, and Permissions-Policy for all responses.
    HSTS is added only in production.

    Note: Cache-Control: no-store for authenticated responses is handled
    separately in the security headers middleware (main.py), since it
    must not apply to static assets.
    """
    # CSP — explicit directives rather than relying on default-src fallback.
    # Future browser CSP changes may add directives that don't inherit from
    # default-src; specifying each one explicitly insulates against that.
    csp = (
        ContentSecurityPolicy()
        .default_src("'self'")
        .script_src("'self'")
        .style_src("'self'")
        .img_src("'self'", "data:")
        .font_src("'self'")
        .connect_src("'self'")
        .media_src("'self'")
        .frame_src("'none'")
        .worker_src("'self'")
        .manifest_src("'self'")
        .frame_ancestors("'none'")
        .object_src("'none'")
        .base_uri("'self'")
        .form_action("'self'")
    )

    if is_production:
        # WARNING: This sets the `preload` directive on the HSTS header, signaling
        # eligibility for the HSTS preload list. The header alone is harmless — only
        # an explicit submission at https://hstspreload.org adds the domain to
        # browsers' built-in preload lists. Serving the domain over HTTP again 
        # (development, debugging, transition), would be blocked by the 
        # preload list.
        hsts = (
            StrictTransportSecurity()
            .max_age(_HSTS_MAX_AGE)
            .include_subdomains()
            .preload()
        )
    else:
        hsts = None

    # Permissions-Policy — disable browser features the app doesn't use.
    # Defense-in-depth: even if compromised content is injected, these
    # features can't be triggered. Each directive is "no origin allowed"
    # (empty allowlist).
    permissions = (
        PermissionsPolicy()
        .accelerometer()
        .camera()
        .display_capture()
        .fullscreen()
        .geolocation()
        .gyroscope()
        .magnetometer()
        .microphone()
        .payment()
        .usb()
    )

    secure_headers = Secure(
        csp=csp,
        hsts=hsts,
        referrer=ReferrerPolicy().strict_origin_when_cross_origin(),
        xcto=XContentTypeOptions().nosniff(),
        xfo=XFrameOptions().deny(),
        permissions=permissions,
    )

    return secure_headers