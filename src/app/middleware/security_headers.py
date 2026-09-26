"""Build the response security-header policy; applying it is the caller's responsibility."""

from secure import Secure
from secure.headers import (
    ContentSecurityPolicy,
    PermissionsPolicy,
    ReferrerPolicy,
    StrictTransportSecurity,
    XContentTypeOptions,
    XFrameOptions,
)

_HSTS_MAX_AGE = 31536000  # 1 year in seconds


def build_secure_headers(is_production: bool) -> Secure:
    """Return CSP, framing, MIME, referrer, and browser-permission headers.

    Production adds one-year HSTS with subdomains and preload. Cache-Control
    and action-page referrer overrides are applied separately by main.py.
    """
    # Explicit directives keep each allowed resource category reviewable.
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
        # HSTS also applies to subdomains; preload-list enrollment is external.
        hsts = StrictTransportSecurity().max_age(_HSTS_MAX_AGE).include_subdomains().preload()
    else:
        hsts = None

    # Disable unused browser capabilities with empty allowlists.
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

    return Secure(
        csp=csp,
        hsts=hsts,
        referrer=ReferrerPolicy().strict_origin_when_cross_origin(),
        xcto=XContentTypeOptions().nosniff(),
        xfo=XFrameOptions().deny(),
        permissions=permissions,
    )
