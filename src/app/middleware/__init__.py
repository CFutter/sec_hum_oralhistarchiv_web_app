""" Middleware components — security headers, sessions, CSRF, rate limiting, and audit logging.

As a convention, the route Dependency ordering is 
dependencies=[Depends(validate_form_content_type), Depends(verify_csrf), ...]
so the cheapest, most general rejection comes first.
"""

from .security_headers import build_secure_headers 
from .rate_limiting import setup_rate_limiting, limiter
from .validators import validate_security_settings
from .audit_logging import setup_audit_logging
from .utils import get_client_ip

from .session import (
    setup_session_middleware,
    setup_totp_gate_middleware,
    set_session_cookie,
    clear_session_cookie,
    require_login,
    require_admin
    )

from .csrf import (
    CSRF_COOKIE_NAME,
    setup_csrf_middleware, 
    verify_csrf, 
    get_csrf_token,
    rotate_csrf_cookie
    )

from .content_type import validate_form_content_type

from .cookies import get_session_id_from_cookie

__all__ = [
    "CSRF_COOKIE_NAME",
    "build_secure_headers",
    "clear_session_cookie",
    "get_client_ip",
    "get_csrf_token",
    "get_session_id_from_cookie",
    "limiter",
    "require_admin",
    "require_login",
    "rotate_csrf_cookie",
    "set_session_cookie",
    "setup_audit_logging",
    "setup_csrf_middleware",
    "setup_rate_limiting",
    "setup_session_middleware",
    "setup_totp_gate_middleware",
    "validate_form_content_type",
    "validate_security_settings",
    "verify_csrf"
    ]