"""Cookie names shared by settings and middleware without import side effects."""

CSRF_COOKIE_NAME = "csrf_token"
PRE_SESSION_COOKIE_NAME = "pre_session_id"

HOST_SESSION_COOKIE_NAME = "__Host-oha_session"
HOST_CSRF_COOKIE_NAME = "__Host-oha_csrf"
HOST_PRE_SESSION_COOKIE_NAME = "__Host-oha_pre_session"


def security_cookie_names(*, hardened: bool) -> tuple[str, str]:
    """Return the fixed CSRF and anonymous-cookie names for the active policy."""
    if hardened:
        return HOST_CSRF_COOKIE_NAME, HOST_PRE_SESSION_COOKIE_NAME
    return CSRF_COOKIE_NAME, PRE_SESSION_COOKIE_NAME
