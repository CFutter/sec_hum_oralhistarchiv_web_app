"""Jinja2 template configuration — shared across routes and error handlers."""
from fastapi import Request 
from fastapi.templating import Jinja2Templates
 
from .url_safety import is_safe_http_url 
from .paths import TEMPLATES_DIR
from .jinja_helpers import url_for_query
from .services import can_view_full
from config import settings
from .middleware import get_csrf_token

_FLASH_UNSET = object()

def safe_url_filter(value: str) -> str:
    """Strip URLs with non-http(s) schemes. Last-line-of-defense against XSS."""
    return value.strip() if is_safe_http_url(value) else ""

def doi_url_filter(value: str) -> str:
    """Turn a DOI into a resolvable https://doi.org/ link.

    Accepts a bare DOI (10.x/...), a doi:-prefixed DOI, or an existing http(s) DOI URL: 
    bare DOIs get the doi.org resolver prefix, URLs pass through. Always yields an http(s)
    href, so it also serves as the XSS guard for the DOI field (no separate
    safe_url needed).
    """
    if not value:
        return ""
    value = value.strip()
    if value.lower().startswith("doi:"):
        value = value[4:]
    if value.startswith(("http://", "https://")):
        return value if is_safe_http_url(value) else ""
    if value.startswith("10."):
        return f"https://doi.org/{value}"
    return ""

def get_flash(request: Request) -> tuple[str, str] | None:
    """Return the flash resolved by SessionResolutionMiddleware for this request.

    The read-and-clear happens once in the middleware (where it can await the
    async consume_flash); this is a pure synchronous read of request.state so
    it's safe to call during template rendering.
    """
    return getattr(request.state, "flash", None)
    
templates = Jinja2Templates(directory=TEMPLATES_DIR)
templates.env.globals["url_for_query"] = url_for_query
templates.env.globals["can_view_full"] = can_view_full
templates.env.globals["csrf_token"] = get_csrf_token
templates.env.globals["contact_email"] = settings.contact_email
templates.env.globals["is_production"] = settings.is_production
templates.env.globals["shibboleth_enabled"] = settings.shibboleth_enabled
templates.env.filters["safe_url"] = safe_url_filter
templates.env.filters["doi_url"] = doi_url_filter
templates.env.globals["get_flash"] = get_flash