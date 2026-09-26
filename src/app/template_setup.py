"""Jinja2 template configuration — shared across routes and error handlers."""

from datetime import UTC, datetime

from fastapi import Request
from fastapi.templating import Jinja2Templates

from config import settings

from .doi import doi_url
from .jinja_helpers import path_for, url_for_query
from .middleware import get_csrf_token
from .paths import TEMPLATES_DIR
from .services import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT, can_view_full
from .services.parsed_record import FACET_LABEL_MAX_CHARS
from .url_safety import is_safe_http_url


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
    return doi_url(value) if value else ""


def utc_datetime_filter(value: datetime | None) -> str:
    """Render a UTC timestamp for display, or an em dash when absent."""
    if value is None:
        return "—"
    return value.astimezone(UTC).strftime("%d %B %Y, %H:%M UTC")


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
templates.env.globals["local_registration_enabled"] = settings.local_registration_enabled
templates.env.filters["safe_url"] = safe_url_filter
templates.env.filters["doi_url"] = doi_url_filter
templates.env.filters["utc_datetime"] = utc_datetime_filter
templates.env.globals["get_flash"] = get_flash
templates.env.globals["path_for"] = path_for
templates.env.globals["facet_label_max_chars"] = FACET_LABEL_MAX_CHARS
templates.env.globals["required_shibboleth_authn_context"] = REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
