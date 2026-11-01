"""Create shared Jinja templates, globals and filters using imported settings."""

from datetime import UTC, datetime
from typing import get_args

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.sources import AccessTier
from config import settings

from .action_token_contract import ACTION_TOKEN_MAX_CHARS
from .credentials import (
    LOCAL_EMAIL_MAX_CHARS,
    LOCAL_PASSWORD_MAX_CHARS,
    MIN_PASSWORD_LENGTH,
    TOTP_CODE_RAW_MAX_CHARS,
)
from .doi import doi_url
from .jinja_helpers import path_for, url_for_query
from .middleware import get_csrf_token
from .paths import TEMPLATES_DIR
from .services import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    can_view_field,
    can_view_full,
    field_required_tier,
    full_required_tier,
)
from .services.parsed_record import FACET_LABEL_MAX_CHARS
from .services.users import DISPLAY_NAME_MAX_LENGTH
from .url_safety import is_safe_http_url


def safe_url_filter(value: str) -> str:
    """Return the stripped absolute, credential-free HTTP(S) URL, or an empty string."""
    return value.strip() if is_safe_http_url(value) else ""


def doi_url_filter(value: str) -> str:
    """Return a canonical escaped DOI resolver URL, a safe legacy URL, or empty string."""
    return doi_url(value) if value else ""


def utc_datetime_filter(value: datetime | None) -> str:
    """Format as UTC (day month year, HH:MM UTC), or an em dash for None.

    Naive datetimes are interpreted in the host local timezone by astimezone().
    """
    if value is None:
        return "—"
    return value.astimezone(UTC).strftime("%d %B %Y, %H:%M UTC")


def get_flash(request: Request) -> tuple[str, str] | None:
    """Read the flash tuple already consumed by session middleware, or return None."""
    return getattr(request.state, "flash", None)


templates = Jinja2Templates(directory=TEMPLATES_DIR)
templates.env.globals["url_for_query"] = url_for_query
templates.env.globals["can_view_full"] = can_view_full
templates.env.globals["can_view_field"] = can_view_field
templates.env.globals["field_required_tier"] = field_required_tier
templates.env.globals["full_required_tier"] = full_required_tier
templates.env.globals["access_tiers"] = get_args(AccessTier)
templates.env.globals["csrf_token"] = get_csrf_token
templates.env.globals["site_name"] = settings.site_name
templates.env.globals["institution_name"] = settings.institution_name
templates.env.globals["about_summary"] = settings.about_summary
templates.env.globals["federated_login_label"] = settings.federated_login_label
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

templates.env.globals["local_email_max_chars"] = LOCAL_EMAIL_MAX_CHARS
templates.env.globals["local_password_max_chars"] = LOCAL_PASSWORD_MAX_CHARS
templates.env.globals["local_password_min_chars"] = MIN_PASSWORD_LENGTH
templates.env.globals["totp_code_raw_max_chars"] = TOTP_CODE_RAW_MAX_CHARS
templates.env.globals["action_token_max_chars"] = ACTION_TOKEN_MAX_CHARS
templates.env.globals["local_display_name_max_chars"] = DISPLAY_NAME_MAX_LENGTH
