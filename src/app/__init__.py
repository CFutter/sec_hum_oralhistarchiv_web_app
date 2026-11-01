"""Digital Oral History Archive — FastAPI application package.

Import-boundary convention: consume another package through its public
facade (its __init__.py), rather than its implementation modules. Within a
package, use sibling-module imports; tests may import internals directly for
focused verification. The re-exports below define this package's intended
public symbol API. Python does not enforce this architectural convention.
"""

from importlib import import_module as _import_module
from typing import TYPE_CHECKING, Any

from .catalogue_sql import CATALOGUE_PAGE_IDS_SOURCE, CATALOGUE_SCAN_CEILING_SOURCE
from .cookie_contract import (
    HOST_CSRF_COOKIE_NAME,
    HOST_PRE_SESSION_COOKIE_NAME,
    HOST_SESSION_COOKIE_NAME,
    security_cookie_names,
)
from .environment import Environment, resolve_environment
from .field_visibility import FIELD_VISIBILITY, PUBLIC_DISCOVERY_FIELDS
from .log_text import escape_log_controls
from .source_contract import SOURCE_NAME_PATTERN

__all__ = [
    "CATALOGUE_PAGE_IDS_SOURCE",
    "CATALOGUE_SCAN_CEILING_SOURCE",
    "FIELD_VISIBILITY",
    "HOST_CSRF_COOKIE_NAME",
    "HOST_PRE_SESSION_COOKIE_NAME",
    "HOST_SESSION_COOKIE_NAME",
    "PUBLIC_DISCOVERY_FIELDS",
    "SOURCE_NAME_PATTERN",
    "Environment",
    "escape_log_controls",
    "get_client_ip",
    "is_safe_http_url",
    "normalize_email",
    "resolve_environment",
    "security_cookie_names",
    "validate_seed_credentials",
]

from .search_projection_sql import (
    SEARCH_AUDIENCES,
    SEARCH_FUNCTION_RESULTS,
    SEARCH_FUNCTION_SOURCES,
    SEARCH_STABLE_FUNCTIONS,
)

__all__ += [
    "SEARCH_AUDIENCES",
    "SEARCH_FUNCTION_RESULTS",
    "SEARCH_FUNCTION_SOURCES",
    "SEARCH_STABLE_FUNCTIONS",
]

_LAZY_EXPORTS = {
    "normalize_email": ".credentials",
    "validate_seed_credentials": ".credentials",
    "get_client_ip": ".request_utils",
    "is_safe_http_url": ".url_safety",
}


def __getattr__(name: str) -> Any:
    """Import and cache a lazy export; raise AttributeError for unknown names."""
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(_import_module(module, __name__), name)
    globals()[name] = value
    return value


if TYPE_CHECKING:
    from .credentials import normalize_email as normalize_email
    from .credentials import validate_seed_credentials as validate_seed_credentials
    from .request_utils import get_client_ip as get_client_ip
    from .url_safety import is_safe_http_url as is_safe_http_url
