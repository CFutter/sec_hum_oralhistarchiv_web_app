"""Jinja2 template helper functions.

Provides utility functions registered as Jinja2 globals in
template_setup.py. These are callable directly from templates
without needing to pass them through route context.
"""

from urllib.parse import urlencode
from fastapi import Request

def url_for_query(request: Request, **new_params: str | None) -> str:
    """Build a URL preserving existing query parameters with selective overrides.

    Merges the current request's query parameters with new_params:
    - Existing parameters are preserved unless overridden.
    - Providing a new value for a key overwrites it.
    - Providing None or an empty string removes the key.

    Used in templates for filter and pagination links, e.g.:
        {{ url_for_query(request, keyword="migration", page=None) }}

    Callers reset pagination by passing page=None (as in the example above), 
    which drops the page parameter so the next request defaults to page 1; 
    other active filters are preserved.
    """
    params = dict(request.query_params)
    for key, value in new_params.items():
        if value:
            params[key] = value
        else:
            params.pop(key, None)
    return f"{request.url.path}?{urlencode(params)}"
