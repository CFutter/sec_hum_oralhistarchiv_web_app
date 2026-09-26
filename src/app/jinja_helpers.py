"""Root-relative route/query helpers registered by template_setup."""

from typing import Any
from urllib.parse import urlencode

from fastapi import Request


def url_for_query(request: Request, **new_params: str | int | None) -> str:
    """Return the request path/query with overrides; None or empty values remove keys.

    Repeated query keys collapse to the last value. Pass page=None to reset pagination.
    """
    params = dict(request.query_params)
    for key, value in new_params.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = str(value)
    qs = urlencode(params)
    path = request.url.path
    return f"{path}?{qs}" if qs else path


def path_for(request: Request, name: str, /, **path_params: Any) -> str:
    """Return root_path plus the named route path, avoiding proxy-scheme mixed content.

    Route names/parameters must resolve through app.url_path_for; NoMatchFound propagates.
    """
    root_path = request.scope.get("root_path", "")
    return f"{root_path}{request.app.url_path_for(name, **path_params)}"
