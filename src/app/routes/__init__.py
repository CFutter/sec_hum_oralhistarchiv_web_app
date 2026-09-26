"""Collect routers with centrally validated access and mutation policies.

Handlers expect initialized app.state resources and session middleware state;
SecureAPIRouter supplies route authorization/content-type/CSRF dependencies.
Unhandled service/database failures propagate to application error handling.
"""

from .auth import routers as auth_routers
from .health import routers as health_routers
from .pages import router as pages_router

application_routers = (pages_router, *health_routers, *auth_routers)

__all__ = ["application_routers"]
