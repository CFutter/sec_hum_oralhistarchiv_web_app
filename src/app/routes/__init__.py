"""Collect routers with centrally validated access and mutation policies.

Handlers require initialized app.state resources and session middleware
state. SecureAPIRouter installs authorization, form-type and CSRF guards;
unhandled service/database failures reach application error handling.
"""

from .auth import routers as auth_routers
from .health import routers as health_routers
from .pages import router as pages_router

application_routers = (pages_router, *health_routers, *auth_routers)

__all__ = ["application_routers"]
