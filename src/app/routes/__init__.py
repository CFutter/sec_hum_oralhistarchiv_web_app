"""Route module registry — re-exports page, health, and auth routers."""

from .pages import router as pages_router
from .health import router as health_router
from .auth import router as auth_router

 
__all__ = [
    "auth_router",
    "health_router",
    "pages_router"
    ]