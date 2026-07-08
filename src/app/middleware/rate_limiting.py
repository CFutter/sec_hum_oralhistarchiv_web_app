"""Rate limiting configuration using slowapi.

CRITICAL: In-memory storage is per-process and NOT shared across gunicorn
workers. With N workers, each worker tracks its own counters — the effective
global rate limit becomes N × the configured value.

For production deployments with `workers > 1`, set `REDIS_ENABLED=true` so
slowapi uses Redis as a shared backend. The `validate_redis_in_production`
settings validator warns when this configuration is missing.

Other security considerations:
- When behind a reverse proxy, X-Forwarded-For must be used to get the real
  client IP. This is handled by get_client_ip with an allowlist of trusted
  upstream IPs (see utils.py and the three-way IP-trust contract documented
  in gunicorn.conf.py).
- Only trust X-Forwarded-For when the immediate peer is in the allowlist.
- In-memory storage resets on every restart, even single-worker.
"""
from fastapi import FastAPI
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware

from config import settings
from .utils import get_client_ip

# Module-level singleton: created once at import time, shared across
# all routes via direct import and via app.state.limiter (set in
# setup_rate_limiting). Settings are read once at import — test
# fixtures that override settings after import will not be reflected.
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[
        f"{settings.rate_limit_per_minute}/minute",
        f"{settings.rate_limit_per_hour}/hour",
        f"{settings.rate_limit_per_day}/day",
    ],
    storage_uri=(
        settings.redis_url.get_secret_value()
        if settings.redis_enabled else "memory://"
    ),
    enabled=settings.rate_limit_enabled,
)

def setup_rate_limiting(app: FastAPI) -> None:
    """Wire the module-level limiter into the FastAPI app."""
    if not settings.rate_limit_enabled:
        return
    app.state.limiter = limiter 
    app.add_middleware(SlowAPIMiddleware)