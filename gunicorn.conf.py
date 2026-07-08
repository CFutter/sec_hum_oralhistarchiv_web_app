"""Gunicorn configuration for production deployment.

Usage:
    gunicorn -c gunicorn.conf.py app.main:app

For this app (mostly I/O-bound with database queries), 
2-4 workers are sufficient.

"""

import multiprocessing

from config import settings

# =============================================================================
# Server socket
# =============================================================================

# Bind to a Unix socket — nginx proxies to this.
# Unix sockets avoid TCP overhead and are not accessible from the network.
bind = "unix:/run/oralhistarchiv/gunicorn.sock"

# =============================================================================
# Worker configuration
# =============================================================================

# ASGI worker class for FastAPI
worker_class = "uvicorn_worker.UvicornWorker"

if settings.redis_enabled:
    # Workers = 2 * CPU cores + 1 (capped at 4 for this app's scale)
    workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
else:
    # One worker if redis is not enabled, to retain the rate limiting.
    workers = 1

# Restart workers after this many requests (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 50

# =============================================================================
# Timeouts
# =============================================================================

# Worker timeout — kill and restart if no response within 30s.
# The OAI-PMH sync runs in a separate process (see run_scheduler.py
# and the oralhistarchiv-scheduler systemd unit), not in request
# workers, so this timeout doesn't affect sync operations.
timeout = 30

# Graceful shutdown timeout — wait up to 30s for in-flight requests
graceful_timeout = 30

# Keep-alive connections (nginx handles external keep-alive)
keepalive = 5

# =============================================================================
# Logging
# =============================================================================

# Gunicorn access log — disabled because the app's audit middleware
# already logs every request with more detail (request ID, user, duration).
accesslog = None

# Gunicorn error log — stderr for systemd journal capture
errorlog = "-"
loglevel = "info"

# =============================================================================
# Process naming
# =============================================================================

proc_name = "oralhistarchiv"

# =============================================================================
# Security
# =============================================================================

# Limit request sizes (forms only, no file uploads)
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190

# SECURITY: Explicitly disable forwarded header trust at the server level.
# The Shibboleth callback (login.py shibboleth_callback) relies on
# request.client.host being the raw TCP peer address. If Gunicorn or
# Uvicorn rewrites client addresses from X-Forwarded-For, an external
# attacker could spoof 127.0.0.1 and bypass the trusted-proxy check.
#
# Note: This only disables automatic rewriting. Application code can
# still read X-Forwarded-For explicitly via request.headers.get(),
# which is what get_client_ip() does for rate limiting.
#
# This setting must be coordinated with:
#   1. App's `trust_proxy=True` — the app reads X-Forwarded-For explicitly
#      in get_client_ip() for rate limiting, separately from Gunicorn.
#   2. nginx must set `X-Forwarded-For: $remote_addr` on proxy_pass —
#      otherwise rate limiting falls back to the nginx peer IP and
#      effectively groups all requests under one rate-limit bucket.
forwarded_allow_ips = ""