"""Gunicorn settings for oralhistarchiv.service; see Deployment.md.

Importing loads application settings. A nonempty RATE_LIMIT_REDIS_URL selects
min(2 * CPU count + 1, 4) workers; otherwise one. Hardened web startup requires
the dedicated limiter.
"""

import multiprocessing

from config import settings

# =============================================================================
# Server socket
# =============================================================================

# Bind to a Unix socket — nginx proxies to this.
# Unix sockets avoid TCP overhead and are not accessible from the network.
bind = "unix:/run/oralhistarchiv/gunicorn.sock"

# Gunicorn temporarily applies its own mask while binding a Unix socket, so a
# systemd UMask alone is insufficient. A socket starts from mode 0777;
# 0777 & ~0117 = 0660, granting access only to the service user and the
# dedicated nginx proxy group configured by oralhistarchiv.service.
umask = 0o117

# =============================================================================
# Worker configuration
# =============================================================================

worker_class = "uvicorn_worker.UvicornWorker"

# Workers = 2 * CPU cores + 1 (capped at 4 for this app's scale). Hardened web
# startup requires and probes RATE_LIMIT_REDIS_URL, so its limiter state is
# shared across every worker. General REDIS_URL is optional cache/pub-sub state
# and must not authorize a multi-worker hardened deployment. A development
# process without the dedicated limiter stays at one worker.
_has_dedicated_rate_limiter = bool(settings.rate_limit_redis_url.get_secret_value())
workers = min(multiprocessing.cpu_count() * 2 + 1, 4) if _has_dedicated_rate_limiter else 1

# Restart workers after this many requests (prevents memory leaks). Recycling
# cannot reset hardened-deployment rate limits because those counters live in
# Redis and ordinary Redis restarts reload the AOF described in Deployment.md.
max_requests = 1000
max_requests_jitter = 50

# =============================================================================
# Timeouts
# =============================================================================

# Worker-silence timeout; this is not a per-request deadline.
timeout = 30

graceful_timeout = 30

keepalive = 5

# =============================================================================
# Logging
# =============================================================================

# Gunicorn access log — disabled because the app's audit middleware
# already logs every request with more detail (request ID, user, duration).
accesslog = None

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
# The Shibboleth callback (login.py shibboleth_callback) treats any TCP
# peer as proof of misdeployment and refuses the request; over the Unix
# socket request.client is None. If Gunicorn/Uvicorn rewrote client
# addresses from X-Forwarded-For, a forged header could make socket
# traffic appear to have a TCP peer (breaking the callback fail-closed)
# and would poison get_client_ip()'s peer-trust decision for
# rate limiting and audit attribution. Keep forwarded_allow_ips empty.
#
# Note: This only disables automatic rewriting. Application code can
# still read X-Forwarded-For explicitly via request.headers.get(),
# which is what get_client_ip() does for rate limiting.
#
# This setting must be coordinated with:
#   1. App's `RATE_LIMIT_TRUST_PROXY=True` — the app reads X-Forwarded-For explicitly
#      in get_client_ip() for rate limiting, separately from Gunicorn.
#   2. nginx must set `X-Forwarded-For: $remote_addr` on proxy_pass —
#      otherwise rate limiting falls back to the nginx peer IP and
#      effectively groups all requests under one rate-limit bucket.
forwarded_allow_ips = ""
