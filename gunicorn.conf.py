"""Gunicorn settings for oralhistarchiv.service; see Deployment.md.

Importing loads application settings. A nonblank RATE_LIMIT_REDIS_URL selects
min(2 * CPU count + 1, 4) workers; otherwise one. Hardened web startup requires
the dedicated limiter.
"""

import multiprocessing

from app.bootstrap_logging import startup_failure_boundary

# Gunicorn prints config-import errors directly before it has a logger. Keep
# invalid Settings values out of that path as well as out of worker logs.
with startup_failure_boundary("settings_import"):
    from config import settings


bind = "unix:/run/oralhistarchiv/gunicorn.sock"

# Gunicorn temporarily applies its own mask while binding a Unix socket, so a
# systemd UMask alone is insufficient. A socket starts from mode 0777;
# 0777 & ~0117 = 0660, granting access only to the service user and the
# dedicated nginx proxy group configured by oralhistarchiv.service.
umask = 0o117


worker_class = "app.server_worker.SafeUvicornWorker"

# Workers = 2 * CPU cores + 1 (capped at 4 for this app's scale). Hardened web
# startup requires and probes RATE_LIMIT_REDIS_URL, so its limiter state is
# shared across every worker. General REDIS_URL is optional cache/pub-sub state
# and must not authorize a multi-worker hardened deployment. A development
# process without the dedicated limiter stays at one worker.
_has_dedicated_rate_limiter = settings.dedicated_rate_limit_storage_uri is not None
workers = min(multiprocessing.cpu_count() * 2 + 1, 4) if _has_dedicated_rate_limiter else 1

# Restart workers after this many requests (prevents memory leaks). Recycling
# cannot reset hardened-deployment rate limits because those counters live in
# Redis and ordinary Redis restarts reload the AOF described in Deployment.md.
max_requests = 1000
max_requests_jitter = 50


# Worker-silence timeout; this is not a per-request deadline.
timeout = 30

graceful_timeout = 30

keepalive = 5


# Gunicorn access log — disabled because the app's audit middleware
# already logs every request with more detail (request ID, user, duration).
accesslog = None

errorlog = "-"
loglevel = "info"


proc_name = "oralhistarchiv"


# These limits bound HTTP request-line/header parsing, not body size.
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190

# Preserve the Unix peer identity for Shibboleth admission and proxy trust checks.
# With RATE_LIMIT_TRUST_PROXY=true, the app reads X-Forwarded-For itself; nginx
# must overwrite it with $remote_addr rather than append client-supplied values.
forwarded_allow_ips = ""
