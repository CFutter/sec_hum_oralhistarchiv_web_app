# Middleware

The middleware stack is the sequence of pre- and post-processing layers that every HTTP request passes through before reaching a route handler. The order of registration in `main.py` matters: the **last** middleware added wraps the rest and runs **outermost**. The effective inbound order is `TrustedHost` → `Session` → `Audit` → rate limiting → security headers → TOTP/purpose gate → `CSRF` cookie → CORS (if enabled) → route. This is deliberate: session runs early so audit can record `user_id`; rate limiting sits inside session/audit so even 429 responses are audited; and the TOTP gate sits *inside* security headers and audit so its redirects carry the standard headers and appear in the audit log.

For the conceptual tour of what each layer protects against and why, see [Architecture → Security Layers](../architecture/security.md).

## Module map

| Module | Purpose | Style |
|---|---|---|
| `session` | Two middlewares: `SessionResolutionMiddleware` reads the session cookie and populates `request.state.user` / `session_purpose` (resolution only); `TotpGateMiddleware` enforces the TOTP-enrolment and `purpose` gates (exempting `/setup-totp`, `/logout`, `/verify-email`) | `BaseHTTPMiddleware` × 2 |
| `audit_logging` | Per-request structured log line with request ID, IP, status, duration | `BaseHTTPMiddleware` |
| `rate_limiting` | slowapi setup with per-minute / per-hour / per-day limits (memory or Redis backend) | slowapi middleware |
| `security_headers` | Builds the `Secure` header set; the bare `@app.middleware` in `main.py` applies it and adds `Cache-Control: no-store` for authenticated responses | Helper called from `main.py` |
| `csrf` | Sets/refreshes the HMAC-bound CSRF cookie on GETs; provides the `verify_csrf` dependency for POST routes | Middleware + dependency |
| `cookies` | itsdangerous signer for the session cookie, session-ID extraction, pre-session IDs, and the "current identifier" used to bind CSRF tokens | Helpers |
| `content_type` | `validate_form_content_type` dependency rejecting non-form POST bodies | Dependency |
| `validators` | `validate_security_settings()` startup check; not a runtime middleware | Startup function |
| `utils` | `get_client_ip` shared by audit logging and rate limiting | Helper |

## `app.middleware.session`

::: app.middleware.session

## `app.middleware.audit_logging`

::: app.middleware.audit_logging

## `app.middleware.rate_limiting`

::: app.middleware.rate_limiting

## `app.middleware.security_headers`

::: app.middleware.security_headers

## `app.middleware.csrf`

::: app.middleware.csrf

## `app.middleware.cookies`

::: app.middleware.cookies

## `app.middleware.content_type`

::: app.middleware.content_type

## `app.middleware.validators`

::: app.middleware.validators

## `app.middleware.utils`

::: app.middleware.utils
