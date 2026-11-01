# Middleware

Inbound order: TrustedHost → optional CORS → audit → database-capacity handling → bounded rate admission → session resolution → security headers → CSRF cookies → route dependencies. Registration in `main.py` wraps the last-added middleware outermost. See [Request Lifecycle](../architecture/request-lifecycle.md).

## Responsibilities

| Module | Responsibility |
|---|---|
| `session` | Identity/flash resolution, recovery-session restriction, and route access dependencies |
| `audit_logging` | Request IDs and scrubbed outcome/error events |
| `database_capacity` | Retryable 503 responses for exhausted database pools |
| `rate_limiting` | Bounded admission before session lookup; fixed-window policies and mandatory shared search starts |
| `security_headers` | Header configuration applied by `main.py` and early refusals |
| `csrf`, `cookies` | Signed session/pre-session identifiers, CSRF cookies, and verification |
| `content_type` | Form-content validation for mutations |
| `validators` | Startup security checks |

The limiter's early `503` responses are returned before session resolution
and the downstream security-header middleware. The limiter applies security
headers directly to these responses and includes `Cache-Control: no-store`
and `Retry-After`.

Redis fixed-window storage additionally bounds counter cardinality and key
length. Refusing a new counter at capacity preserves existing live quotas.
`GET /search` has a shared start budget even if ordinary per-client rate
limiting is disabled; it is checked before session/database work. Search
execution then uses its dedicated pool and nonblocking PostgreSQL lock.

Staging and production web processes require enabled per-client admission in
both settings validation and startup preflight. The development-only disable
switch leaves the shared search gate active. Redis readiness validates effective
connection-pool timeout, retry and TLS settings after URL parsing; query strings
and fragments are rejected before construction. Backend recovery preserves live
quotas and keeps protected traffic refused until the backend is healthy.

`SecureAPIRouter` owns exact route authorization and mutation dependencies; see [Route Security](route-security.md).

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

## Database capacity and package exports

::: app.middleware.database_capacity

::: app.middleware
