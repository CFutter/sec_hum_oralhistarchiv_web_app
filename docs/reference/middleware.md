# Middleware

Inbound order: TrustedHost → optional CORS → audit → database-capacity handling → bounded rate admission → session resolution → security headers → CSRF cookies → route dependencies. Registration in `main.py` wraps the last-added middleware outermost. See [Request Lifecycle](../architecture/request-lifecycle.md).

## Responsibilities

| Module | Responsibility |
|---|---|
| `session` | Identity/flash resolution, recovery-session restriction, and route access dependencies |
| `audit_logging` | Request IDs and scrubbed outcome/error events |
| `database_capacity` | Retryable 503 responses for exhausted database pools |
| `rate_limiting` | Bounded admission before session lookup; memory or Redis policies |
| `security_headers` | Header configuration applied by `main.py` and early refusals |
| `csrf`, `cookies` | Signed session/pre-session identifiers, CSRF cookies, and verification |
| `content_type` | Form-content validation for mutations |
| `validators` | Startup security checks |

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
