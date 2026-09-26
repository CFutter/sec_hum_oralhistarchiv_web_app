# Request Lifecycle

Example: a registered user with a full session requests a dataset whose `visibility_tier` is `registered`.

## The example request

```http
GET /dataset/4711 HTTP/1.1
Host: archive.example.uzh.ch
Cookie: oha_session=<signed-session-id>
```

`oha_session` is the default configurable cookie name. The signed raw token identifies a hashed PostgreSQL session row. A full local session must also satisfy current account, verification, TOTP, and recovery-state checks.

## Step 1 — nginx

In production, nginx terminates TLS, serves `/static/` directly, writes its own access log, and forwards the request to the gunicorn Unix socket. For development, nginx is absent and uvicorn handles the request directly.

## Step 2 — gunicorn → FastAPI

Gunicorn's Uvicorn worker invokes `app.main.app`. Inbound application middleware order is TrustedHost → optional CORS → audit → database-capacity handling → rate admission → session resolution → security headers → CSRF cookies. Route dependencies run after routing.

## Step 3 — TrustedHost middleware

`TrustedHostMiddleware` is outermost. It checks the `Host` header against `ALLOWED_HOSTS` and rejects anything unexpected before any other layer runs — defense in depth alongside nginx's default-reject server block. Our `Host` is allowed, so it passes.

## Step 4 — Audit logging middleware

Audit assigns a 16-character request ID before admission and session lookup. It adds `X-Request-ID` and logs status, duration in milliseconds, scrubbed path/query, client IP, and the resolved user ID. Unhandled inner errors produce `request_error` before re-raising. Successful `/health` and `/static/` responses omit the request log; their errors remain logged.

## Step 5 — Admission

`DatabaseCapacityMiddleware` catches pool acquisition timeouts or an exhausted wait queue and returns 503 with `Retry-After: 5`.

Inside it, `BoundedRateLimitMiddleware` evaluates policies before session lookup using bounded, serialized worker capacity. An exceeded limit returns 429; unavailable storage or admission capacity returns retryable 503. Hardened environments require `RATE_LIMIT_REDIS_URL`; development may use general Redis or process-local memory. Unmatched routes are marked to skip session lookup; read-only static requests bypass rate admission.

`get_client_ip()` trusts forwarded IP headers only when enabled and received from a configured trusted peer or recognized Unix-socket connection. The socket's permissions and proxy configuration are part of that trust boundary.

## Step 6 — Session resolution

`SessionResolutionMiddleware` initializes request state, then skips lookup for marked unmatched/static requests and its exact probe/asset exceptions. Otherwise it verifies the configured cookie's signature and age and resolves the hashed database session. Invalid or expired cookies yield guest state without passive cookie deletion.

A valid lookup supplies the user, purpose, session ID, and flash-present flag. Federated sessions additionally require current approved status and issuer trust; rejected federated sessions are deleted. Pending flashes are consumed only on GET and restored if that GET redirects without a newer flash.

Recovery-purpose sessions may reach only their exact enrollment/logout method/path inventory; other requests redirect to setup before routing. Remaining authorization belongs to route dependencies.

## Step 7 — Security headers

On return from the inner application, `set_secure_headers` applies the CSP, frame/content-type/referrer protections, and disabled browser-feature policy from `build_secure_headers`. Production adds one-year HSTS with `includeSubDomains; preload`.

Paths outside `/static/` receive `Cache-Control: no-store`, including anonymous responses. Reset, verification, and email-confirmation paths also receive `Referrer-Policy: no-referrer`. Early admission refusals apply their own security headers.

## Step 8 — CSRF cookies

For GETs or requests whose session resolution completed, middleware maintains a session/pre-session identifier and its HMAC-bound CSRF cookie. It skips responses explicitly marked as unresolved probes/static traffic. Mutation verification runs in route dependencies.

## Step 9 — Exact route policy

`GET /dataset/{dataset_id}` uses the public policy: guests may browse, but a presented authenticated user must satisfy full-session checks. Setup sessions redirect to enrollment. Our registered full-session user proceeds.

`SecureAPIRouter` installs policy dependencies and mutation Content-Type/CSRF checks. Startup rejects unclassified routes and deviations from reviewed route inventories; only the two signed email-confirmation POSTs omit CSRF.

## Step 10 — The route handler

`routes.pages.detail` reads the pool and viewer tier, then calls `get_dataset_by_id`. Missing rows render 404. Existing rows are redacted in the service before return according to the viewer tier; this registered viewer receives the registered dataset in full.

Non-public datasets emit `dataset_access` with dataset identifiers, required/viewer tiers, and the full-access decision. `detail.html` then renders the returned record. A guest still sees the public discovery envelope and record existence; see [Access Control](access-control.md).

## Step 11 — The template

`detail.html` extends `base.html` for navigation and layout. Jinja2 escapes ordinary interpolated values; URL filters separately validate metadata links. Template authors must preserve these boundaries when adding fields or using `safe`.

## Step 12 — On the way out

The inner response receives cookie and privacy headers, session redirect-flash handling, and the audit request ID/event before returning through the server and proxy. Rate-limit counters were evaluated during admission, before the handler.

## Where things can fail

| Condition | Outcome |
|---|---|
| Disallowed Host | Rejected before inner middleware |
| Invalid/expired session | Guest state |
| Rate limit exceeded | 429 |
| Rate storage/admission unavailable or database pool exhausted | Retryable 503 |
| Session fails the route policy | Policy-specific redirect, 403, or cloaked 404 |
| Missing dataset | 404 |
| Viewer below dataset tier | Redacted detail page |
| Invalid request parameters | 422 |
| Unhandled handler failure | Logged 500 |

Custom handlers render application errors as HTML; admission/capacity failures can return their own responses. Invalid route inventories prevent startup.