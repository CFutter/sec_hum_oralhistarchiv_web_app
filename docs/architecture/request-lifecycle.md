# Request Lifecycle

This page traces a single request end-to-end. We use a representative example: an authenticated user clicks a search result and lands on the detail page of a dataset that is restricted to the *registered* tier.

## The example request

```
GET /dataset/4711 HTTP/1.1
Host: archive.example.uzh.ch
Cookie: oha_session=eyJ...; csrf_token=qDk...
```

The user is logged in. Their session cookie holds a signed session ID. They have already enrolled their authenticator app, so they have a `purpose=full` session. The dataset they are requesting has `visibility_tier='registered'` and they have `access_tier='registered'` — so they should see the full metadata.

## Step 1 — nginx

In production, nginx terminates TLS, serves `/static/` directly, writes its own access log, and forwards the request to the gunicorn Unix socket. For development, nginx is absent and uvicorn handles the request directly.

## Step 2 — gunicorn → FastAPI

Gunicorn hands the raw ASGI scope to a uvicorn worker, which calls into the FastAPI application object exported by `src/app/main.py`. The middleware stack runs with the **last-registered middleware outermost**. The effective inbound order is: TrustedHost → Session → Audit → rate limiting → security headers → TOTP/purpose gate → CSRF cookie → route. We follow that order below.

## Step 3 — TrustedHost middleware

`TrustedHostMiddleware` is outermost. It checks the `Host` header against `ALLOWED_HOSTS` and rejects anything unexpected before any other layer runs — defense in depth alongside nginx's default-reject server block. Our `Host` is allowed, so it passes.

## Step 4 — Session middleware

`SessionResolutionMiddleware` is where authentication resolves, and it runs early so that every downstream layer (including audit logging) can read `request.state.user`. It does the following:

1. Initialise `request.state.user`, `session_purpose`, `session_id`, and the flash fields to their empty defaults.
2. Check whether the path is in `_SESSION_SKIP_PREFIXES` (`/static`, `/health`, matched exact-or-slash so `/healthiness` would not qualify). For these it skips session resolution entirely. Our path `/dataset/4711` is not in this list.
3. Read the `oha_session` cookie and verify its signature and maximum age with `itsdangerous.URLSafeTimedSerializer`. If the cookie is missing, tampered, or expired, the request proceeds as a guest (and a stale cookie is cleared on the way out).
4. With a valid session ID, call `get_session_user(pool, session_id)`, which looks up the (hashed) session row, checks `expires_at`, joins to `users`, requires `is_active`, and returns a parsed `User` together with the session purpose and a flash-present flag.
5. Set `request.state.user`, `request.state.session_purpose`, and `request.state.session_id`, and — only if a flash is pending — read-and-consume it into `request.state.flash`.

This middleware only *resolves*. The TOTP and purpose gates used to live here but have moved into their own middleware (step 8), so that the redirects they issue pass through the security-headers and audit layers.

For our example, the cookie is valid and the user resolves with `purpose=full`.

## Step 5 — Audit logging middleware

`AuditLoggingMiddleware` assigns a 16-character hex `request_id`, records the start time, and stashes the ID on `request.state` so downstream code (and exception handlers) can include it. After the response comes back, it logs a structured JSON record with the request ID, client IP, method, scrubbed path, scrubbed query string, status code, duration, and (because session ran first) the user ID. It also sets the `X-Request-ID` response header. The log goes to stdout, captured by systemd-journald in production.

## Step 6 — Rate limiting (`SlowAPIMiddleware`)

The slowapi middleware extracts the client IP using `get_client_ip()`, which honours `X-Real-IP` / `X-Forwarded-For` only when `RATE_LIMIT_TRUST_PROXY=true` *and* the request arrived through a trusted upstream — either the TCP peer is in `TRUSTED_PROXY_IPS`, or the connection came in over the Unix socket (which, in this deployment, only nginx can reach). It checks the IP's counters in its store (in-memory by default, Redis when `REDIS_ENABLED=true`) and either rejects with 429 or lets it through. Our example user is within the limits, so it passes. Because rate limiting sits inside the audit layer, even a 429 still produces an audit record.

## Step 7 — Security headers middleware

This is the bare `@app.middleware("http")` function in `main.py`. It calls the next layer first, then on the way back out applies the headers configured by `build_secure_headers()`:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'` (and several other explicit directives)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` *(production only)*
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: ...`

It then checks whether `request.state.user` is set and the path is not under `/static/`. Both are true for our example, so it adds:

- `Cache-Control: no-store`

This prevents browsers and intermediate caches from holding authenticated content. Static assets are excluded so fonts and CSS still cache normally.

## Step 8 — TOTP / purpose gate middleware

`TotpGateMiddleware` enforces two access restrictions, unless the path is one of the exempt prefixes (`/setup-totp`, `/logout`, `/verify-email`):

1. **Purpose gate.** A `purpose='totp_setup'` session is redirected to `/setup-totp` for any non-exempt path.
2. **Mandatory-enrolment gate.** A local-auth user with TOTP not yet configured is likewise redirected to `/setup-totp` — a defense-in-depth backup to the purpose gate.

The gate is registered *inside* the security-headers and audit layers precisely so that its 303 redirects pick up the standard security headers and land in the audit log. It reads the state that the (outer) session middleware has already set.

For our example, the session is `purpose=full` and the user has TOTP enabled, so both gates pass.

## Step 9 — CSRF cookie middleware

The CSRF middleware only acts on GETs. It ensures the visitor has an identifier (the session ID if logged in, otherwise a pre-session cookie) and that the `csrf_token` cookie equals `HMAC(session_secret, identifier)`. Our request already has the right cookie, so it is left alone. The middleware does **not** verify the token here — CSRF verification is a route-level dependency, only triggered on POST handlers (see [Authentication & Sessions](auth.md#csrf)).

## Step 10 — The route handler

Routing matches `GET /dataset/{dataset_id}` to `routes.pages.detail`, with `dataset_id=4711`. The handler does:

1. Read `pool` from `request.app.state.db_pool`.
2. Determine the user's effective tier via `_get_user_tier(request)` — `request.state.user.access_tier` for logged-in users, or `"public"` for guests. Our user gets `"registered"`.
3. Call `get_dataset_by_id(pool, 4711, "registered")`. The service queries `oral_history_datasets`, parses the row into a `Dataset`, and **applies the tier redaction itself** via `filter_for_tier` before returning — no caller can obtain an unredacted row. Inside, `can_view_full` compares the user's tier rank (`registered=1`) to the dataset's required rank (`registered=1`); greater-than-or-equal, so the dataset comes back unchanged. If the dataset does not exist, the handler renders a 404 error page instead.
4. Because this dataset is restricted (`visibility_tier != "public"`), emit a structured `dataset_access` audit event with the dataset ID/UUID, the dataset's visibility tier, the user's tier, and whether access was granted (re-derived via `can_view_full` — the returned dataset keeps its `visibility_tier` precisely so this audit decision can still be made).
5. Render `detail.html` with the dataset.

If the user had been a guest (tier `public`), `get_dataset_by_id` would have returned an already-redacted `Dataset` with all sensitive fields nulled out, and the template would have shown only the title and access level with an explanation of why the rest is hidden.

## Step 11 — The template

`detail.html` extends `base.html`. The base template renders the navigation header (Login replaced by the user's name and a Logout button, plus an Admin link when `user.is_admin`), the page body, and the footer. All output is auto-escaped by Jinja2, so any `<script>` in metadata is rendered as text.

## Step 12 — On the way out

The response bubbles back up through the stack: the CSRF middleware leaves the already-fresh cookie alone, the TOTP gate passes it through, security headers are applied (including `Cache-Control: no-store`), the rate limiter records the request, audit logging logs the response with its duration, and the session middleware finishes. The HTTP response goes back through gunicorn → nginx → browser.

## Where things can fail

| Stage | What can go wrong | What the user sees |
|---|---|---|
| TrustedHost | Unexpected `Host` header | Request rejected before routing |
| Session middleware | Tampered or expired cookie | Treated as guest; `request.state.user = None`, stale cookie cleared |
| Rate limit | Too many requests in a window | 429 error page |
| TOTP/purpose gate | `totp_setup` session, or local user without TOTP, on a non-exempt path | 303 redirect to `/setup-totp` |
| Route handler | Dataset ID does not exist | 404 error page |
| Route handler | Database query fails | 500 error page from `unhandled_exception_handler` |
| Tier check | User tier below dataset tier | The detail page renders with redacted fields |

The custom exception handlers in `main.py` ensure that 404, 422 (validation errors), 429, and any uncaught `Exception` produce a clean HTML error page rather than a stack trace, with structured logging for the 422, 429, and 500 cases including the request ID.
