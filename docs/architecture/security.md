# Security Layers

This page is the security tour of the application. It is organised by *layer*, from the network edge inwards, because that is the order in which a request encounters protections — and the order in which an attacker would have to defeat them. (Note that this conceptual edge-inward ordering is not identical to the literal middleware execution order; see [Request Lifecycle](request-lifecycle.md) for the exact order.)

The companion pages [Authentication & Sessions](auth.md) and [Access Control & Visibility](access-control.md) cover their respective subsystems in more depth. This page focuses on the cross-cutting controls and how they fit together.

## Layer 0 — Configuration validators

The first thing the application does on startup is validate its own configuration. If anything is dangerous, the application refuses to start.

`validate_security_settings()` checks **every configured secret** — `SECRET_KEY`, `SESSION_SECRET`, each entry of `TOTP_ENCRYPTION_KEYS`, and (when set) `HEALTH_DETAIL_TOKEN` and `SHIBBOLETH_INTERNAL_SECRET` — and enforces, per secret:

- Not one of the hardcoded template defaults.
- At least 43 characters (the length of `secrets.token_urlsafe(32)` — anything shorter physically cannot hold 256 bits), with a warning below the recommended `token_urlsafe(64)` length.
- Above a Shannon-entropy floor and a minimum count of distinct characters (rejects repeated patterns like `abababab…`).
- Not containing a blocklisted string (`password`, `admin`, `12345678`, …).

It additionally blocks (in staging/production) a non-`https://` `SWISSUBASE_OAI_PMH_URL`, rate limiting enabled in production without `RATE_LIMIT_TRUST_PROXY=true` (per-IP limits would collapse onto nginx's single IP), and credentialed CORS combined with wildcard or non-HTTPS origins.

Pydantic model validators on `Settings` add more: `validate_cors_settings` and `validate_allowed_hosts` (no `*`, no empty lists, no localhost origins outside dev); `validate_database_url` (must be a PostgreSQL URL with a database name); `_require_https_in_prod` (`PUBLIC_BASE_URL` must be a non-localhost `https://` URL outside dev); `validate_cookies_secure` and `validate_debug_only_in_dev` (`COOKIES_SECURE=true` and `FASTAPI_DEBUG=false` enforced outside dev); `require_smtp_in_prod`, `validate_smtp_settings`, `validate_smtp_tls_in_prod`, and `validate_smtp_auth_pair` (SMTP required in production, with TLS, matching user/password pairs, and no placeholder values); `require_health_token_in_prod`; `validate_redis_url_required`; a format check on `DB_STATEMENT_TIMEOUT` (rejects anything that isn't an interval literal); and `validate_shibboleth_settings`, which requires the internal secret whenever Shibboleth is enabled — **in every environment**, not just production.

The dev/production split runs on `ENV_STATE`, not the debug flag: in `dev`, blocking findings are logged as warnings so local development is not painful; in `staging` and `production` they raise and the process exits before binding any socket. This layer exists because the most common security incidents are not exotic exploits — they are deployments with default secrets, wide-open CORS, or the wrong database.

## Layer 1 — Network edge (nginx)

In production, nginx terminates TLS and forwards to Gunicorn over a Unix socket. The application itself never sees a plaintext external connection.

nginx handles:

- TLS 1.2+ with strong cipher suites
- HTTP-to-HTTPS redirect and a default-reject server block for unknown `Host` headers
- Serving `/static/` directly, with long-lived cache headers
- Optional Shibboleth SP integration at the nginx layer (shibd + FastCGI via the nginx-http-shibboleth module), injecting attribute headers (and the `X-Internal-Auth` secret) only on the callback path and stripping them everywhere else
- Setting `X-Real-IP` / `X-Forwarded-For` for client IP attribution

(Restricting `/health/detail` to internal IP ranges at the nginx layer is a recommended extra hardening on top of the application's bearer-token check — a commented snippet ships in `deploy/nginx.conf.example`; uncomment it and set your monitoring ranges if your network layout allows.)

The application is bound to a local socket and is not directly reachable from the network. The `TrustedHostMiddleware` rejects unknown `Host` headers as a further backstop.

## Layer 2 — Rate limiting

If `RATE_LIMIT_ENABLED=true`, slowapi applies three default limits per client IP:

- `RATE_LIMIT_PER_MINUTE` (default 100)
- `RATE_LIMIT_PER_HOUR` (default 1000)
- `RATE_LIMIT_PER_DAY` (default 10000)

plus tighter explicit limits on sensitive auth routes (login, register, reset, TOTP, verification). The client IP is extracted by `get_client_ip()`, which trusts `X-Real-IP` / `X-Forwarded-For` only when `RATE_LIMIT_TRUST_PROXY=true` *and* the request arrived through a trusted upstream — either the TCP peer is in `TRUSTED_PROXY_IPS`, or the connection came in over the Unix socket, which in this deployment only nginx can reach. Otherwise any client could spoof their IP.

The storage backend is in-process memory by default — meaning per-worker counters under multiple Gunicorn workers — or Redis when `REDIS_ENABLED=true`, which makes the limits global across workers. The gunicorn config therefore caps the deployment at a single worker when Redis is disabled, keeping the limits correct at the cost of throughput; a settings validator warns about that configuration in production.

## Layer 3 — CORS

CORS is **disabled by default**. The archive is a single-origin server-rendered application; no client-side JavaScript needs to call it from a different origin. With CORS disabled, the browser's same-origin policy provides strong cross-origin guarantees for free. If a deployment does enable CORS, the staging/production startup validators block unsafe configurations (wildcards, empty origin lists, localhost origins, and any credentialed configuration without concrete HTTPS origins).

## Layer 4 — CSRF

CSRF protection is an **HMAC-bound double-submit cookie**, enforced as a route-level dependency rather than global middleware.

1. The CSRF cookie middleware sets a `csrf_token` cookie on GET responses. The token is not random — it is `HMAC(SESSION_SECRET, identifier)`, where `identifier` is the session ID (or a per-visitor pre-session ID for anonymous visitors). The cookie is `HttpOnly` and `SameSite=Strict`; templates read the token server-side via `{{ csrf_token(request) }}`, so JavaScript never needs access to it.
2. Templates embed the token as a hidden field in every form.
3. POST routes declare `Depends(verify_csrf)`, which checks that the cookie and form field are both present, match (`hmac.compare_digest`), and equal the HMAC recomputed from the request's current identifier. Any failure returns 403.

Because the token is HMAC-bound to the session, a stolen cookie is useless without the matching session, and the token rotates automatically when the identifier changes (and explicitly on logout). Because verification is a route dependency, *which routes are protected is visible in the route signatures* — a new POST route missing `Depends(verify_csrf)` stands out in review. `SameSite=Strict` on both the session and CSRF cookies is the second independent layer. (The two token-consuming confirm POSTs — email verification and email change — deliberately skip `verify_csrf`; there the signed single-use token itself is the capability, and the click may come from a device with no app cookies.)

## Layer 5 — Content-Type validation

The `validate_form_content_type` dependency rejects POST requests that do not declare `application/x-www-form-urlencoded` or `multipart/form-data`, a small defense against content-type confusion. Like CSRF, it is a route-level dependency, so its application is visible per route.

## Layer 6 — Sessions

The session middleware reads the `oha_session` cookie and looks up the session in the database. The cookie contains only a random 32-byte token wrapped in `itsdangerous` for tamper detection; the stored session row keys on the SHA-256 of that token. The actual session — user ID, expiry, purpose — lives in PostgreSQL, which means:

- Logging out is real: the row is deleted, and the cookie cannot be reused even if captured.
- An admin can revoke any user's sessions immediately by deleting their rows (which deactivation and email change do automatically).
- Session expiry is enforced server-side; a tampered cookie cannot extend it.
- A new session ID is issued on every login and the prior session is revoked, eliminating session fixation.

See [Authentication & Sessions](auth.md) for the lifecycle and the `purpose` column that gates `totp_setup` sessions (enforced by the dedicated TOTP-gate middleware).

## Layer 7 — Security headers

The `secure` library builds a `Secure` instance once at startup, applied to every response by an `@app.middleware("http")` function.

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'` (plus other explicit directives) |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | restrictive defaults |
| `Strict-Transport-Security` (production only) | `max-age=31536000; includeSubDomains; preload` |

The CSP is intentionally strict. There is **no `unsafe-inline`** for either scripts or styles, so inline `<script>` blocks and inline `style="..."` attributes are rejected by the browser and templates use external CSS only. The same function adds **`Cache-Control: no-store`** to responses for authenticated requests (identified by `request.state.user` being set), preventing browsers and proxies from caching restricted-tier metadata; static assets are excluded so fonts and CSS still cache.

## Layer 8 — Application code

By the time a request reaches a route handler it has been host-checked, session-resolved, audited, rate-limited, and is about to be wrapped in security headers on the way out. Further protections live in the application code:

- **Parameterised SQL.** Every query uses `psycopg.sql.SQL`, `Identifier`, and `Placeholder` composables — no f-string SQL anywhere. The `test_schema.py` invariant test guards against column-list drift between Python and SQL. <!-- TODO(tests-rework): update this section once the new test suite lands -->
- **ILIKE wildcard escaping.** Free-text search escapes `\`, `%`, and `_` in user input before interpolating into the ILIKE pattern, so a query cannot inject a wildcard pattern.
- **Tier-based output filtering.** `filter_for_tier()` redacts sensitive fields in the service layer before a dataset reaches the template, so a buggy template cannot leak data — and the search, filter, and facet queries are tier-gated in SQL, so match/no-match behaviour cannot be used to probe redacted values either. See [Access Control & Visibility](access-control.md).
- **URL scheme validation.** Upstream URLs are validated to `http(s)` during parsing, and a `safe_url` Jinja filter is a last line of defense before any URL is rendered into an `href`.

Admin routes are gated by `require_admin`, which returns 404 (not 403) for non-admins so the admin area is not revealed.

## Layer 9 — Audit logging

Every request is logged with a unique 16-character request ID, client IP, method, scrubbed path, scrubbed query string, status code, duration, and user ID (if any). The `audit` logger is a separate channel from the application logger, but both write to stdout — there is no separate audit file. systemd-journald captures both streams and handles rotation/retention. Token segments in sensitive paths (`/reset-password/<token>`, `/verify-email/<token>`, `/account/confirm-email/<token>`) and non-allowlisted query parameters are scrubbed before logging.

Sensitive values are stripped by a redaction filter built from Pydantic field metadata: any `SecretStr` field on `Settings` (or any field marked `sensitive=True`) has its actual value replaced with a `[REDACTED:...]` marker wherever it appears, plus a static `Bearer <token>` pattern. This prevents accidental credential leakage even if a developer logs a `repr()` of an object that happens to contain a secret. One deliberate asymmetry: the **application** log additionally auto-redacts anything that looks like an email address; the **audit** channel does not apply that email pattern — audit events never carry raw addresses in the first place, using the keyed `audit_email_hash` where correlation is needed (see [Logging & Audit](../configuration/logging.md)).

Off-host audit copies are shipped by a host-level rsyslog agent over RELP/TLS (reliable, encrypted, mutually authenticated) reading from journald — see the deployment runbook.

## What this composition gives you

No single layer is novel. The point is the *composition*: an attacker has to defeat startup validators, network controls, host checks, rate limiting, session integrity, HMAC-bound CSRF, a strict CSP, parameterised SQL, **and** the per-tier output filter to extract information they should not see. Each layer is a few hundred lines of well-tested code; together they form a defense-in-depth posture appropriate for a system that will, in Phase 2, hold sensitive research data about real people.
