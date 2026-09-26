# Security Layers

These controls protect different boundaries; their order here is conceptual. See [Request Lifecycle](request-lifecycle.md) for middleware order, [Authentication](auth.md) for account transitions, and [Access Control](access-control.md) for metadata disclosure.

## Layer 0 — Configuration validators

Settings construction and startup checks reject invalid configurations. `validate_security_settings()` checks `SECRET_KEY`, `SESSION_SECRET`, all TOTP/outbox encryption keys, optional health tokens, and configured federation secrets through the appropriate activation policy. Length, diversity, entropy, blocklist, and template-default checks reject obvious weaknesses; they do not prove randomness. Generate keys using the documented CSPRNG commands.

Ordinary startup blockers are fatal in staging/production and warnings in development; individual Settings validators may still reject development input. Hardened checks cover secure public URLs/cookies, disabled debug, trusted hosts/proxies, upstream HTTPS, SMTP policy, dedicated limiter storage, and credentialed CORS. See [Settings](../configuration/settings.md) for exact conditions.

Federation activation is strict in every environment: require an independent strong internal secret, exact HTTPS trusted issuers, a non-localhost HTTPS public origin, secure cookies, and a valid host allowlist. The callback accepts only the compiled REFEDS MFA context. Construction and final startup share that activation policy. Configuration changes require restart.

## Layer 1 — Network edge (nginx)

The reference deployment terminates external TLS at nginx and forwards locally to Gunicorn over a Unix socket. This requires the deployment and socket controls below.

nginx handles:

- TLS 1.2+ with strong cipher suites
- HTTP-to-HTTPS redirect and a default-reject server block for unknown `Host` headers
- Serving `/static/` directly, with long-lived cache headers
- Optional Shibboleth SP integration at the nginx layer (shibd + FastCGI via
  the nginx-http-shibboleth module). Phase 1 returns `404` at the callback. In
  Phase 2 the authorized location overwrites the fixed `X-OHA-Shib-*` headers
  and `X-OHA-Internal-Auth` from SP-controlled values; ordinary proxy
  locations clear both those names and the legacy Shibboleth names.
- Setting `X-Real-IP` / `X-Forwarded-For` for client IP attribution

(Restricting `/health/detail` to internal IP ranges at the nginx layer is a recommended extra hardening on top of the application's bearer-token check — a commented snippet ships in `deploy/nginx.conf.example`; uncomment it and set your monitoring ranges if your network layout allows.)

The application is bound to a local socket and is not directly reachable from
the network. That statement depends on deployment state, not merely on using a
Unix pathname: the parent directory must be `0750`, owned by
`oralhistarchiv:oralhistarchiv-proxy`; Gunicorn must create its socket as `0660`
with the same ownership; only nginx's service account may be an additional
member of `oralhistarchiv-proxy`; the scheduler must run as the distinct
`oralhistarchiv-scheduler` account with `/run/oralhistarchiv` inaccessible; and
Gunicorn must have no TCP listener. The nginx account must not be a generic UID
also used by PHP-FPM or unrelated services; inventory every live process under
it or use a dedicated worker identity/instance. Verify those facts after every
deployment as described in [Deployment](../configuration/deployment.md). The `TrustedHostMiddleware` rejects unknown `Host`
headers as a further backstop, but it is not a substitute for this filesystem
boundary.

The Shibboleth callback also requires an exact trusted absolute HTTPS issuer and the compiled
REFEDS MFA context before it touches an account. A new trusted identity is
stored only as a pending, inactive, public, non-admin, unverified row; no
session is issued until an administrator uses the dedicated exact-pair
approval action, which records actor/time, assigns the reviewed tier, bumps
`auth_revision`, and deletes every target session atomically. Because anyone
who can both reach the socket and obtain the internal secret could otherwise
forge the entire assertion, nginx-only socket permissions and secret custody
are authentication controls, not optional hardening.

## Layer 2 — Rate limiting

When enabled, fixed-window limits use keyed identities for IPv4 addresses or IPv6 /64 networks. Defaults are 100/minute, 1,000/hour, and 10,000/day per endpoint; registered decorators control endpoint-specific limits. Forwarding headers require `RATE_LIMIT_TRUST_PROXY` and a trusted TCP peer or the reviewed Unix-socket boundary. Raw addresses do not enter Redis keys.

Staging/production requires dedicated shared `RATE_LIMIT_REDIS_URL`. Development may select general Redis or memory at startup; runtime failures never switch to memory. Startup probes required backend operations. Dynamic admission fails with 503 on unavailable storage or saturated admission; static GET/HEAD and decorated exemptions bypass checks. Unknown paths/methods share one coarse bucket and skip session lookup.

Checks run in a serialized worker with at most eight active/waiting admissions and a 0.25-second admission wait by default. Redis connect/read timeouts are 0.5 seconds with no retries. A one-second evaluation budget only logs slow work; it does not terminate it. `REDIS_ENABLED` controls optional cache/pub-sub, separately from hardened limiting. Secret-key rotation changes limiter identities and requires a coordinated restart.

### Credential attempt budgets

Per-IP limits are a secondary control for credential proofs because a caller can
change source addresses. PostgreSQL holds the authoritative budgets:

- TOTP rotation start, self-service email change, admin promotion preparation
  and acceptance, and administrator recovery authorization share a counter on
  the exact full session. Every reserved submission, including a successful
  one, commits before expensive verification. The first request beyond the
  configured allowance expires only that session, leaving the account and its
  other sessions untouched. Scheduled cleanup later deletes the expired row.
- TOTP rotation confirmation has its own staged challenge counter. Exhaustion
  deletes only the pending challenge.
- Public TOTP recovery first matches an unused high-entropy recovery code
  in the same nonlocking query shape used for an unknown code. Only a match can
  commit one of the three password attempts on that exact code before Argon2
  runs. Unknown codes receive dummy Argon2 work; exhausting one code leaves the
  other codes usable. Ordinary login lockout cannot block this
  administrator-authorized recovery path.

Authenticated step-up operations honor an active account-wide login lock, but
their counters never increment or extend it. Database errors abort the
operation, so loss of the durable counter store cannot turn the controls off.

## Layer 3 — CORS

CORS is disabled by default. If enabled, hardened Settings reject empty/wildcard/localhost origins; credentialed CORS also requires concrete HTTPS origins. CORS governs browser cross-origin response access and does not replace authentication or CSRF protection.

## Layer 4 — Fail-closed route and mutation contract

Every application HTTP route is created by `SecureAPIRouter` with exactly one `RouteAccess` class: public, open during enrolment, capability, TOTP enrolment, full session, local full session, or admin. The router installs the corresponding dependency itself. Public/open/capability/enrolment policies additionally use exact method/path allowlists; `/admin` can only use the admin policy. `validate_route_security_contract()` runs after registration and at startup and rejects plain or forged routes, missing dependencies, new allowlisted-surface keys, duplicate keys, unknown mounts or Starlette routes, and WebSockets.

A public route permits a guest but calls `require_full_session` when a user is present, so a partial session cannot fall back to anonymous authority. Full-session policy requires an active `purpose='full'` session and the completed authentication policy: verified email plus enrolled TOTP for local users, or approved federated state for Shibboleth users. TOTP enrolment is an exact policy for exact `/setup-totp` routes, not a prefix exemption.

### CSRF

The double-submit token is a SHA-256 HMAC of the signed session token or anonymous pre-session identifier, using a domain-separated key derived from `SESSION_SECRET`. Cookie middleware prepares matching template state and HttpOnly, SameSite=Strict cookies for resolved form requests, including POST rerenders. DB-free/unmatched requests and responses that explicitly replace the session cookie skip passive cookie writes.

`SecureAPIRouter` installs `verify_csrf` for methods other than GET/HEAD/OPTIONS, except exact `POST /verify-email` and `POST /account/confirm-email`. Those capabilities are signed, single-use, and email-bound. Verification requires matching string cookie/form values and a valid recomputed HMAC; failures return 403. This proves token binding, not account authorization.

## Layer 5 — Content-Type validation

For every method except `GET`, `HEAD`, and `OPTIONS`, `SecureAPIRouter` also installs `validate_form_content_type`, which accepts only `application/x-www-form-urlencoded` or `multipart/form-data`. Route modules do not opt into this protection, and a future non-POST mutation receives the same defaults.

## Layer 6 — Sessions

The session middleware reads the `oha_session` cookie and looks up the session in the database. The cookie contains only a random 32-byte token wrapped in `itsdangerous` for tamper detection; the stored session row keys on the SHA-256 of that token. The actual session — user ID, expiry, purpose — lives in PostgreSQL, which means:

- Logging out is real: the row is deleted, and the cookie cannot be reused even if captured.
- An admin can revoke any user's sessions immediately by deleting their rows (which deactivation and email change do automatically).
- Session expiry is enforced server-side; a tampered cookie cannot extend it.
- A new session ID is issued on every login and the prior session is revoked, eliminating session fixation.

Shibboleth sessions have an additional live authorization check on every
lookup: federation must still be enabled, the account active and explicitly
approved, and its exact issuer still trusted. Failure deletes the presented
session. Startup also compares a persisted fingerprint over the flag, sorted
issuer set, fixed MFA context, policy version, and callback secret; a missing or
changed value revokes all federated sessions transactionally before requests
are accepted. Session issuance and approval take a shared lock and require an
exact policy-row match before any identity write, closing both concurrency
orders with reconciliation. Local sessions are outside that revocation
predicate.

See [Authentication & Sessions](auth.md) for the session lifecycle and the exact route dependencies that consume the `purpose` column. Session middleware resolves state; it does not authorize path prefixes.

## Layer 7 — Security headers

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'` (plus other explicit directives) |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin`; overridden with `no-referrer` on action-capability pages |
| `Permissions-Policy` | restrictive defaults |
| `Strict-Transport-Security` (production only) | `max-age=31536000; includeSubDomains; preload` |

The CSP is intentionally strict. There is **no `unsafe-inline`** for either scripts or styles, so inline `<script>` blocks and inline `style="..."` attributes are rejected by the browser and templates use external CSS only. The same function adds **`Cache-Control: no-store`** to responses for authenticated requests (identified by `request.state.user` being set), preventing browsers and proxies from caching restricted-tier metadata; static assets are excluded so fonts and CSS still cache. Anonymous password-reset, email-verification, and email-change confirmation pages also receive `Cache-Control: no-store` and `Referrer-Policy: no-referrer` because their URLs or bodies contain live action capabilities.

## Layer 8 — Application code

SQL binds values as parameters and uses reviewed SQL identifiers/fragments where composition is needed. Free-text search escapes backslash, `%`, and `_` for literal substring matching. `filter_for_tier()` redacts restricted metadata before query results reach templates; SQL also gates matching and facet disclosure. Resource/license URLs are validated during parsing and rendering uses the `safe_url` filter. These controls require new fields, queries, and routes to preserve their contracts.

Admin dependencies return 404 for missing/non-admin principals. Existing admins must also satisfy full-session and recovery-code requirements, which can redirect or return 403. See [Access Control](access-control.md) and [Authentication](auth.md).

## Layer 9 — Audit logging

Audited requests receive a 16-hex correlation ID, client attribution, safe path/query structure, status, elapsed time, and resolved user ID. Statuses below 400 on exact `/health` and `/static/` paths are skipped; earlier middleware rejection can also bypass request auditing. Query values are omitted. Route templates replace matched paths; unmatched paths receive only known action-token scrubbing and can retain other attacker-controlled text.

Application and audit output goes to stdout; audit stays JSON. Filters redact configured secrets of at least eight characters and recognized runtime-secret shapes; audit email-pattern matches become keyed markers. Pattern coverage is finite. Exception diagnostics omit messages/arguments but retain bounded frames and categories, with redaction applied afterward.

Host journald owns retention; the shipped rsyslog example forwards selected service units over RELP/TLS when configured. Verify actual collection and delivery. See [Logging & Audit](../configuration/logging.md).

## Operational boundary — database backups

Database backups bypass every request-time tier and presentation control. The
reference deployment therefore runs `pg_dump` under the distinct
`oralhistarchiv_backup` OS/PostgreSQL identity, not under the web or scheduler
identity. That database role has bulk read and `BYPASSRLS` solely so a recovery
archive remains complete when Source B row-level policies arrive; it has no
write privilege and must never be reused by application processes.

The systemd oneshot creates a `0700` persistent state directory, enforces
`UMask=0077`, allows only the local PostgreSQL Unix socket, and cannot read
`/etc/oralhistarchiv` or either application environment file. After checking
the configured database, role, Alembic state,
and critical tables, it streams `pg_dump` directly through `age`; no plaintext
dump is written to a filesystem. A hidden `0600` ciphertext is synced and
atomically renamed only when both pipeline members succeed, and failure cleanup
runs before any retention deletion. The corresponding private `age` identity
stays off the database host and archive store. Recipient encryption protects
confidentiality and detects modification during decryption, but does not
authenticate the producer; provenance comes from the separately authenticated,
versioned or immutable off-host transfer/store. A database/VM snapshot that
contains both data and `/etc/oralhistarchiv/common.env` does not preserve the same
separation and needs its own independently controlled encryption and access
policy.

Archive decryption and application-field decryption are separate recovery
dependencies. Historical backups can still require old
`TOTP_ENCRYPTION_KEYS` and `OUTBOX_ENCRYPTION_KEYS` after the live database has
been rotated. The deployment and key-rotation runbooks define custody,
retirement, failure-injection and isolated-restore checks; repository tests
cannot prove those host-side facts.

## Extension and deployment assumptions

New routes must use the route policy, new catalogue fields need disclosure classification, and new credentials must remain out of logs. Database backups, privileged operators, upstream metadata trust, and socket/secret custody sit outside request-time redaction. Review those boundaries using the linked runbooks; startup checks and repository tests cannot establish host configuration or upstream correctness.
