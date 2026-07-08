# Settings Reference

Every configurable knob in the application. Settings are loaded from environment variables (and from `.env` in `dev` mode only) by Pydantic Settings, which validates types, ranges, and a number of cross-field invariants.

The canonical schema lives in `src/config/settings.py`. The annotated `.env.example` in the repository root is the canonical *example*.

> **Production note.** In `staging` and `production`, `ENV_STATE` must be set as a real OS environment variable (in the systemd unit, container env, or shell profile), **not** in `.env`. Pydantic Settings reads `ENV_STATE` to decide whether to load `.env` at all, so a `.env`-only value is invisible outside dev.

## Environment

| Variable | Type | Default | Notes |
|---|---|---|---|
| `ENV_STATE` | `dev` \| `staging` \| `production` | `dev` | Drives `.env` loading, validator strictness, and dev-only auto-migration. `staging` and `production` are both "hardened" — most security validators treat them identically |
| `PUBLIC_BASE_URL` | str | **(required)** | External base URL used to build emailed links (verification, reset, email change). Must start with `http(s)://`; must be a non-localhost `https://` URL in staging/production |
| `FASTAPI_HOST` | str | `127.0.0.1` | Bind address for the dev server |
| `FASTAPI_PORT` | int | `5000` | Bind port for the dev server |
| `FASTAPI_DEBUG` | bool | `false` | Enables `/docs`, `/redoc`, `/openapi.json`, mock data seeding, and open `/health/detail`. Forbidden outside `dev` (a validator blocks it in staging and production) |
| `PAGINATION_SIZE` | int (1–100) | `20` | Search results per page |
| `ALLOWED_HOSTS` | list[str] | **(required)** | Host headers accepted by `TrustedHostMiddleware`. A validator blocks `"*"` (accepts anything) and an empty list (rejects everything) in staging/production, and warns in dev |

## Database

| Variable | Type | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | SecretStr | (required) | Must start with `postgresql://` or `postgres://` and name a database |
| `DATABASE_POOL_SIZE` | int (1–50) | `5` | Max connections in the psycopg pool (min size is 2) |
| `DB_STATEMENT_TIMEOUT` | str | `5s` | PostgreSQL `statement_timeout` applied to every pooled connection. Format `5s` / `500ms` / `2min`, or `0` to disable; anything else is rejected |

## Secrets and tokens

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SECRET_KEY` | SecretStr | (required) | Signs the itsdangerous tokens (email verification, password reset, email change) and derives the audit-email HMAC key. Does **not** encrypt TOTP secrets. Validated for entropy, length, blocklist, hardcoded default |
| `SESSION_SECRET` | SecretStr | (required) | Cookie signing key and CSRF HMAC key. Independent of `SECRET_KEY`. Same strength validation |
| `TOTP_ENCRYPTION_KEYS` | list[SecretStr] | **(required, min 1 entry)** | Fernet key material for TOTP secrets at rest, as a JSON list. MultiFernet semantics: the **first** key encrypts, **all** keys decrypt — which is what makes rotation possible. Every entry passes the same strength validation |
| `HEALTH_DETAIL_TOKEN` | SecretStr \| None | `None` | Bearer token for `/health/detail` in non-debug. Required in production (startup fails without it); the endpoint returns 404 when authorization fails |

Generate strong values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Each secret has a different blast radius when rotated. Rotating `SECRET_KEY` invalidates outstanding verification/reset/email-change links (short-lived — users request new ones) and breaks audit-hash correlation across the boundary; it does **not** affect TOTP secrets or sessions. Rotating `SESSION_SECRET` logs everyone out. Rotating `TOTP_ENCRYPTION_KEYS` requires the careful prepend → re-encrypt → retire procedure — done wrong, every enrolled authenticator becomes unrecoverable. **Follow the [Key-Rotation Runbook](../runbooks/key-rotation.md) before touching any of them.**

## Sessions and cookies

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SESSION_MAX_AGE_SECONDS` | int (≥60) | `28800` (8h) | Lifetime of a session from creation; also the signed-cookie max age |
| `SESSION_COOKIE_NAME` | str | `oha_session` | Cookie name for the signed session ID |
| `COOKIES_SECURE` | bool | `true` | `Secure` flag on the session/CSRF/pre-session cookies. May be `false` **only** for local plaintext-HTTP development; a validator enforces `true` in staging/production |

## Authentication

| Variable | Type | Default | Notes |
|---|---|---|---|
| `LOCAL_AUTH_ENABLED` | bool | `true` | Disable to block local login and registration |
| `TOTP_ISSUER_NAME` | str | `Oral History Archive UZH` | Label shown in authenticator apps |
| `LOGIN_FAILURE_THRESHOLD` | int (≥1) | `10` | Failed logins before an account is locked |
| `LOGIN_LOCKOUT_MINUTES` | int (≥1) | `15` | How long an account stays locked |
| `UNVERIFIED_REAP_AFTER_DAYS` | int (≥1) | `7` | Delete unverified local accounts older than this (scheduler job) |
| `ADMIN_SEED_EMAIL` | str \| None | `None` | First-run admin bootstrap |
| `ADMIN_SEED_PASSWORD` | SecretStr \| None | `None` | First-run admin bootstrap. Remove after first start |

If both `ADMIN_SEED_*` are set, an `is_admin`, `email_verified` local user is created on startup *only* if no admin exists yet. The seeded account starts at the **`public` access tier** (tiers cannot be set at creation) — the admin can raise their own tier from the dashboard afterwards. The seed password must pass the strength rules; seeding refuses to promote an existing account. Subsequent starts are no-ops.

## Shibboleth (Phase 2 deployment)

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SHIBBOLETH_ENABLED` | bool | `false` | Enables the `/auth/shibboleth/callback` route |
| `SHIBBOLETH_INTERNAL_SECRET` | SecretStr \| None | `None` | Secret injected by nginx as `X-Internal-Auth` on the callback and verified in constant time. **Required whenever Shibboleth is enabled, in every environment** — startup fails without it |
| `SHIBBOLETH_TRUSTED_PROXY_IP` | str | `127.0.0.1` | Currently **not consulted** by the callback route. The shipped trust model is Unix-socket-only plus the `X-Internal-Auth` secret — the route refuses any request with a TCP peer outright (see [Architecture → Auth](../architecture/auth.md)) |
| `SHIBBOLETH_HEADER_REMOTE_USER` | str | `REMOTE_USER` | Header carrying the unique user identifier |
| `SHIBBOLETH_HEADER_MAIL` | str | `mail` | |
| `SHIBBOLETH_HEADER_DISPLAY_NAME` | str | `displayName` | |
| `SHIBBOLETH_HEADER_AFFILIATION` | str | `affiliation` | |
| `SHIBBOLETH_HEADER_COUNTRY` | str | `schacHomeOrganizationCountry` | (`.env.example` overrides this to `country` — keep it consistent with what nginx actually forwards) |

The callback route is implemented; what remains for Phase 2 is the nginx SP deployment (shibd + FastCGI) and federation registration.

## Reverse proxy

| Variable | Type | Default | Notes |
|---|---|---|---|
| `TRUSTED_PROXY_IPS` | list[str] | `["127.0.0.1", "::1"]` | TCP peer IPs from which `X-Real-IP` / `X-Forwarded-For` are trusted for client-IP attribution. A connection over the Unix socket (no TCP peer) also counts as trusted, since only nginx can reach the socket |

## Redis

| Variable | Type | Default | Notes |
|---|---|---|---|
| `REDIS_ENABLED` | bool | `false` | Enables Redis as the shared backend for rate limiting and facet-cache invalidation |
| `REDIS_URL` | SecretStr | `redis://localhost:6379/0` | Required (non-empty) when `REDIS_ENABLED=true` |

When Redis is disabled in production, a startup warning notes that the app runs a **single gunicorn worker** (see `gunicorn.conf.py`) — rate limiting stays correct, but throughput is capped and cross-worker facet-cache invalidation is unavailable. Enable Redis to run multiple workers.

## OAI-PMH sync

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SWISSUBASE_OAI_PMH_URL` | str | demo URL | OAI-PMH endpoint (must be `https://` in staging/production) |
| `OAI_INSTITUTION_FILTER` | str | (required) | Institution name filter applied to harvested records (case-insensitive substring; must not be empty) |
| `SWISSUBASE_MAX_VISIBILITY` | `public` \| `registered` \| `vetted` | `vetted` | Visibility **ceiling** for harvested SWISSUbase records — a record can never be published more permissively than this. Code default is the most restrictive; a deployment ingesting a public catalogue sets it to `public` |
| `SYNC_INTERVAL_SECONDS` | int | `3600` | Incremental sync frequency |
| `FULL_REBUILD_INTERVAL_SECONDS` | int | `86400` | Full rebuild frequency |
| `OAI_MAX_PAGES` | int (≥1) | `500` | Safety cap on resumption-token pagination; aborts a runaway harvest |

These settings are consumed by the scheduler process, not the web app.

## SMTP (transactional email)

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SMTP_ENABLED` | bool | `false` | When false, emails are logged instead of sent (see below). Must be `true` in production |
| `SMTP_HOST` | str | `smtp.example.com` | Placeholder value rejected in production |
| `SMTP_PORT` | int | `587` | |
| `SMTP_USER` | str | `""` | Optional. If empty, no SMTP AUTH is performed. Must be set together with `SMTP_PASSWORD` (both or neither) |
| `SMTP_PASSWORD` | SecretStr \| None | `None` | |
| `SMTP_FROM_ADDRESS` | str | `noreply@example.com` | Placeholder value rejected in production |
| `SMTP_FROM_NAME` | str | `Oral History Archive` | |
| `SMTP_USE_TLS` | bool | `true` | STARTTLS upgrade after connect. Must stay `true` in staging/production when SMTP is enabled; the relay's certificate is verified at startup (`verify_smtp_tls`) |
| `SMTP_CA_BUNDLE` | str \| None | `None` | PEM CA bundle for verifying an internal relay signed by a private CA. Unset = system trust store |
| `CONTACT_EMAIL` | str | `archive@example.uzh.ch` | Shown on the About page and in emails |

`SMTP_ENABLED=false` is the default so development does not require an SMTP server. The full password-reset, email-verification, and email-change flows can still be tested: with SMTP disabled, `send_email` logs the recipient and subject at INFO and — in dev only — the full body (including the link) at DEBUG. Run with `LOG_LEVEL=DEBUG` and read the link from stdout / journald. **Production must set `SMTP_ENABLED=true` and configure real SMTP credentials** — a settings validator enforces this and rejects placeholder host/from values.

## Logging

| Variable | Type | Default | Notes |
|---|---|---|---|
| `LOG_LEVEL` | str | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL` |
| `LOG_FORMAT` | `json` \| `text` | `json` | `json` for production, `text` for development |

Application and audit logs go to stdout in both dev and production. systemd-journald captures them in production; the dev terminal shows them directly. Retention is configured in `/etc/systemd/journald.conf.d/oralhistarchiv.conf` — see the deployment runbook.

## Rate limiting

| Variable | Type | Default | Notes |
|---|---|---|---|
| `RATE_LIMIT_ENABLED` | bool | `true` | Master switch |
| `RATE_LIMIT_PER_MINUTE` | int (≥1) | `100` | Per client IP |
| `RATE_LIMIT_PER_HOUR` | int (≥1) | `1000` | Per client IP |
| `RATE_LIMIT_PER_DAY` | int (≥1) | `10000` | Per client IP |
| `RATE_LIMIT_TRUST_PROXY` | bool | `false` | Trust `X-Real-IP` / `X-Forwarded-For` from trusted upstreams. **Must be `true` in production when rate limiting is enabled** — startup is blocked otherwise, because per-IP limits behind nginx would collapse onto the proxy's IP |

The slowapi backend is in-process memory unless `REDIS_ENABLED=true`, in which case limits are shared across all Gunicorn workers. Without Redis the deployment runs a single worker (see the Redis section above).

## CORS

| Variable | Type | Default | Notes |
|---|---|---|---|
| `CORS_ENABLED` | bool | `false` | |
| `CORS_ORIGINS` | list[str] | `[]` | Required if `CORS_ENABLED=true` |
| `CORS_ALLOW_METHODS` | list[str] | `["GET", "POST"]` | |
| `CORS_ALLOW_HEADERS` | list[str] | `["Authorization", "Content-Type"]` | |
| `CORS_ALLOW_CREDENTIALS` | bool | `false` | With credentials on, every origin must be a concrete `https://` origin — `"*"` or localhost origins block startup even in dev-adjacent checks |

Staging/production startup is **blocked** if any of the following are true:

- `CORS_ORIGINS` contains `"*"`
- `CORS_ENABLED=true` and `CORS_ORIGINS` is empty
- `CORS_ORIGINS` contains a localhost address outside dev

In `dev`, the same conditions emit warnings rather than failing.

## Putting it together: a minimal valid `.env`

```bash
ENV_STATE=dev
FASTAPI_DEBUG=true

PUBLIC_BASE_URL=http://127.0.0.1:5000
DATABASE_URL=postgresql://oha:password@localhost:5432/oralhistarchiv
ALLOWED_HOSTS=["127.0.0.1","localhost"]

SECRET_KEY=replace-me-with-secrets-token-urlsafe-64
SESSION_SECRET=replace-me-with-secrets-token-urlsafe-64
TOTP_ENCRYPTION_KEYS=["replace-me-with-secrets-token-urlsafe-64"]

OAI_INSTITUTION_FILTER=Universität Zürich

ADMIN_SEED_EMAIL=admin@example.uzh.ch
ADMIN_SEED_PASSWORD=replace-me-strong-temporary-password
```

That is enough to start the web application in development (run the scheduler separately, or use `dev.sh`). The placeholder secrets trigger warnings in dev and would block startup in staging/production. Add SMTP, Redis, logging, rate limiting, and CORS settings as you need them.
