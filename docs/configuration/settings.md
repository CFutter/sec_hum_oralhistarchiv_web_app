# Settings Reference

Every configurable knob in the application. Settings are loaded from environment variables (and from `.env` in `dev` mode only) by Pydantic Settings, which validates types, ranges, and a number of cross-field invariants.

The canonical schema lives in `src/config/settings.py`. The annotated `.env.example` in the repository root is the canonical *example*.

> Set ENV_STATE in the OS environment for staging/production. The dotenv gate is chosen on import; a non-dev value found only in an existing .env is rejected. OS variables override dotenv values.

## Environment

| Variable | Type | Default | Notes |
|---|---|---|---|
| `ENV_STATE` | `dev` \| `staging` \| `production` | `dev` | Drives `.env` loading, validator strictness, and dev-only auto-migration. `staging` and `production` are both "hardened" — most security validators treat them identically |
| `PUBLIC_BASE_URL` | str | **(required)** | External origin used to build emailed links (verification, password reset, and email change). Must contain only an `http://` or `https://` scheme, hostname, and optional port—credentials, paths, queries, and fragments are rejected. In staging and production it must use HTTPS and must not point to localhost or another loopback address. |
| `FASTAPI_HOST` | str | `127.0.0.1` | Bind address for the dev server |
| `FASTAPI_PORT` | int | `5000` | Bind port for the dev server |
| `FASTAPI_DEBUG` | bool | `false` | Enables `/docs`, `/redoc`, `/openapi.json`, and open `/health/detail`. Forbidden outside `dev` (a validator blocks it in staging and production) |
| `SEED_MOCK_DATA` | bool | `false` | Seed mock datasets in the dev web lifespan or the staging scheduler after role/schema preflight. Set the staging override in `scheduler.env` only. Blocked in production by a validator; `.env.example` ships it `false` |
| `PAGINATION_SIZE` | int (1–100) | `20` | Search results per page |
| `ALLOWED_HOSTS` | list[str] | **(required)** | Host headers accepted by `TrustedHostMiddleware`. A validator blocks `"*"` (accepts anything) and an empty list (rejects everything) in staging/production, and warns in dev |

`PUBLIC_BASE_URL` is an origin, not a complete URL or deployment path. The
application appends routes such as `/verify-email/...` and `/reset-password/...`
to it.

Valid examples:

- `http://127.0.0.1:5000` in development
- `https://archive.example.org`
- `https://archive.example.org:8443`

Invalid examples include `https://`, URLs containing credentials, and URLs with
a path, query, or fragment, such as `https://archive.example.org/app` or
`https://archive.example.org?tenant=one`.

## Database

| Variable | Type | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | SecretStr | required for application runtime | Development may use a password URL. In staging/production it is supplied only by the process-specific root-owned `web.env` or `scheduler.env` and uses the corresponding peer-authenticated non-owner role; it must not appear in `common.env`. |
| `DATABASE_POOL_SIZE` | int (1–50) | `5` | Per-process pool maximum; minimum is min(2, maximum) |
| `DATABASE_POOL_MAX_WAITING` | int (1–1000) | `32` | Per-process queued connection requests; overflow raises TooManyRequests, acquisition waits at most 10 seconds |
| `SCHEDULER_STATEMENT_TIMEOUT` | str | `5min` | Scheduler pool statement timeout; same syntax as DB_STATEMENT_TIMEOUT |
| `DB_STATEMENT_TIMEOUT` | str | `5s` | PostgreSQL `statement_timeout` applied to every pooled connection. Format `5s` / `500ms` / `2min`, or `0` to disable; anything else is rejected |

`MIGRATION_DATABASE_URL` is read by Alembic rather than application Settings.
In staging/production it exists only in root-owned `migration.env`, selects the
owner through the exact peer mapping, and is loaded only by the static manual
migration unit. Runtime and ad-hoc maintenance processes must never load it.

## Secrets and tokens

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SECRET_KEY` | SecretStr | (required) | Signs the itsdangerous tokens (email verification, password reset, email change) and derives audit-email and limiter-client HMAC keys. Does **not** encrypt TOTP secrets. Validated for entropy, length, blocklist, hardcoded default |
| `SESSION_SECRET` | SecretStr | (required) | Cookie signing key and CSRF HMAC key. Independent of `SECRET_KEY`. Same strength validation |
| `TOTP_ENCRYPTION_KEYS` | list[SecretStr] | **(required, min 1 entry)** | Fernet key material for TOTP secrets at rest, as a JSON list. MultiFernet semantics: the **first** key encrypts, **all** keys decrypt — which is what makes rotation possible. Every entry passes the same strength validation |
| `HEALTH_DETAIL_TOKEN` | SecretStr \| None | `None` | Bearer token outside debug; required in staging/production; rejected authorization returns 404 |
| `OUTBOX_ENCRYPTION_KEYS` | list[SecretStr] | required, nonempty | Independent JSON key ring for email bodies: first encrypts, all decrypt; retain keys needed by queued/retained mail or backups |

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

`SESSION_COOKIE_NAME` must be a valid nonempty cookie name, distinct from
`csrf_token` and `pre_session_id`. `__Secure-` and `__Host-` prefixes are not
supported. Changing the name invalidates existing browser sessions.

## Authentication

| Variable | Type | Default | Notes |
|---|---|---|---|
| `LOCAL_REGISTRATION_ENABLED` | bool | `true` | Disable to block new local registration; existing local users can still sign in |
| `TOTP_ISSUER_NAME` | str | `Oral History Archive UZH` | Label shown in authenticator apps |
| `LOGIN_FAILURE_THRESHOLD` | int (≥1) | `10` | Failed logins before an account is locked |
| `LOGIN_LOCKOUT_MINUTES` | int (≥1) | `15` | How long an account stays locked |
| `SESSION_STEP_UP_ATTEMPT_LIMIT` | int (1–100) | `5` | Credential step-up submissions allowed during one full session, shared across all sensitive step-up routes. The next submission revokes that session. |
| `TOTP_ROTATION_CONFIRMATION_ATTEMPT_LIMIT` | int (1–100) | `5` | Confirmation-code submissions allowed for one staged authenticator rotation. Exhaustion discards only that staged rotation. |
| `UNVERIFIED_REAP_AFTER_DAYS` | int (≥1) | `7` | Delete unverified local accounts older than this (scheduler job) |
| `ADMIN_SEED_EMAIL` | str \| None | `None` | First-run admin bootstrap |
| `ADMIN_SEED_PASSWORD` | SecretStr \| None | `None` | Pair with ADMIN_SEED_EMAIL; 12–200 characters, then password-policy checks during seeding; remove after bootstrap |
| `PASSWORD_WORK_CONCURRENCY` | int (1–2) | `1` | Maximum concurrent password operations per web worker; queued callers wait, so size with request and memory limits |

**Local sign-in policy** `LOCAL_REGISTRATION_ENABLED=false` closes new local sign-ups; it does not disable `/login`, deactivate existing local accounts, or revoke their sessions. There is no `LOCAL_AUTH_ENABLED` switch. This is deliberate: the initial administrator is a local account, while a newly asserted Shibboleth identity starts pending and non-admin and needs administrator approval. Disabling local login after deployment could leave no usable administrator, including if a switch were changed accidentally. A future Shibboleth-only policy needs an explicit administrator bootstrap, migration, and recovery path before local sign-in can be retired; changing the registration setting is not that transition. See [authentication architecture](../architecture/auth.md#local-sign-in-and-registration-policy).

The session step-up counter is durable, shared across the protected routes, and
lasts for the full session lifetime. Successful submissions count too; the
first submission beyond the limit expires only that session and requires a new
login. The scheduled cleanup later deletes the expired row. Lower values reduce
the online guessing allowance but can interrupt a
legitimate administrator or user who performs several sensitive actions in one
session. The TOTP-rotation limit applies only to the staged challenge and
discards that challenge when exhausted. Public authenticator recovery has a
separate fixed database contract of three password attempts per exact recovery
code; it is intentionally not controlled by either setting or by ordinary
login lockout state.

If both `ADMIN_SEED_*` are set, an `is_admin`, `email_verified` local user is created on startup *only* if no admin exists yet. The seeded account starts at the **`public` access tier** (tiers cannot be set at creation) — the admin can raise their own tier from the dashboard afterwards. The seed password must pass the strength rules; seeding refuses to promote an existing account. Subsequent starts are no-ops.

## Shibboleth (Phase 2 deployment)

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SHIBBOLETH_ENABLED` | bool | `false` | Enables the `/auth/shibboleth/callback` route |
| `SHIBBOLETH_INTERNAL_SECRET` | SecretStr \| None | `None` | Secret injected by nginx as `X-OHA-Internal-Auth` on the callback and verified in constant time. **Required whenever Shibboleth is enabled, in every environment** — startup fails without it. Leave unset in Phase 1. |
| `SHIBBOLETH_TRUSTED_ISSUERS` | list[str] | `[]` | Exact absolute HTTPS IdP entity IDs accepted by the callback. Must be non-empty when Shibboleth is enabled; HTTP, URN, relative, blank, whitespace/control-bearing, malformed-host, duplicate, wildcard, comma-bearing, and substring entries are rejected. Configure as a JSON list, for example `["https://eduid.ch/idp/shibboleth"]`. |

Enabling Shibboleth also closes development's relaxed transport defaults:
in **every** environment, `PUBLIC_BASE_URL` must be a non-localhost HTTPS URL,
`COOKIES_SECURE` must be true, and `ALLOWED_HOSTS` must be a non-empty list of
canonical DNS names or canonical, non-loopback IPv4 addresses. Settings
construction fails before the application binds if any of these conditions is
absent. The final runtime startup validator calls the
same pure activation-policy function, repeating secret independence, exact
issuer validity, origin, cookie, and host checks against the live settings
object before the callback can become reachable.

The attribute header names are fixed rather than configurable:
`X-OHA-Shib-Subject`, `X-OHA-Shib-Issuer`, `X-OHA-Shib-Mail`,
`X-OHA-Shib-Display-Name`, `X-OHA-Shib-Affiliation`,
`X-OHA-Shib-Country`, and `X-OHA-Shib-Authn-Context`. nginx must overwrite
each one from an SP-controlled value on the exact callback location and clear
them elsewhere. The callback accepts only the exact authentication context
`https://refeds.org/profile/mfa`; there is deliberately no environment setting
that can weaken this requirement.

The first accepted assertion for an unknown issuer/subject pair creates an
inactive, public, non-admin, unverified pending row with no approval metadata
and no session. An administrator must use the dedicated exact-pair approval
action to choose the tier, activate it, record approval actor/time, bump
`auth_revision`, and delete every target session before a later assertion can
log in. Generic tier/admin/reactivation actions cannot release it. Email never
links accounts, and tier/admin values never come from headers.
The web startup fingerprint covers `SHIBBOLETH_ENABLED`, the sorted exact
issuer list, fixed MFA context, code-owned policy version, and callback secret.
Changing any of them has no effect until the web process restarts; on restart,
all Shibboleth sessions are revoked transactionally and local sessions remain.
The Phase 1 nginx callback returns `404`; replace that gate only after shibd,
the FastCGI authorizer, issuer/subject mapping, REFEDS MFA, socket permissions,
and negative spoofing tests are verified. Set `SHIBBOLETH_ENABLED=true` last.

## Reverse proxy

| Variable | Type | Default | Notes |
|---|---|---|---|
| `TRUSTED_PROXY_IPS` | list[str] | `["127.0.0.1", "::1"]` | TCP peer IPs from which `X-Real-IP` / `X-Forwarded-For` are trusted for client-IP attribution. A connection over the Unix socket (no TCP peer) also counts as trusted, so production must verify the reference socket owner, group, modes, nginx-only group membership, and absence of a TCP listener |

## Redis

| Variable | Type | Default | Notes |
|---|---|---|---|
| `REDIS_ENABLED` | bool | `false` | Enables the optional general Redis for catalogue-cache invalidation; it does not select the security-counter store |
| `REDIS_URL` | SecretStr | `redis://localhost:6379/0` | Required (non-empty) when `REDIS_ENABLED=true` |

`REDIS_ENABLED` selects the optional general Redis for catalogue-cache pub/sub.
The security-counter store is separate: hardened web processes require
`RATE_LIMIT_REDIS_URL`, even when `REDIS_ENABLED=false`. Gunicorn's worker count
depends on the dedicated limiter URL, not the general Redis flag. The general
Redis may be absent without weakening shared rate limits.

## OAI-PMH sync

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SWISSUBASE_OAI_PMH_URL` | str | **(required)** | OAI-PMH endpoint (must be `https://` in staging/production). The example Kassel catalogue uses `https://demo.swissubase.ch/oai-pmh/v1/oai`; the production catalogue uses a different URL and needs its own matching institution filter. |
| `OAI_INSTITUTION_FILTER` | str | (required) | Institution name filter applied to harvested records (case-insensitive substring; must not be empty) |
| `SWISSUBASE_MAX_VISIBILITY` | `public` \| `registered` \| `vetted` | `vetted` | Visibility **ceiling** for harvested SWISSUbase records — a record can never be published more permissively than this. Code default is the most restrictive; a deployment ingesting a public catalogue sets it to `public` |
| `SYNC_INTERVAL_SECONDS` | int | `3600` | Incremental sync frequency |
| `SYNC_WRITE_TIMEOUT_SECONDS` | int (1–3600) | `120` | Complete database write-phase deadline for incremental sync and rebuilds |
| `FULL_REBUILD_INTERVAL_SECONDS` | int | `86400` | Full rebuild frequency |
| `OAI_MAX_PAGES` | int (≥1) | `500` | Safety cap on resumption-token pagination; aborts a runaway harvest |

The scheduler consumes these settings for ingestion. Both web and scheduler
load the shared configuration, so restart both after changing it. The first
incremental job requests an authoritative full rebuild when the source URL or
institution filter differs from the committed catalogue. A rebuild with zero
matching records records an error and does not mark the catalogue current:
check `sync_status.last_rebuild_error` and source counts before treating the
staging import as complete. Do not manually advance the source cursor.

## SMTP (transactional email)

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SMTP_ENABLED` | bool | `false` | False in dev writes private .eml files; required true in staging and production |
| `SMTP_HOST` | str | `smtp.example.com` | Placeholder value rejected in production |
| `SMTP_PORT` | int (1–65535) | `587` | SMTP connection port; STARTTLS, not implicit TLS |
| `SMTP_USER` | str | `""` | Optional. If empty, no SMTP AUTH is performed. Must be set together with `SMTP_PASSWORD` (both or neither) |
| `SMTP_PASSWORD` | SecretStr \| None | `None` | Set with SMTP_USER; empty string counts as supplied, not None |
| `SMTP_FROM_ADDRESS` | str | `noreply@example.com` | Placeholder value rejected in production |
| `SMTP_FROM_NAME` | str | `Oral History Archive` | |
| `SMTP_USE_TLS` | bool | `true` | STARTTLS upgrade after connect. Must stay `true` in staging/production when SMTP is enabled|
| `SMTP_CA_BUNDLE` | str \| None | `None` | PEM CA bundle for verifying an internal relay signed by a private CA. Unset = system trust store |
| `CONTACT_EMAIL` | str | `archive@example.uzh.ch` | Shown on the About page and in emails |

Sender and recipient domains use ASCII IDNA spelling on the SMTP envelope.
New local credentials and `SMTP_FROM_ADDRESS` require ASCII local parts; IDN
domains remain supported without requiring SMTPUTF8.

When `SMTP_ENABLED=false` in development, the scheduler saves complete messages
as private `.eml` files in `DEV_MAILBOX_DIR` (default `.dev-mailbox` relative to
its working directory). Run `./dev.sh` so both web and scheduler are running;
open the newest `.eml` in a mail reader, or inspect its body with
a text editor, to follow verification, reset and
email-change links. Delivery succeeds only after the file is written and
atomically published. The directory must be mode `0700`; files are `0600`.
Delete old development messages when finished; they contain live capabilities.
Application and audit logs continue to redact tokens at every log level.
Settings reject disabled SMTP outside development.

## Logging

| Variable | Type | Default | Notes |
|---|---|---|---|
| `LOG_LEVEL` | str | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL` |
| `LOG_FORMAT` | `json` \| `text` | `json` | `json` for production, `text` for development |

Application and audit logs go to stdout in both dev and production. Audit
records always use JSON so actor, target, request and change fields survive
`LOG_FORMAT=text`. systemd-journald captures them in production; the dev terminal shows them directly. Retention is configured in `/etc/systemd/journald.conf.d/oralhistarchiv.conf` — see the deployment runbook.

## Rate limiting

| Variable | Type | Default | Notes |
|---|---|---|---|
| `RATE_LIMIT_ENABLED` | bool | `true` | Deployment policy requires true; code permits false even in hardened mode |
| `RATE_LIMIT_REDIS_URL` | SecretStr | empty | Dedicated hardened-web Redis URL; dev falls back to enabled general Redis, then memory |
| `RATE_LIMIT_PER_MINUTE` | int (≥1) | `100` | Per client IP |
| `RATE_LIMIT_PER_HOUR` | int (≥1) | `1000` | Per client IP |
| `RATE_LIMIT_PER_DAY` | int (≥1) | `10000` | Per client IP |
| `RATE_LIMIT_TRUST_PROXY` | bool | `false` | Trust `X-Real-IP` / `X-Forwarded-For` from trusted upstreams. **Must be `true` in production when rate limiting is enabled** — startup is blocked otherwise, because per-IP limits behind nginx would collapse onto the proxy's IP |

Use redis://, rediss:// or redis+unix:// without query parameters. Deployment policy requires DB 0, a non-default ACL user, an independent strong
password, remote-TCP TLS and separate limiter/general Redis processes. Settings
checks credential reuse; these other requirements are operator acceptance checks. Put the limiter credential only in web.env.
Startup probes it and later failures return 503; there is no hardened memory
fallback. REDIS_ENABLED controls optional catalogue-statistics pub/sub.

## CORS

| Variable | Default | Meaning |
|---|---|---|
| `CORS_ENABLED` | false | Install CORS middleware |
| `CORS_ORIGINS` | [] | JSON origin list |
| `CORS_ALLOW_METHODS` | ["GET", "POST"] | JSON allowed-method list |
| `CORS_ALLOW_HEADERS` | ["Authorization", "Content-Type"] | JSON allowed-header list |
| `CORS_ALLOW_CREDENTIALS` | false | Permit credentialed cross-origin requests |

When enabled, wildcard/empty origins block hardened startup and warn in dev;
hardened settings also reject origins containing localhost or 127.0.0.1.
The startup security gate checks credentialed origins for concrete HTTPS URLs
outside dev. It does not validate wildcard method/header lists. These
checks do not add authorization to routes.

## Minimal local `.env`

Install the project, create a disposable local PostgreSQL database and replace
the connection URL below. Save this at the checkout root; run ./dev.sh from an
activated project environment. These public development keys must not be used
on a deployed service.

```dotenv
ENV_STATE=dev
FASTAPI_DEBUG=true
COOKIES_SECURE=false
RATE_LIMIT_ENABLED=false
PUBLIC_BASE_URL=http://127.0.0.1:5000
DATABASE_URL=postgresql://oha:password@localhost:5432/oralhistarchiv
ALLOWED_HOSTS=["127.0.0.1","localhost"]
SECRET_KEY=INSECURE-DEV-KEY-CHANGE-IN-PRODUCTION
SESSION_SECRET=INSECURE-SESSION-SECRET-CHANGE-IN-PRODUCTION
TOTP_ENCRYPTION_KEYS=["INSECURE-DEV-TOTP-KEY-CHANGE-IN-PRODUCTION"]
OUTBOX_ENCRYPTION_KEYS=["INSECURE-DEV-OUTBOX-KEY-CHANGE-IN-PRODUCTION"]
OAI_INSTITUTION_FILTER=Universität Kassel
SWISSUBASE_OAI_PMH_URL=https://demo.swissubase.ch/oai-pmh/v1/oai
```

The web process migrates in dev; the scheduler harvests and writes queued mail
to .dev-mailbox. Add ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD together if an
administrator is needed. See the full example for optional settings.

## Mailbox and outbox retention

| Variable | Default | Meaning and range |
|---|---|---|
| `DEV_MAILBOX_DIR` | .dev-mailbox | Nonempty path relative to the scheduler working directory; private .eml output when SMTP is off in dev |
| `OUTBOX_SENT_RETENTION_DAYS` | 7 | Sent-row retention, 1–3650 days |
| `OUTBOX_DEAD_RETENTION_DAYS` | 30 | Dead-row retention, 1–3650 days |
| `OUTBOX_RETENTION_BATCH_SIZE` | 1000 | Maximum deleted per status per pass, 1–5000 |
| `OUTBOX_RETENTION_INTERVAL_SECONDS` | 60 | Cleanup interval, 1–60 seconds |
| `OUTBOX_STALE_AFTER_SECONDS` | 600 | Pending/sending age warning threshold, at least 60 seconds |

Cleanup leaves pending/sending rows intact. Read health-detail JSON and scheduler
logs to detect backlog; configured throughput is a ceiling, not a delivery SLA.

# Local development only
DATABASE_URL=postgresql://oha:password@localhost:5432/oralhistarchiv
ALLOWED_HOSTS=["127.0.0.1","localhost"]

SECRET_KEY=replace-me-with-secrets-token-urlsafe-64
SESSION_SECRET=replace-me-with-secrets-token-urlsafe-64
TOTP_ENCRYPTION_KEYS=["replace-me-with-secrets-token-urlsafe-64"]

OAI_INSTITUTION_FILTER=Universität Kassel
SWISSUBASE_OAI_PMH_URL=https://demo.swissubase.ch/oai-pmh/v1/oai

ADMIN_SEED_EMAIL=admin@example.uzh.ch
ADMIN_SEED_PASSWORD=replace-me-strong-temporary-password
```

That is enough to start the web application in development (run the scheduler separately, or use `dev.sh`). The placeholder secrets trigger warnings in dev and would block startup in staging/production. Add SMTP, Redis, logging, rate limiting, and CORS settings as you need them.

`DEV_MAILBOX_DIR` selects the development mailbox directory.
`OUTBOX_RETENTION_INTERVAL_SECONDS` (default 60, range 1–60) controls retention
frequency independently of `OUTBOX_RETENTION_BATCH_SIZE`. At defaults each
status has capacity for 60,000 deletions/hour, above the sender's maximum
2,400 deliveries/hour. Choose batch size/cadence with headroom over arrivals.
