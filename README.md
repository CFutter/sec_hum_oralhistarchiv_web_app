![CI](https://github.com/CFutter/sec_hum_oralhistarchiv_web_app/actions/workflows/ci.yml/badge.svg)
# Digital Oral History Archive

Search and browse harvested oral-history metadata with tier-based access.

> **Status:** Source A and local authentication are implemented. Registration safety and deployment verification remain release gates; see [Known Limitations](#known-limitations) and [roadmap.md](roadmap.md). Source B is not implemented; federation requires a separately configured Shibboleth edge.

---

## Table of Contents

- [What This Is](#what-this-is)
- [Key Features](#key-features)
- [Architecture at a Glance](#architecture-at-a-glance)
- [Technology Stack](#technology-stack)
- [Project Layout](#project-layout)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Code Quality & Security Tooling](#code-quality--security-tooling)
- [Security Model](#security-model)
- [Documentation](#documentation)
- [Known Limitations](#known-limitations)
- [Phase 2 Roadmap](#phase-2-roadmap)
- [License](#license)

---

## What This Is

The Oral History Archive is a search and browse interface for oral history research datasets. It harvests metadata from external repositories via the OAI-PMH protocol, stores it in a local PostgreSQL cache, and serves it through a server-rendered web interface.

**Administrators can make dataset visibility more restrictive.** Source policy supplies each new record's `visibility_tier`; Source A does not publish a per-record application tier, so new records use `SWISSUBASE_MAX_VISIBILITY`. An authorised operator can raise an existing record's tier directly in the database. Incremental sync and full rebuild preserve the stricter of the stored tier and the incoming source-policy tier. Metadata corrections and withdrawals remain upstream responsibilities; for an urgent removal before the source changes, follow the [emergency withdrawal runbook](docs/runbooks/emergency-dataset-withdrawal.md). See [access control](docs/architecture/access-control.md) for the administrative workflow and its limits.

Two characteristics distinguish it from a generic catalogue front-end:

1. **Tiered metadata visibility.** Every dataset carries a `visibility_tier` (`public`, `registered`, `vetted`). Users below the required tier see only a fixed set of non-sensitive fields — `title`, `access_level`, `visibility_tier`, `source`, `version`, and the identifiers `id`/`uuid` — while every other field is redacted server-side, before rendering. (`uuid` is the public upstream OAI identifier for Source A; its visibility below tier is a deliberate choice to re-evaluate per source policy for Source B.) This is enforced in the service layer (both in the SQL queries and in `filter_for_tier`), so the templates never receive the hidden fields.
2. **Security-first prototype.** The application is designed as a foundation for handling sensitive research data. Argon2 password hashing, mandatory TOTP, email verification, account lockout, server-side sessions, HMAC-bound CSRF cookies, encrypted TOTP secrets at rest, strict CSP, audit logging with sensitive-field redaction, and startup validators for misconfiguration are implemented before sensitive data flows through the system.

### Audiences

| Audience | What they see |
|---|---|
| **Public visitors** | Title and access level of all datasets; full metadata of public-tier datasets |
| **Registered-tier users** | Public and registered-tier metadata; creating a local account alone leaves its tier public |
| **Vetted users** | Full metadata of all tiers, including strictly confidential fields |
| **Administrators** | User management, **user** access-tier assignment, account deactivation (which also revokes the user's sessions), staged email changes; authorised database operators can also raise dataset visibility tiers |

---

## Key Features

### Data ingestion
- OAI-PMH harvesting from SWISSUbase with resumption-token handling and a runaway-pagination cap
- CMDI XML parsing via XXE-hardened lxml
- Institution-based filtering of records, which allows reuse for different use cases
- Incremental sync, deleted-record tombstone handling, and periodic full rebuild on independent schedules
- Per-source visibility ceiling: harvested records are clamped to `SWISSUBASE_MAX_VISIBILITY` via a `SourcePolicy` at ingest; updates and rebuilds preserve any stricter stored classification
- Background scheduler (APScheduler) running in its own dedicated process, not inside the web workers

### Data access
- Trigram-indexed substring search across titles, descriptions, authors, and keywords — tier-aware, so datasets above the user's tier expose only the visible field set (title, access level, tier, source, version, id/uuid)
- Faceted filtering by keyword, language, and access level (keyword and language filters are tier-gated so they cannot probe redacted metadata)
- In-process cache for two global statistics (dataset total and last full rebuild). Redis pub/sub invalidates it across workers after sync; without Redis the one-hour TTL is the fallback. Tier-sensitive facets and metadata counts are queried live.
- Pagination with configurable page size
- Per-tier metadata redaction in the service layer

### Authentication & accounts
- Local accounts with Argon2id password hashing (rehash-on-login when parameters change)
- Mandatory email verification before an account can be used; unverified accounts reaped after a configurable period, 7 days by default
- Mandatory TOTP enrollment for local users (limited `totp_setup` sessions until enrollment completes), with per-code replay protection
- Account lockout after a configurable number of failed logins, with an email notice on lockout
- Password reset via signed, single-use tokens delivered by email and stored as hashes on the user row
- Self-service display-name change, email change (confirmed via link to the new address, notice to the old one), and authenticator rotation (requires the current code)
- Enumeration-safe registration: duplicate sign-ups render the same page and notify the existing address by email instead
- TOTP secrets encrypted at rest with Fernet; keys derived from `TOTP_ENCRYPTION_KEYS` via HKDF (MultiFernet — the first key encrypts, all keys decrypt, enabling rotation)
- Common-password blocklist (SecLists 10k) plus contextual checks and a 12-character minimum
- Shibboleth callback implemented for reverse-proxy federated login (SP deployment is Phase 2)
- Admin dashboard for user access-tier changes, deactivation (revokes sessions), admin promotion, and staged email changes

`LOCAL_REGISTRATION_ENABLED` controls new sign-ups, not existing local login. Keeping local administrator sign-in available during federation rollout is deliberate; see [authentication policy](docs/architecture/auth.md#local-sign-in-and-registration-policy) 

### Security middleware
- Server-side sessions (DB-backed, signed cookie holds only the random ID; `SameSite=Strict`)
- Fail-closed HTTP route policy: every application route is declared through `SecureAPIRouter` with one immutable access class, and startup refuses unclassified or duplicate routes, unreviewed mounts, and WebSocket routes
- HMAC-bound double-submit CSRF and form Content-Type validation are installed automatically on every mutation method; only the two exact token-capability POSTs reviewed in `route_security.py` omit CSRF
- Strict Content Security Policy (no `unsafe-inline`)
- HSTS in production with preload
- `Cache-Control: no-store` on every dynamic response
- Pre-session rate admission via slowapi (configurable per minute / hour /
  day). Hardened deployments require dedicated Redis counters shared across
  web workers and fail closed on storage errors; in-memory counters are
  development-only
- Audit logging on every request, with structured JSON output

### Operations
- The application auto-migrates only in dev. The supplied migration creates a new schema; no upgrade path from earlier prototype schemas is included. In staging and production,
  migrations are an explicit reviewed release operation performed by the
  manual `oralhistarchiv-migrate.service` while web and scheduler are stopped.
  Runtime services use separate peer-authenticated non-owner roles and refuse
  startup unless both the Alembic/schema contract and the exact database-role
  contract pass.
- Startup invariant checks: dataclass/column-list sync, redaction-field classification, 
  and a live-database drift check
- Bounded connection pooling via psycopg_pool, with per-process
  `application_name`, statement timeout, and a finite waiter queue that fails
  promptly under saturation
- Logs to stdout, captured by systemd-journald in production (rotation/retention handled by journald)
- Optional off-host audit shipping via a host-level rsyslog agent (RELP/TLS)
- Public liveness endpoint and token-protected detail health endpoint
- DevContainer with PostgreSQL for reproducible development 
  (`.devcontainer/` — Dockerfile, devcontainer.json docker-compose.yaml, setup.sh)
- Gunicorn + two systemd units (web and scheduler) for production
- Tests cover unit, HTTP-client and real-service integration tiers. Get the current collected count with `pytest --collect-only -q`; parametrization makes source-function counts different.
---

## Architecture at a Glance

nginx terminates HTTPS and proxies to web workers over a Unix socket. Workers
render Jinja pages, query PostgreSQL, enqueue mail and use dedicated limiter
Redis in hardened deployments. The separate scheduler harvests SWISSUbase,
delivers outbox mail and runs cleanup jobs. Optional general Redis invalidates
catalogue statistics across processes. See docs/architecture/ for the contracts.

---

## Technology Stack

## Technology Stack

Python 3.11+, FastAPI, Jinja2, psycopg/PostgreSQL, Alembic, APScheduler and Redis.
Production uses Gunicorn/Uvicorn behind nginx. Dependencies and pinned versions
are in pyproject.toml and uv.lock; the reference deployment uses PostgreSQL 16.

---

## Project Layout

| Path | Purpose |
|---|---|
| src/app/routes/ | HTTP handlers and access-policy declarations |
| src/app/services/ | Authentication, datasets, sync, outbox and persistence |
| src/app/middleware/ | Admission, sessions, CSRF, audit and security checks |
| src/app/templates/, src/app/static/ | Server-rendered UI and assets |
| src/config/ | Environment settings and logging |
| src/alembic/ | Schema migration and revision template |
| src/tests/ | Unit, client and integration tests |
| run.py, run_scheduler.py, dev.sh | Development web, standalone scheduler and combined launcher |
| oralhistarchiv*.service, deploy/ | Reference deployment units, policies and helpers |
| scripts/ | Release, verification and maintenance tools |
| docs/, mkdocs.yaml | Documentation sources and site configuration |

Deployment.md is the installation/runbook reference; roadmap.md lists pending
work and test_plan.md lists acceptance requirements.

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- PostgreSQL 15+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Option A — DevContainer

A DevContainer (Python 3.11 + PostgreSQL, via VS Code's Dev Containers extension) ships in `.devcontainer/`. Open the repo in the container at `/workspaces`; setup installs the locked environment and creates `.env` if absent, pointing `DATABASE_URL` at the Compose service `db`. Existing `.env` files are preserved: set their database host to `db` yourself. Review `.env`, then run `uv run bash dev.sh`.

### Option B — Manual setup (recommended)

Run from the uploaded checkout (or clone your project's actual repository URL).
These commands assume a local Linux PostgreSQL server with postgres peer access:

```bash
uv sync --locked --extra dev --extra doc --python 3.11
source .venv/bin/activate

# Create this OS user's PostgreSQL role once; skip if it already exists.
sudo -u postgres createuser --createdb "$(id -un)"
createdb oralhistarchiv
cp .env.example .env
```

Set DATABASE_URL="postgresql:///oralhistarchiv" in .env for local peer access;
for a different host, use that server's working PostgreSQL URL. Confirm the
source URL/institution pair and change or remove both ADMIN_SEED_* values
before starting. The example's signing/encryption keys are public dev values.

```bash
bash dev.sh
```

Both launcher and web lifespan run the dev migration; the launcher completes
it before starting the scheduler. The release builder requires a Git checkout
and CI provenance; the uploaded ZIP alone is not a production release.

On first start the web application:

1. Configures logging and (dev only) warns about unconsumed `.env` keys
2. Validates security settings (refuses to start with weak secrets in staging/production) and, if SMTP is enabled with TLS, verifies the relay's certificate
3. Runs Alembic migrations to head **in dev only**. Staging/production never
   migrate during runtime startup.
4. Opens the database pool and validates the expected migration/schema contract
   and the process-specific non-owner database-role contract.
5. Validates the dataset/user schema invariants, the redaction-field classification, and the live database columns
6. Seeds mock restricted datasets in dev if `SEED_MOCK_DATA=true` (off by default). In staging, the scheduler seeds after its database preflight; set the flag only in `scheduler.env`. Production rejects the flag.
7. Seeds the admin account if `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` are set and no admin exists yet


The web process does **not** start the background scheduler. Run `run_scheduler.py` as a second process (or use `./dev.sh`, which launches both). The scheduler independently calls the same `validate_security_settings()` gate before it creates or opens its PostgreSQL pool, then validates the runtime schema before constructing APScheduler. It does not rely on the web unit starting successfully or on systemd `After=` ordering. The scheduler runs an incremental sync immediately on start, then on the configured interval; the first full rebuild is staggered five minutes after start.

---

## Configuration

All configuration is loaded from environment variables. In development,
pydantic-settings also reads a local `.env`. Outside dev both runtime units
load root-owned `/etc/oralhistarchiv/common.env`; web additionally loads
`web.env` and the optional Phase-2 `shibboleth.env`, while scheduler loads
`scheduler.env`. `DATABASE_URL` is forbidden in `common.env`: each runtime URL
uses its peer-authenticated non-owner role. The manual migration unit loads only
`migration.env` and uses the owner-only `MIGRATION_DATABASE_URL`. OS environment
variables always take precedence. See `Deployment.md` §§3, 6, 7, and 17.

A complete and annotated example lives in `.env.example`. The most important settings:

| Group | Variable | Purpose |
|---|---|---|
| **Environment** | `ENV_STATE` | `dev` / `staging` / `production` |
| | `PUBLIC_BASE_URL` | External base URL used in emailed links (required; must be non-localhost `https://` in staging/production) |
| | `FASTAPI_DEBUG` | Enables `/docs`, `/redoc`, mock seeding, open `/health/detail` (forbidden outside dev) |
| | `ALLOWED_HOSTS` | Host headers accepted by `TrustedHostMiddleware` (required) |
| **Database** | `DATABASE_URL` | Runtime PostgreSQL URL. Development may use a password URL; staging/production receive a Unix-socket peer URL only from `web.env` or `scheduler.env`. Never place it in `common.env`, and never use it for migrations. |
| | `DATABASE_POOL_SIZE` | Max connections (1–50) |
| | `DATABASE_POOL_MAX_WAITING` | Finite per-process pool waiter queue (default 32); saturation fails promptly with a retryable 503 |
| | `DB_STATEMENT_TIMEOUT` | Per-connection statement timeout (default `5s`) |
| **Secrets** | `SECRET_KEY` | Signs email-verification / password-reset / email-change tokens and derives separate audit-email and pseudonymous limiter-client HMAC keys. Does **not** encrypt TOTP secrets |
| | `SESSION_SECRET` | Session cookie signing + CSRF HMAC key (separate from `SECRET_KEY`) |
| | `TOTP_ENCRYPTION_KEYS` | JSON list of Fernet key material for TOTP secrets at rest — first key encrypts, all keys decrypt (rotation) |
| | `OUTBOX_ENCRYPTION_KEYS` | JSON list of Fernet key material for outbox secrets at rest — first key encrypts, all keys decrypt (rotation) |
| | `HEALTH_DETAIL_TOKEN` | Bearer token for `/health/detail` (required outside development: staging and production) |
| **Sessions** | `SESSION_MAX_AGE_SECONDS` | Default 28800 (8 hours) |
| | `SESSION_COOKIE_NAME` | Default `oha_session` |
| | `COOKIES_SECURE` | Secure flag on cookies — `false` only for local plaintext-HTTP dev |
| **Auth** | `LOCAL_REGISTRATION_ENABLED` | Enable new local registrations; existing local users can still sign in |
| | `TOTP_ISSUER_NAME` | Label shown in authenticator apps |
| | `LOGIN_FAILURE_THRESHOLD` / `LOGIN_LOCKOUT_MINUTES` | Account lockout policy |
| | `UNVERIFIED_REAP_AFTER_DAYS` | Reap unverified accounts after N days |
| | `SHIBBOLETH_ENABLED` / `SHIBBOLETH_INTERNAL_SECRET` | Trust reverse-proxy auth headers on the callback (secret required whenever enabled) |
| | `ADMIN_SEED_EMAIL` / `ADMIN_SEED_PASSWORD` | First-run admin bootstrap |
| **Reverse proxy** | `TRUSTED_PROXY_IPS` | Peer IPs trusted for client-IP attribution |
| **Redis** | `RATE_LIMIT_REDIS_URL` | Dedicated, authenticated security-counter Redis URL; required and functionally probed by hardened web startup, and permitted only in `web.env` |
| | `REDIS_ENABLED` / `REDIS_URL` | General Redis for catalogue-statistics invalidation; dev may reuse it for limiting |
| **OAI sync** | `SWISSUBASE_OAI_PMH_URL` | Endpoint URL |
| | `OAI_INSTITUTION_FILTER` | Required institution name |
| | `SWISSUBASE_MAX_VISIBILITY` | Visibility ceiling applied to harvested records at ingest |
| | `SYNC_INTERVAL_SECONDS` / `FULL_REBUILD_INTERVAL_SECONDS` | Job intervals |
| | `SYNC_WRITE_TIMEOUT_SECONDS` | Complete harvest write-phase deadline (default 120 seconds) |
| | `OAI_MAX_PAGES` | Resumption-token pagination cap |
| **SMTP** | `SMTP_ENABLED` | Required in staging/production; false in dev writes private `.eml` files |
| | `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | SMTP credentials |
| | `SMTP_FROM_ADDRESS` / `SMTP_FROM_NAME` / `CONTACT_EMAIL` | Sender + contact identity |
| | `SMTP_CA_BUNDLE` | PEM CA bundle for a relay signed by a private CA |
| **Logging** | `LOG_LEVEL` / `LOG_FORMAT` | Application verbosity and `json`/`text` output; audit events always use JSON |
| **Rate limit** | `RATE_LIMIT_ENABLED` | Master switch |
| | `RATE_LIMIT_PER_MINUTE` / `_PER_HOUR` / `_PER_DAY` | Fixed-window per-client limits, independent of account tier |
| | `RATE_LIMIT_TRUST_PROXY` | Trust `X-Real-IP` / `X-Forwarded-For` (must be `true` in production behind nginx) |
| **CORS** | `CORS_ENABLED` / `CORS_ORIGINS` / `CORS_ALLOW_METHODS` / `CORS_ALLOW_HEADERS` / `CORS_ALLOW_CREDENTIALS` | Disabled by default |

> ⚠️ **Generate secrets with**
> ```bash
> python -c "import secrets; print(secrets.token_urlsafe(64))"
> ```
> Never commit `.env` files. Outside dev, `ENV_STATE` must be a real OS environment variable — the production systemd units provide it (and the rest of the config) via `EnvironmentFile=`; the app refuses to start if a non-dev `ENV_STATE` is seen only from a `.env` file.

### Secrets & key rotation

Signing, session, TOTP, outbox, health, federation and limiter credentials have distinct purposes and rotation effects.

| Secret | Protects | Rotating it… |
|---|---|---|
| `SECRET_KEY` | Audit-email and pseudonymous limiter-client HMAC keys; signs email-verification, password-reset, email-change tokens | Invalidates outstanding verification/reset/change links, breaks audit-hash correlation, and grants each client one fresh limiter allowance. Rotate only with a non-overlapping web maintenance restart; mixed-key workers multiply quotas. **Does not affect TOTP secrets or sessions.** |
| `SESSION_SECRET` | Session-cookie signature + CSRF HMAC | Logs out all users and invalidates outstanding CSRF tokens; users log in again. **Does not affect TOTP secrets.** |
| `TOTP_ENCRYPTION_KEYS` | TOTP secrets at rest (MultiFernet) | See the safe procedure below. Done wrong, **every enrolled authenticator becomes unrecoverable.** |

Follow [key rotation](docs/runbooks/key-rotation.md) for each credential. TOTP rotation requires re-encryption and primary-key verification; outbox rotation requires retaining old keys until all affected retained messages and backups are handled. The TOTP scripts do not rotate outbox bodies.

### Startup validators

Both the web lifespan and the standalone scheduler call `validate_security_settings()` before opening their PostgreSQL pools or performing application network work. Each process therefore fails on its own;
a failed web startup cannot leave an insecure scheduler running. The function checks `SECRET_KEY`, `SESSION_SECRET`, every `TOTP_ENCRYPTION_KEYS` and `OUTBOX_ENCRYPTION_KEYS` entry, and — when set — `HEALTH_DETAIL_TOKEN` and `SHIBBOLETH_INTERNAL_SECRET`. In staging and production it blocks startup if:

- Any of those secrets is a hardcoded template default, on the blocklist, below the minimum length (43 characters ≙ 256 bits), or below the minimum Shannon entropy
- `SWISSUBASE_OAI_PMH_URL` is not `https://`
- Rate limiting is enabled in production without `RATE_LIMIT_TRUST_PROXY=true` (per-IP limits would collapse onto nginx's IP)
- CORS credentials are combined with wildcard or non-HTTPS origins

Pydantic model validators add more: CORS and `ALLOWED_HOSTS` misconfiguration is blocked in staging/production (wildcards, empty lists, localhost origins); `DATABASE_URL` must be a PostgreSQL URL; `PUBLIC_BASE_URL` must be a non-localhost `https://` URL in staging/production; `COOKIES_SECURE` and `FASTAPI_DEBUG=false` are enforced outside dev; SMTP is required in staging and production (with STARTTLS and paired authentication settings; host/sender placeholders are rejected in production); `HEALTH_DETAIL_TOKEN` is required outside development (staging and production); and `SHIBBOLETH_INTERNAL_SECRET` is required whenever Shibboleth is enabled, in every environment. In dev, the aggregate startup security check downgrades many findings to warnings; Settings validation still rejects invalid values, and enabled federation retains its strict checks.

---

## Running the Application

### Development

```bash
./dev.sh            # web server + scheduler
# or, separately:
python run.py
python run_scheduler.py
```

`dev.sh` requires Bash 4.3+. It supervises both processes, propagates the first exit status, and waits for both children on exit or interruption. Shutdown can take up to the scheduler's 300-second drain plus cleanup.

The web app starts on `http://127.0.0.1:5000`. With `FASTAPI_DEBUG=true`:

- `/docs` (Swagger UI) and `/redoc` are available
- `/health/detail` is open without a token

(Weak-secret findings being warnings instead of startup blockers is tied to `ENV_STATE=dev`, not to the debug flag.)

With the default `SMTP_ENABLED=false`, the scheduler writes email to
`.dev-mailbox/` (`DEV_MAILBOX_DIR`). Open the newest `.eml` file in a mail
reader to complete registration, password reset or an email change. Run both
processes with `./dev.sh`; the web process only queues mail. Logs redact links
at every level. The mailbox is private and should be cleared after testing.

### Production

The three application units are at the repository root; backup units are under `deploy/`. 
The migration unit has no `[Install]` section and must never be
enabled at boot. See `Deployment.md` for the reviewed maintenance, backup,
migration, grant-reapplication, runtime-preflight, smoke-test, and reopen
sequence. Gunicorn and scheduler remain separate long-running services.

```bash
/opt/oralhistarchiv/.venv/bin/python -I -m gunicorn \
  -c /opt/oralhistarchiv/gunicorn.conf.py app.main:app
```

This is the installed interpreter command used by the web unit, whose `flock`
wrapper holds the shared deployment lock. Start production through systemd,
with the scheduler as its own service; see Deployment.md for provisioning and
the manual migration sequence.

### Health checks

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | Public; exempt from application limiting | Handler returns 200 with {"status":"alive"}; nginx admission and outer middleware can reject requests; no dependency check |
| `GET /health/detail` | Bearer token (production) / open (debug) | Database connectivity and synchronization status. Handler JSON returns `healthy`, `degraded`, or `unhealthy`; its 503 means database unreachable. The non-exempt route may instead receive the generic pre-routing limiter 503 during a limiter outage/capacity incident. Sync errors, missing or stale harvests, and missing or stale full rebuilds return HTTP 200 with `"status": "degraded"`; monitoring must inspect content type/body as well as status. |

---

## Testing

The suite has three tiers:

```bash
# Unit + client tiers; use a disposable Redis instance for the shared fixture
pytest -m "not integration"

# Full suite, including the real-PostgreSQL integration tier.
# Start disposable PostgreSQL and Redis first:
docker compose up -d db redis
REQUIRE_DB=1 REQUIRE_REDIS=1 pytest

# With coverage (branch), as CI runs it
pytest --cov=src/app --cov=src/config --cov-branch

# A single tier or file
pytest src/tests/unit/
pytest src/tests/client/test_csrf.py
```

Unit/client tests replace database access, but the shared fixture configures Redis limiter counters and can reset that backend; use only disposable test services. The integration tier (`src/tests/integration/`) needs a real PostgreSQL — its `DATABASE_URL` defaults to the `docker-compose.yml` service (`docker compose up -d db`). **`REQUIRE_DB=1` turns a missing database from a silent skip into a hard failure** (pytest exits 0 on an all-skipped tier, so CI sets this to prove the integration tier actually ran). A Redis-backed behavior tier (`test_redis_tier.py`) is gated the same way with `REQUIRE_REDIS=1` (`docker compose up -d redis`).

Coverage spans: dataset parsing and search, OAI-PMH protocol and CMDI parsing, sync operations, the full auth flow (login, register, email verification and resend, TOTP enrollment and rotation, password reset, email change, admin actions, account lockout), session lifecycle, CSRF token generation and validation, all middleware, security headers, structured logging and redaction, settings validation, scheduler job registration and lifecycle events, the Redis client and catalogue-statistics pub/sub, the email service in disabled mode, the schema column-list invariant, and visibility tier filtering.

---

## Code Quality & Security Tooling

| Tool | Command | What it catches |
|---|---|---|
| `ruff` | `ruff check src/` | PEP 8, type hint hygiene, common bugs |
| `bandit` | `bandit -r src/ --exclude src/tests/` | OWASP / CWE security smells |
| `pip-audit` | `pip-audit` | Known CVEs in pinned dependencies |
| `mypy` | `mypy src/app src/config run.py run_scheduler.py` | Static type errors (pydantic plugin enabled) |
| `pytest --cov` | `pytest --cov=src --cov-report=html` | Coverage gate |

CI runs on pull requests, main-branch pushes and manual dispatch; use its exact commands in .github/workflows/ci.yml.

---

## Security Model

A short tour. The MkDocs **Architecture → Security Layers** page covers each control in depth.

| Concern | Control |
|---|---|
| Credential exposure in tracebacks | `SecretStr` for all secrets, masked `__repr__` on Settings |
| Weak secrets at boot | Strength checks on signing/session/TOTP/outbox keys and configured health/federation secrets; not every external credential |
| SQL injection | `psycopg.sql.Identifier` / `Placeholder` everywhere; no f-string SQL |
| ILIKE wildcard abuse | User input is escaped before being interpolated into ILIKE patterns |
| Search as a redaction oracle | Full-text, keyword, and language matching is tier-gated in SQL; redacted datasets remain deliberately matchable on the public discovery subset (title + access level) |
| XXE in OAI responses | `lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)` |
| XSS | Jinja2 auto-escaping; CSP forbids inline scripts and styles; `safe_url` filter on rendered URLs |
| CSRF / form confusion | `SecureAPIRouter` installs HMAC-bound double-submit verification and form Content-Type validation on every mutation method; only two exact reviewed token-capability POSTs omit CSRF; `SameSite=Strict` |
| Route authorization drift | SecureAPIRouter installs declared policies; startup validates the effective route registry |
| Session hijacking | DB-backed sessions; cookie holds only the random ID; signed with `itsdangerous` |
| Session fixation | New random session ID issued on every login; the previous session is revoked |
| Password storage | Argon2id with default-strong parameters, rehash on login |
| Common passwords | SecLists 10k blocklist + contextual checks + 12-char minimum |
| Account compromise | Mandatory email verification; temporary lockout after repeated failures (with email notice) |
| TOTP secret theft from DB | Fernet encryption; keys derived from `TOTP_ENCRYPTION_KEYS` via HKDF (rotatable via MultiFernet) |
| TOTP replay | Verified codes consume their time-step; a captured code cannot be reused |
| Brute force and account discovery | slowapi limits attempts per resolved client IP; the canonical address is HMAC-pseudonymized before Redis storage. Login failures use one generic response and perform Argon2 work even when no usable stored hash exists. Complete request timing is not claimed to be constant because lockout, audit, and outbox work varies. |
| Click-jacking | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` |
| TLS downgrade | HSTS with `max-age=31536000; includeSubDomains; preload` in production |
| Cached private/capability content | All non-static application responses use `Cache-Control: no-store`; nginx caches only `/static/` assets |
| Misconfigured CORS | Staging/production startup blocked on `*`, empty origins, or localhost |
| Admin-area discovery | `require_admin` returns 404 (not 403) for non-admins |
| Stack-trace leakage | Custom 404/422/500 handlers, no debug pages in production |
| Sensitive data in logs | Application structured-field redaction; arbitrary text and nginx error logs still require review |
| Audit retention | journald capture and optional remote shipping; tamper evidence requires independently controlled collector retention |
| Database-backup disclosure | Separate read-only identity, no filesystem plaintext, `0700` state directory, atomic `age`-encrypted archives, and off-host private-key custody |

---

## Documentation

| Document | What it covers |
|---|---|
| `README.md` | This file — overview, setup, configuration, security summary |
| `Deployment.md` | Production deployment runbook for the VM (nginx, SSL, Redis, Shibboleth, firewall, backups, log shipping) |
| `docs/runbooks/local-staging.md` | Laptop-only staging with demo SWISSUbase, Mailtrap Sandbox, isolated PostgreSQL, Redis and loopback nginx |
| `docs/runbooks/key-rotation.md` | Operator runbook for rotating application secrets and the separately custodied backup recipient |
| `roadmap.md` | Development phases and resolved-debt tracker |
| `docs/` (MkDocs) | User guide, architecture deep dives, settings reference, code reference |

To build the documentation site locally:

```bash
uv sync --locked --extra doc
mkdocs serve
```

The site will be available at `http://127.0.0.1:8000`.

---

## Known Limitations

These are accepted limitations of the current Phase 1 prototype, with planned resolutions noted.

- **Hardened admission depends on a dedicated Redis service.** The web tier fails startup, and later dynamic admission fails closed with a retryable 503, if the dedicated `RATE_LIMIT_REDIS_URL` backend cannot execute its reviewed command contract. nginx retains independent coarse limits during that incident. Optional `REDIS_ENABLED` / `REDIS_URL` state is a physically separate, best-effort catalogue-cache pub/sub service and does not control Gunicorn worker count or security quotas.
- **Single-source ingestion.** Only Source A (SWISSUbase OAI-PMH) is wired up. Source B integration is the headline item of Phase 2.
- **Federated authentication is not yet deployed.** Local accounts with mandatory TOTP cover Phase 1. The Shibboleth callback route and user model are in place, but the nginx SP plumbing (shibd + FastCGI, via the nginx-http-shibboleth module) and SWITCH AAI registration are Phase 2.
- **Per-dataset (not per-field) visibility.** `filter_for_tier` is all-or-nothing per dataset today; a per-field visibility matrix and PostgreSQL Row-Level Security are Phase 2.
- **Manual dataset-tier administration.** Authorised operators can raise existing dataset classifications directly in the database; there is no dataset-tier admin UI. Sync preserves stricter stored tiers, including those inherited from an earlier source policy. Future Source B records must also carry a valid source-owned tier and pass the [mandatory ingestion contract](docs/architecture/source-b-ingestion-contract.md).

---

## Phase 2 Roadmap

The headline goals of Phase 2:

- **Source B integration.** Separate client module, independent sync schedule, download-link provisioning, per-access logging.
- **Shibboleth / SWITCH edu-ID deployment.** An nginx-integrated Shibboleth SP (shibd + FastCGI) in front of the app, federation registration, attribute mapping into the existing user model, attribute-based tier assignment.
- **Field-level visibility matrix.** Per-field minimum tiers, backed by PostgreSQL Row-Level Security as a defense-in-depth layer.
- **FADP / GDPR compliance.** Data processing register, purpose limitation, encryption at rest for Source B, audit trail immutability via remote log shipping, data subject access request procedures.
- **Operational hardening.** Point-in-time recovery, automated deployment, and
  log monitoring/alerting. Encrypted logical-backup tooling is shipped; the
  runbook makes failure/staleness monitoring, authenticated off-host custody,
  and recorded restore verification deployment acceptance conditions.

### Account and security TODOs

- [ ] Resolve unverified local email reservations when a legitimate federated user claims the address, without transferring an attacker-selected password.
- [ ] **Registration verification:** Require mailbox proof before choosing the account password; a verification link must not activate a password set by someone else.
- [ ] **Account deletion:** Add authenticated self-service deletion and audited administrator removal, including session and token revocation and retention-aware data handling.
- [ ] Keep reset, verification and email-change capability tokens out of URL paths that can reach application and edge error logs.

**Release gate:** Do not expose local registration to untrusted users until the registration verification change is complete. Track this unresolved work in [roadmap.md](roadmap.md).

The full Phase 1 → Phase 2 transition plan lives in `roadmap.md`.

---

## License

Copyright (c) 2026
