![CI](https://github.com/CFutter/sec_hum_oralhistarchiv_web_app/actions/workflows/ci.yml/badge.svg)
# Digital Oral History Archive

A web application providing unified search and tiered access to oral history dataset metadata. Built with security-first principles for the University of Zurich. It is intended as a practical query website that can be easily reused for different use cases.

> **Status:** Phase 1 complete — Source A (SWISSUbase, OAI-PMH) integrated with full local authentication (Argon2, mandatory TOTP, email verification, account lockout), server-side sessions, CSRF protection, and tiered metadata visibility. Phase 2 will add Source B (sensitive data) and deploy Shibboleth federation.

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
- [Contributing](#contributing)
- [License](#license)

---

## What This Is

The Oral History Archive is a search and browse interface for oral history research datasets. It harvests metadata from external repositories via the OAI-PMH protocol, stores it in a local PostgreSQL cache, and serves it through a server-rendered web interface.

Two characteristics distinguish it from a generic catalogue front-end:

1. **Tiered metadata visibility.** Every dataset carries a `visibility_tier` (`public`, `registered`, `vetted`). Users below the required tier see only the title and access level — every other field is redacted server-side, before rendering. This is enforced in the service layer (both in the SQL queries and in `filter_for_tier`), so the templates never receive the hidden fields.
2. **Security-first prototype.** The application is designed as a foundation for handling sensitive research data. Argon2 password hashing, mandatory TOTP, email verification, account lockout, server-side sessions, HMAC-bound CSRF cookies, encrypted TOTP secrets at rest, strict CSP, audit logging with sensitive-field redaction, and startup validators for misconfiguration are implemented before sensitive data flows through the system.

### Audiences

| Audience | What they see |
|---|---|
| **Public visitors** | Title and access level of all datasets; full metadata of public-tier datasets |
| **Registered users** | Everything public visitors see, plus full metadata of registered-tier datasets |
| **Vetted users** | Full metadata of all tiers, including strictly confidential fields |
| **Administrators** | User management, tier assignment, account deactivation (which also revokes the user's sessions), staged email changes |

---

## Key Features

### Data ingestion
- OAI-PMH harvesting from SWISSUbase with resumption-token handling and a runaway-pagination cap
- CMDI XML parsing via XXE-hardened lxml
- Institution-based filtering of records, which allows reuse for different use cases
- Incremental sync, deleted-record tombstone handling, and periodic full rebuild on independent schedules
- Per-source visibility ceiling: harvested records are clamped to `SWISSUBASE_MAX_VISIBILITY` via a `SourcePolicy` at ingest
- Background scheduler (APScheduler) running in its own dedicated process, not inside the web workers

### Data access
- Trigram-indexed substring search across titles, descriptions, authors, and keywords — tier-aware, so datasets above the user's tier match on title and access level only
- Faceted filtering by keyword, language, and access level (keyword and language filters are tier-gated so they cannot probe redacted metadata)
- In-process facet cache, invalidated after each sync (cross-worker via Redis pub/sub when enabled)
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
- Admin dashboard for tier changes, deactivation (revokes sessions), admin promotion, and staged email changes

### Security middleware
- Server-side sessions (DB-backed, signed cookie holds only the random ID; `SameSite=Strict`)
- CSRF protection via an HMAC-bound double-submit cookie, verified as a route-level dependency
- Strict Content Security Policy (no `unsafe-inline`)
- HSTS in production with preload
- `Cache-Control: no-store` on authenticated responses
- Rate limiting via slowapi (configurable per minute / hour / day; memory or Redis backend)
- Content-Type allow-list on form endpoints
- Audit logging on every request, with structured JSON output

### Operations
- Alembic migrations run automatically at startup **in dev only**; in production the app verifies the schema version and migrations are applied out of band
- Startup invariant checks: dataclass/column-list sync, redaction-field classification, and a live-database drift check
- Connection pooling via psycopg_pool, with per-process `application_name` and statement timeout
- Logs to stdout, captured by systemd-journald in production (rotation/retention handled by journald)
- Optional off-host audit shipping via a host-level rsyslog agent (RELP/TLS)
- Public liveness endpoint and token-protected detail health endpoint
- DevContainer with PostgreSQL for one-click reproducible development *(planned — not yet in the repository)* <!-- TODO(devcontainer): re-mark as shipped once .devcontainer/ lands and is verified -->
- Gunicorn + two systemd units (web and scheduler) for production
- ~825 tests across 55 test files (53 unit + 2 integration) <!-- TODO(tests-rework): update this section once the new test suite lands -->

---

## Architecture at a Glance

```
┌──────────────────────────────────────────────────────────────────────┐
│  Browser ──HTTPS──▶ nginx ──▶ gunicorn (FastAPI, web service)         │
│                                   │                                    │
│                                   ├──▶ PostgreSQL (pooled)             │
│                                   │      • oral_history_datasets       │
│                                   │      • users  (incl. hashed        │
│                                   │        reset / verification /      │
│                                   │        email-change tokens)        │
│                                   │      • sessions                    │
│                                   │      • sync_status                 │
│                                   │                                    │
│                                   ├──▶ Redis (optional): shared rate   │
│                                   │      limit + facet-cache pub/sub   │
│                                   │                                    │
│                                   └──▶ SMTP (verification, reset,      │
│                                          email-change mail, notices)   │
│                                                                        │
│  Scheduler service (run_scheduler.py, separate process)               │
│                                   ├──▶ PostgreSQL (own pool)           │
│                                   ├──▶ SWISSUbase OAI-PMH (30s tmo)    │
│                                   └──▶ jobs:                           │
│                                          • OAI incremental sync        │
│                                          • OAI full rebuild            │
│                                          • expired-session cleanup     │
│                                          • unverified-account reaper   │
└──────────────────────────────────────────────────────────────────────┘
```

The browser only ever talks to nginx, which proxies to gunicorn over a Unix socket. All external API calls (currently OAI-PMH only) originate from the **scheduler** process, which runs separately from the web workers so the jobs fire once globally rather than once per worker; the web process itself only sends transactional email. There is no client-side JavaScript driving the UI — pages are server-rendered Jinja2.

For a deeper walkthrough of the request lifecycle, sync pipeline, and access control model, see the MkDocs site under **Architecture**.

---

## Technology Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Modern type hints, mature security tooling |
| Web framework | FastAPI 0.136.3 | Pydantic validation, dependency injection, typed routes |
| Server (prod) | Gunicorn + Uvicorn workers | Standard async-capable ASGI deployment |
| Templating | Jinja2 (auto-escaping) | XSS prevention by default, server-side rendering |
| Database | PostgreSQL 15+ | JSONB, trigram indexes, robust constraints |
| DB driver | psycopg 3 + psycopg_pool | Modern driver with native pooling |
| Migrations | Alembic | Version-controlled schema changes |
| Scheduler | APScheduler | Background jobs in a dedicated process |
| Coordination (optional) | Redis | Shared rate-limit store + facet-cache pub/sub invalidation |
| OAI client | requests + lxml | Direct, auditable, XXE-hardened |
| Password hashing | argon2-cffi | OWASP-recommended modern key derivation |
| TOTP | pyotp + qrcode | RFC 6238 |
| Encryption at rest | cryptography (Fernet + HKDF) | TOTP secret protection |
| Rate limiting | slowapi | Decorator-based; memory or Redis backend |
| Security headers | secure | Explicit, audit-friendly configuration |
| Session signing | itsdangerous | Tamper-evident cookie payloads |
| Email validation | email-validator | RFC-compliant |
| Tests | pytest + pytest-asyncio + httpx | Standard FastAPI testing stack <!-- TODO(tests-rework): update this section once the new test suite lands --> |
| Lint / SAST | ruff, bandit, pip-audit | Recommended CI gates |
| Dependency mgmt | uv + pyproject.toml | Fast, reproducible installs |

---

## Project Layout

```
oralhistarchiv/
├── run.py                          # Entry point — uvicorn (dev) or gunicorn (prod)
├── run_scheduler.py                # Entry point — standalone scheduler process
├── dev.sh                          # Runs web + scheduler together for development
├── gunicorn.conf.py                # Production worker / logging config
├── oralhistarchiv.service          # systemd unit — web service
├── oralhistarchiv-scheduler.service# systemd unit — scheduler service
├── pyproject.toml                  # Dependencies and build config
├── mkdocs.yaml                     # Documentation site config
├── README.md
├── Deployment.md                   # Full deployment runbook
├── roadmap.md                      # Development & security roadmap
├── deploy/                         # nginx.conf.example, journald drop-in, rsyslog example
├── docs/                           # MkDocs source (incl. docs/runbooks/key-rotation.md)
└── src/
    ├── alembic.ini
    ├── alembic/
    │   ├── env.py
    │   └── versions/               # Schema migrations
    ├── app/
    │   ├── main.py                 # FastAPI app, lifespan, middleware wiring
    │   ├── paths.py                # Centralized path constants
    │   ├── template_setup.py       # Jinja2 environment + globals
    │   ├── jinja_helpers.py        # Template helpers (url_for_query, etc.)
    │   ├── url_safety.py           # Shared http(s)-scheme allowlist check
    │   ├── routes/
    │   │   ├── pages.py            # Home, search, detail, about
    │   │   ├── health.py           # /health and /health/detail
    │   │   └── auth/               # login, register, verify_email, totp,
    │   │                           #   password_reset, account, email_change, admin
    │   ├── middleware/
    │   │   ├── audit_logging.py
    │   │   ├── content_type.py
    │   │   ├── cookies.py          # Session-cookie signing, CSRF identifier
    │   │   ├── csrf.py
    │   │   ├── rate_limiting.py
    │   │   ├── security_headers.py
    │   │   ├── session.py          # Session resolution + TOTP/purpose gate middlewares
    │   │   ├── utils.py
    │   │   └── validators.py       # Startup config validation
    │   ├── services/
    │   │   ├── access_tiers.py     # Tier ranking, can_access, SourcePolicy/resolve_tier
    │   │   ├── audit.py            # Structured audit event helpers
    │   │   ├── authentication.py   # Password verify, rehash-on-login, lockout counters
    │   │   ├── cache.py            # FacetCache (+ Redis pub/sub)
    │   │   ├── crypto.py           # Fernet + HKDF (TOTP secrets), audit email hash
    │   │   ├── datasets.py         # Dataset model + queries + tier filtering
    │   │   ├── db.py               # Pool + cursor context manager
    │   │   ├── db_drift.py         # Live-DB column drift check (startup)
    │   │   ├── email.py            # SMTP sender + message builders
    │   │   ├── email_change.py     # Self-service / admin email change
    │   │   ├── email_verification.py # Verification token lifecycle
    │   │   ├── oai_client.py       # OAI-PMH protocol + CMDI parsing
    │   │   ├── password_reset.py   # Reset token generation/validation/finalise
    │   │   ├── password_validation.py # Blocklist + contextual + length checks
    │   │   ├── redis_client.py     # Optional Redis connection helper
    │   │   ├── scheduler.py        # APScheduler job registration
    │   │   ├── schema.py           # Single source of truth for column lists
    │   │   ├── seed_admin.py       # First-run admin seeding
    │   │   ├── seed_mock_data.py   # Debug-mode mock restricted datasets
    │   │   ├── sessions.py         # Server-side session CRUD + flash messages
    │   │   ├── sync.py             # Sync orchestrator + access-level classifier
    │   │   ├── tokens.py           # Shared token-hashing primitive
    │   │   ├── totp.py             # TOTP enrollment / verification helpers
    │   │   └── users.py            # User CRUD, schema invariant, unverified reaper
    │   ├── templates/              # Jinja2 templates
    │   └── static/                 # CSS, fonts
    ├── config/
    │   ├── settings.py             # Pydantic Settings + validators
    │   └── logging.py              # Structured logging + redaction
    └── tests/                      # ~825 tests across 55 files (incl. integration/)
                                    # TODO(tests-rework): update this section once the new test suite lands
```

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- PostgreSQL 15+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Option A — DevContainer (planned — not yet in this repository)

<!-- TODO(devcontainer): restore this as the recommended path once .devcontainer/ (including the Dockerfile) is committed and verified end-to-end (container opens, builds, seeds, ./dev.sh runs). -->
A one-click DevContainer (Python + PostgreSQL + seeded database, via VS Code's Dev Containers extension) is planned. A draft exists outside the repository but is not yet committed or verified to run — use Option B for now.

### Option B — Manual setup (recommended)

```bash
git clone <repository-url>
cd oralhistarchiv

uv venv
source .venv/bin/activate
uv pip install -e ".[dev,doc]"

createdb oralhistarchiv

cp .env.example .env
# Edit .env: set at least DATABASE_URL and OAI_INSTITUTION_FILTER.
# The placeholder secrets (SECRET_KEY, SESSION_SECRET, TOTP_ENCRYPTION_KEYS, ...)
# are accepted in dev with warnings; generate real ones before any deployed use.

./dev.sh            # runs the web server and the scheduler together
```

On first start the web application:

1. Configures logging and (dev only) warns about unconsumed `.env` keys
2. Validates security settings (refuses to start with weak secrets in staging/production) and, if SMTP is enabled with TLS, verifies the relay's certificate
3. Opens the database connection pool and creates the facet cache
4. Runs Alembic migrations to head **in dev** (in staging/production it only verifies the schema version and refuses to start on a mismatch)
5. Validates the dataset/user schema invariants, the redaction-field classification, and the live database columns
6. Seeds mock restricted datasets if `FASTAPI_DEBUG=true`
7. Seeds the admin account if `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` are set and no admin exists yet

The web process does **not** start the background scheduler. Run `run_scheduler.py` as a second process (or use `./dev.sh`, which launches both). The scheduler runs an incremental sync immediately on start, then on the configured interval; the first full rebuild is staggered five minutes after start.

---

## Configuration

All configuration is loaded from environment variables, with `.env` supported in development only. Pydantic Settings validates types and ranges; startup validators block staging/production launch on weak secrets, unsafe CORS or `ALLOWED_HOSTS`, invalid database URLs, insecure cookies, a non-HTTPS `PUBLIC_BASE_URL`, or misconfigured SMTP/Shibboleth.

A complete and annotated example lives in `.env.example`. The most important settings:

| Group | Variable | Purpose |
|---|---|---|
| **Environment** | `ENV_STATE` | `dev` / `staging` / `production` |
| | `PUBLIC_BASE_URL` | External base URL used in emailed links (required; must be non-localhost `https://` in staging/production) |
| | `FASTAPI_DEBUG` | Enables `/docs`, `/redoc`, mock seeding, open `/health/detail` (forbidden outside dev) |
| | `ALLOWED_HOSTS` | Host headers accepted by `TrustedHostMiddleware` (required) |
| **Database** | `DATABASE_URL` | PostgreSQL connection string (validated as `postgresql://`) |
| | `DATABASE_POOL_SIZE` | Max connections (1–50) |
| | `DB_STATEMENT_TIMEOUT` | Per-connection statement timeout (default `5s`) |
| **Secrets** | `SECRET_KEY` | Signs email-verification / password-reset / email-change tokens and derives the audit-email HMAC key. Does **not** encrypt TOTP secrets |
| | `SESSION_SECRET` | Session cookie signing + CSRF HMAC key (separate from `SECRET_KEY`) |
| | `TOTP_ENCRYPTION_KEYS` | JSON list of Fernet key material for TOTP secrets at rest — first key encrypts, all keys decrypt (rotation) |
| | `HEALTH_DETAIL_TOKEN` | Bearer token for `/health/detail` (required in production) |
| **Sessions** | `SESSION_MAX_AGE_SECONDS` | Default 28800 (8 hours) |
| | `SESSION_COOKIE_NAME` | Default `oha_session` |
| | `COOKIES_SECURE` | Secure flag on cookies — `false` only for local plaintext-HTTP dev |
| **Auth** | `LOCAL_AUTH_ENABLED` | Toggle local login/register |
| | `TOTP_ISSUER_NAME` | Label shown in authenticator apps |
| | `LOGIN_FAILURE_THRESHOLD` / `LOGIN_LOCKOUT_MINUTES` | Account lockout policy |
| | `UNVERIFIED_REAP_AFTER_DAYS` | Reap unverified accounts after N days |
| | `SHIBBOLETH_ENABLED` / `SHIBBOLETH_INTERNAL_SECRET` | Trust reverse-proxy auth headers on the callback (secret required whenever enabled) |
| | `ADMIN_SEED_EMAIL` / `ADMIN_SEED_PASSWORD` | First-run admin bootstrap |
| **Reverse proxy** | `TRUSTED_PROXY_IPS` | Peer IPs trusted for client-IP attribution |
| **Redis** | `REDIS_ENABLED` / `REDIS_URL` | Shared rate-limit store + facet-cache invalidation |
| **OAI sync** | `SWISSUBASE_OAI_PMH_URL` | Endpoint URL |
| | `OAI_INSTITUTION_FILTER` | Required institution name |
| | `SWISSUBASE_MAX_VISIBILITY` | Visibility ceiling applied to harvested records at ingest |
| | `SYNC_INTERVAL_SECONDS` / `FULL_REBUILD_INTERVAL_SECONDS` | Job intervals |
| | `OAI_MAX_PAGES` | Resumption-token pagination cap |
| **SMTP** | `SMTP_ENABLED` | When false, mail is logged instead of sent |
| | `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | SMTP credentials |
| | `SMTP_FROM_ADDRESS` / `SMTP_FROM_NAME` / `CONTACT_EMAIL` | Sender + contact identity |
| | `SMTP_CA_BUNDLE` | PEM CA bundle for a relay signed by a private CA |
| **Logging** | `LOG_LEVEL` / `LOG_FORMAT` | Verbosity and `json`/`text` output |
| **Rate limit** | `RATE_LIMIT_ENABLED` | Master switch |
| | `RATE_LIMIT_PER_MINUTE` / `_PER_HOUR` / `_PER_DAY` | Tier limits |
| | `RATE_LIMIT_TRUST_PROXY` | Trust `X-Real-IP` / `X-Forwarded-For` (must be `true` in production behind nginx) |
| **CORS** | `CORS_ENABLED` / `CORS_ORIGINS` / `CORS_ALLOW_METHODS` / `CORS_ALLOW_HEADERS` / `CORS_ALLOW_CREDENTIALS` | Disabled by default |

> ⚠️ **Generate secrets with**
> ```bash
> python -c "import secrets; print(secrets.token_urlsafe(64))"
> ```
> Never commit `.env` files. Production deployments should set `ENV_STATE` as a real OS environment variable so pydantic-settings does not try to load `.env` at all. Each secret has different rotation consequences — see the table below and the full procedure in `docs/runbooks/key-rotation.md` before rotating anything.

### Secrets & key rotation

The application uses three independent secrets. They are not interchangeable,
and each has different rotation consequences.

| Secret | Protects | Rotating it… |
|---|---|---|
| `SECRET_KEY` | Audit-email HMAC key; signs email-verification, password-reset, email-change tokens | Invalidates outstanding verification/reset/change links (short-lived — users request new ones) and breaks audit-hash correlation across the boundary. **Does not affect TOTP secrets or sessions.** |
| `SESSION_SECRET` | Session-cookie signature + CSRF HMAC | Logs out all users and invalidates outstanding CSRF tokens; users log in again. **Does not affect TOTP secrets.** |
| `TOTP_ENCRYPTION_KEYS` | TOTP secrets at rest (MultiFernet) | See the safe procedure below. Done wrong, **every enrolled authenticator becomes unrecoverable.** |

**Rotating `TOTP_ENCRYPTION_KEYS` safely** (MultiFernet: first key encrypts, all keys decrypt):

1. **Prepend** a freshly generated key, keeping the current one(s):
   `TOTP_ENCRYPTION_KEYS='["<new-key>", "<old-key>"]'`
   New secrets encrypt under `<new-key>`; existing secrets still decrypt under `<old-key>`.
2. **Re-encrypt** every stored TOTP secret under the new key — decrypt with the
   MultiFernet and re-encrypt (a one-off maintenance script; `MultiFernet.rotate`
   does exactly this per token).
3. Once all secrets are confirmed re-encrypted, **retire** the old key:
   `TOTP_ENCRYPTION_KEYS='["<new-key>"]'`

Never remove or replace the key existing secrets were encrypted under before step 2
completes — decryption then returns `None` for those users and they must re-enroll.

The step-by-step operator procedure, including the re-encryption script and
verification checks, lives in `docs/runbooks/key-rotation.md`.

Generate any secret with:
`python -c "import secrets; print(secrets.token_urlsafe(64))"`

### Startup validators

The `validate_security_settings()` function runs before the app starts accepting requests. It checks `SECRET_KEY`, `SESSION_SECRET`, every `TOTP_ENCRYPTION_KEYS` entry, and — when set — `HEALTH_DETAIL_TOKEN` and `SHIBBOLETH_INTERNAL_SECRET`. In staging and production it blocks startup if:

- Any of those secrets is a hardcoded template default, on the blocklist, below the minimum length (43 characters ≙ 256 bits), or below the minimum Shannon entropy
- `SWISSUBASE_OAI_PMH_URL` is not `https://`
- Rate limiting is enabled in production without `RATE_LIMIT_TRUST_PROXY=true` (per-IP limits would collapse onto nginx's IP)
- CORS credentials are combined with wildcard or non-HTTPS origins

Pydantic model validators add more: CORS and `ALLOWED_HOSTS` misconfiguration is blocked in staging/production (wildcards, empty lists, localhost origins); `DATABASE_URL` must be a PostgreSQL URL; `PUBLIC_BASE_URL` must be a non-localhost `https://` URL in staging/production; `COOKIES_SECURE` and `FASTAPI_DEBUG=false` are enforced outside dev; SMTP is required in production (with TLS, matching user/password pairs, and no placeholder values); `HEALTH_DETAIL_TOKEN` is required in production; and `SHIBBOLETH_INTERNAL_SECRET` is required whenever Shibboleth is enabled, in every environment. In `ENV_STATE=dev`, blocking findings are logged as warnings instead so local development is not painful.

---

## Running the Application

### Development

```bash
./dev.sh            # web server + scheduler
# or, separately:
python run.py
python run_scheduler.py
```

The web app starts on `http://127.0.0.1:5000`. With `FASTAPI_DEBUG=true`:

- Mock restricted datasets are seeded (refused in production)
- `/docs` (Swagger UI) and `/redoc` are available
- `/health/detail` is open without a token

(Weak-secret findings being warnings instead of startup blockers is tied to `ENV_STATE=dev`, not to the debug flag.)

### Production

The repository ships with `gunicorn.conf.py`, `oralhistarchiv.service`, and `oralhistarchiv-scheduler.service`. See [`Deployment.md`](./Deployment.md) for the full VM runbook covering nginx, SSL, Redis, Shibboleth SP, firewall, backups, and log shipping. The short version of the web process:

```bash
gunicorn -c gunicorn.conf.py app.main:app
```

with the scheduler running as its own service alongside it.

### Health checks

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | Public, rate-limit exempt | `{"status": "alive"}`, always 200 — liveness only, no dependency checks |
| `GET /health/detail` | Bearer token (production) / open (debug) | Database connectivity and sync status (last harvest, last error). Overall status `healthy` / `degraded` (sync error recorded) / `unhealthy`; HTTP 503 only when the database is unreachable |

---

## Testing

<!-- TODO(tests-rework): update this section once the new test suite lands -->

```bash
# The full suite (~825 tests)
pytest

# With coverage report
pytest --cov=src --cov-report=html

# Run a specific area
pytest src/tests/test_auth_routes.py
pytest src/tests/test_visibility.py
```

Most tests use FastAPI's `TestClient`. The shared `conftest.py` provides a mock connection pool on `app.state.db_pool` and patches service functions, so the bulk of the suite runs without a real PostgreSQL instance. Integration tests for SQL behaviour live under `src/tests/integration/` and use a real PostgreSQL via the DevContainer. (Test counts are approximate — they depend on parametrization and shift as the suite grows.)

<!-- TODO(devcontainer): the DevContainer referenced above is not yet in the repository — see Quick Start Option A. -->

Coverage spans: dataset parsing and search, OAI-PMH protocol and CMDI parsing, sync operations, the full auth flow (login, register, email verification and resend, TOTP enrollment and rotation, password reset, email change, admin actions, account lockout), session lifecycle, CSRF token generation and validation, all middleware, security headers, structured logging and redaction, settings validation, scheduler job registration and lifecycle events, the Redis client and facet-cache pub/sub, the email service in disabled mode, the schema column-list invariant, and visibility tier filtering.

---

## Code Quality & Security Tooling

| Tool | Command | What it catches |
|---|---|---|
| `ruff` | `ruff check src/` | PEP 8, type hint hygiene, common bugs |
| `bandit` | `bandit -r src/ --exclude src/tests/` | OWASP / CWE security smells |
| `pip-audit` | `pip-audit` | Known CVEs in pinned dependencies |
| `pytest --cov` | `pytest --cov=src --cov-report=html` | Coverage gate |

<!-- TODO(tests-rework): update this section once the new test suite lands -->

All four are recommended to run before merge.

---

## Security Model

A short tour. The MkDocs **Architecture → Security Layers** page covers each control in depth.

| Concern | Control |
|---|---|
| Credential exposure in tracebacks | `SecretStr` for all secrets, masked `__repr__` on Settings |
| Weak secrets at boot | Entropy + length + blocklist + hardcoded-default checks on every secret, including each `TOTP_ENCRYPTION_KEYS` entry |
| SQL injection | `psycopg.sql.Identifier` / `Placeholder` everywhere; no f-string SQL |
| ILIKE wildcard abuse | User input is escaped before being interpolated into ILIKE patterns |
| Search as a redaction oracle | Free-text, keyword, and language matching is tier-gated in SQL; redacted datasets are only matchable on title + access level |
| XXE in OAI responses | `lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)` |
| XSS | Jinja2 auto-escaping; CSP forbids inline scripts and styles; `safe_url` filter on rendered URLs |
| CSRF | HMAC-bound double-submit cookie verified by route-level dependency; `SameSite=Strict` |
| Session hijacking | DB-backed sessions; cookie holds only the random ID; signed with `itsdangerous` |
| Session fixation | New random session ID issued on every login; the previous session is revoked |
| Password storage | Argon2id with default-strong parameters, rehash on login |
| Common passwords | SecLists 10k blocklist + contextual checks + 12-char minimum |
| Account compromise | Mandatory email verification; temporary lockout after repeated failures (with email notice) |
| TOTP secret theft from DB | Fernet encryption; keys derived from `TOTP_ENCRYPTION_KEYS` via HKDF (rotatable via MultiFernet) |
| TOTP replay | Verified codes consume their time-step; a captured code cannot be reused |
| Brute force | slowapi rate limits per IP; failed login responses time-constant |
| Click-jacking | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` |
| TLS downgrade | HSTS with `max-age=31536000; includeSubDomains; preload` in production |
| Cached private content | `Cache-Control: no-store` on responses to authenticated requests |
| Misconfigured CORS | Staging/production startup blocked on `*`, empty origins, or localhost |
| Admin-area discovery | `require_admin` returns 404 (not 403) for non-admins |
| Stack-trace leakage | Custom 404/422/500 handlers, no debug pages in production |
| Sensitive data in logs | Field-metadata-driven redaction in `config/logging.py` |
| Tamper-evident audit | journald capture, plus optional remote syslog shipping outside the host |


---

## Documentation

| Document | What it covers |
|---|---|
| `README.md` | This file — overview, setup, configuration, security summary |
| `Deployment.md` | Production deployment runbook for the VM (nginx, SSL, Redis, Shibboleth, firewall, backups, log shipping) |
| `docs/runbooks/key-rotation.md` | Operator runbook for rotating every secret, including the TOTP-key re-encryption procedure |
| `roadmap.md` | Development phases and resolved-debt tracker |
| `docs/` (MkDocs) | User guide, architecture deep dives, settings reference, code reference |

To build the documentation site locally:

```bash
uv pip install -e ".[doc]"
mkdocs serve
```

The site will be available at `http://127.0.0.1:8000`.

---

## Known Limitations

These are accepted limitations of the current Phase 1 prototype, with planned resolutions noted.

- **Rate limiting and facet cache require Redis to coordinate across workers.** With `REDIS_ENABLED=false`, slowapi counters and the facet cache are per-process — the gunicorn config therefore runs a single worker in that mode, which keeps rate limiting correct but caps throughput. Enabling Redis unlocks multiple workers, makes rate limits global, and propagates facet-cache invalidations across workers via pub/sub. Production at scale should enable Redis.
- **Single-source ingestion.** Only Source A (SWISSUbase OAI-PMH) is wired up. Source B integration is the headline item of Phase 2.
- **Federated authentication is not yet deployed.** Local accounts with mandatory TOTP cover Phase 1. The Shibboleth callback route and user model are in place, but the nginx SP plumbing (shibd + FastCGI, via the nginx-http-shibboleth module) and SWITCH AAI registration are Phase 2.
- **Per-dataset (not per-field) visibility.** `filter_for_tier` is all-or-nothing per dataset today; a per-field visibility matrix and PostgreSQL Row-Level Security are Phase 2.
- **No admin UI for dataset tiers.** A dataset's `visibility_tier` starts at the source's configured ceiling and is changed by editing the database directly.

---

## Phase 2 Roadmap

The headline goals of Phase 2:

- **Source B integration.** Separate client module, independent sync schedule, download-link provisioning, per-access logging.
- **Shibboleth / SWITCH edu-ID deployment.** An nginx-integrated Shibboleth SP (shibd + FastCGI) in front of the app, federation registration, attribute mapping into the existing user model, attribute-based tier assignment.
- **Field-level visibility matrix.** Per-field minimum tiers, backed by PostgreSQL Row-Level Security as a defense-in-depth layer.
- **FADP / GDPR compliance.** Data processing register, purpose limitation, encryption at rest for Source B, audit trail immutability via remote log shipping, data subject access request procedures.
- **Operational hardening.** CI/CD pipeline, automated backups with point-in-time recovery, log monitoring and alerting.

The full Phase 1 → Phase 2 transition plan lives in `roadmap.md`. (A per-finding security register — e.g. the SEC-012 split cited in the key-rotation runbook — is not yet part of it; see the open questions.)

---

## License

Copyright (c) 2026 