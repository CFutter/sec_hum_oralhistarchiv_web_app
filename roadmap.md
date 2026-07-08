# Project Roadmap — Digital Oral History Archive

**University of Zurich**
**Last Updated:** June 2026

This roadmap uses the same two-phase framing as the README. **Phase 1** is the current shipped state of the prototype. **Phase 2** is the planned work to take it from a hardened prototype to a production system holding sensitive (Source B) research data. Items are marked ✅ implemented or ⬜ planned.

---

## Phase 1 — Core Application & Security Hardening

**Status: ✅ Complete (shipped)**

Phase 1 delivers a security-hardened, single-source archive with full local authentication and tiered metadata visibility. Everything in this section is implemented in the current codebase.

### Data ingestion

| Item | Status | Notes |
|------|--------|-------|
| OAI-PMH harvesting from SWISSUbase | ✅ | `oai_client.py`, resumption-token handling with an `OAI_MAX_PAGES` cap |
| XXE-hardened CMDI XML parsing | ✅ | `_SAFE_XML_PARSER` (`resolve_entities=False`, `no_network=True`, `load_dtd=False`) |
| Institution filtering | ✅ | `OAI_INSTITUTION_FILTER`, applied after parsing |
| Incremental sync + deleted-record tombstones | ✅ | `sync.py`, `from=` watermark in `sync_status` |
| Periodic full rebuild (source-scoped) | ✅ | `_full_rebuild_source_a`, `_delete_source_records()` |
| Dedicated scheduler process | ✅ | `run_scheduler.py` + `oralhistarchiv-scheduler.service`; four jobs (sync, rebuild, session cleanup, unverified reaper) |
| `access_level` derived from license string | ✅ | `_classify_access_level` — see Phase 2 note on making this more robust |

### Authentication & accounts

| Item | Status | Notes |
|------|--------|-------|
| Local accounts with Argon2id hashing + rehash-on-login | ✅ | `authentication.py`, `users.py` |
| Mandatory email verification | ✅ | `register.py`, `verify_email.py`, `email_verification.py`; login blocks unverified accounts |
| send_verification flow (no enumeration) | ✅ | `register.py` / `send_verification.html` |
| Unverified-account reaper | ✅ | Scheduler job, `UNVERIFIED_REAP_AFTER_DAYS` |
| Mandatory TOTP enrollment | ✅ | `totp.py`; `purpose='totp_setup'` sessions gated to exempt prefixes |
| TOTP secret encryption at rest | ✅ | Fernet, key via HKDF from `SECRET_KEY` (`crypto.py`) |
| Self-service authenticator rotation | ✅ | `/account/reset-totp`, requires current + new code |
| Account lockout after repeated failures | ✅ | `LOGIN_FAILURE_THRESHOLD` / `LOGIN_LOCKOUT_MINUTES` |
| Password reset via signed, hashed, single-use tokens | ✅ | `password_reset.py`; token hash stored on the `users` row, no separate table |
| Common-password blocklist + contextual + 12-char min | ✅ | `password_validation.py` (SecLists 10k) |
| Self-service display-name and email change | ✅ | `account.py`, `email_change.py`; email change confirmed via link to the new address |
| Shibboleth callback route + auto-provisioning | ✅ | `login.py`; trusted-proxy + optional `X-Internal-Auth` gating |
| SMTP email service (verification, reset, email change) | ✅ | `email.py`; logs instead of sending when `SMTP_ENABLED=false` |

### Visibility & access control

| Item | Status | Notes |
|------|--------|-------|
| `source` column + source-scoped rebuilds | ✅ | `datasets.py`, `sync.py` |
| `visibility_tier` independent of `access_level` | ✅ | `datasets.py` |
| Tier ranking + `can_access` | ✅ | `access_tiers.py` |
| `filter_for_tier()` redacted copy | ✅ | Keeps only id, uuid, title, access_level, version, source, visibility_tier |
| Per-tier rendering in templates | ✅ | `search.html`, `detail.html` — stub + access badge |
| Mock restricted datasets (debug only) | ✅ | `seed_mock_data.py` (`source="mock"`, `visibility_tier="vetted"`) |

### Admin system

| Item | Status | Notes |
|------|--------|-------|
| `is_admin` column (role, separate from `access_tier`) | ✅ | `users.py` + migration |
| `require_admin` dependency (returns 404 to non-admins) | ✅ | `routes/auth/admin.py` |
| Admin nav visibility | ✅ | `base.html` shows the Admin link only when `is_admin` |
| User management (tier, activate/deactivate, promote, revoke sessions, stage email change) | ✅ | `admin.py` |
| First-run admin seeding | ✅ | `seed_admin.py`, `ADMIN_SEED_*` |

### Security middleware & hardening

| Item | Status | Notes |
|------|--------|-------|
| Server-side sessions, signed cookie holds only the ID | ✅ | `sessions.py`, `session.py`; `SameSite=Strict` |
| HMAC-bound double-submit CSRF, route-level dependency | ✅ | `csrf.py`; `HttpOnly` cookie, token injected server-side |
| Strict CSP (no `unsafe-inline`), HSTS, frame-deny | ✅ | `security_headers.py` |
| `Cache-Control: no-store` on authenticated responses | ✅ | bare `@app.middleware` in `main.py` |
| Rate limiting (memory or Redis) | ✅ | `rate_limiting.py`, slowapi |
| Content-Type allow-list on forms | ✅ | `content_type.py` |
| Audit logging with request IDs and path/query scrubbing | ✅ | `audit_logging.py`, `audit.py` |
| `psycopg.sql` composables everywhere (no f-string SQL) | ✅ | `datasets.py`, `users.py`, `schema.py` |
| ILIKE wildcard escaping | ✅ | `datasets.py` |
| `SecretStr` for credentials + log redaction | ✅ | `settings.py`, `config/logging.py` |
| Startup security validators | ✅ | `validators.py`, Settings model validators |
| Server-side email validation on registration | ✅ | `email-validator` |
| Keyword facet frequency filter (2+ datasets) | ✅ | `get_facets()` `HAVING COUNT(*) >= 2` |

### Data access UX

| Item | Status | Notes |
|------|--------|-------|
| Trigram-indexed substring search | ✅ | trigger-maintained `search_text`, `pg_trgm` GIN index |
| Faceted filtering (keyword, language, access level) | ✅ | `search.html` |
| Facet cache with post-sync invalidation | ✅ | `cache.py`; Redis pub/sub for cross-worker invalidation when enabled |
| Pagination with configurable page size | ✅ | `PAGINATION_SIZE` |
| Download button / request-access on detail page | ✅ | `download_url` parsed from `resource_proxies`, tier-respecting in `detail.html` |

### Operations & deployment

| Item | Status | Notes |
|------|--------|-------|
| Gunicorn config + web systemd unit | ✅ | `gunicorn.conf.py`, `oralhistarchiv.service` (Unix socket) |
| Scheduler systemd unit | ✅ | `oralhistarchiv-scheduler.service` |
| nginx reverse proxy + TLS termination | ✅ | `deploy/nginx.conf.example`, documented in `Deployment.md` |
| Redis for shared rate-limit + cache invalidation | ✅ | `redis_client.py`, `REDIS_ENABLED` |
| Logging to stdout → journald (multi-process safe) | ✅ | `config/logging.py`, `deploy/journald-oralhistarchiv.conf` |
| Public + token-protected health endpoints | ✅ | `routes/health.py` |
| DevContainer with PostgreSQL | ✅ | `.devcontainer/` |
| Alembic migrations (auto in dev, out-of-band in prod) | ✅ | `main.py` lifespan / systemd `ExecStartPre` |
| MkDocs Material documentation site | ✅ | `docs/`, `mkdocs.yaml`, mkdocstrings reference |

### Resolved technical debt

Items previously flagged as debt that are now fixed:

| Item | Status | Notes |
|------|--------|-------|
| `users.py` → `sessions.py` circular import | ✅ Resolved | Session invalidation now lives in `password_reset.update_password_with_token`, which imports `delete_user_sessions` at module top level; `users.py` no longer imports `sessions` |
| `FacetCache.get_cached_facets()` TOCTOU | ✅ Resolved | The cache-population check now runs inside `with self._lock` |
| TOTP secrets stored as plain base32 | ✅ Resolved | Now Fernet-encrypted at rest |
| In-process-only rate limiting | ✅ Resolved | Redis backend available (`REDIS_ENABLED`) |

### Test suite

The suite contains roughly **825 test functions across 55 files** (53 unit modules plus two integration modules under `src/tests/integration/`). Counts are approximate — they move with parametrization and as the suite grows. Coverage spans dataset parsing/search, OAI-PMH and CMDI parsing, sync operations, the full auth flow (login, registration, email verification, TOTP enrollment and rotation, password reset, email change, lockout, admin actions), sessions, CSRF, all middleware, security headers, logging/redaction, settings validation, scheduler jobs and lifecycle events, the Redis client and facet-cache pub/sub, the email service in disabled mode, the schema invariant, and visibility filtering. The `test_schema.py` and `test_visibility.py` modules are the canaries for data-model changes.

---

## Phase 2 — Sensitive Data, Federation & Production Operations

**Status: ⬜ Planned**

Phase 2 takes the prototype to a system that can hold sensitive Source B data, authenticate federated users, and run with production-grade operations and compliance.

### Source B integration

| Item | Status | Notes |
|------|--------|-------|
| Source B client module | ⬜ Planned | Same upsert pipeline as Source A; distinct `source` tag |
| Source B branches in `run_sync()` / `run_full_rebuild()` | ⬜ Planned | `_sync_source_b()`, `_full_rebuild_source_b()` (stubbed today) |
| Source B data-sharing agreement | ⬜ Planned | DPIA precondition |
| Ethics board approval (if applicable) | ⬜ Planned | Depends on Source B data |
| Download-link provisioning + per-access logging for Source B | ⬜ Planned | Builds on the existing download/audit hooks |

### Federated authentication (Shibboleth deployment)

| Item | Status | Notes |
|------|--------|-------|
| nginx + `mod_shib` SP deployment | ⬜ Planned | Application callback already implemented; this is the edge plumbing |
| SWITCH AAI / eduGAIN registration | ⬜ Planned | Federation metadata, attribute release |
| Attribute-based tier assignment | ⬜ Planned | Map affiliation/entitlement to `access_tier` |
| REFEDS MFA profile enforcement | ⬜ Planned | Require MFA assertion from the IdP |

### Field-level visibility & RLS

| Item | Status | Notes |
|------|--------|-------|
| Per-field visibility matrix | ⬜ Planned | Replace all-or-nothing `filter_for_tier` with per-field minimum tiers |
| PostgreSQL Row-Level Security | ⬜ Planned | Defense-in-depth so direct SQL cannot bypass tier rules |
| Admin UI for per-dataset tier assignment | ⬜ Planned | Today tiers are set in the database directly |

### Compliance (FADP / GDPR)

| Item | Status | Notes |
|------|--------|-------|
| Data processing register | ⬜ Planned | |
| DPIA review with the Data Protection Advisor | ⬜ Planned | |
| Data classification matrix + asset inventory | ⬜ Planned | |
| Incident response procedure | ⬜ Planned | |
| Data subject access request procedures | ⬜ Planned | |
| Immutable audit trail via external log shipping | ⬜ Planned | rsyslog agent over RELP/TLS (deploy/rsyslog-…conf.example); host-level, not in-app |

> The compliance documents are not yet written. Earlier drafts and an ISO 27001 / LeoMed questionnaire mapping were produced for a previous prototype iteration and are **not** part of this repository.

### Operational hardening

| Item | Status | Notes |
|------|--------|-------|
| CI/CD pipeline | ⬜ Planned | Automated `pytest`, `ruff`, `bandit`, `pip-audit` on push. `Deployment.md` includes a template workflow to start from |
| Log monitoring and alerting | ⬜ Planned | Alert on health-check failure and recorded sync errors |
| Automated backups with point-in-time recovery | ⬜ Planned | `pg_dump` schedule is documented; PITR is the next step |
| TOTP recovery / admin reset UI | ⬜ Planned | Today, a user who loses their authenticator must be helped out of band |

### Performance & scalability

| Item | Status | Notes |
|------|--------|-------|
| Full-text search (`tsvector`) | ⬜ Planned | Replace ILIKE substring matching; not urgent at current scale |
| GIN indexes on array columns | ⬜ Planned | `keywords`, `languages` — only if search becomes slow |
| Cursor-based pagination | ⬜ Planned | Replace OFFSET; only matters at scale |
| Robust `access_level` classification | ⬜ Planned | Replace the license-string `startswith` heuristic with an explicit mapping |

### Dependencies

| Item | Status | Notes |
|------|--------|-------|
| `pygments` advisory (GHSA-5239-wwwm-4pmq) | ⬜ Waiting | Dev-only (MkDocs) dependency; docs are built separately from production |

Secrets management & key isolation (Phase 2 hardening)
Context / motivation. Today all application secrets live in a single .env file: SECRET_KEY, SESSION_SECRET, the database password, the SMTP password, and (transitively, via HKDF) the derived TOTP-encryption key and the audit-email-hash key. This makes .env a single point of compromise — a config-file disclosure (backup leak, misconfigured permissions, accidental commit, env captured in a log) yields the entire system at once. The goal of this work is to reduce the blast radius of at-rest secret disclosure. Note the explicit limit: this does not defend against a code-execution attacker, who reads secrets from process memory regardless of how they are stored at rest. The defensible boundary is "one leaked file must not equal total compromise," not "secrets are unreadable to a process-level attacker."
Current state (what is already correct). Per-purpose key separation is in place: SECRET_KEY and SESSION_SECRET are distinct, and purpose-specific keys (Fernet/TOTP encryption, audit-email-hash) are derived via HKDF-SHA256 with distinct info domain labels, so a leak of one derived key does not expose the others. The remaining weakness is shared root and shared location, not key reuse.
Planned work, in priority order:

Remove the database password from secrets entirely. Switch production Postgres to Unix-socket peer/ident authentication so there is no DB password in the environment at all. (Highest value, lowest friction — eliminates one secret rather than relocating it.)
Move high-value secrets out of .env in production. Load SECRET_KEY and SESSION_SECRET via systemd LoadCredential=/SetCredential= (or a secrets manager such as Vault), so they are injected into the unit's runtime and never persist in a world-readable file. This extends the existing guidance that production should set these as real environment variables rather than loading .env.
Isolate the SMTP credential. Store the SMTP password in a separate, tightly-permissioned credential source rather than alongside the application signing keys, so the mail credential and the signing keys do not share a disclosure event.
Document the rotation blast radius. Maintain a single authoritative note (next to the crypto.py rotation warning) listing everything that breaks when SECRET_KEY is rotated: enrolled TOTP secrets, outstanding email/reset/verification tokens, and audit-email-hash correlation (added when audit_email_hash was introduced for. Rotation must be a planned, documented operation, not an ad-hoc change.

Explicitly out of scope (decision recorded): Threshold/Shamir secret-splitting (e.g. Vault-style unseal shares) is not planned. It targets a trusted-insider-with-host-access threat model beyond a university archive, and adds key-ceremony and share-custody operational burden disproportionate to the risk. Splitting the root SECRET_KEY across sources also buys little while every derived key depends on it and a code-exec attacker reads it from memory regardless. Revisit only if the threat model escalates to requiring insider resistance at the root of trust.
---

*This roadmap reflects the state of the `main` branch. The architecture deep-dives in the MkDocs site describe the implemented Phase 1 behaviour in detail.*
