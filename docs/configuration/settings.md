# Settings Reference

Every configurable knob in the application. Settings are loaded from environment variables (and from `.env` in `dev` mode only) by Pydantic Settings, which validates types, ranges, and a number of cross-field invariants.

The canonical schema lives in `src/config/settings.py`. The annotated `.env.example` in the repository root is the canonical *example*.

> Set the exact uppercase ENV_STATE in the OS environment for every launcher, including development. Missing values, alternate casing and collisions are rejected before loading settings. Only explicit dev selection enables dotenv loading; a dotenv file cannot change the mode.

## Environment

| Variable | Type | Default | Notes |
|---|---|---|---|
| `ENV_STATE` | `dev` \| `staging` \| `production` | **(required OS key)** | Drives `.env` loading, validator strictness, and dev-only auto-migration. `staging` and `production` are both "hardened" — most security validators treat them identically |
| `APP_PROCESS_ROLE` | `web` \| `scheduler` \| `maintenance` | `web` | Selects secret custody. Hardened scheduler startup requires `scheduler`; web requires `web`. Scheduler must have no TOTP key ring. |
| `PARSER_EXECUTION_MODE` | `service` \| `local` | `service` | Separately privileged parser service required outside development. `local` explicitly permits same-UID spawning only in development. Scheduler startup freezes the validated selection. |
| `PUBLIC_BASE_URL` | str | **(required)** | Browser-facing origin used for CSRF origin checks and emailed links. Must contain only an `http://` or `https://` scheme, hostname, and optional port—credentials, paths, queries, and fragments are rejected. In staging and production it must use HTTPS and must not point to localhost or another loopback address. |
| `FASTAPI_HOST` | str | `127.0.0.1` | Bind address for the dev server |
| `FASTAPI_PORT` | int | `5000` | Bind port for the dev server |
| `FASTAPI_DEBUG` | bool | `false` | Enables `/docs`, `/redoc`, `/openapi.json`, and open `/health/detail`. Forbidden outside `dev` (a validator blocks it in staging and production) |
| `PAGINATION_SIZE` | int (1–100) | `20` | Search results per page |
| `ALLOWED_HOSTS` | list[str] | **(required)** | Host headers accepted by `TrustedHostMiddleware`. An empty list (rejects everything) blocks startup in every environment. `"*"` (accepts anything) blocks staging/production and warns in dev |

`PUBLIC_BASE_URL` is an origin, not a complete URL or deployment path. The
application appends routes such as `/verify-email/...` and `/reset-password/...`
to it.

Browser form submissions must match this origin's scheme, hostname and port,
including during development. For an HTTPS development proxy, configure its
external HTTPS origin rather than the application's internal HTTP listener.
Add its bare hostname to `ALLOWED_HOSTS` and use `COOKIES_SECURE=true` for that
HTTPS browser endpoint. `CORS_ORIGINS` does not override the CSRF origin check.
Restart every web process after configuration changes; exported process
variables take precedence over development's `.env` file.

Valid examples:

- `http://127.0.0.1:5000` in development
- `https://archive.example.org`
- `https://archive.example.org:8443`

Invalid examples include `https://`, URLs containing credentials, and URLs with
a path, query, or fragment, such as `https://archive.example.org/app` or
`https://archive.example.org?tenant=one`.

`ORALHISTARCHIV_PARSER_SOCKET` is an OS-level transport override, defaulting to
`/run/oralhistarchiv-parser.sock`. It must name a root-owned socket in protected
root-owned directories. The parser service reads no application settings and
receives only one explicit job. Install the supplied socket/service and complete
the effective sandbox checks in [Deployment](../../Deployment.md#parser-privilege-boundary).

## Site identity

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SITE_NAME` | str | `Oral History Archive` | Page titles, navigation, footer, application title and email content; also the default TOTP issuer. |
| `INSTITUTION_NAME` | str | `Your institution` | Footer, About contact text and email signature. |
| `ABOUT_SUMMARY` | str | `Search and explore interview metadata from oral history research collections.` | Home, About and default page description; plain text, escaped by Jinja. |
| `FEDERATED_LOGIN_LABEL` | str | `Institutional login` | Federated sign-in heading/button, account method and authenticator guidance; does not enable federation. |

These four values are trimmed and must contain nonblank, single-line printable
text. Restart the application processes after changing configuration. Keep
web and scheduler configuration consistent by placing deployment values in
`common.env`. `SMTP_FROM_NAME` independently controls the mail sender's display
name; set it to the desired site name as well. Previously queued email retains
the content recorded when it was enqueued.

## Database

| Variable | Type | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | SecretStr | required for application runtime | Development may use a password URL. In staging/production it is supplied only by the process-specific root-owned `web.env` or `scheduler.env` and uses the corresponding peer-authenticated non-owner role; it must not appear in `common.env`. |
| `DATABASE_POOL_SIZE` | int (1–50) | `5` | Per-process pool maximum; minimum is min(2, maximum) |
| `DATABASE_POOL_MAX_WAITING` | int (1–1000) | `32` | Per-process queued connection requests; overflow raises TooManyRequests, acquisition waits at most 10 seconds |
| `SCHEDULER_STATEMENT_TIMEOUT` | str | `5min` | Scheduler pool statement timeout; same syntax as DB_STATEMENT_TIMEOUT |
| `DB_STATEMENT_TIMEOUT` | str | `5s` | PostgreSQL `statement_timeout` applied to every pooled connection. Bare `0` disables it; otherwise use a positive ASCII integer plus `ms`, `s`, or `min`, without leading zeros or whitespace, within 1–2147483647 milliseconds |

Examples: `5s`, `500ms`, `2min`. Only bare `0` disables the timeout: `0s`,
`000ms`, Unicode digits, trailing newlines and out-of-range values are rejected
at settings construction. Leading zeros are rejected because PostgreSQL can
interpret the quantity as octal (`0500ms` means 320ms). Explicit `create_pool`
overrides use the same validation before constructing a pool; `None` selects
`DB_STATEMENT_TIMEOUT`. The maximum whole-unit quantities are `2147483647ms`,
`2147483s`, and `35791min`.

### Search capacity

Every `GET /search` uses a separate one-connection pool per web worker, the
same web database role, and a deployment-wide PostgreSQL transaction advisory
lock. Search never borrows the ordinary request/session pool. A mandatory shared
start budget runs before session lookup, including when `RATE_LIMIT_ENABLED=false`.
It applies to empty browsing, filters, literal and full-text terms, numbered
pages, cursor continuation and page restarts alike. Development without Redis
uses a process-local start budget and must retain its single-worker setup.

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SEARCH_STATEMENT_TIMEOUT_MS` | int (1–2000) | `500` | Positive SQL timeout for the search pool; `DB_STATEMENT_TIMEOUT=0` cannot disable it |
| `SEARCH_OPERATION_TIMEOUT_SECONDS` | positive float (≤5) | `1.0` | Deadline for the complete search operation, including checkout, results and facets |
| `SEARCH_POOL_TIMEOUT_SECONDS` | positive float (≤1) | `0.1` | Maximum connection-acquisition wait in the separate search pool |
| `SEARCH_GLOBAL_RATE_PER_SECOND` | positive float (≤1000) | `0.5` | Shared search starts per second across workers; the default admits one start every two seconds |
| `SEARCH_GLOBAL_BURST` | int (1–1000) | `1` | Staging/production requires exactly one; development may use a larger test budget |

The pool-acquisition timeout and SQL statement timeout must each be strictly
shorter than the operation deadline. Staging/production also requires
`SEARCH_GLOBAL_RATE_PER_SECOND * SEARCH_OPERATION_TIMEOUT_SECONDS <= 0.5`.
These validation rules retain time between admitted worst-case operations; do
not raise the start rate independently of the operation deadline. Redis stores
the selected rate/burst policy and rejects disagreeing workers. Changing that
persisted policy requires a coordinated, reviewed state migration; this release
does not automatically reset or migrate it. The immediate
per-worker permit and nonblocking PostgreSQL lock admit no waiting search
backlog. Capacity exhaustion, unavailable admission storage, connection failure
or a search timeout returns a retryable, non-cacheable 503, with no ordinary-pool
or query-mode fallback. Rollback/connection cleanup follows the operation
deadline. Rollback has a separate one-second deadline; connection close/pool
return can extend cleanup, and the local permit remains held until it finishes.
These controls bound search work; measure authentication and database latency under
representative concurrent traffic before deployment.

`MIGRATION_DATABASE_URL` is read by Alembic rather than application Settings.
In staging/production it exists only in root-owned `migration.env`, selects the
owner through the exact peer mapping, and is loaded only by the static manual
migration unit. Runtime and ad-hoc maintenance processes must never load it.

## Secrets and tokens

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SECRET_KEY` | SecretStr | (required) | Signs the itsdangerous tokens (email verification, password reset, email change) and derives audit-email and limiter-client HMAC keys. Does **not** encrypt TOTP secrets. Validated for entropy, length, blocklist, hardcoded default |
| `SESSION_SECRET` | SecretStr | (required) | Cookie signing key and CSRF HMAC key. Independent of `SECRET_KEY`. Same strength validation |
| `TOTP_ENCRYPTION_KEYS` | list[SecretStr] | **required for web/maintenance; forbidden for scheduler** | Fernet key material for TOTP secrets at rest, as a JSON list. MultiFernet semantics: the **first** key encrypts, **all** keys decrypt — which is what makes rotation possible. Every entry passes the same strength validation |
| `HEALTH_DETAIL_TOKEN` | SecretStr \| None | `None` | Bearer token outside debug; required in staging/production; rejected authorization returns 404 |
| `OUTBOX_ENCRYPTION_KEYS` | list[SecretStr] | required, nonempty | Independent JSON key ring for email bodies: first encrypts, all decrypt; retain keys needed by queued/retained mail or backups |

Generate strong values with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Each secret has a different blast radius when rotated. Rotating `SECRET_KEY` invalidates outstanding verification/reset/email-change links (short-lived — users request new ones) and breaks audit-hash correlation across the boundary; it does **not** affect TOTP secrets or sessions. Rotating `SESSION_SECRET` logs everyone out. Rotating `TOTP_ENCRYPTION_KEYS` requires the careful prepend → re-encrypt → retire procedure — done wrong, every enrolled authenticator becomes unrecoverable. **Follow the [Key-Rotation Runbook](../runbooks/key-rotation.md) before touching any of them.**

## Backup publication diagnostics

| Variable | Type | Default | Notes |
|---|---|---|---|
| `BACKUP_STATUS_FILE` | str \| None | `None` | Optional absolute local marker path; no existence check at startup. Empty, relative, ambiguous or control-character paths are rejected. Missing/unreadable/unsafe/malformed/future markers report unknown. |

The reference web environment points at
`/var/lib/oralhistarchiv-backup-status/last-success`. The independent backup
configuration's `BACKUP_STATUS_DIR` names the containing directory; it is not an
application setting. Unset/empty writer configuration disables marker publication.
Use a protected local directory, not a remote filesystem. The reader rejects a
final symlink, nonregular/hardlinked/group- or world-writable file, or oversized content and reads only
bounded nonsecret protocol content. Parent directories are deployment-owned
trust boundaries.

Authorized `/health/detail` adds `checks.backup` with `status=ok` and a
nonnegative integer `age_seconds`, or `status=unknown` and `age_seconds=null`.
Age comes from the publication timestamp, not file mtime. Unknown or old age
preserves the existing readiness classification and requires a separate monitor
policy. This is a local encrypted-publication observation, not off-host,
producer-authenticity, restore or PITR assurance. See the
[monitoring checklist](../runbooks/monitoring.md) and
[PITR template](../runbooks/point-in-time-recovery.md).

## Sessions and cookies

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SESSION_MAX_AGE_SECONDS` | int (60–31536000) | `28800` (8h) | Absolute session/cookie lifetime; staging and production cap it at eight hours. Setup/recovery database sessions are capped at ten minutes. |
| `SESSION_IDLE_TIMEOUT_SECONDS` | int (60–28800) | `1800` | Server-side inactivity expiry; an expired session cannot be revived by a later request. |
| `SESSION_ACTIVITY_UPDATE_INTERVAL_SECONDS` | int (1–300) | `60` | Minimum interval between activity writes; must not exceed the idle timeout. |
| `SESSION_COOKIE_NAME` | str | `oha_session` in dev; `__Host-oha_session` when hardened | Cookie name for the signed session ID; hardened custom names must keep `__Host-`. |
| `COOKIES_SECURE` | bool | `true` | `Secure` flag on the session/CSRF/pre-session cookies. May be `false` **only** for local plaintext-HTTP development; a validator enforces `true` in staging/production |

`SESSION_COOKIE_NAME` must be a valid nonempty cookie name, distinct from both
CSRF/pre-session names. Hardened fixed names are `__Host-oha_csrf` and
`__Host-oha_pre_session`; development keeps `csrf_token` and `pre_session_id`.
All host-prefixed cookies require Secure, root Path and no Domain, including
when they are deleted. Hardened lookup ignores legacy unprefixed names, and
ambiguous duplicate active security-cookie names are rejected. Plan a fresh
login at the naming cutover. Ordinary hardened mutations require the canonical
Origin, or a canonical Referer fallback; missing both is rejected. See the
[browser and bootstrap runbook](../runbooks/bootstrap-admin.md).

## Authentication

| Variable | Type | Default | Notes |
|---|---|---|---|
| `LOCAL_REGISTRATION_ENABLED` | bool | `true` in dev; `false` when hardened | Explicitly enable new local registration in staging/production; existing local users can still sign in when disabled. |
| `TOTP_ISSUER_NAME` | str | `SITE_NAME` | Blank or omitted uses the site name; an explicit single-line value overrides it. Affects new enrollment/rotation labels only; existing authenticator entries and codes remain valid. |
| `LOGIN_FAILURE_THRESHOLD` | int (≥1) | `10` | Failed logins before an account is locked |
| `LOGIN_LOCKOUT_MINUTES` | int (1–10080) | `15` | How long an account stays locked; maximum 7 days |
| `SESSION_STEP_UP_ATTEMPT_LIMIT` | int (1–100) | `5` | Credential step-up submissions allowed during one full session, shared across all sensitive step-up routes. The next submission revokes that session. |
| `TOTP_ROTATION_CONFIRMATION_ATTEMPT_LIMIT` | int (1–100) | `5` | Confirmation-code submissions allowed for one staged authenticator rotation. Exhaustion discards only that staged rotation. |
| `UNVERIFIED_REAP_AFTER_DAYS` | int (1–3650) | `7` | Delete unverified local accounts older than this (scheduler job); maximum 3650 days |
| `PASSWORD_WORK_CONCURRENCY` | int (1–2) | `1` | Maximum concurrent password operations per web worker; size with request and memory limits |
| `PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS` | finite float (0.01–5) | `1.0` | Maximum queue wait for each password operation; saturation returns HTTP 503 with `Retry-After: 5`. Running work retains its slot until completion. |

**Local sign-in policy** `LOCAL_REGISTRATION_ENABLED=false` closes new local sign-ups; it does not disable `/login`, deactivate existing local accounts, or revoke their sessions. `LOCAL_AUTH_ENABLED` is obsolete and is rejected with migration guidance. This is deliberate: the initial administrator is a local account, while a newly asserted Shibboleth identity starts pending and non-admin and needs administrator approval. Disabling local login after deployment could leave no usable administrator, including if a switch were changed accidentally. A future Shibboleth-only policy needs an explicit administrator bootstrap, migration, and recovery path before local sign-in can be retired; changing the registration setting is not that transition. See [authentication architecture](../architecture/auth.md#local-sign-in-and-registration-policy).

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

`ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` are no longer service settings.
Remove legacy assignments and run the one-shot `scripts/bootstrap_admin.py`
command from a protected terminal. The command reads the password without echo,
rejects published placeholders and never promotes an existing account. See
[initial administrator bootstrap](../runbooks/bootstrap-admin.md).

## Shibboleth (Phase 2 deployment)

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SHIBBOLETH_ENABLED` | bool | `false` | Enables the `/auth/shibboleth/callback` route |
| `SHIBBOLETH_INTERNAL_SECRET` | SecretStr \| None | `None` | Secret injected by nginx as `X-OHA-Internal-Auth` on the callback and verified in constant time. **Required whenever Shibboleth is enabled, in every environment** — startup fails without it. Leave unset in Phase 1. |
| `SHIBBOLETH_TRUSTED_ISSUERS` | list[str] | `[]` | Exact absolute HTTPS IdP entity IDs accepted by the callback. Must be non-empty when Shibboleth is enabled; HTTP, URN, relative, blank, whitespace/control-bearing, malformed-host, duplicate, wildcard, comma-bearing, and substring entries are rejected. Configure as a JSON list, for example `["https://idp.example.org/idp/shibboleth"]`. |
| `FEDERATED_TIER_RULES` | tuple of immutable rule models | `[]` | Ordered JSON rule list. Supplied match predicates combine with AND; the first match produces an advisory tier and rule snapshot. Malformed rules block settings construction even when federation is disabled. Each trusted assertion refreshes the stored proposal and rule for explicit administrator review; rules never assign authority. |

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
`X-OHA-Shib-Entitlement`, `X-OHA-Shib-Country`, and
`X-OHA-Shib-Authn-Context`. nginx must overwrite
each one from an SP-controlled value on the exact callback location and clear
them elsewhere. The callback accepts only the exact authentication context
`https://refeds.org/profile/mfa`; there is deliberately no environment setting
that can weaken this requirement. The optional entitlement header is bounded
to 4096 decoded characters and uses the same duplicate, UTF-8, printability
and raw-length checks as the other fixed optional headers. The supplied SP
variable alias is `entitlement`; confirm its installed attribute map before
activation.

[Federated tier proposals](../architecture/federated-tier-rules.md) defines
the exact rule schema, entitlement value decoding and review contract. Changing
`FEDERATED_TIER_RULES` requires restarting the web process to load the new
immutable configuration. It does not change the session-authority fingerprint
and cannot grant a tier, approve an identity or revoke a session.

The first accepted assertion for an unknown issuer/subject pair creates an
inactive, public, non-admin, unverified pending row with no approval metadata
and no session. The latest trusted issuer, affiliation, entitlement serialization,
proposal and matched rule are stored separately for review. An administrator
must use the dedicated exact-pair approval action with the current review revision
to choose the tier, activate it, record approval actor/time, bump
`auth_revision`, and delete every target session before a later assertion can
log in. Generic tier/admin/reactivation actions cannot release it. Email never
links accounts, and tier/admin values never come from headers. The approval form
defaults to `public`; a proposal does not preselect the grant. Later changed
proposals are flagged against the proposal reviewed at approval, including an
explicit no-match baseline, without changing the chosen tier or revoking sessions.
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
| `REDIS_URL` | SecretStr | `redis://localhost:6379/0` | Required when enabled; query parameters/fragments are rejected; remote hardened TCP requires TLS |

`REDIS_ENABLED` selects the optional general Redis for catalogue-cache pub/sub.
The security-counter store is separate: hardened web processes require
`RATE_LIMIT_REDIS_URL`, even when `REDIS_ENABLED=false`. Gunicorn's worker count
depends on the dedicated limiter URL, not the general Redis flag. The general
Redis may be absent without weakening shared rate limits.

Redis URLs select a destination and credentials; they cannot override client
options. Neither Redis URL accepts a query string or fragment, including an
empty `?` or `#`. Use `rediss://` for remote TCP outside development; plaintext
TCP is limited to loopback. The general client supports `unix://` and the
limiter supports `redis+unix://` for absolute local socket paths. TLS requires
certificate and hostname verification. Configure trust through the host's
certificate store rather than disabling verification in a URL.

After construction, both clients validate the effective connection-pool
options. Admission uses at most 0.5-second connect/read timeouts; the optional
cache client uses at most two seconds. Both disable automatic retries. Failed
policy checks and connection errors are reported without credential-bearing
URLs or dependency exception text.

With `REDIS_ENABLED=false` in production, Settings emits a warning about
catalogue-statistics freshness. Cross-worker invalidation is unavailable,
so cached statistics may remain stale until the one-hour cache TTL expires.
This warning does not relax the separate hardened-web requirement for
`RATE_LIMIT_REDIS_URL`.

## Runtime sources

| Variable | Type | Default | Notes |
|---|---|---|---|
| `SOURCES_CONFIG_FILE` | str \| None | `None` | Source TOML path required by web/scheduler startup. Empty normalizes to `None`; runtime selection then refuses startup. Settings construction does not open the file. |
| `ALLOW_FIXTURE_SOURCE` | bool | `false` | Explicit permission for configured fixture adapters in production; does not select a fixture. |

Web and scheduler require an explicit `SOURCES_CONFIG_FILE` selection. Both read
and validate that file once before opening runtime resources, then retain its
ordered source tuple until restart. Missing or empty selection, file errors,
invalid configuration and startup-policy failures abort startup without fallback.
The web tuple contains nonsecret `CatalogueSource` metadata and pure policy;
only the scheduler constructs fetch adapters and resolves feed secrets. Place
feed bearer/signing variables only in `scheduler.env`, never `common.env` or
`web.env`. The web rejects selected feed credential variables even when empty.
The same source descriptions produce the same catalogue policy fingerprint in
either process. Before serving requests, web startup verifies its fingerprint
against the durable database binding and rejects a mismatch.

Per-source `incremental_interval_seconds` and `rebuild_interval_seconds` accept
strict TOML integers from 1 to 31536000 seconds (365 days). Their defaults remain
3600 and 86400 seconds. `write_timeout_seconds` remains bounded to 1–3600 seconds.
`rebuild_max_inferred_delete_count` accepts nonnegative integers (default 100),
and `rebuild_max_inferred_delete_ratio_percent` accepts integers from 0 to 100
(default 25). Both limits apply to absence-based full-rebuild deletions. See
[source configuration](../sources/index.md#configure-sources-in-toml) for a
temporary, source-specific contraction acceptance procedure.

Settings may be constructed without a selection for imports, migrations and
offline inspection. Surrounding path whitespace is rejected. The shipped
`.env.example` explicitly selects `deploy/environment/sources.dev.toml` for
offline development through normal ingestion.

Development permits ordinary readable relative or absolute paths. Staging and
production require a direct absolute POSIX path without parent traversal or
symlink components. The file and every opened directory must be root-owned and
not group/other-writable. Both runtime identities need directory read/search
access and file read access. Actual selected endpoints receive adapter-specific
startup validation.

The seven former global source settings are removed and rejected, even when
empty. Their replacements are flat fields in each `[[sources]]` entry:

| Removed setting | Source-TOML field |
|---|---|
| `SWISSUBASE_OAI_PMH_URL` | `endpoint` |
| `OAI_INSTITUTION_FILTER` | `institution_filter` |
| `SWISSUBASE_MAX_VISIBILITY` | `max_visibility` |
| `SYNC_INTERVAL_SECONDS` | `incremental_interval_seconds` |
| `FULL_REBUILD_INTERVAL_SECONDS` | `rebuild_interval_seconds` |
| `OAI_MAX_PAGES` | `max_pages` |
| `SYNC_WRITE_TIMEOUT_SECONDS` | `write_timeout_seconds` |

Before removing an existing OAI deployment's environment variables, transfer
their effective values into reviewed TOML. Preserve source name `swissubase`,
the exact endpoint, effective institution filter, `max_visibility` and
`requires_record_tier=false` to preserve its ingestion binding. The former
Settings validator stripped institution-filter whitespace; copy that effective
value. Preserve nondefault page limits, intervals and write timeout.

Changed interpretation inputs fence incremental ingestion until an
authoritative rebuild succeeds. Stored row classification changes through
ingestion. A revised serving policy requires an explicit owner transition of
the durable binding; current source and field minima then apply to existing
rows. Web reads, including cached statistics, refuse a superseded fingerprint
until the worker loads the current configuration. Unselecting a source does not
delete its catalogue rows.

`deploy/environment/sources.example.toml` demonstrates the strict flat format.
Review its placeholders and fixture entry before deployment. Keep both runtime
services stopped during configuration replacement, remove retired variables
from all environment files and overlays, then restart both with the same file
revision. Production fixture sources require `ALLOW_FIXTURE_SOURCE=true`.

### Resource-link logging

`log_resource_access` belongs to each flat `[[sources]]` TOML entry, not to an
environment variable. It accepts only booleans and defaults to the resolved
`requires_record_tier` value. `true` displays internal links that recheck the
current metadata tier and audit successful redirects; explicit `false` displays
safe direct resource/landing links. Retained unknown or unselected sources use
internal links conservatively. Calling the internal route directly still audits
a successful redirect even when the display setting is false.

Both processes retain source configuration until restart. Apply a changed
setting through the existing reviewed source-file replacement/restart procedure;
this flag does not change ingestion fingerprints or require a rebuild. It does
not change metadata tiers or upstream material authorization. See
[Resource access and audit](../architecture/resource-access.md).

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
| `CONTACT_EMAIL` | str | `archive@example.org` | Shown on the About page and in emails |

Settings requires `SMTP_USER` and `SMTP_PASSWORD` together. With SMTP enabled,
omitting both credentials selects an unauthenticated relay. If a username is
configured but its password is missing at send time, SMTP delivery is refused
and reported as a temporary failure.

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
| `RATE_LIMIT_ENABLED` | bool | `true` | Required true for staging/production web processes; development may disable per-client quotas |
| `RATE_LIMIT_REDIS_URL` | SecretStr | empty | Dedicated hardened-web Redis URL; dev falls back to enabled general Redis, then memory |
| `LIMITER_COUNTER_CAPACITY` | int (1–20000) | `20000` | Maximum simultaneously registered fixed-window counters in the bounded Redis store; share one value across workers |
| `LIMITER_CLEANUP_BATCH_SIZE` | int (1–1024) | `128` | Maximum expired registry entries reclaimed in one bounded cleanup pass |
| `RATE_LIMIT_PER_MINUTE` | int (≥1) | `100` | Per client IP |
| `RATE_LIMIT_PER_HOUR` | int (≥1) | `1000` | Per client IP |
| `RATE_LIMIT_PER_DAY` | int (≥1) | `10000` | Per client IP |
| `RATE_LIMIT_TRUST_PROXY` | bool | `false` | Trust `X-Real-IP` / `X-Forwarded-For` from trusted upstreams. **Must be `true` in production when rate limiting is enabled** — startup is blocked otherwise, because per-IP limits behind nginx would collapse onto the proxy's IP |

Use redis://, rediss:// or redis+unix:// without query parameters or fragments.
Hardened settings and web preflight enforce DB 0, a non-default named ACL user
with a password, and TLS for remote TCP. Settings also checks credential reuse.
Provision an independently generated strong password and separate limiter/general
Redis processes; validate the actual server ACLs and physical isolation during
deployment. Put the limiter credential only in web.env.
Startup probes it and later failures return 503; there is no hardened memory
fallback. REDIS_ENABLED controls optional catalogue-statistics pub/sub.

Do not disable admission to recover from a Redis outage. Keep the web service
closed or return the existing retryable refusals while restoring the dedicated
backend. Preserve its live counters and persisted policy. Re-run the documented
readiness probe, restart the web service with admission enabled, and reopen
traffic only after readiness succeeds. Maintenance access should use an
independently restricted administrative channel, not an unrestricted public app.

Redis admission tracks actual counter keys in a bounded expiry registry. A new
counter is refused at the configured capacity; live counters are not evicted or
reset to make room. Expired entries are reclaimed in bounded batches. Existing
registered counters retain their values and deadlines. The counter-key byte
limit and fixed number of control keys bound additional state independently of
client-address diversity. Capacity refusal returns the same fail-closed 503 as
other unavailable admission storage; it does not execute the protected route or
create an in-memory fallback quota.

The 20,000-counter default is a ceiling, not a promise that a particular Redis
host has sufficient headroom. Account for the expiry registry, key bytes, AOF
and allocator overhead when validating the reference 128 MiB `maxmemory`.
Use [the deployment procedure](../../Deployment.md#limiter-capacity-and-existing-counters)
for capacity selection and an upgrade from unregistered legacy counters. Keep
all live counter data; never flush the store to make startup pass.

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
PARSER_EXECUTION_MODE=local
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
SOURCES_CONFIG_FILE=deploy/environment/sources.dev.toml
ALLOW_FIXTURE_SOURCE=false
```

The web process migrates in dev; the scheduler harvests and writes queued mail
to .dev-mailbox. Export ENV_STATE=dev before launch and use the protected
bootstrap command when an administrator is needed. See the full example for
optional settings.

## Mailbox and outbox retention

| Variable | Default | Meaning and range |
|---|---|---|
| `DEV_MAILBOX_DIR` | .dev-mailbox | Nonempty path relative to the scheduler working directory; private .eml output when SMTP is off in dev |
| `OUTBOX_SENT_RETENTION_DAYS` | 7 | Sent-row retention, 1–3650 days |
| `OUTBOX_DEAD_RETENTION_DAYS` | 30 | Dead-row retention, 1–3650 days |
| `OUTBOX_RETENTION_BATCH_SIZE` | 1000 | Maximum deleted per status per pass, 1–5000 |
| `OUTBOX_RETENTION_INTERVAL_SECONDS` | 60 | Cleanup interval, 1–60 seconds |
| `OUTBOX_STALE_AFTER_SECONDS` | 600 | Pending/sending age warning threshold, 60–86400 seconds (maximum 1 day) |

Cleanup leaves pending/sending rows intact. Read health-detail JSON and scheduler
logs to detect backlog; configured throughput is a ceiling, not a delivery SLA.

Integer duration settings reject booleans. Numeric environment strings remain
supported. Session creation, session-cookie and unverified-account-reaper
overrides require actual Python integers within the same documented ranges;
invalid values raise `ValueError` before signing, SQL or connection acquisition.
`None` selects the corresponding configured default on wrappers that expose it.

The session, lockout, unverified-account and outbox-warning maxima are supported
operational policy, not the mathematical limits of Python timestamps. Change
them through a reviewed edit to `src/app/duration_contract.py`, then update the
reference, examples and boundary tests together. The database-timeout maximum
is PostgreSQL's representable millisecond range and must not be raised as a
policy adjustment. Existing defaults are unchanged; no schema change is needed.

`DEV_MAILBOX_DIR` selects the development mailbox directory.
`OUTBOX_RETENTION_INTERVAL_SECONDS` (default 60, range 1–60) controls retention
frequency independently of `OUTBOX_RETENTION_BATCH_SIZE`. At defaults each
status has capacity for 60,000 deletions/hour, above the sender's maximum
2,400 deliveries/hour. Choose batch size/cadence with headroom over arrivals.
