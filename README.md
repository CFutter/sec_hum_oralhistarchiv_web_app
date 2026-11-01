# Digital Oral History Archive

Search and browse oral-history metadata from configured sources through a
server-rendered catalogue with public, registered and vetted metadata tiers.

The application includes OAI-PMH/CMDI, deterministic bundled fixture, static
JSON proof and authenticated JSON-feed adapters. Each selected source has its
own identity, visibility policy, display labels, schedule and synchronization
state. PostgreSQL serves catalogue requests; a separate scheduler imports
source data.

> Development version `0.1.0`. Real-source approval, representative recovery
> and deployment activation require separate acceptance. See
> [Known Limitations](#known-limitations) and [Remaining Work](#remaining-work).

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
- [Code Quality and Security Tooling](#code-quality-and-security-tooling)
- [Security Model](#security-model)
- [Documentation](#documentation)
- [Known Limitations](#known-limitations)
- [Remaining Work](#remaining-work)
- [License](#license)

## What This Is

The Oral History Archive is a search and browse interface for research-dataset
metadata. Configured adapters import metadata into a local PostgreSQL catalogue;
FastAPI and Jinja2 serve it through a web interface. The upstream repository
remains responsible for access to recordings and other linked materials.

Every dataset has a `visibility_tier`: `public`, `registered` or `vetted`.
Viewers below that tier receive only the public discovery envelope: `id`,
`uuid`, `title`, `access_level`, `version`, `source` and `visibility_tier`.
Source owners must approve those values, record existence and their combination
for unrestricted publication. A higher metadata tier does not conceal that
envelope.

Every metadata field also has a code minimum and may have a stricter immutable
source minimum. Protected fields require the strictest record/code/source tier;
meeting the record tier alone does not bypass a raised field minimum. The seven
public discovery fields remain public. See the
[field policy](docs/architecture/field-visibility.md) for all 22 classifications,
source override syntax and restart behavior.

SQL prevents restricted metadata from contributing to unauthorized search and
filter matches. Dataset services then redact returned objects before they
reach templates. PostgreSQL RLS additionally limits raw web-role rows by the
effective record tier. Narrow owner-backed views preserve public discovery and
administrator identity/state controls. Field minima still require the matching
application SQL/redaction/template rules; RLS does not redact individual columns.

Source policy resolves each incoming metadata tier. A valid explicit upstream
assertion can tighten or lower it automatically; an omitted tier retains the last
accepted restriction. Eligible administrators can impose
a durable visibility floor or hide and restore an identity through
**Admin → Dataset administration**. Those restrictions survive synchronization,
rebuilds and deletion followed by reintroduction of the same `(source, uuid)`.

Administrator-hidden records are excluded from catalogue detail, search,
facets, recent records and counts at every viewer tier. Administrator status
does not bypass metadata-tier enforcement. Changing source configuration alone
does not immediately reclassify existing records.

See [access control](docs/architecture/access-control.md) and the
[emergency withdrawal runbook](docs/runbooks/emergency-dataset-withdrawal.md).

### Audiences

| Audience | Access |
|---|---|
| Public visitors | Public discovery fields for served records and other fields whose effective record/code/source requirement is public |
| Registered-tier users | Fields requiring public or registered; creating a local account alone leaves its tier public |
| Vetted users | Full catalogue metadata at all three tiers; external resource access remains governed upstream |
| Administrators | Account and dataset administration; administrator status does not grant a higher metadata tier |

## Key Features

| Area | Implemented behavior and contract |
|---|---|
| Ingestion | Four adapters, bounded isolated source work, durable staging, reconciliation and source-specific policy; [ingestion](docs/architecture/sync.md) |
| Catalogue | Field-aware search, filters, opaque continuation, tier redaction and durable hiding; [access control](docs/architecture/access-control.md) |
| Accounts | Mailbox-first registration, password/TOTP, recovery and reviewed federation; [authentication](docs/architecture/auth.md) |
| Operations | Separate web/scheduler identities, shared admission, transactional mail and encrypted backup tooling; [deployment](Deployment.md) |

## Architecture at a Glance

nginx terminates HTTPS and proxies over a Unix socket to Gunicorn/Uvicorn web
workers. Workers validate sessions, render pages, query PostgreSQL and enqueue
mail. Hardened web admission uses a dedicated security-counter Redis service.

The standalone scheduler harvests selected sources, delivers queued mail and
runs cleanup. It owns APScheduler and has its own PostgreSQL pool. Web workers
never start ingestion jobs. Optional general Redis distributes catalogue-cache
invalidation separately from security counters.

Both processes load the same source file. Web workers retain nonsecret
catalogue metadata and reject selected feed credential variables. Only the
scheduler resolves feed credentials and constructs fetch adapters. Snapshots
remain fixed until restart.

The JSON-feed adapter performs complete source fetching, parsing, validation and
serialization inside one spawned worker. Parent reconstruction uses the bounded,
validated result and checks the same deadline; that reconstruction is not
separately force-terminable.

See [ingestion architecture](docs/architecture/sync.md) for transaction,
recovery, cursor and worker boundaries.

## Technology Stack

FastAPI, Jinja2, psycopg/PostgreSQL, Alembic, APScheduler and Redis. The reference
production deployment uses Gunicorn/Uvicorn behind nginx.

CI uses Python 3.11 and PostgreSQL 18. Release tooling requires Python 3.11;
the reference deployment uses PostgreSQL 18. Package metadata permits Python
3.11 and later; other Python series are not covered by the current CI/release
process. Dependencies and pinned versions are recorded in `pyproject.toml` and
`uv.lock`.

## Project Layout

| Path | Purpose |
|---|---|
| `src/app/sources/` | Adapter protocol, registry, source models, feed validation, transport and startup policy |
| `src/app/routes/` | HTTP handlers and route access declarations |
| `src/app/services/` | Authentication, catalogue reads, dataset administration, ingestion, outbox and persistence |
| `src/app/middleware/` | Admission, sessions, CSRF, audit and security checks |
| `src/app/templates/`, `src/app/static/` | Server-rendered UI and assets |
| `src/config/` | Process settings and logging |
| `src/alembic/` | Schema migration and revision template |
| `src/tests/` | Unit, client, adapter-conformance and integration tests |
| `run.py`, `run_scheduler.py`, `dev.sh` | Development web, scheduler and combined launcher |
| `oralhistarchiv*.service`, `deploy/` | Reference deployment units, policies and helpers |
| `scripts/` | Release, verification and maintenance tools |
| `docs/`, `mkdocs.yaml` | Documentation sources and site configuration |

## Quick Start

### Prerequisites

- Python 3.11.
- PostgreSQL 18 and a disposable development database.
- [uv](https://docs.astral.sh/uv/) for the locked project environment.

### Option A: DevContainer

The DevContainer provides Python 3.11, PostgreSQL 18 and matching client tools.
Open `/workspaces`; setup installs locked dev/doc dependencies and creates `.env`
only when absent, using host `db`. Review existing `.env` files yourself.
The PostgreSQL 18 volume is `postgres-data-pg18`, mounted at `/var/lib/postgresql`;
it starts a fresh cluster and does not reuse the former development volume.

Review the database URL and source selection, then run the combined launcher
from the repository root. Bootstrap an administrator interactively after startup.

### Option B: Manual setup

These commands assume a local Linux PostgreSQL server with postgres peer access:

```bash
uv sync --locked --extra dev --extra doc --python 3.11

# Create this OS user's database role once; skip if it already exists.
sudo -u postgres createuser --createdb "$(id -un)"
createdb oralhistarchiv

# Copy only when you do not already have a local configuration to preserve.
cp .env.example .env
```

Set `DATABASE_URL="postgresql:///oralhistarchiv"` in `.env` for local peer
access, or use the working development URL for your database host. Remove any
legacy `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` assignments: runtime services
reject them. The example signing/encryption keys are public development values
and must not be deployed. Start the processes below before bootstrapping an
administrator so development migrations have initialized the database.

The copied example selects only `fixture_demo` through
`deploy/environment/sources.dev.toml`. Start both processes with that explicit
selection:

```bash
ENV_STATE=dev \
SOURCES_CONFIG_FILE="$PWD/deploy/environment/sources.dev.toml" \
ALLOW_FIXTURE_SOURCE=false \
uv run bash dev.sh
```

The scheduler imports three bundled synthetic records through normal ingestion,
with public, registered and vetted metadata tiers. This selection makes no
upstream request. The web process does not populate the catalogue.

`dev.sh` first validates the application settings and requires the effective
`ENV_STATE` to be `dev`, then runs the development migration and starts scheduler
and web. Invalid settings or a non-development environment stop the launcher
before migrations or child processes begin.
The web lifespan also checks/runs development migrations. A fresh selected
source has no committed fingerprint, so its immediately due incremental job
requests an authoritative rebuild through the normal scheduler recovery path.
Periodic rebuilds remain scheduled independently.

When an administrator is needed, leave the launcher running and use another
interactive terminal from the repository root:

```bash
ENV_STATE=dev uv run python scripts/bootstrap_admin.py --email operator@example.org
```

Enter a fresh password when prompted, complete authenticator/recovery-code
enrollment in the browser, then verify a fresh login. See
[bootstrap](docs/runbooks/bootstrap-admin.md) for the protected deployment command.

### Web startup order

1. Configure logging and, in development, warn about unconsumed dotenv keys.
2. Validate security settings and load nonsecret source metadata; reject
   selected feed credential variables in the web environment.
3. Validate route access declarations and probe the rate-limit backend.
4. Warm the password blocklist and dummy password hash.
5. Run Alembic migrations in development only.
6. Open ordinary and dedicated search PostgreSQL pools and validate runtime
   schema, invariants and applicable role contracts.
7. Reconcile federated-session policy and initialize the selected-source
   statistics cache.

Web startup neither provisions source-status rows nor harvests catalogue data.
The scheduler independently validates security and selects sources before
opening its pool. It validates schema/role contracts, provisions selected source
rows, then constructs the jobs. It does not depend on successful web startup.

## Configuration

Export exact OS key `ENV_STATE=dev`, `staging` or `production` before launch.
Only development reads the checkout's `.env`; OS values take precedence.
[Settings](docs/configuration/settings.md) documents every process variable,
default, range and validation rule; `.env.example` is the annotated dev example.

Both processes require the same explicit `SOURCES_CONFIG_FILE`. Source identity,
policy, schedules and adapter inputs use flat TOML; see
[Sources](docs/sources/index.md) and [feed configuration](docs/sources/json-feed-configuration.md).
Hardened source files require the protected absolute-path procedure. Only the
scheduler receives feed credentials; selected credential variables make web
startup fail. Snapshots remain fixed until restart. Changed catalogue policy
also requires an [owner transition](docs/runbooks/search-policy.md).

Use [Deployment](Deployment.md) for separate common/web/scheduler/migration
profiles, generated independent secrets and restart order. Remove retired
settings rather than assigning empty/false values. Follow
[key rotation](docs/runbooks/key-rotation.md) before replacing or removing keys.

## Running the Application

### Development

Run from the repository root with reviewed development settings:

```bash
export ENV_STATE=dev
uv run bash dev.sh

# Or run in separate terminals with the same source selection:
uv run python run.py
uv run python run_scheduler.py
```

`dev.sh` requires Bash 4.3+ and validates the same environment/dotenv settings as
the application before migrating or launching either child. Only an effective
`ENV_STATE=dev` is accepted; staging and production use the reviewed workflow in
`Deployment.md`. It propagates the first child's exit status,
terminates the sibling and reaps both children. Scheduler shutdown allows a
300-second drain and a five-second cancellation grace period before closing
resources.

The example web address is `http://127.0.0.1:5000`. `FASTAPI_DEBUG=true` enables
API documentation and unauthenticated `/health/detail` only in development.
Development warning behavior is controlled by `ENV_STATE`, not that debug flag.

With `SMTP_ENABLED=false`, the scheduler writes queued messages into the private
`.dev-mailbox/` directory. Open its `.eml` files in a mail reader to complete
development account flows. The web process queues mail but does not deliver it.

Local registration starts with email only. Follow the delivered setup link to
choose the password/profile, then log in and complete authenticator enrollment.
Open the public link, paste the separate security code from the same email
into the form, then submit it. The code is the credential; the link alone grants
no action. No JavaScript is required. See the
[action-link procedure](docs/runbooks/action-links.md) for code entry, cutover
and edge logging limits.

### Production

Use the reviewed release and systemd procedures in [Deployment](Deployment.md).
Web and scheduler are separate long-running services with peer-authenticated
non-owner database roles. The manual migration unit is not enabled at boot;
migrations and grant reapplication run while runtime services are stopped.
Runtime startup never migrates hardened databases.

This explicitly approved pre-deployment reset keeps one fresh-install revision,
`4f73ae3ff827`. It includes catalogue RLS, narrow views, consumed-snapshot cursors,
the bounded password-reset proof window and password-change notification mail.
Initialize an empty database using `upgrade head` through the manual migration
unit and apply the matching runtime grants before starting the release. The
backup script pins the same single head.

After migration, users and catalogue records are empty. Configured sources
populate the catalogue; registration and explicit administrator bootstrap create
accounts. The repository contains no deployment data or pre-created accounts.

Recreate databases initialized from an earlier body of this baseline before
using this release: `upgrade head` does not rerun an already recorded revision,
and stamping cannot repair the missing structure. The operator owns that reset;
application/updater tools do not recreate databases. Verify the complete schema
and runtime-role inventories after initializing the new database. There is no
forward migration for an existing database in this pre-deployment release.

The baseline keeps revision-local SQL snapshots; changing current application
SQL cannot change its replay. An explicitly reviewed reset before the first
retained deployment must update the snapshots and SQL regression pins together.
After that deployment, preserve old revisions and introduce a new reviewed
migration for every schema change. See [migration history](src/alembic/README).

Release builds require a clean checkout matching the requested commit. The
deployment checklist separately binds that commit to the approved CI run.
A source archive alone is not a reviewed production release.

Public registration, federation and a real sensitive source each require their
own activation evidence. Enabling one does not establish acceptance of the
others.

### Health checks

| Endpoint | Access | Meaning |
|---|---|---|
| `GET /health` | Public; exempt from application rate admission | Handler liveness only: `200 {"status":"alive"}`. It does not check dependencies; outer middleware/nginx may still reject a request. |
| `GET /health/detail` | Bearer token outside debug; unauthorized requests receive 404 | Database/pool availability, per-source history, outbox diagnostics and optional backup-publication age. Dependency unavailability can return 503; source/outbox degradation can return 200 with `"status":"degraded"`. Backup age is informational and needs its own monitor policy. |

The diagnostic route also passes through normal admission, which can return a
generic retryable 503 during limiter storage/capacity incidents. Monitoring must
check response type and body as well as status.

Source freshness uses each selected source's own schedule and recorded
timestamps. It is not a live upstream probe or evidence of sensitive-source
acceptance. Authorized `checks.backup` reports `status=ok` and integer
`age_seconds` from the optional local marker, or `status=unknown` and a null age.
It does not change readiness or prove off-host receipt, restore or PITR. Use the
[monitoring checklist](docs/runbooks/monitoring.md) for every degraded cause and
independent backup/capacity checks; the [PITR template](docs/runbooks/point-in-time-recovery.md)
requires an approved physical-backup/WAL design and isolated replay evidence.

## Testing

Tests combine controlled doubles, real spawned-worker and local TLS probes,
and PostgreSQL integration tests. The shared limiter fixture uses Redis and may
reset counters, so all test services must be disposable.

Before switching an existing Compose test cluster to PostgreSQL 18, remove its
disposable data with `docker compose down --volumes`, then start it again.

```bash
uv run pytest --collect-only -q

# Unit and client tiers, with a disposable Redis service available.
uv run pytest -m "not integration"

# Start disposable services, then require the real-service integration tier.
docker compose up -d db redis
REQUIRE_DB=1 REQUIRE_REDIS=1 uv run pytest -p no:randomly

# Local application/configuration branch-coverage report.
uv run pytest --cov=src/app --cov=src/config --cov-branch --cov-report=html
```

The integration URL defaults to the disposable Compose test database. Its
fixtures truncate data and must never target a development/staging catalogue.
`REQUIRE_DB=1` and `REQUIRE_REDIS=1` turn unavailable required services into
failures instead of permitted local skips. An all-skipped test run can otherwise
exit successfully.

When the fresh baseline is edited during a planned database reset, recreate all
existing disposable test databases, including xdist worker databases. Reusing
the same Alembic revision with `upgrade head` does not retrofit that schema body.

Generic ingestion and shared client tests construct explicit OAI sources with
`src/tests/source_fixtures.py`. Shared adapter-conformance cases cover all four
registered adapters. JSON-feed cases explicitly prepare synthetic credentials;
dedicated tests exercise authenticated TLS, complete fetching, validation,
resource limits and worker termination.

Real development lifespans select `src/tests/sources.toml`, pinned by bootstrap
instead of inheriting an operator's selection. Individual tests override
configurations directly. Settings and runtime-selection tests exercise their
configuration boundaries explicitly. These test configurations are separate
from the shipped development fixture.

Development Settings can read the checkout's `.env`, but tests must explicitly
control every setting relevant to their assertions. Scheduler import tests use
a complete synthetic staging environment so a developer's web TOTP key cannot
enter through dotenv fallback. Keep development keys in their intended runtime
configuration; remove ambient configuration dependencies from the tests.

Unknown markers/configuration are rejected. Expected failures are strict: an
unexpected pass requires removing or updating the expectation. The
`known_defect` marker labels a regression and does not skip it. Measure collection
with `uv run pytest --collect-only -q`; CI currently enforces no minimum
collected-case count.

Redis coordination/fault tests need `redis-server` on `PATH` and start private
servers; logical databases do not isolate pub/sub or client-management commands.
Host-level checks also use `nginx` and `systemd-analyze`. Email-action forms
use ordinary HTML and explicit code entry; no JavaScript or Node test step is
required. `REQUIRE_NGINX=1` and
`REQUIRE_SYSTEMD=1` make missing binaries fatal. Permitted local skip pairs are
listed in `scripts/expected-skips.txt`; CI permits no skips.

CI runs the suite in serial collection order with `-p no:randomly`, and with
`-p randomly -n auto --maxprocesses 15`. Each job has separate services.
CI pins `TEST_RATE_LIMIT_REDIS_DB=0`, leaving databases 1–15 for worker counters;
a higher local base requires fewer workers. Reproduce randomized failures with
the recorded seed and worker count; worker timing/scheduling can still vary.

Search availability acceptance additionally exercises all query/pagination
modes under a shared start budget, busy global database lock and operation
expiry while ordinary login/detail traffic continues. See the
[search load procedure](docs/runbooks/search-fulltext.md#capacity-and-load-acceptance).
Validate bounded Redis counter capacity and restart persistence using the
[deployment procedure](Deployment.md#limiter-capacity-and-existing-counters).
Those load checks use disposable services and representative data.

Synthetic feed tests do not replace real-source disclosure approval, deployed
acceptance or representative backup/restore evidence.

## Code Quality and Security Tooling

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/app src/config run.py run_scheduler.py run_parser.py scripts gunicorn.conf.py
uv run mypy src/tests
uv run bandit -r src/app src/config run.py run_scheduler.py run_parser.py gunicorn.conf.py scripts
bash scripts/check-no-site-refs.sh
uv run mkdocs build --strict
```

CI additionally audits pinned runtime dependencies and builds/tests installed
release artifacts. Follow the exact commands in
[the CI workflow](.github/workflows/ci.yml) for dependency auditing, no-skip
checks and coverage gates. A local coverage report alone does not enforce them.

With branch coverage enabled, the current CI floors are 92.5% overall and 90%
for the reviewed security-module scope. Re-measure both CI orders when
enforcement code or coverage scope changes; use the lower measured result and
keep the floor no more than 1.5 percentage points below it.
`TestCIWorkflowGates` pins both the overall floor and the reviewed
security-module include patterns.

Both mypy scopes are blocking. The `tests.*` overrides allow unannotated test
functions; wholly unannotated bodies are not checked by default. A green local
selection does not establish full CI, strict-documentation or VM acceptance.

## Security Model

See [Security Layers](docs/architecture/security.md) for detailed boundaries.

| Concern | Implemented boundary and practical limit |
|---|---|
| Secret representations | Declared secret fields use masked types; feed credential snapshots exclude secret fields from their representation. Arbitrary text still requires review. |
| Weak keys | Necessary-condition strength checks plus required CSPRNG generation; passing a diversity check does not prove randomness. |
| SQL injection | Bound data values and safely composed identifiers; trusted static SQL fragments remain part of the reviewed code. |
| Metadata disclosure | Tier-gated SQL matching, Python result redaction and durable administrator hiding; public discovery values must be independently approved. |
| XML attacks | Entity resolution, external DTD loading and parser network access disabled; bounded OAI transport/process handling. |
| Feed authentication | Verified HTTPS, bearer authorization and exact-byte HMAC verification before decoding; signed request binding and freshness checks follow authentication. |
| Feed resource exhaustion | Seven configured budgets and a terminating complete-fetch worker; bounded parent reconstruction checks the deadline but is not separately force-terminable. |
| XSS | Jinja escaping, strict CSP and safe URL filtering. |
| CSRF and route drift | Declared access policies, mutation checks and startup route validation; only exact `POST /account/confirm-email` omits CSRF. |
| Sessions | Random server-side identifiers and signed cookies; login creates a fresh identifier. Revocation of a previous login session is best-effort and logs failure. |
| Registration | Email-only passwordless pending accounts, mailbox-bound setup, CSRF-protected completion and no automatic login; deployed relay/mailbox acceptance remains required. |
| Email-action transport | Non-secret public-ID GET forms and separately emailed codes entered in bound secret/public-ID POSTs; no JavaScript. The code remains a credential and obsolete/arbitrary edge request targets can still be logged. |
| Passwords and TOTP | Argon2id, password-policy checks, local email verification, lockout, encrypted TOTP secrets and consumed TOTP steps. |
| Brute force | Per-client admission and shared hardened Redis counters; addresses are HMAC-pseudonymized before storage. Entire-request timing is not constant. |
| Framing and transport | CSP frame restrictions, `X-Frame-Options: DENY` and production HSTS. |
| Cached private content | Dynamic application responses use `no-store`; reference nginx caching is limited to static assets. |
| Administrative authority | Eligible full sessions and transactional authority rechecks; admin status does not raise metadata tier. |
| Logging | Structured field redaction and bounded diagnostics; arbitrary message text and edge logs remain review surfaces. |
| Audit retention | Journald capture and optional remote shipping; independently controlled retention/integrity remains an operational responsibility. |
| Backups | Separate read-only identity, streamed `age` encryption, private state directory, atomic archives and off-host private-key custody. Restore/custody verification remains required. |

## Documentation

| Document | Scope |
|---|---|
| [Deployment](Deployment.md) | Reference VM installation, maintenance, identities, backups and activation gates |
| [Deployment checklist](docs/configuration/deployment.md) | Deployment policies, upgrade procedures and registration activation |
| [Settings](docs/configuration/settings.md) | Process settings and source configuration |
| [Ingestion](docs/architecture/sync.md) | Source adapters, scheduling, state, recovery, worker and transaction boundaries |
| [Access control](docs/architecture/access-control.md) | Public discovery envelope, metadata tiers and durable administrator restrictions |
| [Field visibility](docs/architecture/field-visibility.md) | Complete field classification, source minima, Python/SQL/template enforcement, RLS and recovery boundaries |
| [Resource access and audit](docs/architecture/resource-access.md) | Tier-checked stored redirects, source logging policy and application acceptance evidence |
| [Authentication](docs/architecture/auth.md) | Mailbox-first registration, sessions, local/federated authentication and route policies |
| [Federated tier proposals](docs/architecture/federated-tier-rules.md) | Ordered rules, stored trusted proposals, explicit review and later mismatches |
| [Federation integration](docs/runbooks/federation-integration.md) | Generic SP/header contract, staged activation, negative tests and rollback; real Gate F evidence remains separate |
| [Accounts](docs/user-guide/accounts.md) | Account setup, authentication, recovery and access-tier guidance |
| [Emergency withdrawal](docs/runbooks/emergency-dataset-withdrawal.md) | Dataset administration and the controlled operator fallback |
| [Laptop staging](docs/runbooks/local-staging.md) | Isolated staging topology and acceptance checks |
| [Key rotation](docs/runbooks/key-rotation.md) | Credential-specific rotation and custody procedures |
| [Monitoring](docs/runbooks/monitoring.md) | Per-source/outbox degraded-cause queries, publication age and independent operational checks |
| [Point-in-time recovery](docs/runbooks/point-in-time-recovery.md) | Physical base/WAL archiving, independent encrypted retention and isolated replay template |
| [Sensitive Source Contract](docs/architecture/source-b-ingestion-contract.md) | Mandatory sensitive-source acceptance criteria |
| [Feed Contract v1](docs/sources/feed-contract-v1.md) | Wire specification, JSON Schema, synthetic examples and evidence mapping |
| [JSON-feed configuration](docs/sources/json-feed-configuration.md) | Strict descriptions and explicit credential preparation |
| [JSON-feed transport](docs/sources/json-feed-transport.md) | Authenticated bounded page reads and transport-worker boundaries |
| [JSON-feed pages](docs/sources/json-feed-pages.md) | Strict JSON, request binding, freshness and page-chain identities |
| [JSON-feed records](docs/sources/json-feed-records.md) | Native metadata validation, quarantine and bounded candidate harvest bytes |
| [JSON-feed adapter](docs/sources/json-feed-adapter.md) | Complete isolated fetch, runtime credentials, fingerprints and cursor protection |
| [JSON-feed persistence](docs/sources/json-feed-persistence.md) | Signed-feed PostgreSQL coverage, committed-change auditing and remaining acceptance |
| [JSON-feed catalogue](docs/sources/json-feed-catalogue.md) | Signed native catalogue disclosure, search, facets, counts and correction/withdrawal acceptance |
| [JSON-feed acceptance](docs/sources/json-feed-acceptance.md) | Requirement evidence, encrypted synthetic recovery and remaining operational acceptance |
| [Roadmap](roadmap.md) | Development tracking and outstanding work |
| [Sources](docs/sources/index.md) | Adapter selection, configuration, visibility and source status |

Serve documentation with `uv run mkdocs serve` at `http://127.0.0.1:8000`.
Check it from the repository root:

```bash
bash scripts/check-no-site-refs.sh
uv run mkdocs build --strict
```

## Known Limitations

- **Actual sensitive-source acceptance remains open.** B1–B9 application work,
  including persistence, correction/withdrawal audits, catalogue checks and
  synthetic recovery, is accepted. Source-owner approval, actual-feed acceptance
  and representative encrypted restore remain open. Synthetic fixtures do not
  approve a real feed's public discovery envelope or classification.
- **WP E implementation is accepted; formal closure is pending.** E1–E4 field
  enforcement, row security and actual-role encrypted synthetic recovery are
  accepted. The [E5 record](docs/architecture/field-visibility.md#wp-e-implementation-acceptance-record)
  awaits the approved main commit, required checks and earlier E2 interface
  references; the new
  classification-drift check passes locally.
  Host peer, custody and representative deployed recovery remain separate open
  [operator records](docs/runbooks/visibility-recovery-acceptance.md).
  Shared-role application code remains trusted, and RLS does not enforce
  per-field minima for arbitrary SQL. WP L supplies generic compliance templates;
  completed institutional records, approvals and operational evidence remain open.
- **Source selection is not catalogue withdrawal.** Deselecting a source does
  not hide its stored records. Use dataset administration for supported
  emergency hiding and follow the withdrawal runbook.
- **Dedicated Redis is a hardened web dependency.** Required counter failures
  prevent startup or fail dynamic admission with a retryable 503. The optional
  general catalogue-cache Redis service does not control security quotas or
  Gunicorn worker count. Upgrades preserve live counter state; legacy counters
  require the documented maintenance-window expiry procedure, never a flush.
- **Federation requires independent activation.** Callback/approval code does
  not establish SP installation, attribute release, trusted MFA assertions or
  successful deployed login. Those need their own acceptance evidence.
- **Registration activation remains a deployment gate.** Mailbox-first
  registration is implemented. Public activation still requires acceptance
  through the deployment's production SMTP relay and a disposable mailbox.
- **Operational rehearsals remain separate.** Implemented dataset controls and
  backup tooling do not establish that the withdrawal runbook, representative
  restore or key-custody procedures have been executed successfully.

## Remaining Work

The [roadmap](roadmap.md) lists remaining implementation and operator outcomes.
Keep real-source, federation, registration, retained-state and recovery evidence
separate from synthetic tests and repository checks.

### Registration activation gate

Keep `LOCAL_REGISTRATION_ENABLED=false` until the deployment passes
[Gate R](docs/configuration/deployment.md#registration-activation-gate-r): real
relay/mailbox registration, single-use setup, authenticator enrollment and a
fresh login, plus CSRF, admission and lockout checks with disposable accounts.
Record results without credentials or security codes.

## Contributing and reporting

See [CONTRIBUTING.md](CONTRIBUTING.md) for development/review expectations and
[SECURITY.md](SECURITY.md) for private vulnerability reporting guidance.
[CHANGELOG.md](CHANGELOG.md) records unreleased changes, and
[CITATION.cff](CITATION.cff) provides citation metadata.

## License

The application is provided under the [MIT license](LICENSE). Bundled Source
Sans 3 fonts are licensed under OFL-1.1; the common-password list retains its
MIT notice. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution,
provenance and the accompanying license texts.
