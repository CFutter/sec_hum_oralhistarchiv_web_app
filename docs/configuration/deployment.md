# Deployment

This page is a high-level overview of how the application is meant to be deployed in production. The full step-by-step runbook with exact commands, file contents, and configuration snippets lives in **`Deployment.md`** at the repository root. That document is the operational source of truth; this page summarises the architecture and tells you what each piece is for.

## Target environment

Follow [Deployment.md](../../Deployment.md) for the reference Ubuntu host:
Python 3.11, PostgreSQL 18, nginx/TLS, isolated web/scheduler identities, a
dedicated persistent Redis limiter, and optional separate cache Redis. Backup
uses a read-only identity and age encryption; producer authenticity depends on
authenticated transfer and separately controlled retention.

## Component map

```mermaid
flowchart TD
    browser[Browser] --> nginx[nginx and TLS]
    nginx --> web[Web workers]
    web --> db[PostgreSQL]
    web --> limiter[Dedicated limiter Redis]
    web <--> cache[Optional cache Redis]
    scheduler[Scheduler] --> db
    scheduler --> cache
    scheduler --> source[Configured sources]
    scheduler --> smtp[SMTP relay]
```

Web workers enqueue mail in PostgreSQL; the scheduler delivers it. Journald
collects process logs; optional rsyslog forwarding is host configuration.

## Why this shape

A few of the choices in the reference deployment are non-obvious and worth motivating.

### Single VM

The supplied units and paths target one host. Multi-host deployment requires
separate review of scheduler ownership, database roles, secrets and proxy trust.

### Two systemd units: web and scheduler

The web app and the background scheduler run as **separate systemd services
and separate OS identities** (`oralhistarchiv.service` and
`oralhistarchiv-scheduler.service`). Running the scheduler in its own process
means ingestion and maintenance jobs fire once globally rather than
once per Gunicorn worker. The distinct UID is also load-bearing: a compromised
scheduler must not inherit the web user's access to the proxy socket or the
web-only Shibboleth secret. The scheduler has no HTTP surface; it is monitored
via `systemctl is-active` and the `sync_status` table.

### Gunicorn over a Unix socket

The FastAPI process binds to a Unix socket in `/run/oralhistarchiv/`, never to
a TCP port. The shipped units make the parent directory
`oralhistarchiv:oralhistarchiv-proxy` mode `0750`; Gunicorn creates the socket
with the same ownership and mode `0660`. Only the web identity and nginx's
verified worker identity may access that group. The scheduler has a distinct UID and
an explicit `InaccessiblePaths=-/run/oralhistarchiv`. Those exact ownership,
mode, group-membership, and no-TCP-listener facts must be verified on the host;
the source files alone do not establish the deployed boundary. The proxy UID
must run only the intended nginx workers: on a shared host, PHP-FPM or another
service under `www-data` would inherit socket access. Inventory its live
processes or use a dedicated nginx worker identity/instance.

### Redis for shared state

The dedicated limiter Redis backs slowapi's security counters across workers.
It has its own ACL, no-eviction policy and AOF so ordinary restarts retain live
quotas; it is excluded from backups. A separate, optional general Redis handles
best-effort catalogue-statistics pub/sub. With no dedicated limiter URL, development
uses a single Gunicorn worker. Hardened web startup requires the dedicated
limiter regardless of the general Redis setting.

The bounded backend caps live fixed-window counter allocations and refuses new
allocations without deleting live quotas. Startup validates retained registry
state and refuses unregistered legacy counters. Upgrade all web writers
together: preserve Redis/AOF, stop old writers and wait for their actual
remaining TTLs before starting the new release. This release requires that
maintenance-window procedure; never flush/reset the store or weaken `noeviction`. Capacity sizing,
ACL commands and restart validation are in the [main deployment procedure](../../Deployment.md#limiter-capacity-and-existing-counters).

### Search isolation and database capacity

Each web worker opens an additional one-connection search pool under the same
web database role. Include that extra connection per worker when sizing
PostgreSQL; the scheduler keeps its separate existing pool. Search does not
fall back to the ordinary pool. A deployment-wide start budget runs before
session lookup, and a nonblocking PostgreSQL transaction advisory lock limits
active search operations to one across workers using the same database.

The default start rate is one operation every two seconds, with burst one,
a 500 ms SQL timeout, a one-second complete-operation deadline and 100 ms
connection acquisition. Staging/production rejects a burst greater than one
or a start-rate/deadline product above 0.5. The controls apply to every
`GET /search` mode and remain enabled when ordinary per-client limits are
disabled. Busy or expired work returns retryable, non-cacheable 503.

Run the [search load acceptance](../runbooks/search-fulltext.md#capacity-and-load-acceptance)
against representative data and record login/ordinary-request latency during
search saturation. Separate pools and bounded concurrency do not reserve CPU,
disk bandwidth or PostgreSQL memory. Keep the independent edge limits.

### nginx in front, with the Shibboleth SP at the edge

nginx provides the reviewed edge boundary. While federation is closed, the exact
`/auth/shibboleth/callback` location returns `404`, does not proxy to the
application, and `SHIBBOLETH_INTERNAL_SECRET` remains unset.

When Shibboleth comes online in Phase 2, the SP runs at the nginx layer. The
FastCGI authorizer must populate and nginx must overwrite the fixed private
headers `X-OHA-Shib-Subject`, `X-OHA-Shib-Issuer`, `X-OHA-Shib-Mail`,
`X-OHA-Shib-Display-Name`, `X-OHA-Shib-Affiliation`, `X-OHA-Shib-Entitlement`,
`X-OHA-Shib-Country`, and `X-OHA-Shib-Authn-Context`, plus
`X-OHA-Internal-Auth`, on the exact
callback location. Ordinary proxy locations clear all of these and the legacy
Shibboleth header names; client input is never forwarded as identity data.
The callback explicitly sets `satisfy all` (so an inherited access-policy
setting cannot make the Shibboleth authorizer optional),
`shib_request_use_headers off` (so the nginx module cannot copy ambient request
headers into its attribute namespace), and `proxy_pass_request_headers off`
(so the client header set does not reach the application), then forwards only
the reviewed explicit values.

The application then requires all of the following: `SHIBBOLETH_ENABLED=true`,
a constant-time match with `SHIBBOLETH_INTERNAL_SECRET`, an absolute HTTPS
issuer exactly in `SHIBBOLETH_TRUSTED_ISSUERS`, and the exact REFEDS MFA context
`https://refeds.org/profile/mfa`. There is no IP-based trust: the callback
refuses any request that arrives with a TCP peer because legitimate requests
arrive over the Unix socket. That check is only a topology tripwire; nginx-only
socket permissions, the SP authorizer, header replacement, and secret custody
are the actual trust boundary.

A first accepted assertion is not a login. It creates an inactive, public,
non-admin, unverified pending row keyed by `(issuer, subject)` and issues no
session. An administrator must use the dedicated approval action, which
re-matches that exact pair, assigns the selected tier, activates the row, and
records approval actor/time, bumps `auth_revision`, and deletes every target
session atomically. Generic tier, administrator and reactivation actions cannot
approve pending identities. Dedicated approval itself requires enabled,
currently trusted federation; only a later matching assertion can log in.
The [WP F acceptance record](../runbooks/federated-tier-acceptance.md) maps
application evidence and the separate open Gate F requirements. Follow the
[generic federation integration runbook](../runbooks/federation-integration.md)
for the ordered SP preparation, pre-flip checks, production canary and
rollback procedure; synthetic application tests do not complete that host
acceptance. With federation enabled, every valid-token `POST /logout` uses the
fixed same-origin SP logout handler, including local and anonymous callers.
An invalid-token retry with completed anonymous session resolution and no
session cookie only redirects to `/`, without cookie changes or SP handoff;
see [CSRF](../architecture/security.md#csrf).

Federated session eligibility is also fail-closed after login. Each lookup
requires the flag, active/approved state, and a still-trusted exact issuer.
Startup stores a fingerprint of the flag, sorted issuer list, fixed MFA
context, policy version, and callback secret; a missing or changed fingerprint
revokes every Shibboleth session in the same transaction that records the new
digest. Local sessions are untouched.

### Logs to journald

The application writes structured logs to stdout; systemd-journald captures both the web and scheduler streams and handles rotation/retention (configured in `/etc/systemd/journald.conf.d/oralhistarchiv.conf`). This is multi-process safe, unlike file-based rotation. For off-host retention, a host-level rsyslog agent forwards journald output over RELP/TLS (see `deploy/rsyslog-oralhistarchiv.conf.example`).

### Encrypted backups under a separate identity

The backup timer does not run as either application user and does not read the
root-owned `/etc/oralhistarchiv` environment files. A dedicated read-only PostgreSQL role passes an explicit
database/schema preflight, then streams a custom-format dump directly through
`age` inside a `0700` systemd state directory. No plaintext dump is written to
a filesystem; only a `0600` encrypted `*.dump.age` file is atomically published.
The private identity is held off-host under separate recovery custody.
PostgreSQL custom format is not itself encryption, and `age` recipient
encryption does not authenticate who produced an archive. The deployment
runbook's filesystem, authenticated-transfer/provenance, failure, monitoring,
off-host-copy and isolated-restore checks are mandatory host controls, not
properties the application can verify at startup.

WP M1 adds an optional nonsecret publication marker in a separate backup-owned
status directory. Install `deploy/oralhistarchiv-backup-tmpfiles.conf` only after
the backup OS identity exists; the ordinary application tmpfiles contract and
its stable deployment-lock inode stay unchanged. Configure `BACKUP_STATUS_DIR`
for the backup writer and the matching `BACKUP_STATUS_FILE` in web.env. The web
identity gains no backup-directory, recovery-key or database privilege. The
[monitoring checklist](../runbooks/monitoring.md) explains marker age, unknown
states and independent timer/off-host/restore checks.

The [PITR runbook](../runbooks/point-in-time-recovery.md) is a template for a
separately reviewed physical-base/WAL deployment with independently encrypted
retention and an isolated replay drill. It does not turn the logical dump unit
into continuous archiving or establish a successful production recovery.

## Operational procedures

Use [Deployment.md](../../Deployment.md) for installation, configuration,
preflight, backup/restore, monitoring and maintenance. Use [key rotation](../runbooks/key-rotation.md)
for signing/session credentials, TOTP re-encryption, outbox-key retention and
backup-key custody. The encrypted systemd timer workflow creates age archives;
its private identity is held off-host.

## First-deployment checklist

Complete the acceptance checklist in [Deployment.md](../../Deployment.md#16-post-deployment-checklist).
The migration unit must report static and inactive, not enabled; web/scheduler
use their own non-owner roles. Keep public registration and federation closed
until their respective release gates pass. A fresh schema is supported;
existing prototype databases require a reviewed migration/import plan.


## Upgrades

Production runtime processes never run Alembic. Follow `Deployment.md` - "17. Maintenance":
enter nginx maintenance, stop web and scheduler, take and verify an encrypted
backup, review migrations and `database-runtime-grants.sql` together, start the
static/manual `oralhistarchiv-migrate.service`, confirm its journal and
Alembic head, then start scheduler and web and require both exact runtime-role
preflights before restoring traffic.

## Rollback

There is no generic production `alembic downgrade` command. Every
schema-changing release must ship a reviewed forward-repair or restore plan.
Run it through an equivalently sandboxed owner-only one-shot while web and
scheduler remain stopped, reapply the matching deny-first grant manifest,
deploy matching application code, and require both runtime preflights before
reopening traffic. Never run `alembic` as a runtime OS/DB identity. The
[federation-specific rollback ordering](../runbooks/federation-integration.md#federation-rollback-boundary)
still takes precedence. Suspected internal-credential disclosure requires
the stopped-web-first incident procedure in the key-rotation runbook.


## Terminal email retention and delivery monitoring

The scheduler runs `outbox_retention` every `OUTBOX_RETENTION_INTERVAL_SECONDS` (60 by default). It deletes sent messages older
than `OUTBOX_SENT_RETENTION_DAYS` (default 7) and dead messages older than
`OUTBOX_DEAD_RETENTION_DAYS` (default 30), using their terminal timestamps.
Each run deletes at most `OUTBOX_RETENTION_BATCH_SIZE` rows per status
(default 1000; at most twice the configured batch size total). Pending and sending messages are preserved.
Oldest eligible rows are processed first; locked rows wait for a later run.
There is no automatic replay of dead messages: request a new action email
through the relevant account flow. Purged bodies and per-message diagnostics
cannot be recovered from the live database.

Monitor authenticated `/health/detail` JSON, not just its HTTP status. Its
`checks.outbox` object exposes pending/sending/dead counts, oldest pending
and sending ages, and a retention-overdue count. Stalled messages at
`OUTBOX_STALE_AFTER_SECONDS` (default 600), unavailable outbox diagnostics,
or terminal rows overdue by more than two hours make the overall status
`degraded` while HTTP remains 200. A nonzero dead count is informational:
also uses `dead` for expected cancellations. Inspect scheduler logs
for failed `outbox_retention` runs and successful `outbox_retention` events
with `sent_deleted` and `dead_deleted` counts. Sustained growth in overdue
rows means cleanup is failing or its bounded throughput is insufficient;
raise the batch size within its 5000-row per-status limit after checking load.

Retention does not itself prove an old `OUTBOX_ENCRYPTION_KEYS` entry is
unused: pending/sending bodies, retained terminal bodies, and backups may
still need it. Follow the key-rotation runbook before removing a key.

## Scheduler shutdown budget

`run_scheduler.py` allows 300 seconds for running jobs to drain, then a
5-second cancellation grace. The scheduler unit sets `TimeoutStopSec=330s`,
leaving 25 seconds for cleanup. Keep these paired values aligned; the
`src/tests/unit/test_deployment_units.py` test checks their relationship.
`KillMode=mixed` sends the initial stop signal to the scheduler, allowing it
to drain or terminate its SMTP child. `SendSIGKILL=yes` retains systemd's
final group-wide forced stop if graceful shutdown fails.

After installing the revised unit, reload and inspect the effective settings:

```bash
sudo systemctl daemon-reload
systemctl show oralhistarchiv-scheduler.service \
    --property=TimeoutStopUSec --property=KillMode --property=SendSIGKILL
```

Expected values: a 330-second stop timeout (commonly displayed as `5min 30s`),
`KillMode=mixed`, and `SendSIGKILL=yes`. Check local drop-ins if they differ.
A restart can now wait for that drain budget; plan deployment timing accordingly.

## Installing the application wheel

Ordinary non-editable wheel installations are supported. Hatch packages the
single source migration repository (`src/alembic/` and `src/alembic.ini`)
inside `app/_migration_assets/`; do not maintain a second hand-copied tree.
Runtime paths prefer the packaged assets and only use the old source paths
in a detected source checkout. Direct zip-import is unsupported.

The packaged migration CLI may be called directly only in development. In
staging/production, install the release's unit and migration assets and invoke
the CLI exclusively through the static/manual
`oralhistarchiv-migrate.service`; the unit supplies `migration.env`, quiesces
both runtime units through `Conflicts=`, and reapplies the reviewed runtime
grants. Never add Alembic to a runtime unit's `ExecStartPre` and never load
`migration.env` into a wheel-only web or scheduler process.

## Email-action link cutover

Reset, registration-verification and email-change emails now use a non-secret
public path ID and a separately printed security code. URLs contain no token,
query or fragment. The GET page is generic; the user copies the code into the
HTML form and submits it. POST binds the ID to the secret and applies the
existing signature/account checks. No JavaScript, Node test step or database
migration is needed. Deploy the matching application and templates together.

Before delivery resumes, follow the
[action-link cutover and reissue procedure](../runbooks/action-links.md#deploying-the-link-format-change)
for queued old-format messages and already-issued links. Do not rewrite
ciphertext or requeue obsolete message bodies manually. The new transport
cannot erase secrets already recorded in mail systems, browsers or edge logs.

## Registration activation (Gate R)

Keep `LOCAL_REGISTRATION_ENABLED=false` on the deployment until the mailbox-first
registration release is accepted and deployed. Before opening registration,
complete a real flow through the production SMTP relay with a disposable
mailbox: email-only request, delivered setup link, password/profile completion,
single-use rejection on replay, then password login and authenticator/recovery
code enrollment. Check missing/wrong CSRF rejection and that an attacker-supplied
initial password never becomes a login credential. Verify rate limits and
lockout against the public endpoint. Record revision, date, HTTP outcomes and
the mailbox/relay result without recording passwords or raw capability URLs.
Enable the flag only after that acceptance.
