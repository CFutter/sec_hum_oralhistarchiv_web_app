# Cache, Scheduler, Email & Administrator Bootstrap

Background jobs, catalogue cache, transactional mail and one-shot bootstrap.

## In-memory catalogue statistics cache

Each web process caches selected-source rebuild freshness for one hour.
`CatalogueStatsCache` requires explicit `source_names` and snapshots them before
starting its subscriber. The private entry contains only the timestamp and its
monotonic build time; an unknown timestamp is a cached result rather than an
empty entry. Fills use the timestamp-only query and never count catalogue rows.
Public dataset totals are queried live on every read. The returned total and
cached freshness may come from different database snapshots.

Freshness is the oldest successful rebuild among the selected sources. It is
unknown if any selected source lacks a status row or successful rebuild.
Unselected status rows do not affect freshness. Stored datasets remain counted
even when their source is no longer selected, unless administrator-hidden.

Optional Redis pub/sub invalidates rebuild freshness across workers after sync
attempts; TTL expiry covers missed notifications. Dataset totals, tier-sensitive
counts and facets query PostgreSQL directly. A hide/restore committed before
the count query is visible without Redis invalidation.

::: app.services.cache

## Scheduler

`run_scheduler.py` owns one APScheduler instance and requires at least two pooled connections.

| Job | Interval | First run |
|---|---|---|
| Email delivery | 15 seconds | Immediately |
| Incremental sync, per source | `SourceSchedule.incremental_interval_seconds` | Immediately |
| Full rebuild, per source | `SourceSchedule.rebuild_interval_seconds` | Five-minute steps in configuration order |
| Session cleanup | One hour | Immediately |
| Unverified-account cleanup | One hour | After ten minutes |
| Outbox retention | `OUTBOX_RETENTION_INTERVAL_SECONDS` | After 30 seconds |

Each job has `max_instances=1`. Sync/rebuild share process and PostgreSQL advisory locks; incremental recovery outcomes can trigger an immediate rebuild. `RunningJobTracker` tracks work for shutdown. See [Sync](../../architecture/sync.md).

::: app.services.scheduler

## Email

Web transactions persist encrypted messages; the scheduler leases, revalidates, and delivers them with bounded child-process SMTP work. Delivery can be retried, so consumers must tolerate duplicate email after uncertain outcomes.

With SMTP disabled in development, delivery atomically publishes `.eml` files in `DEV_MAILBOX_DIR` (default `.dev-mailbox` under the scheduler working directory). The directory must be private (`0700`) and files use `0600`. Treat saved capability links as secrets and remove messages when no longer needed. Staging and production require SMTP with TLS.

::: app.services.email

::: app.services.email_outbox

::: app.services.mail_issuance

::: app.services.email_delivery

::: app.services.outbox_maintenance

::: app.services.smtp_process

::: app.services._smtp_child

## Email token lifecycles

Verification and email-change services store single-use hashes on users and queue their messages transactionally. Shared token primitives sign payloads and derive hash/expiry metadata.

::: app.services.email_verification

::: app.services.email_change

::: app.services.tokens

::: app.services.email_utils

## Audit helpers

Typed event helpers for the dedicated audit channel; see [Logging & Audit](../../configuration/logging.md).

::: app.services.audit

## Redis client

`redis_client` is the optional general Redis connection helper: it returns a configured client when `REDIS_ENABLED=true` and `None` otherwise. `CatalogueStatsCache` can fall back to its TTL when this connection is absent. The hardened rate limiter uses its separate `RATE_LIMIT_REDIS_URL` and fails startup if that store is unavailable.

::: app.services.redis_client

## Administrator bootstrap

Run `scripts/bootstrap_admin.py --email ADDRESS` from a protected terminal to create the first verified local administrator at public tier. It reads the password without echo and refuses an existing administrator or email owner. Complete TOTP/recovery-code enrollment and log in again before administration. Runtime services reject seed credentials. See [bootstrap](../../runbooks/bootstrap-admin.md).

::: app.services.seed_admin


## Service package exports

::: app.services
