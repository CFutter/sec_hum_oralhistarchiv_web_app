# Cache, Scheduler, Email & Seeders

Background jobs, catalogue cache, transactional mail, and seeders.

## In-memory catalogue statistics cache

Each web process caches total dataset count and last full-rebuild time for one hour. Optional Redis pub/sub invalidates these statistics across workers after sync attempts; TTL expiry covers missed notifications. Tier-sensitive counts and facets query PostgreSQL directly.

::: app.services.cache

## Scheduler

`run_scheduler.py` owns one APScheduler instance and requires at least two pooled connections.

| Job | Interval | First run |
|---|---|---|
| Email delivery | 15 seconds | Immediately |
| Incremental sync | `SYNC_INTERVAL_SECONDS` | Immediately |
| Full rebuild | `FULL_REBUILD_INTERVAL_SECONDS` | After five minutes |
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

## Seeders

Administrator seeding creates one verified local account at public tier only when no administrator exists; it refuses to promote an existing email owner. The account must complete TOTP/recovery-code setup before privileged administration. Remove seed credentials after successful bootstrap.

Mock seeding runs only when explicitly enabled: development web startup or staging scheduler startup. Production rejects the flag. Mock rows use source `mock`, restricted access, and vetted visibility; Source A rebuilds leave them intact.

::: app.services.seed_admin

::: app.services.seed_mock_data

## Service package exports

::: app.services
