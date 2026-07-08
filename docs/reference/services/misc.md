# Cache, Scheduler, Email & Seeders

The remaining service modules — small, single-purpose, but important to know about.

## In-memory facet cache

`cache.FacetCache` keeps the search-sidebar facets (keywords, languages, access levels) in process memory so the search page does not pay a database round trip on every request. It is thread-safe (a lock guards the lazy rebuild) and is invalidated explicitly after every sync by the scheduler process. The cache also has a TTL safety net: even if an invalidation signal is missed, it is rebuilt at least once an hour.

The cache is per-process — each Gunicorn worker holds its own copy. When Redis is enabled, `FacetCache` subscribes to a Redis pub/sub channel and invalidations published by the scheduler (or any worker) are propagated to every worker, so a sync that runs in the dedicated scheduler process clears the cache in all web workers. Without Redis the cache runs in local-only mode and relies on the TTL.

::: app.services.cache

## Scheduler

`scheduler.create_scheduler(pool, facet_cache)` registers four jobs on an APScheduler `AsyncIOScheduler`:

- **incremental_sync** — every `SYNC_INTERVAL_SECONDS`, first run scheduled for `now`
- **full_rebuild** — every `FULL_REBUILD_INTERVAL_SECONDS`, first run scheduled five minutes after start
- **session_cleanup** — hourly, deletes expired session rows
- **reap_unverified** — every 24 hours, deletes local accounts that never completed email verification

The first incremental sync is scheduled for `now`, so a freshly started instance populates itself immediately. Every job uses `max_instances=1`, so a slow run cannot overlap *with itself*. That alone does not stop the incremental sync and the full rebuild interleaving with *each other*, so an explicit `asyncio.Lock` (`_sync_mutex`) additionally serialises those two jobs — see [Architecture → OAI-PMH Sync Pipeline](../../architecture/sync.md) for the tombstone-resurrection race it closes. A lifecycle listener emits structured logs for job executions, errors, and missed runs.

The scheduler is **not** created inside the web application. It runs in its own process — `run_scheduler.py` builds a dedicated connection pool and `FacetCache`, calls `create_scheduler`, and starts it. In production this is the `oralhistarchiv-scheduler` systemd unit. Running it separately prevents the jobs from firing once per Gunicorn worker.

For the rationale and the per-job behaviour, see [Architecture → OAI-PMH Sync Pipeline](../../architecture/sync.md).

::: app.services.scheduler

## Email

`email` is a thin wrapper around `smtplib` with one important behaviour: when `SMTP_ENABLED=false` (the default in dev), it does **not** silently drop the email. It logs the recipient and subject at INFO level and — in dev only — the full message body at DEBUG level. This means the password-reset, email-verification, and email-change flows can be exercised end-to-end in development by running with `LOG_LEVEL=DEBUG` and copying the link out of the journal/stdout — no SMTP server required.

In production, `SMTP_ENABLED=true` must be set or these emails will only be logged, never sent. This is checked by a settings validator (which also rejects unmodified placeholder values in production) and documented in the deployment runbook checklist. When TLS is on, the module's `verify_smtp_tls()` runs at startup and exercises STARTTLS against the configured relay — honouring `SMTP_CA_BUNDLE` for privately signed relays — so a broken mail TLS setup fails at boot rather than silently when a recovery email never arrives.

The module provides typed builders for each message: `send_password_reset_email`, `send_verification_email`, `send_email_change_verification` (to the new address), `send_email_change_notice` (to the old address), `send_duplicate_registration_notice` (to an address someone tried to re-register — the enumeration-safe counterpart to the identical registration page), and `send_account_locked_notice` (on lockout).

::: app.services.email

## Email token lifecycles

Two small modules own the single-use, hashed token lifecycles that the email flows ride on. `email_verification` generates, stores (SHA-256 on the user row), validates, and atomically consumes the verification token; `email_change` does the same for the staged email change (pending address, confirm link to the new address, notice to the old one, session invalidation on commit). Both build on `tokens`, the shared primitive for itsdangerous-signed token generation and hash comparison.

::: app.services.email_verification

::: app.services.email_change

::: app.services.tokens

## Audit helpers

`audit` provides the typed helpers routes use to emit structured audit events (`audit_login_success`, `audit_admin_action`, `audit_dataset_access`, …) on the dedicated `audit` logger — see [Configuration → Logging & Audit](../../configuration/logging.md) for the channel semantics.

::: app.services.audit

## Redis client

`redis_client` is the optional-Redis connection helper: it returns a configured client when `REDIS_ENABLED=true` and `None` otherwise, so callers (rate limiting, `FacetCache`) degrade gracefully without conditional imports.

::: app.services.redis_client

## Seeders

`seed_admin` runs once on startup if both `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` are set. It creates an `is_admin`, `email_verified` local user with that email and password — but only if no admin exists yet. The seeded account starts at the **`public` access tier** (tiers cannot be set at user creation), so an admin who also needs tier-gated visibility raises their own tier from the dashboard afterwards. It refuses to promote an existing user and validates the seed password against the strength rules. Subsequent starts are no-ops, so leaving the seed values in the environment is harmless but pointless; the deployment checklist recommends removing them after the first successful start.

`seed_mock_data` runs only when `FASTAPI_DEBUG=true` (and refuses to run in production). It inserts a small set of mock datasets — all tagged `source="mock"`, `access_level="restricted"`, and `visibility_tier="vetted"` — so the tier-filtering logic and the dataset detail/redaction paths can be exercised in development without waiting for a real OAI-PMH harvest. Because the rows carry `source="mock"`, a real `_full_rebuild_source_a()` (which only deletes `source="swissubase"` rows) never touches them.

::: app.services.seed_admin

::: app.services.seed_mock_data
