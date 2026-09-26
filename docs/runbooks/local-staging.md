# Laptop-only staging

This is a staging topology checklist, not a reproducible installer. The named
staging units, certificate and host configuration are not included. Adapt
[Deployment.md](../../Deployment.md) in a reviewed host configuration before
running it; keep listeners on loopback and use separate test data/secrets.

## Isolated services and configuration

| Component | Laptop staging value |
|---|---|
| Python | Installed Python 3.11, with the project synced using `uv sync --locked --no-dev --no-editable` |
| PostgreSQL | Dedicated cluster/database on port `5433`; apply `deploy/bootstrap-database-roles.sql`, migrations, `deploy/database-runtime-grants.sql`, then verify both runtime roles with `deploy/verify-runtime-database-access.sql` |
| Web and scheduler | Separate `oralhistarchiv-staging-web.service` and `oralhistarchiv-staging-scheduler.service` identities; the scheduler alone imports source data and delivers queued mail |
| Rate-limit Redis | Dedicated loopback port `6380`, separate identity, ACL and persistent AOF; `RATE_LIMIT_REDIS_URL` belongs in web configuration only |
| nginx | TLS at `127.0.0.1:8443` for `archive.test`; map the name to `127.0.0.1` in `/etc/hosts` and use a local self-signed certificate |
| Email | Mailtrap **Email Sandbox** SMTP credentials, STARTTLS and `SMTP_ENABLED=true`; check that the sandbox has no automatic forwarding rule for test addresses |
| Source A | `SWISSUBASE_OAI_PMH_URL="https://demo.swissubase.ch/oai-pmh/v1/oai"` and `OAI_INSTITUTION_FILTER="Universität Kassel"` |

Use root-owned `0600` `common.env`, `web.env`, `scheduler.env` and
`migration.env` in a root-only directory under `/etc`. Keep the migration
database owner credential outside both runtime environments. Set
`ENV_STATE=staging`, `PUBLIC_BASE_URL=https://archive.test:8443`, secure
cookies and a generated health-detail token. Set `SEED_MOCK_DATA=true` only in
`scheduler.env` if the three restricted mock datasets are useful. Mailtrap
credentials, encryption keys, seed credentials and certificate private keys
must remain outside source control.

The production runbook uses a production SWISSUbase endpoint and different
host ports and identities. Do not copy its `ENV_STATE=production` unit preflight
or public nginx listener into a laptop-only staging unit. The source URL and
institution filter must match the same upstream catalogue. Check the demo
endpoint's OAI-PMH `Identify` response before configuring it.

## Verify before using the site

1. Apply the migrations with the database owner, then the runtime grants with
   that owner. Run the shipped SQL verifier as the web role and as the
   scheduler role. The scheduler needs the narrow `UPDATE (flash_category)`
   grant on `sessions` for its expired-session `FOR UPDATE SKIP LOCKED` query;
   do not grant table-wide `UPDATE`.
2. Run the [dedicated Redis scripted-counter restart and ACL probe](../../Deployment.md#7-gunicorn-scheduler--systemd)
   before starting the web service; the behavior probe is the persistence gate. When a non-distribution binary is used, review the systemd unit's
   `ExecStart` path and repeat the probe after changes.
3. Start the dedicated Redis, web, scheduler and nginx units. Confirm that
   nginx listens only on `127.0.0.1:8443`; PostgreSQL and Redis must not have
   public listeners. The other host's port `80` can remain with Caddy.
4. Check `https://archive.test:8443/health` using the local certificate as
   curl's `--cacert`; then load `/register` in the laptop browser. Create one
   disposable local account and check the verification message in the Mailtrap
   sandbox. The scheduler's `email_outbox` job delivers it; the `sent` state
   and message in the sandbox jointly confirm the flow.
5. Confirm a successful Source A rebuild independently of the web liveness
   check. A fresh database intentionally makes the first incremental job
   request a full rebuild. A zero-match rebuild is an error, even if the
   scheduler remains active. Inspect counts and status with the read-only
   backup role:

   ```sql
   SELECT source, count(*) FROM public.oral_history_datasets
   GROUP BY source ORDER BY source;
   SELECT last_full_rebuild_date, source_cursor,
          last_sync_error, last_rebuild_error
   FROM public.sync_status WHERE id = 1;
   ```

   Expect `swissubase` rows and a populated `last_full_rebuild_date`. Correct
   the URL/filter pairing if the error says `0 matching records`; restarting
   the scheduler triggers a new authoritative rebuild. Never advance or erase
   the source cursor to silence an error.
6. Sign in as the seeded administrator and complete TOTP enrollment. Remove
   `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD` from `common.env` after that
   first successful login, then restart the web and scheduler units. Decide
   explicitly whether the test units should start at boot; stop/disable them
   when the local trial is over.

The repository's root `docker-compose.yml` is for destructive integration
tests: its database is truncated by the test suite and must never hold this
staging catalogue. A separate Compose project could automate this staging
topology, but it needs its own non-owner database roles, migration step,
dedicated persistent Redis, secrets, loopback-only proxy and durable volumes.
