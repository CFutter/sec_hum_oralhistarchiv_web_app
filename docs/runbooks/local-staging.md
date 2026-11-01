# Laptop-only staging

For an existing retained installation, first follow the
[retained staging inventory and recovery preparation](retained-staging-inventory.md).
The fresh topology below does not authorize recreating its database, resetting
source progress or replacing a retained-state upgrade with an empty install.

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
| Catalogue | A reviewed fixture-only source TOML, selected explicitly by both web and scheduler |

Use root-owned `0600` `common.env`, `web.env`, `scheduler.env` and
`migration.env` in a root-only directory under `/etc`. Keep the migration owner
credential outside both runtime environments. Set `ENV_STATE=staging` as a real
process environment variable, `PUBLIC_BASE_URL=https://archive.test:8443`,
`ALLOWED_HOSTS` containing `archive.test`, `FASTAPI_DEBUG=false`, secure cookies
and a generated health-detail token. Staging does not load the checkout's `.env`.

Use reviewed staging Gunicorn and scheduler units with staging-specific paths
and a proxy-only Unix socket. `dev.sh` is development-only and rejects staging
before running migrations or starting either child process. Use the reviewed
staging migration and service workflow below. Do not copy the production unit
preflight or public nginx listener unchanged.

### Select an explicit offline catalogue

From the reviewed checkout root, install the nonsecret source TOML separately
from the private environment files:

```bash
sudo install -d -o root -g root -m 0755 /etc/oralhistarchiv-staging-sources
sudo install -o root -g root -m 0644 deploy/environment/sources.dev.toml \
  /etc/oralhistarchiv-staging-sources/sources.toml
sudo namei -l /etc/oralhistarchiv-staging-sources/sources.toml
```

Set the shared selection in `common.env`:

```dotenv
SOURCES_CONFIG_FILE="/etc/oralhistarchiv-staging-sources/sources.toml"
ALLOW_FIXTURE_SOURCE=false
```

Both processes require a nonempty selector; there is no source fallback or
mock-data seeder. Staging accepts fixtures without production fixture
permission, but requires a direct absolute POSIX path without `..` or symlinks.
The file and every opened directory must be root-owned and not group- or
other-writable. Both identities need directory read/search and file read access.

Remove retired settings from environment files and inherited variables; false
or empty assignments still fail. See the
[settings reference](../configuration/settings.md). Stop both services while
replacing the selection, then restart both against the same reviewed file;
running processes retain their startup configuration.

The scheduler imports three synthetic `fixture_demo` records through normal
ingestion, with public, registered and vetted metadata tiers. The web process
does not populate them. The fixed cursor is `2020-01-04T00:00:00+00:00`;
operational harvest/rebuild timestamps determine freshness. The fixture makes
no upstream HTTP request, and its links do not provide real recordings.

For a later OAI trial, prepare a separate flat TOML with a reviewed compatible
HTTPS endpoint and its matching institution filter. The mixed
`sources.example.toml` activates every entry and contains a placeholder OAI
endpoint rejected in staging; it is not the offline selection. See
[Sources](../sources/index.md) for adapter fields and policy.

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
   public listeners. The other host's port `80` can remain with its existing web server.
4. Check `https://archive.test:8443/health` using the local certificate as
   curl's `--cacert`; then load `/register` in the laptop browser. Create one
   disposable local account and check the verification message in the Mailtrap
   sandbox. The scheduler's `email_outbox_delivery` job delivers it; the `sent` state
   and message in the sandbox jointly confirm the flow.
5. Confirm a successful rebuild for each selected source independently of web
   liveness. A fresh database intentionally makes the first incremental job
   request a full rebuild. A zero-match rebuild is an error, even if the
   scheduler remains active. Inspect counts and status with the read-only
   backup role:

   ```sql
   SELECT source, last_full_rebuild_date, source_cursor,
         last_sync_error, last_rebuild_error
   FROM public.sync_status ORDER BY source;
   ```

   Expect a populated `last_full_rebuild_date` for each selected source.
   The fixture-only selection produces the `fixture_demo` status row and
   three synthetic catalogue records. An OAI selection uses its configured
   identity and a matching endpoint/institution pair. A zero-match rebuild is
   an error. Never advance or erase the source cursor to silence an error.
6. Create the first administrator through the [bootstrap procedure](bootstrap-admin.md),
   adapted to the reviewed staging paths and environment. Runtime services reject
   `ADMIN_SEED_EMAIL` and `ADMIN_SEED_PASSWORD`; never place them in service files.
   Complete TOTP enrollment, then log in again. Decide whether staging units
   should start at boot; stop/disable them after the trial.

The repository's root `docker-compose.yml` is for destructive integration
tests: its database is truncated by the test suite and must never hold this
staging catalogue. A separate Compose project could automate this staging
topology, but it needs its own non-owner database roles, migration step,
dedicated persistent Redis, secrets, loopback-only proxy and durable volumes.
