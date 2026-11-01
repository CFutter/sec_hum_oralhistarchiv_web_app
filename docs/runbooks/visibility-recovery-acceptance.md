# Visibility and recovery acceptance

Record implementation-test evidence separately from candidate-host peer,
archive-custody and representative restore evidence. Disposable synthetic tests
prove only their exercised boundary; record actual run/approval references before
marking any acceptance item passed.

## Scope and existing procedures

The [field policy](../architecture/field-visibility.md) defines the seven public
discovery fields, stricter source minima, row policies and trusted viewer context.
The fresh-install baseline is `4f73ae3ff827`; inspect its actual contract when
reviewing retained databases.

Use the repository-root `Deployment.md` as the operational source of truth:
section 3 covers exact peer identities, section 11 covers encrypted backups,
custody and isolated restoration, and section 17 covers maintenance and runtime
restart. The
[deployment overview](../configuration/deployment.md),
[laptop-staging checklist](local-staging.md) and
[backup-recipient rotation procedure](key-rotation.md#7-rotating-the-backup-archive-recipient)
explain those boundaries. Laptop Staging is not an installer; its example
staging units are not supplied by the repository.

## Automated evidence

The E4 case is
`src/tests/integration/test_deployed_preflight_db.py::test_actual_backup_role_encrypted_restore_reestablishes_catalogue_boundaries`.
Run it with `DATABASE_URL` explicitly selecting a disposable `*_test` database
and `REDIS_URL` selecting disposable Redis:

```bash
REQUIRE_DB=1 REQUIRE_REDIS=1 uv run pytest -q -rs \
  src/tests/integration/test_deployed_preflight_db.py::test_actual_backup_role_encrypted_restore_reestablishes_catalogue_boundaries
```

This module requires a separate disposable PostgreSQL cluster with no existing
`oralhistarchiv` database or deployment roles. Its fixture refuses to replace
them and skips instead; that skip is not passing acceptance evidence. The
existing CI service containers provide the intended isolated test environment.

The case uses actual restricted backup/recovery/web logins and synthetic
public, registered, vetted, administrator-raised and hidden records. It streams
the backup login's custom-format dump through `age`, restores the decrypted
stream as the recovery owner, reestablishes the target's reviewed grants and
database-specific role defaults, and checks the restored catalogue boundary.
Its exact data comparison covers catalogue values, durable administrator state
and revision. It is not a claim about every account or source-state table.
The separate [B9 recovery evidence](../sources/json-feed-acceptance.md#encrypted-synthetic-round-trip)
covers encrypted native-feed source state and staged replay using the test login.

Retain the test result, fixed/randomized CI references, collected count and
coverage results. Synthetic keys/logins do not establish operational custody or
host peer mapping.

## Candidate-host identity and row checks

Run this section only on the reviewed candidate host with the installed release
and operator-approved data. It performs reads and connection checks; it does
not install roles, reset a database or grant new authority. An empty catalogue
can pass negative checks vacuously, so retain the nonempty automated witness
and the representative restore comparison separately.

Use the existing reference host's Unix socket and OS/database identities:

```bash
sudo -u oralhistarchiv-migrate psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv --set=ON_ERROR_STOP=1 \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_web --set=ON_ERROR_STOP=1 \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv-scheduler psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1 \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv_backup psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_backup --set=ON_ERROR_STOP=1 \
  --command='SELECT current_user, session_user'
```

Each command must report the requested database identity twice. Repeat section 3's
negative checks: web requesting the owner, migration requesting web, and
scheduler/backup requesting database `postgres` must all be rejected. These
checks must use the actual OS identities and peer connection; a TCP test login
or `SET ROLE` does not establish this host boundary.

Run both installed access inventories and require exit zero:

```bash
sudo -u oralhistarchiv psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_web --set=ON_ERROR_STOP=1 \
  --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
sudo -u oralhistarchiv-scheduler psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1 \
  --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
```

For the raw web-row check, open a fresh connection without a supplied viewer
setting. The output is limited to booleans, not metadata or hidden identities:

```bash
sudo -u oralhistarchiv psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_web --set=ON_ERROR_STOP=1 <<'SQL'
BEGIN READ ONLY;
SELECT COALESCE(current_setting('app.viewer_tier', true), '') = ''
    AS default_context_is_unset;
SELECT COALESCE(bool_and(visibility_tier = 'public'), true)
    AS default_reads_only_public_stored_tiers
FROM public.oral_history_datasets;
SELECT set_config('app.viewer_tier', 'public', true);
SELECT NOT EXISTS (
    SELECT 1 FROM public.oral_history_datasets AS stored
    JOIN public.dataset_admin_state AS state
      ON state.source = stored.source AND state.uuid = stored.uuid
    WHERE state.hidden_at IS NOT NULL
       OR state.visibility_tier IN ('registered', 'vetted')
) AS public_reads_exclude_hidden_and_raised_rows;
ROLLBACK;
SQL
```

All three Boolean checks must return `t`. The local viewer setting lasts only
for this rolled-back read transaction. These checks cover the row floor, not
arbitrary-SQL enforcement of E2's individual field minima. Scheduler authority
is checked by its exact inventory and the accepted actual-role ingestion cases;
do not mutate live catalogue rows to demonstrate a synthetic write.

## Encrypted isolated recovery checklist

Execute section 11's complete backup and restore procedure in an operator-owned
recovery environment that cannot reach production. Keep the archive, private
identity and application key-ring values there; do not attach them to this
record or provide their values to an application/updater tool.

1. Record the approved release/CI reference and actual schema/view/policy
   inventory. The revision label `4f73ae3ff827` alone cannot distinguish an
   earlier body of the same preproduction baseline.
2. Record the installed backup service's success and role/schema preflight,
   archive/storage identity, authenticated transfer/provenance reference and
   filesystem/ACL checks. Only ciphertext `*.dump.age` is retained; private-key
   custody remains separate from both application and archive storage access.
3. Run `deploy/oralhistarchiv-backup-verify.sh` on the trusted recovery host.
   Its decryption and `pg_restore --list` result is a preliminary check, not
   proof of restored rows or application recovery.
4. Restore the decrypted stream with section 11's `--exit-on-error --single-transaction`
   owner/recovery procedure into a newly created isolated database. Never give
   the backup role CREATE or data-writing privileges to perform restoration.
   Do not point a drill at an existing development, staging or production
   database. Cleanup may remove only the destination created for that drill.
5. Provision the isolated target's reviewed role attributes, memberships,
   authentication and grants separately. Logical restoration does not provision
   OS peer mappings or cluster role attributes. The web/scheduler
   `search_path=pg_catalog,public` defaults are scoped to a database and must
   also be established for the restore target before its runtime validators
   can pass. The shipped grant manifest explicitly names `oralhistarchiv`;
   do not run it against another target without a reviewed target-specific
   version. Restoring ACLs alone does not establish these boundaries.
6. Compare approved backup-time state with restored state through the read-only
   `BYPASSRLS` backup identity, including all relevant public/registered/vetted,
   hidden and administrator-raised records. Check full catalogue/admin values,
   not just counts. Include source state, staging/quarantine and application-key
   checks when that archive contains them; state the exact scope and any gap.
   Run the restored web/scheduler inventories, verify default-public raw web
   reads, and preserve the accepted discovery envelope above tier.
7. Record the comparison, any applicable login/TOTP/outbox decryption outcome,
   operator/reviewer, date and cleanup result without row contents or secrets.
   Retain the last restore-verified archive and required key versions until a
   successor passes, under the approved retention policy.

No private feed is required for the synthetic E4 witness. Real-feed acceptance
and source-owner disclosure approval remain the separate
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md)
obligations. Synthetic coverage cannot certify a representative deployed archive.

## Acceptance record

Use operator-private issue or change-record references when the evidence cannot
be public. Record identifiers and pass/fail outcomes, not credentials, raw
payloads, capability URLs, private keys or sensitive rows.

| Evidence | Private reference/date/operator/reviewer | Result |
|---|---|---|
| Implementation checks and synthetic actual-role encrypted restore | Exact candidate CI/run and comparison scope | Pending observed evidence |
| Candidate-host peers and role/schema inventories | Four allowed identities and negative results | Pending host execution |
| Backup service, archive provenance and separate off-host custody | Service/storage/custody references, without key values | Pending operational evidence |
| Representative isolated encrypted restore | Backup-time comparison, key-version checks and cleanup | Pending representative archive |

Leave unavailable host/archive evidence pending. Completing this worksheet or
passing a format check does not prove operational recovery.
