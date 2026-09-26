# Emergency Dataset Withdrawal

Use this runbook only when sensitive metadata must be removed from the public
application before the authoritative source can publish its correction or
withdrawal. Normal corrections belong in the source repository and flow through
synchronization.

This procedure deletes the local row rather than raising its tier. A tier change
would still expose the record's redacted title and identifiers to lower-tier
viewers. It does not erase copies already present in database backups, remote
logs, browser history, or downstream systems; handle those under the incident
response and retention procedures.

## Preconditions

- Open an incident/change record containing the source, UUID, reason, approver,
  and timestamps. Do not put sensitive metadata itself in the ticket or shell
  history.
- Arrange the authoritative correction or withdrawal with the source curator.
- Use the scheduler peer role, which can delete catalogue rows; do not broaden web grants.

## Procedure

1. Stop ingestion and any ad-hoc sync jobs. Stopping the scheduler also pauses mail delivery and maintenance jobs:

   ```console
   sudo systemctl stop oralhistarchiv-scheduler
   ```

2. Open a peer-authenticated SQL session:

   ```console
   sudo -u oralhistarchiv-scheduler /usr/bin/psql -X --no-password \
     --host=/var/run/postgresql --dbname=oralhistarchiv \
     --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1
   ```

   Confirm the database and substitute the reviewed source/UUID below.
   Commit only if inspection and deletion each affect the one intended row.

   ```sql
   BEGIN;

   SELECT id, source, uuid, visibility_tier
   FROM oral_history_datasets
   WHERE source = 'SOURCE_NAME' AND uuid = 'SOURCE_UUID'
   FOR UPDATE;

   DELETE FROM oral_history_datasets
   WHERE source = 'SOURCE_NAME' AND uuid = 'SOURCE_UUID';

   -- Expect exactly one row. ROLLBACK and investigate any other result.
   COMMIT;
   ```

3. Restart every web instance to clear cached catalogue statistics; facets are queried live:

   ```console
   sudo systemctl restart oralhistarchiv
   ```

4. Verify as an anonymous, registered, and vetted viewer that the detail URL,
   search results, counts, and facets no longer expose the record. Verify in SQL
   that no row remains for the exact `(source, uuid)`; deletion removes the
   normalized columns, data JSONB and trigger-maintained search text together.

5. Record the database result and application verification in the incident
   record. Complete any backup/log containment required by policy.

6. Keep the scheduler stopped until the upstream correction is effective and
   persisted incremental_harvest has been reviewed. Both incremental sync and
   full rebuild drain staged work first, so either can recreate the removed row.
   No withdrawal-specific staging-reconciliation command is supplied. Obtain a
   reviewed reconciliation/discard plan and verify an authoritative rebuild
   before resuming normal scheduling; do not merely request a rebuild.

7. Confirm the record remains absent, or that a corrected record contains no
   sensitive value in normalized columns, `data`, search results, or facets.

## Failure rule

If the source has not yet been corrected, leave the scheduler stopped and
escalate the freshness impact. Do not maintain a silent permanent database edit:
ordinary upserts treat the source as authoritative and can overwrite or recreate
local state.
