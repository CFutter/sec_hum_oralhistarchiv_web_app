# Emergency Dataset Withdrawal

Use this procedure when a dataset must disappear from every catalogue view
before its authoritative source can publish a correction or withdrawal. Raising
a tier leaves the public discovery envelope visible; hiding removes that
envelope too. Hiding retains local metadata and does not erase database backups,
logs, browser history or downstream copies.

## Primary path: administrator UI

1. Open an incident/change record with the reviewed source, UUID, reason,
   approver and timestamps. Keep sensitive metadata out of the ticket.
2. Sign in with an eligible full administrator session. Open **Admin → Dataset
   administration**, filter by the exact UUID and source name, and open the
   matching ID. Check both identity fields before acting. Hidden records and
   records from unselected sources are included in this control view.
3. Choose **Hide dataset**. A successful response confirms the committed change;
   a timeout or error requires reloading the control page to check current state
   before retrying. An already hidden dataset is a no-op.
4. Verify the normal detail URL returns 404 for anonymous, registered and vetted
   viewers. Verify the record is absent from search, recent cards, facets and
   catalogue counts. No worker restart or Redis invalidation is required.
5. Record the `admin_dataset_hidden` event's request, actor, dataset/source/UUID
   and before/after state. A change appends durable evidence transactionally and
   emits a local log after commit; no-ops append none. Follow
   [security event delivery](security-event-delivery.md) if the local copy is missing.
6. Arrange the authoritative correction with the source curator. Ingestion may
   continue: the durable `(source, uuid)` hide survives incremental updates,
   rebuilds, withdrawal and reintroduction. A new UUID is a different identity
   and needs its own review.
7. Once disclosure is approved, reopen the control page and choose **Restore
   dataset**. Restore clears only hiding, preserves the administrator tier floor,
   and emits `admin_dataset_restored` for a change. Verify the restored record
   at all three tiers and record the outcome.

The control pages show identifiers, visibility state and the public catalogue
title for nonhidden records. Hidden titles are withheld; use the reviewed source
and UUID to identify them. The normal catalogue detail page also links to these
controls with **Manage visibility** for administrators. Administrator status
grants no extra catalogue metadata tier. Raising requires a valid selected
source policy; hide and restore also work for retained unselected sources.
If the source has removed the raw catalogue row, its durable restriction remains
stored and applies if that identity returns; there is no current dataset ID to
manage in the UI while the row is absent.

An **Awaiting upstream correction** note identifies an independent ingestion
quarantine. A rejected update to a known identity withholds its previous copy
from every catalogue tier, including its title and resource redirects. Keep the
source/UUID for upstream correction and inspect the source's ingestion status.
Administrator restore clears only the administrator's hide; it cannot override
this quarantine. A fully validated correction from a later fresh harvest must
commit before serving resumes. Do not delete quarantine rows or reset failures
to force the previous copy back into service. Existing administrator floors and
hiding still apply after the correction.

## SQL fallback: web tier unavailable

Use this only when the web tier cannot serve the UI. Use the existing web peer
identity, which can write administrator state but cannot update raw catalogue
metadata. Do not broaden grants or delete the catalogue row.

```console
sudo -u oralhistarchiv /usr/bin/psql -X --no-password \
  --host=/var/run/postgresql --dbname=oralhistarchiv \
  --username=oralhistarchiv_web --set=ON_ERROR_STOP=1
```

Confirm the database and substitute the reviewed source/UUID in both statements.
The advisory key is the same single-bigint key used by ingestion and the UI.
The transaction serializes with those writers; use a finite timeout.

```sql
BEGIN;
SET LOCAL statement_timeout = '30s';
SELECT pg_advisory_xact_lock(1330135379);

SELECT stored.id, stored.source, stored.uuid, stored.visibility_tier,
       admin_state.visibility_tier AS administrator_floor, admin_state.hidden_at
FROM dataset_admin_catalogue AS stored
LEFT JOIN dataset_admin_state AS admin_state
  ON admin_state.source = stored.source AND admin_state.uuid = stored.uuid
WHERE stored.source = 'SOURCE_NAME' AND stored.uuid = 'SOURCE_UUID';

INSERT INTO dataset_admin_state (source, uuid, hidden_at)
SELECT source, uuid, clock_timestamp()
FROM dataset_admin_catalogue
WHERE source = 'SOURCE_NAME' AND uuid = 'SOURCE_UUID'
ON CONFLICT (source, uuid) DO UPDATE
SET hidden_at = COALESCE(dataset_admin_state.hidden_at, EXCLUDED.hidden_at)
RETURNING source, uuid, visibility_tier AS administrator_floor, hidden_at;

-- COMMIT only when inspection and RETURNING each identify the one intended row.
-- Otherwise ROLLBACK and investigate.
```

Execute `COMMIT;` or `ROLLBACK;` explicitly after inspection. A timeout aborts the
transaction; roll back before any retry. The upsert preserves an existing floor
and first hide timestamp. SQL emits no application administration event: record
the operator identity, time, exact SQL result and reason in the incident record.
After web recovery, perform the viewer checks above. Restore through the UI.

## Disposable-instance rehearsal

Rehearse the primary path on a disposable instance with a synthetic selected
source and a record approved for testing. Record the
revision, date, source/UUID, administrator ID, HTTP outcomes, all-tier viewer
checks and three change events for raise/hide/restore. Include a rejected
below-floor raise (4xx, no state change/event) and a repeated action (no-op).
Do not use a production record or reset an application database for this drill.

`src/tests/integration/test_dataset_admin_routes_db.py::test_withdrawal_ui_rehearsal`
automates the HTTP/service/database checks against the test harness's disposable
database. It complements the operator's browser/runbook rehearsal; a passing
automated test does not itself record that deployment exercise.
