# Monitoring and backup-publication checklist

**Template: adopt thresholds, owners and response procedures before use.**
The application supplies liveness, authorized diagnostics and an optional local
backup-publication age. It does not install an alerting service, configure PITR,
verify an off-host copy or demonstrate that recovery objectives have been met.
Keep completed monitor credentials, incident records and private results in
`<approved-restricted-monitoring-system>`.

## Ownership and approved thresholds

| Decision | Approved value or reference |
|---|---|
| Service, environment and configured source inventory | `<service-and-selected-source-register>` |
| Monitoring identity, credentials and restricted result handling | `<monitor-identity-and-credential-custody>` |
| Polling, timeout, retry and alert delivery | `<poll-timeout-retry-and-delivery-policy>` |
| On-call owner, deputy and escalation | `<response-owner-and-escalation-policy>` |
| Unknown/old backup age and timer failure thresholds | `<backup-freshness-and-failure-policy>` |
| Source-specific intervals and startup/grace decisions | `<source-interval-and-initialization-policy>` |
| Queue/retention, database/pool and Redis capacity limits | `<capacity-queue-and-retention-policy>` |
| WAL/base-chain, off-host receipt and replay-drill objectives | `<pitr-chain-lag-rpo-rto-and-drill-policy>` |
| Last exercise, review date and approver | `<exercise-review-and-approval-record>` |

A monitor must alert on its own failed or overdue collection. Silence, an empty
response or an inaccessible endpoint is not healthy evidence. Validate the
deployed credential, host routing, expected JSON shape and selected-source set.
Record changes to source names and intervals with the deployment that applies
them; diagnostics cover only the configured sources, not every retained row.

## Endpoint and transport checks

`GET /health` returns exactly `{"status":"alive"}` without database, Redis or
backup-marker reads. It is process liveness, not readiness or backup assurance.

`GET /health/detail` requires the exact Bearer `HEALTH_DETAIL_TOKEN` outside
development debug mode. Rejected authorization returns the generic 404 before
diagnostic reads. Keep the token out of URLs, command arguments, public logs and
dashboard exports. Use an approved restricted monitor-client configuration;
do not enable debug mode to make monitoring work. Responses are not cacheable.

The detailed endpoint retains security rate admission. Distinguish an outer
admission 503 from a valid health JSON response reporting a disconnected
database. Check status code, content type, JSON schema and the actual body:

| Observation | Interpretation and response |
|---|---|
| `/health` is unavailable | Inspect host/edge/web availability; dependency failures alone must not turn liveness into an automatic restart loop. |
| Detail returns 404 | Check the approved credential and routing privately; this response grants no diagnostic evidence. |
| Detail transport error, timeout, unexpected body or admission 503 | Monitor collection failed. Inspect edge/web/rate-limit dependencies and retry/escalate under the approved policy. |
| Valid detail JSON: `status=unhealthy`, HTTP 503 | Database check did not establish or retain connectivity. Use the database/pool check below. |
| Valid detail JSON: `status=degraded`, HTTP 200 | Database was reachable, but source or outbox diagnostics indicate trouble or could not be read. Follow the cause map; HTTP success alone is insufficient. |
| Valid detail JSON: `status=healthy`, HTTP 200 | The implemented database/source/outbox checks passed at that request. Independently assess backup age, off-host custody, capacity and PITR. |

Store only the minimum authorized diagnostic result. Recorded source errors can
contain operational details; a restricted health token does not make their
unfiltered publication safe. Use [Logging & Audit](../configuration/logging.md)
and the [incident procedure](../compliance/incident-response.md) for evidence
handling rather than copying credentials or private payloads into an alert.

## Every degraded cause and its query

All source fields below live under `checks.sources` for the configured source.
Source age is degraded only when **strictly greater than twice that source's
own configured interval**. At the exact boundary it is still healthy. Outbox
staleness uses **greater than or equal to** `OUTBOX_STALE_AFTER_SECONDS`.

<!-- HEALTH_DIAGNOSTIC_MAP_START -->
| Cause or observation | What to check | Read-only query or check |
|---|---|---|
| `sync_status_missing` | No status row exists for a selected source. | [Source state](#source-state-query); zero rows is the missing-row result. |
| `sync_stale` | No successful harvest, or harvest age is over twice the source's incremental interval. | [Source state](#source-state-query), `harvest_age_seconds` and `harvest_stale`. |
| `full_rebuild_stale` | No successful full rebuild, or rebuild age is over twice that source's rebuild interval. | [Source state](#source-state-query), `rebuild_age_seconds` and `rebuild_stale`. |
| `sync_error` | The independent incremental-error channel is populated; inspect its time and restricted scheduler evidence. | [Source state](#source-state-query), `has_sync_error` and `last_sync_error_at`. |
| `rebuild_error` | The independent rebuild-error channel is populated, even if incremental work succeeds. | [Source state](#source-state-query), `has_rebuild_error` and `last_rebuild_error_at`. |
| Source has `status=degraded`, `sync=error` without the specific fields above | Its query/diagnostic read failed after connectivity succeeded; earlier completed source results may still be present. | [Database/pool and read failures](#database-pool-and-read-failures), then [source state](#source-state-query). |
| `outbox_error` | Outbox diagnostics could not be read after database connectivity succeeded. | [Database/pool and read failures](#database-pool-and-read-failures), then [outbox state](#outbox-state-query). |
| `outbox_degraded` | One or more queue/failure/retention conditions in the following rows hold. | [Outbox state](#outbox-state-query) for every predicate; do not stop after the first. |
| `recent_failure_count` greater than zero | A dead delivery/body failure occurred in the past 24 hours; cancellation is excluded. | [Outbox state](#outbox-state-query), recent failure count; then restricted delivery-worker evidence. |
| `oldest_pending_age_seconds` at least the configured stale threshold | Pending mail is too old. | [Outbox state](#outbox-state-query), pending age; inspect producer/delivery scheduling and relay state. |
| `oldest_sending_age_seconds` at least the configured stale threshold | Claimed sending work is too old. | [Outbox state](#outbox-state-query), sending age; inspect delivery-worker deadline/reaping and scheduler state. |
| `retention_overdue_count` greater than zero | Sent/dead terminal rows are older than their separate configured retention periods plus two hours' grace. | [Outbox state](#outbox-state-query), terminal retention; inspect `outbox_retention` scheduling. |
<!-- HEALTH_DIAGNOSTIC_MAP_END -->

A nonzero `dead_count` alone does **not** degrade health. Counts cap at 1,000;
equality means at least that many, not a complete total. Empty queue ages are
null. A SQL query cancellation/read failure during the initial `SELECT 1` is unhealthy;
after successful connectivity, an ordinary source/outbox read failure is
degraded. Connection and pool failures can make the response unhealthy at any
stage. The diagnostic snapshot is per request, not a historical availability
measurement or an automatically consistent multi-system incident timeline.

## Read-only investigation queries

Run these through the approved existing runtime/monitoring access procedure,
under the intended database identity and a read-only transaction with a bounded
statement timeout. Do not grant new database privileges just to make a query
pass. Do not use the owner/migration credential for routine monitoring. Never
reset, migrate, truncate or restore a retained database to diagnose a monitor.

For `psql` examples, supply reviewed values for `source`,
`incremental_interval_seconds`, `rebuild_interval_seconds`,
`sent_retention_days`, `dead_retention_days` and `outbox_stale_after_seconds`
using its variable mechanism. The `:'name'` syntax quotes values as SQL
literals. Obtain intervals/retention from the effective deployed configuration,
not an unrelated default. Save detailed results only in the approved system.

### Database, pool and read failures

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT current_database(), current_user, session_user, 1 AS reachable;
SELECT state, COUNT(*) AS own_connections
FROM pg_catalog.pg_stat_activity
WHERE usename = current_user
GROUP BY state;
COMMIT;
```

An independent successful query does not prove the application pool had spare
capacity earlier. Correlate the request time with web/scheduler journals,
runtime preflight, peer/socket permissions, database availability, pool
admission and timeout diagnostics. `QueryCanceled` after established
connectivity differs from a connection failure; do not classify all SQL errors
as a dead PostgreSQL service. A permission/schema error needs its reviewed
deployment repair, not an expanded runtime grant.

### Source state query

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT source, last_harvest_date, last_full_rebuild_date,
       EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - last_harvest_date)
           AS harvest_age_seconds,
       EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - last_full_rebuild_date)
           AS rebuild_age_seconds,
       last_harvest_date IS NULL OR
           CURRENT_TIMESTAMP - last_harvest_date >
           make_interval(secs => 2 * :'incremental_interval_seconds'::double precision)
           AS harvest_stale,
       last_full_rebuild_date IS NULL OR
           CURRENT_TIMESTAMP - last_full_rebuild_date >
           make_interval(secs => 2 * :'rebuild_interval_seconds'::double precision)
           AS rebuild_stale,
       COALESCE(last_sync_error, '') <> '' AS has_sync_error,
       last_sync_error_at,
       COALESCE(last_rebuild_error, '') <> '' AS has_rebuild_error,
       last_rebuild_error_at
FROM public.sync_status
WHERE source = :'source';
COMMIT;
```

Compare configured sources separately. Deselection removes a source from
`/health/detail`, but this SQL can still read its retained status; catalogue
rows also remain. Investigate incremental/rebuild errors independently and
recover through the normal workflow rather than clearing diagnostics.

### Outbox state query

Recipient/account lock contention retries after 30 seconds and refunds a claim
when no SMTP attempt occurred. On a contention event at **one hour of total
queue age**, including the exact boundary, the message becomes `dead` with
`terminal_outcome='delivery_failed'` and
`last_error='delivery_state_contention_exhausted'`. This is a separate bound
from the seven SMTP delivery attempts: old mail is not retried indefinitely
behind a locked account. The worker emits `email_outbox_contention_exhausted`;
the normal recent-failure health condition and dead-message retention apply.
Investigate sustained account-row locking before issuing a fresh action message
through the supported workflow. The cutoff may abandon eventually deliverable
mail; it never overrides expiry or reactivates the old capability.

The query below returns investigation totals; `/health/detail` deliberately
caps its counts at 1,000. It exposes no recipient, subject, body or credential.

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT COUNT(*) FILTER (WHERE status = 'pending') AS pending_count,
       COUNT(*) FILTER (WHERE status = 'sending') AS sending_count,
       COUNT(*) FILTER (WHERE status = 'dead') AS dead_count,
       COUNT(*) FILTER (WHERE status = 'dead'
           AND last_error = 'delivery_state_contention_exhausted')
           AS contention_exhausted_count,
       COUNT(*) FILTER (
           WHERE status = 'dead'
             AND terminal_outcome IN ('delivery_failed', 'body_unreadable')
             AND failed_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
       ) AS recent_failure_count,
       GREATEST(0, EXTRACT(EPOCH FROM CURRENT_TIMESTAMP -
           MIN(created_at) FILTER (WHERE status = 'pending')))
           AS oldest_pending_age_seconds,
       GREATEST(0, EXTRACT(EPOCH FROM CURRENT_TIMESTAMP -
           MIN(locked_at) FILTER (WHERE status = 'sending')))
           AS oldest_sending_age_seconds,
       COUNT(*) FILTER (
           WHERE status = 'sent' AND sent_at < CURRENT_TIMESTAMP -
               make_interval(days => :'sent_retention_days'::integer) - INTERVAL '2 hours'
       ) + COUNT(*) FILTER (
           WHERE status = 'dead' AND failed_at < CURRENT_TIMESTAMP -
               make_interval(days => :'dead_retention_days'::integer) - INTERVAL '2 hours'
       ) AS retention_overdue_count
FROM public.email_outbox;
COMMIT;
```

Compare the two ages with the effective `outbox_stale_after_seconds` value.
For an empty category, PostgreSQL's `GREATEST(0, NULL)` here displays zero;
the health API returns null. The threshold is positive, so this investigation
display difference does not change the stale predicate. Check the scheduler,
SMTP provider and child-process diagnostics without bypassing action-link
expiry or replaying messages blindly. See [email-action handling](action-links.md)
and [terminal retention](../configuration/deployment.md#terminal-email-retention-and-delivery-monitoring).

## Backup marker and independent backup checks

The web setting `BACKUP_STATUS_FILE` is optional and defaults to disabled. The
reference deployment points it at
`/var/lib/oralhistarchiv-backup-status/last-success`; the backup configuration's
`BACKUP_STATUS_DIR` names the containing directory. That separate directory is
backup-owned 0755 and contains only a 0644 nonsecret timestamp marker. Archive
storage stays 0700 and ciphertext stays 0600. No web group, archive, recovery-key
or database privilege is added.

The exact marker is `OHA_BACKUP_SUCCESS_V1 <positive-Unix-seconds>` plus one
newline. It is published atomically after local encrypted archive publication,
retention and backup-directory synchronization. Age uses this content, not
mtime: copying or touching an old marker does not make a backup newer.

- `checks.backup.status=ok` supplies a nonnegative integer `age_seconds` for a
  valid marker. Apply `<approved-backup-age-alert-seconds>` in the monitor.
- `checks.backup.status=unknown`, `age_seconds=null` means disabled, missing,
  inaccessible, malformed, oversized, unsafe/nonregular, future-dated or
  temporarily unavailable marker information. Alert under the approved policy;
  inspect file/configuration/clock/worker-capacity state with the responsible
  operator. No path or raw file contents appear in the health response. The
  0.2-second budget limits worker admission, not an already-admitted filesystem
  read; keep the configured path on protected local storage.
- Backup observations do not change the endpoint's existing database/source/
  outbox readiness classification. A healthy response with unknown or old
  backup age still needs a backup alert.

Inspect the backup service and timer independently:

```console
systemctl show oralhistarchiv-backup.service -p Result -p ExecMainStatus
systemctl status oralhistarchiv-backup.timer --no-pager
journalctl -u oralhistarchiv-backup.service --since today --no-pager
```

The marker identifies a local encrypted-publication checkpoint, not necessarily
the last unit exit result. A crash or synchronization/logging failure after its
rename can leave a new marker alongside a failed/unknown unit. Failures before
marker publication preserve the old timestamp. A marker-publication failure
can leave a valid new archive with an older marker; investigate both signals.

Require separate evidence for off-host receipt, authenticated provenance,
key custody, complete decryption/restore, inventory completeness and drill
age. A table-of-contents listing is not a restore. See the
[backup controls](../configuration/deployment.md#encrypted-backups-under-a-separate-identity),
[key rotation](key-rotation.md), [recovery acceptance](visibility-recovery-acceptance.md)
and [PITR template](point-in-time-recovery.md).

## Capacity, WAL and response rehearsal

Monitor disk/inodes, PostgreSQL/pool capacity, scheduler/job failures, log
shipping/expiry and alert delivery. Observe the dedicated limiter Redis using
its separate approved `PING`/`INFO` monitoring identity; never hand its monitor
credential to the web or scheduler or broaden the web limiter's key authority.
Review persistence, eviction/TTL policy and errors as well as memory. Optional
catalogue-cache Redis is a separate dependency.

The bounded counter registry can refuse new allocations before Redis reaches
its physical memory ceiling. Investigate `rate_limit_backend_unavailable` with
category `capacity` without flushing live quotas or deleting registry state.
Compare the chosen counter cap, observed traffic and tested memory headroom.
Startup refusal after a legacy deployment can mean unregistered retained
counters; follow the stopped-writer TTL-drain procedure in
[deployment guidance](../configuration/deployment.md#redis-for-shared-state).

Search has its own one-connection pool per web worker, a shared start budget and
a nonblocking PostgreSQL transaction lock. Monitor `search_start_budget_exhausted`
and `search_unavailable` separately from ordinary pool failures. Exercise all
search modes while login/detail traffic continues; record its latency/error
envelope, PostgreSQL load and connection counts. Search timeout/refusal must not
send work to the ordinary pool. Keep the start gate enabled even when ordinary
per-client limiting is disabled. See [search load acceptance](search-fulltext.md#capacity-and-load-acceptance).

An exhausted start budget returns a styled 503 with `Retry-After`,
`Cache-Control: no-store` and a query-free “Back to search” link. It logs
`search_start_budget_exhausted`; backend failures instead log
`rate_limit_backend_unavailable`. This happens before session lookup without
database access or cookie issuance, so omitted account controls and a null
logged user ID do not mean the browser lost its login. JSON logs retain event,
request and safe failure-category fields; text logs show distinct messages.

If the separately approved PITR design is deployed, inspect its dedicated
archive-job results, off-host acknowledgements, base/WAL/history chain
completeness, archive lag, private-key recoverability and actual replay-drill
age. An authorized database operator can inspect `pg_catalog.pg_stat_archiver`
and filesystem capacity. Neither an advancing archived-segment count nor
`checks.backup` proves a complete usable retained chain. Failed archiving can
fill `pg_wal`; low-write periods also need an approved archive-lag strategy.

Exercise missing source history, stale/error channels, outbox failure/staleness/
retention, inaccessible or old markers, timer failure, monitor credential
failure and alert-delivery failure on explicitly disposable infrastructure.
Record `<scenario-observation-alert-response-and-review-reference>` with the
actual query/check, owner, timestamps and recovery verification. Keep unresolved
causes open; do not weaken checks or edit state merely to turn a dashboard green.
