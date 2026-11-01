# Durable security event delivery

Dataset administrator restrictions and configured ingestion restriction events
append metadata-free evidence in their mutation transaction. The owner-owned
`security_audit_events` table stores a stable UUID, database timestamp, event
type and bounded identity/restriction payload. There are no account or dataset
foreign keys: deleting an account or withdrawn metadata cannot erase evidence.
If an event cannot be appended, its owning mutation rolls back.

The web and scheduler producers can insert events, but cannot select, update or
delete them. Delivery receipts are private to the database owner. Include both
`security_audit_events` and `security_audit_receipts` in backups and recovery
checks. Backup readers need SELECT on both. Owner access remains a trust
boundary; a mutable database alone does not provide tamper-proof evidence.

## Sink contract

Provision an independently controlled HTTPS endpoint. The exporter sends one
JSON object per request:

```json
{
  "event_id": "eafde9c3-c05d-4446-9b20-538a2663ee75",
  "created_at": "2026-01-01T12:00:00+00:00",
  "event_type": "admin_dataset_hidden",
  "payload": {"actor_admin_id": 12, "dataset_id": 45}
}
```

Authenticate the exporter using its dedicated bearer token. The sink must
validate the event, durably store it, and deduplicate by `event_id`. Only then
may it return HTTP 200 with:

```json
{"event_id":"eafde9c3-c05d-4446-9b20-538a2663ee75","stored":true}
```

The response must identify the same event and fit within 4 KiB. Redirects,
non-200 responses, malformed receipts, mismatched IDs and `stored` values other
than JSON `true` fail delivery. TLS certificate verification is mandatory;
environment proxy/netrc configuration is not inherited. Connection/read timeouts
are two/five seconds and automatic HTTP retries are disabled.

An HTTP response by itself cannot establish the sink's storage guarantees.
Qualification must verify that its acknowledgement follows durable storage,
including during sink failure/restart. Protect the sink token, event readership
and independently managed retention. Do not place credentials in the sink URL.

## Exporting

Run the installed `scripts/export_security_audit.py` using the database-owner
operating-system identity. Supply only its protected `DATABASE_URL`,
`AUDIT_SINK_URL` and `AUDIT_SINK_TOKEN` environment. The command does not load
application Settings, authentication keys, SMTP credentials or source fetch
credentials. Supply secrets through an institution-managed protected mechanism,
not command-line arguments, shell history or ordinary web/scheduler profiles.

For example, after arranging that protected environment:

```sh
/opt/oralhistarchiv/.venv/bin/python \
  /opt/oralhistarchiv/scripts/export_security_audit.py --limit 100
```

The limit is 1–100 events per invocation. A transaction advisory lock admits one
exporter without waiting; producers continue independently. The command exits
nonzero on delivery/configuration/storage failure and prints no response bodies,
connection strings or transport exceptions. Schedule repeated invocations with
an overall service deadline and monitor failures. A successful invocation reports
the number of events acknowledged by the sink.

Receipts commit only after matching sink acknowledgements. If a batch fails,
its receipts roll back; the sink can receive already-stored events again after a
restart. Delivery is at least once, with stable IDs and idempotent sink storage,
not exactly once. Events are never deleted or modified by the exporter. A second
successful export sends no already-acknowledged events.

## Monitoring and retention

Using the owner connection, monitor pending count and oldest pending age:

```sql
SELECT count(*), min(event.created_at)
FROM public.security_audit_events AS event
LEFT JOIN public.security_audit_receipts AS receipt USING (event_id)
WHERE receipt.event_id IS NULL;
```

Alert on a growing backlog, an overdue oldest event, repeated exporter failure
and unexpected sink duplicates. Size local storage for outages. Define approved
local and sink retention; local pruning is an owner-controlled archival task and
must not remove unacknowledged evidence. There is no automatic lossy pruning.

Local structured log copies remain useful for operations but are not delivery
acknowledgements. Read-disclosure events remain a separate best-effort policy.
Only the committed security outbox closes the mutation-to-local-log crash gap.

## Qualification

The PostgreSQL tests verify mutation/event rollback, post-commit local logging
failure, retention after metadata deletion and receipt rollback/retry with stable
IDs. Sink tests reject missing, oversized and mismatched acknowledgements. Verify
the actual runtime roles cannot read or rewrite event history, and qualify the
real independent sink before claiming end-to-end durable delivery.
