# JSON-feed persistence and ingestion audit

Signed native feeds use the generic PostgreSQL ingestion engine.
[Catalogue](json-feed-catalogue.md) and [synthetic recovery](json-feed-acceptance.md)
checks cover downstream behavior; real-source acceptance remains separate.

## Signed input through PostgreSQL

Tests start with the registered adapter and signed native bytes, then use the
ordinary `run_sync()` and `run_full_rebuild()` paths. Fixtures control HTTP
delivery, time and process execution; real signature verification, parsing,
candidate serialization and PostgreSQL writes execute. Separate B6 TLS/process
tests cover the isolated transport boundary.

| Area | Required database behavior |
|---|---|
| Valid input | Persist accepted metadata with its source identity through the real write boundary |
| Quarantine | Discard an invalid replacement, retain the previous row for recovery, and withhold its serving copy until a valid fresh correction commits |
| Classification | Apply the source floor to the current explicit upstream tier; retain administrator restrictions |
| Administration | Preserve administrator floors and hiding across updates, rebuilds and withdrawal/reintroduction |
| Source isolation | Scope changes, failures, staging and withdrawals by `(source, uuid)`, including UUIDs shared by two sources |
| Recovery | Resume committed staging and preserve catalogue/cursor state on rejected input or failed writes |
| Fatal input | Preserve committed source state, apart from its error channel, after redirect, signature, UTF-8 or identity rejection |
| Resource limits | Preserve the same state for every byte/count cap and an expired fetch deadline |
| Cutoff protection | Refuse older snapshots before staging, pending replay writes or full-apply removals |

The cases are in `test_sensitive_source_sync_db.py`,
`test_sensitive_source_audit_db.py` and `test_sensitive_source_failure_db.py` under
`src/tests/integration/`. Failure coverage includes all six byte/count caps:
page, aggregate, record and result bytes, record/withdrawal count and page count.
Only the selected sync/rebuild error and its timestamp may change; the foreign
source's complete snapshot remains identical.

Quarantine protects its UUID from inferred deletion while valid neighbours can
proceed under the existing transaction and contraction guards. If that identity
already has a catalogue row, a separate durable `ingestion_quarantine` entry
withholds it from all catalogue tiers, search, facets and resource redirects.
The previous payload stays stored for recovery; no partial tier or other field
is adopted from the invalid replacement. New rejected identities have no serving
row. Unresolved
failures prevent clean completion/cursor advancement. Separate durable
consumed-snapshot progress still advances, so incremental polling stays bounded.
Scheduled full rebuilds retry every quarantined identity, including a corrected
record whose upstream timestamp did not change. New uncertain identities are
retained, and partial status remains degraded. A valid replacement
can clear its failure and replace the source tier, including a valid lower
explicit tier, subject to source and administrator floors.
Serving is restored only when a fully validated record from a later fresh
harvest is successfully persisted. Its harvest start must be later than the
quarantine's latest failed harvest start; replaying the same or older staged
input cannot restore serving. Its snapshot cutoff must also be at least the
latest rejected cutoff, including when the failed rebuild did not advance the
normal source cursor. Clearing quarantine shares the valid upsert's
transaction, so a later rollback retains the restriction. A corrected full
snapshot may retain its upstream timestamp; it is still a fresh harvest.
An all-invalid snapshot still upserts identity-only fixed quarantine reasons in
the existing status transaction. Prior failures, clean completion timestamps,
clean cursor/binding and staging remain; consumed progress advances separately;
quarantined rows retain their previous data without serving it.
No deletion is inferred. Optional explicit withdrawals commit and emit first.

Serving restrictions for rejected known identities commit before full-rebuild
reconciliation. Identified record-write failures are also persisted after their
batch or rebuild transaction finishes, including a rollback or cancellation.
Database failures are reported; a failed quarantine write is never reported as
successful containment. The independent source/UUID state survives catalogue
deletion, diagnostic cleanup and administrator hide/restore. Only a later valid
upstream correction clears it; there is no administrator override. Dataset
administration shows the identity and an explanatory pending-correction note,
withholding the old title and catalogue link.

The engine supplies its two-day overlap; the adapter only widens to whole
seconds. Equal committed cutoffs are allowed. Older cutoffs are refused even
when the requested overlap would include them.

## Transactions and durable restrictions

Incremental batches commit catalogue changes, failure state and staging progress
together. Audit buffers from successful savepoints merge into their owning
transaction; failed savepoints discard them. Earlier committed batches survive a
later failure, and replay resumes at committed progress.

Full rebuilds retain source-scoped contraction and uncertain-ID guards. A
zero-match rebuild may commit explicit withdrawals while returning `failed`;
it does not infer deletion of all unmentioned rows. A failed outcome therefore
does not universally mean that no changes committed.

Ingestion retains `dataset_admin_state`: its floor and hiding survive raw-row
withdrawal and apply when the same identity returns. Explicit valid corrections
can lower the source tier; an omitted tier retains its prior restriction.
Hiding excludes the identity independently of
its tier. See the [withdrawal runbook](../runbooks/emergency-dataset-withdrawal.md).

## Audit only committed changes

For sources with `requires_record_tier=true`, two INFO events on the `audit`
logger describe actual changes, regardless of adapter type:

| Event | Controlled state fields |
|---|---|
| `tier_changed` | `old_tier` and `new_tier`, comparing the existing row's effective tier with its durable administrator floor applied |
| `dataset_withdrawn` | `reason="explicit"` or `reason="inferred"`, only for a row actually deleted |

Records also contain `event_type`, `dataset_id`, `source` and `uuid`. State comes
from actual before/after queries or `DELETE ... RETURNING`. Insertions, unchanged
replays, raw-tier changes masked by an administrator floor, absent deletions and
rolled-back writes produce no corresponding event. Administrator hide/restore
audit events remain separate.

Events contain no titles, descriptions, URLs, raw metadata, credentials or
capability material. Effective-tier comparisons describe restriction state;
they do not grant permission to reveal a hidden dataset.

Buffers append stable-ID events to `security_audit_events` before their owning
transaction commits: each incremental batch, each authoritative-withdrawal
transaction and the rebuild transaction. Failed transactions discard their
pending events; a later failure does not undo earlier committed events.
Postcommit structured logs are additional operational copies. The owner-operated
exporter retries delivery to an independent sink, recording its matching durable
storage acknowledgement. The sink deduplicates repeated stable IDs. See
[security event delivery](../runbooks/security-event-delivery.md).

The independent `source_security_state` ledger retains the last accepted tier
when metadata is withdrawn and later returns without an explicit classification.
A fresh valid explicit upstream tier replaces that classification automatically,
including a lower tier. The source policy and independent administrator floor
continue to apply. Lowering appends a durable `source_restriction_lowered` event
with the old and new tiers in the same transaction. The ledger contains no
descriptive source metadata and cannot be cleared by runtime ingestion.

## Diagnostics and remaining evidence

JSON-feed phase failures use fixed status/log codes without upstream exception
text, tracebacks, record snippets or credentials. Native quarantine reasons are
`duplicate_record_key`, `record_shape`, `record_tier`, `record_timestamp` and
`record_metadata`; arbitrary uncertainty text becomes `record_rejected`.
Stale-cutoff rejection keeps its fixed text. DOI warnings omit raw values.
Public source/UUID identities remain available to locate failures; rejected
metadata does not enter diagnostic fields.

Run service-backed checks with `REQUIRE_DB=1` and `REQUIRE_REDIS=1`; collection
and unit checks do not replace PostgreSQL execution. Normal coverage and CI
gates remain in force.

[Catalogue checks](json-feed-catalogue.md) cover signed native records across
redaction, search, facets, counts and detail for every viewer tier. Real-source
activation still requires source-owner approval of the public envelope and a
representative encrypted isolated restore. See the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md) and
[Feed Contract v1](feed-contract-v1.md).
