# OAI-PMH Sync Pipeline

SWISSUbase (Source A) is the only enabled source. PostgreSQL serves the local
catalogue: source curators own metadata corrections, publication and withdrawal,
while administrators may impose stricter local visibility classifications.
Search and detail requests read PostgreSQL, never the upstream API.

## Scheduling and serialization

`run_scheduler.py` owns APScheduler, its pool and shutdown tracking; web workers
never start scheduler jobs. Incremental sync starts immediately, with the first
full rebuild staggered five minutes later. Settings control later intervals.
Session cleanup, unverified-account cleanup, outbox delivery and outbox
retention are separate tracked jobs; see `services/scheduler.py`.

Incremental sync and full rebuild share both an in-process `asyncio.Lock` and
a PostgreSQL session advisory lock. Every catalogue and status transaction
uses the same connection that owns that lock. Losing that connection fences
the old job: it cannot continue writing through a replacement pool connection.
Cancellation rolls back the active transaction and releases the session lock;
a connection with uncertain cleanup is closed before returning to the pool. This prevents an overlapping rebuild from resurrecting a tombstone
using an older snapshot. Per-job `max_instances=1` alone is insufficient.

After each sync attempt, the scheduler invalidates the global statistics
cache. Redis pub/sub distributes invalidation to workers; TTL is a fallback.
Only total dataset count and last completed rebuild time are cached.
Tier-sensitive facets and home metadata counts are always read live.

## Source cursor versus operational timestamps

`source_cursor` records the completed harvest's first OAI `responseDate`; `last_harvest_date` and `last_full_rebuild_date` record local run-start time. Incremental requests use the UTC date two days before the cursor, inclusively. Older delayed changes require a full rebuild.

A missing or changed committed source fingerprint requires a full rebuild; the scheduler performs it immediately on the incremental recovery outcome. With a matching fingerprint but no cursor, incremental fetching starts at `1900-01-01`. The fresh migration leaves both cursor and fingerprint unset. A successful empty poll updates local liveness without advancing the cursor; unresolved identities prevent advancement.

## Complete, bounded harvests

Network/XML work runs in a spawned process before catalogue writes. A 240-second parent watchdog bounds waits; cleanup and synchronous result decoding can extend elapsed time. HTTP connect/read timeouts are ten seconds, with up to three retries. `OAI_MAX_PAGES` caps pages; fixed limits are 4 MiB/page, 32 MiB received, 1 MiB/XML record, 20,000 records, 16 MiB retained/serialized result, and 4,096 resumption-token characters. Responses stream into bounded pages; the successful attempt's XML records are then retained together for classification. Compressed responses and redirects are rejected.

Require the OAI root, one valid first-page `responseDate`, and `ListRecords` except first-page `noRecordsMatch`, which is empty success. Continuations require an explicit terminal token element. Repeated tokens, duplicate identities, malformed identities, and other protocol failures abort the harvest. A rejected continuation token triggers one fetch without `from`, followed by inclusive local datestamp filtering under the original budget.

Each record needs exactly one header/identifier; text is stripped. The supported CMDI profile requires one Dataset. Institution membership is classified before content validation, so a definite nonmatch is withdrawn even with malformed title content. Matching records require nonblank titles with distinct language tags. Unknown profiles and absent/unusable institutions are uncertain and retain existing catalogue rows. Protocol diagnostics retain bounded code/message text; validation diagnostics omit input values.

`ParsedRecord` validates required keys/types at parsing, decoding, orchestration, and writes. Nullable fields and arrays may be empty. Keyword/language labels contain 1–256 characters. XML entity resolution, DTD loading/validation, and network loading are disabled. Resource/license URLs use the shared HTTP(S) policy. DOI URI forms decode once and fold ASCII case; bare DOI names preserve percent characters. Raw parsed values remain in JSONB `data`.

## Incremental writes and recovery

Stage a versioned harvest with its source fingerprint, start time, position, 
and affected count in `sync_status`. Resume it before fetching again. 
Format/parser changes compatible with the source can reset staging for refetch; 
corrupt or source-incompatible state requires a full rebuild. Never advance a 
cursor manually to suppress failures.

Process sorted explicit deletions/nonmatches before matching records. Each 
identity has a savepoint; batches commit catalogue changes, failure records, 
and progress together after 50 items or a two-second elapsed check between 
items. The two seconds are not a hard transaction deadline. Cancellation/failure 
rolls back the active batch, preserving earlier commits; replay starts at the 
last committed position. Recoverable data/constraint/validation failures are 
stored in `ingestion_failures`, not the unused `incremental_failures` column. 
A later empty poll cannot clear them.

`SYNC_WRITE_TIMEOUT_SECONDS` bounds each incremental staging/replay phase 
and full-rebuild application through async cancellation. Synchronous encoding 
is not preempted by that timeout. Write failures are reported in a separate 
five-second attempt on the same advisory-lock connection, then re-raised. 
Lost connections cannot be replaced to continue writes.

`SourcePolicy` supplies the source-specific access classifier and clamps
visibility. Source A has no per-record application tier and uses
`SWISSUBASE_MAX_VISIBILITY` as a source-wide publication ceiling. New rows use
the resolved source tier. For an existing `(source, uuid)`, the shared upsert
atomically stores the stricter of the current and incoming tiers, using the
ranking defined in `access_tiers.py`. Incremental updates and full rebuilds
therefore preserve administrative restrictions while accepting metadata
updates and any stricter incoming classification. See
[Access Control & Visibility](access-control.md#how-visibility_tier-gets-set)
for the direct-database administrative workflow.

## Full rebuild

Replay pending incremental work when possible, then fetch from `1900-01-01`. Unreplayable staging remains until replacement reconciliation commits. Fetch failure preserves catalogue data. With no matching records, apply explicit withdrawals only, preserve all unmentioned rows and completion timestamps, and return `failed`.

For a nonempty harvest, one transaction applies explicit withdrawals, checks inferred deletions, removes absent rows, and upserts matches. Inferred deletion above 100 rows **or** 25% of remaining source rows aborts all changes. Keep matching and uncertain UUIDs, including failed replacements. DOI-dependent records share a savepoint so swaps can clear old DOIs and apply together; a group failure restores every member. Fewer than half successful matching writes aborts the transaction.

Accepted partial rebuilds commit healthy changes and replace the failure set but leave completion timestamps, cursor, and source binding unchanged. Clean rebuilds advance both timestamps and cursor/binding and clear both error channels. Incremental success does not clear rebuild errors. Surviving UUIDs retain local IDs.

Runners return `SyncOutcome` (`success`, `partial`, `failed`) or raise infrastructure/write errors. Returned ingestion outcomes log `ingestion_job_outcome`, including partial/failure; escaping errors log `scheduler_job_error`. Count semantics are documented on `SyncOutcome`; a failed outcome can still include explicit withdrawals. Repair upstream metadata or use the [withdrawal runbook](../runbooks/emergency-dataset-withdrawal.md).

## Schema changes and future sources

Update column/dataclass/parser contracts and add a migration together; startup compares managed PostgreSQL objects with declared contracts. Follow [Deployment](../configuration/deployment.md) for owner-run migrations and runtime grants.

The only migration is a fresh-install baseline. No historical DOI backfill or legacy upgrade chain is included; an existing database needs a separately designed and tested upgrade path.

Source B has no enabled adapter. Its future transport, authentication, permissions, and reconciliation must satisfy the [Source B contract](source-b-ingestion-contract.md).
