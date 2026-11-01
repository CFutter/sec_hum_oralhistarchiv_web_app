# Source Ingestion Pipeline

The scheduler imports configured sources into PostgreSQL. The shipped development
example selects only the bundled fixture adapter. Source curators own metadata
corrections, publication and withdrawal. Archive administrators can impose stricter
local metadata visibility and hide datasets through the administrative controls.
Catalogue requests read PostgreSQL, never the upstream API.

## Adapter boundary

`app.sources` exports `AccessTier`, `SourcePolicy`, source configuration models,
`SourceDisplay`, `SourceSchedule`, `ConfiguredSource` and the `SourceAdapter`
protocol. Production consumers outside that package import its public API.
The shared tier, parsed-record and harvest contracts are defined in
`app.ingestion_contracts`, whose initializer exposes their public API.
`services/access_tiers.py` owns ranking and resolution functions.

The adapter protocol consists of a persistent name, write policy,
`config_fingerprint()` and blocking `fetch(*, since=...)`. Display metadata and
schedules belong to `ConfiguredSource`. Configuration models are strict and
frozen; construction rejects disagreement between configuration, adapter
identity and actual write policy.

Four adapters are registered:

| Adapter | Native input |
|---|---|
| `oai_pmh_cmdi` | Remote OAI-PMH records using the supported CMDI profile |
| `fixture` | Bundled synthetic `catalogue_v1` snapshot |
| `static_json` | Bundled synthetic `proof_v1` snapshot |
| `json_feed` | Authenticated HTTPS feed implementing Feed Contract v1 |

Adapters capture their configuration before fetching. Fingerprinting and the
parsing, classification and serialization paths use neutral contracts without
loading global settings or runtime services. Adapters import these shared APIs
through `app.ingestion_contracts`; a local service import during fetch would
reintroduce the dependency. Every ingestion run uses the same adapter instance
for its fingerprint and fetch.

The fetch boundary is an aware timestamp or `None`; wrong types and naive
timestamps are rejected. The engine normalizes the committed cursor to UTC,
subtracts its two-day overlap and offloads blocking fetch to a threadpool.
`None` requests full input.

Adapters may widen an inclusive lower boundary to their native granularity,
never narrow it. OAI uses an inclusive UTC date and retains `1900-01-01` as its
full-input transport baseline. Bundled adapters use inclusive UTC days.
JSON feeds round down to a whole UTC second and do not subtract another overlap.

## Runtime source selection

The scheduler calls `app.services.load_runtime_sources()`; web workers call the
secret-free `load_runtime_catalogue_sources()` counterpart. Both run after shared
security validation and before opening runtime resources. An explicit
`SOURCES_CONFIG_FILE` is required. Missing or empty selection, file errors,
invalid configuration, missing credentials and startup-policy failures abort
startup without fallback. Each process retains its ordered source tuple until
restart.

Settings construction validates selector syntax without reading the source
file. It may retain `None` for imports, migrations and offline inspection;
runtime selection then refuses to start. Process settings come from the
environment and, in development, dotenv. Source interpretation, labels,
schedules and adapter inputs come from the selected TOML.

The seven retired global source settings and `SEED_MOCK_DATA` are rejected,
including false or empty assignments. The
[settings reference](../configuration/settings.md) describes the source-TOML
fields that replace them.

The source file uses flat `[[sources]]` entries. Display, schedule and
adapter-specific fields share each entry; nested display/schedule tables are
not accepted. The parser selects the registered configuration model from
`adapter` and rejects unknown fields and ambiguous source sets.
See `deploy/environment/sources.example.toml` for the schema example.

### Construction and credentials

`configure_sources()` constructs validated descriptions without fetching or
reading ambient secrets. JSON-feed sources require explicit, source-bound
`JsonFeedCredentials` snapshots prepared by `prepare_json_feed_startup()`.

Within `app.sources.configuration`, `configure_sources_from_toml()` parses a
supplied document and `load_sources_file()` reads an explicit UTF-8 path.
These construction-only helpers likewise accept prepared `credentials`.

`load_sources_for_startup()` adds deployment startup policy and accepts an
explicit `environ` mapping. Omitting that argument means an empty mapping,
not a process-environment lookup. The application runtime caller,
`app.services.load_runtime_sources()`, deliberately passes `os.environ`.

All selected feed descriptions, credential identities, reference roles and
cross-source secret separation are validated before any adapter factory runs.
Bearer and signing credentials use separate references. Signing keys cannot
be shared between feeds or reused as bearer material.

Construction captures frozen configuration and credential snapshots. Changing
the supplied mapping afterward does not update a running process. Credential
rotation therefore requires a fresh snapshot and process restart.

### File and endpoint policy

Development accepts an ordinary readable path. Staging and production require
a direct absolute POSIX path without parent traversal or symlink components.
The file and every opened directory must be root-owned and not group- or
other-writable. Validation and reading use the same opened descriptors;
nonregular files are rejected and descriptors close on every exit path.

OAI endpoints must be credential-free. Staging and production additionally
require HTTPS and reject placeholder hosts.

JSON-feed endpoints require credential-free HTTPS in every environment.
Staging and production also reject placeholder hosts.

Production sources using either `fixture` or `static_json` require explicit
`ALLOW_FIXTURE_SOURCE=true` permission. Permission alone does not select a source.

See [Sources](../sources/index.md) and
[JSON-feed configuration](../sources/json-feed-configuration.md).

### Deterministic fixture adapter

The registered `fixture` adapter serves the bundled `catalogue_v1` dataset:
three synthetic records with explicit public, registered and vetted tiers.
These labels exercise metadata visibility and do not establish sensitive-source
acceptance.

Construction snapshots package bytes once, reading at most `max_bytes` plus
one overflow-detection byte. `max_bytes` defaults to 65,536 and cannot exceed
1 MiB. Direct adapter construction requires immutable bytes and enforces the
hard maximum. No arbitrary file path or endpoint is accepted.

Its fingerprint binds the adapter contract version, dataset name, exact payload
digest, source identity and visibility policy. Display metadata, schedules and
byte budgets are excluded. Fingerprinting and fetching use the same snapshot;
a changed package file affects newly constructed adapters.

Fixture boundaries normalize to UTC and widen to an inclusive UTC day. `None`
selects the complete catalogue. The fixed cursor is
`2020-01-04T00:00:00+00:00`. Any boundary on that UTC date returns no records;
boundaries on later UTC days are rejected. A timestamp later than midnight on
the cursor's day therefore still returns an empty harvest.

Every fetch decodes fresh records and validates the entire snapshot before
filtering. The fixture permits matching records only, requires modification
timestamps no later than its cursor and enforces mandatory record tiers when
configured. The exact `Public access` label maps to public resource access;
all other labels map to restricted. This label does not grant access to an
external resource.

The common source restriction defaults to `vetted`. The shipped development
configuration explicitly sets `max_visibility="public"` and
`requires_record_tier=true` so the three record tiers remain distinct.

Fixture ingestion uses the normal source binding, staged recovery, write policy
and scheduler wrapper. Scheduler startup provisions its source-status row.
An unbound source's immediate incremental job requests an authoritative rebuild;
the wrapper starts that recovery without waiting for the periodic rebuild.
There is no separate fixture bootstrap or database mock seeder. The web process
does not write fixture catalogue rows.

After that rebuild, normal incremental polling subtracts the engine's two-day
overlap from the fixed cursor. The fixture receives `2020-01-02` and reoffers
the registered and vetted records. Repeated polling remains deterministic and
does not move the fixed upstream cursor forward.

The `static_json` adapter follows the same bounded package-snapshot approach
with its independent native `proof_v1` format and contract version.

## Scheduling and serialization

`run_scheduler.py` owns APScheduler, its pool and shutdown tracking. Web workers
never start scheduler jobs. Each selected source receives an immediately due
incremental job and its own periodic rebuild job.

Initial periodic rebuilds are scheduled five minutes multiplied by source
position in configuration order: five minutes for the first source, ten for
the second and so on. Later runs use that source's configured intervals.
Recovery-triggered rebuilds run through the existing wrapper, subject to the
ingestion locks, without waiting for the periodic rebuild. A changed existing
source binding first requires explicit owner acknowledgement; neither a
periodic rebuild nor a restart bypasses that review. Periodic jobs remain
scheduled independently.

`create_scheduler()` requires an ordered, nonempty collection of uniquely named
sources. Job IDs are `incremental_sync:<name>` and `full_rebuild:<name>`;
tracker IDs match them. Each job retains its exact configured source.
Session cleanup, unverified-account cleanup, outbox delivery and retention
are registered once as shared tracked jobs.

Incremental sync and full rebuild share an in-process `asyncio.Lock` and a
PostgreSQL session advisory lock. Sources therefore ingest serially.
Every catalogue and status transaction uses the connection owning that advisory
lock. Losing the connection fences the old job: it cannot continue writing
through a replacement pool connection.

During source fetching, cancellation sets a parent-side event. Both network
supervisors check it during pipe/message/exit waits, terminate the child and
reap it before the thread returns. The ingestion lock and scheduler tracking
remain owned until that thread completes. OAI and feed shutdown waits are
bounded to one second per cleanup stage, fitting the scheduler's five-second
cancellation grace for the supported process cleanup path. Parent-side bounded
result decoding remains cooperative, as described below.

Cancellation rolls back the active transaction and releases the session lock;
a connection with uncertain cleanup is closed before returning to the pool.
Per-job `max_instances=1` alone does not supply this cross-job serialization.

Administrator dataset-state mutations cooperate with the same advisory-lock
identity using a transaction lock. They do not change ingestion's session-lock
fencing.

After each sync attempt the scheduler invalidates rebuild freshness.
Redis pub/sub distributes invalidation to workers; the one-hour TTL is the
fallback. The cache holds only the oldest selected-source rebuild timestamp,
including an unknown (`None`) result. Freshness fills query source status without
counting catalogue rows. Public dataset totals and tier-sensitive facets are
read live. Home does not calculate language or keyword totals.

## Source cursor versus operational timestamps

`source_cursor` is the validated upstream watermark:

| Adapter | Cursor |
|---|---|
| `oai_pmh_cmdi` | The completed attempt's first `responseDate` |
| `fixture` | Fixed bundled snapshot cursor |
| `static_json` | Fixed bundled snapshot cursor |
| `json_feed` | The complete chain's first `generated_at`, shared by every page |

The operational `last_harvest_date` and `last_full_rebuild_date` record successful
local run-start timestamps, not completion times. Resumed incremental work retains
its original staged start time.

Incremental requests pass the UTC cursor minus two days to the adapter.
Adapters widen that boundary only as needed for their native timestamp
granularity. Older delayed changes require a full rebuild. With a matching
fingerprint but no cursor, incremental fetching requests full input.

A missing consumed-snapshot fingerprint requests an authoritative initial
rebuild. A changed existing fingerprint stops before fetch or replay until its
exact previous/target pair has been acknowledged by the owner. See the
[source rebinding runbook](../runbooks/source-rebinding.md).

`source_fetch_cursor` and `source_fetch_fingerprint` record consumed snapshot
progress separately from clean completion. Once a full reconciliation commits
valid rows and durable quarantine, subsequent incremental ticks use that fetched
cursor even if some identities remain uncertain. They do not launch the same
full recovery every hour or repeatedly widen a pinned incremental window.
The older `source_cursor`/`source_fingerprint` and completion timestamps retain
clean-state meaning. A changed interpretation becomes clean only after a
successful full rebuild; partial or aborted rebuilds cannot claim completion.

Every uncertain or failed identity stays in `ingestion_failures`, including
legitimate new records. Existing last-good rows remain protected. An ordinary
incremental correction or explicit withdrawal clears that identity's failure;
the existing scheduled full rebuild retries every remaining identity even if
its upstream modification timestamp never changes. The retry delay is therefore
at most the configured rebuild interval when the source is available and the
rebuild completes (one day by default). Operators can invoke the documented full
rebuild entrypoint for an earlier retry. Partial status remains visibly degraded.
This policy advances acquisition while explicitly retaining incomplete catalogue
state; it does not silently discard quarantine.

Even an empty incremental poll advances consumed progress. Clean empty polls
retain the earlier clean cursor as before. Unresolved failures prevent clean
liveness/cursor advancement, not consumed-snapshot progress. An all-uncertain
rebuild retains non-explicit rows and clean state while persisting its quarantine
and fetched cutoff. An entirely empty rebuild has no retry set and remains
ambiguous; it does not establish a new consumed binding. Contraction or write-threshold aborts publish
no fetched progress because their catalogue transaction rolled back.

### Interpretation fingerprints

OAI fingerprints bind source name, endpoint, institution filter,
`max_visibility`, `requires_record_tier`, the exact access-label mapping and
fallback, and the CMDI parser contract version. Version 2 extracts the first
validated `Dataset/Overview/Dataset_title` node. Introducing this version
changes existing OAI bindings: reviewed rebinding requires an
authoritative rebuild, which reparses unchanged records and replaces old
titles. Old staged output cannot bypass the binding check. Do not stamp the
new fingerprint onto old catalogue data or pending harvests.

Fixture and static JSON fingerprints bind source name, visibility policy,
dataset, contract version and exact payload digest.

JSON-feed fingerprints bind source identity, endpoint, adapter identifier,
feed-contract and interpretation revision, mandatory record tiers, source floor,
reviewed public/access mappings, and the `credential_env` and `signing_key_env`
reference names.

Resolved secret values, display metadata, schedules and operational budgets do
not change JSON-feed interpretation bindings. Rotating values under unchanged
references requires a fresh snapshot/restart without a rebuild. Changing either
reference name requires owner acknowledgement and an authoritative rebuild.

Stored-envelope and parsed-record versions have their own recovery checks.
Do not overwrite a stored fingerprint or cursor to bypass recovery.
A failed or partial rebuild retains the old clean binding and cursor, although
permitted withdrawals or valid partial writes may already have committed.
Successful partial reconciliation separately publishes consumed progress;
rolled-back reconciliation does not.

A binding change does not rewrite stored tiers. After the explicit catalogue
[policy transition](../runbooks/search-policy.md) and restart, tighter source
floors/field minima constrain existing reads before ingestion catches up.
Ingestion still needs acknowledgement and rebuild for changed interpretation.
Lowering configuration alone does not lower retained stored tiers; valid explicit
upstream corrections can do so.

### JSON-feed cutoff protection

For `JsonFeedConfig` sources, the engine compares the candidate cutoff with
the latest of clean and consumed source cursors under the existing ingestion/fencing boundary:

- Before staging newly fetched incremental input.
- Before replaying a stored incremental harvest.
- At incremental application before failure-set, catalogue or progress changes.
- Before full reconciliation, including its zero-matching-record path.

Older cutoffs are rejected. Equality and an absent committed cursor are allowed.
Invalid or naive committed timestamps fail closed.

Full reconciliation rereads the committed cursor after any pending incremental
recovery, because that recovery may already have advanced it. A full snapshot
older than the resulting commitment is rejected before applying its removals.

Rejected snapshots do not stage or apply their catalogue, failure-set, progress
or cursor changes. The caller may still record a status diagnostic.
The adapter's overlapping `since` is not this committed-cursor guard.

## Source-keyed persistent state

`sync_status` is keyed by persistent source name. The fresh-install migration
creates an empty source-state table. Runtime schema and role validation are
read-only; after they succeed, scheduler startup inserts missing selected rows
with `ON CONFLICT (source) DO NOTHING`.

Existing state is preserved. Newly provisioned rows have no cursor or
fingerprint, retaining the initial full-rebuild fence. Every status read and
write is source-scoped, including progress, staged recovery, errors and
finalization. State helpers require an explicit source name derived from the
selected `ConfiguredSource`; they do not infer ownership from a global policy.
Incremental and rebuild entrypoints require `configured_source`, and recovery
retains that object.

The scheduler provisions the selected identities and passes its source tuple
to job registration and cache construction. Web retains its own tuple as
`app.state.configured_sources` without provisioning source state or harvesting.

Authorized health diagnostics use each selected source's schedule. About
displays configured labels, optional sensitivity descriptions and finite
persisted-state badges. These are recorded-history indicators, not live upstream
probes. Home freshness uses the oldest selected-source rebuild and remains
unknown when selected history is incomplete.

Unselected status rows are excluded from selected-source freshness calculations.
Unselected rows retain public discovery and counts unless hidden/quarantined;
protected fields require vetted access. Deselecting a source does not withdraw it.

## Complete, bounded harvests

`app.ingestion_contracts` owns `HarvestResult` and its validated five-field JSON
document: matching records, deleted identities, nonmatching identities,
uncertain identities and source cursor. Existing service exports remain aliases
of those canonical objects. Worker candidates and durable staging use the same
representation. Result construction alone does not validate it.

Uncertainty reasons must be strings, matching the decoder's existing contract.
Empty and Unicode strings remain valid. Mutating a reason to another type is
rejected by validation and serialization before it can become an unrecoverable
staged payload. The wire layout and stored/parser versions are unchanged.

Durable staging uses the source-neutral bounded encoder with a 16 MiB default
inner-harvest budget. Stored-envelope metadata is outside that limit. It is a
serialized-result bound, not a total process-memory or database-envelope cap;
ordinary encoding materializes JSON before its byte-size check.

Worker decoding returns the validated harvest data without retaining the input
byte buffer. Durable staging validates and freshly encodes the current mutable
result on every call. Invalid fingerprints and budgets fail before current-state
validation; a newly encoded payload exceeding the byte budget is rejected.
Full rebuilds validate the fetched harvest directly before reconciliation.
Concurrent mutation during validation or serialization is unsupported.

The bundled adapters' `max_bytes` input-snapshot budgets are separate from
durable staging. JSON-feed `max_result_bytes` limits its fetched candidate,
not a per-source database-staging setting. There is no runtime per-source
staging-budget setting.

### OAI-PMH/CMDI transport

OAI-specific transport and process-framing errors remain in `oai_client.py`.
In hardened deployments OAI network/XML work runs in a separately bounded parser
service, whose job spawns the harvest process before returning a result. The
development-only local mode retains explicit process supervision. A 240-second
watchdog bounds worker/result waiting; cleanup
and synchronous parent decoding can extend elapsed time.

The adapter passes its configured source name and the parent's current
`LOG_LEVEL`/`LOG_FORMAT` explicitly to the isolated transport. These logging
arguments are required and validated before pipes/processes are created. The
spawned worker installs its own standard application/audit handlers before
harvesting; it does not rely on inherited logging state. Worker records carry
`source` and `worker_pid`, including text output. Logging initialization failures
use the same bounded error frame and pipe cleanup as harvest failures.
Construction and direct parser/codec imports remain independent of runtime
settings; the adapter reads logging settings only when fetching. Logging policy
does not change source interpretation fingerprints or stored-harvest versions.

HTTP connect/read timeouts are ten seconds, with up to three retries.
OAI limits are 4 MiB per page, 32 MiB received, 1 MiB per XML record,
20,000 records, 16 MiB retained/serialized result and 4,096 resumption-token
characters. Each bounded page is classified into native records before the
next page is requested. Completed XML pages are released; only the native
harvest is retained until the attempt validates. Redirects and compressed
responses are rejected.

XML callbacks also enforce 100,000 elements, depth 64, 3,145,728 text/attribute
characters and 200,000 attributes before retaining the offending value in the
tree. Shared record contracts bound collection counts, individual labels, URLs
and long text. See [OAI resource limits](../sources/oai-ingestion-limits.md).

The OAI adapter passes its configured `max_pages` explicitly across the process
boundary. Direct transport calls that omit it use 500 pages. Non-integer,
boolean and nonpositive caps fail before HTTP or process resources are created.
An initial attempt and its continuation-token fallback each have their own page
allowance; byte, record-count and deadline budgets remain cumulative.

Retained-result bytes and the source cursor reset for a fallback attempt.
Classification errors are deferred until transport completes so a rejected
continuation can still discard the entire attempt. Failed output and its XML
references are released before retrying; no partial result reaches ingestion.

The client requires the OAI root, one valid first-page `responseDate` and exactly
one `ListRecords`, except that a sole first-page `noRecordsMatch` error is an
empty success. Error and result elements cannot coexist; multiple errors abort
without interpreting the first as empty success or continuation recovery. Each
result has at most one resumption token, and continuations require an explicit
terminal token element. Ambiguous pages yield no records or cursor. Repeated tokens,
duplicate or malformed identities and other protocol failures abort the
harvest. A rejected continuation token triggers one fetch without `from`,
followed by inclusive local datestamp filtering under the shared budgets.

Each record needs exactly one header identifier; its text is stripped.
The supported CMDI profile requires one Dataset. Institution membership is
classified before content validation; a definite nonmatch withholds a known
record without deleting its retained metadata. Matching records need nonblank
titles with distinct language tags. The selected title is the trimmed direct
text of the first validated `Dataset/Overview/Dataset_title`, in document
order; titles elsewhere in the record cannot override it. Unknown profiles
and absent or unusable institutions are uncertain and retain existing
catalogue rows.

OAI protocol diagnostics retain bounded code/message text; validation diagnostics
omit input values. `ParsedRecord` validates required keys/types at parsing,
decoding, orchestration and writes. Nullable fields and arrays may be empty;
keyword/language labels contain 1–256 characters.

XML entity resolution, DTD loading/validation and network loading are disabled.
Resource/license URLs use the shared HTTP(S) policy. DOI URI forms decode once
and fold ASCII case; bare DOI names preserve percent characters.
Raw parsed values remain in JSONB `data`.

### Authenticated JSON feeds

`JsonFeedAdapter` implements [Feed Contract v1](../sources/feed-contract-v1.md).
It requires separate prepared bearer and signing credentials and mandatory
record tiers.

Each request uses the fixed HTTPS endpoint, a fresh random nonce, explicit bearer
authorization and identity encoding. Redirects, automatic retries and non-200
responses are refused. HMAC-SHA256 verifies the exact response bytes before
UTF-8 decoding or JSON parsing.

After authenticated decoding, the validator checks the signed request echo,
freshness, snapshot/cutoff continuity, pagination completion and identities.
All pages must describe the same snapshot and cutoff.

A valid, unambiguous public UUID with invalid metadata becomes an identity-only
quarantine reason. Duplicate nonidentity keys also quarantine that record.
Incoming rejected metadata is discarded. Missing, malformed or repeated
identities, invalid envelopes, incomplete chains and resource failures abort
the complete fetch.

The full adapter uses one spawned worker for direct HTTP, JSON/page validation,
record classification and result serialization. It does not nest the standalone
B3 `JsonFeedTransport` page workers.

| Budget | Default and maximum | Scope |
|---|---:|---|
| `max_page_bytes` | 1 MiB | One exact response body |
| `max_total_bytes` | 8 MiB | All response bodies in the attempt |
| `max_record_bytes` | 64 KiB | Original UTF-8 record bytes, including rejected records |
| `max_records` | 10,000 | Record and withdrawal entries, including quarantine |
| `max_pages` | 100 | Page requests in the attempt |
| `max_result_bytes` | 16 MiB | Serialized candidate `HarvestResult` |
| `fetch_deadline_seconds` | 120 seconds | One absolute source-work deadline |

Each budget is a strict positive integer and can tighten, but not exceed, its
profile maximum.

The shared process boundary bounds worker byte frames, handles partial IPC,
requires normal child exit within the deadline, and terminates, kills if needed,
and reaps blocked workers. Cleanup has bounded grace beyond the deadline.
Worker failures carry fixed allowlisted transport/protocol codes, not incoming
exception text or body fragments.

The parent reconstructs only the validated, size-bounded candidate and checks
the same deadline before and after reconstruction. Parent reconstruction is
not separately force-terminable. The terminating child covers source HTTP,
JSON parsing, metadata validation and serialization.

Failed or incomplete source fetches return no harvest. Successful fetching alone
does not establish database, catalogue or operational acceptance.
See [JSON-feed adapter integration](../sources/json-feed-adapter.md).

## Incremental writes and recovery

Stage a versioned harvest with source fingerprint, start time, position and
affected count in `sync_status`. Resume it before fetching again. Compatible
stored-format or parser changes can clear staging and refetch under the current
source binding. Malformed state, incompatible bindings or invalid durable
progress require an authoritative rebuild. Staging that requires full
reharvesting remains until replacement reconciliation commits.

Before replay, one transaction records uncertainty and quarantines known
uncertain/filter-excluded identities. Replay processes sorted explicit
withdrawals, then matching records, each in a savepoint. Batches commit record
changes, successful-identity failure cleanup and progress after 50 items or a
two-second elapsed check between items; this is not a hard transaction deadline.

Cancellation or failure rolls back the active batch while earlier committed
batches survive. Replay resumes from the last committed position.

Recoverable data, constraint and validation failures are stored in
`ingestion_failures`, keyed by `(source, uuid)`. Adapter uncertainty reasons
protect their identities and preserve last-known-good catalogue rows.
A later empty poll cannot clear unresolved identities.

Indexed identities and DOI input are limited to 512 characters. Every harvest
identity classification is checked before staging, including uncertainty and
withdrawals. An oversized identity rejects the harvest because its original
value cannot safely serve as a quarantine key. Identifiable oversized DOI
records are quarantined by the adapters. Parsed-record contract version 3
requests an incremental refetch for retained older envelopes.

Source policy supplies the access classifier and resolves metadata visibility.
The upsert accepts an explicit valid upstream tier, including a lower tier,
subject to the source policy. If the source omits its tier, the last accepted
restriction is retained, including after metadata deletion and reintroduction.
It compares persisted content before writing: an existing identity allocates no
new sequence value, and an unchanged record causes no row UPDATE or search
trigger execution. `synced_at` is the time its persisted catalogue content last
changed, not the time it was most recently seen upstream. Successful unchanged
polls still advance the source-level `sync_status` observation state under the
existing cursor rules. Affected counts continue to count successfully reconciled
records, including unchanged records, rather than only physical row changes.
Normal ingestion serializes writes with the common catalogue lock. For direct
writer calls that concurrently introduce the same previously absent identity,
an atomic conflict fallback preserves the stricter tier; this rare insert race
can consume an unused sequence value and execute the update trigger.
Catalogue reads separately apply durable `dataset_admin_state` restrictions
keyed by `(source, uuid)`: administrator floors can only tighten the served tier,
and hidden identities are excluded.

Ingestion never writes that administrative state, so withdrawals and rebuild
pruning cannot erase it. The same identity reuses it when reintroduced.
See [Access Control & Visibility](access-control.md#how-visibility_tier-gets-set).

With `requires_record_tier=true`, the shared write boundary rejects a missing
or null record tier. Existing savepoint and durable-failure handling applies:
new rows are not inserted, previous rows are retained and unresolved failures
prevent success timestamps and cursor advancement.

That same source policy enables committed tier-change and withdrawal audit
events for every adapter. Audit buffers follow item/DOI-group savepoints and
publish only after their owning transaction commits. Adapter type does not
enable or disable this policy. JSON-feed diagnostic redaction remains a
separate adapter-specific concern; enabling audit on another source does not
change its failure messages.

Adapters may reject invalid input earlier. The bundled adapters validate
mandatory tiers across their whole snapshots; JSON feeds quarantine identifiable
invalid metadata before returning a harvest. A returned matching record with
an unknown non-null tier fails harvest validation before staging.

Finalization clears staged bytes and progress. With unresolved failures,
success timestamps and the cursor remain unchanged. Otherwise it updates local
liveness and clears the incremental error. The clean upstream cursor advances
when the staged work contains matching records, tombstones or filter exclusions.

Incremental staging and replay each receive a separate selected-source
`write_timeout_seconds` timeout. Full-rebuild application uses that same
configured value. These asynchronous timeouts do not cover adapter fetching
or waiting for ingestion locks, and cannot preempt synchronous serialization.

Caught write exceptions and timeouts receive a separate best-effort five-second
diagnostic attempt on the same advisory-lock connection. Diagnostic UPDATEs
use a savepoint so a suppressed statement error cannot abort other caller
writes. Privacy policy is mandatory at the diagnostic helper boundaries.
Escaping deterministic record-write failures request authoritative full
recovery; transient failures and application invariants still propagate.
External cancellation has no such diagnostic-reporting guarantee.
A lost connection cannot be replaced to continue writing.

## Full rebuild

A rebuild first attempts pending incremental recovery, which may commit
catalogue changes and advance the committed cursor. It then requests full input
from the adapter. If that new fetch fails, no replacement harvest is applied;
completed incremental replay remains committed.

For JSON feeds, full reconciliation rereads and checks the committed cursor
before applying any removals. This check also precedes the zero-match branch.

With no matching records, commit authoritative tombstones, preserve unmentioned
metadata and clean completion state, and return `failed`. Record uncertainty
and known filter exclusions without replacing existing failures. An uncertain
snapshot publishes consumed progress and may clear supplied staging if unchanged;
an empty snapshot retains staging and consumed state. Failure can therefore
include committed changes.

Local institution-filter exclusions quarantine known records instead of deleting
their metadata. They remain withheld until a valid fresh matching correction.
They do not release a retained DOI assignment: a replacement using that DOI
requires an authoritative predecessor withdrawal or an upstream ownership fix.

For a nonempty harvest, authoritative tombstones commit independently before the
reconciliation transaction checks inferred removals, removes absent rows and
upserts matches. Inferred deletion and local filter exclusions
strictly above the source's count **or** percentage budget abort the transaction.
Defaults remain 100 rows and 25% of the source rows remaining after explicit
withdrawals. The operational settings are `rebuild_max_inferred_delete_count`
and `rebuild_max_inferred_delete_ratio_percent`; temporary reviewed overrides
must be restored after acceptance. Matching and uncertain UUIDs are retained,
including failed replacements. Filter-excluded rows are retained under serving
quarantine even when the guard aborts. A later failure never restores metadata
already withdrawn by an authoritative tombstone. The last accepted tier
in `source_security_state` survives metadata deletion and reintroduction when
the returning source omits a fresh explicit tier assertion.

DOI-dependent records share a savepoint so swaps can clear old DOIs and apply
together; a group failure restores every member. Fewer than half the matching
writes succeeding aborts the transaction. Exactly half may commit a partial
rebuild under the remaining guards.

Accepted partial rebuilds commit healthy changes and replace the failure set,
but leave success timestamps, cursor and source binding unchanged.
Retained staged bytes can be cleared as part of the accepted reconciliation
transaction.

Clean rebuilds advance both success timestamps, publish the new cursor/binding
and clear both error channels. Incremental success does not clear rebuild errors.
Surviving UUIDs retain local IDs.

Runners return `SyncOutcome` (`success`, `partial`, `failed`) or raise
infrastructure/write errors. Returned ingestion outcomes log
`ingestion_job_outcome`, including partial/failure; escaping errors log
`scheduler_job_error`. Count semantics are documented on `SyncOutcome`.

Repair upstream metadata or follow the
[withdrawal runbook](../runbooks/emergency-dataset-withdrawal.md).

## Adapter conformance

`src/tests/sources/test_conformance.py` applies shared behavioral checks to
every registered adapter. Each adapter supplies its native recorded inputs,
configuration, expected identities, cursor boundaries and resource-limit
expectations through its own provider in `src/tests/sources/cases/`.

The suite exercises registry construction, flat TOML loading, explicit
startup policy, complete validated harvests, inclusive UTC boundaries,
independent results, interpretation fingerprints and native input budgets.
It also checks the shared ingestion boundary for source identity, tier
restrictions, mandatory record tiers and committed-binding changes that
forbid cursor reuse or staged replay.

The OAI provider runs the real bounded XML reader and CMDI parser against
replayed HTTP responses while replacing child-process execution.
The `fixture` and `static_json` providers read their real bundled native inputs.

The JSON-feed provider runs real response-byte handling, exact-byte HMAC
authentication, page validation, record classification, complete collection
and harvest serialization. It substitutes recorded HTTP sessions, the complete
process boundary and a controlled UTC clock. Signature-enforcing spies retain
the real collaborator signatures.

Real TLS, spawned-worker isolation, processing stalls, partial IPC, termination,
reaping and hardened file traversal have dedicated tests. No skipped adapter
placeholder represents the JSON-feed implementation.

The static JSON extensibility-proof implementation and its providers are present.
Formal extensibility-proof records and deployed acceptance remain separate
requirements; the shared suite alone does not establish either.

