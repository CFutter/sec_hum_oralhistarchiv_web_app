# Feed Contract v1

The [isolated adapter](json-feed-adapter.md),
[PostgreSQL persistence/audit tests](json-feed-persistence.md),
[catalogue tests](json-feed-catalogue.md) and
[synthetic recovery tests](json-feed-acceptance.md) implement this profile.
Repository tests and examples do not establish source-owner approval,
real-feed acceptance or representative encrypted recovery; retain those
operational records separately before activation.

The [Sensitive Source Contract](../architecture/source-b-ingestion-contract.md)
defines the stable `SB-DISC-*`, `SB-VIS-*` and `SB-TRANS-*` requirements.
This page fixes the v1 wire profile used to implement those requirements.
The [JSON Schema](feed-contract-v1.schema.json) describes one response page.
Unknown fields are rejected; changing the accepted wire profile requires an
explicit contract/version review.

## Request and response binding

The endpoint is a fixed absolute HTTPS URL without user information, query or
fragment. TLS certificate verification is required. Only that endpoint is
contacted; opaque pagination cursors are query values, never URLs.

Each request is `GET endpoint` with these query parameters:

| Parameter | Meaning |
|---|---|
| `nonce` | Fresh, cryptographically random 32-byte value encoded as 64 lowercase hexadecimal characters; never reused, including on retries |
| `since` | Inclusive UTC lower boundary for an incremental harvest; omitted for a full rebuild |
| `cursor` | The preceding page's opaque `next_cursor`; omitted on the first request |

Send `Authorization: Bearer <credential>`, `Accept: application/json` and
`Accept-Encoding: identity`. The bearer credential and signing key come from
separate environment-variable references. Never put credentials in URLs.
No redirects are followed. Every status other than 200 aborts the fetch;
a 404, 204, 304 or expired cursor is not an empty successful page.

Every response contains exactly `feed_version`, `snapshot_id`, `generated_at`,
`request`, `records`, `withdrawn`, `next_cursor` and `complete`.
`feed_version` is the JSON integer literal `1`; decimal/exponent spellings and
booleans are refused by the runtime. `request` contains exactly `nonce`, `since`
and `cursor`; absent request parameters are echoed as JSON null.
The signed echoes must match the actual request exactly. The source must not
serve a cached response with an earlier nonce.

The signed request echo binds the response to this page request; a body
signature and recent timestamp alone do not prevent signed-page substitution.

## Integrity, freshness and pagination

The response has exactly one `X-Feed-Signature` value, with the form
`v1=<64 lowercase hexadecimal characters>`. It is HMAC-SHA256 over the exact
response body bytes, excluding HTTP framing. The signing-key variable contains
the unpadded base64url encoding of exactly 32 random bytes; decode those bytes
before using them as the HMAC key. Use a distinct key per feed and environment.
Do not trim the key, canonicalize JSON, or verify a reserialized document.
Compare signatures in constant time before UTF-8 decoding or JSON parsing.

Accept only `application/json`, with no charset or `charset=utf-8`, and absent
or `identity` content encoding. Reject other encodings rather than relying on
unbounded automatic decompression. Enforce the page-byte budget while reading,
before signature verification or parsing can allocate an unbounded body.

`generated_at` is the snapshot cutoff, not each page's delivery time.
Every page has the same `snapshot_id` and `generated_at`. The snapshot is a
stable view of all records and withdrawals selected for that harvest.
At each page's acceptance, the cutoff must be within 600 seconds of the
client's current UTC time. All timestamps use whole-second UTC
`YYYY-MM-DDTHH:MM:SSZ`; offsets, fractional seconds and leap seconds are outside
this v1 profile. Every record's `modified_at` is at or before the cutoff.

A nonfinal page has `complete=false` and a nonempty URL-safe `next_cursor`.
A final page has `complete=true` and `next_cursor=null`. Reject repeated
cursors, snapshot/cutoff changes, mismatched request echoes and any incomplete
chain. A continuation cursor must refer to the same snapshot and selection.
Nothing is persisted or returned as a harvest until the complete chain passes.

Fresh nonces reject captured responses. For `JsonFeedConfig`, the engine
rejects cutoffs older than either the clean `source_cursor` or consumed
`source_fetch_cursor` before staging, replay writes or full-apply withdrawals
and inferred deletions, including zero-match results. Equal cutoffs are allowed.
The overlapping `fetch(since)` boundary is not this durable rollback guard.

## Records and the public discovery envelope

Every record contains all fields required by the schema, with explicit nulls
and empty arrays where allowed. The fields match `ParsedRecord`, except that
wire `modified_at` becomes internal `upstream_modified_at`. `visibility_tier`
is mandatory and is exactly `public`, `registered` or `vetted`. No request or
record supplies local `id`, `source`, `access_level` or administrative state.

| Public value | V1 mapping and constraint |
|---|---|
| `id` | Application-generated; public and enumerable |
| `uuid` | Canonical lowercase UUIDv4, newly allocated as a public dataset identifier; never a participant/case identifier, credential or private lookup key |
| `title` | Curated, trimmed, nonblank public discovery title, 1–256 characters, without C0 or DEL controls |
| `access_level` | Exact `license_val` mapping: `Public access` → `public`; `Restricted access` → `restricted`; no other label is accepted |
| `version` | Null or a reviewed public numeric release label: one to three dot-separated components, each containing one to six digits |
| `source` | The application's configured source name |
| `visibility_tier` | The effective restriction after source policy, stored restrictions and the durable administrative floor are applied |

Only `title` and the derived `access_level` enter public free-text search.
A title, UUID or version passing the schema is not thereby safe to publish.
The source owner must approve every public value and their combination,
including public record existence, ordering, counts and restriction tier.
No automated test can replace that approval.

Nullable text allows 16,384 characters, labels 256, HTTP(S) URLs 2,048 and
DOIs 512. `project_title` additionally uses the source's
`max_project_title_chars`: 4,096 by default, configurable from 1 to 16,384 in
`sources.toml`. Increase it only for a reviewed source requirement; an identifiable
record above the configured cap is quarantined as `record_metadata` while valid
neighbours continue. Lists allow 100 entries; institutions require at least one label.
Resource proxies contain only `type` (`Resource` or `LandingPage`) and a
nullable HTTP(S) `ref`. Title/version rules apply independently. These are
character/item limits; byte budgets are separate.

[B5 native validation](json-feed-records.md) also rejects NUL or unpaired Unicode
surrogates in any string, and HTTP(S) URLs without a hostname or with malformed
ports, user information, whitespace, controls or backslashes. The schema alone does not
cover these runtime representability and URL checks.

Metadata tier and material-access labels are independent. The adapter requires
an explicit record tier and applies the current source floor. A valid fresh
upstream correction can lower the stored tier; durable administrator floors
and hiding survive updates, rebuilds and reintroduction of the same
`(source, uuid)`.

## Selection, withdrawals and failure handling

The engine supplies incremental `since` with its existing two-day overlap;
the adapter must not subtract another overlap. Runtime record timestamps must
lie inclusively between the supplied normalized whole-second boundary and the
snapshot cutoff; full rebuilds have no lower bound. Select changes inclusively
through that cutoff. Return each selected UUID once, in its final
state at that cutoff: a current record or a withdrawal, never both. A later
reintroduction must carry a new modification time. Withdrawals still effective
at the cutoff must be included for the requested interval. The source must
retain tombstones long enough to cover the deployed
poll/recovery window; if coverage is unavailable, reject incremental fetching
and require an authoritative rebuild rather than silently dropping withdrawals.
Full rebuilds omit `since` and return the complete current selection.

`withdrawn` contains canonical public UUIDs and authorizes physical removal
from this source's serving cache. Identities are globally unique and disjoint
across all records and withdrawals in the harvest, including quarantined
records. Repeated identities are errors even when their contents agree.

Decode UTF-8 strictly and reject non-JSON values such as NaN and Infinity.
Preserve duplicate object-key evidence until its failure boundary is known;
an ordinary last-key-wins dictionary decoder is insufficient.

| Failure | Required outcome |
|---|---|
| Valid public UUID but invalid metadata/tier/timestamp, or duplicate nonidentity keys (including nested keys) | Quarantine with a fixed reason, discard incoming metadata and protect the UUID from inferred deletion. Preserve any old bytes but withhold that row from every catalogue tier until a valid fresh correction commits; continue valid neighbours. |
| Missing, invalid or repeated UUID key; repeated identity across records/pages/withdrawals; malformed withdrawal or nonobject record | Abort the entire fetch |
| Invalid envelope or cutoff/selection relationship, duplicate envelope/request key, malformed/ambiguous JSON outside an identifiable record, signature, nonce, freshness, page-chain, encoding, budget or deadline failure | Abort the entire fetch |

Producer validation applies the whole-page schema. The runtime must validate
the envelope separately from each identifiable record, so a malformed record
is quarantined rather than turning whole-page schema rejection into the
default failure policy.

Quarantine becomes `HarvestResult.uncertain_records`, source-scoped failures
and, for existing rows, durable `ingestion_quarantine`. A valid correction
clears quarantine only from a later harvest start and a cutoff at least as
recent as the latest rejection; replaying the same staged input cannot restore
serving. Diagnostics contain fixed reasons and public identifiers, without
incoming metadata or credentials. An aborted fetch applies no pages and
advances no cursor; the serving catalogue remains intact.

The completed chain supplies its first cutoff as `HarvestResult.source_cursor`;
the engine owns persistence. Uncertain IDs block inferred deletion, contraction
guards can abort, and zero-match rebuilds infer no wholesale deletion. Explicit
withdrawals and separate consumed progress can commit even when reconciliation
returns `partial` or `failed`; the clean cursor does not advance until failures
are resolved. Schema validity does not override these guards.

Effective tier changes and actual withdrawals persist `tier_changed` and
`dataset_withdrawn` events with source/UUID and changed state in the mutation
transaction, without metadata payloads. Local log copies follow commit;
unchanged records and absent withdrawals emit no state-change event.
[Persistence tests](json-feed-persistence.md) cover these boundaries.

## Resource budgets

[`JsonFeedConfig`](json-feed-configuration.md) validates these per-source caps.
[Isolated fetching](json-feed-adapter.md) bounds HTTP, decoding, validation and
serialization in one terminating child. Parent reconstruction is size-bounded
and checks the same deadline cooperatively. Runtime construction requires
explicit prepared credentials.

| Budget | V1 initial default | What counts |
|---|---:|---|
| `max_page_bytes` | 1,048,576 | Exact body bytes of one response |
| `max_total_bytes` | 8,388,608 | Sum of all response bodies in the fetch |
| `max_record_bytes` | 65,536 | Original UTF-8 bytes of each record object, including malformed/quarantined records |
| `max_records` | 10,000 | All record entries and withdrawal entries across all pages, including quarantined entries |
| `max_pages` | 100 | Every response page, including empty pages |
| `max_result_bytes` | 16,777,216 | Serialized retained `HarvestResult`, including quarantine diagnostics |
| `fetch_deadline_seconds` | 120 | One terminating monotonic deadline covering transport, decoding, validation and result serialization |

Every budget is a positive integer; booleans and coercible strings are refused.
Configured values can tighten but not exceed these v1 profile maxima.
The terminating worker boundary must stop blocking work and reap the worker;
abandoning a thread or using only socket inactivity timeouts is insufficient.
Budget and deadline failures abort the whole fetch, never masquerade as record
quarantine. All source bindings and hard profile changes require fingerprint
review; operational budgets themselves do not change source interpretation.

## Synthetic examples and executable evidence

- [Full harvest, page 1](examples/feed-v1-full-page-1.json): public and registered records.
- [Full harvest, page 2](examples/feed-v1-full-page-2.json): vetted record and an explicit withdrawal.
- [Empty incremental result](examples/feed-v1-empty-incremental.json): a completed empty selection.

Their fixed times and nonces make them reproducible structural examples, not
live signed responses. B3/B4 tests supply controlled clocks, fresh request
nonces and signatures for transport and page validation. Existing offline
source fixtures remain separate and unchanged.

B1's `src/tests/unit/test_feed_contract_schema.py` checks the schema, examples,
record-model mapping and structural negative cases. Use an explicit JSON Schema
2020-12 validator **with format checking enabled**. JSON Schema checks numeric 
values, not their original JSON spelling. The runtime additionally requires 
`feed_version` to be written as `1`, rejecting decimal and exponent spellings 
such as `1.0` and `1e0`.

The [B9 evidence map](source-b-evidence.json) names executable behavior functions
for all 22 IDs. Collection checks references and placeholder markers; full test
execution and the separate operational records remain required.

| Stable requirements | Implemented test coverage; retain execution results separately |
|---|---|
| `SB-DISC-001`, `SB-DISC-006` | Tiered catalogue release, public/protected search, facets, counts and pagination |
| `SB-DISC-002`, `SB-DISC-009` | Disclosure boundaries and the limit of structural validation; source-owner approval is separate |
| `SB-DISC-003`, `SB-DISC-004`, `SB-DISC-005` | Title/UUID/label/version constraints and catalogue release; public suitability needs owner approval |
| `SB-DISC-007`, `SB-DISC-008` | Persisted quarantine, fresh corrections, withdrawals, warm-cache refresh and durable hiding |
| `SB-VIS-001`, `SB-VIS-002` | Duplicate-key/tier rejection and source-scoped persistence |
| `SB-VIS-003`, `SB-VIS-004`, `SB-VIS-007`, `SB-VIS-008` | Tier corrections, administrator floors/hides, source isolation and fatal-input preservation |
| `SB-VIS-005`, `SB-TRANS-001` | Verified TLS/signatures, redirect refusal, signed echoes, freshness and complete chains; real-feed acceptance is separate |
| `SB-VIS-006` | Committed effective tier changes, actual withdrawals and rollback-safe audit |
| `SB-VIS-009` | Backup preflight, test-login grants and encrypted synthetic restore/replay; deployed identity/custody checks and representative recovery are separate |
| `SB-TRANS-002`, `SB-TRANS-003`, `SB-TRANS-004` | All seven budgets, terminating source work, bounded parent decoding and committed-state preservation |

Before activation, retain passing mapped tests and the separate source-owner,
real-feed and representative-recovery records; synthetic evidence is insufficient.
