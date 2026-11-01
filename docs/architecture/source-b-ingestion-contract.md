# Sensitive Source Contract

**Status:** These acceptance requirements apply to every adapter configured
with `requires_record_tier=true`. B1–B6 implement the
[authenticated JSON-feed adapter](../sources/json-feed-adapter.md): wire contract,
configuration/credentials, transport, page/record validation, one complete-fetch
worker, runtime wiring, fingerprint and committed-cutoff guards. B7's signed-native
PostgreSQL persistence, failure-preservation and committed-audit checks are
accepted, as are [B8 catalogue cases](../sources/json-feed-catalogue.md).
[B9 evidence and recovery checks](../sources/json-feed-acceptance.md) map all
22 requirements to executable tests and add an encrypted synthetic restore.
Source-owner approval, real-feed acceptance and representative encrypted
isolated restore evidence remain outstanding.

The authoritative source owns source classifications and public-envelope
corrections. The database is a synchronized serving cache. Administrative hide
state and minimum tiers are durable local restrictions stored independently
and must survive synchronization and reintroduction of the same identity.

## Public discovery is an explicit disclosure policy

The archive is deliberately a searchable catalogue of restricted datasets.
Below-tier viewers receive exactly `app.services.PUBLIC_DISCOVERY_FIELDS`:

| Field | Public meaning and required constraint |
|---|---|
| `id` | Application-generated, public and enumerable row identifier |
| `uuid` | Stable public dataset identifier; never a participant/case identifier, storage key, credential or private lookup key |
| `title` | Curated public discovery title, deliberately displayed and searchable |
| `access_level` | Controlled public label for material access; no sensitive free-text explanation |
| `version` | Public release label; no internal workflow, case or participant identifier |
| `source` | Application-controlled configured source name |
| `visibility_tier` | Public effective restriction: `public`, `registered` or `vetted` |

These values must be safe individually and in combination. The source owner
must accept public record existence, result membership, ordering, pagination,
counts and existing-versus-absent detail responses. `title` and `access_level`
are public search fields; the access-level filter and facet are public too.
Administratively hidden rows are excluded from every catalogue surface.

If record existence or any required public-envelope value is sensitive, that
record is incompatible with this catalogue profile. Do not ingest it until the
source can provide a safe public representation or a separately reviewed
product design exists. A high metadata tier does not hide the public envelope.

## Mandatory public-discovery contract

- **SB-DISC-001 — Explicit profile adoption.** The adapter MUST explicitly adopt
  the exact `PUBLIC_DISCOVERY_FIELDS` and `PUBLIC_SEARCH_FIELDS` sets in reviewed
  code. A request, record or environment variable MUST NOT select extra fields.
- **SB-DISC-002 — Unrestricted-public standard.** Every public-envelope value,
  and the envelope as a whole, MUST be approved for disclosure to an
  unauthenticated internet user. A higher tier protects only other fields.
- **SB-DISC-003 — Curated title.** `title` MUST be a deliberate public discovery
  title, never an unreviewed copy of a confidential interview, participant,
  case or file title. Its searchability cannot be disabled per record.
- **SB-DISC-004 — Public identifiers and existence.** `uuid` MUST be a public,
  non-secret dataset identifier, not a credential or private lookup key.
  The source owner MUST accept public existence and enumeration channels.
- **SB-DISC-005 — Controlled public labels.** `access_level`, `version` and
  `source` MUST use reviewed controlled mappings or application constants,
  not sensitive free text. The effective tier is itself public metadata.
- **SB-DISC-006 — Search boundary.** Ungated `search_text_public` MUST contain
  only `PUBLIC_SEARCH_FIELDS`: title and access level. Keywords, languages,
  descriptions, projects, authors, participant attributes, alternate titles,
  internal identifiers and URLs MUST remain outside it.
- **SB-DISC-007 — Fail closed before persistence.** Unsafe incoming records MUST
  be rejected or quarantined before persistence parameters or writes are built.
  Unreviewed heuristic replacement values are insufficient. Last-known-good
  retention MUST follow an explicit reconciliation rule.
- **SB-DISC-008 — Source correction.** Source corrections and withdrawals MUST
  update or remove normalized columns, raw JSONB metadata, search vectors,
  results, aggregates and affected caches. Durable administrative restrictions
  remain effective independently of those corrections.
- **SB-DISC-009 — No semantic claim from structural tests.** Tests can pin public
  fields and channels, but cannot prove human-language values are nonsensitive.
  Source governance, curated mappings, sample review and documented sign-off
  remain mandatory.

## Field-policy enforcement

WP E batches E1/E2 are accepted: the total immutable `FIELD_VISIBILITY` matrix,
Python redaction, stricter source field overrides, matching SQL
search/filter/facet/count gates and field-aware templates. Every code minimum
initially equals `public`. Protected fields require the strictest code/source
minimum and effective
stored/administrator record tier. `SourceConfig.field_visibility` is an immutable
strictly validated mapping; it can only tighten code minima and cannot change
the exact seven-field discovery envelope or the two public search fields above.
Resource-target representations must share the same merged minimum.

The process's trusted configured-source snapshot selects read policy; records,
request fields and upstream metadata cannot choose it. Changed policy requires
[owner projection replacement](../runbooks/search-policy.md), then restart,
without changing ingestion fingerprints or requiring an ingestion rebuild. An
unselected source's retained protected fields require `vetted` in runtime reads;
its public discovery remains visible until the identity is hidden. Python, SQL
and templates enforce the same field requirements, including independent
keyword/language filters and facets. The stored full-search trigger is unchanged
and is not used as an unrestricted matching channel. Resource redirects still
require full-record permission. None of this relaxes source-owner obligations.

E3's web-role record/admin-floor RLS and narrow owner-backed discovery/control
views are accepted. Default viewer
context is public; authenticated application services set and restore trusted
transaction-local context. Scheduler writes and read-only `BYPASSRLS` backups
retain their separate roles. RLS does not enforce E2 field minima for arbitrary
SQL under the shared web role. E3 is part of the single fresh-install baseline
`4f73ae3ff827`; an older initialized baseline requires operator recreation/rebuild,
not an `upgrade head`/stamp retrofit. Backup preflight and isolated restore must
cover every tier and hidden identity.
E4's actual-role encrypted synthetic recovery is accepted as implementation
evidence. Deployment-host role verification, custody and a representative
encrypted isolated restore remain separate deployment/Source B records. The
[visibility/recovery acceptance record](../runbooks/visibility-recovery-acceptance.md)
retains those operational obligations. The
[field-policy implementation record](field-visibility.md#wp-e-implementation-acceptance-record)
requires the reviewed commit, CI results and synthetic interface evidence.

See [Field visibility](field-visibility.md) for the complete 22-field
classification and exact runtime/offline scope boundary; it is also the WP E
input to the [WP L catalogue classification slice](../compliance/data-classification.md).
The [processing register](../compliance/processing-register.md) and linked WP L
templates provide the generic governance records. Actual inventories,
source-owner decisions and institutional approval remain open operator work.

## Mandatory visibility-tier contract

- **SB-VIS-001 — Mandatory source classification.** Every accepted record MUST
  contain exactly one canonical `visibility_tier`: `public`, `registered` or
  `vetted`. Duplicate tier keys MUST be rejected or quarantined even if equal;
  never silently choose the first or last value.
- **SB-VIS-002 — Invalid classifications fail closed.** Missing, null, malformed,
  case-variant or unknown tiers MUST NOT be defaulted or persisted. The strict
  write resolver raises `SourceVisibilityTierError`; the adapter MUST define
  rejection, quarantine and last-known-good handling before integration.
- **SB-VIS-003 — Application floor.** The incoming effective tier is the stricter
  of the authenticated record tier and `SourcePolicy.max_visibility`.
  Application policy MUST NOT loosen the source assertion.
- **SB-VIS-004 — Source ownership and durable restrictions.** Valid source
  versions replace cached metadata and their explicit source tier, including
  valid less restrictive corrections. The configured source floor and durable
  administrator floor MUST still apply. Administrative
  hide state MUST survive deletion and reintroduction of `(source, uuid)`.
- **SB-VIS-005 — Integrity binding.** Tier and metadata MUST be covered by the
  same source authentication and integrity mechanism. An unauthenticated
  header, filename, query value or other side channel cannot assert a tier.
- **SB-VIS-006 — Complete derived-state update.** Tier changes, corrections and
  withdrawals MUST update all affected serving state. Tier transitions and
  withdrawals MUST emit audit events without sensitive metadata values.
- **SB-VIS-007 — Source isolation.** Every update, withdrawal, quarantine and
  rebuild MUST be scoped by `(source, uuid)` and leave other sources untouched.
- **SB-VIS-008 — Integration boundary.** The adapter MUST validate discovery
  values before persistence and use `requires_record_tier=true`. The shared
  write boundary MUST call `resolve_required_source_tier()` before classification,
  persistence parameters and upserts. Tier validation does not establish public
  suitability or source authenticity.
- **SB-VIS-009 — Recovery coverage.** Before activation, backup roles, grants and
  preflight MUST cover every relevant schema/table. An encrypted archive MUST
  be restored in isolation with representative sensitive-source rows, including
  any enabled RLS boundary. If another database is used, the
  one-database backup job is insufficient; a separately encrypted, jointly tested recovery path is
  mandatory.

## Mandatory transport contract

- **SB-TRANS-001 — No redirects.** Disable automatic redirects and reject every
  redirect response. Relocation requires reviewed configuration. Never forward
  credentials, keys or asserted metadata to a redirect-selected origin.
- **SB-TRANS-002 — Explicit resource budgets.** Enforce per-response bytes,
  aggregate bytes, record bytes/count, pages and retained-result/staging limits
  before persistence. Disable compression and reject nonidentity encodings when
  decompression cannot be bounded. Quarantined input still consumes budgets.
- **SB-TRANS-003 — Terminating total deadline.** A wall-clock deadline MUST
  terminate blocking transport/parser work and reap its worker. Inactivity
  timeouts and abandoned threads are insufficient.
- **SB-TRANS-004 — Failure preservation.** Redirect, encoding, byte, record,
  result, parser and deadline failures MUST return no harvest or watermark
  advance and preserve the last-known-good serving catalogue. Explicitly
  specified per-record quarantine is separate from whole-fetch failure.

## Existing foundations and remaining acceptance

The application already has strict tier resolution, the exact public field and
search sets, redaction, source-scoped ingestion and quarantine, durable admin
restrictions, contraction guards and source-independent backup preflight.
Those shared primitives do not establish an authenticated feed implementation.

B1 schema tests prove structural examples only. B2–B5 add explicit credentials,
authenticated pages, lossless JSON/page chains, native metadata and bounded
candidate assembly. B6 integrates them into the registered adapter, complete
source-work child, runtime loader and committed-cutoff guard. B7's accepted
PostgreSQL cases exercise native signed input, durable quarantine/recovery,
source isolation and committed audit events. Accepted B8 cases cover catalogue
services and HTTP using the same native input. B9's
[machine-readable evidence map](../sources/source-b-evidence.json) links all
22 IDs to behavior functions and their literal docstrings, with collection
checks that reject placeholder markers. Acceptance requires all mapped behavior
cases to pass and separate approval of operational records:

| Evidence | Required coverage |
|---|---|
| Adapter tests in `src/tests/sources/test_json_feed.py` | Authentication, exact-byte signatures, request binding, freshness/replay, decoding, duplicate keys, pagination, budgets, terminating deadline and policy adoption |
| `src/tests/integration/test_sensitive_source_sync_db.py` | Last-known-good/watermark preservation, quarantine, corrections, tier retention, source isolation, rebuilds, withdrawals and audit events |
| `src/tests/integration/test_sensitive_source_pages_db.py` | Exact discovery envelope below tier across search/facets/counts/detail; full metadata at the permitted tier |
| `src/tests/integration/test_source_b_backup_db.py` | Actual encrypted synthetic dump/restore, complete source-state equality and staged replay; production role/custody and representative restore remain operational evidence |
| Source-owner record | Approved public values/mappings and unrestricted-public disclosure of the complete envelope |

Do not add skipped or expected-failure placeholders to suggest those behaviors
are tested. The [B9 acceptance record](../sources/json-feed-acceptance.md)
separates executable synthetic checks from source-owner approval, real-feed
acceptance and representative isolated recovery. The
[v1 evidence summary](../sources/feed-contract-v1.md#synthetic-examples-and-executable-evidence)
retains the wire-level boundaries.

Before adapter implementation, fix the transport/schema/public mappings,
resource limits, failure rules and reconciliation model in the reviewed
contract. Before enabling a real source, record its schema validation,
source-owner approval, real adapter tests, correction/withdrawal procedure,
audit evidence, backup custody and representative restore. Synthetic work does
not wait for the private upstream; it does not replace that activation evidence.

## Reuse with a different disclosure policy

A different public/sensitive split requires coordinated review of redaction,
public search, the PostgreSQL search trigger and schema contract, filters,
facets, counts, templates, audit fields and integration tests. A field must not
become public merely because a template currently omits it.

## Emergency local withdrawal

Use **Admin → Dataset administration** to hide the dataset. Hiding removes it
from every catalogue surface, including public discovery details, at every tier.
Raising a tier alone preserves that discovery envelope and is insufficient when
it must disappear. The durable hide survives incremental sync, rebuild and
reintroduction of the same `(source, uuid)`; preserving it does not require
pausing the scheduler. Correct the authoritative source separately.

Use the documented direct-SQL fallback only when the web tier is unavailable.
It writes the same durable administrative state. See
[Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md).