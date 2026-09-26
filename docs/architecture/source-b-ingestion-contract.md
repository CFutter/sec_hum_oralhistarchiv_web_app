# Source B Ingestion Contract

**Status:** Source B ingestion is unimplemented. This document specifies acceptance requirements for its future client, parser, scheduler integration, and persistence adapter; it is not a description of current Source A behavior.

Source B's authoritative system must own classifications and public-envelope corrections. The local database is a serving cache; synchronization may overwrite local edits.

This contract has two independent parts:

1. `visibility_tier` decides who may receive the full metadata.
2. The **public discovery envelope** defines the small part of every record that
   remains visible even when the viewer is below that tier.

A correct tier does not make a sensitive public-envelope value safe. Both parts
must pass before a record is persisted.

## Public discovery is an explicit disclosure policy

The application deliberately remains a searchable catalogue of the existence of
restricted datasets. A below-tier viewer receives the fields in
`services.datasets.PUBLIC_DISCOVERY_FIELDS`:

| Field | Public meaning and Source B constraint |
|---|---|
| `id` | Application-generated row identifier. Its existence and enumerability are public. |
| `uuid` | Stable public dataset identifier. It must not contain a participant/case identifier, storage key, access token, or identifier that resolves to non-public metadata. |
| `title` | Deliberately displayed and searchable. Source B must supply a curated public discovery title, not copy an unreviewed sensitive title. |
| `access_level` | Public controlled label describing access to the underlying material. It must not contain free-text reasons or subject information. |
| `version` | Public release/version label only. It must not contain internal workflow, case, or participant identifiers. |
| `source` | Application-controlled source name, never an upstream free-text value. |
| `visibility_tier` | Publicly reveals that the record is `public`, `registered`, or `vetted`. This disclosure is intentional. |

These fields are public **individually and in combination**. For example, a
generic title may still identify a participant when combined with a rare version
label or a resolvable UUID. Approval must consider the complete envelope as one
disclosure.

The following catalogue behavior is also intentional and must be safe for every
Source B record:

- blank search and recent-dataset views acknowledge the record's existence;
- the public result count, ordering, pagination, and sequential `id` expose that
  records exist and can change over time;
- `/dataset/{id}` returns a redacted record for an existing above-tier dataset
  and a 404 for an absent one;
- `title` and `access_level` are in `PUBLIC_SEARCH_FIELDS` and therefore match
  free-text searches at every viewer tier;
- the `access_level` filter and facet are public catalogue channels; and
- the tier-independent catalogue total includes the record.

If the existence of a Source B record, its restriction tier, or any required
public-envelope value is sensitive, that record is incompatible with this
catalogue profile. It must not be ingested until the authoritative source can
provide a safe public representation or a separate non-enumerable product design
is implemented.

## Mandatory public-discovery contract

- **SB-DISC-001 — Explicit profile adoption.** The Source B implementation MUST
  explicitly adopt the exact `PUBLIC_DISCOVERY_FIELDS` and
  `PUBLIC_SEARCH_FIELDS` sets in reviewed code. It MUST NOT inherit a parser's
  arbitrary output fields or make the field set configurable by a request,
  record, or deployment environment variable.
- **SB-DISC-002 — Unrestricted-public standard.** Every public-envelope value,
  and the envelope considered as a whole, MUST be approved for disclosure to an
  unauthenticated internet user. A `registered` or `vetted` tier protects only
  fields outside the envelope.
- **SB-DISC-003 — Curated title.** `title` MUST be a deliberate public discovery
  title. It MUST NOT be populated by blindly copying a confidential interview,
  participant, case, or file title. Searchability is intentional and cannot be
  disabled per record under the current design.
- **SB-DISC-004 — Public identifiers and existence.** `uuid` MUST be a public,
  non-secret dataset identifier and MUST NOT act as a credential or resolve to a
  private record. The source owner MUST accept that local `id`, `uuid`, result
  membership, ordering, and 200-versus-404 behavior reveal record existence.
- **SB-DISC-005 — Controlled public labels.** `access_level`, `version`, and
  `source` MUST come from reviewed controlled mappings or application constants,
  not sensitive free text. `visibility_tier` is itself public metadata.
- **SB-DISC-006 — Search boundary.** Ungated `search_text_public` MUST be built
  only from `PUBLIC_SEARCH_FIELDS` (`title` and `access_level`). Keywords,
  languages, descriptions, project metadata, authors, participant attributes,
  alternate titles, internal identifiers, and URLs MUST remain outside it.
- **SB-DISC-007 — Fail closed before persistence.** A record that cannot satisfy
  this profile MUST be rejected or quarantined before `build_record_params()` or
  `upsert_dataset()` is called. Replacing an unsafe title or identifier with an
  unreviewed heuristic value is not sufficient. Keeping a previously accepted
  last-known-good version is permitted only as an explicit reconciliation rule.
- **SB-DISC-008 — Source correction.** The authoritative source owns public-title
  and identifier corrections. A correction or withdrawal MUST update or remove
  normalized columns, the raw `data` JSONB copy, search vectors, results,
  aggregates, and any cached derived state.
- **SB-DISC-009 — No semantic claim from structural tests.** Automated tests can
  pin which fields and channels are public, but cannot prove that human-language
  values are non-sensitive. Source governance, schema constraints, curated
  mappings, sample review, and documented sign-off remain mandatory controls.

## Mandatory visibility-tier contract

- **SB-VIS-001 — Mandatory source classification.** Every Source B record
  accepted for persistence MUST contain exactly one canonical
  `visibility_tier`: `public`, `registered`, or `vetted`. A parser that sees
  duplicate or conflicting tier fields MUST reject the record rather than
  silently choosing the first or last value.
- **SB-VIS-002 — Invalid classifications fail closed.** Missing, null,
  malformed, case-variant, or unknown tiers MUST raise
  `SourceVisibilityTierError` before new metadata is persisted. They MUST NOT be
  replaced with a default tier. The future adapter must explicitly choose
  whether the record is rejected, quarantined, or causes batch rollback; it
  must never publish the incoming content. Keeping a previously persisted,
  valid source version is permitted only as an explicit last-known-good
  reconciliation decision.
- **SB-VIS-003 — Application ceiling.** The effective dataset tier is the more
  restrictive of the authenticated source tier and
  `SourcePolicy.max_visibility`. Application policy may tighten a source
  assertion but MUST NOT make it more permissive.
- **SB-VIS-004 — Source ownership.** A valid later Source B version replaces
  the cached source tier, subject to SB-VIS-003. Administrators
  may raise the stored classification directly; a more permissive source
  version MUST NOT lower it. But classification corrections
  are expected to be made at the source and then synchronized.
- **SB-VIS-005 — Integrity binding.** The tier MUST be covered by the same
  source-authentication and integrity mechanism as the record metadata. An
  unauthenticated header, query parameter, filename, or other side channel is
  not a valid tier assertion.
- **SB-VIS-006 — Complete derived-state update.** A tier change, metadata
  correction, or withdrawal MUST update or remove normalized columns, the raw
  `data` JSONB copy, search vectors, result visibility, aggregates, and any
  affected caches. Tier transitions and withdrawals MUST produce an audit
  event.
- **SB-VIS-007 — Source isolation.** Every update, withdrawal, and rebuild MUST
  be scoped by `(source, uuid)`. Source B reconciliation must not modify Source
  A or mock rows.
- **SB-VIS-008 — Integration boundary.** The Source B adapter MUST validate the
  public discovery envelope and call `resolve_required_source_tier()` before
  `build_record_params()` and `upsert_dataset()`. It MUST NOT use
  `_upsert_public_catalogue_record()`, whose missing-tier behavior exists
  specifically for Source A.
- **SB-VIS-009 — Recovery coverage.** Before Source B is enabled, the dedicated
  backup role, grants, and backup preflight MUST cover every Source B schema and
  table. An encrypted archive MUST be restored in isolation and prove that
  representative Source B rows survive despite production RLS. If Source B is
  stored in another database, the one-database backup job is insufficient and a
  separately encrypted, jointly tested recovery path is mandatory.
- **SB-TRANS-001 — No redirects.** A Source B transport MUST disable automatic
  redirects and reject every redirect response. Endpoint relocation requires a
  reviewed configuration change. Authentication credentials, integrity keys,
  cookies, bearer tokens, and asserted metadata MUST never be forwarded to a
  redirect-selected origin.
- **SB-TRANS-002 — Explicit resource budgets.** Before shared persistence, the client MUST enforce reviewed per-response compressed/decompressed byte limits, aggregate-transfer limits, per-record size/count limits, and retained-result/staging limits. If decompression cannot be bounded, disable compression and reject non-identity encodings.
- **SB-TRANS-003 — Terminating total deadline.** Ingestion MUST enforce a wall-clock deadline that terminates blocking transport/parser work. Inactivity timeouts and abandoned worker threads are insufficient.
- **SB-TRANS-004 — Failure preservation.** Redirect, encoding, byte, record, result, parser, and deadline failures MUST produce no harvest result or watermark advance and MUST preserve last-known-good serving state.


## What is executable now

The transport-independent controls that exist before Source B are deliberately
small:

- `PUBLIC_DISCOVERY_FIELDS` is the exact below-tier release set;
- `PUBLIC_SEARCH_FIELDS` is the exact ungated free-text subset and must remain a
  subset of the release set;
- `filter_for_tier()` and `assert_redaction_total()` enforce a complete,
  disjoint field classification and fail startup if an unapproved public-search
  field appears;
- the schema contract pins the PostgreSQL `search_text_public` trigger body; and
- `resolve_required_source_tier()` rejects missing or invalid tiers and clamps
  valid tiers against the source ceiling.

The unit and database integration tests pin those structural properties,
including public title/access-level search on above-tier rows and non-matching of
full-only fields below tier. They do not certify actual Source B values because
no Source B schema, parser, or records exist yet.

## Acceptance tests for the implementation pull request

When Source B ingestion is implemented, its pull request MUST add tests proving
the real adapter—not only generic primitives—meets the contract:

| Test concern | Required location |
|---|---|
| Redirect refusal; bounded transport decoding; per-response, aggregate, per-record, record-count, and retained-result limits; terminating wall-clock deadline; failure preservation; and record-schema validation | `src/tests/unit/test_source_b_client.py` (or the transport module's matching test file), plus `src/tests/integration/test_source_b_sync_db.py` for last-known-good/watermark behavior |
| Authenticated/integrity-protected binding of tier and metadata; tampering, replay, substitution, and reordering fail closed | the transport module's unit tests plus `src/tests/integration/test_source_b_sync_db.py` |
| Explicit adoption of `PUBLIC_DISCOVERY_FIELDS`; controlled mappings for `title`, `uuid`, `access_level`, `version`, and `source`; rejection/quarantine of structurally unsafe values | `src/tests/unit/test_source_b_policy.py` and `src/tests/integration/test_source_b_sync_db.py` |
| Strict resolver and discovery validation run before persistence; tier changes; last-known-good behavior; withdrawals; source-scoped rebuilds; complete derived-data cleanup | `src/tests/integration/test_source_b_sync_db.py` |
| Public browsing/search/detail behavior exposes only the approved envelope while a permitted tier receives the full record | `src/tests/integration/test_source_b_pages_db.py` |
| Tier transitions and withdrawals emit required audit events without including sensitive metadata | `src/tests/integration/test_source_b_sync_db.py` and the audit integration suite |
| Cross-process invalidation or direct re-query behavior prevents stale authorization-sensitive aggregates after corrections | the existing Redis/page integration suites or a Source B-specific integration module |
| Backup grants/preflight include the real Source B storage; an encrypted isolated restore preserves representative rows under the recovery role | `src/tests/integration/test_source_b_backup_db.py` (or the deployment recovery acceptance suite) |

Do not add skipped or `xfail` placeholder tests now: they can create the
appearance of coverage without exercising an implementation. The contract IDs
above are stable names future tests should cite in their docstrings.

## Pre-implementation approval record

Before coding or enabling Source B, record all of the following in the Source B
implementation review:

1. the transport, authentication, integrity, replay, and record-boundary model, including exact redirect policy, 
   byte/record/result budgets, a terminating total deadline, and last-known-good behavior for every 
   transport/parser/resource failure;
2. the authoritative schema location and the single-valued tier field;
3. the source owner's written approval that record existence and the complete
   public discovery envelope are unrestricted-public data;
4. the exact mapping or curation rule for each public-envelope field, including
   a statement that `uuid` is not a credential or private lookup key;
5. the reject, quarantine, batch-rollback, and last-known-good behavior;
6. correction and withdrawal semantics, audit events, and operator runbook;
7. backup-role grants, database coverage, encrypted off-host custody, and a
   representative isolated restore; and
8. passing adapter-level tests for every `SB-DISC-*`, `SB-VIS-*`, and `SB-TRANS-*` requirement.

## Reuse with a different disclosure policy

`PUBLIC_DISCOVERY_FIELDS` is intentionally a named policy boundary. A fork whose
records have a different public/sensitive split must define its own set rather
than assuming this application's choices are generic. That change requires a
coordinated review of `filter_for_tier()`, `_redacted_values()`,
`PUBLIC_SEARCH_FIELDS`, the PostgreSQL search trigger and schema contract, query
filters/facets/counts, templates, audit fields, and the unit and integration
tests. A field must never become public merely because a template currently does
not render it.

## Emergency local withdrawal

If metadata must disappear before the authoritative source can be corrected,
operators may perform the documented manual database withdrawal. Raising a
dataset's tier preserves the public discovery envelope, so it is insufficient
when that envelope must also disappear. The next sync can restore a withdrawn
record unless the scheduler stays paused until the source is fixed. See
[Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md).
