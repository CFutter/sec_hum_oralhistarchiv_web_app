# Access Control & Visibility

The application applies three metadata tiers:

1. Every user has an `access_tier` of `public`, `registered` or `vetted`.
2. Every dataset has a `visibility_tier` of `public`, `registered` or `vetted`,
   supplied or constrained by its source policy. The effective tier is the
   stricter stored tier and durable administrator floor. Synchronization
   accepts explicit upstream tier corrections and retains the prior tier when it is omitted.
3. Each metadata field also has a code minimum and an optional stricter source
   minimum. Outside the public discovery envelope, a viewer must meet the
   strictest record/code/source requirement for that field. Full metadata
   requires permission for every field. The public envelope stays `id`, `uuid`,
   `title`, `access_level`, `version`, `source`, `visibility_tier`.

These tiers govern catalogue metadata. The upstream repository separately
governs access to recordings and other linked resources.

## The tier hierarchy

`public < registered < vetted`, ranked 0, 1 and 2 in
`services/access_tiers.py`. `can_access()` compares ranks; `can_view_field()`
applies the effective field requirement and `can_view_full()` checks all
fields. `full_required_tier()` supplies the actual full-record requirement for
notices. Unknown tiers are rejected. User metadata tiers are independent of
administrator privileges.

## Where the check runs

Routes resolve `request.state.user.access_tier`, defaulting guests to `public`,
and pass it and the trusted process configured-source snapshot to dataset
services. `search_catalogue_page`, the compatibility `search_datasets`,
`get_recent_datasets` and `get_dataset_by_id` apply `filter_for_tier` with that
same scope before returning dataset objects.

Catalogue discovery first joins `dataset_admin_state` by `(source, uuid)`.
A non-NULL `hidden_at` excludes the row at every viewer tier, including detail
(404), search and separate exact counts, recent records, facets and all catalogue
counts. Hiding is applied before pagination and facet sampling. Otherwise the
effective tier is the stricter stored tier and optional administrator floor.
SQL metadata gates and Python redaction combine that same effective tier with
the code and source minimum for each protected field.
Public totals are live, including through `CatalogueStatsCache`, so enforcement
does not depend on Redis invalidation or restarting web workers.

SQL restricts which hidden fields may participate in search and filtering.
Result rows can still contain full metadata inside the application; Python
redaction removes restricted values before results reach templates. New callers
must use the tier-aware services or redact explicitly before exposing data.

### PostgreSQL row-level enforcement

E3 enables base-table RLS for `oralhistarchiv_web`. Its SELECT policy requires
both the stored tier and durable administrator floor to fit the viewer tier
and excludes hidden identities. Unset, empty or invalid `app.viewer_tier` means
`public`. `get_catalogue_cursor()` sets that context from the authenticated
principal for each catalogue query with transaction-local configuration and
restores the prior value after successful nested scopes. An exception rolls
back its scope; pooled queries do not inherit an earlier user's tier.

The owner-backed security-barrier `catalogue_discovery` view preserves the exact
seven-field public envelope, without timestamps, ordering ordinals, raw metadata
or full-search text. Services left-join the RLS-protected base table
for permitted metadata. This retains public discovery of an above-tier record
without granting its raw row. The separate `dataset_admin_catalogue` view
contains only ID/source/UUID, stored tier and canonical record tier, including
hidden identities. Administrator routes still guard reads, and mutation services
recheck write authority; that view never confers a higher metadata tier.

Both views use `security_invoker=false` and the trusted table owner's deliberate
RLS bypass. The table has RLS enabled and `FORCE ROW LEVEL SECURITY` false.
Separate exact-current-user policies cover web SELECT and scheduler ingestion;
their `PUBLIC` targets require no implicit runtime-role creation. Hardened
runtime roles remain nonowners, `NOBYPASSRLS` and without memberships. Development
and migrations using the owner intentionally bypass these row policies.

RLS protects the whole-record floor, while E2's stricter field minima remain
application SQL/redaction/template rules. Direct SQL can read all columns of
an admitted row. The shared web role can set its viewer setting, so trusted
application authentication remains part of this boundary; this is not a claim
of protection against arbitrary SQL execution under that role.

Separately stored administrator state survives catalogue deletion and is applied
again when the same identity returns. Raw-row SQL edits do not create durable
administrator state. Web can SELECT, INSERT and UPDATE that state through the
authorized application path; scheduler can SELECT it. Accepted administrator
controls continue to audit changes without granting metadata access.

### Search and facets

- Public title and access-level text may match searches at every tier. The five
  other searchable fields contribute only when individually permitted: description,
  project title, project description, keywords and authors. Full-text matching
  evaluates one disclosure-appropriate document per row, so hidden words cannot
  influence negation or phrase results. Partially visible rows use an exact
  field-masked document; the raw full vector never prefilters that path.
- Search uses explicit `pg_catalog.simple` full-text configuration, without
  stemming or accent folding. Plain alphanumeric/whitespace terms use web-search
  AND semantics plus the former escaped literal-substring fallback. Double quotes,
  OR between terms (case-insensitive), or a leading/whitespace-separated minus
  before a term select only web-search semantics. Any `%`, `_` or backslash
  selects literal matching even when operator-like text is also present. Other
  punctuation stays literal unless explicit web syntax was selected. Outer
  whitespace is trimmed; spelling, case and internal whitespace are preserved.
  There is no relevance-ranking change.
- Separate `catalogue_search_public`, `catalogue_search_registered` and
  `catalogue_search_vetted` tables contain only each audience's searchable fields,
  with independent indexes. Page/count functions select one audience and verify
  the bound policy fingerprint. `catalogue_search_candidates` delegates to these
  projections for compatibility; requests never probe unrestricted raw indexes.
  Mutations maintain projections atomically. See [search policy](../runbooks/search-policy.md).
- Keyword and language filters and suggestions use their own field requirements.
  Access-level filtering is public. The bounded page query and separate exact
  count API apply the same field gates; normal navigation does not count matches.
- Facet suggestions use a bounded sample of recent records, not a complete
  catalogue vocabulary. Restricted records can occupy positions in that sample;
  tier filtering prevents disclosure of their hidden values.
- Home shows a live nonhidden dataset total and at most three recent redacted
  records. It does not aggregate language or keyword arrays across the catalogue.
  Search suggestions retain their bounded sample and independent field gates.

### Pagination

Numbered search pages stop at 100 and use lookahead rather than exact totals;
later navigation uses a version 2 encrypted/authenticated identity bookmark
bound to the current query, filters, viewer session/tier, page size and
source/field policy. The handoff records a current
anchor identity and ID ceiling. Every continuation rechecks current anchor
eligibility, matching, administrator hiding, RLS and redaction. Invalid, expired
or ineligible-anchor bookmarks restart at page 1 with one generic notice;
oversized inputs fail request validation. See the
[pagination contract](../runbooks/search-pagination.md).

Each request uses fresh database state. Higher IDs after handoff are excluded,
but a lower-ID late commit can appear in logical order. Updates to existing
rows can reorder, omit or repeat results across requests. The owner-backed
`catalogue_page_ids()` function resolves private timestamp/ID anchors and limits
separate non-NULL/NULL seek branches before merging them. It reapplies exact
matching and field gates before each branch limit, with no global discovery
window or deep OFFSET. `catalogue_scan_ceiling()` supplies the initial ceiling.
Only web has direct EXECUTE on these functions, and startup pins their complete
SQL and privilege contracts. This is not a frozen catalogue snapshot or a
production performance result. The separate exact-count API defaults to a
2,000 ms requested timeout, preserves a shorter existing limit and restores the
previous setting after success.

Templates receive hidden scalar fields as `None` and hidden list fields as
empty lists. They render permitted fields independently and show restriction
notices using their actual effective field/full-record requirement. They do not
infer permission from an empty or redacted value.

## What gets redacted

For a viewer below the dataset's effective record tier, `filter_for_tier`
creates a fresh `Dataset` containing only the public discovery envelope:

| Survives redaction | Removed by redaction |
|---|---|
| `id`, `uuid` | `description`, `resource_description` |
| `title` | `project_title`, `project_description` |
| `access_level` | `authors`, `keywords`, `languages` |
| `version` | `resource_access_url`, `landing_page_url`, `resource_proxies` |
| `source`, `visibility_tier` | `license_val`, `license_url`, `doi`, `resource_type`, `bibliographical_citation` |

This remains the default field partition for the current `Dataset`. A stricter
field minimum can additionally redact individual protected fields from a
record otherwise allowed at the viewer's tier. The startup guard,
`assert_field_visibility_total()`, checks a complete immutable
`FIELD_VISIBILITY` matrix, the discovery/redaction partition, canonical tiers,
public search minima and consistent resource-target minima. Field redaction
uses the strictest code/source field minimum and effective record tier outside
the approved public envelope. All code minima are initially `public`. Optional
immutable `SourceConfig.field_visibility` overrides can only tighten them.
Runtime records whose source is unselected default to `vetted` for protected
fields. A fully authorized viewer receives the original object; a restricted
projection has fresh redaction lists. See the [field policy](field-visibility.md)
for the complete 22-field classification, source syntax and process scope.

Every surviving value, the fact that the record exists and the fields in
combination must be approved for unrestricted public disclosure. Titles are
deliberately displayed and searchable. A `uuid` must be a public dataset
identifier, not a participant identifier, private lookup key or credential.
An existence-revealing title cannot be made confidential by setting its record
to `vetted`.

This is a semantic source contract as well as a field-partition check. Tests
can prove which fields the application releases; they cannot establish that a
human-language title is safe. An OAI catalogue's public-metadata suitability is
an operational source assumption, not something HTTPS or source-file ownership
checks certify. Source B must independently satisfy the
[Source B Ingestion Contract](source-b-ingestion-contract.md) before activation.

## Why `visibility_tier` and `access_level` are different

| Field | Meaning | Authority |
|---|---|---|
| `visibility_tier` | Record minimum for protected metadata; field minima can raise it further | Source policy, accepted upstream classification and durable administrator floor |
| `access_level` | Displayed classification of material access | Source-specific classifier |

Record tiers and field minima gate local metadata. `access_level` is a public
label and filter, not an application download permission. Resource and landing links
are displayed when full metadata and a usable URL are available, regardless of
that label. Configured source display metadata supplies their action labels;
the external repository enforces material access.

## How `access_level` gets set

Each adapter policy supplies its own resource-access classifier. OAI/CMDI
uses an immutable exact mapping: `Public access`, `License CC BY` and
`CC BY 4.0` map to `public`; `Restricted access` maps to `restricted`.
Missing (`None`) and every other string fall back to `restricted`. Nontext
input raises `TypeError` without echoing the raw value. Comparisons preserve
case and whitespace; no prefix match or normalization expands the public set.
The retained CC labels are application-test compatibility inputs, not provider
or source-owner evidence about access or licensing.

The fixture and static-JSON adapters still recognize only exact `Public access`
as public, with every other label and `None` restricted. The JSON feed still
accepts only exact `Public access` and `Restricted access`; unknown strings
raise `ValueError`, and missing/nontext values raise `TypeError`. See the
[complete adapter mapping table](../sources/index.md#resource-access-classification).

K1 binds the OAI/CMDI mapping and restricted fallback into the interpretation
fingerprint. Existing OAI source state therefore needs a normal authoritative
rebuild; stored rows are not relabeled merely by deploying code. No schema
change or database reset is needed. This changes a public label/filter, not
metadata-tier enforcement, resource-link gating or upstream permissions.
Validate the upstream link and access contract operationally.

## How `visibility_tier` gets set

Each selected source has a `SourcePolicy`. Its `max_visibility`, configured in
the source TOML, is the most permissive publication tier allowed for that
source. The common configuration default is `vetted`. The development fixture
explicitly selects `public` so its public, registered and vetted record tiers
remain distinct.

For a recognized record tier, the incoming effective tier is the stricter of
the source restriction and the record tier. For sources without per-record
classification, `requires_record_tier=false` permits a missing tier and
`resolve_tier(None, policy)` supplies the source restriction. OAI/CMDI parsing
supplies no application tier; its configuration defaults to
`requires_record_tier=false`. Configuration and direct OAI adapter construction reject
`requires_record_tier=true` before harvesting.

When `requires_record_tier=true`, the shared write boundary calls
`resolve_required_source_tier()` before classifying access or building
persistence parameters. Missing or unknown tiers are rejected. Adapters may
validate earlier: fixture fetching checks its complete snapshot before
returning records. A returned matching record with an unknown non-null tier
also fails harvest validation before staging.

For an existing `(source, uuid)`, incremental sync and full rebuild atomically
apply an explicit valid upstream tier, including a lower tier, subject to the
configured source floor and durable administrator restrictions. If the source
omits a tier, the last accepted restriction is retained. A
configuration change alone does not immediately reclassify served rows.
Changing source interpretation or policy requires an authoritative rebuild;
existing rows retain their stored classification while that rebuild is pending.

Source `field_visibility` is a separate read policy and does not change
ingestion fingerprints. Changed catalogue policy requires the explicit owner
[projection replacement](../runbooks/search-policy.md), then process restart;
restart alone rejects a different binding. Callers must supply trusted
`configured_sources`. Unselected sources retain public discovery, while
protected fields require vetted access.

Source B must require record tiers, authenticate their provenance and validate
that every public discovery value is approved for unrestricted publication.
The generic tier guard and the synthetic fixture do not establish these
guarantees or complete the Source B ingestion contract.

## Administrative dataset restrictions

Use **Admin → Dataset administration** (`/admin/datasets`) to search by exact
UUID and optional source name, then open the per-dataset control page. Both
identity fields distinguish a record; identical UUIDs in different sources are
independent. The control list includes hidden and retained unselected sources.
It shows identifiers, visibility state and the approved public catalogue title
for nonhidden records. Titles come from a bounded left join to the existing
`catalogue_discovery` view; hidden identities retain no title. Protected metadata
is not read by these controls. A link to the normal catalogue page applies the
administrator's own metadata tier. The normal catalogue detail page also offers
administrators a **Manage visibility** link to the same controls, so they can
identify a record using the existing tier-aware catalogue search first.

The control list reads at most 21 identities to render each 20-record page.
Previous/Next links retain exact identity filters and use ID boundaries, so
navigation performs neither global counts nor growing offsets. Exact totals,
numbered pages and a last-page shortcut are intentionally omitted. New records
can appear when returning to newer pages; deletions may leave a stale link
empty, where First page restarts the same filtered browse. Boundaries are not
permissions and all route and mutation authorization checks still apply.
The `search_admin_datasets()` service returns `DatasetAdminPage`; callers must
use its records and newer/older boundaries rather than the former count tuple.
Its exact UUID filter does not match titles or other metadata, including hidden
titles. Source and UUID remain the authoritative identity when titles coincide.

The page offers the currently permitted tier choices. Saving a floor cannot
lower the stored tier, an existing administrator floor or the current resolved
source restriction. A selected policy is required for raising; an unavailable
policy or invalid mandatory record classification blocks raising but permits
hide/restore. Submitted policy or identity fields never select mutation policy.
The service rechecks every restriction at the write boundary, so a stale form
can return a fixed 4xx response without changing state.

**Hide dataset** excludes the entire discovery envelope at every tier.
**Restore dataset** clears only hiding and preserves the durable floor. A
repeated action is a no-op; setting a durable floor equal to the effective tier
can still be a real change because the floor survives raw-row reintroduction.
State belongs to `(source, uuid)` and survives physical catalogue deletion.
Absent raw rows have no current actionable ID and are omitted from the UI.

All three routes use the administrator policy; the mutation additionally
requires form content type and the session-bound CSRF pair. The backend owns
transaction authorization and audit. Web has SELECT, INSERT and UPDATE on
administrator state and only SELECT on raw catalogue metadata; scheduler only
reads administrator state. No schema revision or grant expansion is required
for these routes.

Follow the [Emergency Dataset Withdrawal](../runbooks/emergency-dataset-withdrawal.md)
for the primary UI procedure, all-tier verification and the SQL fallback when
the web tier is unavailable. Raw catalogue SQL changes are not the durable
administration path. Existing stored classifications are not backfilled into
administrator state because they have no administrator provenance.

Removing a source from the selected TOML controls future ingestion and selected
source diagnostics; its stored records remain served unless hidden.

## Audited dataset mutation service

`app.services.change_dataset_admin_state()` implements `raise_tier`, `hide` and
`restore`. It receives the exact actor/session credential and server-resolved
request correlation, plus the process's trusted configured-source snapshot.
Submitted form data must not supply source policy.

The mutation waits for the same PostgreSQL advisory identity as ingestion,
then checks federation policy and current administrator/session authority.
It rechecks full authority after any administrator-state row-lock wait. The
web role requires no UPDATE grant on the raw catalogue. Existing database
statement timeouts bound lock waiting; cancellation and database failures roll
back. Ingestion retains its session-lock and connection-loss fencing.

A raise cannot fall below the stored tier, existing administrator floor or the
current source-policy resolution of persisted `data.visibility_tier`. A missing
selected policy or invalid mandatory tier rejects the raise. Hide and restore
remain available for retained unselected sources. Restore clears only hiding.
Repeated actions are no-ops, while establishing a durable floor equal to the
current stored tier is a real change because it survives reintroduction.

Changed actions append one `admin_dataset_tier_raised`, `admin_dataset_hidden`
or `admin_dataset_restored` event in the same transaction as the restriction.
Rejections, rollback and no-ops retain no successful-change event. A failed
append rolls the restriction back. After commit, the service also emits an
optional local log copy; HTTP routes must not duplicate it. The durable event
survives a crash before that local copy is emitted. Delivery to an independent
sink uses the owner-operated [security event exporter](../runbooks/security-event-delivery.md).
The administrator UI delegates to this service and does not duplicate its
change events. Successful actions redirect to the control page; rejected
actions return fixed 4xx feedback. Unexpected storage failures propagate.

## What gets logged

The detail handler retains `dataset_access` for nonpublic dataset tiers,
including granted and denied full-metadata views. In addition, detail, home,
search and resource responses emit `metadata_disclosure` descriptions whenever
the view displays protected values or denies protected fields. Protection comes
from the effective field policy, even for a public-tier record. Events contain
record ID, source/UUID, the names of fields actually displayed, denied field
names, and a full/partial/denied outcome. Empty/default values do not count as
disclosures. Card descriptions follow their rendered field and keyword slices;
internal resource redirects do not claim to expose the upstream URL in HTML.

Descriptions are grouped into at most five records per event and at most one
hundred records per response. No metadata values, search terms, filter values,
capability URLs or session tokens are included. Facet suggestions use the current
viewer tier and the same independent field gates as exact filters. Their query
returns protected contributor identities and field names in the same snapshot as
the displayed options. At most 200 sampled records contribute to those events;
unlisted singleton keywords, out-of-sample records and suppressed options do not
produce disclosure claims. Contributor events use batches of at most five records.

Read-disclosure descriptions remain best-effort local audit events; they are not
transactional delivery guarantees. Durable restriction/mutation evidence uses
the separate security event outbox. Neither event kind establishes that an
external resource was downloaded after its redirect was issued. Access histories
are sensitive and need restricted readership and an approved retention policy.

Audit output uses configured logging. The reference deployment captures stdout
with journald; it does not create a separate `audit.log`. Remote shipping and
independently controlled retention require deployment configuration and
acceptance evidence.

## Administrative user access

`is_admin` is independent of `access_tier`. Admin routes require an eligible
full-session administrator. Missing and nonadmin principals receive 404;
administrator session and recovery requirements retain their own redirects or
403 responses. Local administrators need usable recovery codes.

Admin write services recheck active administrator status and the full, unexpired
session under locks; local actors must also satisfy TOTP/recovery requirements.
Administrator status does not confer vetted metadata access. The metadata tier
must be assigned separately.

## Limitations

The [field-policy implementation record](field-visibility.md#wp-e-implementation-acceptance-record)
requires the reviewed commit, CI results and synthetic interface evidence.
The [operator record](../runbooks/visibility-recovery-acceptance.md) separately
requires host peer, custody and representative deployed-recovery evidence.
There is no expiring metadata-tier grant or in-app per-dataset access-request
workflow. Administrators assign user tiers manually; source policy and stored
restrictions govern dataset classification.

The backup identity remains read-only `BYPASSRLS`, with no memberships and SELECT
on all managed tables, so recovery can include every tier and hidden identity.
Preflight verifies those properties and the dump keeps `row_security=off` to
refuse a silently filtered archive. Isolated restore runs as its owner/recovery
identity; verification also uses the backup identity without granting it DDL or
DML. Disposable role/restore tests do not replace deployed peer-mapping, custody
and representative recovery evidence. See the [field-policy contract](field-visibility.md)
for migration and acceptance boundaries.
