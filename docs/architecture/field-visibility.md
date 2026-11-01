# Field visibility policy

Field minima apply through Python, SQL and templates. PostgreSQL adds a web-role
row boundary and safe discovery/control projections. Resource redirects require
full metadata permission. Verify current ordering, navigation and grants with
the [pagination checks](../runbooks/search-pagination.md#targeted-validation).
Host identities, key custody and representative restore require separate
[deployment evidence](../runbooks/visibility-recovery-acceptance.md).

## Policy ownership and effective minima

The pure `app.field_visibility` module owns the immutable `FIELD_VISIBILITY`
mapping, also exported through the public `app.services` API. The mapping has
one canonical access tier for every field of `Dataset`. All 22 code minima are
initially `public`; these are additional floors, not permission to disclose
every field publicly. The table is the application field classification used
by WP E. The [catalogue classification matrix](../compliance/data-classification.md)
lists those same fields and policy memberships with a code-checked drift guard.
That supplies the catalogue slice of WP L. The
[processing register](../compliance/processing-register.md) provides the wider
asset-inventory template; completed inventories and governance approval remain
operator work.

| Dataset field | Code minimum | Record/source field restrictions apply |
|---|---|---|
| `id` | `public` | No; approved public discovery |
| `uuid` | `public` | No; approved public discovery |
| `title` | `public` | No; approved public discovery |
| `project_title` | `public` | Yes |
| `description` | `public` | Yes |
| `resource_description` | `public` | Yes |
| `languages` | `public` | Yes |
| `project_description` | `public` | Yes |
| `authors` | `public` | Yes |
| `keywords` | `public` | Yes |
| `resource_proxies` | `public` | Yes; shared resource-target minimum |
| `resource_access_url` | `public` | Yes; shared resource-target minimum |
| `landing_page_url` | `public` | Yes; shared resource-target minimum |
| `license_val` | `public` | Yes |
| `license_url` | `public` | Yes |
| `access_level` | `public` | No; approved public discovery |
| `version` | `public` | No; approved public discovery |
| `doi` | `public` | Yes |
| `resource_type` | `public` | Yes |
| `bibliographical_citation` | `public` | Yes |
| `source` | `public` | No; approved public discovery |
| `visibility_tier` | `public` | No; approved public discovery |

For protected fields, the required tier is the strictest of the effective
record tier, code minimum and configured source minimum. The effective record
tier includes the durable administrator floor. Ingestion still preserves the
accepted upstream tier (retaining the prior tier when omitted). No field policy
can lower an administrator restriction.
Hiding removes the whole identity before catalogue projection at every tier.

The public envelope stays exactly `id`, `uuid`, `title`, `access_level`,
`version`, `source`, `visibility_tier`. Ungated public search stays limited to
`title` and `access_level`. Source owners must approve every public discovery
value and its combination; structural validation cannot certify that approval.

Raw `resource_proxies` and derived `resource_access_url` and `landing_page_url`
overlap. Their merged code/source minima must be equal, so a stricter raw-proxy
rule cannot leak through a derived URL.

## Source overrides and process scope

Search masks use the versioned contract in `src/app/search_mask_contract.py`.
Version 1 assigns explicit values: description `1`, project title `2`, project
description `4`, keywords `8`, authors `16`, and languages `32`. The first five
form the document mask `31`; languages participates only in filter visibility,
and the complete page/filter mask is `63`. Tuple position never assigns a bit.

The field table also owns text/array conversion and document order. Python
count/page contexts and SQL document construction consume that table. One
candidate-selector template supplies both the count view and page function.
The page function records the version/map digest in its stored source; the
count view uses a versioned context CTE. Exact runtime schema checks validate
both SQL consumers, and local startup validation rejects unregistered field-map,
array-kind or document-order edits before database checks. Bookmark context
includes the protocol tag, invalidating bookmarks from another contract.

A protocol change requires a new registered version, current SQL/contract
updates, a reviewed migration and count/page/filter regression checks. Historical
revisions keep literal SQL. An authorized reset before the first retained
deployment may instead update the initial snapshots and their history digests.

An optional `field_visibility` inline table belongs to the existing flat
`[[sources]]` entry. For example, add this line to a reviewed source entry:

```toml
field_visibility = { description = "registered", keywords = "vetted" }
```

`SourceConfig.field_visibility` snapshots an immutable mapping. It accepts only
the 22 known field names and canonical `public`, `registered`, `vetted` tiers.
An override may equal or raise its code minimum; it cannot lower one. Discovery
and public-search fields must remain `public`. All three resource-target fields
must have the same minimum after merging the overrides with the code matrix;
raising that group therefore requires configuring all three members together.

Web catalogue calls and template permission helpers explicitly receive the
process's trusted configured-source snapshot. Form/query values never select
field policy. Changed policy requires an explicit owner
[projection replacement](../runbooks/search-policy.md) and process restart;
restart alone rejects a mismatched binding. No ingestion rebuild or schema
migration is required solely for field minima.

After source loading, web startup calls `build_catalogue_policy()` once and
retains the resulting immutable `CataloguePolicy` in app state. It contains
source-name lookups, resolved field minima, reusable SQL cases, masks for all
three viewer tiers and a static bookmark-policy digest. Page services and
template helpers share this object through their required `configured_sources`
argument. Explicit source or code-matrix replacement rebuilds the app's policy;
there is no process-global memoization. Direct callers may still supply a raw
source sequence, which is compiled once at the outer service boundary.

Only immutable configuration is compiled. Each permission check still combines
it with the dataset's current effective stored/administrator tier, and every
SQL condition retains its per-row record-tier check. Hidden identities, live
counts and record/admin decisions are not cached. Tests that change immutable
policy inputs must build a fresh context or replace the app's source/matrix
snapshot.

Stored records from an unselected source remain discoverable. In an explicit
runtime scope, all their protected fields default to `vetted`, while the seven
public discovery fields remain public. Deselecting a source cannot silently
relax its former field restrictions. Service callers must explicitly supply
`configured_sources`, as either a source sequence or a compiled policy. An
explicitly empty selection retains the same conservative unknown-source rule.

## Public service API

- `build_catalogue_policy(configured_sources)` prepares one immutable context
  for repeated service and template calls using the same source selection.
- `field_required_tier(dataset, field_name, *, configured_sources=...)` resolves
  one field's effective requirement.
- `can_view_field(dataset, user_tier, field_name, *, configured_sources=...)`
  compares the viewer to that requirement.
- `full_required_tier(dataset, *, configured_sources=...)` resolves the strictest
  requirement across the complete record.
- `can_view_full(dataset, user_tier, *, configured_sources=...)` requires every
  field to be permitted. Resource actions and redirects retain this gate.
- `filter_for_tier(dataset, user_tier, *, configured_sources=...)` preserves
  permitted values and replaces refused protected fields with established
  scalar/list defaults. A fully permitted record keeps its original object;
  redaction does not mutate the input and creates fresh hidden lists.
- `assert_field_visibility_total()` validates the entire matrix and partition
  before web or scheduler database checks.

The startup guard rejects missing/unknown matrix fields, noncanonical minima,
missing/overlapping/stale redaction classifications, restricted discovery/search
minima and inconsistent resource-target minima. Unknown fields and invalid tiers
fail closed in the resolver. Administrator status supplies no metadata bypass.

## Search, aggregates and templates

SQL and Python resolve the same effective field requirement. Full-text search
uses explicit `pg_catalog.simple`, with no stemming or accent folding. Its
public document is title plus access level. Its full document starts with that
public document, followed by description, project title, project description,
keywords and authors in that order. Each extra field contributes only when its
record/code/source requirement is met. One allowed document is evaluated per
row, including for NOT and phrase queries: a hidden term neither supplies a
positive match nor changes the result of a negative condition.

Separate public, registered and vetted projection tables contain only the
fields each audience may search, with independent vector, trigram, filter and
ordering indexes. Page/count functions select one projection and require the
complete bound policy fingerprint. The compatibility candidate view delegates
to those projections; raw unrestricted indexes are outside the query path.
Record, administrator-state and quarantine changes update projections in the
same transaction. Stale workers fail closed. See [search policy](../runbooks/search-policy.md).

Plain word input combines full-text AND matching with the prior escaped
literal-substring fallback. Explicit quotes, OR and separated minus select
web-search operators without that fallback. Percent, underscore and backslash
always remain literal; other punctuation remains literal unless explicit web
syntax is requested. See the [mode table](../runbooks/search-fulltext.md#query-modes).
The legacy text blobs remain maintained without changing their field order or
space separators; `search_text_full` still omits access level. Those legacy
blobs are never an unrestricted disclosure predicate.

Keyword/language filters still use exact array membership and access-level
filtering remains public. Normal search applies these gates inside the bounded
ordering function and does not request an exact count. The separate exact-count
API applies the same field gates. Facets select 200 recent IDs through that
ordering function before inspecting visible values, and retain their per-array
and suggestion limits. Home renders at most three recent redacted records and
a live dataset total; it does not compute language or keyword totals. Public
catalogue totals count every nonhidden discovery record.

Templates render each permitted metadata field independently. Restricted-field
notices use the actual effective requirement, including source minima, rather
than inferring permission from the now-redacted value. Resource links remain
available only with full-record permission and a usable stored target. Field
redaction does not itself authorize an upstream recording download.

## PostgreSQL row boundary

E3 enables RLS on `oral_history_datasets` while retaining accepted above-tier
public discovery. `catalogue_discovery` is an owner-backed security-barrier view
with `security_invoker=false`. It exposes exactly the seven public discovery
fields, excludes hidden identities and applies the effective stored/administrator
tier. It exposes no timestamp, ordering ordinal, JSON metadata or full-search
blob. Catalogue services left-join base-table metadata, whose RLS
policy admits only nonhidden records within the web viewer's effective record
tier. Public envelopes therefore remain available when metadata is refused.

`catalogue_page_ids()` resolves timestamp/ID ordering inside an
owner-backed function returning only bounded IDs. It applies current record,
source and field gates before limiting separate non-NULL/NULL seek branches;
only the bounded branch results are merged. `catalogue_scan_ceiling()` supplies
the initial ID ceiling. Web has explicit EXECUTE on these two functions;
scheduler and backup do not. Exact function definitions and privileges are
checked with the other runtime contracts. Page and exact-count predicates use
only the selected audience projection. Page masks retain their independent
language bit; query parameters do not depend on session search settings.
Common terms and filters may examine many candidates. Bounded output does not
establish production performance.

`dataset_admin_catalogue` is a separate owner-backed security-barrier view.
It includes hidden identities but exposes only local ID, source, UUID, stored
tier and canonical persisted record tier. Administrator routes guard read access;
mutation services recheck authority and audit changes. This
identity/state projection grants no metadata permission and never raises the
request's viewer tier.
Administrator read services left-join the existing `catalogue_discovery` view
to add only its approved public title for nonhidden rows. Hidden rows remain
identity/state controls without a title, and protected metadata is not selected.
Their exact source/UUID lookup does not search metadata.

The web SELECT policy requires the exact web database identity. Unset, empty
and invalid viewer settings resolve to `public`; only `public`, `registered`
and `vetted` select their canonical rank. A separate scheduler policy preserves
its catalogue ingestion operations. Policies target `PUBLIC` with explicit
identity predicates, so installation does not implicitly create runtime roles.
The table owner retains its deliberate development/migration bypass:
`FORCE ROW LEVEL SECURITY` is false. Hardened web and scheduler roles remain
nonowners, `NOBYPASSRLS`, without role memberships.

`get_catalogue_cursor()` sets a trusted viewer tier for each catalogue query
with transaction-local configuration and restores the preceding setting after
successful nested use. Transaction rollback handles failed scopes. Pool reuse
does not carry a prior viewer tier into later queries. Routes resolve the tier
from the authenticated principal; HTTP parameters never select it.

RLS enforces the record/admin floor on whole rows. E2's code/source field minima
remain application SQL/redaction/template rules; arbitrary SQL within an allowed
row is not a field-redaction boundary. The shared web database role can set its
viewer setting, so authenticated application code remains trusted. These checks
do not claim protection from arbitrary SQL execution under that role.

## Migration and recovery

E3 is included directly in the single fresh-install baseline `4f73ae3ff827`;
there is no separate upgrade revision. A database
initialized from an earlier body of that baseline requires operator
recreation/rebuild: `upgrade head` sees its revision as current and does not
reapply changed baseline SQL, and stamping cannot retrofit it. The operator
owns any database reset and retained-data import plan; application/updater tools
do not perform it. For a fresh database, the manual migration unit applies the
baseline and matching runtime grants before either runtime starts. The backup
pin is `4f73ae3ff827`; the reviewed baseline reset includes quarantine progress
directly. Complete schema/view/policy checks are required in addition to the
revision label. See the [deployment procedure](../configuration/deployment.md).

The backup role remains read-only `BYPASSRLS`, without role memberships and with
SELECT on every managed table. Preflight verifies that authority before dumping.
`pg_dump` keeps its default `row_security=off`, refusing a dump that would be
silently filtered. Restore into an isolated database as its owner/recovery
identity, reapply the reviewed grants, and verify complete data through the
backup identity as well as the web/scheduler boundary. Backup needs no DDL/DML
grant. Disposable automated role/restore cases do not establish production
custody, deployed peer mappings or representative encrypted recovery. The E4
operator checklist retains those separate deployment/Source B acceptance records.

## WP E implementation acceptance record

The original workplan has four implementation criteria. Its isolated-restore
criterion is exercised with actual restricted roles and synthetic records;
it does not require a production host or private feed. E5 records that boundary
without marking the retained deployment checklist complete.

| Original criterion | Implementation evidence |
|---|---|
| Startup rejects an incomplete field matrix or nonpublic public-search fields | Total immutable matrix, startup validation and public discovery/search subset guard; unit nodes below |
| Every tier/field releases only permitted detail/search/facet values | All-tier Dataset projections, rendered pages, independently gated SQL matching/filter/facet/count cases and retained source/admin floors |
| Raw web RLS defaults to public; scheduler and complete backup recovery retain their authority; policy contracts are pinned | Actual web/scheduler/backup login cases, exact runtime SQL/schema policy inventory and actual-role encrypted isolated restore |
| Access-control/Sensitive Source docs describe the policy and WP L's matrix lists the same fields | These linked contracts plus the catalogue classification matrix and its public-contract drift test |

The executable references for those four rows are:

1. `src/tests/unit/test_field_visibility.py::test_startup_rejects_missing_matrix_entries`
   and `src/tests/unit/test_field_visibility.py::test_startup_and_field_helpers_refuse_nonpublic_discovery_minima`.
2. `src/tests/integration/test_field_visibility_db.py::test_mixed_source_minima_release_all_fields_and_render_partial_metadata`,
   `src/tests/integration/test_field_visibility_db.py::test_source_policy_gates_each_search_field_and_the_empty_page_count`
   and `src/tests/integration/test_field_visibility_db.py::test_language_and_keyword_policies_independently_gate_filters_and_facets`.
3. `src/tests/integration/test_deployed_preflight_db.py::test_web_role_raw_reads_apply_the_current_tier_and_durable_restrictions`,
   `src/tests/integration/test_deployed_preflight_db.py::test_scheduler_hidden_dml_and_actual_backup_role_dump_restore_preserve_all_rows`,
   `src/tests/integration/test_deployed_preflight_db.py::test_runtime_preflight_with_actual_deployed_role_login_defaults`,
   `src/tests/integration/test_deployed_preflight_db.py::test_owner_views_have_exact_safe_projections_and_unknown_roles_cannot_bypass_rls`,
   `src/tests/unit/test_schema_contract_rls.py::test_exact_policy_inventory_rejects_privilege_broadening`
   and `src/tests/integration/test_deployed_preflight_db.py::test_actual_backup_role_encrypted_restore_reestablishes_catalogue_boundaries`.
   The owner-view actual-login case executes `deploy/verify-runtime-database-access.sql`;
   `db_schema_contract.py` pins the row policies and narrow views.
4. `src/tests/unit/test_data_classification_docs.py::test_catalogue_classification_table_matches_the_public_field_contract`,
   the [access-control contract](access-control.md),
   [Sensitive Source Contract](source-b-ingestion-contract.md) and
   [catalogue classification matrix](../compliance/data-classification.md).

Record the exact reviewed commit, complete serial/randomized CI and measured
coverage, strict documentation/reference scans, and synthetic partial-detail
interface evidence. Keep host identity, custody and representative restore
records in the [operator checklist](../runbooks/visibility-recovery-acceptance.md).

WP L's generic templates are documented in the
[processing register](../compliance/processing-register.md). Completed asset
inventories, institutional approval, source-owner approval, real-feed acceptance
and registration/federation activation are not closed by this WP E record.
The [visibility/recovery runbook](../runbooks/visibility-recovery-acceptance.md)
keeps their relevant operator evidence distinct. Strict-build results, final
main CI and earlier E2 screenshot references must be recorded from the reviewed
checkout; local targeted results or an unchanged warning comparison do not
establish those final passes.

## Verification

E1–E4 implementation is accepted, including the actual-role encrypted synthetic
recovery witness and
the [visibility/recovery acceptance record](../runbooks/visibility-recovery-acceptance.md).
Its host peer, custody and representative-restore evidence remains open; the
automated case does not replace those records.

With disposable PostgreSQL/Redis services available, the new boundary cases are:

```bash
uv run pytest -q \
  src/tests/integration/test_catalogue_context_db.py \
  src/tests/unit/test_schema_contract_rls.py \
  src/tests/integration/test_deployed_preflight_db.py \
  src/tests/integration/test_catalogue_rls_migration_db.py
```

Run the field-policy unit and PostgreSQL/HTTP acceptance cases, followed by the
existing sensitive-source catalogue, administrator restriction and resource
acceptance suites against disposable PostgreSQL/Redis services. E3 also requires
real restricted-role RLS checks and isolated restore coverage on disposable
roles/databases; never run destructive drills against an existing user database.
Retain complete serial and randomized parallel CI, the measured collection floor,
92.5% overall branch coverage and 90% security coverage. E2 field-policy changes
alone need no migration; E3 requires the current fresh-install baseline and
matching grants above, including operator recreation of an older initialized
baseline where applicable.

See [Access control and visibility](access-control.md), the
[Sensitive Source Contract](source-b-ingestion-contract.md) and
[resource-access acceptance](resource-access.md).

The web lifespan publishes one immutable catalogue policy. Request handlers read
that snapshot without rebuilding or assigning application state. Embeddings
that intentionally replace sources or code visibility must call
`app.catalogue_runtime.replace_catalogue_sources(app, sources)` at startup or
between requests; direct state assignment and cross-thread replacement are not
supported. A rejected replacement leaves the previously published policy intact.
If a catalogue statistics cache already exists, replacement also updates its
source scope and invalidates cached rebuild freshness. In-flight reads may
finish with their captured old scope, but cannot cache that result for the new
selection. This operation does not reload scheduler jobs or deployment settings;
restart remains the normal whole-process configuration boundary.
Search bookmark encryption retains only the current derived key in a one-entry
cache keyed by `SECRET_KEY`; an explicit key replacement evicts the old key and
invalidates its bookmarks. Restart remains the normal configuration boundary.
