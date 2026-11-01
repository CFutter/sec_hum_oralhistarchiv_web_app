# Datasets Service

`datasets` provides parsed dataset records, search, statistics, and tier redaction.

`Dataset` requires an explicit keyword-only `source` matching
`[a-z0-9_]{1,32}`. Construction rejects invalid identities without normalization.
Row decoding requires the source column and never substitutes a default
identity. Tier redaction retains the stored source unchanged.

`build_catalogue_policy()` compiles immutable source/field rules, static SQL
cases and tier-specific masks. Reuse its `CataloguePolicy` result through the
required `configured_sources=` argument for repeated calls. Raw source
sequences remain accepted and are compiled at the outer service boundary.
Web lifespan prepares one policy and page routes share it with templates.
Record and administrator visibility floors are evaluated live.

A valid stored identity remains readable when its source is no longer selected
for ingestion. Identity validation does not register or activate a source.

See [Access Control](../../architecture/access-control.md) for disclosure rules and [Data Model](../../architecture/data-model.md) for schema contracts.

`get_global_catalogue_stats()` and `get_last_full_rebuild_date()` require explicit
`source_names`. They report the oldest selected-source rebuild, or null if any
selected source is missing or has never rebuilt. The combined statistics query
keeps the nonhidden dataset count and freshness in one SQL statement snapshot.

::: app.services.datasets

Suggestions sample 200 recent nonhidden rows, inspect at most 100 keywords/languages per row, and return up to 50 values per category. Keywords/languages are tier-gated; access levels remain public. Keywords require two occurrences in the sampled arrays. Exact filters query the full catalogue.

`get_facets(..., disclosures=records)` optionally fills a caller-owned list of
`FacetDisclosure` identities and protected field names contributing to the
returned options. Options and contributors come from one SQL snapshot. The
search route uses the current viewer tier and audits those contributors after
successful rendering. Unlisted options do not generate disclosure claims, and
neither option values nor search/filter text enter the events.

All catalogue queries apply the stricter stored/administrator tier and exclude
hidden identities before counts, ordering, pagination and facet sampling.
The cache wrapper serves a live count with independently cached freshness.

## Dataset administrator mutations

The public service boundary exports the context, state, change, rejection and
action types together with `change_dataset_admin_state()`. The service owns its
transaction and successful-change audit; callers supply current runtime sources
and server-resolved request correlation. The keyword-only `configured_sources`
argument is required. Pass `()` explicitly for intentional hide/restore actions
on retained sources; raising a tier still requires its selected policy.
The administrator routes delegate
to this service without duplicating its audit.

::: app.services.dataset_admin

## Dataset administrator control reads

`DatasetAdminRecord`, `get_admin_dataset_by_id()` and `search_admin_datasets()`
are exported through `app.services`. Callers must enforce administrator access.
Both read helpers require keyword-only `configured_sources`; an omitted snapshot
raises `TypeError` before database access. Explicit `()` returns retained identities
with source-dependent raise choices unavailable, rather than implying a runtime
source selection. The result contains identity, restriction state and permitted
raise choices, including hidden/unselected records. `public_title` comes only
from the existing `catalogue_discovery` view and is unavailable for hidden rows;
no protected metadata is read. UUID and source filters are exact, combine with
AND and never match titles or other metadata. Pages use bounded descending-ID
keysets and at most `page_size + 1` rows, without global counts or growing offsets.
Titles are retrieved in the same query, without a per-row lookup. Catalogue
changes can alter the live results between page requests.

::: app.services.dataset_admin_queries
