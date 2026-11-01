# JSON-feed catalogue acceptance

**Status: B8 signed-native catalogue acceptance is green.** These service and HTTP
cases extend the accepted [B7 persistence/audit boundary](json-feed-persistence.md).
They ingest synthetic signed feed bytes through the real adapter and engine;
they do not require the private upstream to be available.

## Exactly seven public values

Below a record's effective metadata tier, only `PUBLIC_DISCOVERY_FIELDS` retain
values. Other `Dataset` scalars become `None` and lists become empty before
results reach templates; private values must also be absent from HTML source.

| Field | Public value |
|---|---|
| `id` | Application row identifier, including existence and enumerability |
| `uuid` | Public, nonsecret dataset identifier |
| `title` | Curated public discovery title |
| `access_level` | Controlled label for upstream material access |
| `version` | Reviewed public release label, or null |
| `source` | Configured source identity |
| `visibility_tier` | Effective stored tier with the administrator floor applied |

Tiers order as `public < registered < vetted`. Each protected field requires
the strictest effective record, code and source minimum. Meeting the record
tier alone does not guarantee full metadata. Unselected retained sources
require vetted access for protected fields.

Administrator authority does not raise the metadata tier. A public-tier
administrator receives the same restricted release as another public viewer.
The cases compare the complete allowed `Dataset` values, not just one marker.

## Services and rendered pages

Signed native fixtures exercise public/registered/vetted records through these
surfaces, including guest and public-tier administrator release cases:

| Surface | Acceptance boundary |
|---|---|
| Detail | Exact service release and HTTP rendering; absent/hidden records return 404 |
| Search | Public title/access text remains discoverable; each protected field requires its record/code/source tier |
| Filters and facets | Keyword/language values are tier-gated; controlled access-level filtering remains public |
| Counts | Live public dataset totals retain discoverable, nonhidden records; home does not calculate language/keyword totals |
| Recent records and home | Exact released records in services, template context and HTML |
| Pagination | Correct numbered service/HTTP pages, empty service-page counts and out-of-range HTTP redirects; hiding precedes pagination |

Private markers cover descriptions, projects, authors and metadata labels.
Below-tier values cannot influence private-field search results or appear in
filter suggestions, counters, detail or HTML. Public discovery titles and access
labels are deliberately searchable at every tier. Facet suggestions retain their
existing bounded-sample rules; B8 does not turn them into an exhaustive vocabulary.

## Corrections, withdrawals and local administration

Incremental and full-rebuild cases replace signed native metadata, then check
normalized columns, raw JSONB, derived search values and catalogue responses.
Old corrected values must disappear from their former search/filter surfaces.
Withdrawals remove the record from detail/search/recent and remove its
contribution to counts and facets.

Real administrator hide/restore actions exclude or restore the selected identity
across catalogue surfaces. Another source sharing its UUID remains untouched.
Two already-created catalogue-stats caches and the warm home-page cache must
report live post-withdrawal totals without explicit invalidation or restart.
Durable floors and hide state retain the semantics accepted in B7.

## Evidence and remaining acceptance

The catalogue cases use ingested records, not fabricated `Dataset` objects or
prepared harvests. HTTP delivery, time and process seams remain fixture-controlled;
real feed authentication, parsing, ingestion and catalogue SQL still execute.
Separate B6 transport/process evidence covers actual TLS and isolation.
Accept B8 only after these cases pass with `REQUIRE_DB=1` and `REQUIRE_REDIS=1`;
collection does not replace execution.

Structural and behavioral tests cannot approve human-language disclosure. The
source owner must approve every public value, the combination of values, record
existence, ordering and counts for unrestricted publication. A vetted tier cannot
make an unsafe public title or identifier confidential.

B8 does not close WP B. [B9 evidence and recovery checks](json-feed-acceptance.md)
retain the requirement map and define the execution/restore records. Real-source
activation still needs source-owner sign-off and a representative encrypted
isolated restore; neither is established by synthetic catalogue cases. See the
[Sensitive Source Contract](../architecture/source-b-ingestion-contract.md)
and [Feed Contract v1](feed-contract-v1.md).