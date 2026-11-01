# Sources

The archive collects metadata from configured sources and serves a local
PostgreSQL catalogue. The scheduler imports and reconciles records; catalogue
requests do not contact upstream repositories. Recordings and other linked
materials remain at the originating repository, which controls access to them.

Both the web process and scheduler require an explicit `SOURCES_CONFIG_FILE`.
Each reads and validates the selected file once during startup and retains its
ordered configuration until restart. A missing or empty selection, unreadable
file or invalid configuration stops startup. There is no legacy-source fallback
or mock-seeding switch.

## Available adapters

| Adapter | Input | Intended use |
|---|---|---|
| `fixture` | The bundled `catalogue_v1` JSON dataset | Offline development and synthetic demonstrations |
| `oai_pmh_cmdi` | An OAI-PMH endpoint using the supported CMDI profile | Importing a compatible repository catalogue |
| `static_json` | The bundled `proof_v1` native JSON snapshot | Synthetic adapter extensibility proof; no remote transport |
| `json_feed` | Authenticated HTTPS JSON pages | Feed Contract v1 import with explicit credentials and strict validation |

An OAI-PMH endpoint must provide the supported CMDI profile; an arbitrary
OAI-PMH repository is not automatically compatible. See the
[ingestion architecture](../architecture/sync.md) for parsing, resource limits
and recovery behavior. The `static_json` proof adapter reads packaged synthetic
input and has no remote transport.

The [JSON-feed adapter](json-feed-adapter.md) is the fourth runnable adapter.
It uses [explicit credentials](json-feed-configuration.md), exact-byte response
authentication, strict page/metadata validation and one complete-fetch worker.
Its [v1 contract](feed-contract-v1.md) defines the wire schema;
[persistence](json-feed-persistence.md), catalogue and
[synthetic recovery evidence](json-feed-acceptance.md) cover the accepted
application behavior through B9. The shipped development selection stays on
the offline fixture. Real-source approval and deployed recovery remain separate.

[JSON-feed configuration](json-feed-configuration.md) describes strict pure
descriptions and explicit credential preparation before adapter construction.
[B3 transport](json-feed-transport.md) reads authenticated bounded page bytes;
[B4 page validation](json-feed-pages.md) checks strict JSON, request binding,
page chains and identities; [B5 record validation](json-feed-records.md) checks
native metadata and bounded candidate harvest bytes. The complete-fetch worker
and runnable adapter are implemented through B6.

## Start with the offline fixture

The shipped `.env.example` selects `deploy/environment/sources.dev.toml`. That
file enables only `fixture_demo`, with three neutral synthetic records carrying
public, registered and vetted metadata tiers.

For an existing development checkout, update the active `.env` rather than
assuming that changes to `.env.example` replace it:

```dotenv
SOURCES_CONFIG_FILE="deploy/environment/sources.dev.toml"
ALLOW_FIXTURE_SOURCE=false
```

From the checkout root, use the normal development launcher after configuring
the local database and other application settings:

```bash
ENV_STATE=dev uv run bash dev.sh
```

Actual environment variables override `.env`. Check for an exported selector
when the chosen source differs from the file you edited. Remove retired settings
from active configuration; assigning them a false or empty value still fails
settings validation. The [settings reference](../configuration/settings.md)
lists those keys and their replacements.

Scheduler startup provisions source state. The first incremental attempt for
an unbound source requests an authoritative rebuild through normal recovery;
the scheduler performs it without waiting for the periodic rebuild. The web
process does not populate fixture rows. Refresh the catalogue after ingestion
completes. Previously stored rows are retained, so an existing database may
contain more than the three fixture records.

The fixture uses a fixed upstream cursor of `2020-01-04T00:00:00+00:00`.
Synchronization freshness uses operational timestamps, not the age of that
synthetic upstream date. The fixture's example resource URLs do not provide
real interview recordings.

## Configure sources in TOML

The file uses flat `[[sources]]` entries. Do not add nested `[sources.display]`
or `[sources.schedule]` tables. Unknown fields, unknown adapters, duplicate
source names and an empty source list are rejected.

Both `incremental_interval_seconds` and `rebuild_interval_seconds` require
integers from 1 to 31536000 seconds (maximum 365 days); defaults are 3600 and
86400 respectively. `write_timeout_seconds` accepts 1–3600 seconds and defaults
to 120. Booleans and quoted numeric strings are rejected. These limits apply
to every adapter and are checked before scheduler job construction.

Absence-based deletion during a full rebuild must satisfy both
`rebuild_max_inferred_delete_count` (a nonnegative integer, default 100) and
`rebuild_max_inferred_delete_ratio_percent` (an integer from 0 to 100, default
25). Setting either limit to zero permits no absence-based deletion. Explicit
upstream withdrawals are evaluated separately. These operational budgets do
not change the source interpretation fingerprint.

For a reviewed contraction from three records to two, temporarily add the
following flat fields to the affected source entry:

```toml
rebuild_max_inferred_delete_count = 1
rebuild_max_inferred_delete_ratio_percent = 34
```

Restart the processes using that configuration, run the full rebuild, then
restore the normal limits and restart again. A raised limit applies to later
rebuilds too until restored. This does not override the independent guard that
retains existing data when a full harvest returns no matching records, or the
minimum successful-write threshold.

The following example selects **both** sources. It is a schema example, not
an offline configuration. Replace the OAI endpoint and institution filter with
reviewed values before use. The `example.org` endpoint is a placeholder and is
rejected in staging and production.

```toml
[[sources]]
name = "fixture_demo"
adapter = "fixture"
label = "Synthetic interview examples"
sensitivity_badge = "Synthetic examples"
dataset = "catalogue_v1"
max_visibility = "public"
requires_record_tier = true
incremental_interval_seconds = 3600
rebuild_interval_seconds = 86400
write_timeout_seconds = 120
max_bytes = 65536

[[sources]]
name = "example_archive"
adapter = "oai_pmh_cmdi"
label = "Example archive"
resource_link_label = "Open resource"
landing_link_label = "View source record"
endpoint = "https://repository.example.org/oai"
institution_filter = "Example University"
max_visibility = "public"
requires_record_tier = false
incremental_interval_seconds = 3600
rebuild_interval_seconds = 86400
write_timeout_seconds = 120
max_pages = 500
```

The repository's `deploy/environment/sources.example.toml` is another mixed
schema example. Selecting it activates every entry, including its OAI source.
Continue using `sources.dev.toml` when only the offline fixture is wanted.

### Common fields

| Field | Default | Meaning |
|---|---|---|
| `name` | Required | Persistent source identity: 1–32 lowercase ASCII letters, digits or underscores; unique within the selected file |
| `adapter` | Required | A registered adapter identifier |
| `label` | Required | Nonblank, single-line source label, shown on About and used for configured source presentation |
| `resource_link_label` | `Open resource` | Action text for resource links |
| `landing_link_label` | `View source record` | Action text for source-record links |
| `sensitivity_badge` | Omitted | Optional source description displayed on About; omission displays “Not specified” |
| `max_visibility` | `vetted` | The most permissive permitted tier for full metadata from this source |
| `requires_record_tier` | Adapter-specific | Defaults to `true` for `fixture` and `static_json`; OAI/CMDI permits only `false`; `json_feed` requires `true` |
| `log_resource_access` | Resolved `requires_record_tier` | Strict boolean; `true` uses internal tier-checked audited resource/landing links; `false` uses safe direct links |
| `incremental_interval_seconds` | `3600` | Positive interval between incremental jobs |
| `rebuild_interval_seconds` | `86400` | Positive interval between periodic full rebuilds |
| `write_timeout_seconds` | `120` | Asynchronous timeout for each ingestion write phase, from 1 to 3600 seconds; separate from fetching and lock waiting |
| `rebuild_max_inferred_delete_count` | `100` | Nonnegative maximum number of records a full rebuild may delete by absence |
| `rebuild_max_inferred_delete_ratio_percent` | `25` | Maximum percentage of remaining source rows a full rebuild may delete by absence, from 0 to 100 |

Labels are display text, escaped by templates. A sensitivity description is
not inferred from a tier and does not change authorization. Choose text that
is suitable for public display.

### Adapter-specific fields

| Adapter | Field | Default and requirements |
|---|---|---|
| `fixture` | `dataset` | `catalogue_v1`; only this bundled dataset is accepted |
| `fixture` | `max_bytes` | `65536`; positive integer, at most 1 MiB, bounding the bundled input snapshot |
| `oai_pmh_cmdi` | `endpoint` | Required absolute HTTP(S) URL without embedded credentials; staging and production require HTTPS and reject placeholder hosts |
| `oai_pmh_cmdi` | `institution_filter` | Required nonblank, case-insensitive substring used to match institution metadata; the configured text is preserved |
| `oai_pmh_cmdi` | `max_pages` | `500`; positive integer cap on pages per harvest attempt |
| `static_json` | `dataset` | `proof_v1`; only this bundled native snapshot is accepted |
| `static_json` | `max_bytes` | `65536`; positive integer up to 1 MiB for the input snapshot |
| `json_feed` | Endpoint, credential references and seven budgets | See [JSON-feed configuration](json-feed-configuration.md); HTTPS is mandatory in every environment |

The bundled `fixture` and `static_json` adapters do not accept an endpoint or
arbitrary filesystem path. Their input byte limits do not configure the
separate durable-staging limit. JSON feeds use separate bearer/signing references
and prepared secret snapshots. Runtime source loading explicitly supplies the
process environment; construction helpers require supplied snapshots and never
look up ambient secrets. Do not put credentials in URLs.

## Deploy a selected file

Development permits a readable relative or absolute path. Staging and production
require a direct absolute POSIX path without `..` or symlink components. The
source file and every directory opened along that path must be root-owned and
must not be group- or other-writable. The service account also needs directory
read/search access and file read access.

The reference deployment keeps the nonsecret source file separately from the
private service environment files:

| Path | Ownership | Mode |
|---|---|---|
| `/etc/oralhistarchiv-sources` | `root:root` | `0755` |
| `/etc/oralhistarchiv-sources/sources.toml` | `root:root` | `0644` |

Select the same file for both runtime processes through their shared environment:

```dotenv
SOURCES_CONFIG_FILE="/etc/oralhistarchiv-sources/sources.toml"
ALLOW_FIXTURE_SOURCE=false
```

Production refuses selected `fixture` or `static_json` sources unless
`ALLOW_FIXTURE_SOURCE=true` is explicitly configured. That permission alone
does not select a source; the file still determines the complete source set.
Staging permits both bundled synthetic adapters without this production
permission, while retaining the hardened file and endpoint requirements.

Stop both runtime services while replacing source configuration, then start
them together with the same revision. A running process retains its old
snapshot. Changing a file underneath running processes does not update their
configuration. Follow the [deployment procedure](../configuration/deployment.md)
for service accounts, installation and restart sequencing.

## Metadata tiers and public discovery

Tiers order as `public < registered < vetted`. Each protected field requires
the strictest record, code and source minimum; full metadata requires all fields.
The source tier is the stricter of its valid explicit record tier and
`max_visibility`; an omitted tier retains the last accepted source restriction.
Administrator floors apply independently.

For example, a source restriction of `registered` raises a public record to
registered while preserving a vetted record as vetted. The development fixture
uses `max_visibility="public"` so its three explicit record tiers remain
distinct. With `requires_record_tier=false`, a missing record tier uses the
source restriction. With `true`, a missing tier is rejected before persistence.
The current OAI/CMDI parser supplies no application record tier and requires
`requires_record_tier=false`. An explicit `true` is rejected during source
configuration, before any harvest. The adapter also rejects a mandatory-tier
policy during direct construction. Use `max_visibility` for an OAI source's
metadata floor; native per-record tier requirements need a capable adapter.
Resource auditing remains independently configurable with
`log_resource_access=true`.

These tiers do not conceal the existence of catalogue records. Every dataset
has a public discovery envelope, including when full metadata requires vetted
access:

| Public field | Disclosure |
|---|---|
| `id` | The local row identifier, record existence and enumerability |
| `uuid` | A stable public dataset identifier; never a credential, participant/case identifier or private lookup key |
| `title` | The public discovery title; deliberately displayed and searchable |
| `access_level` | A public label describing access to the underlying material; also searchable and filterable |
| `version` | A public release/version label |
| `source` | The application-controlled, configured source name |
| `visibility_tier` | The record's public metadata-tier classification |

The source owner must approve these values, record existence and their
combination for unrestricted publication. A vetted tier cannot make an unsafe
title or identifier confidential. Structural checks and adapter conformance
tests do not establish that human-language content is safe to publish.

`access_level` describes upstream resource access and does not grant download
permission. The originating repository enforces access to recordings. See
[Access Control & Visibility](../architecture/access-control.md) for redaction,
search behavior and local classification procedures.

## Resource-access classification

`SourcePolicy.classify_access` assigns the stored/displayed `access_level`.
It does not set a metadata tier, authorize an application download or establish
that an upstream resource is available. The four adapters retain separate
contracts:

| Adapter | Exact label mapped to `public` | Restricted/default or invalid input |
|---|---|---|
| `oai_pmh_cmdi` | `Public access`, `License CC BY`, `CC BY 4.0` | `Restricted access` maps to `restricted`; `None` and every other string also map to `restricted`; nontext values raise `TypeError` without including the raw value |
| `fixture` | `Public access` | Every other label and `None` map to `restricted` |
| `static_json` | `Public access` | Every other label and `None` map to `restricted` |
| `json_feed` | `Public access` | `Restricted access` maps to `restricted`; every other string raises `ValueError`; `None` or nontext input raises `TypeError` |

These are exact comparisons: no case folding, whitespace trimming, Unicode
normalization or prefix matching is applied. For example, `public access`,
` Public access`, `Public access ` and `Public access extra` are not the public
label. OAI/CMDI classifies all four as `restricted`; the JSON feed rejects them
as outside its reviewed wire vocabulary. Missing OAI/CMDI license metadata
arrives as `None` and is restricted. Existing fixture, static-JSON and JSON-feed
semantics are unchanged.

The two retained OAI/CMDI CC spellings come from existing application tests,
including the record-pipeline fixture and incremental-ingestion fixture. They
are compatibility inputs, not provider documentation, license interpretation,
source-owner approval or governance evidence. No additional CC, open-access or
license vocabulary is inferred. Review an exact new label before extending the
mapping. See the [K1–K3 acceptance record](../runbooks/search-pagination-acceptance.md)
for the accepted application scope and remaining evidence/deployment work.

## Understand source status

About lists selected sources in configuration order using configured labels,
optional sensitivity descriptions and recorded synchronization history:

| Badge | Meaning |
|---|---|
| Active | Both successful harvest and rebuild timestamps are present and no older than twice their respective configured intervals, with neither error channel set |
| Awaiting sync | Clean synchronization history is missing or incomplete |
| Needs attention | A synchronization error is recorded, or any available successful timestamp is older than twice its own configured interval |

Exactly twice an interval is still fresh. These badges are not live upstream
probes. They do not expose endpoint URLs or diagnostic error messages.
Authorized [health diagnostics](../reference/routes/health.md) provide more
detail. Home freshness is the oldest successful rebuild among selected sources;
it remains unknown if a selected source lacks a status row or successful rebuild.

## Change or remove a configuration entry

Keep a source's name stable when retaining its state. Names are exact canonical
identities, not display labels: no default or normalization silently assigns
dataset ownership. Records are identified within their source, so changing a
source name does not rename its stored records.

Changing endpoint, institution filter or visibility policy changes an OAI
source's interpretation fingerprint. The OAI/CMDI fingerprint also binds the
exact resource-access label mapping, its restricted fallback and the CMDI
parser contract version. Version 2 selects the first validated dataset title
rather than an unrelated earlier title elsewhere in the XML. It replaces the
earlier unversioned parser binding, so an existing OAI source requires a normal
authoritative source rebuild before incremental work can continue under the
new interpretation. Normal scheduler recovery requests that rebuild; applying
a tests/docs updater does not perform an operator action. Do not rewrite the
stored binding or cursor to bypass it. Served rows retain their stored labels
until the normal rebuild writes them. The rebuild reparses unchanged upstream
records; old staged titles are not replayed under the new binding. No schema
change, database reset or data migration is required. The bundled `fixture`
and `static_json` fingerprints
also bind their dataset, payload bytes and adapter contract version.

JSON-feed fingerprints bind source identity, endpoint, reviewed contract/mappings,
visibility policy, `max_project_title_chars` and credential-reference names. Resolved secret values, display,
schedules and all seven feed budgets are excluded. Same-reference value rotation
needs restart, not rebuild; changing a reference requires authoritative rebuild.

Changing policy does not rewrite stored tiers. After the owner catalogue-policy
transition and restart, tighter source/field minima already constrain reads.
Successful writes
apply explicit valid upstream tier corrections, including less restrictive
corrections, subject to the configured source floor. An omitted tier retains its
previous restriction. Administrator restrictions continue to apply. Do not overwrite
stored cursors or fingerprints to bypass recovery.

Removing a source entry stops its scheduled ingestion after restart and excludes
its state from selected-source freshness calculations. Its stored catalogue rows
remain counted and discoverable unless hidden or quarantined; protected fields
require vetted access when the source is unselected.
Retained records use generic source-link labels when their source is no longer
configured. Deselecting a source is not a withdrawal mechanism.

For urgent removal, use the
[emergency withdrawal runbook](../runbooks/emergency-dataset-withdrawal.md).
Raising a tier still leaves the public discovery envelope visible.

Adapter implementation, shared conformance and operational acceptance are
separate requirements; implementing an authenticated sensitive source also
requires its own reviewed ingestion contract.
