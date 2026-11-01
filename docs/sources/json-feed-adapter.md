# Authenticated JSON-feed adapter

`json_feed` is a registered Feed Contract v1 adapter with isolated complete
fetching. See [persistence](json-feed-persistence.md),
[catalogue behavior](json-feed-catalogue.md) and
[recovery acceptance](json-feed-acceptance.md) for its downstream boundaries.

## Construct with explicit credentials

Use the owning-package API. Configuration and secret preparation remain separate
from construction; no HTTP request or ambient environment read occurs here:

```python
from app.sources import (
    JsonFeedConfig,
    configure_sources,
    prepare_json_feed_startup,
)

# descriptions and provided_environment come from the configuration example.
feeds = tuple(item for item in descriptions if isinstance(item, JsonFeedConfig))
credentials = prepare_json_feed_startup(
    feeds, environment="dev", environ=provided_environment
)
sources = configure_sources(descriptions, credentials=credentials)
```

`configure_sources_from_toml()` and `load_sources_file()` likewise accept explicit
prepared `credentials`. Scheduler callers use `load_sources_for_startup()` with
`environment` and an explicit `environ` mapping, retaining the hardened file and
endpoint policy. Omitting `environ` means an empty mapping, not process lookup.
`app.services.load_runtime_sources()` deliberately supplies `os.environ`.
All selected feed references, roles and secret material are validated before
any adapter factory runs. The adapter captures frozen configuration/credential
snapshots; changing the caller's mapping does not update a running process.

The web uses `load_catalogue_sources_for_startup()` through
`app.services.load_runtime_catalogue_sources()`. Its `CatalogueSource` snapshots
contain validated configuration and pure policy, without an adapter or fetch
method. The web needs no feed secret and rejects selected feed credential
variables in its environment. Only the scheduler receives their values. Both
loaders apply the same nonsecret file and endpoint policy and compile the same
catalogue fingerprint from identical descriptions. Web publication verifies the
durable search-policy binding before making the snapshot available to requests.

## One complete-fetch worker

`JsonFeedAdapter.fetch(since=...)` returns a validated `HarvestResult`. The
source-owned `fetch_json_feed_isolated()` starts one spawned worker with one
absolute monotonic deadline. That child performs direct authenticated HTTPS,
all page requests, strict JSON/page-chain checks, native record validation and
bounded result serialization. It does not nest the B3 per-page workers.

All seven configured budgets apply to the complete attempt. The shared process
boundary handles bounded byte frames, partial IPC, termination, kill escalation
and reaping, with bounded cleanup. Worker failures carry fixed allowlisted
codes rather than incoming exception text or body fragments.

The parent reconstructs the already validated, size-bounded candidate into a
`HarvestResult` with checks against the same absolute deadline. Parent
reconstruction is bounded and checked; it is not separately force-terminable.
The killable boundary covers source HTTP, JSON parsing, metadata validation and
serialization in the child. Failed or incomplete attempts return no harvest.

## Interpretation binding and cursor protection

The same adapter instance supplies fingerprint and fetch. Its canonical binding
covers source identity, endpoint, adapter identifier, feed contract and
interpretation revision 2, mandatory record tiers, source floor, project-title
character cap, reviewed
public/access mappings and the
`credential_env` and `signing_key_env` reference names. Display, schedules,
all seven operational budgets and resolved secret values are excluded.

`json_feed_protocol.py` owns the immutable wire-version and material-access-label
mapping used by page/record validation, access classification and fingerprint
serialization. The published JSON schema is checked against those shared facts.
Other interpretation changes still require deliberate revision review.

Rotating values under unchanged references needs a fresh snapshot/restart,
without a rebuild. Changing either reference name changes the binding and
requires authoritative rebuild, as do other interpretation changes.

Stored harvests use shared parser contract 4. Pending payloads with older parser
contracts are refetched; a changed source binding requires full reharvest through
the existing recovery path. No database schema change is required.

For `JsonFeedConfig` sources, ingestion rejects a cutoff older than the committed
cursor before staging new input, before pending replay writes and before full
apply can withdraw or infer-delete anything, including the zero-match path.
Equality is allowed. The engine still supplies its two-day overlap; the adapter
only widens to whole seconds and does not subtract another overlap.

The shared engine applies stored/admin tier floors and durable hiding. Adapter
construction, fingerprints and successful fetches do not prove source-specific
persistence, correction/withdrawal audits, redaction, public-disclosure approval
or representative restore. See the [remaining evidence map](feed-contract-v1.md#synthetic-examples-and-executable-evidence)
before enabling a real sensitive source.
