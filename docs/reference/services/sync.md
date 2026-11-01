# Sync & OAI Client

All registered adapters use the same generic ingestion engine.
Web and scheduler require an explicit `SOURCES_CONFIG_FILE`; 
missing or empty selection aborts runtime startup. File, parsing, 
construction and startup-policy failures propagate without fallback. 
Each process retains the loader's ordered source tuple until restart.

Settings construction validates the selector's syntax without opening the
source file. It may retain `None` for imports, migrations and offline inspection;
that value does not permit either runtime process to start.

Registered OAI-PMH/CMDI and fixture adapters use the same generic ingestion
engine. `app.services.run_sync()` and `app.services.run_full_rebuild()` require
a keyword-only `configured_source`. That object supplies the adapter, write
policy, persistent identity and write timeout throughout the run. The web
process neither harvests records nor provisions source-status rows.

See the [ingestion architecture](../../architecture/sync.md) for transaction,
recovery and scheduler behavior, and the
[settings reference](../../configuration/settings.md) for configuration migration.

## `app.services.ingestion`

::: app.services.ingestion

## Runtime source selection

The scheduler uses `app.services.load_runtime_sources()` to resolve feed
credentials and construct adapters. Web startup uses
`app.services.load_runtime_catalogue_sources()` for nonsecret metadata and
rejects selected feed credential variables in its environment. Neither falls
back to fixtures; `.env.example` explicitly selects the offline fixture file.

::: app.services.runtime_sources

## `app.sources.oai_client`

The OAI adapter delegates to the existing bounded, process-isolated transport.
Its configured `max_pages` is passed explicitly to the worker. Direct transport
calls that omit that argument retain the transport's 500-page default.

::: app.sources.oai_client

## Source adapters and construction

`ConfiguredSource` owns configuration, adapter, display metadata and schedule.
The narrower `SourceAdapter` protocol exposes identity, write policy,
`config_fingerprint()` and blocking `fetch(*, since=...)`.

`registered_adapter_names()` returns the registered adapter identifiers in
declaration order. The shared conformance suite discovers an adapter-owned
provider under `src/tests/sources/cases/` for every identifier. Missing
providers fail the suite.

`app.sources.configuration.configure_sources_from_toml()` parses a document;
`load_sources_file()` reads UTF-8. Both require explicit `credentials`
for selected feeds, construct without fetching, and omit runtime path and
environment-policy checks.

::: app.sources

::: app.sources.configuration

::: app.sources.base

::: app.sources.oai_pmh_cmdi

::: app.sources.fixture

::: app.sources.static_json

## Startup source files

`app.sources.load_sources_for_startup(path, *, environment, allow_fixture=False, environ=None)`
validates the selected UTF-8 file and source policies, resolves feed credentials
only from `environ` (`None` means empty), then constructs the ordered adapters.
It neither fetches nor reads global settings. The catalogue-only loader returns
nonsecret metadata without resolving credentials or constructing fetch adapters.

Development accepts an ordinary readable relative or absolute path. Staging
and production require a direct absolute POSIX path without `..` or symlink
components. Every opened directory and the regular file must be root-owned
and must not be group- or other-writable. The caller needs directory read/search
access and file read access.

Validation and reading use the same opened descriptors. The final open is
nonblocking, so a FIFO cannot hang startup; nonregular files are rejected.
Descriptors close on success and failure. Unsupported hardened-platform
operations fail rather than falling back to weaker checks.

OAI endpoints must be credential-free; hardened modes additionally require
HTTPS and reject placeholder hosts. JSON feeds require HTTPS in every mode,
strict endpoints and explicit bearer/signing credentials; hardened modes reject
placeholder hosts. Production `fixture` and `static_json` selections require
`ALLOW_FIXTURE_SOURCE=true`. See [feed configuration](../../sources/json-feed-configuration.md).

The direct-path policy applies to source configuration. Application release
switching through its existing symlink remains a separate deployment contract.

::: app.sources.startup

::: app.sources.startup_file

## Record and staging contracts

`HarvestResult` contains matching records, deleted identities, definite
nonmatching identities, uncertain identities and an aware source cursor.
Construction alone does not validate it; validation and codec boundaries check
record schemas and disjoint normalized identities.

The shared bounded encoder and both stored-harvest encoders accept a `max_bytes`
keyword, defaulting to 16 MiB. Durable staging uses this existing default;
there is no runtime source-TOML setting for a per-source staging budget.
The limit covers the encoded inner harvest, excluding stored-envelope metadata.
The separate `max_bytes` fields of the bundled `fixture` and `static_json`
adapters limit their input snapshots and do not configure durable staging.

This serialized-result bound is not a total memory or database-envelope cap.
Ordinary encoding materializes JSON before checking its byte size; stored
decoding does not provide a separate predecode payload-size limit.

Worker decoding retains only the validated harvest data. Durable staging
validates and freshly encodes the current mutable result; later record,
classification and timestamp changes therefore enter the staged payload.
Invalid fingerprints and budgets are rejected before harvest validation.
Exceeding a valid byte budget raises `HarvestResultSizeError`; invalid budgets
raise `ValueError`. Record/schema and serialization errors propagate.

Stored envelopes bind recovery data to its source fingerprint and format/parser
versions. Operational page limits, schedules and write timeouts do not change
the interpretation fingerprint. Staged replay and committed cursor reuse
remain subject to the engine's source-binding checks.

::: app.services.harvest

::: app.services.parsed_record

::: app.services.stored_harvest
