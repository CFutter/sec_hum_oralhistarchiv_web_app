# Sync & OAI Client

The two modules that fill the local PostgreSQL mirror: `sync` orchestrates the incremental syncs and full rebuilds (including access-level classification, the `SourcePolicy`-clamped visibility tier, per-record error resilience, and the `sync_status` bookkeeping), and `oai_client` speaks the OAI-PMH protocol — resumption tokens, the XXE-hardened per-call parser, CMDI parsing, and the institution filter.

For the end-to-end narrative — why a local cache exists, how the four scheduler jobs and the `_sync_mutex` interact, the harvest-watermark semantics, tombstones, the DOI-collision case, and the savepoint-based full rebuild — see **[Architecture → OAI-PMH Sync Pipeline](../../architecture/sync.md)**. This page is the code-level reference.

## `app.services.sync`

::: app.services.sync

## `app.services.oai_client`

::: app.services.oai_client
