# Datasets Service

The dataset service layer is the only thing that route handlers should call when they need dataset data. It owns the `Dataset` and `Author` dataclasses, the SQL queries, the parsing of database rows into Python objects, the per-tier visibility filter, and the schema invariant check.

For the visibility model and the search semantics — the two tier-gated search columns, the tier-gated keyword/language filters, ILIKE escaping, and tier-scoped facets — see [Architecture → Access Control & Visibility](../../architecture/access-control.md). For the underlying columns, triggers, and trigram indexes, see [Architecture → Data Model](../../architecture/data-model.md).

::: app.services.datasets
