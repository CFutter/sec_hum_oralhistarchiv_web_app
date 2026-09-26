# Datasets Service

`datasets` provides parsed dataset records, search, statistics, and tier redaction.

See [Access Control](../../architecture/access-control.md) for disclosure rules and [Data Model](../../architecture/data-model.md) for schema contracts.

::: app.services.datasets

Suggestions sample 200 recent rows, inspect at most 100 keywords/languages per row, and return up to 50 values per category. Keywords/languages are tier-gated; access levels remain public. Keywords require two occurrences in the sampled arrays. Exact filters query the full catalogue.