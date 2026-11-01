# Database & Schema

Database access and executable schema contracts. The `Database` type accepts an async connection pool or an existing async connection. `get_db_cursor` commits successful transactions and rolls back failed ones. When an existing connection already has an open transaction, the cursor context uses a nested savepoint; the caller still owns the outer commit or rollback. Existing connections preserve the ingestion advisory-lock session.

Credential workflows that reserve an attempt before checking a proof require a pool or an initially idle connection for that reservation to commit independently. Wrapping the whole workflow in an outer transaction would defer that commit and allow a later rollback to undo the reservation. Callers own the lifetime of directly supplied connections and must close them after use.

`app.runtime_preflight.validate_runtime_schema` checks dataclass/column and redaction contracts, tier ranks, outbox message contracts, runtime-role privileges, Alembic head, and live database objects. Both web and scheduler run it before work begins.

Web search uses its own one-connection pool under the same web role, with a
positive SQL timeout and bounded acquisition. Its lifecycle is owned alongside
the ordinary web pool. Search failure cannot borrow the ordinary pool. An
immediate local permit and a PostgreSQL transaction try-advisory lock cover the
complete result/facet operation; the operation deadline rolls back unfinished
work before returning a retryable 503. See [search capacity settings](../../configuration/settings.md#search-capacity).

## `app.services.db`

::: app.services.db

## `app.services.schema`

::: app.services.schema

## `app.services.db_drift`

::: app.services.db_drift

## Additional database contracts

::: app.services.database_privileges

::: app.services.db_constraints

::: app.services.db_schema_contract

::: app.services.schema_invariants
