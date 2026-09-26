# Database & Schema

Database access and executable schema contracts. `get_db_cursor` accepts a pool or an existing async connection; successful contexts commit and failing contexts roll back their transaction. Existing connections preserve the ingestion advisory-lock session.

`app.runtime_preflight.validate_runtime_schema` checks dataclass/column and redaction contracts, tier ranks, outbox message contracts, runtime-role privileges, Alembic head, and live database objects. Both web and scheduler run it before work begins.

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
