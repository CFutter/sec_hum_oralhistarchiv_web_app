# Database & Schema

Three thin but important modules.

`db` owns the psycopg connection pool and the `get_db_cursor` context manager that every other service uses to talk to PostgreSQL. The pool is created in the application `lifespan` (and, independently, in the scheduler process) and stored on `app.state.db_pool`; services receive it as an explicit argument rather than reaching for a global. This makes the database dependency visible at every call site and trivial to mock in tests. Each pooled connection is tagged with an `application_name` (`oralhistarchiv-web` or `oralhistarchiv-scheduler`) and a `statement_timeout`, so the two processes are distinguishable in `pg_stat_activity`.

`schema` is the single source of truth for the column lists used in `oral_history_datasets` SELECTs and INSERTs, and the pre-built `psycopg.sql` composables that wrap them. Both `datasets.py` and `sync.py` (and `seed_mock_data.py`) import from here, which prevents the most common bug in this kind of code: adding a column on one side of the read/write boundary and forgetting it on the other.

`db_drift` closes the remaining gap: the dataclass-vs-column-list checks cannot see the **live database**, and several columns (auth tokens, lockout counters, session purpose/flash) are touched only by raw SQL that no dataclass mirrors. `validate_schema_against_db()` queries `information_schema` and asserts every column the code references actually exists.

Five startup invariant checks guard against drift, all run from the lifespan handler:

- `validate_dataset_schema()` (in `datasets.py`) asserts the SELECT column list matches the `Dataset` dataclass, minus the computed fields.
- `validate_dataset_insert_schema()` asserts `DATASET_INSERT_COLUMNS` is `DATASET_COLUMNS` followed by `data` and `last_modified`, in that order.
- `validate_user_schema()` (in `users.py`) does the equivalent check for the user column list and the `User` dataclass.
- `assert_redaction_total()` (in `datasets.py`) asserts every `Dataset` field is classified as visible-or-redacted exactly once.
- `validate_schema_against_db()` (in `db_drift.py`) checks the live database has every column the code references.

## `app.services.db`

::: app.services.db

## `app.services.schema`

::: app.services.schema

## `app.services.db_drift`

::: app.services.db_drift
