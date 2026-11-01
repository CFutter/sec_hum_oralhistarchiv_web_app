"""Narrow dataset RETURNING answers for ingestion orchestration tests."""

from unittest.mock import create_autospec

from psycopg import AsyncCursor
from psycopg.sql import Composable

from app.services.ingestion_audit import DatasetWriteState
from app.services.schema import DATASET_INSERT_COLUMNS


def dataset_write_state_from_params(_cursor, params):
    """Give a mocked writer an explicit result for its supplied identity."""
    values = dict(zip(DATASET_INSERT_COLUMNS, params, strict=True))
    return DatasetWriteState(
        1,
        values["source"],
        values["uuid"],
        values["visibility_tier"],
    )


def add_dataset_returning(cursor):
    """Answer the catalogue write separately from status-row sequences.

    This does not simulate PostgreSQL conflict resolution or transactions.
    Returned identities come from the actual insert parameters.
    """
    status_fetchone = cursor.fetchone
    identities = {}

    async def fetchone():
        """Return dataset-write identities from insert parameters, delegating non-write fetches."""
        call = cursor.execute.await_args
        if call is not None:
            statement = call.args[0]
            text = statement.as_string(None) if isinstance(statement, Composable) else statement
            text = " ".join(text.split())

            if text.startswith("WITH incoming AS MATERIALIZED"):
                assert "INSERT INTO oral_history_datasets" in text
                projection = text.partition("RETURNING")[2].partition("), inserted AS")[0].strip()
                assert {name.strip().removeprefix("stored.") for name in projection.split(",")} == {
                    "id",
                    "source",
                    "uuid",
                    "visibility_tier",
                }

                values = dict(zip(DATASET_INSERT_COLUMNS, call.args[1], strict=True))
                identity = (values["source"], values["uuid"])
                dataset_id = identities.setdefault(
                    identity,
                    len(identities) + 1,
                )
                return {
                    "id": dataset_id,
                    "source": values["source"],
                    "uuid": values["uuid"],
                    "visibility_tier": values["visibility_tier"],
                }

        return await status_fetchone()

    cursor.fetchone = create_autospec(
        AsyncCursor,
        instance=True,
        spec_set=True,
    ).fetchone
    cursor.fetchone.side_effect = fetchone
    return cursor
