"""Multipart bytea persistence and staged replay for each selected source."""

import asyncio
import json
from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import ingestion
from app.services.harvest import HarvestResult, harvest_result_from_document
from app.services.stored_harvest import decode_stored_harvest
from app.sources import ConfiguredSource
from app.sources.oai_client import encode_harvest_result
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, SourceCase, harvest_result, make_record
from tests.source_fixtures import legacy_source


def _isolated_worker_result(harvest: HarvestResult) -> HarvestResult:
    """Reconstruct the same validated data returned by worker decoding."""
    payload = encode_harvest_result(harvest)
    return harvest_result_from_document(json.loads(payload.decode("utf-8")))


async def _stage_and_interrupt_after_one_commit(
    db_pool,
    monkeypatch,
    fetch_return: HarvestResult,
    *,
    configured_source: ConfiguredSource,
) -> ConfiguredSource:
    """Interrupt the selected source after one committed item."""
    configured_source = legacy_source(
        name=configured_source.name,
        schedule={"write_timeout_seconds": 1},
    )
    monkeypatch.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
    original = ingestion._upsert_public_catalogue_record
    writes = 0

    async def block_on_second_item(*args):
        """Perform one real write, then block indefinitely on the second call."""
        nonlocal writes
        writes += 1
        if writes == 2:
            await asyncio.Event().wait()
        return await original(*args)

    monkeypatch.setattr(
        ingestion,
        "_upsert_public_catalogue_record",
        create_autospec(original, side_effect=block_on_second_item),
    )
    with (
        patch(FETCH, autospec=True, return_value=fetch_return),
        pytest.raises(TimeoutError),
    ):
        await ingestion.run_sync(db_pool, configured_source=configured_source)

    return configured_source


class TestStagedEnvelopePersistence(SourceCase):
    """Check staged Envelope Persistence."""

    async def test_an_interrupted_incremental_stages_a_harvest_that_decodes_back_to_the_original(
        self, db_pool, monkeypatch
    ):
        """A decoded worker result survives fresh multipart encoding and persistence."""
        harvest = harvest_result([make_record("staged-1"), make_record("staged-2")])
        isolated = _isolated_worker_result(harvest)

        configured_source = await _stage_and_interrupt_after_one_commit(
            db_pool,
            monkeypatch,
            isolated,
            configured_source=self.source,
        )

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            payload = fresh.execute(
                "SELECT incremental_harvest FROM sync_status WHERE source = %s",
                (configured_source.name,),
            ).fetchone()[0]
        assert payload is not None

        decoded = decode_stored_harvest(
            bytes(payload),
            expected_source_fingerprint=configured_source.adapter.config_fingerprint(),
        )
        assert decoded == harvest

    async def test_a_replayed_staged_harvest_finishes_with_the_same_outcome_as_an_uninterrupted_run(
        self, db_pool, sync_conn, monkeypatch
    ):
        """A retry replays the remaining staged work without refetching."""
        harvest = harvest_result([make_record("resume-1"), make_record("resume-2")])
        isolated = _isolated_worker_result(harvest)

        configured_source = await _stage_and_interrupt_after_one_commit(
            db_pool,
            monkeypatch,
            isolated,
            configured_source=self.source,
        )

        assert sync_conn.execute(
            "SELECT incremental_position, incremental_affected FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone() == (1, 1)

        with patch(FETCH, autospec=True, return_value=isolated) as fetch:
            outcome = await ingestion.run_sync(db_pool, configured_source=configured_source)

        fetch.assert_not_called()
        assert outcome.status == "success"
        assert outcome.affected_count == 2
        assert sync_conn.execute(
            "SELECT incremental_harvest, incremental_position, incremental_affected, "
            "source_cursor, last_sync_error FROM sync_status WHERE source = %s",
            (configured_source.name,),
        ).fetchone() == (None, 0, 0, harvest.source_cursor, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 2


class TestStagingWriteFailure(SourceCase):
    """Check staging Write Failure."""

    async def test_a_failure_during_the_multipart_bytea_update_leaves_no_partial_envelope(
        self, db_pool, sync_conn, monkeypatch
    ):
        """A multipart staging error leaves no partial bytes or progress."""
        configured_source = self.source
        harvest = harvest_result([make_record("never-staged")])
        real_execute = psycopg.AsyncCursor.execute

        async def faulty_execute(self, query, params=None, **kwargs):
            """Reject multipart staged-harvest updates with OperationalError; delegate other SQL."""
            if isinstance(query, str) and "incremental_harvest =" in query and "||" in query:
                raise psycopg.OperationalError("simulated multipart UPDATE failure")
            return await real_execute(self, query, params, **kwargs)

        monkeypatch.setattr(
            psycopg.AsyncCursor,
            "execute",
            create_autospec(real_execute, side_effect=faulty_execute),
        )
        with (
            patch(FETCH, autospec=True, return_value=harvest),
            pytest.raises(psycopg.OperationalError, match="simulated multipart UPDATE failure"),
        ):
            await ingestion.run_sync(db_pool, configured_source=configured_source)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            row = fresh.execute(
                "SELECT incremental_harvest, incremental_position, incremental_affected, "
                "incremental_started_at, last_sync_error FROM sync_status WHERE source = %s",
                (configured_source.name,),
            ).fetchone()
        assert row[:4] == (None, 0, 0, None)
        assert row[4] is not None and "OperationalError" in row[4]
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0


class TestFullRebuildNeverStagesAWorkerPayload(SourceCase):
    """Check full Rebuild Never Stages AWorker Payload."""

    async def test_a_full_rebuild_stores_no_worker_payload_bytes(self, db_pool, sync_conn):
        """A rebuild discards fetched worker bytes instead of staging them."""
        harvest = harvest_result([make_record("rebuilt-1")])
        isolated = _isolated_worker_result(harvest)

        with patch(FETCH, autospec=True, return_value=isolated):
            outcome = await ingestion.run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "success"
        assert (
            sync_conn.execute(
                "SELECT incremental_harvest FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()[0]
            is None
        )
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("rebuilt-1",)
            ).fetchone()[0]
            == 1
        )
