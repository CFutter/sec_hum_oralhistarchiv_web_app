"""Multipart bytea persistence and replay of the staged incremental harvest.

``app.services.sync._sync_source_a`` stages a fetched harvest into
``sync_status.incremental_harvest`` as three concatenated bytea fragments
BEFORE applying any of it (sync.py:638-661), and
``encode_stored_harvest_parts`` (stored_harvest.py:166-194) reuses an
already-serialized worker payload instead of re-encoding when the harvest
carries one attached — exactly what ``fetch_updates_isolated`` hands back in
production. A full rebuild fetch discards that attachment
(``HarvestResult.discard_serialized_worker_payload``, sync.py:966) and never
writes to this column at all.
"""

import asyncio
import json
from unittest.mock import patch

import psycopg
import pytest

from app.services import sync
from app.services.oai_client import (
    HarvestResult,
    encode_harvest_result,
    harvest_result_from_document,
)
from app.services.stored_harvest import decode_stored_harvest
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH, harvest_result, make_record


def _isolated_worker_result(harvest: HarvestResult) -> HarvestResult:
    """Reproduce exactly what ``fetch_updates_isolated`` hands its caller: the
    same harvest, carrying the worker's own encoded bytes already attached,
    so ``encode_stored_harvest_parts`` reuses them instead of re-encoding.
    Built from the public encode/decode codec (``encode_harvest_result``,
    ``harvest_result_from_document``); attaching the bytes back onto the
    reconstructed result has no public equivalent, mirroring
    ``oai_client._decode_worker_harvest_result`` exactly.
    """
    payload = encode_harvest_result(harvest)
    staged = harvest_result_from_document(json.loads(payload.decode("utf-8")))
    staged._attach_serialized_worker_payload(payload)
    return staged


async def _stage_and_interrupt_after_one_commit(
    db_pool, monkeypatch, fetch_return: HarvestResult
) -> None:
    """Run ``run_sync`` against ``fetch_return``, forcing a ``TimeoutError``
    once exactly one work item has committed — a genuine mid-run
    interruption (observed via a real forced timeout, not a sleep), leaving
    the staged envelope and that one committed row behind for the caller to
    inspect."""
    monkeypatch.setattr(settings, "sync_write_timeout_seconds", 0.15)
    monkeypatch.setattr(sync, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
    original = sync._upsert_public_catalogue_record
    writes = 0

    async def block_on_second_item(*args):
        nonlocal writes
        writes += 1
        if writes == 2:
            await asyncio.Event().wait()
        return await original(*args)

    monkeypatch.setattr(sync, "_upsert_public_catalogue_record", block_on_second_item)
    with (
        patch(FETCH, autospec=True, return_value=fetch_return),
        pytest.raises(TimeoutError),
    ):
        await sync.run_sync(db_pool)


class TestStagedEnvelopePersistence:
    """The staged envelope this instance wrote is exactly what a later
    reader (or a later replay by this same instance) decodes back."""

    async def test_an_interrupted_incremental_stages_a_harvest_that_decodes_back_to_the_original(
        self, db_pool, monkeypatch
    ):
        """An isolated worker's HarvestResult, carrying its
        own attached serialized payload, is staged into
        ``sync_status.incremental_harvest`` before any row is written. Read
        through an INDEPENDENT connection (never the pool under test) and
        decoded with the public ``decode_stored_harvest``, it reconstructs
        the identical harvest — proving the multipart bytea concatenation
        round-trips the worker's own bytes rather than corrupting or
        re-deriving them."""
        harvest = harvest_result([make_record("staged-1"), make_record("staged-2")])
        isolated = _isolated_worker_result(harvest)

        await _stage_and_interrupt_after_one_commit(db_pool, monkeypatch, isolated)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            payload = fresh.execute(
                "SELECT incremental_harvest FROM sync_status WHERE id = 1"
            ).fetchone()[0]
        assert payload is not None

        decoded = decode_stored_harvest(
            bytes(payload), expected_source_fingerprint=sync._source_a_fingerprint()
        )
        assert decoded == harvest

    async def test_a_replayed_staged_harvest_finishes_with_the_same_outcome_as_an_uninterrupted_run(
        self, db_pool, sync_conn, monkeypatch
    ):
        """After the interruption above, a follow-up
        ``run_sync`` decodes the staged envelope and finishes the remaining
        work WITHOUT re-fetching (the isolated harvest fetch is not called
        again) — position, affected count, and cursor advancement end up
        exactly where an uninterrupted single run would have left them."""
        harvest = harvest_result([make_record("resume-1"), make_record("resume-2")])
        isolated = _isolated_worker_result(harvest)

        await _stage_and_interrupt_after_one_commit(db_pool, monkeypatch, isolated)

        assert sync_conn.execute(
            "SELECT incremental_position, incremental_affected FROM sync_status"
        ).fetchone() == (1, 1)

        with patch(FETCH, autospec=True, return_value=isolated) as fetch:
            outcome = await sync.run_sync(db_pool)

        fetch.assert_not_called()
        assert outcome.status == "success"
        assert outcome.affected_count == 2
        assert sync_conn.execute(
            "SELECT incremental_harvest, incremental_position, incremental_affected, "
            "source_cursor, last_sync_error FROM sync_status"
        ).fetchone() == (None, 0, 0, harvest.source_cursor, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 2


class TestStagingWriteFailure:
    async def test_a_failure_during_the_multipart_bytea_update_leaves_no_partial_envelope(
        self, db_pool, sync_conn, monkeypatch
    ):
        """A database error raised while executing the
        three-fragment concatenating UPDATE must not leave a partially
        written envelope — the whole staging transaction rolls back, so the
        column stays exactly NULL and progress stays exactly zero, not some
        truncated byte string with a nonzero position."""
        harvest = harvest_result([make_record("never-staged")])
        real_execute = psycopg.AsyncCursor.execute

        async def faulty_execute(self, query, params=None, **kwargs):
            if isinstance(query, str) and "incremental_harvest =" in query and "||" in query:
                raise psycopg.OperationalError("simulated multipart UPDATE failure")
            return await real_execute(self, query, params, **kwargs)

        monkeypatch.setattr(psycopg.AsyncCursor, "execute", faulty_execute)
        with (
            patch(FETCH, autospec=True, return_value=harvest),
            pytest.raises(psycopg.OperationalError, match="simulated multipart UPDATE failure"),
        ):
            await sync.run_sync(db_pool)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            row = fresh.execute(
                "SELECT incremental_harvest, incremental_position, incremental_affected, "
                "incremental_started_at, last_sync_error FROM sync_status WHERE id = 1"
            ).fetchone()
        assert row[:4] == (None, 0, 0, None)
        assert row[4] is not None and "OperationalError" in row[4]
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0


class TestFullRebuildNeverStagesAWorkerPayload:
    async def test_a_full_rebuild_stores_no_worker_payload_bytes(self, db_pool, sync_conn):
        """Even when the fetched harvest carries an
        attached worker payload exactly like the incremental path's, a full
        rebuild discards it (``HarvestResult.discard_serialized_worker_payload``)
        before applying — ``incremental_harvest`` stays NULL, because a
        rebuild never stages resumable state at all. Positive control:
        ``TestStagedEnvelopePersistence`` above proves the very same
        attached-payload harvest DOES get staged on the incremental path."""
        harvest = harvest_result([make_record("rebuilt-1")])
        isolated = _isolated_worker_result(harvest)

        with patch(FETCH, autospec=True, return_value=isolated):
            outcome = await sync.run_full_rebuild(db_pool)

        assert outcome.status == "success"
        assert (
            sync_conn.execute("SELECT incremental_harvest FROM sync_status").fetchone()[0] is None
        )
        assert (
            sync_conn.execute(
                "SELECT count(*) FROM oral_history_datasets WHERE uuid = %s", ("rebuilt-1",)
            ).fetchone()[0]
            == 1
        )
