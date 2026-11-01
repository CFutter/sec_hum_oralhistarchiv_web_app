"""Ingestion recovery and source isolation against PostgreSQL."""

from unittest.mock import create_autospec, patch

import pytest
from psycopg import sql
from psycopg.errors import ProgramLimitExceeded

from app.services import ingestion
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    ingestion_failure_uuids,
    make_record,
)
from tests.source_fixtures import legacy_source


async def _raise_program_limit(cur):
    """Produce a real class-54 error without depending on physical index limits."""
    await cur.execute(
        "DO $$ BEGIN RAISE EXCEPTION 'controlled record size failure' "
        "USING ERRCODE = '54000'; END $$"
    )


def _staged_state(conn, source):
    """Read staged harvest bytes and replay position; require a status row."""
    row = conn.execute(
        "SELECT incremental_harvest, incremental_position FROM sync_status WHERE source = %s",
        (source,),
    ).fetchone()
    assert row is not None
    return (bytes(row[0]) if row[0] is not None else None, row[1])


@pytest.mark.parametrize(
    "recovery_failure",
    [None, "fetch", "write"],
    ids=["commits-recovery", "retains-on-fetch-failure", "retains-on-write-failure"],
)
async def test_unreplayable_staged_harvest_does_not_block_full_fetch(
    db_pool, sync_conn, sync_source, monkeypatch, recovery_failure
):
    """An error outside item savepoints requests a rebuild and retains bytes until recovery."""
    real_quarantine = ingestion._upsert_ingestion_failures_cur

    async def fail_poisoned_quarantine(cur, source, failures):
        """Inject a program-limit error for unreplayable quarantine entries; delegate others."""
        if "unreplayable" in failures:
            await _raise_program_limit(cur)
        return await real_quarantine(cur, source, failures)

    monkeypatch.setattr(
        ingestion,
        "_upsert_ingestion_failures_cur",
        create_autospec(real_quarantine, side_effect=fail_poisoned_quarantine),
    )
    staged = harvest_result(
        [make_record("good-record")], uncertain_records={"unreplayable": "bad metadata"}
    )
    with patch(FETCH, autospec=True, return_value=staged):
        initial = await ingestion.run_sync(db_pool, configured_source=sync_source)

    assert initial.requires_full_rebuild is True
    before = _staged_state(sync_conn, sync_source.name)
    assert before[0] is not None
    assert before[1] == 0
    assert count_datasets(sync_conn, source=sync_source.name) == 0

    with patch(
        FETCH, autospec=True, return_value=harvest_result([make_record("good-record")])
    ) as fetch:
        if recovery_failure == "fetch":
            fetch.side_effect = RuntimeError("controlled upstream failure")
        if recovery_failure == "write":

            async def fail_rebuild_publication(cur, *_args, **_kwargs):
                # Publication follows staged-payload clearing in the same
                # transaction, so this proves that clearing rolls back too.
                """Raise the injected PostgreSQL program-limit failure during rebuild publication."""
                await _raise_program_limit(cur)

            monkeypatch.setattr(
                ingestion,
                "_update_full_rebuild_timestamp",
                create_autospec(
                    ingestion._update_full_rebuild_timestamp,
                    side_effect=fail_rebuild_publication,
                ),
            )
            with pytest.raises(ProgramLimitExceeded):
                await ingestion.run_full_rebuild(db_pool, configured_source=sync_source)
        else:
            recovered = await ingestion.run_full_rebuild(db_pool, configured_source=sync_source)
            assert recovered.status == ("failed" if recovery_failure == "fetch" else "success")

    fetch.assert_called_once()
    if recovery_failure is not None:
        assert _staged_state(sync_conn, sync_source.name) == before
        assert count_datasets(sync_conn, source=sync_source.name) == 0
    else:
        assert _staged_state(sync_conn, sync_source.name) == (None, 0)
        assert count_datasets(sync_conn, uuid="good-record", source=sync_source.name) == 1


@pytest.mark.parametrize("operation", ["incremental", "rebuild"])
async def test_program_limit_is_quarantined_without_losing_good_records(
    db_pool, sync_conn, sync_source, monkeypatch, operation
):
    """Both item and rebuild-group savepoints recover from a real server error."""
    real_upsert = ingestion._upsert_public_catalogue_record

    async def fail_one_record(cur, record, policy):
        """Inject a PostgreSQL program-limit error for the marked record; delegate others."""
        if record["uuid"] == "too-large-on-write":
            await _raise_program_limit(cur)
        return await real_upsert(cur, record, policy)

    monkeypatch.setattr(
        ingestion,
        "_upsert_public_catalogue_record",
        create_autospec(real_upsert, side_effect=fail_one_record),
    )
    offered = [make_record(f"good-{number}") for number in range(3)]
    offered.append(make_record("too-large-on-write"))
    run = ingestion.run_sync if operation == "incremental" else ingestion.run_full_rebuild
    with patch(FETCH, autospec=True, return_value=harvest_result(offered)):
        outcome = await run(db_pool, configured_source=sync_source)

    assert outcome.status == "partial"
    assert outcome.affected_count == 3
    assert outcome.failed_count == 1
    assert outcome.requires_full_rebuild is False
    assert count_datasets(sync_conn, source=sync_source.name) == 3
    assert ingestion_failure_uuids(sync_conn, source=sync_source.name) == {"too-large-on-write"}
    assert _staged_state(sync_conn, sync_source.name) == (None, 0)


async def test_diagnostic_statement_failure_preserves_quarantine_and_fetch_progress(
    db_pool, sync_conn, sync_source, monkeypatch
):
    """The swallowed UPDATE error rolls back its savepoint, not the outer writes."""
    monkeypatch.setitem(
        ingestion._SYNC_ERROR_COLUMNS,
        "rebuild",
        (sql.Identifier("no_such_error_column"), sql.Identifier("no_such_error_time_column")),
    )
    harvest = harvest_result(
        uncertain_records={"uncertain-a": "bad metadata", "uncertain-b": "bad metadata"}
    )
    with patch(FETCH, autospec=True, return_value=harvest):
        outcome = await ingestion.run_full_rebuild(db_pool, configured_source=sync_source)

    assert outcome.status == "failed"
    assert outcome.failed_count == 2
    assert ingestion_failure_uuids(sync_conn, source=sync_source.name) == {
        "uncertain-a",
        "uncertain-b",
    }
    assert sync_conn.execute(
        "SELECT source_fetch_cursor, source_fetch_fingerprint FROM sync_status WHERE source = %s",
        (sync_source.name,),
    ).fetchone() == (harvest.source_cursor, sync_source.adapter.config_fingerprint())


@pytest.mark.parametrize(
    "approved", [False, True], ids=["default-refuses", "explicit-source-budget"]
)
async def test_three_to_two_contraction_requires_explicit_source_budget(
    db_pool, sync_conn, sync_source, approved
):
    """Verify three to two contraction requires explicit source budget."""
    records = [make_record(f"record-{number}") for number in range(3)]
    with patch(FETCH, autospec=True, return_value=harvest_result(records)):
        assert (
            await ingestion.run_full_rebuild(db_pool, configured_source=sync_source)
        ).status == "success"

    source = (
        legacy_source(
            name=sync_source.name,
            schedule={
                "rebuild_max_inferred_delete_count": 1,
                "rebuild_max_inferred_delete_ratio_percent": 34,
            },
        )
        if approved
        else sync_source
    )
    with patch(FETCH, autospec=True, return_value=harvest_result(records[:2])):
        outcome = await ingestion.run_full_rebuild(db_pool, configured_source=source)

    assert outcome.status == ("success" if approved else "failed")
    assert count_datasets(sync_conn, source=source.name) == (2 if approved else 3)


async def test_permissive_contraction_budget_does_not_authorize_an_empty_snapshot(
    db_pool, sync_conn, sync_source
):
    """Verify permissive contraction budget does not authorize an empty snapshot."""
    source = legacy_source(
        name=sync_source.name,
        schedule={
            "rebuild_max_inferred_delete_count": 100,
            "rebuild_max_inferred_delete_ratio_percent": 100,
        },
    )
    with patch(FETCH, autospec=True, return_value=harvest_result([make_record("retained")])):
        assert (
            await ingestion.run_full_rebuild(db_pool, configured_source=source)
        ).status == "success"
    with patch(FETCH, autospec=True, return_value=harvest_result()):
        outcome = await ingestion.run_full_rebuild(db_pool, configured_source=source)

    assert outcome.status == "failed"
    assert count_datasets(sync_conn, uuid="retained", source=source.name) == 1
