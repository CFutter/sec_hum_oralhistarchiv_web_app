"""Durable quarantine never pins acquisition or silently loses a new identity."""

from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import pytest

from app.services.cache import CatalogueStatsCache
from app.services.harvest import HarvestResult
from app.services.ingestion import run_full_rebuild
from app.services.scheduler import rebuild_and_invalidate, sync_and_invalidate
from app.services.stored_harvest import encode_stored_harvest
from app.services.sync_state import ensure_source_status_rows
from tests.integration.sync_doubles import FETCH, make_record
from tests.source_fixtures import legacy_source

_INITIAL = datetime(2030, 1, 2, tzinfo=UTC)
_FIRST = datetime(2030, 1, 10, tzinfo=UTC)
_SECOND = datetime(2030, 1, 15, tzinfo=UTC)
_THIRD = datetime(2030, 1, 20, tzinfo=UTC)


def _state(connection, source):
    """Return the source progress row and failure UUID set, then commit the observer transaction."""
    row = connection.execute(
        "SELECT source_cursor, source_fingerprint, source_fetch_cursor, "
        "source_fetch_fingerprint, last_full_rebuild_date "
        "FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone()
    failures = connection.execute(
        "SELECT uuid FROM ingestion_failures WHERE source = %s ORDER BY uuid", (source.name,)
    ).fetchall()
    connection.commit()
    return row, {value[0] for value in failures}


@pytest.mark.parametrize("initially_bound", [False, True], ids=["fresh", "bound"])
async def test_quarantine_advances_acquisition_survives_restart_and_retries_unchanged_timestamp(
    db_pool, sync_conn, dataset_factory, initially_bound
):
    """Verify quarantine advances acquisition survives restart and retries unchanged timestamp."""
    source = legacy_source(name="quarantine", max_visibility="public")
    await ensure_source_status_rows(db_pool, (source.name,))
    dataset_factory(source=source.name, uuid="previous", title="Last good metadata")
    if initially_bound:
        sync_conn.execute(
            "UPDATE sync_status SET source_cursor = %s, source_fingerprint = %s WHERE source = %s",
            (_INITIAL, source.adapter.config_fingerprint(), source.name),
        )
        sync_conn.commit()
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    first = HarvestResult(
        matching_records=[make_record("healthy")],
        uncertain_records={"previous": "invalid metadata", "new": "invalid metadata"},
        source_cursor=_FIRST,
    )
    with patch(FETCH, autospec=True, return_value=first):
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "partial"
    state, failures = _state(sync_conn, source)
    assert state[:2] == (
        (_INITIAL, source.adapter.config_fingerprint()) if initially_bound else (None, None)
    )
    assert state[2:4] == (_FIRST, source.adapter.config_fingerprint())
    assert state[4] is None
    assert failures == {"previous", "new"}
    assert sync_conn.execute(
        "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = 'previous'",
        (source.name,),
    ).fetchone() == ("Last good metadata",)
    sync_conn.commit()

    # Reconstruct process-owned configuration; only database state bridges ticks.
    source = legacy_source(name="quarantine", max_visibility="public")
    for cutoff, expected_since in ((_SECOND, "2030-01-08"), (_THIRD, "2030-01-13")):
        with patch(FETCH, autospec=True, return_value=HarvestResult(source_cursor=cutoff)) as fetch:
            assert (await sync_and_invalidate(db_pool, cache, source)).status == "partial"
        assert fetch.call_count == 1
        assert fetch.call_args.kwargs["since"] == expected_since
        state, failures = _state(sync_conn, source)
        assert state[2] == cutoff
        assert failures == {"previous", "new"}

    # Publisher repairs metadata but keeps its old modification timestamp: the
    # periodic full retry must recover both the retained and the new identity.
    corrected = HarvestResult(
        matching_records=[
            make_record("healthy"),
            make_record("previous", title="Corrected metadata", upstream_modified_at=_INITIAL),
            make_record("new", upstream_modified_at=_INITIAL),
        ],
        source_cursor=_THIRD,
    )
    with patch(FETCH, autospec=True, return_value=corrected) as fetch:
        assert (await rebuild_and_invalidate(db_pool, cache, source)).status == "success"
    assert fetch.call_args.kwargs["since"] == "1900-01-01"
    state, failures = _state(sync_conn, source)
    assert not failures
    assert state[:4] == (
        _THIRD,
        source.adapter.config_fingerprint(),
        _THIRD,
        source.adapter.config_fingerprint(),
    )
    assert state[4] is not None
    assert sync_conn.execute(
        "SELECT uuid, title FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
        (source.name,),
    ).fetchall() == [
        ("healthy", "Oral History Interviews"),
        ("new", "Oral History Interviews"),
        ("previous", "Corrected metadata"),
    ]


async def test_all_uncertain_initial_snapshot_is_durable_without_hourly_full_recovery(
    db_pool, sync_conn
):
    """Verify all uncertain initial snapshot is durable without hourly full recovery."""
    source = legacy_source(name="all_uncertain")
    await ensure_source_status_rows(db_pool, (source.name,))
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(uncertain_records={"new": "unsupported"}, source_cursor=_FIRST),
    ):
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "failed"
    assert _state(sync_conn, source)[1] == {"new"}
    with patch(FETCH, autospec=True, return_value=HarvestResult(source_cursor=_SECOND)) as fetch:
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "partial"
    assert fetch.call_count == 1
    assert fetch.call_args.kwargs["since"] == "2030-01-08"
    state, failures = _state(sync_conn, source)
    assert state[:2] == (None, None)
    assert state[2] == _SECOND
    assert failures == {"new"}


@pytest.mark.parametrize("abort", ["contraction", "write_threshold"])
async def test_rebuild_rollback_does_not_publish_consumed_progress(
    db_pool, sync_conn, dataset_factory, abort
):
    """Verify rebuild rollback does not publish consumed progress."""
    source = legacy_source(name="abort_progress")
    await ensure_source_status_rows(db_pool, (source.name,))
    if abort == "contraction":
        for index in range(5):
            dataset_factory(source=source.name, uuid=f"record-{index}")
        records = [make_record("record-0")]
    else:
        records = [
            make_record("first", doi="10.1234/duplicate"),
            make_record("second", doi="10.1234/duplicate"),
        ]
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(matching_records=records, source_cursor=_FIRST),
    ):
        assert (await run_full_rebuild(db_pool, configured_source=source)).status == "failed"
    state, _ = _state(sync_conn, source)
    assert state == (None, None, None, None, None)


async def test_all_uncertain_recovery_replaces_incompatible_staging_atomically(
    db_pool, sync_conn, approve_source_rebinding
):
    """Verify all uncertain recovery replaces incompatible staging atomically."""
    old_source = legacy_source(name="staged_unknown")
    source = legacy_source(name="staged_unknown", institution_filter="Changed institution")
    await ensure_source_status_rows(db_pool, (source.name,))
    pending = encode_stored_harvest(
        HarvestResult(matching_records=[make_record("old")], source_cursor=_INITIAL),
        source_fingerprint=old_source.adapter.config_fingerprint(),
    )
    sync_conn.execute(
        """UPDATE sync_status SET source_cursor = %s, source_fingerprint = %s,
           incremental_harvest = %s, incremental_started_at = %s WHERE source = %s""",
        (_INITIAL, old_source.adapter.config_fingerprint(), pending, _INITIAL, source.name),
    )
    sync_conn.commit()
    approve_source_rebinding(source)
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(uncertain_records={"new": "unsupported"}, source_cursor=_FIRST),
    ) as fetch:
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "failed"
    assert fetch.call_count == 1
    assert sync_conn.execute(
        "SELECT incremental_harvest, incremental_started_at FROM sync_status WHERE source = %s",
        (source.name,),
    ).fetchone() == (None, None)
    sync_conn.commit()
    with patch(FETCH, autospec=True, return_value=HarvestResult(source_cursor=_SECOND)) as fetch:
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "partial"
    assert fetch.call_count == 1
    assert fetch.call_args.kwargs["since"] == "2030-01-08"
    state, failures = _state(sync_conn, source)
    assert state[:2] == (_INITIAL, old_source.adapter.config_fingerprint())
    assert state[2:4] == (_SECOND, source.adapter.config_fingerprint())
    assert failures == {"new"}


async def test_all_uncertain_identity_is_resolved_by_explicit_full_withdrawal(db_pool, sync_conn):
    """Verify all uncertain identity is resolved by explicit full withdrawal."""
    source = legacy_source(name="uncertain_withdrawal")
    await ensure_source_status_rows(db_pool, (source.name,))
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(uncertain_records={"new": "unsupported"}, source_cursor=_FIRST),
    ):
        await run_full_rebuild(db_pool, configured_source=source)
    assert _state(sync_conn, source)[1] == {"new"}
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(deleted_uuids={"new"}, source_cursor=_SECOND),
    ):
        await run_full_rebuild(db_pool, configured_source=source)
    assert not _state(sync_conn, source)[1]


async def test_changed_nonfeed_interpretation_uses_its_own_consumed_cursor(
    db_pool, sync_conn, approve_source_rebinding
):
    """Verify changed nonfeed interpretation uses its own consumed cursor."""
    old_source = legacy_source(name="changed_cursor")
    source = legacy_source(name="changed_cursor", institution_filter="Changed institution")
    await ensure_source_status_rows(db_pool, (source.name,))
    sync_conn.execute(
        "UPDATE sync_status SET source_cursor = %s, source_fingerprint = %s WHERE source = %s",
        (_THIRD, old_source.adapter.config_fingerprint(), source.name),
    )
    sync_conn.commit()
    approve_source_rebinding(source)
    with patch(
        FETCH,
        autospec=True,
        return_value=HarvestResult(
            matching_records=[make_record("healthy")],
            uncertain_records={"new": "unsupported"},
            source_cursor=_FIRST,
        ),
    ):
        assert (await run_full_rebuild(db_pool, configured_source=source)).status == "partial"
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    with patch(FETCH, autospec=True, return_value=HarvestResult(source_cursor=_SECOND)) as fetch:
        assert (await sync_and_invalidate(db_pool, cache, source)).status == "partial"
    assert fetch.call_args.kwargs["since"] == "2030-01-08"
    state, failures = _state(sync_conn, source)
    assert state[:2] == (_THIRD, old_source.adapter.config_fingerprint())
    assert state[2:4] == (_SECOND, source.adapter.config_fingerprint())
    assert failures == {"new"}
