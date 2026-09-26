"""Abort/commit threshold guards protecting the full rebuild.

``app.services.sync._full_rebuild_source_a`` refuses to apply a rebuild
whose offered set looks like truncated or ambiguous upstream data: the
contraction guard (sync.py:289-326) bounds absence-inferred deletion, an
empty harvest is treated as ambiguous rather than a live wipe, and a batch
whose write-success rate falls below half is rolled back entirely. The
un-guarded reconciliation mechanics live in ``test_sync_rebuild_db.py``.
"""

import logging
from datetime import UTC, datetime
from unittest.mock import patch

import psycopg
import pytest

from app.services import sync as sync_module
from app.services.sync import run_full_rebuild
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    make_record,
    sync_status_row,
)

from .conftest import TEST_DATABASE_URL


def _bulk_seed_swissubase_rows(conn: psycopg.Connection, uuids: list[str]) -> None:
    """Fast multi-row seed for scenarios needing hundreds of existing rows.

    Mirrors ``dataset_factory``'s column defaults (array columns non-NULL
    empty) but inserts through one connection/cursor instead of one
    connection per row — the contraction-guard's absolute-count boundary is
    only reachable with existing-row counts in the hundreds.
    """
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO oral_history_datasets
                (uuid, title, source, access_level, visibility_tier,
                 description, authors, keywords, languages, institutions,
                 main_disciplines)
            VALUES (%s, %s, 'swissubase', 'public', 'public', %s, %s, %s, %s, %s, %s)
            """,
            [(uuid, f"Bulk seed {uuid}", "", [], [], [], [], []) for uuid in uuids],
        )
    conn.commit()


class TestContractionGuard:
    """Absence-based deletion limit (sync.py:289-326, 175-190)."""

    async def test_full_rebuild_refuses_when_offered_set_omits_more_than_a_quarter_of_existing_rows(
        self, db_pool, sync_conn, dataset_factory
    ):
        """More than 25% of existing Source A rows absent from the offered
        keep-list trips the contraction guard (_RebuildContractionAborted):
        the run fails, every pre-existing row (offered and omitted alike)
        survives, last_rebuild_error carries the real n/m absence count,
        the rebuild channel (not the incremental one) is written, and
        last_full_rebuild_date does not advance."""
        keep_uuids = [f"oai:x:guard-keep-{i}" for i in range(5)]
        omit_uuids = [f"oai:x:guard-omit-{i}" for i in range(3)]  # 3/8 = 37.5% > 25%
        for uuid in keep_uuids + omit_uuids:
            dataset_factory(uuid=uuid, source="swissubase")

        before = sync_status_row(sync_conn)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "failed"
        for uuid in keep_uuids + omit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source="swissubase") == 1

        after = sync_status_row(sync_conn)
        assert after["last_rebuild_error"] is not None
        assert after["last_rebuild_error"].startswith(
            "Full rebuild aborted — upstream would remove 3/8 records by absence"
        )
        assert after["last_sync_error"] == before["last_sync_error"]  # incremental untouched
        assert after["last_sync_error_at"] == before["last_sync_error_at"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]

    async def test_full_rebuild_proceeds_when_offered_set_omits_at_most_a_quarter_of_existing_rows(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Positive control for the contraction guard: omitting exactly 25%
        of existing Source A rows is at the limit, not over it, so the
        rebuild proceeds — the omitted rows are deleted, the offered rows
        stay, last_full_rebuild_date advances and last_rebuild_error is
        clear."""
        keep_uuids = [f"oai:x:guard-ok-keep-{i}" for i in range(6)]
        omit_uuids = [f"oai:x:guard-ok-omit-{i}" for i in range(2)]  # 2/8 = 25%, at the limit
        for uuid in keep_uuids + omit_uuids:
            dataset_factory(uuid=uuid, source="swissubase")

        before = sync_status_row(sync_conn)
        assert before["last_full_rebuild_date"] is None
        rebuild_t0 = datetime.now(UTC)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "success"
        for uuid in omit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source="swissubase") == 0
        for uuid in keep_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source="swissubase") == 1

        after = sync_status_row(sync_conn)
        assert after["last_full_rebuild_date"] is not None
        assert after["last_full_rebuild_date"] >= rebuild_t0
        assert after["last_rebuild_error"] is None

    async def test_full_rebuild_refuses_at_101_inferred_deletions_even_under_the_ratio_limit(
        self, db_pool, sync_conn
    ):
        """The absolute cap (100 records) trips independently of the 25%
        ratio: 101 inferred deletions out of 1000 existing rows is only
        10.1%, well under the ratio limit, but still exceeds the absolute
        count and must abort exactly like a ratio breach does."""
        existing = 1000
        omitted = 101
        keep_uuids = [f"oai:x:cap-keep-{i}" for i in range(existing - omitted)]
        omit_uuids = [f"oai:x:cap-omit-{i}" for i in range(omitted)]
        _bulk_seed_swissubase_rows(sync_conn, keep_uuids + omit_uuids)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "failed"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, source="swissubase") == existing
        after = sync_status_row(sync_conn)
        assert after["last_rebuild_error"] is not None
        assert after["last_rebuild_error"].startswith(
            f"Full rebuild aborted — upstream would remove {omitted}/{existing} records by absence"
        )

    async def test_full_rebuild_proceeds_at_exactly_100_inferred_deletions(
        self, db_pool, sync_conn
    ):
        """Positive control for the absolute cap: exactly 100 inferred
        deletions (10% of 1000 existing rows, also under the ratio limit)
        is at the cap, not over it, so the rebuild proceeds."""
        existing = 1000
        omitted = 100
        keep_uuids = [f"oai:x:cap-ok-keep-{i}" for i in range(existing - omitted)]
        omit_uuids = [f"oai:x:cap-ok-omit-{i}" for i in range(omitted)]
        _bulk_seed_swissubase_rows(sync_conn, keep_uuids + omit_uuids)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "success"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, source="swissubase") == existing - omitted
            for uuid in omit_uuids:
                assert count_datasets(fresh, uuid=uuid, source="swissubase") == 0
            for uuid in keep_uuids:
                assert count_datasets(fresh, uuid=uuid, source="swissubase") == 1


class TestLargeUpstreamContraction:
    """A near-total absence-based contraction is refused and leaves the
    catalogue exactly as it was, whatever its absolute size."""

    async def test_full_rebuild_refuses_near_total_contraction_of_a_large_catalogue(
        self, db_pool, sync_conn
    ):
        """1,000 existing Source A rows, only one offered as still-matching:
        999/1000 (99.9%) trips both the ratio and absolute-count limits.
        Every pre-existing row survives — the guard is checked and the
        catalogue transaction rolled back before any DELETE takes effect —
        and the recorded error carries the real contraction counts."""
        existing_uuids = [f"oai:x:large-{i}" for i in range(1000)]
        _bulk_seed_swissubase_rows(sync_conn, existing_uuids)
        before_rows = sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase' ORDER BY uuid"
        ).fetchall()

        kept_uuid = existing_uuids[0]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(kept_uuid)]),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "failed"
        # An independent connection proves the catalogue transaction never
        # committed any part of the contraction, not merely that this
        # connection's own view looks unchanged.
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after_rows = fresh.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase' ORDER BY uuid"
            ).fetchall()
            after_status = sync_status_row(fresh)
        assert after_rows == before_rows
        assert after_status["last_rebuild_error"] is not None
        assert after_status["last_rebuild_error"].startswith(
            "Full rebuild aborted — upstream would remove 999/1000 records by absence"
        )
        assert after_status["last_full_rebuild_date"] is None


class TestExplicitWithdrawalsBesideTheContractionGuard:
    """Explicit upstream withdrawals (tombstones / definitive mismatches)
    are deleted in the same transaction as the absence-based stale-delete,
    but the contraction guard's count must reflect only the absence-based
    portion — an explicit removal is authoritative regardless of size."""

    async def test_contraction_guard_counts_only_absence_based_removals(
        self, db_pool, sync_conn, dataset_factory
    ):
        """8 existing rows; 3 are explicitly tombstoned (37.5% of the
        original 8 — over the ratio limit if explicit removals counted
        toward the guard) and the remaining 5 are all offered as matching
        (0 absence-based deletions). If explicit removals were folded into
        the guard's count, this rebuild would abort; instead it must
        succeed, because the guard counts only rows absent from the offered
        keep-list AFTER explicit removals have already been applied."""
        explicit_uuids = [f"oai:x:explicit-{i}" for i in range(3)]
        kept_uuids = [f"oai:x:kept-{i}" for i in range(5)]
        for uuid in explicit_uuids + kept_uuids:
            dataset_factory(uuid=uuid, source="swissubase")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record(uuid) for uuid in kept_uuids],
                deleted_uuids=set(explicit_uuids),
            ),
        ):
            outcome = await run_full_rebuild(db_pool)

        assert outcome.status == "success"
        for uuid in explicit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source="swissubase") == 0
        for uuid in kept_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source="swissubase") == 1

    async def test_write_failure_after_the_guard_rolls_back_explicit_and_inferred_deletions_together(
        self, db_pool, dataset_factory, monkeypatch
    ):
        """A failure injected after the contraction guard has already
        passed — but before the rebuild's completion commits — rolls back
        the explicit tombstone delete AND the absence-based stale delete
        together, in the same transaction: neither kind of removal survives
        a rebuild that never reaches its own commit.

        Positive control: the sibling test above proves the same explicit
        + inferred combination committing cleanly when nothing fails.
        """
        explicit_uuid = "oai:x:explicit-rollback"
        inferred_stale_uuid = "oai:x:inferred-rollback"
        kept_uuid = "oai:x:kept-rollback"
        # Filler rows stay existing AND offered (protected), diluting the
        # single inferred-stale row below the guard's 25% ratio so this
        # rebuild reaches the injected failure instead of aborting on the
        # contraction guard itself.
        filler_uuids = [f"oai:x:filler-rollback-{i}" for i in range(4)]
        for uuid in (explicit_uuid, inferred_stale_uuid, kept_uuid, *filler_uuids):
            dataset_factory(uuid=uuid, source="swissubase")

        async def broken_timestamp_update(*_args, **_kwargs):
            raise RuntimeError("injected post-guard write failure")

        monkeypatch.setattr(sync_module, "_update_full_rebuild_timestamp", broken_timestamp_update)

        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result(
                    [make_record(kept_uuid)] + [make_record(uuid) for uuid in filler_uuids],
                    deleted_uuids={explicit_uuid},
                ),
            ),
            pytest.raises(RuntimeError, match="injected post-guard write failure"),
        ):
            await run_full_rebuild(db_pool)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, uuid=explicit_uuid, source="swissubase") == 1
            assert count_datasets(fresh, uuid=inferred_stale_uuid, source="swissubase") == 1
            assert count_datasets(fresh, uuid=kept_uuid, source="swissubase") == 1
            for uuid in filler_uuids:
                assert count_datasets(fresh, uuid=uuid, source="swissubase") == 1


class TestAmbiguousEmptyHarvestGuard:
    """An ambiguous empty harvest must not wipe the catalogue; an explicit,
    identity-scoped withdrawal is authoritative even with zero live
    records."""

    @pytest.mark.parametrize(
        "harvest",
        [
            pytest.param(harvest_result(), id="empty-fetch"),
            pytest.param(
                harvest_result(
                    uncertain_records={
                        "oai:x:precious-1": "missing or unusable institution metadata"
                    }
                ),
                id="only-uncertain",
            ),
        ],
    )
    async def test_full_rebuild_aborts_on_empty_fetch_keeping_data(
        self, db_pool, sync_conn, dataset_factory, caplog, harvest
    ):
        """Existing rows are kept, a warning is logged, neither timestamp
        advances, and the failure is recorded on the REBUILD channel
        (never the incremental one) — the empty-fetch guard fires before
        any DB write, distinct from the in-transaction threshold abort
        pinned below."""
        dataset_factory(uuid="oai:x:precious-1", source="swissubase")
        before = sync_status_row(sync_conn)

        with (
            caplog.at_level(logging.WARNING, logger="app.services.sync"),
            patch(FETCH, autospec=True, return_value=harvest),
        ):
            await run_full_rebuild(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:precious-1") == 1
        assert any("Full rebuild aborted" in r.message for r in caplog.records)

        after = sync_status_row(sync_conn)
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_rebuild_error"] is not None
        assert "0 matching records" in after["last_rebuild_error"]
        assert after["last_sync_error"] is None  # incremental channel untouched

    @pytest.mark.parametrize(
        "harvest",
        [
            pytest.param(
                harvest_result(deleted_uuids={"oai:x:withdrawn"}),
                id="tombstone",
            ),
            pytest.param(
                harvest_result(nonmatching_uuids={"oai:x:withdrawn"}),
                id="definitive-institution-mismatch",
            ),
        ],
    )
    async def test_empty_full_rebuild_applies_only_explicit_source_withdrawals(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
        harvest,
    ):
        """A bare empty harvest remains ambiguous and is handled by the
        guard above. Tombstones and definitive filter mismatches identify
        exact source rows and therefore remain authoritative even when no
        live record accompanies them."""
        dataset_factory(uuid="oai:x:withdrawn", source="swissubase")
        dataset_factory(uuid="oai:x:unmentioned", source="swissubase")
        dataset_factory(uuid="oai:x:withdrawn", source="mock")
        before = sync_status_row(sync_conn)

        with patch(FETCH, autospec=True, return_value=harvest):
            await run_full_rebuild(db_pool)

        assert (
            count_datasets(
                sync_conn,
                uuid="oai:x:withdrawn",
                source="swissubase",
            )
            == 0
        )
        assert (
            count_datasets(
                sync_conn,
                uuid="oai:x:unmentioned",
                source="swissubase",
            )
            == 1
        )
        assert count_datasets(sync_conn, uuid="oai:x:withdrawn", source="mock") == 1

        after = sync_status_row(sync_conn)
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_rebuild_error"] is not None
        assert "1 explicit source removal(s) applied" in after["last_rebuild_error"]
        assert after["last_sync_error"] is None


def _failing_record(uuid, failure_kind, *, title="old failed record"):
    """A parser-shaped record that PostgreSQL rejects after structural validation."""
    record = make_record(uuid, title=title)
    if failure_kind == "nul-array":
        record["authors"] = ["\x00"]  # Valid Python shape, rejected by PostgreSQL.
    else:
        assert failure_kind == "nul-text"
        record["description"] = "\x00"
    return record


def _threshold_records(offered, successful, failure_kind):
    """Build real parser-shaped records; keep failures separate from missing UUIDs."""
    records = [make_record(f"oai:threshold:good-{i}", title="new title") for i in range(successful)]
    records.extend(
        _failing_record(f"oai:threshold:bad-{i}", failure_kind) for i in range(offered - successful)
    )
    return records


def _contraction_guard_filler_count(anchor_existing_count):
    """How many extra offered-but-failing Source A rows dilute the guard.

    The contraction guard (sync.py:289-326) refuses to infer-delete more than
    25% of existing Source A rows. These fixtures always carry exactly one
    row that is never offered again ("oai:x:pre-existing" / "oai:x:stale"),
    so the guard only clears once at least 4 Source A rows exist; filler rows
    are offered (and therefore protected) so they do not add to the inferred
    count.
    """
    return max(0, 4 - anchor_existing_count)


def _seed_threshold_status(sync_conn):
    """Use committed, nonempty prior status so preservation assertions are meaningful."""
    prior_time = datetime(2020, 1, 1, tzinfo=UTC)
    sync_conn.execute(
        """UPDATE sync_status
           SET last_harvest_date = %s,
               last_full_rebuild_date = %s,
               last_sync_error = 'prior incremental error',
               last_sync_error_at = %s,
               last_rebuild_error = 'prior rebuild error',
               last_rebuild_error_at = %s
           WHERE id = 1""",
        (prior_time, prior_time, prior_time, prior_time),
    )
    sync_conn.commit()
    status = sync_status_row(sync_conn)
    sync_conn.commit()
    return status


class TestSuccessRateThreshold:
    """Too few successful writes among offered records rolls the whole
    rebuild back; at least half commits it."""

    @pytest.mark.parametrize(
        ("offered", "successful"),
        [
            pytest.param(1, 0, id="zero-of-one"),
            pytest.param(3, 1, id="one-of-three"),
            pytest.param(4, 1, id="one-of-four"),
            pytest.param(5, 2, id="two-of-five"),
        ],
    )
    @pytest.mark.parametrize("failure_kind", ["nul-array", "nul-text"])
    async def test_full_rebuild_below_threshold_aborts(
        self, db_pool, sync_conn, dataset_factory, offered, successful, failure_kind, caplog
    ):
        """Too few successes roll back stale deletion, inserts, updates,
        and timestamps. Missing-UUID failures must count even though their
        former rows are absent from the stale-delete keep-list. The
        two-of-five case also updates an existing offered row before
        aborting."""
        dataset_factory(uuid="oai:x:pre-existing", source="swissubase")
        dataset_factory(uuid="oai:mock:unrelated", source="mock")
        if successful > 1:
            dataset_factory(uuid="oai:threshold:good-1", source="swissubase", title="old title")
        for i in range(offered - successful):
            dataset_factory(
                uuid=f"oai:threshold:bad-{i}", source="swissubase", title="old failed record"
            )

        # Dilute the contraction guard: filler rows are pre-existing AND
        # offered (so they stay protected, not inferred-absent), keeping
        # the one truly stale row ("oai:x:pre-existing") at or below 25% of
        # existing rows.
        anchor_existing = 1 + (1 if successful > 1 else 0) + (offered - successful)
        filler = _contraction_guard_filler_count(anchor_existing)
        for i in range(filler):
            dataset_factory(
                uuid=f"oai:threshold:filler-{i}", source="swissubase", title="old filler record"
            )
        total_offered = offered + filler

        before_rows = sync_conn.execute(
            "SELECT id, uuid, source, title FROM oral_history_datasets ORDER BY id"
        ).fetchall()
        sync_conn.commit()
        before = _seed_threshold_status(sync_conn)

        records = _threshold_records(offered, successful, failure_kind) + [
            _failing_record(f"oai:threshold:filler-{i}", failure_kind, title="old filler record")
            for i in range(filler)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            await run_full_rebuild(db_pool)

        # A new connection observes only committed state after the service returns.
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after_rows = fresh.execute(
                "SELECT id, uuid, source, title FROM oral_history_datasets ORDER BY id"
            ).fetchall()
            after = sync_status_row(fresh)

        assert after_rows == before_rows
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_sync_error"] == before["last_sync_error"]
        assert after["last_sync_error_at"] == before["last_sync_error_at"]
        assert "ABORTED" in (after["last_rebuild_error"] or "")
        assert f"{successful}/{total_offered}" in after["last_rebuild_error"]
        assert after["last_rebuild_error_at"] > before["last_rebuild_error_at"]

        abort_logs = [
            record
            for record in caplog.records
            if getattr(record, "event_type", None) == "sync_rebuild_aborted"
        ]
        assert len(abort_logs) == 1
        assert abort_logs[0].success_count == successful
        assert abort_logs[0].offered == total_offered

    @pytest.mark.parametrize(
        ("offered", "successful"),
        [
            pytest.param(2, 1, id="one-of-two"),
            pytest.param(3, 2, id="two-of-three"),
            pytest.param(4, 2, id="two-of-four"),
            pytest.param(5, 3, id="three-of-five"),
        ],
    )
    @pytest.mark.parametrize("failure_kind", ["nul-array", "nul-text"])
    async def test_full_rebuild_at_threshold_commits(
        self, db_pool, sync_conn, dataset_factory, offered, successful, failure_kind, caplog
    ):
        """Exactly half, or the smallest integer above half, commits the
        rebuild. Includes successful updates, a new insert in larger
        batches, stale removal, and preservation of offered-but-malformed
        rows. Upstream filtering uncertainty is outside this test: these
        records have already been returned."""
        dataset_factory(uuid="oai:x:stale", source="swissubase")
        dataset_factory(uuid="oai:mock:unrelated", source="mock")
        dataset_factory(uuid="oai:threshold:good-0", source="swissubase", title="old title")
        original_id = sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE source = 'swissubase' AND uuid = %s",
            ("oai:threshold:good-0",),
        ).fetchone()[0]
        sync_conn.commit()
        for i in range(offered - successful):
            dataset_factory(
                uuid=f"oai:threshold:bad-{i}",
                source="swissubase",
                title="old failed record",
            )

        # Dilute the contraction guard: filler rows are pre-existing AND
        # offered AND succeed, so they add equally to the existing, offered
        # and success counts — diluting "oai:x:stale" (the one truly stale
        # row) to at or below 25% of existing rows without disturbing the
        # success/offered ratio that decides whether this rebuild commits.
        anchor_existing = 2 + (offered - successful)
        filler = _contraction_guard_filler_count(anchor_existing)
        for i in range(filler):
            dataset_factory(
                uuid=f"oai:threshold:filler-{i}", source="swissubase", title="old filler title"
            )

        before = _seed_threshold_status(sync_conn)
        records = _threshold_records(offered, successful, failure_kind) + [
            make_record(f"oai:threshold:filler-{i}", title="new filler title")
            for i in range(filler)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            await run_full_rebuild(db_pool)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after = sync_status_row(fresh)
            rows = fresh.execute(
                "SELECT id, uuid, title FROM oral_history_datasets WHERE source = 'swissubase'"
            ).fetchall()
            assert count_datasets(fresh, uuid="oai:mock:unrelated", source="mock") == 1

        by_uuid = {uuid: (row_id, title) for row_id, uuid, title in rows}
        expected_uuids = {f"oai:threshold:good-{i}" for i in range(successful)}
        expected_uuids.update(f"oai:threshold:filler-{i}" for i in range(filler))
        expected_uuids.update(f"oai:threshold:bad-{i}" for i in range(offered - successful))
        for i in range(offered - successful):
            assert by_uuid[f"oai:threshold:bad-{i}"][1] == "old failed record"
        assert set(by_uuid) == expected_uuids
        assert by_uuid["oai:threshold:good-0"] == (original_id, "new title")
        for i in range(successful):
            assert by_uuid[f"oai:threshold:good-{i}"][1] == "new title"
        for i in range(filler):
            assert by_uuid[f"oai:threshold:filler-{i}"][1] == "new filler title"

        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_sync_error"] is not None
        assert after["last_sync_error_at"] >= before["last_sync_error_at"]
        err = after["last_rebuild_error"]
        assert err is not None
        assert "ABORTED" not in err
        assert f"{offered - successful} record(s) failed" in err
        assert after["last_rebuild_error_at"] > before["last_rebuild_error_at"]
        assert not any(
            getattr(record, "event_type", None) == "sync_rebuild_aborted"
            for record in caplog.records
        )
