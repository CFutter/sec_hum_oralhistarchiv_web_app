"""Abort/commit threshold guards protecting each source's full rebuild."""

import logging
from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import psycopg
import pytest

from app.services import ingestion as sync_module
from app.services.ingestion import run_full_rebuild
from tests.integration.sync_doubles import (
    FETCH,
    SourceCase,
    count_datasets,
    harvest_result,
    make_record,
    sync_status_row,
)

from .conftest import TEST_DATABASE_URL


def _bulk_seed_rows(conn: psycopg.Connection, uuids: list[str], *, source: str) -> None:
    """Seed large catalogues through one committed connection."""
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO oral_history_datasets
                (uuid, title, source, access_level, visibility_tier,
                 description, authors, keywords, languages, institutions,
                 main_disciplines)
            VALUES (%s, %s, %s, 'public', 'public', %s, %s, %s, %s, %s, %s)
            """,
            [(uuid, f"Bulk seed {uuid}", source, "", [], [], [], [], []) for uuid in uuids],
        )
    conn.commit()


class TestContractionGuard(SourceCase):
    """Check contraction Guard."""

    async def test_full_rebuild_refuses_when_offered_set_omits_more_than_a_quarter_of_existing_rows(
        self, db_pool, sync_conn, dataset_factory
    ):
        """More than 25% inferred deletion aborts without changing the catalogue."""
        keep_uuids = [f"oai:x:guard-keep-{i}" for i in range(5)]
        omit_uuids = [f"oai:x:guard-omit-{i}" for i in range(3)]
        for uuid in keep_uuids + omit_uuids:
            dataset_factory(uuid=uuid, source=self.source.name)

        before = sync_status_row(sync_conn, source=self.source.name)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "failed"
        for uuid in keep_uuids + omit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source=self.source.name) == 1

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_rebuild_error"] is not None
        assert after["last_rebuild_error"].startswith(
            "Full rebuild aborted — upstream would remove 3/8 records by absence"
        )
        assert after["last_sync_error"] == before["last_sync_error"]
        assert after["last_sync_error_at"] == before["last_sync_error_at"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]

    async def test_full_rebuild_proceeds_when_offered_set_omits_at_most_a_quarter_of_existing_rows(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Exactly 25% inferred deletion is permitted."""
        keep_uuids = [f"oai:x:guard-ok-keep-{i}" for i in range(6)]
        omit_uuids = [f"oai:x:guard-ok-omit-{i}" for i in range(2)]
        for uuid in keep_uuids + omit_uuids:
            dataset_factory(uuid=uuid, source=self.source.name)

        before = sync_status_row(sync_conn, source=self.source.name)
        assert before["last_full_rebuild_date"] is None
        rebuild_t0 = datetime.now(UTC)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "success"
        for uuid in omit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source=self.source.name) == 0
        for uuid in keep_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source=self.source.name) == 1

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_full_rebuild_date"] is not None
        assert after["last_full_rebuild_date"] >= rebuild_t0
        assert after["last_rebuild_error"] is None

    async def test_full_rebuild_refuses_at_101_inferred_deletions_even_under_the_ratio_limit(
        self, db_pool, sync_conn
    ):
        """The absolute cap applies independently of the percentage cap."""
        existing = 1000
        omitted = 101
        keep_uuids = [f"oai:x:cap-keep-{i}" for i in range(existing - omitted)]
        omit_uuids = [f"oai:x:cap-omit-{i}" for i in range(omitted)]
        _bulk_seed_rows(sync_conn, keep_uuids + omit_uuids, source=self.source.name)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "failed"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, source=self.source.name) == existing
        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_rebuild_error"] is not None
        assert after["last_rebuild_error"].startswith(
            f"Full rebuild aborted — upstream would remove {omitted}/{existing} records by absence"
        )

    async def test_full_rebuild_proceeds_at_exactly_100_inferred_deletions(
        self, db_pool, sync_conn
    ):
        """Exactly 100 inferred deletions are permitted when the ratio also passes."""
        existing = 1000
        omitted = 100
        keep_uuids = [f"oai:x:cap-ok-keep-{i}" for i in range(existing - omitted)]
        omit_uuids = [f"oai:x:cap-ok-omit-{i}" for i in range(omitted)]
        _bulk_seed_rows(sync_conn, keep_uuids + omit_uuids, source=self.source.name)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(uuid) for uuid in keep_uuids]),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "success"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, source=self.source.name) == existing - omitted
            for uuid in omit_uuids:
                assert count_datasets(fresh, uuid=uuid, source=self.source.name) == 0
            for uuid in keep_uuids:
                assert count_datasets(fresh, uuid=uuid, source=self.source.name) == 1


class TestLargeUpstreamContraction(SourceCase):
    """Check large Upstream Contraction."""

    async def test_full_rebuild_refuses_near_total_contraction_of_a_large_catalogue(
        self, db_pool, sync_conn
    ):
        """A 999/1000 contraction preserves every existing row."""
        existing_uuids = [f"oai:x:large-{i}" for i in range(1000)]
        _bulk_seed_rows(sync_conn, existing_uuids, source=self.source.name)
        before_rows = sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
            (self.source.name,),
        ).fetchall()

        kept_uuid = existing_uuids[0]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record(kept_uuid)]),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "failed"
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after_rows = fresh.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
                (self.source.name,),
            ).fetchall()
            after_status = sync_status_row(fresh, source=self.source.name)
        assert after_rows == before_rows
        assert after_status["last_rebuild_error"] is not None
        assert after_status["last_rebuild_error"].startswith(
            "Full rebuild aborted — upstream would remove 999/1000 records by absence"
        )
        assert after_status["last_full_rebuild_date"] is None


class TestExplicitWithdrawalsBesideTheContractionGuard(SourceCase):
    """Check explicit Withdrawals Beside The Contraction Guard."""

    async def test_contraction_guard_counts_only_absence_based_removals(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Explicit removals do not contribute to inferred-deletion limits."""
        explicit_uuids = [f"oai:x:explicit-{i}" for i in range(3)]
        kept_uuids = [f"oai:x:kept-{i}" for i in range(5)]
        for uuid in explicit_uuids + kept_uuids:
            dataset_factory(uuid=uuid, source=self.source.name)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record(uuid) for uuid in kept_uuids],
                deleted_uuids=set(explicit_uuids),
            ),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        assert outcome.status == "success"
        for uuid in explicit_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source=self.source.name) == 0
        for uuid in kept_uuids:
            assert count_datasets(sync_conn, uuid=uuid, source=self.source.name) == 1

    async def test_write_failure_rolls_back_inferred_deletion_but_keeps_authoritative_withdrawal(
        self, db_pool, dataset_factory, monkeypatch
    ):
        """Unrelated writes cannot restore genuinely withdrawn upstream metadata."""
        explicit_uuid = "oai:x:explicit-rollback"
        inferred_stale_uuid = "oai:x:inferred-rollback"
        kept_uuid = "oai:x:kept-rollback"
        filler_uuids = [f"oai:x:filler-rollback-{i}" for i in range(4)]
        for uuid in (explicit_uuid, inferred_stale_uuid, kept_uuid, *filler_uuids):
            dataset_factory(uuid=uuid, source=self.source.name)

        original = sync_module._update_full_rebuild_timestamp

        async def broken_timestamp_update(*_args, **_kwargs):
            """Raise the injected post-guard status-write failure."""
            raise RuntimeError("injected post-guard write failure")

        monkeypatch.setattr(
            sync_module,
            "_update_full_rebuild_timestamp",
            create_autospec(original, side_effect=broken_timestamp_update),
        )

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
            await run_full_rebuild(db_pool, configured_source=self.source)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            assert count_datasets(fresh, uuid=explicit_uuid, source=self.source.name) == 0
            assert count_datasets(fresh, uuid=inferred_stale_uuid, source=self.source.name) == 1
            assert count_datasets(fresh, uuid=kept_uuid, source=self.source.name) == 1
            for uuid in filler_uuids:
                assert count_datasets(fresh, uuid=uuid, source=self.source.name) == 1


class TestAmbiguousEmptyHarvestGuard(SourceCase):
    """Check ambiguous Empty Harvest Guard."""

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
        """An ambiguous empty harvest preserves rows and completion timestamps."""
        dataset_factory(uuid="oai:x:precious-1", source=self.source.name)
        before = sync_status_row(sync_conn, source=self.source.name)

        with (
            caplog.at_level(logging.WARNING, logger="app.services.ingestion"),
            patch(FETCH, autospec=True, return_value=harvest),
        ):
            await run_full_rebuild(db_pool, configured_source=self.source)

        assert count_datasets(sync_conn, uuid="oai:x:precious-1") == 1
        assert any("Full rebuild aborted" in r.message for r in caplog.records)

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_rebuild_error"] is not None
        assert "0 matching records" in after["last_rebuild_error"]
        assert after["last_sync_error"] is None

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
        """Tombstones delete; filter exclusions withhold the retained record."""
        dataset_factory(uuid="oai:x:withdrawn", source=self.source.name)
        dataset_factory(uuid="oai:x:unmentioned", source=self.source.name)
        dataset_factory(uuid="oai:x:withdrawn", source="mock")
        before = sync_status_row(sync_conn, source=self.source.name)

        with patch(FETCH, autospec=True, return_value=harvest):
            await run_full_rebuild(db_pool, configured_source=self.source)

        assert count_datasets(
            sync_conn,
            uuid="oai:x:withdrawn",
            source=self.source.name,
        ) == int(bool(harvest.nonmatching_uuids))
        assert (
            count_datasets(
                sync_conn,
                uuid="oai:x:unmentioned",
                source=self.source.name,
            )
            == 1
        )
        assert count_datasets(sync_conn, uuid="oai:x:withdrawn", source="mock") == 1

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        assert after["last_rebuild_error"] is not None
        removals = int(bool(harvest.deleted_uuids))
        assert f"{removals} explicit source removal(s) applied" in after["last_rebuild_error"]
        quarantined = sync_conn.execute(
            "SELECT reason FROM ingestion_quarantine WHERE source = %s AND uuid = %s",
            (self.source.name, "oai:x:withdrawn"),
        ).fetchone()
        assert quarantined == (("filter_mismatch",) if harvest.nonmatching_uuids else None)
        assert after["last_sync_error"] is None


def _failing_record(uuid, failure_kind, *, title="old failed record"):
    """A parser-shaped record rejected by PostgreSQL after structural validation."""
    record = make_record(uuid, title=title)
    if failure_kind == "nul-array":
        record["authors"] = ["\x00"]
    else:
        assert failure_kind == "nul-text"
        record["description"] = "\x00"
    return record


def _threshold_records(offered, successful, failure_kind):
    """Build the requested mixture of successful and deliberately failing records."""
    records = [make_record(f"oai:threshold:good-{i}", title="new title") for i in range(successful)]
    records.extend(
        _failing_record(f"oai:threshold:bad-{i}", failure_kind) for i in range(offered - successful)
    )
    return records


def _contraction_guard_filler_count(anchor_existing_count):
    """Dilute one stale row to at most 25% without adding inferred deletions."""
    return max(0, 4 - anchor_existing_count)


def _seed_threshold_status(sync_conn, *, source: str):
    """Seed historical success times and both error channels for threshold assertions."""
    prior_time = datetime(2020, 1, 1, tzinfo=UTC)
    sync_conn.execute(
        """UPDATE sync_status
           SET last_harvest_date = %s,
               last_full_rebuild_date = %s,
               last_sync_error = 'prior incremental error',
               last_sync_error_at = %s,
               last_rebuild_error = 'prior rebuild error',
               last_rebuild_error_at = %s
           WHERE source = %s""",
        (prior_time, prior_time, prior_time, prior_time, source),
    )
    sync_conn.commit()
    status = sync_status_row(sync_conn, source=source)
    sync_conn.commit()
    return status


class TestSuccessRateThreshold(SourceCase):
    """Check success Rate Threshold."""

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
        """Too few successes roll back catalogue changes and timestamps."""
        dataset_factory(uuid="oai:x:pre-existing", source=self.source.name)
        dataset_factory(uuid="oai:mock:unrelated", source="mock")
        if successful > 1:
            dataset_factory(uuid="oai:threshold:good-1", source=self.source.name, title="old title")
        for i in range(offered - successful):
            dataset_factory(
                uuid=f"oai:threshold:bad-{i}", source=self.source.name, title="old failed record"
            )

        anchor_existing = 1 + (1 if successful > 1 else 0) + (offered - successful)
        filler = _contraction_guard_filler_count(anchor_existing)
        for i in range(filler):
            dataset_factory(
                uuid=f"oai:threshold:filler-{i}", source=self.source.name, title="old filler record"
            )
        total_offered = offered + filler

        before_rows = sync_conn.execute(
            "SELECT id, uuid, source, title FROM oral_history_datasets ORDER BY id"
        ).fetchall()
        sync_conn.commit()
        before = _seed_threshold_status(sync_conn, source=self.source.name)

        records = _threshold_records(offered, successful, failure_kind) + [
            _failing_record(f"oai:threshold:filler-{i}", failure_kind, title="old filler record")
            for i in range(filler)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            await run_full_rebuild(db_pool, configured_source=self.source)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after_rows = fresh.execute(
                "SELECT id, uuid, source, title FROM oral_history_datasets ORDER BY id"
            ).fetchall()
            after = sync_status_row(fresh, source=self.source.name)

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
        """At least half succeeds; valid writes commit and failed old rows survive."""
        dataset_factory(uuid="oai:x:stale", source=self.source.name)
        dataset_factory(uuid="oai:mock:unrelated", source="mock")
        dataset_factory(uuid="oai:threshold:good-0", source=self.source.name, title="old title")
        original_id = sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (self.source.name, "oai:threshold:good-0"),
        ).fetchone()[0]
        sync_conn.commit()
        for i in range(offered - successful):
            dataset_factory(
                uuid=f"oai:threshold:bad-{i}",
                source=self.source.name,
                title="old failed record",
            )

        anchor_existing = 2 + (offered - successful)
        filler = _contraction_guard_filler_count(anchor_existing)
        for i in range(filler):
            dataset_factory(
                uuid=f"oai:threshold:filler-{i}", source=self.source.name, title="old filler title"
            )

        before = _seed_threshold_status(sync_conn, source=self.source.name)
        records = _threshold_records(offered, successful, failure_kind) + [
            make_record(f"oai:threshold:filler-{i}", title="new filler title")
            for i in range(filler)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            await run_full_rebuild(db_pool, configured_source=self.source)

        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            after = sync_status_row(fresh, source=self.source.name)
            rows = fresh.execute(
                "SELECT id, uuid, title FROM oral_history_datasets WHERE source = %s",
                (self.source.name,),
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


@pytest.mark.parametrize(
    "uncertain_records,withdrawals,expected_uuids",
    [
        pytest.param(
            {"new-c": "invalid metadata"},
            set(),
            {"old-a", "old-b", "new-c"},
            id="retained-plus-new-failure",
        ),
        pytest.param({}, set(), {"old-a", "old-b"}, id="empty-response-retains-failures"),
        pytest.param(
            {"new-c": "invalid metadata"},
            {"old-a"},
            {"old-b", "new-c"},
            id="withdrawal-removes-old-failure",
        ),
        pytest.param(
            {"old-a": "updated diagnostic"},
            set(),
            {"old-a", "old-b"},
            id="existing-failure-counted-once",
        ),
        pytest.param({}, {"old-a", "old-b"}, set(), id="all-failures-withdrawn"),
    ],
)
async def test_empty_rebuild_reports_persisted_failure_count(
    db_pool,
    sync_conn,
    dataset_factory,
    sync_source,
    uncertain_records,
    withdrawals,
    expected_uuids,
):
    """Report all retained failures for this source, including older failures."""
    source = sync_source.name
    other_source = "unrelated_archive"
    for uuid in ("old-a", "old-b"):
        dataset_factory(uuid=uuid, source=source)

    with sync_conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO ingestion_failures (source, uuid, message) VALUES (%s, %s, %s)",
            [
                (source, "old-a", "previous failure"),
                (source, "old-b", "previous failure"),
                (other_source, "other-x", "unrelated failure"),
            ],
        )
    sync_conn.commit()

    with patch(
        FETCH,
        autospec=True,
        return_value=harvest_result(
            uncertain_records=uncertain_records,
            deleted_uuids=withdrawals,
        ),
    ):
        outcome = await run_full_rebuild(db_pool, configured_source=sync_source)

    rows = sync_conn.execute(
        "SELECT uuid FROM ingestion_failures WHERE source = %s",
        (source,),
    ).fetchall()
    actual_uuids = {row[0] for row in rows}
    assert actual_uuids == expected_uuids
    assert outcome.status == "failed"
    assert outcome.failed_count == len(actual_uuids)
    assert outcome.affected_count == len(withdrawals)
    assert count_datasets(sync_conn, source=source) == 2 - len(withdrawals)
    assert sync_conn.execute(
        "SELECT uuid, message FROM ingestion_failures WHERE source = %s",
        (other_source,),
    ).fetchall() == [("other-x", "unrelated failure")]
