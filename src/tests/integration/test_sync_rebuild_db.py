"""Integration tests for full rebuilds under each selected source identity."""

from datetime import UTC, datetime
from unittest.mock import create_autospec, patch

import psycopg
import pytest
from psycopg import sql

from app.services import ingestion
from app.services.datasets import get_last_full_rebuild_date
from app.services.db import get_db_cursor
from app.services.ingestion import _sync_source, run_full_rebuild
from app.sources import ConfiguredSource
from app.sources.oai_client import OAI_NS
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    FakeOAIResponse,
    fetch_updates_in_process,
    patch_session_get,
)

from .conftest import TEST_DATABASE_URL


class SourceCase:
    """Run each scenario with the configured source supplied by the matrix fixture."""

    source: ConfiguredSource

    @pytest.fixture(autouse=True)
    def _select_source(self, sync_source):
        """Attach the parametrized source to this test instance."""
        self.source = sync_source


class TestRebuildReconciliation(SourceCase):
    """Check rebuild Reconciliation."""

    async def test_full_rebuild_reconciles_source_scoped_and_advances_timestamps(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify full rebuild reconciles source scoped and advances timestamps."""
        # The contraction guard (ingestion.py:289-326) refuses to infer-delete more
        # than 25% of the selected source's rows in one rebuild. Three rows that
        # stay offered dilute the one truly stale row ("oai:x:old-X") to
        # 1/4 = 25%, at the limit rather than over it, so the reconciliation
        # under test runs instead of tripping the guard first.
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:old-X", title="Stale X"),
                    make_record("oai:x:stays-1", title="Stays 1"),
                    make_record("oai:x:stays-2", title="Stays 2"),
                    make_record("oai:x:stays-3", title="Stays 3"),
                ]
            ),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        dataset_factory(uuid="oai:mock:keep-me", source="mock")

        before = sync_status_row(sync_conn, source=self.source.name)
        assert before["last_full_rebuild_date"] is None

        rebuild_t0 = datetime.now(UTC)
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:new-Y", title="Fresh Y"),
                    make_record("oai:x:stays-1", title="Stays 1"),
                    make_record("oai:x:stays-2", title="Stays 2"),
                    make_record("oai:x:stays-3", title="Stays 3"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:old-X") == 0  # stale gone
        assert count_datasets(sync_conn, uuid="oai:x:new-Y") == 1  # fresh in
        assert count_datasets(sync_conn, uuid="oai:x:stays-1") == 1  # re-offered row kept
        assert count_datasets(sync_conn, uuid="oai:mock:keep-me") == 1  # other source kept

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_full_rebuild_date"] is not None
        assert after["last_full_rebuild_date"] >= rebuild_t0
        assert after["last_harvest_date"] >= rebuild_t0
        assert after["last_harvest_date"] > before["last_harvest_date"]
        # Both stamped from the same harvest_started_at instant.
        assert after["last_harvest_date"] == after["last_full_rebuild_date"]

    async def test_full_rebuild_preserves_ids_and_reaps_unoffered(self, db_pool, sync_conn):
        """A uuid offered by consecutive rebuilds keeps its id (ON CONFLICT
        (source, uuid) updates in place — externally held /dataset/{id}
        links survive the nightly rebuild), while a uuid upstream stops
        offering is reaped by the stale-delete."""
        # Dilute the contraction guard (ingestion.py:289-326): two more rows
        # re-offered unchanged in both rebuilds keep the one truly unoffered
        # row ("oai:x:gone-1") at 1/4 = 25% of existing rows in the second
        # rebuild, at the limit rather than over it.
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:stable-1", title="v1"),
                    make_record("oai:x:gone-1"),
                    make_record("oai:x:stable-2", title="unchanged"),
                    make_record("oai:x:stable-3", title="unchanged"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )
        id_before = sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = 'oai:x:stable-1'",
            (self.source.name,),
        ).fetchone()[0]

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:stable-1", title="v2"),
                    make_record("oai:x:stable-2", title="unchanged"),
                    make_record("oai:x:stable-3", title="unchanged"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        row = sync_conn.execute(
            "SELECT id, title FROM oral_history_datasets "
            "WHERE source = %s AND uuid = 'oai:x:stable-1'",
            (self.source.name,),
        ).fetchone()
        assert row == (id_before, "v2")  # same id, updated content
        assert count_datasets(sync_conn, uuid="oai:x:gone-1") == 0

    async def test_full_rebuild_resolves_doi_collision_in_one_pass(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify full rebuild resolves doi collision in one pass."""
        dataset_factory(uuid="oai:x:old-ver", source=self.source.name, doi="10.5/reused")
        # Dilute the contraction guard (ingestion.py:289-326): three more
        # pre-existing rows stay offered (protected), keeping the one truly
        # stale row ("oai:x:old-ver") at 1/4 = 25% of existing rows, at the
        # limit rather than over it.
        dataset_factory(uuid="oai:x:doi-stays-1", source=self.source.name)
        dataset_factory(uuid="oai:x:doi-stays-2", source=self.source.name)
        dataset_factory(uuid="oai:x:doi-stays-3", source=self.source.name)
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:new-ver", doi="10.5/reused"),  # old-ver NOT offered
                    make_record("oai:x:doi-stays-1"),
                    make_record("oai:x:doi-stays-2"),
                    make_record("oai:x:doi-stays-3"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:new-ver") == 1
        assert count_datasets(sync_conn, uuid="oai:x:old-ver") == 0
        assert count_datasets(sync_conn, uuid="oai:x:doi-stays-1") == 1  # re-offered row kept
        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_rebuild_error"] is None  # no unique-violation skip
        assert status["last_sync_error"] is None

    async def test_full_rebuild_failed_record_keeps_previous_version(self, db_pool, sync_conn):
        """Verify full rebuild failed record keeps previous version."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:keeper", title="old good")]),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        broken = make_record("oai:x:keeper", title="new broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    broken,
                    make_record("oai:x:filler-1"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        row = sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = 'oai:x:keeper'",
            (self.source.name,),
        ).fetchone()
        assert row == ("old good",)  # old version survived the failed upsert
        assert count_datasets(sync_conn, uuid="oai:x:filler-1") == 1
        assert "oai:x:keeper" in (
            sync_status_row(sync_conn, source=self.source.name)["last_rebuild_error"] or ""
        )

    @pytest.mark.parametrize(
        "size",
        [2, 3],
        ids=["two_way_swap", "three_way_cycle"],
    )
    async def test_full_rebuild_reconciles_doi_swap_cycles_without_changing_ids(
        self, db_pool, sync_conn, dataset_factory, size
    ):
        """Verify full rebuild reconciles doi swap cycles without changing IDs."""
        ids = [
            dataset_factory(uuid=f"cycle:{i}", source=self.source.name, doi=f"10.1234/{i}")
            for i in range(size)
        ]
        records = [
            make_record(f"cycle:{i}", doi=f"https://doi.org/10.1234/{(i + 1) % size}")
            for i in range(size)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            outcome = await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )
        assert outcome.status == "success"
        rows = sync_conn.execute(
            "SELECT id, doi, source FROM oral_history_datasets ORDER BY id"
        ).fetchall()
        assert rows == [
            (ids[i], f"10.1234/{(i + 1) % size}", self.source.name) for i in range(size)
        ]


class TestRebuildFaultIsolation(SourceCase):
    """Check rebuild Fault Isolation."""

    async def test_full_rebuild_savepoint_isolates_broken_record(self, db_pool, dataset_factory):
        """Verify full rebuild savepoint isolates broken record."""
        dataset_factory(uuid="oai:x:pre-rebuild", source=self.source.name)
        # Dilute the contraction guard (ingestion.py:289-326): three more
        # pre-existing rows stay offered (protected), so the one truly stale
        # row is 1/4 = 25% of the selected source's rows, at the limit rather
        # than over it.
        dataset_factory(uuid="oai:x:sp-stays-1", source=self.source.name)
        dataset_factory(uuid="oai:x:sp-stays-2", source=self.source.name)
        dataset_factory(uuid="oai:x:sp-stays-3", source=self.source.name)

        broken = make_record("oai:x:sp-broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:sp-good-1"),
                    broken,
                    make_record("oai:x:sp-good-2"),
                    make_record("oai:x:sp-stays-1"),
                    make_record("oai:x:sp-stays-2"),
                    make_record("oai:x:sp-stays-3"),
                ]
            ),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        # A NEW connection proves the transaction committed (not just visible
        # from an in-flight snapshot).
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            uuids = {
                r[0]
                for r in fresh.execute(
                    "SELECT uuid FROM oral_history_datasets WHERE source = %s",
                    (self.source.name,),
                ).fetchall()
            }
            err = fresh.execute(
                "SELECT last_rebuild_error FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()[0]

        assert uuids == {
            "oai:x:sp-good-1",
            "oai:x:sp-good-2",
            "oai:x:sp-stays-1",
            "oai:x:sp-stays-2",
            "oai:x:sp-stays-3",
        }
        assert err is not None
        assert "oai:x:sp-broken" in err
        assert "ABORTED" not in err  # committed run records via the normal context

    async def test_full_rebuild_fetch_failure_keeps_data(self, db_pool, sync_conn, dataset_factory):
        """If the harvest itself raises, nothing is deleted and the error is
        recorded on the REBUILD channel with the 'Full rebuild:' prefix; the
        incremental channel stays untouched."""
        dataset_factory(uuid="oai:x:survivor-1", source=self.source.name)

        with patch(FETCH, autospec=True, side_effect=RuntimeError("upstream exploded")):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:survivor-1") == 1
        status = sync_status_row(sync_conn, source=self.source.name)
        err = status["last_rebuild_error"]
        assert err is not None
        assert err.startswith("Full rebuild:")
        assert "upstream exploded" in err
        assert status["last_sync_error"] is None

    async def test_full_rebuild_malformed_second_page_keeps_existing_data(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
    ):
        """A valid first page followed by a malformed page must not
        reconcile against the partial result set."""
        dataset_factory(
            uuid="oai:x:must-survive",
            source=self.source.name,
            title="Existing dataset",
        )
        before = sync_status_row(sync_conn, source=self.source.name)

        first_page = (
            f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate>'
            "<ListRecords>"
            f"{SAMPLE_CMDI_XML}"
            "<resumptionToken>T1</resumptionToken>"
            "</ListRecords>"
            "</OAI-PMH>"
        ).encode()

        malformed_second_page = b"<html><body>maintenance</body></html>"

        patcher, mock_get = patch_session_get(
            side_effect=[
                FakeOAIResponse(first_page),
                FakeOAIResponse(malformed_second_page),
            ],
        )

        with (
            patcher,
            patch(FETCH, autospec=True, side_effect=fetch_updates_in_process),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        after = sync_status_row(sync_conn, source=self.source.name)

        assert mock_get.call_count == 2

        assert count_datasets(sync_conn, uuid="oai:x:must-survive") == 1

        # No partial record was applied either.
        assert (
            count_datasets(
                sync_conn,
                uuid="oai:swissubase.ch:test-uuid-xml",
            )
            == 0
        )

        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]

        assert after["last_rebuild_error"] is not None
        assert after["last_rebuild_error"].startswith("Full rebuild:")
        assert "malformed_response" in after["last_rebuild_error"]

    async def test_full_rebuild_all_inserts_fail_rolls_back_and_records(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify full rebuild all inserts fail rolls back and records."""
        dataset_factory(uuid="oai:x:precious-1", source=self.source.name)
        # Dilute the contraction guard (ingestion.py:289-326): three more
        # pre-existing rows stay offered (protected — and, like the doomed
        # ones, blocked by the same check constraint), so the one truly
        # stale row is 1/4 = 25% of the selected source's rows, at the limit
        # rather than over it.
        dataset_factory(uuid="oai:x:filler-1", source=self.source.name)
        dataset_factory(uuid="oai:x:filler-2", source=self.source.name)
        dataset_factory(uuid="oai:x:filler-3", source=self.source.name)
        before = sync_status_row(sync_conn, source=self.source.name)

        sync_conn.commit()
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(
                sql.SQL(
                    "ALTER TABLE oral_history_datasets "
                    "ADD CONSTRAINT tmp_block_writes "
                    "CHECK (source <> {}) NOT VALID"
                ).format(sql.Literal(self.source.name))
            )
            conn.commit()
        try:
            with patch(
                FETCH,
                autospec=True,
                return_value=harvest_result(
                    [
                        make_record("oai:x:doomed-1"),
                        make_record("oai:x:doomed-2"),
                        make_record("oai:x:filler-1"),
                        make_record("oai:x:filler-2"),
                        make_record("oai:x:filler-3"),
                    ]
                ),
            ):
                await run_full_rebuild(
                    db_pool,
                    configured_source=self.source,
                )
        finally:
            with psycopg.connect(TEST_DATABASE_URL) as conn:
                conn.execute("ALTER TABLE oral_history_datasets DROP CONSTRAINT tmp_block_writes")
                conn.commit()

        # The stale-delete was rolled back: the unoffered row survives, as
        # does every offered-but-doomed row (nothing was actually deleted or
        # written).
        assert count_datasets(sync_conn, uuid="oai:x:precious-1") == 1
        assert count_datasets(sync_conn, uuid="oai:x:filler-1") == 1
        assert count_datasets(sync_conn, uuid="oai:x:doomed-1") == 0

        after = sync_status_row(sync_conn, source=self.source.name)
        assert after["last_full_rebuild_date"] == before["last_full_rebuild_date"]
        # The abort must not reset the incremental cursor either.
        assert after["last_harvest_date"] == before["last_harvest_date"]
        assert after["last_rebuild_error"] is not None
        assert "ABORTED" in after["last_rebuild_error"]
        assert "0/5" in after["last_rebuild_error"]  # 0 successes of 5 offered records
        assert after["last_sync_error"] is None  # incremental channel untouched

    async def test_zero_live_withdrawal_commits_before_status_recording(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
    ):
        """A later status failure cannot roll back a withdrawal: the
        zero-live path intentionally commits its exact source deletion
        before opening the dedicated transaction used by
        _record_sync_error()."""
        dataset_factory(uuid="oai:x:withdrawn-before-status-error", source=self.source.name)

        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result(deleted_uuids={"oai:x:withdrawn-before-status-error"}),
            ),
            patch(
                "app.services.ingestion._record_sync_error",
                autospec=True,
                side_effect=RuntimeError("simulated status transaction failure"),
            ),
            pytest.raises(RuntimeError, match="simulated status transaction failure"),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        assert (
            count_datasets(
                sync_conn,
                uuid="oai:x:withdrawn-before-status-error",
                source=self.source.name,
            )
            == 0
        )

    @pytest.mark.parametrize(
        "failure",
        ["invalid_record", "duplicate_doi", "uncertain_owner"],
        ids=["invalid_record_write_failure", "duplicate_doi_in_group", "uncertain_owner_record"],
    )
    async def test_full_rebuild_failed_doi_group_preserves_previous_assignments(
        self, db_pool, sync_conn, dataset_factory, failure, monkeypatch
    ):
        """Verify full rebuild failed doi group preserves previous assignments."""
        dataset_factory(uuid="a", source=self.source.name, doi="10.1234/a")
        dataset_factory(uuid="b", source=self.source.name, doi="10.1234/b")
        records = [make_record("a", doi="10.1234/b"), make_record("b", doi="10.1234/a")]
        uncertain = {}
        if failure == "invalid_record":
            original = ingestion._upsert_public_catalogue_record

            async def reject_second(cur, record, policy):
                """Perform the real upsert and raise IntegrityError for the marked second record."""
                result = await original(cur, record, policy)
                if record["uuid"] == "b":
                    raise psycopg.IntegrityError("injected replacement failure")
                return result

            monkeypatch.setattr(
                ingestion,
                "_upsert_public_catalogue_record",
                create_autospec(original, side_effect=reject_second),
            )
        elif failure == "duplicate_doi":
            records[1]["doi"] = "10.1234/b"
        else:
            records.pop()
            uncertain = {"b": "unreadable"}
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(records, uncertain_records=uncertain),
        ):
            outcome = await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )
        assert outcome.status == "failed"
        assert sync_conn.execute(
            "SELECT uuid, doi, source FROM oral_history_datasets ORDER BY uuid"
        ).fetchall() == [
            ("a", "10.1234/a", self.source.name),
            ("b", "10.1234/b", self.source.name),
        ]

    async def test_full_rebuild_status_failure_rolls_back_catalogue_and_completion(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify full rebuild status failure rolls back catalogue and completion."""
        dataset_factory(uuid="a", source=self.source.name, title="Old")
        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result([make_record("a", title="New")]),
            ),
            patch(
                "app.services.ingestion._clear_sync_error",
                autospec=True,
                side_effect=psycopg.OperationalError("lost"),
            ),
            pytest.raises(psycopg.OperationalError),
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )
        assert sync_conn.execute("SELECT title, source FROM oral_history_datasets").fetchone() == (
            "Old",
            self.source.name,
        )
        assert sync_conn.execute(
            "SELECT last_full_rebuild_date FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone() == (None,)

    async def test_partial_rebuild_replaces_resolved_old_failures_with_current_failures(
        self, db_pool, sync_conn
    ):
        """Unresolved-identity records live in ingestion_failures, not a sync_status
        column (ingestion.py:360-503): a full rebuild replaces the prior failure set for
        the source with exactly the current run's failures."""
        sync_conn.execute(
            "INSERT INTO ingestion_failures (source, uuid, message) VALUES "
            "(%s, %s, %s), (%s, %s, %s)",
            (self.source.name, "fixed", "old error", self.source.name, "absent", "old error"),
        )
        previous = datetime(2026, 1, 1, tzinfo=UTC)
        sync_conn.execute(
            "UPDATE sync_status SET source_cursor = %s WHERE source = %s",
            (previous, self.source.name),
        )
        sync_conn.commit()
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("fixed")], uncertain_records={"still-broken": "invalid metadata"}
            ),
        ):
            await ingestion._full_rebuild_source(
                db_pool,
                configured_source=self.source,
            )
        failures = sync_conn.execute(
            "SELECT uuid, message FROM ingestion_failures WHERE source = %s ORDER BY uuid",
            (self.source.name,),
        ).fetchall()
        assert failures == [("still-broken", "invalid metadata")]
        stored_cursor = sync_conn.execute(
            "SELECT source_cursor FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone()[0]
        assert stored_cursor == previous


class TestRebuildChannelIsolation(SourceCase):
    """The rebuild and incremental diagnostic channels stay independent,
    except that a clean rebuild resolves a prior incremental failure it has
    since re-verified."""

    async def test_incremental_failure_never_masks_rebuild_abort(self, db_pool, sync_conn):
        """With a rebuild ABORT recorded, an incremental run with failing
        records writes its record errors to the INCREMENTAL channel and
        leaves the rebuild channel's message — the most important error in
        the system — fully intact."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """UPDATE sync_status
                   SET last_rebuild_error = 'Full rebuild ABORTED — 0/9 inserted, stale-delete rolled back, existing data kept: 9 record(s) failed',
                       last_rebuild_error_at = CURRENT_TIMESTAMP
                   WHERE source = %s""",
                (self.source.name,),
            )

        broken = make_record("oai:x:inc-broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.
        with patch(FETCH, autospec=True, return_value=harvest_result([broken])):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        status = sync_status_row(sync_conn, source=self.source.name)
        assert "oai:x:inc-broken" in (status["last_sync_error"] or "")
        assert "ABORTED" in status["last_rebuild_error"]  # untouched

    async def test_clean_rebuild_clears_both_channels(self, db_pool, sync_conn):
        """Verify clean rebuild clears both channels."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """UPDATE sync_status
                   SET last_sync_error = 'Incremental sync (fetch): boom',
                       last_sync_error_at = CURRENT_TIMESTAMP,
                       last_rebuild_error = 'Full rebuild: upstream returned 0 live records',
                       last_rebuild_error_at = CURRENT_TIMESTAMP
                   WHERE source = %s""",
                (self.source.name,),
            )

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:clean-1")])
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_rebuild_error"] is None  # own channel cleared
        assert status["last_rebuild_error_at"] is None
        assert status["last_sync_error"] is None  # resolved incremental failure also cleared
        assert status["last_sync_error_at"] is None


class TestLastFullRebuildDatePublication(SourceCase):
    """``get_last_full_rebuild_date`` once raised NameError ('timezone' was
    never imported in datasets.py), 500-ing the home page as soon as any
    full rebuild had ever completed."""

    async def test_get_last_full_rebuild_date_none_before_any_rebuild(self, db_pool):
        """Fresh sync_status (last_full_rebuild_date NULL) -> None, no crash."""
        assert (
            await get_last_full_rebuild_date(
                db_pool,
                source_names=(self.source.name,),
            )
            is None
        )

    async def test_get_last_full_rebuild_date_formats_after_rebuild(self, db_pool):
        """After a successful rebuild it must return the display datetime."""
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:rebuilt-1")])
        ):
            await run_full_rebuild(
                db_pool,
                configured_source=self.source,
            )

        rebuilt_at = await get_last_full_rebuild_date(
            db_pool,
            source_names=(self.source.name,),
        )
        assert rebuilt_at is not None
