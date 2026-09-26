"""Integration tests for the full-rebuild Source A reconciliation.

Covers ``app.services.sync._full_rebuild_source_a`` / ``run_full_rebuild``:
source-scoped stale-delete plus upsert, timestamp publication, per-record
SAVEPOINT isolation, fetch/parse failures, DOI-collision resolution in one
pass, id preservation across rebuilds, and the two diagnostic channels
staying independent except where a clean rebuild resolves a prior
incremental failure. Abort/commit threshold guards live in
``test_sync_rebuild_thresholds_db.py``; the plain incremental mechanics live
in ``test_sync_incremental_db.py``.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import psycopg
import pytest

from app.services import oai_client, sync
from app.services.datasets import get_last_full_rebuild_date
from app.services.db import get_db_cursor
from app.services.oai_client import OAI_NS
from app.services.sync import _sync_source_a, run_full_rebuild
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import SAMPLE_CMDI_XML, FakeOAIResponse, patch_session_get

from .conftest import TEST_DATABASE_URL


class TestRebuildReconciliation:
    async def test_full_rebuild_reconciles_source_scoped_and_advances_timestamps(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Full rebuild reconciles: swissubase rows whose uuid upstream no
        longer OFFERS are stale-deleted (the mock-source row is untouched —
        the delete is source-scoped), offered records upsert in place, and
        _update_full_rebuild_timestamp advances BOTH last_full_rebuild_date
        and last_harvest_date (the incremental cursor resets to the rebuild
        instant)."""
        # The contraction guard (sync.py:289-326) refuses to infer-delete more
        # than 25% of existing Source A rows in one rebuild. Three rows that
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
            await _sync_source_a(db_pool)
        dataset_factory(uuid="oai:mock:keep-me", source="mock")

        before = sync_status_row(sync_conn)
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
            await run_full_rebuild(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:old-X") == 0  # stale gone
        assert count_datasets(sync_conn, uuid="oai:x:new-Y") == 1  # fresh in
        assert count_datasets(sync_conn, uuid="oai:x:stays-1") == 1  # re-offered row kept
        assert count_datasets(sync_conn, uuid="oai:mock:keep-me") == 1  # other source kept

        after = sync_status_row(sync_conn)
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
        # Dilute the contraction guard (sync.py:289-326): two more rows
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
            await run_full_rebuild(db_pool)
        id_before = sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE uuid = 'oai:x:stable-1'"
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
            await run_full_rebuild(db_pool)

        row = sync_conn.execute(
            "SELECT id, title FROM oral_history_datasets WHERE uuid = 'oai:x:stable-1'"
        ).fetchone()
        assert row == (id_before, "v2")  # same id, updated content
        assert count_datasets(sync_conn, uuid="oai:x:gone-1") == 0

    async def test_full_rebuild_resolves_doi_collision_in_one_pass(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Ordering pin: the stale-delete runs BEFORE the upserts precisely
        so a re-minted uuid reusing its predecessor's DOI can insert cleanly
        within the SAME rebuild (the resolution _sync_source_a's
        DOI-collision message promises). Moving the stale-delete after the
        loop would record a doi unique violation here instead of a clean
        run."""
        dataset_factory(uuid="oai:x:old-ver", source="swissubase", doi="10.5/reused")
        # Dilute the contraction guard (sync.py:289-326): three more
        # pre-existing rows stay offered (protected), keeping the one truly
        # stale row ("oai:x:old-ver") at 1/4 = 25% of existing rows, at the
        # limit rather than over it.
        dataset_factory(uuid="oai:x:doi-stays-1", source="swissubase")
        dataset_factory(uuid="oai:x:doi-stays-2", source="swissubase")
        dataset_factory(uuid="oai:x:doi-stays-3", source="swissubase")
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
            await run_full_rebuild(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:new-ver") == 1
        assert count_datasets(sync_conn, uuid="oai:x:old-ver") == 0
        assert count_datasets(sync_conn, uuid="oai:x:doi-stays-1") == 1  # re-offered row kept
        status = sync_status_row(sync_conn)
        assert status["last_rebuild_error"] is None  # no unique-violation skip
        assert status["last_sync_error"] is None

    async def test_full_rebuild_failed_record_keeps_previous_version(self, db_pool, sync_conn):
        """Keep-list pin: the stale-delete keep-list is what upstream
        OFFERED, never what inserted successfully — a record that is
        offered but fails to write must leave its previous version standing
        (stale-but-present), not be reaped. The filler record gives one
        success out of two offered records, meeting the exactly-half
        threshold so the rebuild commits."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:keeper", title="old good")]),
        ):
            await run_full_rebuild(db_pool)

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
            await run_full_rebuild(db_pool)

        row = sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE uuid = 'oai:x:keeper'"
        ).fetchone()
        assert row == ("old good",)  # old version survived the failed upsert
        assert count_datasets(sync_conn, uuid="oai:x:filler-1") == 1
        assert "oai:x:keeper" in (sync_status_row(sync_conn)["last_rebuild_error"] or "")

    @pytest.mark.parametrize(
        "size",
        [2, 3],
        ids=["two_way_swap", "three_way_cycle"],
    )
    async def test_full_rebuild_reconciles_doi_swap_cycles_without_changing_ids(
        self, db_pool, sync_conn, dataset_factory, size
    ):
        """A cycle of DOI reassignments — each record claims the DOI its
        predecessor in the cycle is giving up — resolves within a single
        rebuild pass and keeps every dataset's id, generalizing the
        two-record swap pinned by
        test_full_rebuild_resolves_doi_collision_in_one_pass to longer
        cycles."""
        ids = [
            dataset_factory(uuid=f"cycle:{i}", source="swissubase", doi=f"10.1234/{i}")
            for i in range(size)
        ]
        records = [
            make_record(f"cycle:{i}", doi=f"https://doi.org/10.1234/{(i + 1) % size}")
            for i in range(size)
        ]
        with patch(FETCH, autospec=True, return_value=harvest_result(records)):
            outcome = await run_full_rebuild(db_pool)
        assert outcome.status == "success"
        rows = sync_conn.execute("SELECT id, doi FROM oral_history_datasets ORDER BY id").fetchall()
        assert rows == [(ids[i], f"10.1234/{(i + 1) % size}") for i in range(size)]


class TestRebuildFaultIsolation:
    async def test_full_rebuild_savepoint_isolates_broken_record(self, db_pool, dataset_factory):
        """One malformed record rolls back only its own SAVEPOINT: both
        healthy records are present AND COMMITTED (visible from a
        brand-new connection), the pre-existing row is gone BECAUSE upstream
        no longer offered its uuid (stale-delete, not a blanket wipe — the
        offered-but-failed case is pinned separately by
        test_full_rebuild_failed_record_keeps_previous_version), and the
        failure is recorded on the REBUILD channel. 2 of 3 offered records
        succeed, meeting the at-least-half policy, so the rebuild commits."""
        dataset_factory(uuid="oai:x:pre-rebuild", source="swissubase")
        # Dilute the contraction guard (sync.py:289-326): three more
        # pre-existing rows stay offered (protected), so the one truly stale
        # row is 1/4 = 25% of existing Source A rows, at the limit rather
        # than over it.
        dataset_factory(uuid="oai:x:sp-stays-1", source="swissubase")
        dataset_factory(uuid="oai:x:sp-stays-2", source="swissubase")
        dataset_factory(uuid="oai:x:sp-stays-3", source="swissubase")

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
            await run_full_rebuild(db_pool)

        # A NEW connection proves the transaction committed (not just visible
        # from an in-flight snapshot).
        with psycopg.connect(TEST_DATABASE_URL) as fresh:
            uuids = {
                r[0]
                for r in fresh.execute(
                    "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase'"
                ).fetchall()
            }
            err = fresh.execute(
                "SELECT last_rebuild_error FROM sync_status WHERE id = 1"
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
        dataset_factory(uuid="oai:x:survivor-1", source="swissubase")

        with patch(FETCH, autospec=True, side_effect=RuntimeError("upstream exploded")):
            await run_full_rebuild(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:survivor-1") == 1
        status = sync_status_row(sync_conn)
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
            source="swissubase",
            title="Existing dataset",
        )
        before = sync_status_row(sync_conn)

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
            patch(FETCH, new=oai_client.fetch_updates),
        ):
            await run_full_rebuild(db_pool)

        after = sync_status_row(sync_conn)

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
        """When every offered record fails to write (systemic condition —
        schema outran the sync code, mass encoding change, ...), the
        rebuild aborts via _RebuildAborted: the stale-delete is rolled back
        (existing rows survive, even ones upstream no longer offers),
        NEITHER timestamp advances, and the abort is recorded on the
        REBUILD channel with the success/offered counts. Zero of two
        successes is below half.

        Uses a NOT VALID check constraint: existing rows are unchecked, but
        every new swissubase write violates it — exactly the
        all-inserts-fail shape. The try/finally DROP is mandatory: TRUNCATE
        isolation does not undo DDL, and a leaked constraint would poison
        every later dataset-writing test in the session."""
        dataset_factory(uuid="oai:x:precious-1", source="swissubase")
        # Dilute the contraction guard (sync.py:289-326): three more
        # pre-existing rows stay offered (protected — and, like the doomed
        # ones, blocked by the same check constraint), so the one truly
        # stale row is 1/4 = 25% of existing Source A rows, at the limit
        # rather than over it.
        dataset_factory(uuid="oai:x:filler-1", source="swissubase")
        dataset_factory(uuid="oai:x:filler-2", source="swissubase")
        dataset_factory(uuid="oai:x:filler-3", source="swissubase")
        before = sync_status_row(sync_conn)

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(
                "ALTER TABLE oral_history_datasets ADD CONSTRAINT tmp_block_writes "
                "CHECK (source <> 'swissubase') NOT VALID"
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
                await run_full_rebuild(db_pool)
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

        after = sync_status_row(sync_conn)
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
        dataset_factory(uuid="oai:x:withdrawn-before-status-error", source="swissubase")

        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result(deleted_uuids={"oai:x:withdrawn-before-status-error"}),
            ),
            patch(
                "app.services.sync._record_sync_error",
                autospec=True,
                side_effect=RuntimeError("simulated status transaction failure"),
            ),
            pytest.raises(RuntimeError, match="simulated status transaction failure"),
        ):
            await run_full_rebuild(db_pool)

        assert (
            count_datasets(
                sync_conn,
                uuid="oai:x:withdrawn-before-status-error",
                source="swissubase",
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
        """A DOI-correction group that cannot be applied cleanly — a write
        failure partway through the group, a duplicate final DOI within the
        group, or an uncertain-owner record dropped from the offer — leaves
        every dataset's previous uuid/DOI assignment exactly as it was; the
        group's SAVEPOINT rolls back as a unit instead of partially
        applying."""
        dataset_factory(uuid="a", source="swissubase", doi="10.1234/a")
        dataset_factory(uuid="b", source="swissubase", doi="10.1234/b")
        records = [make_record("a", doi="10.1234/b"), make_record("b", doi="10.1234/a")]
        uncertain = {}
        if failure == "invalid_record":
            original = sync._upsert_public_catalogue_record

            async def reject_second(cur, record, policy):
                await original(cur, record, policy)
                if record["uuid"] == "b":
                    raise psycopg.IntegrityError("injected replacement failure")

            monkeypatch.setattr(sync, "_upsert_public_catalogue_record", reject_second)
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
            outcome = await run_full_rebuild(db_pool)
        assert outcome.status == "failed"
        assert sync_conn.execute(
            "SELECT uuid, doi FROM oral_history_datasets ORDER BY uuid"
        ).fetchall() == [("a", "10.1234/a"), ("b", "10.1234/b")]

    async def test_full_rebuild_status_failure_rolls_back_catalogue_and_completion(
        self, db_pool, sync_conn, dataset_factory
    ):
        """The catalogue write and the rebuild-completion timestamp update
        share one transaction: if clearing the rebuild's own error channel
        fails after a successful reconciliation, the whole rebuild rolls
        back — the catalogue keeps its previous version and
        last_full_rebuild_date is NOT advanced. The zero-live-withdrawal
        path is the only intentional exception to this
        (test_zero_live_withdrawal_commits_before_status_recording)."""
        dataset_factory(uuid="a", source="swissubase", title="Old")
        with (
            patch(
                FETCH,
                autospec=True,
                return_value=harvest_result([make_record("a", title="New")]),
            ),
            patch(
                "app.services.sync._clear_sync_error",
                autospec=True,
                side_effect=psycopg.OperationalError("lost"),
            ),
            pytest.raises(psycopg.OperationalError),
        ):
            await run_full_rebuild(db_pool)
        assert sync_conn.execute("SELECT title FROM oral_history_datasets").fetchone() == ("Old",)
        assert sync_conn.execute("SELECT last_full_rebuild_date FROM sync_status").fetchone() == (
            None,
        )

    async def test_partial_rebuild_replaces_resolved_old_failures_with_current_failures(
        self, db_pool, sync_conn
    ):
        """Unresolved-identity records live in ingestion_failures, not a sync_status
        column (sync.py:360-503): a full rebuild replaces the prior failure set for
        the source with exactly the current run's failures."""
        sync_conn.execute(
            "INSERT INTO ingestion_failures (source, uuid, message) VALUES "
            "(%s, %s, %s), (%s, %s, %s)",
            ("swissubase", "fixed", "old error", "swissubase", "absent", "old error"),
        )
        sync_conn.execute(
            "UPDATE sync_status SET source_cursor = %s", (datetime(2026, 1, 1, tzinfo=UTC),)
        )
        sync_conn.commit()
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("fixed")], uncertain_records={"still-broken": "invalid metadata"}
            ),
        ):
            await sync._full_rebuild_source_a(db_pool)
        failures = sync_conn.execute(
            "SELECT uuid, message FROM ingestion_failures WHERE source = 'swissubase' ORDER BY uuid"
        ).fetchall()
        assert failures == [("still-broken", "invalid metadata")]
        source_cursor = sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone()[0]
        assert source_cursor == datetime(2026, 1, 1, tzinfo=UTC)


class TestRebuildChannelIsolation:
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
                   WHERE id = 1"""
            )

        broken = make_record("oai:x:inc-broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.
        with patch(FETCH, autospec=True, return_value=harvest_result([broken])):
            await _sync_source_a(db_pool)

        status = sync_status_row(sync_conn)
        assert "oai:x:inc-broken" in (status["last_sync_error"] or "")
        assert "ABORTED" in status["last_rebuild_error"]  # untouched

    async def test_clean_rebuild_clears_both_channels(self, db_pool, sync_conn):
        """A rebuild with no failed record clears BOTH diagnostic channels.

        docs/architecture/sync.md:124-129: "After an accepted rebuild,
        unresolved state is exactly its current failure set" — a clean
        rebuild has an empty failure set, so both the rebuild channel
        (sync.py:1163-1164) and any stale incremental channel entry it
        resolves (sync.py:499-501) are cleared. Only the REVERSE direction
        is forbidden: a clean incremental poll must never erase a failed
        rebuild (test_incremental_failure_never_masks_rebuild_abort is that
        positive control for the guard)."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """UPDATE sync_status
                   SET last_sync_error = 'Incremental sync (fetch): boom',
                       last_sync_error_at = CURRENT_TIMESTAMP,
                       last_rebuild_error = 'Full rebuild: upstream returned 0 live records',
                       last_rebuild_error_at = CURRENT_TIMESTAMP
                   WHERE id = 1"""
            )

        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:clean-1")])
        ):
            await run_full_rebuild(db_pool)

        status = sync_status_row(sync_conn)
        assert status["last_rebuild_error"] is None  # own channel cleared
        assert status["last_rebuild_error_at"] is None
        assert status["last_sync_error"] is None  # resolved incremental failure also cleared
        assert status["last_sync_error_at"] is None


class TestLastFullRebuildDatePublication:
    """``get_last_full_rebuild_date`` once raised NameError ('timezone' was
    never imported in datasets.py), 500-ing the home page as soon as any
    full rebuild had ever completed."""

    async def test_get_last_full_rebuild_date_none_before_any_rebuild(self, db_pool):
        """Fresh sync_status (last_full_rebuild_date NULL) -> None, no crash."""
        assert await get_last_full_rebuild_date(db_pool) is None

    async def test_get_last_full_rebuild_date_formats_after_rebuild(self, db_pool):
        """After a successful rebuild it must return the display datetime."""
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:rebuilt-1")])
        ):
            await run_full_rebuild(db_pool)

        rebuilt_at = await get_last_full_rebuild_date(db_pool)
        assert rebuilt_at is not None
