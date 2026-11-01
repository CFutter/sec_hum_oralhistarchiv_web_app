"""Incremental ingestion regressions for each selected source against PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest
from lxml import etree

from app.services import ingestion
from app.services.db import get_db_cursor
from app.services.harvest import HarvestResult
from app.services.ingestion import (
    _sync_source,
    _upsert_public_catalogue_record,
    run_full_rebuild,
)
from app.services.schema import PARSER_OWNED
from app.services.source_fetch import run_source_fetch
from app.sources import ConfiguredSource, oai_client
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    ingestion_failure_uuids,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import (
    SOURCE_CURSOR,
    FakeOAIResponse,
    fetch_updates_in_process,
    patch_records,
    patch_session_get,
)
from tests.source_fixtures import TEST_INSTITUTION_FILTER, legacy_source


class SourceCase:
    """Attach the parametrized source to each ingestion test instance."""

    source: ConfiguredSource

    @pytest.fixture(autouse=True)
    def _select_source(self, sync_source):
        """Attach the parametrized source to this test instance."""
        self.source = sync_source


class TestMakeRecordHarness:
    """Check make Record Harness."""

    def test_make_record_matches_parser_contract(self):
        """Harness self-check: make_record emits exactly schema.PARSER_OWNED.

        If DATASET_COLUMNS / PARSER_OWNED drift, this fails first with a
        clear diff instead of every sync test failing on an opaque KeyError.
        """
        assert set(make_record("u")) == PARSER_OWNED


class TestUpsertBoundaryContract(SourceCase):
    """``_upsert_public_catalogue_record`` refuses a falsy uuid at the boundary."""

    async def test_upsert_raises_on_none_uuid_before_touching_table(self, db_pool, sync_conn):
        """uuid=None raises ValueError BEFORE any INSERT — a NULL-uuid row can
        never conflict-match and would duplicate on every sync."""
        with pytest.raises(ValueError, match="uuid"):
            async with get_db_cursor(db_pool) as cur:
                await _upsert_public_catalogue_record(
                    cur, make_record(uuid=None), self.source.policy
                )
        assert count_datasets(sync_conn) == 0

    async def test_upsert_raises_on_empty_uuid(self, db_pool, sync_conn):
        """An empty-string uuid is just as falsy — same ValueError, no row."""
        with pytest.raises(ValueError):
            async with get_db_cursor(db_pool) as cur:
                await _upsert_public_catalogue_record(cur, make_record(uuid=""), self.source.policy)
        assert count_datasets(sync_conn) == 0

    async def test_sync_loop_records_missing_uuid_as_failed_record(self, db_pool, sync_conn):
        """An invalid harvest identity fails validation before staging or writes.

        The fetch error records the identity failure without creating a row.
        """
        with patch(FETCH, autospec=True, return_value=harvest_result([make_record(uuid=None)])):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_sync_error"] is not None
        assert "fetch" in status["last_sync_error"]
        assert "identities" in status["last_sync_error"]
        assert count_datasets(sync_conn) == 0


class TestIncrementalHappyPath(SourceCase):
    """Policy tier, access classification, the migration-owned search
    trigger, and watermark timing on a clean incremental run."""

    async def test_incremental_sync_happy_path(self, db_pool, sync_conn):
        """Check incremental insertion, access classification, source scoping and progress."""
        configured_source = self.source
        fetch_returned_at = {}

        def fake_fetch(**_kwargs):
            # Capture t1 INSIDE the fake: the watermark must be <= this instant.
            """Return the case's synthetic harvest and apply its test-controlled synchronization."""
            fetch_returned_at["t1"] = datetime.now(UTC)
            return harvest_result(
                [
                    make_record(
                        uuid="oai:swissubase:aaa-1",
                        title="Restricted Interviews",
                        description="Testimony about the unmistakableword flood of 1962.",
                        license_val="Restricted access (special agreement)",
                        doi="10.1/aaa-1",
                    ),
                    make_record(
                        uuid="oai:swissubase:bbb-2",
                        title="Open Interviews",
                        license_val="CC BY 4.0",
                        doi="10.1/bbb-2",
                    ),
                ]
            )

        t0 = datetime.now(UTC)
        with patch(FETCH, autospec=True, side_effect=fake_fetch):
            await _sync_source(
                db_pool,
                configured_source=configured_source,
            )

        rows = sync_conn.execute(
            """SELECT uuid, source, visibility_tier, access_level,
                      search_text_public, search_text_full
               FROM oral_history_datasets ORDER BY uuid"""
        ).fetchall()
        assert len(rows) == 2
        by_uuid = {r[0]: r for r in rows}

        for r in rows:
            assert r[1] == self.source.name
            # Records without an explicit tier resolve to the selected policy ceiling.
            assert r[2] == configured_source.policy.max_visibility

        # License classification: 'Restricted access …' -> restricted; CC -> public.
        assert by_uuid["oai:swissubase:aaa-1"][3] == "restricted"
        assert by_uuid["oai:swissubase:bbb-2"][3] == "public"

        # Search trigger: full blob has the distinctive description word;
        # public blob has the title but NOT the description.
        _, _, _, _, pub, full = by_uuid["oai:swissubase:aaa-1"]
        assert "unmistakableword" in full
        assert "Restricted Interviews" in pub
        assert "unmistakableword" not in pub

        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_sync_error"] is None
        # Watermark: captured before the fetch, so t0 <= watermark <= t1.
        assert t0 <= status["last_harvest_date"] <= fetch_returned_at["t1"]

    async def test_sync_same_uuid_twice_updates_not_duplicates(self, db_pool, sync_conn):
        """Re-syncing a UUID updates the selected source's existing row."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:dup-1", title="Old Title")]),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:dup-1", title="New Title")]),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        rows = sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (self.source.name, "oai:x:dup-1"),
        ).fetchall()
        assert rows == [("New Title",)]
        assert count_datasets(sync_conn) == 1

    async def test_empty_incremental_poll_does_not_advance_source_cursor(self, db_pool, sync_conn):
        """A poll that returns no matching, deleted or nonmatching records still
        asks the harvest for everything since the last-known source cursor minus
        the overlap window, but leaves that stored cursor untouched — there is
        nothing new to advance the watermark to."""
        previous = datetime(2026, 1, 3, 18, tzinfo=UTC)
        sync_conn.execute(
            "UPDATE sync_status SET source_cursor = %s WHERE source = %s",
            (previous, self.source.name),
        )
        sync_conn.commit()
        with patch(FETCH, autospec=True, return_value=harvest_result()) as fetch:
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        assert fetch.call_args is not None
        assert fetch.call_args.kwargs["since"] == (previous - timedelta(days=2)).strftime(
            "%Y-%m-%d"
        )
        assert (
            sync_conn.execute(
                "SELECT source_cursor FROM sync_status WHERE source = %s",
                (self.source.name,),
            ).fetchone()[0]
            == previous
        )

    @pytest.mark.parametrize(
        "runner",
        [
            pytest.param(_sync_source, id="incremental"),
            pytest.param(run_full_rebuild, id="full-rebuild"),
        ],
    )
    async def test_source_a_upstream_redaction_clears_every_stored_copy(
        self,
        db_pool,
        sync_conn,
        runner,
    ):
        """Verify source a upstream redaction clears every stored copy."""
        uuid = "oai:x:upstream-redaction"
        marker = "source-a-sensitive-withdrawal-marker"
        original_modified_at = datetime(2026, 1, 2, tzinfo=UTC)
        corrected_modified_at = datetime(2026, 2, 3, tzinfo=UTC)
        original = make_record(
            uuid,
            title=f"Interview {marker}",
            project_title=marker,
            description=marker,
            resource_description=marker,
            languages=[marker],
            project_description=marker,
            authors=[marker],
            keywords=[marker],
            resource_proxies=[{"type": "LandingPage", "ref": f"https://example.org/{marker}"}],
            license_val=f"Restricted access {marker}",
            license_url=f"https://example.org/license/{marker}",
            version=marker,
            doi=f"10.1234/{marker}",
            resource_type=marker,
            institutions=[TEST_INSTITUTION_FILTER, marker],
            main_disciplines=[marker],
            bibliographical_citation=marker,
            upstream_modified_at=original_modified_at,
        )
        with patch(FETCH, autospec=True, return_value=harvest_result([original])):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        positive = sync_conn.execute(
            """SELECT uuid, title, project_title, description, resource_description,
                      languages, project_description, authors, keywords,
                      resource_proxies, license_val, license_url, access_level,
                      institutions, version, doi, resource_type, main_disciplines,
                      bibliographical_citation, source, visibility_tier,
                      upstream_modified_at, data::text, search_text_public,
                      search_text_full
               FROM oral_history_datasets
               WHERE source = %s AND uuid = %s""",
            (self.source.name, uuid),
        ).fetchone()
        assert positive is not None
        assert positive[12] == "restricted"
        assert positive[19] == self.source.name
        assert positive[20] == self.source.policy.max_visibility
        assert positive[21] == original_modified_at
        marker_bearing_indexes = (
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            13,
            14,
            15,
            16,
            17,
            18,
            22,
            23,
            24,
        )
        assert all(marker in str(positive[index]) for index in marker_bearing_indexes)

        corrected = make_record(
            uuid,
            title="Corrected public catalogue title",
            project_title=None,
            description=None,
            resource_description=None,
            languages=[],
            project_description=None,
            authors=[],
            keywords=[],
            resource_proxies=[],
            license_val=None,
            license_url=None,
            version=None,
            doi=None,
            resource_type=None,
            institutions=[TEST_INSTITUTION_FILTER],
            main_disciplines=[],
            bibliographical_citation=None,
            upstream_modified_at=corrected_modified_at,
        )
        with patch(FETCH, autospec=True, return_value=harvest_result([corrected])):
            await runner(db_pool, configured_source=self.source)

        row = sync_conn.execute(
            """SELECT uuid, title, project_title, description, resource_description,
                      languages, project_description, authors, keywords,
                      resource_proxies, license_val, license_url, access_level,
                      institutions, version, doi, resource_type, main_disciplines,
                      bibliographical_citation, source, visibility_tier,
                      upstream_modified_at, data::text, search_text_public,
                      search_text_full
               FROM oral_history_datasets
               WHERE source = %s AND uuid = %s""",
            (self.source.name, uuid),
        ).fetchone()
        assert row is not None
        assert row[:22] == (
            uuid,
            "Corrected public catalogue title",
            None,
            None,
            None,
            [],
            None,
            [],
            [],
            [],
            None,
            None,
            "restricted",
            [TEST_INSTITUTION_FILTER],
            None,
            None,
            None,
            [],
            None,
            self.source.name,
            self.source.policy.max_visibility,
            corrected_modified_at,
        )
        assert marker not in row[22]  # complete parsed record JSONB
        assert marker not in row[23]  # public trigger-derived search text
        assert marker not in row[24]  # full trigger-derived search text


class TestWithdrawals(SourceCase):
    """Tombstones and definitive filter mismatches on the incremental path."""

    async def test_tombstone_record_deletes_row(self, db_pool, sync_conn):
        """An OAI tombstone removes the corresponding source row."""
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:tomb-1")])
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        assert count_datasets(sync_conn, uuid="oai:x:tomb-1") == 1

        with patch(
            FETCH, autospec=True, return_value=harvest_result(deleted_uuids={"oai:x:tomb-1"})
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        assert count_datasets(sync_conn, uuid="oai:x:tomb-1") == 0
        assert sync_status_row(sync_conn, source=self.source.name)["last_sync_error"] is None

    async def test_tombstone_for_never_seen_uuid_is_a_clean_noop(self, db_pool, sync_conn):
        """OAI replays tombstones, so a delete for a uuid this instance
        never held must be a clean no-op — 0 rows deleted, no error recorded,
        the watermark still advances. Raising on a 0-row DELETE would turn
        routine replayed tombstones into a perpetual last_sync_error."""
        before = sync_status_row(sync_conn, source=self.source.name)["last_harvest_date"]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:never-existed"}),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        assert sync_status_row(sync_conn, source=self.source.name)["last_sync_error"] is None
        assert sync_status_row(sync_conn, source=self.source.name)["last_harvest_date"] > before

    async def test_tombstone_spares_foreign_source_row_sharing_its_uuid(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify tombstone spares foreign source row sharing its UUID."""
        dataset_factory(uuid="oai:x:cross-tomb", source="mock")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:cross-tomb"}),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:cross-tomb") == 1  # survives
        assert count_datasets(sync_conn, uuid="oai:x:cross-tomb", source="mock") == 1
        assert sync_status_row(sync_conn, source=self.source.name)["last_sync_error"] is None

    async def test_tombstone_still_deletes_same_source_row_with_that_uuid(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Verify tombstone still deletes same source row with that UUID."""
        dataset_factory(uuid="oai:x:cross-tomb", source=self.source.name)

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:cross-tomb"}),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:cross-tomb") == 0  # deleted
        assert sync_status_row(sync_conn, source=self.source.name)["last_sync_error"] is None

    async def test_incremental_nonmatching_record_withholds_only_source_row(
        self, db_pool, sync_conn, dataset_factory
    ):
        """A local filter exclusion retains the selected row under serving quarantine."""
        dataset_factory(uuid="oai:x:nonmatching", source=self.source.name)
        dataset_factory(uuid="oai:x:nonmatching", source="mock")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(nonmatching_uuids={"oai:x:nonmatching"}),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:nonmatching", source=self.source.name) == 1
        assert count_datasets(sync_conn, uuid="oai:x:nonmatching", source="mock") == 1
        assert sync_status_row(sync_conn, source=self.source.name)["last_sync_error"] is not None
        assert sync_conn.execute(
            "SELECT source, reason FROM ingestion_quarantine WHERE uuid = 'oai:x:nonmatching'"
        ).fetchall() == [(self.source.name, "filter_mismatch")]

    async def test_spaced_tombstone_deletes_live_record(self, db_pool, monkeypatch):
        """Whitespace-normalized tombstones delete the persisted live
        identifier — the identifier extracted from a tombstone header is
        stripped before matching."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "INSERT INTO oral_history_datasets (uuid, source, title) VALUES (%s, %s, 'Old')",
                ("oai:test:spaced", self.source.name),
            )
        xml = etree.fromstring(
            b'<record xmlns="http://www.openarchives.org/OAI/2.0/">'
            b'<header status="deleted"><identifier>  oai:test:spaced \n</identifier></header></record>'
        )
        monkeypatch.setattr(
            FETCH,
            create_autospec(
                oai_client.fetch_updates_isolated, side_effect=fetch_updates_in_process
            ),
        )
        with patch_records(return_value=[xml]):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "SELECT 1 FROM oral_history_datasets WHERE source = %s AND uuid = %s",
                (self.source.name, "oai:test:spaced"),
            )
            assert await cur.fetchone() is None

    async def test_many_unknown_filter_exclusions_advance_cursor_without_creating_state(
        self, db_pool, sync_conn
    ):
        """Unknown filter exclusions are clean progress, without retained per-identity state."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(nonmatching_uuids={f"other:{i}" for i in range(20000)}),
        ):
            outcome = await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        assert outcome.affected_count == 0
        assert outcome.status == "success"
        assert sync_conn.execute(
            "SELECT source_cursor FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone() == (SOURCE_CURSOR,)
        for table in ("ingestion_quarantine", "ingestion_failures", "source_security_state"):
            assert sync_conn.execute(
                f"SELECT count(*) FROM {table} WHERE source = %s", (self.source.name,)
            ).fetchone() == (0,)


class TestDoiCollision(SourceCase):
    """The self-diagnosing UniqueViolation branch on the incremental path."""

    async def test_doi_collision_skips_record_with_diagnostic_message(self, db_pool, sync_conn):
        """Verify doi collision skips record with diagnostic message."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("oai:x:orig-1", title="Original Version", doi="10.1/dup")]
            ),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        assert count_datasets(sync_conn, uuid="oai:x:orig-1") == 1

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    # colliding record FIRST — proves the follow-up record still lands
                    make_record("oai:x:newver-2", title="New Version", doi="10.1/dup"),
                    make_record("oai:x:innocent-3", title="Innocent Bystander", doi="10.1/other"),
                ]
            ),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        # Colliding record skipped; original intact; batch-mate landed.
        assert count_datasets(sync_conn, uuid="oai:x:newver-2") == 0
        assert sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (self.source.name, "oai:x:orig-1"),
        ).fetchone() == ("Original Version",)
        assert count_datasets(sync_conn, uuid="oai:x:innocent-3") == 1

        err = sync_status_row(sync_conn, source=self.source.name)["last_sync_error"]
        assert err is not None
        assert "DOI collision" in err
        assert "reused an existing" in err
        assert "oai:x:newver-2" in err


class TestSameHarvestDoiReplacement(SourceCase):
    """A withdrawn predecessor and its DOI successor inside one harvest."""

    @pytest.mark.parametrize(
        "withdrawal",
        ["deleted_uuids", "nonmatching_uuids"],
        ids=["predecessor_tombstoned", "predecessor_filtered_out"],
    )
    async def test_same_harvest_replaces_a_doi_predecessor(
        self, db_pool, sync_conn, dataset_factory, monkeypatch, withdrawal
    ):
        """Only an authoritative tombstone frees the predecessor's DOI ownership."""
        dataset_factory(source=self.source.name, uuid="old-uuid", doi="10.1234/shared")
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[make_record("new-uuid", doi="10.1234/shared")],
            **{withdrawal: {"old-uuid"}},
        )
        monkeypatch.setattr(
            ingestion, "run_source_fetch", create_autospec(run_source_fetch, return_value=harvest)
        )
        result = await ingestion.run_sync(
            db_pool,
            configured_source=self.source,
        )
        if withdrawal == "nonmatching_uuids":
            assert result.status == "partial" and result.affected_count == 0
            assert sync_conn.execute(
                "SELECT uuid FROM oral_history_datasets WHERE source = %s", (self.source.name,)
            ).fetchall() == [("old-uuid",)]
            assert sync_conn.execute(
                "SELECT uuid, reason FROM ingestion_quarantine WHERE source = %s",
                (self.source.name,),
            ).fetchall() == [("old-uuid", "filter_mismatch")]
            assert ingestion_failure_uuids(sync_conn, source=self.source.name) == {
                "old-uuid",
                "new-uuid",
            }
            return
        assert result.status == "success"
        assert result.affected_count == 2
        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = %s",
            (self.source.name,),
        ).fetchall() == [("new-uuid",)]
        assert (
            sync_conn.execute(
                "SELECT uuid FROM ingestion_failures WHERE source = %s",
                (self.source.name,),
            ).fetchall()
            == []
        )
        assert ingestion_failure_uuids(sync_conn, source=self.source.name) == set()


class TestPerRecordResilience(SourceCase):
    """Per-record fault isolation and watermark discipline in the
    incremental loop."""

    async def test_incremental_sync_survives_one_broken_record(self, db_pool, sync_conn):
        """A PostgreSQL-rejected record is isolated and recorded as failed.

        Both healthy neighbours still land.
        """
        broken = make_record("oai:x:broken-2")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [
                    make_record("oai:x:good-1"),
                    broken,
                    make_record("oai:x:good-3"),
                ]
            ),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        assert count_datasets(sync_conn, uuid="oai:x:good-1") == 1
        assert count_datasets(sync_conn, uuid="oai:x:good-3") == 1
        assert count_datasets(sync_conn, uuid="oai:x:broken-2") == 0

        err = sync_status_row(sync_conn, source=self.source.name)["last_sync_error"]
        assert err is not None
        assert "oai:x:broken-2" in err

    async def test_watermark_is_pinned_by_per_record_failures(self, db_pool, sync_conn):
        """A per-record failure among an otherwise successful batch still
        holds the watermark back, even though the successful record lands."""
        broken = make_record("oai:x:broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.
        before = sync_status_row(sync_conn, source=self.source.name)["last_harvest_date"]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:ok"), broken]),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )
        status = sync_status_row(sync_conn, source=self.source.name)
        assert count_datasets(sync_conn, uuid="oai:x:ok") == 1
        assert "oai:x:broken" in status["last_sync_error"]
        assert status["last_harvest_date"] == before

    async def test_malformed_incremental_response_records_error_and_holds_watermark(
        self,
        db_pool,
        sync_conn,
    ):
        """A well-formed but non-OAI HTTP 200 response is a fetch failure.

        The incremental watermark must not advance, and an unrelated rebuild
        error must remain untouched.
        """
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                """UPDATE sync_status
                   SET last_sync_error = 'stale incremental fetch error',
                       last_sync_error_at = CURRENT_TIMESTAMP,
                       last_rebuild_error = 'existing rebuild error',
                       last_rebuild_error_at = CURRENT_TIMESTAMP
                   WHERE source = %s""",
                (self.source.name,),
            )

        before = sync_status_row(sync_conn, source=self.source.name)

        malformed_body = b"<html><body>maintenance</body></html>"
        patcher, mock_get = patch_session_get(
            return_value=FakeOAIResponse(malformed_body),
        )

        with (
            patcher,
            patch(FETCH, autospec=True, side_effect=fetch_updates_in_process),
        ):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        after = sync_status_row(sync_conn, source=self.source.name)

        assert mock_get.call_count == 1
        assert after["last_harvest_date"] == before["last_harvest_date"]

        assert after["last_sync_error"] is not None
        assert after["last_sync_error"].startswith("Incremental sync (fetch):")
        assert "malformed_response" in after["last_sync_error"]
        assert after["last_sync_error_at"] is not None

        assert after["last_rebuild_error"] == before["last_rebuild_error"]
        assert after["last_rebuild_error_at"] == before["last_rebuild_error_at"]

    async def test_transient_fetch_error_recovers_after_quiet_upstream(self, db_pool, sync_conn):
        """A transient incremental fetch failure is recorded with the
        'Incremental sync (fetch):' prefix and holds the watermark back; a
        later EMPTY successful sync — days of quiet upstream — clears the
        channel instead of leaving /health/detail 'degraded' forever."""
        before = sync_status_row(sync_conn, source=self.source.name)["last_harvest_date"]

        with patch(FETCH, autospec=True, side_effect=RuntimeError("flaky network")):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_sync_error"] is not None
        assert status["last_sync_error"].startswith("Incremental sync (fetch):")
        assert status["last_harvest_date"] == before  # fetch failure holds the watermark

        with patch(FETCH, autospec=True, return_value=harvest_result()):
            await _sync_source(
                db_pool,
                configured_source=self.source,
            )

        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_sync_error"] is None
        assert status["last_harvest_date"] > before


class TestTransactionalWriteFaults(SourceCase):
    """The write phase commits one batch/record at a time, so a mid-run
    failure discards only the work in flight, and a persisted write fault
    lands on the health channel of the path (incremental or full-rebuild)
    that produced it."""

    async def test_repeated_write_deadlines_resume_the_tail_without_refetching(
        self, db_pool, sync_conn, monkeypatch
    ):
        """Verify repeated write deadlines resume the tail without refetching."""
        harvest = harvest_result([make_record(f"resume-{i}") for i in range(3)])
        fetch = create_autospec(run_source_fetch, return_value=harvest)
        monkeypatch.setattr(ingestion, "run_source_fetch", fetch)
        configured_source = legacy_source(
            name=self.source.name, schedule={"write_timeout_seconds": 1}
        )
        monkeypatch.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
        original = ingestion._upsert_public_catalogue_record
        writes_this_run = 0

        async def one_then_block(*args):
            """Perform one real write, then block indefinitely on the second call."""
            nonlocal writes_this_run
            writes_this_run += 1
            if writes_this_run == 2:
                await asyncio.Event().wait()
            return await original(*args)

        monkeypatch.setattr(
            ingestion,
            "_upsert_public_catalogue_record",
            create_autospec(original, side_effect=one_then_block),
        )
        # One actual connection throughout, like the advisory-lock-owning
        # scheduler: call the connection-level entry point directly rather
        # than run_sync (which acquires its own lock connection from a pool).
        # Each failed transaction must leave this connection usable for
        # reporting.
        async with db_pool.connection() as connection:
            for expected_count in (1, 2):
                writes_this_run = 0
                with pytest.raises(TimeoutError):
                    await ingestion._run_sync_on_locked_connection(
                        connection,
                        configured_source=configured_source,
                    )
                assert (
                    sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0]
                    == expected_count
                )
                state = sync_conn.execute(
                    "SELECT incremental_position, source_cursor, last_sync_error "
                    "FROM sync_status WHERE source = %s",
                    (self.source.name,),
                ).fetchone()
                assert state[0] == expected_count
                assert state[1] is None
                assert "TimeoutError" in state[2]
                sync_conn.commit()
            writes_this_run = 0
            result = await ingestion._run_sync_on_locked_connection(
                connection,
                configured_source=configured_source,
            )
        assert result.status == "success" and result.affected_count == 3
        fetch.assert_awaited_once()
        assert sync_conn.execute(
            "SELECT incremental_harvest, incremental_position, source_cursor, last_sync_error "
            "FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone() == (None, 0, harvest.source_cursor, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 3

    @pytest.mark.parametrize(
        "run",
        [
            pytest.param(ingestion.run_sync, id="incremental"),
            pytest.param(ingestion.run_full_rebuild, id="full-rebuild"),
        ],
    )
    async def test_write_fault_persists_its_health_channel_after_rollback(
        self, db_pool, sync_conn, monkeypatch, run
    ):
        """A write fault raised out of the top-level entry point rolls back
        every row of that run and records the error on ONLY the health
        channel belonging to the path that failed, leaving the other
        channel untouched."""
        monkeypatch.setattr(
            ingestion,
            "run_source_fetch",
            create_autospec(run_source_fetch, return_value=harvest_result([make_record("fault")])),
        )

        original = ingestion._upsert_public_catalogue_record

        async def broken_write(*_args):
            """Raise the injected catalogue-write failure."""
            raise RuntimeError("injected write failure")

        monkeypatch.setattr(
            ingestion,
            "_upsert_public_catalogue_record",
            create_autospec(original, side_effect=broken_write),
        )
        with pytest.raises(RuntimeError, match="injected write failure"):
            await run(db_pool, configured_source=self.source)
        incremental, full = sync_conn.execute(
            "SELECT last_sync_error, last_rebuild_error FROM sync_status WHERE source = %s",
            (self.source.name,),
        ).fetchone()
        rebuild = run is ingestion.run_full_rebuild
        assert "injected write failure" in (full if rebuild else incremental)
        assert (incremental if rebuild else full) is None
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0
