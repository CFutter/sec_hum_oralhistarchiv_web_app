"""Integration tests for the incremental Source A sync against real PostgreSQL.

Covers ``app.services.sync._sync_source_a``: the record-upsert boundary
contract, the happy path (policy tier, access classification, the
migration-owned search trigger, watermark timing), replay/idempotency,
upstream redaction, tombstones and other withdrawals, DOI collisions, and
per-record resilience of the incremental loop. Full-rebuild scenarios live in
``test_sync_rebuild_db.py`` and ``test_sync_rebuild_thresholds_db.py``;
reconciliation of ambiguous/uncertain records lives in
``test_sync_uncertain_reconciliation_db.py``.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest
from lxml import etree
from starlette.concurrency import run_in_threadpool

from app.services import oai_client, sync
from app.services.db import get_db_cursor
from app.services.schema import PARSER_OWNED
from app.services.sync import (
    _SWISSUBASE_POLICY,
    _sync_source_a,
    _upsert_public_catalogue_record,
    run_full_rebuild,
)
from config import settings
from tests.integration.sync_doubles import (
    FETCH,
    count_datasets,
    harvest_result,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import SOURCE_CURSOR, FakeOAIResponse, patch_records, patch_session_get


class TestMakeRecordHarness:
    def test_make_record_matches_parser_contract(self):
        """Harness self-check: make_record emits exactly schema.PARSER_OWNED.

        If DATASET_COLUMNS / PARSER_OWNED drift, this fails first with a
        clear diff instead of every sync test failing on an opaque KeyError.
        """
        assert set(make_record("u")) == PARSER_OWNED


class TestUpsertBoundaryContract:
    """``_upsert_public_catalogue_record`` refuses a falsy uuid at the boundary."""

    async def test_upsert_raises_on_none_uuid_before_touching_table(self, db_pool, sync_conn):
        """uuid=None raises ValueError BEFORE any INSERT — a NULL-uuid row can
        never conflict-match and would duplicate on every sync."""
        with pytest.raises(ValueError, match="uuid"):
            async with get_db_cursor(db_pool) as cur:
                await _upsert_public_catalogue_record(
                    cur, make_record(uuid=None), _SWISSUBASE_POLICY
                )
        assert count_datasets(sync_conn) == 0

    async def test_upsert_raises_on_empty_uuid(self, db_pool, sync_conn):
        """An empty-string uuid is just as falsy — same ValueError, no row."""
        with pytest.raises(ValueError):
            async with get_db_cursor(db_pool) as cur:
                await _upsert_public_catalogue_record(cur, make_record(uuid=""), _SWISSUBASE_POLICY)
        assert count_datasets(sync_conn) == 0

    async def test_sync_loop_records_missing_uuid_as_failed_record(self, db_pool, sync_conn):
        """Through the loop: a no-uuid record is skipped-and-recorded — the
        sync COMPLETES and last_sync_error carries the '<no-uuid>' marker
        instead of the whole run aborting or duplicates accumulating."""
        with patch(FETCH, autospec=True, return_value=harvest_result([make_record(uuid=None)])):
            await _sync_source_a(db_pool)

        status = sync_status_row(sync_conn)
        assert status["last_sync_error"] is not None
        assert "fetch" in status["last_sync_error"]
        assert "identities" in status["last_sync_error"]
        assert count_datasets(sync_conn) == 0


class TestIncrementalHappyPath:
    """Policy tier, access classification, the migration-owned search
    trigger, and watermark timing on a clean incremental run."""

    async def test_incremental_sync_happy_path(self, db_pool, sync_conn):
        """Two records land with source='swissubase'; visibility resolves through
        the source POLICY ceiling (settings.swissubase_max_visibility — records
        carry no tier of their own); access_level derives from the license text;
        the SEARCH TRIGGER (defined only in the migration — schema source of
        truth) fills search_text_full with the description but keeps it OUT of
        search_text_public; the watermark lands between call start and fetch
        return (captured BEFORE the fetch); error state clears."""
        fetch_returned_at = {}

        def fake_fetch(**_kwargs):
            # Capture t1 INSIDE the fake: the watermark must be <= this instant.
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
            await _sync_source_a(db_pool)

        rows = sync_conn.execute(
            """SELECT uuid, source, visibility_tier, access_level,
                      search_text_public, search_text_full
               FROM oral_history_datasets ORDER BY uuid"""
        ).fetchall()
        assert len(rows) == 2
        by_uuid = {r[0]: r for r in rows}

        for r in rows:
            assert r[1] == "swissubase"
            # Records carry visibility_tier=None -> resolve_tier returns the
            # policy ceiling, which is settings.swissubase_max_visibility
            # ('vetted' in the default test env).
            assert r[2] == settings.swissubase_max_visibility

        # License classification: 'Restricted access …' -> restricted; CC -> public.
        assert by_uuid["oai:swissubase:aaa-1"][3] == "restricted"
        assert by_uuid["oai:swissubase:bbb-2"][3] == "public"

        # Search trigger: full blob has the distinctive description word;
        # public blob has the title but NOT the description.
        _, _, _, _, pub, full = by_uuid["oai:swissubase:aaa-1"]
        assert "unmistakableword" in full
        assert "Restricted Interviews" in pub
        assert "unmistakableword" not in pub

        status = sync_status_row(sync_conn)
        assert status["last_sync_error"] is None
        # Watermark: captured before the fetch, so t0 <= watermark <= t1.
        assert t0 <= status["last_harvest_date"] <= fetch_returned_at["t1"]

    async def test_sync_same_uuid_twice_updates_not_duplicates(self, db_pool, sync_conn):
        """ON CONFLICT (source, uuid) DO UPDATE: re-syncing the same uuid with
        a changed title updates the single existing row instead of inserting
        a second."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:dup-1", title="Old Title")]),
        ):
            await _sync_source_a(db_pool)
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:dup-1", title="New Title")]),
        ):
            await _sync_source_a(db_pool)

        rows = sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE uuid = %s", ("oai:x:dup-1",)
        ).fetchall()
        assert rows == [("New Title",)]
        assert count_datasets(sync_conn) == 1

    async def test_empty_incremental_poll_does_not_advance_source_cursor(self, db_pool, sync_conn):
        """A poll that returns no matching, deleted or nonmatching records still
        asks the harvest for everything since the last-known source cursor minus
        the overlap window, but leaves that stored cursor untouched — there is
        nothing new to advance the watermark to."""
        previous = datetime(2026, 1, 3, 18, tzinfo=UTC)
        sync_conn.execute("UPDATE sync_status SET source_cursor=%s", (previous,))
        sync_conn.commit()
        with patch(FETCH, autospec=True, return_value=harvest_result()) as fetch:
            await _sync_source_a(db_pool)
        assert fetch.call_args.kwargs["since"] == (previous - timedelta(days=2)).strftime(
            "%Y-%m-%d"
        )
        assert sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone()[0] == previous


class TestUpstreamRedactionPropagation:
    @pytest.mark.parametrize(
        "runner",
        [
            pytest.param(_sync_source_a, id="incremental"),
            pytest.param(run_full_rebuild, id="full-rebuild"),
        ],
    )
    async def test_source_a_upstream_redaction_clears_every_stored_copy(
        self,
        db_pool,
        sync_conn,
        runner,
    ):
        """A correction replaces normalized, raw and derived copies, whether
        the correction lands via the incremental loop or a full rebuild.

        The Source A database is a source-authoritative cache. A correction
        that merely clears the rendered column but leaves the previous value
        in JSONB or trigger-maintained search text would retain withdrawn
        metadata.
        """
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
            institutions=[settings.oai_institution_filter, marker],
            main_disciplines=[marker],
            bibliographical_citation=marker,
            upstream_modified_at=original_modified_at,
        )
        with patch(FETCH, autospec=True, return_value=harvest_result([original])):
            await _sync_source_a(db_pool)

        positive = sync_conn.execute(
            """SELECT uuid, title, project_title, description, resource_description,
                      languages, project_description, authors, keywords,
                      resource_proxies, license_val, license_url, access_level,
                      institutions, version, doi, resource_type, main_disciplines,
                      bibliographical_citation, source, visibility_tier,
                      upstream_modified_at, data::text, search_text_public,
                      search_text_full
               FROM oral_history_datasets
               WHERE source = 'swissubase' AND uuid = %s""",
            (uuid,),
        ).fetchone()
        assert positive is not None
        assert positive[12] == "restricted"
        assert positive[19] == "swissubase"
        assert positive[20] == _SWISSUBASE_POLICY.max_visibility
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
            institutions=[settings.oai_institution_filter],
            main_disciplines=[],
            bibliographical_citation=None,
            upstream_modified_at=corrected_modified_at,
        )
        with patch(FETCH, autospec=True, return_value=harvest_result([corrected])):
            await runner(db_pool)

        row = sync_conn.execute(
            """SELECT uuid, title, project_title, description, resource_description,
                      languages, project_description, authors, keywords,
                      resource_proxies, license_val, license_url, access_level,
                      institutions, version, doi, resource_type, main_disciplines,
                      bibliographical_citation, source, visibility_tier,
                      upstream_modified_at, data::text, search_text_public,
                      search_text_full
               FROM oral_history_datasets
               WHERE source = 'swissubase' AND uuid = %s""",
            (uuid,),
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
            "public",
            [settings.oai_institution_filter],
            None,
            None,
            None,
            [],
            None,
            "swissubase",
            _SWISSUBASE_POLICY.max_visibility,
            corrected_modified_at,
        )
        assert marker not in row[22]  # complete parsed record JSONB
        assert marker not in row[23]  # public trigger-derived search text
        assert marker not in row[24]  # full trigger-derived search text


class TestWithdrawals:
    """Tombstones and definitive filter mismatches on the incremental path."""

    async def test_tombstone_record_deletes_row(self, db_pool, sync_conn):
        """An OAI tombstone removes the corresponding source row."""
        with patch(
            FETCH, autospec=True, return_value=harvest_result([make_record("oai:x:tomb-1")])
        ):
            await _sync_source_a(db_pool)
        assert count_datasets(sync_conn, uuid="oai:x:tomb-1") == 1

        with patch(
            FETCH, autospec=True, return_value=harvest_result(deleted_uuids={"oai:x:tomb-1"})
        ):
            await _sync_source_a(db_pool)
        assert count_datasets(sync_conn, uuid="oai:x:tomb-1") == 0
        assert sync_status_row(sync_conn)["last_sync_error"] is None

    async def test_tombstone_for_never_seen_uuid_is_a_clean_noop(self, db_pool, sync_conn):
        """OAI replays tombstones, so a delete for a uuid this instance
        never held must be a clean no-op — 0 rows deleted, no error recorded,
        the watermark still advances. Raising on a 0-row DELETE would turn
        routine replayed tombstones into a perpetual last_sync_error."""
        before = sync_status_row(sync_conn)["last_harvest_date"]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:never-existed"}),
        ):
            await _sync_source_a(db_pool)

        assert sync_status_row(sync_conn)["last_sync_error"] is None
        assert sync_status_row(sync_conn)["last_harvest_date"] > before

    async def test_tombstone_spares_foreign_source_row_sharing_its_uuid(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Cross-source data loss on the INCREMENTAL tombstone path —
        without the 'AND source =' predicate on the tombstone DELETE, a
        replayed Source A tombstone would silently destroy ANY row that
        happens to share its uuid, wiping another source's catalogue entry.
        (The REBUILD path's source-scoping is pinned separately in
        test_sync_rebuild_db.py. Positive control for the survival
        assertion: the same-source twin below.)"""
        dataset_factory(uuid="oai:x:cross-tomb", source="mock")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:cross-tomb"}),
        ):
            await _sync_source_a(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:cross-tomb") == 1  # survives
        assert sync_status_row(sync_conn)["last_sync_error"] is None

    async def test_tombstone_still_deletes_same_source_row_with_that_uuid(
        self, db_pool, sync_conn, dataset_factory
    ):
        """Identical tombstone, identical row differing ONLY in
        source='swissubase': the DELETE must fire. Pins the second half of
        the 'AND source =' predicate, so an over-scoped 'fix' that stops the
        incremental tombstone from deleting anything at all fails here
        instead of quietly accumulating upstream-deleted records."""
        dataset_factory(uuid="oai:x:cross-tomb", source="swissubase")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(deleted_uuids={"oai:x:cross-tomb"}),
        ):
            await _sync_source_a(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:cross-tomb") == 0  # deleted
        assert sync_status_row(sync_conn)["last_sync_error"] is None

    async def test_incremental_nonmatching_record_removes_only_source_row(
        self, db_pool, sync_conn, dataset_factory
    ):
        """A definite filter mismatch is an authoritative Source A removal."""
        dataset_factory(uuid="oai:x:nonmatching", source="swissubase")
        dataset_factory(uuid="oai:x:nonmatching", source="mock")

        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(nonmatching_uuids={"oai:x:nonmatching"}),
        ):
            await _sync_source_a(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:nonmatching", source="swissubase") == 0
        assert count_datasets(sync_conn, uuid="oai:x:nonmatching", source="mock") == 1
        assert sync_status_row(sync_conn)["last_sync_error"] is None

    async def test_spaced_tombstone_deletes_live_record(self, db_pool, monkeypatch):
        """Whitespace-normalized tombstones delete the persisted live
        identifier — the identifier extracted from a tombstone header is
        stripped before matching."""
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "INSERT INTO oral_history_datasets (uuid, source, title) VALUES (%s, 'swissubase', 'Old')",
                ("oai:test:spaced",),
            )
        xml = etree.fromstring(
            b'<record xmlns="http://www.openarchives.org/OAI/2.0/">'
            b'<header status="deleted"><identifier>  oai:test:spaced \n</identifier></header></record>'
        )
        monkeypatch.setattr("app.services.sync.fetch_updates_isolated", oai_client.fetch_updates)
        with patch_records(return_value=[xml]):
            await _sync_source_a(db_pool)
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "SELECT 1 FROM oral_history_datasets WHERE uuid = %s", ("oai:test:spaced",)
            )
            assert await cur.fetchone() is None

    async def test_many_unrelated_withdrawals_advance_cursor_without_claiming_changes(
        self, db_pool, sync_conn
    ):
        """20,000 upstream withdrawals for uuids this instance never held (a
        large definitive-mismatch batch) apply as a clean no-op: nothing is
        claimed as a change, the run still reports success, and the
        incremental cursor still advances to the harvest's source_cursor."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(nonmatching_uuids={f"other:{i}" for i in range(20000)}),
        ):
            outcome = await _sync_source_a(db_pool)
        assert outcome.affected_count == 0
        assert outcome.status == "success"
        assert sync_conn.execute("SELECT source_cursor FROM sync_status").fetchone() == (
            SOURCE_CURSOR,
        )


class TestDoiCollision:
    """The self-diagnosing UniqueViolation branch on the incremental path."""

    async def test_doi_collision_skips_record_with_diagnostic_message(self, db_pool, sync_conn):
        """Upstream minted a new uuid but reused an existing doi: the doi
        UNIQUE constraint blocks the new version; the sync records the
        self-diagnosing 'DOI collision' message naming the new uuid, keeps
        the original row, and still lands the other record of the same
        batch (per-record isolation)."""
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result(
                [make_record("oai:x:orig-1", title="Original Version", doi="10.1/dup")]
            ),
        ):
            await _sync_source_a(db_pool)
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
            await _sync_source_a(db_pool)

        # Colliding record skipped; original intact; batch-mate landed.
        assert count_datasets(sync_conn, uuid="oai:x:newver-2") == 0
        assert sync_conn.execute(
            "SELECT title FROM oral_history_datasets WHERE uuid = %s", ("oai:x:orig-1",)
        ).fetchone() == ("Original Version",)
        assert count_datasets(sync_conn, uuid="oai:x:innocent-3") == 1

        err = sync_status_row(sync_conn)["last_sync_error"]
        assert err is not None
        assert "DOI collision" in err
        assert "reused an existing" in err
        assert "oai:x:newver-2" in err


class TestSameHarvestDoiReplacement:
    """A withdrawn predecessor and its DOI successor inside one harvest."""

    @pytest.mark.parametrize(
        "withdrawal",
        ["deleted_uuids", "nonmatching_uuids"],
        ids=["predecessor_tombstoned", "predecessor_filtered_out"],
    )
    async def test_same_harvest_replaces_a_doi_predecessor(
        self, db_pool, sync_conn, dataset_factory, monkeypatch, withdrawal
    ):
        """Withdrawals in a harvest batch apply before the batch's inserts,
        so a successor record reusing its predecessor's DOI lands instead of
        colliding with the still-present old row — whether the predecessor
        leaves via an OAI tombstone (deleted_uuids) or a definitive filter
        mismatch (nonmatching_uuids) in that same batch."""
        dataset_factory(source="swissubase", uuid="old-uuid", doi="10.1234/shared")
        harvest = oai_client.HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[make_record("new-uuid", doi="10.1234/shared")],
            **{withdrawal: {"old-uuid"}},
        )
        monkeypatch.setattr(
            sync, "run_in_threadpool", create_autospec(run_in_threadpool, return_value=harvest)
        )
        result = await sync.run_sync(db_pool)
        assert result.status == "success"
        assert result.affected_count == 2
        assert sync_conn.execute(
            "SELECT uuid FROM oral_history_datasets WHERE source = 'swissubase'"
        ).fetchall() == [("new-uuid",)]
        assert sync_conn.execute("SELECT incremental_failures FROM sync_status").fetchone() == ({},)


class TestPerRecordResilience:
    """Per-record fault isolation and watermark discipline in the
    incremental loop."""

    async def test_incremental_sync_survives_one_broken_record(self, db_pool, sync_conn):
        """A record missing a PARSER_OWNED key (parser-contract drift ->
        KeyError) is skipped-and-recorded; both healthy neighbours still
        land."""
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
            await _sync_source_a(db_pool)

        assert count_datasets(sync_conn, uuid="oai:x:good-1") == 1
        assert count_datasets(sync_conn, uuid="oai:x:good-3") == 1
        assert count_datasets(sync_conn, uuid="oai:x:broken-2") == 0

        err = sync_status_row(sync_conn)["last_sync_error"]
        assert err is not None
        assert "oai:x:broken-2" in err

    async def test_watermark_is_pinned_by_per_record_failures(self, db_pool, sync_conn):
        """A per-record failure among an otherwise successful batch still
        holds the watermark back, even though the successful record lands."""
        broken = make_record("oai:x:broken")
        broken["authors"] = ["\x00"]  # PostgreSQL rejects NUL after structural validation.
        before = sync_status_row(sync_conn)["last_harvest_date"]
        with patch(
            FETCH,
            autospec=True,
            return_value=harvest_result([make_record("oai:x:ok"), broken]),
        ):
            await _sync_source_a(db_pool)
        status = sync_status_row(sync_conn)
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
                   WHERE id = 1"""
            )

        before = sync_status_row(sync_conn)

        malformed_body = b"<html><body>maintenance</body></html>"
        patcher, mock_get = patch_session_get(
            return_value=FakeOAIResponse(malformed_body),
        )

        with (
            patcher,
            patch(FETCH, new=oai_client.fetch_updates),
        ):
            await _sync_source_a(db_pool)

        after = sync_status_row(sync_conn)

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
        before = sync_status_row(sync_conn)["last_harvest_date"]

        with patch(FETCH, autospec=True, side_effect=RuntimeError("flaky network")):
            await _sync_source_a(db_pool)

        status = sync_status_row(sync_conn)
        assert status["last_sync_error"] is not None
        assert status["last_sync_error"].startswith("Incremental sync (fetch):")
        assert status["last_harvest_date"] == before  # fetch failure holds the watermark

        with patch(FETCH, autospec=True, return_value=harvest_result()):
            await _sync_source_a(db_pool)

        status = sync_status_row(sync_conn)
        assert status["last_sync_error"] is None
        assert status["last_harvest_date"] > before


class TestTransactionalWriteFaults:
    """The write phase commits one batch/record at a time, so a mid-run
    failure discards only the work in flight, and a persisted write fault
    lands on the health channel of the path (incremental or full-rebuild)
    that produced it."""

    async def test_repeated_write_deadlines_resume_the_tail_without_refetching(
        self, db_pool, sync_conn, monkeypatch
    ):
        """Each committed incremental batch is its own top-level transaction,
        so a deadline mid-batch can only discard the item in flight, never an
        already-committed one before it. Forcing one item per batch pins that
        resumability: two deadlines in a row each advance the position by
        exactly one, and the eventual clean run picks up the remaining tail
        without re-fetching the harvest."""
        harvest = harvest_result([make_record(f"resume-{i}") for i in range(3)])
        fetch = create_autospec(run_in_threadpool, return_value=harvest)
        monkeypatch.setattr(sync, "run_in_threadpool", fetch)
        monkeypatch.setattr(settings, "sync_write_timeout_seconds", 0.15)
        monkeypatch.setattr(sync, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
        original = sync._upsert_public_catalogue_record
        writes_this_run = 0

        async def one_then_block(*args):
            nonlocal writes_this_run
            writes_this_run += 1
            if writes_this_run == 2:
                await asyncio.Event().wait()
            return await original(*args)

        monkeypatch.setattr(sync, "_upsert_public_catalogue_record", one_then_block)
        # One actual connection throughout, like the advisory-lock-owning
        # scheduler: call the connection-level entry point directly rather
        # than run_sync (which acquires its own lock connection from a pool).
        # Each failed transaction must leave this connection usable for
        # reporting.
        async with db_pool.connection() as connection:
            for expected_count in (1, 2):
                writes_this_run = 0
                with pytest.raises(TimeoutError):
                    await sync._run_sync_on_locked_connection(connection)
                assert (
                    sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0]
                    == expected_count
                )
                state = sync_conn.execute(
                    "SELECT incremental_position, source_cursor, last_sync_error FROM sync_status"
                ).fetchone()
                assert state[0] == expected_count
                assert state[1] is None
                assert "TimeoutError" in state[2]
                sync_conn.commit()
            writes_this_run = 0
            result = await sync._run_sync_on_locked_connection(connection)
        assert result.status == "success" and result.affected_count == 3
        fetch.assert_awaited_once()
        assert sync_conn.execute(
            "SELECT incremental_harvest, incremental_position, source_cursor, last_sync_error "
            "FROM sync_status"
        ).fetchone() == (None, 0, harvest.source_cursor, None)
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 3

    @pytest.mark.parametrize(
        "run",
        [
            pytest.param(sync.run_sync, id="incremental"),
            pytest.param(sync.run_full_rebuild, id="full-rebuild"),
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
            sync,
            "run_in_threadpool",
            create_autospec(run_in_threadpool, return_value=harvest_result([make_record("fault")])),
        )

        async def broken_write(*_args):
            raise RuntimeError("injected write failure")

        monkeypatch.setattr(sync, "_upsert_public_catalogue_record", broken_write)
        with pytest.raises(RuntimeError, match="injected write failure"):
            await run(db_pool)
        incremental, full = sync_conn.execute(
            "SELECT last_sync_error, last_rebuild_error FROM sync_status"
        ).fetchone()
        rebuild = run is sync.run_full_rebuild
        assert "injected write failure" in (full if rebuild else incremental)
        assert (incremental if rebuild else full) is None
        assert sync_conn.execute("SELECT count(*) FROM oral_history_datasets").fetchone()[0] == 0
