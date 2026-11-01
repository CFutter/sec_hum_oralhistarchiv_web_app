"""Reconciliation of ambiguous and definite institution-filter outcomes."""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from lxml import etree

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.services.ingestion import run_full_rebuild
from app.sources.oai_client import OAI_NS
from tests.integration.sync_doubles import (
    FETCH,
    SourceCase,
    ingestion_failure_uuids,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    FakeOAIResponse,
    fetch_updates_in_process,
    patch_session_get,
)
from tests.source_fixtures import TEST_INSTITUTION_FILTER


def _uncertain_record_xml(uuid, institutions):
    """Adapt real CMDI XML while keeping each record's DOI distinct."""
    record = etree.fromstring(SAMPLE_CMDI_XML.encode())
    identifier = record.find(f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier")
    assert identifier is not None
    identifier.text = uuid

    nodes = record.xpath(".//*[local-name()='Institution']")
    assert nodes
    parent = nodes[0].getparent()
    assert parent is not None
    tag = nodes[0].tag
    for node in nodes:
        parent.remove(node)
    for name in institutions:
        etree.SubElement(parent, tag).text = name

    for node in record.xpath(".//*[local-name()='DOI']"):
        node.text = f"10.1234/{uuid.rsplit(':', 1)[-1]}"
    return etree.tostring(record, encoding="unicode")


def _uncertain_record_page(records, token=""):
    """Wrap supplied records and a resumption token in an OAI XML response."""
    return FakeOAIResponse(
        (
            f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate><ListRecords>'
            + "".join(records)
            + f"<resumptionToken>{token}</resumptionToken>"
            + "</ListRecords></OAI-PMH>"
        ).encode()
    )


class TestUncertainInstitutionMetadata(SourceCase):
    """Check uncertain Institution Metadata."""

    @pytest.mark.parametrize(
        ("runner", "expected_titles"),
        [
            pytest.param(
                run_full_rebuild,
                {
                    "oai:uncertain-inst:known": "Test Dataset Title",
                    "oai:uncertain-inst:uncertain": "Existing title",
                    "oai:uncertain-inst:new": "Test Dataset Title",
                },
                id="rebuild",
            ),
            pytest.param(
                ingestion._sync_source,
                {
                    "oai:uncertain-inst:known": "Test Dataset Title",
                    "oai:uncertain-inst:uncertain": "Existing title",
                    "oai:uncertain-inst:new": "Test Dataset Title",
                },
                id="incremental",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "institutions",
        [[], [" \t "]],
        ids=["missing", "blank"],
    )
    async def test_uncertain_institution_preserves_row_and_pins_watermark(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
        runner,
        expected_titles,
        institutions,
    ):
        """Verify uncertain institution preserves row and pins watermark."""
        for uuid in (
            "oai:uncertain-inst:known",
            "oai:uncertain-inst:uncertain",
            "oai:uncertain-inst:deleted",
        ):
            dataset_factory(
                uuid=uuid,
                source=self.source.name,
                title="Existing title",
            )

        prior = datetime(2020, 1, 1, tzinfo=UTC)
        sync_conn.execute(
            """
            UPDATE sync_status
            SET last_harvest_date = %s,
                last_full_rebuild_date = %s,
                last_sync_error = 'prior incremental error',
                last_sync_error_at = %s,
                last_rebuild_error = 'prior rebuild error',
                last_rebuild_error_at = %s
            WHERE source = %s
            """,
            (prior, prior, prior, prior, self.source.name),
        )
        sync_conn.commit()

        matching = [TEST_INSTITUTION_FILTER]
        tombstone = (
            '<record><header status="deleted">'
            "<identifier>oai:uncertain-inst:deleted</identifier>"
            "</header></record>"
        )

        patcher, mock_get = patch_session_get(
            side_effect=[
                _uncertain_record_page(
                    [
                        _uncertain_record_xml("oai:uncertain-inst:known", matching),
                        _uncertain_record_xml("oai:uncertain-inst:new", matching),
                        tombstone,
                    ],
                    token="T1",
                ),
                _uncertain_record_page(
                    [
                        _uncertain_record_xml(
                            "oai:uncertain-inst:uncertain",
                            institutions,
                        )
                    ]
                ),
            ]
        )

        with (
            patcher as session_factory,
            patch(FETCH, autospec=True, side_effect=fetch_updates_in_process),
        ):
            await runner(db_pool, configured_source=self.source)

        assert mock_get.call_count == 2
        session_factory.return_value.close.assert_called_once()

        after = sync_status_row(sync_conn, source=self.source.name)
        rows = sync_conn.execute(
            """
            SELECT uuid, title
            FROM oral_history_datasets
            WHERE source = %s
            ORDER BY uuid
            """,
            (self.source.name,),
        ).fetchall()
        failure_uuids = ingestion_failure_uuids(sync_conn, source=self.source.name)

        assert dict(rows) == expected_titles
        assert "oai:uncertain-inst:deleted" not in dict(rows)
        assert "oai:uncertain-inst:uncertain" in failure_uuids

        if runner is run_full_rebuild:
            assert dict(rows)["oai:uncertain-inst:uncertain"] == "Existing title"
            assert after["last_full_rebuild_date"] == prior
            assert after["last_harvest_date"] == prior
            assert "oai:uncertain-inst:uncertain" in after["last_rebuild_error"]
            assert after["last_rebuild_error_at"] > prior
            assert "oai:uncertain-inst:uncertain" in after["last_sync_error"]
            assert after["last_sync_error_at"] > prior
        else:
            assert dict(rows)["oai:uncertain-inst:uncertain"] == "Existing title"
            assert after["last_harvest_date"] == prior
            assert after["last_full_rebuild_date"] == prior
            assert "oai:uncertain-inst:uncertain" in after["last_sync_error"]
            assert after["last_sync_error_at"] > prior
            assert after["last_rebuild_error"] == "prior rebuild error"
            assert after["last_rebuild_error_at"] == prior

    async def test_full_rebuild_preserves_uncertain_row_and_pins_completion(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
    ):
        """An offered-but-unclassifiable identity remains protected from deletion."""
        uncertain_uuid = "oai:uncertain-inst:direct-uncertain"
        uncertain_id = dataset_factory(
            uuid=uncertain_uuid,
            source=self.source.name,
            title="Last known good title",
        )
        dataset_factory(
            uuid="oai:uncertain-inst:direct-stale",
            source=self.source.name,
            title="Actually absent upstream",
        )
        dataset_factory(
            uuid="oai:uncertain-inst:direct-kept-1",
            source=self.source.name,
            title="Still offered 1",
        )
        dataset_factory(
            uuid="oai:uncertain-inst:direct-kept-2",
            source=self.source.name,
            title="Still offered 2",
        )

        prior = datetime(2020, 1, 1, tzinfo=UTC)
        sync_conn.execute(
            """UPDATE sync_status
               SET last_harvest_date = %s,
                   last_full_rebuild_date = %s,
                   last_sync_error = NULL,
                   last_sync_error_at = NULL,
                   last_rebuild_error = NULL,
                   last_rebuild_error_at = NULL
               WHERE source = %s""",
            (prior, prior, self.source.name),
        )
        sync_conn.commit()

        reason = "missing or unusable institution metadata"
        harvest = HarvestResult(
            source_cursor=SOURCE_CURSOR,
            matching_records=[
                make_record(
                    "oai:uncertain-inst:direct-matching",
                    title="Fresh matching record",
                ),
                make_record("oai:uncertain-inst:direct-kept-1", title="Still offered 1"),
                make_record("oai:uncertain-inst:direct-kept-2", title="Still offered 2"),
            ],
            uncertain_records={uncertain_uuid: reason},
        )

        with patch(FETCH, autospec=True, return_value=harvest):
            await ingestion._full_rebuild_source(db_pool, configured_source=self.source)

        rows = sync_conn.execute(
            """SELECT id, uuid, title
               FROM oral_history_datasets
               WHERE source = %s""",
            (self.source.name,),
        ).fetchall()
        by_uuid = {uuid: (row_id, title) for row_id, uuid, title in rows}

        assert by_uuid[uncertain_uuid] == (uncertain_id, "Last known good title")
        assert by_uuid["oai:uncertain-inst:direct-matching"][1] == "Fresh matching record"
        assert by_uuid["oai:uncertain-inst:direct-kept-1"][1] == "Still offered 1"
        assert by_uuid["oai:uncertain-inst:direct-kept-2"][1] == "Still offered 2"
        assert "oai:uncertain-inst:direct-stale" not in by_uuid

        status = sync_status_row(sync_conn, source=self.source.name)
        failures = dict(
            sync_conn.execute(
                "SELECT uuid, message FROM ingestion_failures WHERE source = %s",
                (self.source.name,),
            ).fetchall()
        )

        assert status["last_harvest_date"] == prior
        assert status["last_full_rebuild_date"] == prior
        assert failures == {uncertain_uuid: reason}
        assert uncertain_uuid in status["last_sync_error"]
        assert uncertain_uuid in status["last_rebuild_error"]


class TestDefiniteInstitutionMismatch(SourceCase):
    """Check definite Institution Mismatch."""

    async def test_known_nonmatching_record_is_still_reconciled(
        self, db_pool, sync_conn, dataset_factory
    ):
        """A broad filter exclusion withholds known data and triggers source review."""
        dataset_factory(uuid="oai:uncertain-inst:excluded", source=self.source.name)
        patcher, mock_get = patch_session_get(
            return_value=_uncertain_record_page(
                [
                    _uncertain_record_xml("oai:uncertain-inst:accepted", [TEST_INSTITUTION_FILTER]),
                    _uncertain_record_xml("oai:uncertain-inst:excluded", ["Elsewhere Institute"]),
                ]
            )
        )
        with (
            patcher,
            patch(FETCH, autospec=True, side_effect=fetch_updates_in_process),
        ):
            outcome = await run_full_rebuild(db_pool, configured_source=self.source)

        mock_get.assert_called_once()
        rows = dict(
            sync_conn.execute(
                "SELECT uuid, source FROM oral_history_datasets WHERE source = %s",
                (self.source.name,),
            ).fetchall()
        )
        assert "oai:uncertain-inst:excluded" in rows
        assert "oai:uncertain-inst:accepted" not in rows
        assert outcome.status == "failed"
        assert sync_conn.execute(
            "SELECT reason FROM ingestion_quarantine WHERE source = %s AND uuid = %s",
            (self.source.name, "oai:uncertain-inst:excluded"),
        ).fetchone() == ("filter_mismatch",)
        status = sync_status_row(sync_conn, source=self.source.name)
        assert status["last_full_rebuild_date"] is None
        assert "filter exclusion" in status["last_rebuild_error"]
