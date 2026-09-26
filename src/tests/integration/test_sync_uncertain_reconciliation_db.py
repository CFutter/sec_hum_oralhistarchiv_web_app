"""Reconciliation of ambiguous and definite institution-filter outcomes.

An offered-but-unclassifiable UUID (``HarvestResult.uncertain_records``) must
never look absent to reconciliation on either sync path, while a definite
institution mismatch is still an authoritative removal. Both paths write
through ``app.services.sync``; the plain incremental and rebuild mechanics
live in ``test_sync_incremental_db.py`` and ``test_sync_rebuild_db.py``.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from lxml import etree

from app.services import oai_client, sync
from app.services.oai_client import OAI_NS, HarvestResult
from app.services.sync import run_full_rebuild
from config import settings
from tests.integration.sync_doubles import (
    FETCH,
    ingestion_failure_uuids,
    make_record,
    sync_status_row,
)
from tests.oai_fixtures import SAMPLE_CMDI_XML, SOURCE_CURSOR, FakeOAIResponse, patch_session_get


def _uncertain_record_xml(uuid, institutions):
    """Adapt real CMDI XML; distinct DOIs avoid unrelated uniqueness failures."""
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
    return FakeOAIResponse(
        (
            f'<OAI-PMH xmlns="{OAI_NS}"><responseDate>2026-09-10T12:00:00Z</responseDate><ListRecords>'
            + "".join(records)
            + f"<resumptionToken>{token}</resumptionToken>"
            + "</ListRecords></OAI-PMH>"
        ).encode()
    )


class TestUncertainInstitutionMetadata:
    """A row whose institution metadata is missing or unusable must be
    preserved, and both diagnostic channels must pin the run that could not
    resolve it — never claim a complete, watermark-advancing reconciliation."""

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
                sync._sync_source_a,
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
        for uuid in (
            "oai:uncertain-inst:known",
            "oai:uncertain-inst:uncertain",
            "oai:uncertain-inst:deleted",
        ):
            dataset_factory(
                uuid=uuid,
                source="swissubase",
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
            WHERE id = 1
            """,
            (prior, prior, prior, prior),
        )
        sync_conn.commit()

        matching = [settings.oai_institution_filter]
        tombstone = (
            '<record><header status="deleted">'
            "<identifier>oai:uncertain-inst:deleted</identifier>"
            "</header></record>"
        )

        patcher, mock_get = patch_session_get(
            side_effect=[
                _uncertain_record_page(
                    [
                        _uncertain_record_xml(
                            "oai:uncertain-inst:known",
                            matching,
                        ),
                        _uncertain_record_xml(
                            "oai:uncertain-inst:new",
                            matching,
                        ),
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
            patch(FETCH, new=oai_client.fetch_updates),
        ):
            await runner(db_pool)

        assert mock_get.call_count == 2
        session_factory.return_value.close.assert_called_once()

        after = sync_status_row(sync_conn)
        rows = sync_conn.execute(
            """
            SELECT uuid, title
            FROM oral_history_datasets
            WHERE source = 'swissubase'
            ORDER BY uuid
            """
        ).fetchall()
        failure_uuids = ingestion_failure_uuids(sync_conn)

        assert dict(rows) == expected_titles
        assert "oai:uncertain-inst:deleted" not in dict(rows)
        assert "oai:uncertain-inst:uncertain" in failure_uuids

        if runner is run_full_rebuild:
            # The uncertain UUID is protected from stale deletion. Because the
            # rebuild was incomplete, neither catalogue cursor advances and
            # both recovery channels retain the unresolved identity.
            assert dict(rows)["oai:uncertain-inst:uncertain"] == "Existing title"
            assert after["last_full_rebuild_date"] == prior
            assert after["last_harvest_date"] == prior
            assert "oai:uncertain-inst:uncertain" in after["last_rebuild_error"]
            assert after["last_rebuild_error_at"] > prior
            assert "oai:uncertain-inst:uncertain" in after["last_sync_error"]
            assert after["last_sync_error_at"] > prior
        else:
            # Incremental sync also retains the last known representation and
            # pins its cursor until this identifier can be replayed
            # successfully.
            assert dict(rows)["oai:uncertain-inst:uncertain"] == "Existing title"
            assert after["last_harvest_date"] == prior
            assert after["last_full_rebuild_date"] == prior
            assert "oai:uncertain-inst:uncertain" in after["last_sync_error"]
            assert after["last_sync_error_at"] > prior

            # Error channels remain independent.
            assert after["last_rebuild_error"] == "prior rebuild error"
            assert after["last_rebuild_error_at"] == prior

    async def test_full_rebuild_preserves_uncertain_row_and_pins_completion(
        self,
        db_pool,
        sync_conn,
        dataset_factory,
    ):
        """An offered-but-unclassifiable UUID must never look absent to
        reconciliation, driven directly through the rebuild entry point
        (rather than through a patched OAI page) as a positive control on
        the reconciliation function itself."""
        uncertain_uuid = "oai:uncertain-inst:direct-uncertain"
        uncertain_id = dataset_factory(
            uuid=uncertain_uuid,
            source="swissubase",
            title="Last known good title",
        )
        dataset_factory(
            uuid="oai:uncertain-inst:direct-stale",
            source="swissubase",
            title="Actually absent upstream",
        )
        # The contraction guard (sync.py:289-326) refuses to infer-delete
        # more than 25% of existing Source A rows in one rebuild. Only
        # "oai:uncertain-inst:direct-stale" is unoffered here, so two more
        # pre-existing rows that stay offered (and therefore protected) keep
        # inferred absence at 1/4 = 25%, at the limit rather than over it,
        # letting the reconciliation under test run instead of tripping the
        # guard first.
        dataset_factory(
            uuid="oai:uncertain-inst:direct-kept-1", source="swissubase", title="Still offered 1"
        )
        dataset_factory(
            uuid="oai:uncertain-inst:direct-kept-2", source="swissubase", title="Still offered 2"
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
               WHERE id = 1""",
            (prior, prior),
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
            await sync._full_rebuild_source_a(db_pool)

        rows = sync_conn.execute(
            """SELECT id, uuid, title
               FROM oral_history_datasets
               WHERE source = 'swissubase'"""
        ).fetchall()
        by_uuid = {uuid: (row_id, title) for row_id, uuid, title in rows}

        assert by_uuid[uncertain_uuid] == (uncertain_id, "Last known good title")
        assert by_uuid["oai:uncertain-inst:direct-matching"][1] == "Fresh matching record"
        assert by_uuid["oai:uncertain-inst:direct-kept-1"][1] == "Still offered 1"
        assert by_uuid["oai:uncertain-inst:direct-kept-2"][1] == "Still offered 2"
        assert "oai:uncertain-inst:direct-stale" not in by_uuid

        status = sync_status_row(sync_conn)
        # Unresolved identities live in ingestion_failures, not the dead
        # sync_status.incremental_failures column (sync.py:360-503).
        failures = dict(
            sync_conn.execute(
                "SELECT uuid, message FROM ingestion_failures WHERE source = 'swissubase'"
            ).fetchall()
        )

        assert status["last_harvest_date"] == prior
        assert status["last_full_rebuild_date"] == prior
        assert failures == {uncertain_uuid: reason}
        assert uncertain_uuid in status["last_sync_error"]
        assert uncertain_uuid in status["last_rebuild_error"]


class TestDefiniteInstitutionMismatch:
    """Positive control for TestUncertainInstitutionMetadata: a definite
    (not ambiguous) filter mismatch must still be reconciled away."""

    async def test_known_nonmatching_record_is_still_reconciled(
        self, db_pool, sync_conn, dataset_factory
    ):
        """A definite institution change must still remove a previously
        included row."""
        dataset_factory(uuid="oai:uncertain-inst:excluded", source="swissubase")
        patcher, mock_get = patch_session_get(
            return_value=_uncertain_record_page(
                [
                    _uncertain_record_xml(
                        "oai:uncertain-inst:accepted", [settings.oai_institution_filter]
                    ),
                    _uncertain_record_xml("oai:uncertain-inst:excluded", ["Elsewhere Institute"]),
                ]
            )
        )
        with (
            patcher,
            patch(FETCH, new=oai_client.fetch_updates),
        ):
            await run_full_rebuild(db_pool)

        mock_get.assert_called_once()
        rows = dict(
            sync_conn.execute(
                "SELECT uuid, source FROM oral_history_datasets WHERE source = 'swissubase'"
            ).fetchall()
        )
        assert "oai:uncertain-inst:excluded" not in rows
        assert "oai:uncertain-inst:accepted" in rows
        status = sync_status_row(sync_conn)
        assert status["last_full_rebuild_date"] is not None
        assert status["last_harvest_date"] == status["last_full_rebuild_date"]
        assert status["last_rebuild_error"] is None
