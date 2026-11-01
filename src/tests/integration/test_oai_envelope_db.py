"""Ambiguous upstream envelopes must not become authoritative rebuild input."""

from unittest.mock import patch

from lxml import etree

from app.services.ingestion import run_full_rebuild
from app.sources.oai_client import OAI_NS
from tests.integration.sync_doubles import FETCH
from tests.oai_fixtures import (
    SAMPLE_CMDI_XML,
    SOURCE_CURSOR,
    FakeOAIResponse,
    fetch_updates_in_process,
    patch_session_get,
)


async def test_duplicate_results_preserve_five_existing_rows_and_committed_cursor(
    db_pool, sync_conn, sync_source, dataset_factory
):
    """The omitted fifth identity would pass the 25% contraction guard if accepted."""
    identifiers = [f"oai:ambiguity:{number}" for number in range(5)]
    for identifier in identifiers:
        dataset_factory(uuid=identifier, source=sync_source.name, title="Committed title")
    sync_conn.execute(
        "UPDATE sync_status SET source_cursor = %s WHERE source = %s",
        (SOURCE_CURSOR, sync_source.name),
    )
    sync_conn.commit()

    def snapshot():
        """Read catalogue rows and source progress, then commit the observer transaction."""
        rows = sync_conn.execute(
            "SELECT uuid, title FROM oral_history_datasets WHERE source = %s ORDER BY uuid",
            (sync_source.name,),
        ).fetchall()
        status = sync_conn.execute(
            "SELECT source_cursor, source_fingerprint, last_full_rebuild_date "
            "FROM sync_status WHERE source = %s",
            (sync_source.name,),
        ).fetchone()
        sync_conn.commit()
        return rows, status

    before = snapshot()
    records = []
    for identifier in identifiers:
        record = etree.fromstring(
            SAMPLE_CMDI_XML.replace("oai:swissubase.ch:test-uuid-xml", identifier).encode()
        )
        # Avoid an unrelated DOI-uniqueness refusal hiding the truncation regression.
        for doi in record.xpath("//*[local-name()='DOI']"):
            doi.text = None
        records.append(etree.tostring(record, encoding="unicode"))
    body = (
        f'<OAI-PMH xmlns="{OAI_NS}">'
        "<responseDate>2026-10-26T10:00:00Z</responseDate>"
        f"<ListRecords>{''.join(records[:4])}</ListRecords>"
        f"<ListRecords>{records[4]}</ListRecords></OAI-PMH>"
    ).encode()
    session_patch, get = patch_session_get(return_value=FakeOAIResponse(body))
    with session_patch, patch(FETCH, autospec=True, side_effect=fetch_updates_in_process):
        outcome = await run_full_rebuild(db_pool, configured_source=sync_source)

    assert outcome.status == "failed"
    assert "malformed_response" in outcome.reason
    assert get.call_count == 1
    assert snapshot() == before
