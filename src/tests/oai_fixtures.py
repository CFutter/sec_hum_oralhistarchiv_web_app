"""Shared synthetic CMDI records, streaming HTTP responses and in-process OAI fetch doubles."""

from collections.abc import Iterator
from datetime import UTC, datetime
from threading import Event
from unittest.mock import MagicMock, patch

from lxml import etree

from app.ingestion_contracts import HarvestResult
from app.ingestion_contracts.cancellation import check_harvest_cancellation
from app.sources import oai_client
from app.sources.oai_client import OAI_DEFAULT_MAX_PAGES, _parse_cmdi_to_dict

SOURCE_CURSOR = datetime(2026, 9, 10, 12, tzinfo=UTC)


def fetch_updates_in_process(
    oai_url: str,
    since: str,
    institution_filter: str,
    *,
    source: str,
    log_level: str,
    log_format: str,
    max_pages: int = OAI_DEFAULT_MAX_PAGES,
    cancel_event: Event | None = None,
) -> HarvestResult:
    """Adapt the isolated entrypoint to the real parser for recorded-input tests.

    Consume child logging metadata at this test-only boundary. Dedicated worker
    tests exercise process setup and logging through fetch_updates_isolated.
    """
    del source, log_level, log_format
    check_harvest_cancellation(cancel_event)
    return oai_client.fetch_updates(
        oai_url=oai_url,
        since=since,
        institution_filter=institution_filter,
        max_pages=max_pages,
    )


def patch_records(*, return_value):
    """Mock the iterator, including its source-clock result on the budget."""

    def records(*_args, **kwargs):
        """Publish the fixture source cursor on the budget and yield the supplied records."""
        kwargs["budget"].source_cursor = SOURCE_CURSOR
        yield from return_value

    return patch("app.sources.oai_client._oai_list_records", autospec=True, side_effect=records)


def parsed_record(uuid, **overrides):
    """A complete parser output for worker/orchestrator contract tests."""
    record = _parse_cmdi_to_dict(etree.fromstring(SAMPLE_CMDI_XML.encode()))
    record["uuid"] = uuid
    record["doi"] = None
    record.update(overrides)
    return record


# Sample CMDI record.
#
# Canonical synthetic sample shared by the OAI parser, client and sync tests.
# Its institutions include 'Universität Beispielstadt', matching the explicit
# TEST_INSTITUTION_FILTER used by the OAI tests.

SAMPLE_CMDI_XML = """\
<record xmlns:oai="http://www.openarchives.org/OAI/2.0/">
<oai:header>
<oai:identifier>oai:swissubase.ch:test-uuid-xml</oai:identifier>
<oai:datestamp>2026-03-06T13:38:02Z</oai:datestamp>
</oai:header>
<metadata>
<cmd:CMD xmlns:cmd="http://www.clarin.eu/cmd/1"
         xmlns:cmdp="http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562">
<cmd:Resources>
<cmd:ResourceProxyList>
<cmd:ResourceProxy id="lp_1">
<cmd:ResourceType>LandingPage</cmd:ResourceType>
<cmd:ResourceRef>https://example.com/doi/10.1234</cmd:ResourceRef>
</cmd:ResourceProxy>
<cmd:ResourceProxy id="res_1">
<cmd:ResourceType>Resource</cmd:ResourceType>
<cmd:ResourceRef>https://example.com/download</cmd:ResourceRef>
</cmd:ResourceProxy>
</cmd:ResourceProxyList>
</cmd:Resources>
<cmd:Components>
<cmdp:SWISSUbase>
<cmdp:Project>
<cmdp:Overview>
<cmdp:Author>Müller, Urs</cmdp:Author>
<cmdp:Author>Keller, Anna</cmdp:Author>
<cmdp:Institution>Universität Beispielstadt</cmdp:Institution>
<cmdp:Institution>Example University</cmdp:Institution>
<cmdp:Project_title xml:lang="en">Test Project Title</cmdp:Project_title>
<cmdp:Project_title xml:lang="de">Test Projekttitel</cmdp:Project_title>
<cmdp:Main_discipline xml:lang="en">Linguistics</cmdp:Main_discipline>
<cmdp:Main_discipline xml:lang="de">Linguistik</cmdp:Main_discipline>
</cmdp:Overview>
<cmdp:General_description>
<cmdp:Abstract xml:lang="en">This is the project abstract.</cmdp:Abstract>
</cmdp:General_description>
<cmdp:Dataset>
<cmdp:Overview>
<cmdp:Dataset_title xml:lang="en">Test Dataset Title</cmdp:Dataset_title>
<cmdp:DOI>https://doi.org/10.48656/test-xml</cmdp:DOI>
<cmdp:Dataset_description>A test dataset description.</cmdp:Dataset_description>
<cmdp:Bibliographical_citation>Müller, U. &amp; Keller, A. (2026). Test Dataset (Version 2.5) [Data set]. https://doi.org/10.48656/test-xml</cmdp:Bibliographical_citation>
<cmdp:Dataset_version>2.5</cmdp:Dataset_version>
</cmdp:Overview>
<cmdp:Resource>
<cmdp:Resource_type xml:lang="en">Corpus</cmdp:Resource_type>
<cmdp:Resource_description>Audio recordings from field research.</cmdp:Resource_description>
<cmdp:Keywords>keyword1, keyword2, keyword3</cmdp:Keywords>
<cmdp:Language_name xml:lang="en">English</cmdp:Language_name>
<cmdp:Language_name xml:lang="en">German</cmdp:Language_name>
</cmdp:Resource>
<cmdp:License>
<cmdp:License>Restricted access</cmdp:License>
<cmdp:LicenseURL>https://example.com/license</cmdp:LicenseURL>
</cmdp:License>
</cmdp:Dataset>
</cmdp:Project>
</cmdp:SWISSUbase>
</cmd:Components>
</cmd:CMD>
</metadata>
</record>
"""


class FakeOAIResponse:
    """Streaming requests.Response stand-in used by OAI protocol tests."""

    def __init__(
        self,
        content: bytes = b"",
        status_error: Exception | None = None,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        """Store response metadata and chunks; None uses the complete content as one chunk."""
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False
        self.iterated = False
        self._chunks = chunks if chunks is not None else [content]
        self._status_error = status_error

    def __enter__(self) -> "FakeOAIResponse":
        """Return this response."""
        return self

    def __exit__(self, *_args: object) -> None:
        """Mark the response closed on context exit."""
        self.close()

    def raise_for_status(self) -> None:
        """Raise the configured status exception, if any."""
        if self._status_error is not None:
            raise self._status_error

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        """Require a positive chunk size, mark iteration and yield configured chunks unchanged."""
        assert chunk_size > 0
        self.iterated = True
        yield from self._chunks

    def close(self) -> None:
        """Mark this response closed."""
        self.closed = True


def patch_session_get(**get_config):
    """Return the session-factory patch and GET mock configured by get_config."""
    fake = MagicMock()
    fake.get = MagicMock(**get_config)
    return (
        patch("app.sources.oai_client._build_session", autospec=True, return_value=fake),
        fake.get,
    )
