"""Shared OAI fixtures: the canonical sample CMDI record + OAI fetch stubs.

Single home for the test doubles that every OAI-facing tier needs, so the
sample record and the fake-HTTP plumbing cannot drift between copies:

- SAMPLE_CMDI_XML  — the canonical CMDI record string, parsed (and spliced
  into variants) by tests/unit/test_parsing_units.py and
  tests/unit/test_oai_client.py.
- FakeOAIResponse  — requests.Response stand-in (.content bytes +
  .raise_for_status()).
- patch_session_get — patches the OAI client's per-harvest Session factory
  and hands back the fake session's .get mock.

Used by tests/unit/test_oai_client.py, tests/unit/test_parsing_units.py and
tests/integration/test_sync_db.py.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from lxml import etree

from app.services.oai_client import _parse_cmdi_to_dict

SOURCE_CURSOR = datetime(2026, 9, 10, 12, tzinfo=UTC)


def patch_records(*, return_value):
    """Mock the iterator, including its source-clock result on the budget."""

    def records(*_args, **kwargs):
        kwargs["budget"].source_cursor = SOURCE_CURSOR
        return iter(return_value)

    return patch("app.services.oai_client._oai_list_records", autospec=True, side_effect=records)


def parsed_record(uuid, **overrides):
    """A complete parser output for worker/orchestrator contract tests."""
    record = _parse_cmdi_to_dict(etree.fromstring(SAMPLE_CMDI_XML.encode()))
    record["uuid"] = uuid
    record["doi"] = None
    record.update(overrides)
    return record


# ---------------------------------------------------------------------------
# Sample CMDI record.
#
# Copied verbatim from src/tests_legacy/conftest.py::SAMPLE_CMDI_XML (that
# module cannot be imported: it does `from app.middleware.cookies import
# get_signer`, a function the current code base no longer exposes). Its
# institutions include 'Universität Kassel', which matches the test-env
# OAI_INSTITUTION_FILTER set by src/tests/conftest.py.
# ---------------------------------------------------------------------------

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
<cmdp:Institution>Universität Kassel</cmdp:Institution>
<cmdp:Institution>University of Zurich</cmdp:Institution>
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
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False
        self.iterated = False
        self._chunks = chunks if chunks is not None else [content]
        self._status_error = status_error

    def __enter__(self) -> "FakeOAIResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def raise_for_status(self) -> None:
        if self._status_error is not None:
            raise self._status_error

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        assert chunk_size > 0
        self.iterated = True
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


def patch_session_get(**get_config):
    """The client builds a Session per harvest via
    _build_session(); patch the factory and expose the fake session's .get,
    which is where a test configures the HTTP responses a harvest sees."""
    fake = MagicMock()
    fake.get = MagicMock(**get_config)
    return (
        patch("app.services.oai_client._build_session", autospec=True, return_value=fake),
        fake.get,
    )
