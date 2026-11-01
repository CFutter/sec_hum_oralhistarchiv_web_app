"""Exercise the real OAI adapter, bounded HTTP reader and CMDI parser.

Only the child-process boundary and the HTTP session factory are replaced.
The shared fixture installs its requests blocker after make_case() captures
the real Session method signatures.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, create_autospec

import pytest
import requests
from lxml import etree

from app.sources import OaiPmhCmdiAdapter, oai_client
from tests.oai_fixtures import SAMPLE_CMDI_XML, FakeOAIResponse, fetch_updates_in_process
from tests.sources.contracts import Case

OAI_NS = "http://www.openarchives.org/OAI/2.0/"
CMDP_NS = "http://www.clarin.eu/cmd/1/profiles/clarin.eu:cr1:p_1696338267562"
ENDPOINT = "https://www.swissubase.ch/oai-pmh/v1/oai"
CURSOR = datetime(2020, 1, 4, tzinfo=UTC)
IDENTIFIERS = ("oai:contract:1", "oai:contract:2", "oai:contract:3")
SELECTIONS = {
    "1900-01-01": (1, 2, 3),
    "2020-01-01": (1, 2, 3),
    "2020-01-02": (2, 3),
    "2020-01-03": (3,),
    "2020-01-04": (),
}
TOKEN_PREFIX = "contract-page-2:"


def _record(index: int) -> etree._Element:
    """Build fixture record 1, 2 or 3 with matching identity, date, title and DOI."""
    record = etree.fromstring(SAMPLE_CMDI_XML.encode("utf-8"))
    record.tag = f"{{{OAI_NS}}}record"
    metadata = record.find("metadata")
    assert metadata is not None
    metadata.tag = f"{{{OAI_NS}}}metadata"
    replacements = {
        f"{{{OAI_NS}}}header/{{{OAI_NS}}}identifier": IDENTIFIERS[index - 1],
        f"{{{OAI_NS}}}header/{{{OAI_NS}}}datestamp": f"2020-01-0{index}T12:00:00Z",
        f".//{{{CMDP_NS}}}Dataset_title": f"Contract interview {index}",
        f".//{{{CMDP_NS}}}DOI": f"https://doi.org/10.48656/contract-{index}",
    }
    for path, value in replacements.items():
        node = record.find(path)
        assert node is not None
        node.text = value
    return record


def _response(indices: tuple[int, ...], *, token: str | None) -> bytes:
    """Serialize an OAI page; token=None requires no records and emits noRecordsMatch."""
    root = etree.Element(f"{{{OAI_NS}}}OAI-PMH", nsmap={"oai": OAI_NS})
    etree.SubElement(root, f"{{{OAI_NS}}}responseDate").text = "2020-01-04T00:00:00Z"
    if token is None:
        assert not indices
        etree.SubElement(
            root, f"{{{OAI_NS}}}error", code="noRecordsMatch"
        ).text = "No records match the requested date"
    else:
        records = etree.SubElement(root, f"{{{OAI_NS}}}ListRecords")
        for index in indices:
            records.append(_record(index))
        etree.SubElement(records, f"{{{OAI_NS}}}resumptionToken").text = token
    return etree.tostring(root, encoding="utf-8")


def make_case(monkeypatch: pytest.MonkeyPatch) -> Case:
    """Install recorded OAI transport and in-process fetching; return the adapter conformance case."""
    io_calls: list[dict[str, object]] = []

    def replay_get(
        url: str,
        *,
        params: dict[str, str],
        timeout: tuple[int, int],
        allow_redirects: bool,
        stream: bool,
        headers: dict[str, str],
    ) -> FakeOAIResponse:
        """Validate OAI request parameters and replay the selected fixture page."""
        assert url == ENDPOINT
        assert timeout == oai_client.OAI_REQUEST_TIMEOUT
        assert allow_redirects is False
        assert stream is True
        assert headers == {"Accept-Encoding": "identity"}
        assert params["verb"] == "ListRecords"
        io_calls.append({"url": url, "params": dict(params)})
        if "resumptionToken" in params:
            assert set(params) == {"verb", "resumptionToken"}
            token = params["resumptionToken"]
            assert token.startswith(TOKEN_PREFIX)
            date = token.removeprefix(TOKEN_PREFIX)
            assert SELECTIONS.get(date)
            return FakeOAIResponse(_response(SELECTIONS[date][1:], token=""))
        assert set(params) == {"verb", "metadataPrefix", "from"}
        assert params["metadataPrefix"] == "oai_cmdi12"
        date = params["from"]
        assert date in SELECTIONS
        selected = SELECTIONS[date]
        if not selected:
            return FakeOAIResponse(_response((), token=None))
        return FakeOAIResponse(_response(selected[:1], token=TOKEN_PREFIX + date))

    # Session construction performs no request. Capture bound signatures
    # before the shared request blocker, then close the unused adapters.
    session_spec = requests.Session()
    original_get = session_spec.get
    original_close = session_spec.close
    original_close()

    def new_session() -> MagicMock:
        """Build a signature-checked session double replaying the OAI fixture responses."""
        session = MagicMock(spec_set=session_spec)
        session.get = create_autospec(original_get, side_effect=replay_get)
        session.close = create_autospec(original_close, return_value=None)
        return session

    original_build_session = oai_client._build_session
    original_isolated_fetch = oai_client.fetch_updates_isolated
    direct_fetch = fetch_updates_in_process
    monkeypatch.setattr(
        oai_client,
        "_build_session",
        create_autospec(original_build_session, side_effect=new_session),
    )
    monkeypatch.setattr(
        oai_client,
        "fetch_updates_isolated",
        create_autospec(original_isolated_fetch, side_effect=direct_fetch),
    )

    return Case(
        adapter_id="oai_pmh_cmdi",
        supports_required_record_tier=False,
        adapter_type=OaiPmhCmdiAdapter,
        values={
            "name": "contract_archive",
            "adapter": "oai_pmh_cmdi",
            "display": {"label": "Contract archive"},
            "max_visibility": "public",
            "requires_record_tier": False,
            "endpoint": ENDPOINT,
            "institution_filter": "Beispielstadt",
            "max_pages": 7,
        },
        document="""[[sources]]
name = "contract_archive"
adapter = "oai_pmh_cmdi"
label = "Contract archive"
max_visibility = "public"
requires_record_tier = false
endpoint = "https://www.swissubase.ch/oai-pmh/v1/oai"
institution_filter = "Beispielstadt"
max_pages = 7
""",
        cursor=CURSOR,
        boundary=datetime(2020, 1, 2, 12, tzinfo=UTC),
        full_ids=IDENTIFIERS,
        boundary_ids=IDENTIFIERS[1:],
        raw_tiers=(None, None, None),
        expected_registered_tiers=("registered", "registered", "registered"),
        operational_overrides={
            "display": {"label": "Renamed archive", "sensitivity_badge": "Examples"},
            "schedule": {
                "incremental_interval_seconds": 900,
                "rebuild_interval_seconds": 43200,
                "write_timeout_seconds": 240,
            },
            "max_pages": 11,
        },
        insufficient_budget={"max_pages": 1},
        budget_error=oai_client.OAIProtocolError,
        budget_match="pagination_loop",
        io_calls=io_calls,
    )
