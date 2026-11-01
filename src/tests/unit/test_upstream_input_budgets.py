"""Bound XML before tree allocation and reject oversized metadata at shared boundaries."""

import io
import logging
from types import SimpleNamespace

import pytest
from lxml import etree
from pydantic import ValidationError

from app.ingestion_contracts.parsed_record import (
    PROJECT_TITLE_MAX_CHARS,
    RECORD_MAX_COLLECTION_ITEMS,
    RECORD_MAX_LABEL_CHARS,
    RECORD_MAX_TEXT_CHARS,
    RECORD_MAX_URL_CHARS,
    validate_parsed_record,
)
from app.routes.auth.helpers import safe_redirect_url
from app.sources import oai_client
from config.logging import JSONFormatter, RedactingFormatter
from tests.oai_fixtures import SAMPLE_CMDI_XML, FakeOAIResponse, parsed_record, patch_session_get


@pytest.mark.parametrize(
    ("setting", "limit", "body"),
    [
        ("_OAI_MAX_XML_ELEMENTS", 8, b"<root>" + b"<item/>" * 8 + b"</root>"),
        ("_OAI_MAX_XML_DEPTH", 4, b"<a><b><c><d><e/></d></c></b></a>"),
        ("_OAI_MAX_XML_TEXT_CHARS", 8, b"<a>12345<b/>6789</a>"),
        ("_OAI_MAX_XML_ATTRIBUTES", 2, b'<a x="1" y="2" z="3"/>'),
        ("_OAI_MAX_XML_TEXT_CHARS", 8, b'<a secret="123456789"/>'),
    ],
)
def test_http_page_parser_enforces_each_budget_before_classification(
    monkeypatch, setting, limit, body
):
    """Check HTTP page parser enforces each budget before classification."""
    monkeypatch.setattr(oai_client, setting, limit)
    patcher, _ = patch_session_get(return_value=FakeOAIResponse(body))
    with patcher, pytest.raises(oai_client.OAIProtocolError) as rejected:
        list(oai_client._oai_list_records("https://archive.example.org/oai", "cmdi", None))
    assert rejected.value.error_code == "xml_budget_exceeded"


def test_xml_target_stops_before_retaining_the_next_element(monkeypatch):
    """Check XML target stops before retaining the next element."""
    monkeypatch.setattr(oai_client, "_OAI_MAX_XML_ELEMENTS", 2)
    target = oai_client._BudgetedXMLTarget()
    target.start("root", {})
    target.start("accepted", {})
    target.end("accepted")
    with pytest.raises(oai_client.OAIProtocolError):
        target.start("not-retained", {})
    assert target._elements == 3
    with pytest.raises(oai_client.OAIProtocolError):
        target.close()


def test_xml_page_rejects_doctype_without_resolving_its_contents():
    """Check XML page rejects doctype without resolving its contents."""
    payload = b'<!DOCTYPE a [<!ENTITY capability "never-disclose-this">]><a>&capability;</a>'
    parser = oai_client._make_safe_parser(target=oai_client._BudgetedXMLTarget())
    with pytest.raises(oai_client.OAIProtocolError) as rejected:
        etree.fromstring(payload, parser=parser)
    assert "never-disclose-this" not in str(rejected.value)


@pytest.mark.parametrize(
    ("field", "allowed", "rejected"),
    [
        ("title", "t" * RECORD_MAX_LABEL_CHARS, "t" * (RECORD_MAX_LABEL_CHARS + 1)),
        (
            "project_title",
            "p" * PROJECT_TITLE_MAX_CHARS,
            "p" * (PROJECT_TITLE_MAX_CHARS + 1),
        ),
        ("license_val", "l" * RECORD_MAX_LABEL_CHARS, "l" * (RECORD_MAX_LABEL_CHARS + 1)),
        ("version", "v" * RECORD_MAX_LABEL_CHARS, "v" * (RECORD_MAX_LABEL_CHARS + 1)),
        ("resource_type", "r" * RECORD_MAX_LABEL_CHARS, "r" * (RECORD_MAX_LABEL_CHARS + 1)),
        ("description", "d" * RECORD_MAX_TEXT_CHARS, "d" * (RECORD_MAX_TEXT_CHARS + 1)),
        ("license_url", "u" * RECORD_MAX_URL_CHARS, "u" * (RECORD_MAX_URL_CHARS + 1)),
        ("authors", ["A"] * RECORD_MAX_COLLECTION_ITEMS, ["A"] * (RECORD_MAX_COLLECTION_ITEMS + 1)),
        ("institutions", ["A" * RECORD_MAX_LABEL_CHARS], ["A" * (RECORD_MAX_LABEL_CHARS + 1)]),
        (
            "resource_proxies",
            [{"type": "Resource", "ref": "u" * RECORD_MAX_URL_CHARS}],
            [{"type": "Resource", "ref": "u" * (RECORD_MAX_URL_CHARS + 1)}],
        ),
    ],
)
def test_shared_record_validation_checks_inclusive_bounds(field, allowed, rejected):
    """Check shared record validation checks inclusive bounds (ValidationError)."""
    record = parsed_record("bounded")
    validate_parsed_record({**record, field: allowed})
    with pytest.raises(ValidationError):
        validate_parsed_record({**record, field: rejected})


def test_record_url_length_diagnostics_do_not_include_rejected_capability_values():
    """Check record URL length diagnostics do not include rejected capability values (ValidationError)."""
    secret = "capability-in-a-rejected-long-url"
    record = parsed_record("bounded-url")
    record["license_url"] = f"https://archive.example.org/{secret}?" + "q" * RECORD_MAX_URL_CHARS
    with pytest.raises(ValidationError) as rejected:
        validate_parsed_record(record)
    assert secret not in str(rejected.value)
    record["license_url"] = None
    record["resource_proxies"] = [
        {
            "type": "Resource",
            "ref": "https://archive.example.org/" + secret + "q" * RECORD_MAX_URL_CHARS,
        }
    ]
    with pytest.raises(ValidationError) as rejected:
        validate_parsed_record(record)
    assert secret not in str(rejected.value)


@pytest.mark.parametrize("formatter", [JSONFormatter, RedactingFormatter])
def test_rejected_urls_never_reach_either_log_formatter(formatter):
    """Check rejected URLs never reach either log formatter."""
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(formatter())
    loggers = [logging.getLogger("app.routes.auth.helpers"), oai_client.logger]
    for logger in loggers:
        logger.addHandler(handler)
    canary = "sensitive-participant-capability-canary"
    try:
        for url in (
            f"https://name:{canary}@outside.example.org/{canary}?token={canary}#{canary}",
            f"//outside.example.org/{canary}",
            f"/\\outside.example.org/{canary}",
        ):
            request = SimpleNamespace(query_params={"next": url})
            assert safe_redirect_url(request) == "/"
        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        resource = record.xpath("//*[local-name()='ResourceRef']")[0]
        resource.text = f"file:///private/{canary}"
        oai_client._parse_cmdi_to_dict(record)
    finally:
        for logger in loggers:
            logger.removeHandler(handler)
    assert canary not in output.getvalue()
    assert "Blocked unsafe redirect target" in output.getvalue()
    assert "Rejected unsafe URL" in output.getvalue()


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_actual_worker_logging_escapes_upstream_datestamp_controls(monkeypatch, capsys, log_format):
    """Check actual worker logging escapes upstream datestamp controls."""
    root = logging.getLogger()
    audit = logging.getLogger("audit")
    for logger in (root, audit):
        monkeypatch.setattr(logger, "handlers", list(logger.handlers))
        monkeypatch.setattr(logger, "level", logger.level)
        monkeypatch.setattr(logger, "propagate", logger.propagate)
    oai_client._configure_worker_logging(
        source="logging_probe", log_level="INFO", log_format=log_format
    )
    assert oai_client._parse_oai_datestamp("bad\nforged-line\x1b[31m\rvalue") is None
    oai_client.logger.warning("Literal diagnostic\nforged-line\x1b[31m\rvalue")
    output = capsys.readouterr().out
    assert len(output.splitlines()) == 2
    assert "forged-line" not in output.splitlines()[0]
    assert "\x1b" not in output and "\r" not in output
    assert "forged-line" in output
    assert "\\n" in output
    assert "logging_probe" in output
