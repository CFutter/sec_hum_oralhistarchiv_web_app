"""The generic federation runbook must track the shipped trust-boundary contract."""

import re
from urllib.parse import unquote, urlsplit

import pytest

from app.federation_contract import (
    AFFILIATION_MAX_LENGTH,
    AUTHN_CONTEXT_MAX_LENGTH,
    COUNTRY_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    ENTITLEMENT_MAX_LENGTH,
    ISSUER_MAX_LENGTH,
    SUBJECT_MAX_LENGTH,
)
from app.paths import PROJECT_ROOT
from app.services import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_COUNTRY_HEADER,
    SHIBBOLETH_DISPLAY_NAME_HEADER,
    SHIBBOLETH_ENTITLEMENT_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
)

_RUNBOOK = "runbooks/federation-integration.md"
_HEADER_CONTRACT = (
    (SHIBBOLETH_INTERNAL_AUTH_HEADER, True, 1024),
    (SHIBBOLETH_ISSUER_HEADER, True, ISSUER_MAX_LENGTH),
    (SHIBBOLETH_SUBJECT_HEADER, True, SUBJECT_MAX_LENGTH),
    (SHIBBOLETH_MAIL_HEADER, True, EMAIL_MAX_LENGTH),
    (SHIBBOLETH_AUTHN_CONTEXT_HEADER, True, AUTHN_CONTEXT_MAX_LENGTH),
    (SHIBBOLETH_DISPLAY_NAME_HEADER, False, DISPLAY_NAME_MAX_LENGTH),
    (SHIBBOLETH_AFFILIATION_HEADER, False, AFFILIATION_MAX_LENGTH),
    (SHIBBOLETH_ENTITLEMENT_HEADER, False, ENTITLEMENT_MAX_LENGTH),
    (SHIBBOLETH_COUNTRY_HEADER, False, COUNTRY_MAX_LENGTH),
)
_NEGATIVE_CASES = {
    "disabled",
    "tcp-peer",
    "client-header-spoof",
    "missing-required",
    "duplicate-header",
    "malformed-header",
    "wrong-secret",
    "untrusted-issuer",
    "non-mfa",
    "optional-entitlement",
    "email-collision",
    "stale-review",
    "stale-policy",
    "off-origin-redirect",
    "logout",
}
_LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^\s)]+)\)")


def _document():
    """Read the shipped federation integration runbook as UTF-8."""
    return (PROJECT_ROOT / "docs" / _RUNBOOK).read_text(encoding="utf-8")


def _marked_table(name, headings):
    """Return rows from a uniquely marked Markdown table after validating headings and shape."""
    document = _document()
    start = f"<!-- {name}_START -->"
    end = f"<!-- {name}_END -->"
    assert document.count(start) == document.count(end) == 1, name
    table = document.split(start, 1)[1].split(end, 1)[0]
    lines = [line.strip() for line in table.splitlines() if line.strip()]
    assert len(lines) > 2 and all(line.startswith("|") and line.endswith("|") for line in lines)
    cells = [tuple(cell.strip() for cell in line[1:-1].split("|")) for line in lines]
    assert cells[0] == headings, f"Unexpected contract table columns: {name}"
    assert all(re.fullmatch(r":?-+:?", value) for value in cells[1]), name
    assert all(len(row) == len(headings) and all(row) for row in cells[2:]), name
    return cells[2:]


def test_federation_runbook_is_listed_once_in_navigation():
    """Federation runbook is listed once in navigation."""
    navigation = (PROJECT_ROOT / "mkdocs.yaml").read_text(encoding="utf-8")
    entries = re.findall(r"(?m)^\s+- [^:\n]+:\s+([^\s#]+)\s*$", navigation)
    assert entries.count(_RUNBOOK) == 1, "Missing or duplicate federation runbook navigation"
    assert (PROJECT_ROOT / "docs" / _RUNBOOK).is_file()


def test_header_map_has_exactly_the_nine_fixed_private_headers():
    """Header map has exactly the nine fixed private headers."""
    rows = _marked_table(
        "FEDERATION_HEADER_MAP",
        ("Header", "Required", "SP/nginx source", "Decoded character limit"),
    )
    names = [row[0].strip("`") for row in rows]
    assert len(names) == len(set(names)), "Duplicate private header in integration contract"
    assert set(names) == {header for header, _required, _limit in _HEADER_CONTRACT}


@pytest.mark.parametrize(
    ("header", "required", "limit"),
    _HEADER_CONTRACT,
    ids=[header for header, _required, _limit in _HEADER_CONTRACT],
)
def test_header_requirements_limits_and_nginx_sources_match_the_shipped_contract(
    header, required, limit
):
    """Header requirements limits and nginx sources match the shipped contract."""
    rows = _marked_table(
        "FEDERATION_HEADER_MAP",
        ("Header", "Required", "SP/nginx source", "Decoded character limit"),
    )
    matching = [row for row in rows if row[0].strip("`") == header]
    assert len(matching) == 1, f"Missing or duplicate private header: {header}"
    _name, documented_required, source, documented_limit = matching[0]
    assert documented_required.strip("`").casefold() == ("yes" if required else "no")
    assert documented_limit.strip("`") == str(limit), f"Stale decoded limit: {header}"
    if header == SHIBBOLETH_INTERNAL_AUTH_HEADER:
        assert "SHIBBOLETH_INTERNAL_SECRET" in source, "Internal auth must use its own secret"
    else:
        fragment = (PROJECT_ROOT / "deploy/nginx-shibboleth-phase2.conf.example").read_text(
            encoding="utf-8"
        )
        assignment = re.search(
            rf"(?m)^\s*proxy_set_header\s+{re.escape(header)}\s+(\$[a-z_]+)\s*;", fragment
        )
        assert assignment is not None, f"Shipped callback does not overwrite {header}"
        assert assignment[1] in source, f"Runbook maps {header} from the wrong nginx variable"


def test_runbook_pins_the_code_owned_mfa_context():
    """Runbook pins the code owned mfa context."""
    assert f"`{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT}`" in _document(), (
        "The assurance requirement must be the application's exact fixed context"
    )


def test_negative_matrix_covers_each_trust_and_recovery_boundary():
    """Negative matrix covers each trust and recovery boundary."""
    rows = _marked_table("FEDERATION_NEGATIVE_MAP", ("Case", "Expected result", "Evidence"))
    cases = [row[0].strip("`") for row in rows]
    assert len(cases) == len(set(cases)), "Duplicate federation acceptance case"
    assert set(cases) >= _NEGATIVE_CASES, (
        f"Missing federation cases: {_NEGATIVE_CASES - set(cases)}"
    )
    for case, expected, evidence in rows:
        assert expected.strip("` ") and evidence.strip("` "), f"Incomplete acceptance row: {case}"


def test_generic_integration_runbook_has_no_institution_specific_dependencies():
    """Generic integration runbook has no institution specific dependencies."""
    assert not re.search(r"(?i)\b(?:uzh|switch|leomed|eduid|swissubase|kassel)\b", _document()), (
        "The generic integration procedure must not depend on the original institution"
    )


def test_runbook_decision_placeholders_remain_visible_outside_code_fences():
    """Runbook decision placeholders remain visible outside code fences."""
    document = re.sub(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$", "", _document())
    document = re.sub(r"<!--.*?-->", "", document, flags=re.S)
    placeholders = list(re.finditer(r"<[a-zA-Z][^>\n]*>", document))
    spans = [match.span() for match in re.finditer(r"`[^`\n]+`", document)]
    assert placeholders, "Generic integration decisions need marked operator placeholders"
    for value in placeholders:
        assert any(start < value.start() < value.end() < end for start, end in spans), (
            f"Decision would be hidden as HTML rather than displayed: {value[0]}"
        )


def test_federation_procedure_links_resolve_inside_shipped_docs():
    """Federation procedure links resolve inside shipped docs."""
    docs = (PROJECT_ROOT / "docs").resolve()
    path = docs / _RUNBOOK
    document = _document()
    links = _LINK.findall(document)
    assert links and len(links) == document.count("]("), "Unrecognized federation procedure link"
    for link in links:
        url = urlsplit(link)
        if url.scheme or url.netloc:
            assert url.scheme == "https" and url.netloc, f"Unsafe procedure link: {link}"
            continue
        assert not url.query, f"Procedure link contains query values: {link}"
        target = (path.parent / unquote(url.path)).resolve() if url.path else path
        assert target.is_relative_to(docs), f"Procedure link leaves shipped docs: {link}"
        assert target.is_file() and target.suffix == ".md", f"Missing federation procedure: {link}"
