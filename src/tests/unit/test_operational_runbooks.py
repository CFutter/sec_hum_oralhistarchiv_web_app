"""Operational templates expose current diagnostic causes without destructive queries."""

import ast
import re
from urllib.parse import unquote, urlsplit

import pytest

from app.paths import PROJECT_ROOT

_RUNBOOKS = ("runbooks/monitoring.md", "runbooks/point-in-time-recovery.md")
_LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^\s)]+)\)")


@pytest.mark.parametrize("name", _RUNBOOKS)
def test_operational_runbook_is_listed_once_in_navigation(name):
    """Check operational runbook is listed once in navigation."""
    navigation = (PROJECT_ROOT / "mkdocs.yaml").read_text(encoding="utf-8")
    entries = re.findall(r"(?m)^\s+- [^:\n]+:\s+([^\s#]+)\s*$", navigation)
    assert entries.count(name) == 1, f"Missing or duplicate operational navigation: {name}"
    assert (PROJECT_ROOT / "docs" / name).is_file()


@pytest.mark.parametrize("name", _RUNBOOKS)
def test_operational_template_decisions_render_as_literal_code(name):
    """Check operational template decisions render as literal code."""
    document = (PROJECT_ROOT / "docs" / name).read_text(encoding="utf-8")
    document = re.sub(r"<!--.*?-->", "", document, flags=re.S)
    placeholders = list(re.finditer(r"<[a-zA-Z][^>\n]*>", document))
    spans = [match.span() for match in re.finditer(r"`[^`\n]+`", document)]
    assert placeholders, f"Template has no marked operator decisions: {name}"
    for value in placeholders:
        assert any(start < value.start() < value.end() < end for start, end in spans), (
            f"Decision would be hidden as HTML rather than displayed: {value[0]}"
        )


@pytest.mark.parametrize("name", _RUNBOOKS)
def test_operational_runbook_links_remain_inside_shipped_docs(name):
    """Check operational runbook links remain inside shipped docs."""
    docs = (PROJECT_ROOT / "docs").resolve()
    document = docs / name
    text = document.read_text(encoding="utf-8")
    links = _LINK.findall(text)
    assert links and len(links) == text.count("]("), f"Unrecognized procedure link: {name}"
    for link in links:
        url = urlsplit(link)
        if url.scheme or url.netloc:
            assert url.scheme == "https" and url.netloc
            continue
        assert not url.query
        path = (document.parent / unquote(url.path)).resolve() if url.path else document
        assert path.is_relative_to(docs) and path.is_file(), f"Missing procedure: {link}"


def test_every_current_degraded_diagnostic_key_has_a_linked_investigation():
    """Check every current degraded diagnostic key has a linked investigation."""
    source = (PROJECT_ROOT / "src/app/routes/health.py").read_text(encoding="utf-8")
    keys = {
        node.slice.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Name)
        and node.value.id == "checks"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and node.slice.value.endswith(("_missing", "_stale", "_error", "_degraded"))
    }
    document = (PROJECT_ROOT / "docs/runbooks/monitoring.md").read_text(encoding="utf-8")
    start = "<!-- HEALTH_DIAGNOSTIC_MAP_START -->"
    end = "<!-- HEALTH_DIAGNOSTIC_MAP_END -->"
    assert document.count(start) == document.count(end) == 1
    table = document.split(start, 1)[1].split(end, 1)[0]
    rows = [line for line in table.splitlines() if line.startswith("| ")][1:]
    labels = [re.match(r"\| `([a-z_]+)` \|", row) for row in rows]
    documented = [match[1] for match in labels if match is not None]
    assert keys and keys <= set(documented), (
        f"Undocumented degraded causes: {keys - set(documented)}"
    )
    assert len(documented) == len(set(documented)), "Duplicate diagnostic cause row"
    headings = {
        re.sub(r"[^\w\s-]", "", line.lstrip("# ").lower()).replace(" ", "-")
        for line in document.splitlines()
        if line.startswith("#")
    }
    for row in rows:
        queries = re.findall(r"\]\(#([a-z0-9-]+)\)", row)
        assert queries, f"Diagnostic has no investigation query/check: {row}"
        assert set(queries) <= headings, f"Missing investigation section: {queries}"


def test_monitoring_sql_is_read_only_and_has_a_statement_budget():
    """Check monitoring SQL is read only and has a statement budget."""
    document = (PROJECT_ROOT / "docs/runbooks/monitoring.md").read_text(encoding="utf-8")
    queries = re.findall(r"(?ms)^```sql\n(.*?)^```$", document)
    assert queries, "No investigation queries supplied"
    for query in queries:
        assert query.startswith("BEGIN READ ONLY;\n") and query.rstrip().endswith("COMMIT;")
        assert "SET LOCAL statement_timeout = '5s';" in query
        assert not re.search(r"\b(INSERT|UPDATE|DELETE|TRUNCATE|DROP|ALTER|CREATE|GRANT)\b", query)
