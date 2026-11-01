"""Compliance templates stay discoverable, linked and usable before operator adoption."""

import re
from urllib.parse import unquote, urlsplit

import pytest

from app.paths import PROJECT_ROOT

_TEMPLATES = (
    "compliance/processing-register.md",
    "compliance/dpia-questionnaire.md",
    "compliance/dsar-procedure.md",
    "compliance/incident-response.md",
)
_COMPLIANCE_PAGES = (
    *_TEMPLATES,
    "compliance/data-classification.md",
    "runbooks/retention-dsar-template.md",
)
_LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^\s)]+)\)")
_PLACEHOLDER = re.compile(r"<[a-z][a-z0-9-]*>")


@pytest.mark.parametrize("name", _COMPLIANCE_PAGES)
def test_compliance_page_is_listed_once_in_the_compliance_navigation(name):
    """A file existing on disk is insufficient if readers cannot find it."""
    navigation = (PROJECT_ROOT / "mkdocs.yaml").read_text(encoding="utf-8")
    sections = re.findall(r"(?m)^  - Compliance:[ \t]*\n((?:[ ]{4}[^\n]*\n|\n)*)", navigation)
    assert len(sections) == 1, "Expected one Compliance navigation section"
    leaves = re.findall(r"(?m)^      - [^:\n]+:\s+([^\s#]+)\s*$", sections[0])
    assert leaves.count(name) == 1, f"Missing or duplicate Compliance navigation: {name}"
    assert (PROJECT_ROOT / "docs" / name).is_file()


@pytest.mark.parametrize("name", _TEMPLATES)
def test_template_decision_placeholders_are_literal_code_not_hidden_html(name):
    """Unfilled decision values must remain visible when Markdown is rendered."""
    document = (PROJECT_ROOT / "docs" / name).read_text(encoding="utf-8")
    placeholders = list(_PLACEHOLDER.finditer(document))
    assert placeholders, f"Template has no marked operator decisions: {name}"
    for placeholder in placeholders:
        start, end = placeholder.span()
        assert document[start - 1 : start] == "`" and document[end : end + 1] == "`", (
            f"Placeholder must render literally in inline code: {name}: {placeholder[0]}"
        )
    assert not re.search(r"(?<!`)<[^>\n]+>(?!`)", document), (
        f"Template contains an unmarked placeholder or raw HTML: {name}"
    )


@pytest.mark.parametrize("name", _TEMPLATES)
def test_template_local_links_resolve_inside_the_documentation_tree(name):
    """Procedure links must resolve to shipped documentation, never local paths."""
    docs = (PROJECT_ROOT / "docs").resolve()
    path = docs / name
    document = path.read_text(encoding="utf-8")
    links = _LINK.findall(document)
    assert links, f"Template does not link its implementation procedures: {name}"
    assert len(links) == document.count("]("), f"Unrecognized Markdown link syntax: {name}"
    for link in links:
        url = urlsplit(link)
        if url.scheme or url.netloc:
            assert url.scheme == "https" and url.netloc, f"Unsafe external link: {link}"
            continue
        assert not url.query, f"Procedure links must not contain query values: {link}"
        target = (path.parent / unquote(url.path)).resolve() if url.path else path
        assert target.is_relative_to(docs), f"Link leaves the shipped docs tree: {link}"
        assert target.is_file() and target.suffix == ".md", f"Missing procedure: {link}"
