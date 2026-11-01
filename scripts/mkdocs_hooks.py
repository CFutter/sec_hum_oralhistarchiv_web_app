"""Expose the canonical root deployment guide through MkDocs without copying it.

Only known guide links are rebased in memory. Markdown code examples and source
files stay unchanged; MkDocs remains an optional documentation dependency.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Any

_GUIDE = "Deployment.md"
_GUIDE_REFERRERS = frozenset(
    {
        "architecture/auth.md",
        "configuration/deployment.md",
        "configuration/settings.md",
        "runbooks/admin-totp-break-glass.md",
        "runbooks/local-staging.md",
    }
)
_GUIDE_DOC_LINKS = frozenset(
    {
        "docs/configuration/settings.md",
        "docs/runbooks/federation-integration.md",
        "docs/runbooks/key-rotation.md",
        "docs/runbooks/retained-staging-inventory.md",
        "docs/runbooks/search-fulltext.md",
        "docs/runbooks/bootstrap-admin.md",
        "docs/runbooks/deployment-boundaries.md",
        "docs/runbooks/security-event-delivery.md",
        "docs/runbooks/mail-recovery.md",
        "docs/runbooks/source-rebinding.md",
        "docs/runbooks/dependency-advisories.md",
    }
)
_FRAGMENTS = {
    "2-vm-setup--hardening": "2-vm-setup-hardening",
    "7-gunicorn-scheduler--systemd": "7-gunicorn-scheduler-systemd",
    "8-nginx--ssl": "8-nginx-ssl",
}
_FENCE = re.compile(r"^[ \t]*(?:>[ \t]*)*(?P<marker>`{3,}|~{3,})(?P<tail>.*)$")
_LINK_END = re.compile(
    r"""[ \t]*(?:(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|"""
    r"""\((?:\\.|[^)\\\n])*\))[ \t]*)?\)"""
)


def _destination(value: str, source_uri: str) -> str:
    """Rebase allowlisted guide links/fragments for source_uri; return other destinations
    unchanged.
    """
    path, separator, fragment = value.partition("#")
    if source_uri == _GUIDE:
        if path in _GUIDE_DOC_LINKS:
            return value.removeprefix("docs/")
        if path:
            return value
    elif source_uri in _GUIDE_REFERRERS and path in {"../Deployment.md", "../../Deployment.md"}:
        path = "../Deployment.md"
    else:
        return value
    return path + separator + _FRAGMENTS.get(fragment, fragment)


def _code_end(text: str, start: int) -> int:
    """Return the end of a matched backtick span, or just its unmatched opener."""
    opener = re.match(r"`+", text[start:])
    if opener is None:
        return start
    length = len(opener[0])
    for closer in re.finditer(r"`+", text[start + length :]):
        if len(closer[0]) == length:
            return start + length + closer.end()
    return start + length


def _link_bounds(text: str, start: int) -> tuple[int, int, int] | None:
    """Locate one inline Markdown link's destination and closing parenthesis."""
    index, depth = start + 1, 1
    while index < len(text) and depth:
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "`":
            index = _code_end(text, index)
            continue
        if text[index] in "[]":
            depth += 1 if text[index] == "[" else -1
        index += 1
    if depth or text[index : index + 1] != "(":
        return None
    index += 1
    while index < len(text) and text[index] in " \t":
        index += 1
    angled = text[index : index + 1] == "<"
    begin = index + int(angled)
    index = begin
    while index < len(text) and text[index] not in (">\n" if angled else " \t\n()"):
        if text[index] == "\\":
            return None
        index += 1
    if index == begin or (angled and text[index : index + 1] != ">"):
        return None
    ending = _LINK_END.match(text, index + int(angled))
    return (begin, index, ending.end()) if ending else None


def _inline(markdown: str, source_uri: str) -> str:
    """Rebase supported inline links while leaving escapes, code spans and images unchanged."""
    pieces: list[str] = []
    index, previous = 0, 0
    while index < len(markdown):
        character = markdown[index]
        if character == "\\":
            index += 2
            continue
        if character == "`":
            index = _code_end(markdown, index)
            continue
        if character == "[" and (index == 0 or markdown[index - 1] != "!"):
            bounds = _link_bounds(markdown, index)
            if bounds:
                begin, end, index = bounds
                replacement = _destination(markdown[begin:end], source_uri)
                pieces.extend((markdown[previous:begin], replacement))
                previous = end
                continue
        index += 1
    pieces.append(markdown[previous:])
    return "".join(pieces)


def render_markdown(markdown: str, *, source_uri: str) -> str:
    """Rebase only this repository's known guide links outside Markdown code."""
    if source_uri != _GUIDE and source_uri not in _GUIDE_REFERRERS:
        return markdown
    output: list[str] = []
    pending: list[str] = []
    fence = ""
    for line in markdown.splitlines(keepends=True):
        match = _FENCE.match(line.rstrip("\r\n"))
        if fence:
            output.append(line)
            if (
                match
                and match["marker"][0] == fence[0]
                and len(match["marker"]) >= len(fence)
                and not match["tail"].strip()
            ):
                fence = ""
        elif match and (match["marker"][0] != "`" or "`" not in match["tail"]):
            output.append(_inline("".join(pending), source_uri))
            pending.clear()
            output.append(line)
            fence = match["marker"]
        else:
            pending.append(line)
    output.append(_inline("".join(pending), source_uri))
    return "".join(output)


def on_files(files: Any, *, config: Any) -> None:
    """Register the root guide and adjust affected pages through MkDocs' event API."""
    if files.get_file_from_path(_GUIDE) is not None:
        raise ValueError("The generated deployment guide conflicts with a documentation file")
    root = Path(config.config_file_path).resolve().parent
    canonical = (root / _GUIDE).read_text(encoding="utf-8")
    file_type = importlib.import_module("mkdocs.structure.files").File
    generated = file_type.generated(
        config, _GUIDE, content=render_markdown(canonical, source_uri=_GUIDE)
    )
    for file in files:
        if file.src_uri in _GUIDE_REFERRERS:
            file.content_string = render_markdown(file.content_string, source_uri=file.src_uri)
    files.append(generated)
