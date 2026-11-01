"""The publication scanner checks repository content without broad exclusions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from app.paths import PROJECT_ROOT

_SCANNER = PROJECT_ROOT / "scripts/check_site_refs.py"
_WRAPPER = PROJECT_ROOT / "scripts/check-no-site-refs.sh"
_POLICY_PATH = "scripts/site-reference-policy.toml"
_APPROVED_LINE = b"public vendor blocked-marker"
_RULE = {
    "id": "test-reference",
    "pattern": "blocked[-]marker",
    "reason": "A synthetic prohibited reference for scanner acceptance.",
}


def _git(root: Path, *args: str) -> None:
    """Run git in the synthetic checkout with system/global config disabled and a ten-second deadline."""
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        timeout=10,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )


def _write(root: Path, name: str, data: bytes) -> Path:
    """Create parent directories, write the selected bytes, and return the file path."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _write_policy(
    root: Path,
    *,
    rules: list[dict[str, str]] | None = None,
    exceptions: list[dict[str, Any]] | None = None,
) -> None:
    """Write the synthetic scanner policy, treating None as defaults and empty lists as explicit."""
    selected_rules = rules if rules is not None else [_RULE]
    entries = exceptions if exceptions is not None else []
    parts = ["version = 1\n"]
    if not entries:
        parts.append("exceptions = []\n")
    for rule in selected_rules:
        parts.append("\n[[rules]]\n")
        parts.extend(f"{key} = {json.dumps(value)}\n" for key, value in rule.items())
    for entry in entries:
        parts.append("\n[[exceptions]]\n")
        parts.extend(f"{key} = {json.dumps(value)}\n" for key, value in entry.items())
    _write(root, _POLICY_PATH, "".join(parts).encode())


def _repository(tmp_path: Path) -> Path:
    """Initialize a synthetic checkout, write its policy, and stage all files without committing."""
    root = tmp_path / "checkout"
    root.mkdir()
    _git(root, "init", "--quiet")
    _write_policy(root)
    _git(root, "add", "--all")
    return root


def _scan(root: Path, *, wrapper: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the scanner or wrapper with isolated git configuration and a fifteen-second deadline."""
    command = ["bash", str(_WRAPPER)] if wrapper else [sys.executable, str(_SCANNER)]
    return subprocess.run(
        [*command, "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )


def _exception(name: str = "docs/upstream.md") -> dict[str, Any]:
    """Build an exact-line exception for the synthetic approved public reference."""
    return {
        "path": name,
        "rule": "test-reference",
        "line_sha256": hashlib.sha256(_APPROVED_LINE).hexdigest(),
        "count": 1,
        "kind": "vendor",
        "reason": "Reviewed synthetic public upstream declaration.",
    }


def _real_rules(root: Path) -> None:
    """Copy real deny rules into the synthetic policy with exact-line exceptions for their
    declarations.
    """
    source = tomllib.loads((PROJECT_ROOT / _POLICY_PATH).read_text(encoding="utf-8"))
    rules = [
        {key: str(rule[key]) for key in ("id", "pattern", "reason")} for rule in source["rules"]
    ]
    _write_policy(root, rules=rules)
    # Only the exact copied deny-pattern declarations may refer to themselves.
    exceptions: list[dict[str, Any]] = []
    for line in (root / _POLICY_PATH).read_bytes().splitlines():
        for rule in rules:
            count = len(list(re.finditer(rule["pattern"], line.decode())))
            if count:
                exceptions.append(
                    {
                        "path": _POLICY_PATH,
                        "rule": rule["id"],
                        "line_sha256": hashlib.sha256(line).hexdigest(),
                        "count": count,
                        "kind": "policy",
                        "reason": "Exact deny-pattern declaration copied from the reviewed policy.",
                    }
                )
    _write_policy(root, rules=rules, exceptions=exceptions)


def test_clean_repository_passes(tmp_path: Path) -> None:
    """Check clean repository passes."""
    root = _repository(tmp_path)
    _write(root, "README.md", b"Generic catalogue documentation.\n")
    result = _scan(root)
    assert result.returncode == 0, result.stderr
    assert "0 unapproved findings" in result.stdout


@pytest.mark.parametrize(
    "name",
    [
        "README.md",
        "docs/operation.md",
        "src/app/example.py",
        "deploy/service.conf.example",
        ".github/workflows/example.yml",
        ".env.example",
    ],
    ids=["root", "documentation", "application", "deployment", "workflow", "environment"],
)
def test_new_reference_fails_in_every_repository_area(tmp_path: Path, name: str) -> None:
    """Check new reference fails in every repository area."""
    root = _repository(tmp_path)
    _write(root, name, b"blocked-marker\n")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert f"{json.dumps(name)}:1: test-reference" in result.stdout


def test_binary_content_is_scanned_without_utf8_assumptions(tmp_path: Path) -> None:
    """Check binary content is scanned without utf8 assumptions."""
    root = _repository(tmp_path)
    _write(root, "assets/example.bin", b"\xff\x00blocked-marker\xfe\n")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert '"assets/example.bin":1: test-reference' in result.stdout


def test_filename_findings_are_escaped_and_do_not_need_matching_content(tmp_path: Path) -> None:
    """Check filename findings are escaped and do not need matching content."""
    root = _repository(tmp_path)
    name = "docs/a blocked-marker\nreference.md"
    _write(root, name, b"ordinary content\n")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert f"{json.dumps(name)}:0: test-reference (filename)" in result.stdout
    assert name not in result.stdout


def test_tracked_ignored_content_is_still_checked(tmp_path: Path) -> None:
    """Check tracked ignored content is still checked."""
    root = _repository(tmp_path)
    _write(root, ".gitignore", b"private.local\n")
    _write(root, "private.local", b"blocked-marker\n")
    _git(root, "add", "--force", "private.local")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert '"private.local":1:' in result.stdout


def test_untracked_ignored_environment_is_not_treated_as_repository_content(tmp_path: Path) -> None:
    """Check untracked ignored environment is not treated as repository content."""
    root = _repository(tmp_path)
    _write(root, ".gitignore", b".venv/\n.env\n")
    _write(root, ".venv/local.txt", b"blocked-marker\n")
    _write(root, ".env", b"blocked-marker\n")
    result = _scan(root)
    assert result.returncode == 0, result.stderr
    assert "0 unapproved findings" in result.stdout


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_exact_reviewed_line_is_accepted_with_checkout_newlines(
    tmp_path: Path, newline: bytes
) -> None:
    """Check exact reviewed line is accepted with checkout newlines."""
    root = _repository(tmp_path)
    _write(root, "docs/upstream.md", _APPROVED_LINE + newline)
    _write_policy(root, exceptions=[_exception()])
    result = _scan(root)
    assert result.returncode == 0, result.stderr
    assert "1 exact reviewed exceptions" in result.stdout


@pytest.mark.parametrize("change", ["changed-line", "extra-occurrence", "removed-line"])
def test_changed_or_stale_exception_never_silently_passes(tmp_path: Path, change: str) -> None:
    """Check changed or stale exception never silently passes."""
    root = _repository(tmp_path)
    content = {
        "changed-line": b"different vendor blocked-marker\n",
        "extra-occurrence": _APPROVED_LINE + b"\n" + _APPROVED_LINE + b"\n",
        "removed-line": b"ordinary replacement\n",
    }[change]
    _write(root, "docs/upstream.md", content)
    _write_policy(root, exceptions=[_exception()])
    result = _scan(root)
    assert result.returncode == 2
    assert "exception count changed" in result.stderr


def test_allowance_cannot_be_copied_to_another_file(tmp_path: Path) -> None:
    """Check allowance cannot be copied to another file."""
    root = _repository(tmp_path)
    _write(root, "docs/upstream.md", _APPROVED_LINE + b"\n")
    _write(root, "deploy/copied.conf", _APPROVED_LINE + b"\n")
    _write_policy(root, exceptions=[_exception()])
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert '"deploy/copied.conf":1: test-reference' in result.stdout


@pytest.mark.parametrize("invalid", ["glob", "duplicate", "zero-count"])
def test_invalid_exception_records_fail_closed(tmp_path: Path, invalid: str) -> None:
    """Check invalid exception records fail closed."""
    root = _repository(tmp_path)
    entry = _exception()
    entries = [entry]
    if invalid == "glob":
        entry["path"] = "docs/*.md"
    elif invalid == "duplicate":
        entries.append(dict(entry))
    else:
        entry["count"] = 0
    _write_policy(root, exceptions=entries)
    result = _scan(root)
    assert result.returncode == 2
    assert "Site reference scan failed:" in result.stderr


@pytest.mark.parametrize(
    "policy",
    [
        b"version = [\n",
        b"version=2\nrules=[]\nexceptions=[]\n",
        b"version=1\nrules=[]\nexceptions=[]\n",
    ],
    ids=["invalid-toml", "unknown-version", "empty-rule-list"],
)
def test_unusable_policy_is_an_error(tmp_path: Path, policy: bytes) -> None:
    """Check unusable policy is an error."""
    root = _repository(tmp_path)
    _write(root, _POLICY_PATH, policy)
    result = _scan(root)
    assert result.returncode == 2
    assert "Site reference scan failed:" in result.stderr


@pytest.mark.parametrize("parent", [False, True], ids=["leaf", "parent"])
def test_symlink_inputs_cannot_escape_the_checkout(tmp_path: Path, parent: bool) -> None:
    """Check symlink inputs cannot escape the checkout."""
    root = _repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.md").write_text("ordinary text\n", encoding="utf-8")
    if parent:
        tracked = _write(root, "docs/file.md", b"ordinary text\n")
        _git(root, "add", "docs/file.md")
        tracked.unlink()
        tracked.parent.rmdir()
        (root / "docs").symlink_to(outside, target_is_directory=True)
    else:
        (root / "linked.md").symlink_to(outside / "file.md")
    result = _scan(root)
    assert result.returncode == 2
    assert "symlink input refused" in result.stderr


def test_missing_tracked_file_is_not_a_clean_inventory(tmp_path: Path) -> None:
    """Check missing tracked file is not a clean inventory."""
    root = _repository(tmp_path)
    path = _write(root, "docs/missing.md", b"ordinary text\n")
    _git(root, "add", "docs/missing.md")
    path.unlink()
    result = _scan(root)
    assert result.returncode == 2
    assert "Site reference scan failed:" in result.stderr


def test_snapshot_without_git_provenance_refuses(tmp_path: Path) -> None:
    """Check snapshot without git provenance refuses."""
    root = tmp_path / "unversioned"
    root.mkdir()
    _write_policy(root)
    result = _scan(root)
    assert result.returncode == 2
    assert "Git inventory" in result.stderr


def test_shell_entrypoint_preserves_failure_status(tmp_path: Path) -> None:
    """Check shell entrypoint preserves failure status."""
    root = _repository(tmp_path)
    _write(root, "README.md", b"blocked-marker\n")
    result = _scan(root, wrapper=True)
    assert result.returncode == 1, result.stderr
    assert "1 unapproved findings" in result.stdout


@pytest.mark.parametrize(
    ("sample", "rule"),
    [
        ("admin@" + "u" + "zh.ch", "institution"),
        ("Kass" + "el", "former-site"),
        ("SWI" + "TCHaai", "organisation"),
        ("SWISS" + "UBASE_OAI_PMH_URL", "upstream-name"),
        ("Ca" + "ddy", "obsolete-proxy"),
        ("Central" + " IT", "site-operations"),
        ("https://github.com/" + "CFut" + "ter/private", "private-repository"),
    ],
    ids=["domain", "place", "organisation", "retired-key", "proxy", "operations", "repository"],
)
def test_real_policy_rejects_each_protected_reference_class(
    tmp_path: Path, sample: str, rule: str
) -> None:
    """Check real policy rejects each protected reference class."""
    root = _repository(tmp_path)
    _real_rules(root)
    _write(root, "new-reference.txt", sample.encode() + b"\n")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert f'"new-reference.txt":1: {rule}' in result.stdout


def test_real_policy_allows_ordinary_technical_switch_language(tmp_path: Path) -> None:
    """Check real policy allows ordinary technical switch language."""
    root = _repository(tmp_path)
    _real_rules(root)
    _write(
        root, "README.md", b"The operator may switch workers after switching the active release.\n"
    )
    result = _scan(root)
    assert result.returncode == 0, result.stderr
    assert "0 unapproved findings" in result.stdout


@pytest.mark.parametrize(
    ("sample", "rule"),
    [
        ("Central\n" + "IT", "site-operations"),
        ("univers" + "ity\n" + "of\n" + "zurich", "institution"),
    ],
    ids=["operations-phrase", "institution-name"],
)
def test_real_policy_rejects_protected_references_across_physical_lines(
    tmp_path: Path, sample: str, rule: str
) -> None:
    """Check real policy rejects protected references across physical lines."""
    root = _repository(tmp_path)
    _real_rules(root)
    _write(root, "new-reference.txt", sample.encode() + b"\n")
    result = _scan(root)
    assert result.returncode == 1, result.stderr
    assert rule in result.stdout
    assert '"new-reference.txt"' in result.stdout


def test_subdirectory_with_policy_cannot_stand_in_for_the_complete_checkout(tmp_path: Path) -> None:
    """Check subdirectory with policy cannot stand in for the complete checkout."""
    root = _repository(tmp_path)
    nested = root / "partial-checkout"
    nested.mkdir()
    _write_policy(nested)
    _write(nested, "README.md", b"ordinary subset\n")
    result = _scan(nested)
    assert result.returncode == 2
    assert "Git inventory" in result.stderr
