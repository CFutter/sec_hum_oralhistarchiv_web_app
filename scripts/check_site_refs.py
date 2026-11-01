#!/usr/bin/env python3
"""Check Git-indexed and unignored repository files against the publication policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess  # nosec B404 - fixed Git inventory command, never a shell
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

POLICY_PATH = "scripts/site-reference-policy.toml"
MIN_REASON_LENGTH = 12
KINDS = {"policy", "compatibility", "vendor", "security-data", "negative-test"}


class ScanError(ValueError):
    """A missing or unsafe input must fail the gate."""


@dataclass(frozen=True)
class Rule:
    """Pair a publication-policy rule ID with its compiled regex."""

    identifier: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class ExceptionRecord:
    """Approve an exact path/rule/line digest and occurrence count."""

    path: str
    rule: str
    digest: str
    count: int


def repository_path(root: Path, name: str) -> Path:
    """Return an existing regular repository file after rejecting traversal, symlinks and special
    files.

    root must be trusted; invalid paths raise ScanError, filesystem errors propagate.
    """
    relative = PurePosixPath(name)
    if (
        not name
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or "\\" in name
        or "\x00" in name
    ):
        raise ScanError("unsafe repository path")
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ScanError(f"symlink input refused: {json.dumps(name)}")
        expected = stat.S_ISREG if index == len(relative.parts) - 1 else stat.S_ISDIR
        if not expected(info.st_mode):
            raise ScanError(f"nonregular input refused: {json.dumps(name)}")
    return current


def read_bytes(root: Path, name: str) -> bytes:
    """Read an existing checked file without following its final symlink; validation/I/O errors
    propagate.
    """
    path = repository_path(root, name)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read()


def required_string(record: dict[str, Any], key: str) -> str:
    """Return a nonblank string field unchanged; otherwise raise ScanError."""
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ScanError(f"policy field must be nonempty text: {key}")
    return value


def load_rules(records: Any) -> list[Rule]:
    """Compile a nonempty exact-field rule list; reject duplicate IDs and empty-matching
    patterns.

    Invalid policy raises ScanError; invalid regex syntax raises re.error.
    """
    if not isinstance(records, list) or not records:
        raise ScanError("policy must define at least one rule")
    rules: list[Rule] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "pattern", "reason"}:
            raise ScanError("invalid rule fields")
        identifier = required_string(record, "id")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", identifier):
            raise ScanError("invalid rule identifier")
        required_string(record, "reason")
        pattern = re.compile(required_string(record, "pattern"))
        if pattern.search("") is not None:
            raise ScanError("rules must not match empty text")
        rules.append(Rule(identifier, pattern))
    if len({rule.identifier for rule in rules}) != len(rules):
        raise ScanError("duplicate rule identifier")
    return rules


def load_exceptions(records: Any, rules: list[Rule]) -> list[ExceptionRecord]:
    """Validate exact reviewed exceptions and reject unknown rules, invalid counts/digests or
    duplicates.
    """
    if not isinstance(records, list):
        raise ScanError("exceptions must be an array")
    result: list[ExceptionRecord] = []
    identifiers = {rule.identifier for rule in rules}
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "rule",
            "line_sha256",
            "count",
            "kind",
            "reason",
        }:
            raise ScanError("invalid exception fields")
        path = required_string(record, "path")
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or any(char in path for char in "*?[]\\\x00")
        ):
            raise ScanError("exception paths must be exact repository paths")
        rule = required_string(record, "rule")
        digest = required_string(record, "line_sha256")
        count = record["count"]
        if rule not in identifiers or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ScanError("unknown exception rule or invalid line digest")
        if type(count) is not int or count < 1:
            raise ScanError("exception counts must be positive integers")
        if (
            required_string(record, "kind") not in KINDS
            or len(required_string(record, "reason")) < MIN_REASON_LENGTH
        ):
            raise ScanError("exceptions need a supported kind and review reason")
        result.append(ExceptionRecord(path, rule, digest, count))
    keys = [(entry.path, entry.rule, entry.digest) for entry in result]
    if len(set(keys)) != len(keys):
        raise ScanError("duplicate exception record")
    return result


def load_policy(root: Path) -> tuple[list[Rule], list[ExceptionRecord]]:
    """Read/decode version-1 policy TOML under root; return validated rules and exceptions.

    Validation, decoding, regex and filesystem errors propagate.
    """
    policy = tomllib.loads(read_bytes(root, POLICY_PATH).decode("utf-8"))
    if set(policy) != {"version", "rules", "exceptions"} or type(policy["version"]) is not int:
        raise ScanError("policy must contain only version, rules and exceptions")
    if policy["version"] != 1:
        raise ScanError("unsupported policy version")
    rules = load_rules(policy["rules"])
    return rules, load_exceptions(policy["exceptions"], rules)


def git_output(root: Path, *arguments: str) -> bytes:
    """Return Git stdout with a 30-second timeout; nonzero exit or any stderr raises ScanError."""
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments]
    result = subprocess.run(  # nosec B603 - fixed Git commands and options, never a shell
        command, capture_output=True, check=False, timeout=30
    )
    if result.returncode or result.stderr:
        raise ScanError("Git inventory failed; run from a complete Git checkout")
    return result.stdout


def tracked_and_new_files(root: Path) -> list[str]:
    """Return sorted indexed/unignored paths at the checkout root; require the policy file.

    Invalid/empty Git inventories raise ScanError; Git timeout/OS failures propagate.
    """
    top = Path(os.fsdecode(git_output(root, "rev-parse", "--show-toplevel").removesuffix(b"\n")))
    if top.resolve() != root.resolve():
        raise ScanError("Git inventory requires the checkout root, not a subdirectory")
    output = git_output(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    names = sorted({os.fsdecode(name) for name in output.split(b"\x00") if name})
    if not names or POLICY_PATH not in names:
        raise ScanError("Git inventory is empty or publication policy is excluded")
    return names


def line_digest(line: bytes) -> str:
    """Hash a line after removing one trailing LF and then one trailing CR."""
    canonical = line.removesuffix(b"\n").removesuffix(b"\r")
    return hashlib.sha256(canonical).hexdigest()


def scan(root: Path) -> int:
    """Print unapproved filename/text findings; return 1 if found, otherwise 0.

    Read every indexed/unignored file, compare approved line hashes/counts and
    reject stale exceptions with ScanError. Multiline matches are never exempted.
    """
    rules, exceptions = load_policy(root)
    approved = {(entry.path, entry.rule, entry.digest): entry.count for entry in exceptions}
    observed = dict.fromkeys(approved, 0)
    findings: list[str] = []
    names = tracked_and_new_files(root)
    for name in names:
        findings.extend(
            f"{json.dumps(name)}:0: {rule.identifier} (filename)"
            for rule in rules
            if rule.pattern.search(name)
        )
        data = read_bytes(root, name)
        full_text = data.decode("utf-8", errors="surrogateescape")
        for rule in rules:
            for match in rule.pattern.finditer(full_text):
                if "\n" in match.group() or "\r" in match.group():
                    number = full_text.count("\n", 0, match.start()) + 1
                    findings.append(f"{json.dumps(name)}:{number}: {rule.identifier} (multiline)")
        for number, line in enumerate(data.splitlines(keepends=True), start=1):
            text = line.decode("utf-8", errors="surrogateescape")
            for rule in rules:
                count = sum(1 for _ in rule.pattern.finditer(text))
                if not count:
                    continue
                key = (name, rule.identifier, line_digest(line))
                if key in approved:
                    observed[key] += count
                else:
                    findings.append(f"{json.dumps(name)}:{number}: {rule.identifier}")
    for finding in findings:
        print(finding)
    stale = [key for key, count in observed.items() if count != approved[key]]
    for path, rule_id, _digest in stale:
        print(f"exception count changed: {json.dumps(path)}: {rule_id}", file=sys.stderr)
    if stale:
        raise ScanError("stale or expanded exception records; review the precise finding")
    print(
        f"Site reference scan: {len(names)} files; {len(findings)} unapproved findings; "
        f"{len(exceptions)} exact reviewed exceptions."
    )
    return 1 if findings else 0


def main() -> int:
    """Parse --root and print scan results; return 0/1 for clean/findings or 2 for scan failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        root = args.root.absolute()
        if any(path.is_symlink() for path in (root, *root.parents)):
            raise ScanError("symlink checkout root refused")
        return scan(root)
    except (OSError, ValueError, re.error, subprocess.SubprocessError) as exc:
        print(f"Site reference scan failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
