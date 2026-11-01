"""Behavior references stay executable; collection is not execution evidence."""

import ast
import json
import re
import subprocess
import sys
from datetime import UTC, datetime

from app.paths import PROJECT_ROOT
from app.sources import FeedRecordInput
from app.sources.json_feed_records import classify_feed_record

_DOCS = PROJECT_ROOT / "docs" / "sources"
_MAP = _DOCS / "source-b-evidence.json"
_ID = re.compile(r"\bSB-(?:DISC|VIS|TRANS)-\d{3}\b")
_EXPECTED_IDS = {
    f"SB-{category}-{number:03d}"
    for category, count in (("DISC", 9), ("VIS", 9), ("TRANS", 4))
    for number in range(1, count + 1)
}
_COLLECT = """
'''Collect pytest node IDs/markers to argv[1]; pass remaining arguments to pytest.'''
import json
import sys
from pathlib import Path
import pytest

class Collector:
    '''Write collection evidence through a pytest hook.'''
    def pytest_collection_finish(self, session):
        '''Write session node IDs and sorted marker names as UTF-8 JSON to argv[1].'''
        Path(sys.argv[1]).write_text(json.dumps([
            {"nodeid": item.nodeid, "markers": sorted({mark.name for mark in item.iter_markers()})}
            for item in session.items
        ]), encoding="utf-8")

raise SystemExit(pytest.main(sys.argv[2:], plugins=[Collector()]))
"""


def _evidence():
    """Read the source-B evidence map as JSON."""
    return json.loads(_MAP.read_text(encoding="utf-8"))


def _mapped_nodes():
    """Return the sorted distinct test node IDs named by the evidence requirements."""
    return sorted(
        {node for entry in _evidence()["requirements"].values() for node in entry["tests"]}
    )


def _function(nodeid):
    """Resolve a strict unparametrized evidence test node ID to its function AST."""
    filename, *names = nodeid.split("::")
    assert re.fullmatch(r"src/tests/(?:unit|integration)/test_[a-z0-9_]+\.py", filename), nodeid
    assert names and names[-1].startswith("test_") and "[" not in nodeid, nodeid
    body = ast.parse((PROJECT_ROOT / filename).read_text(encoding="utf-8")).body
    for name in names:
        matches = [
            item
            for item in body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
        ]
        assert len(matches) == 1, nodeid
        selected = matches[0]
        body = selected.body
    assert isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)), nodeid
    return selected


def test_structural_record_validation_does_not_certify_public_disclosure():
    """SB-DISC-009: accepted text still needs independent public-disclosure approval."""
    page = json.loads((_DOCS / "examples/feed-v1-full-page-1.json").read_text(encoding="utf-8"))
    wire = page["records"][0]
    # Synthetic counterexample: structural validation cannot recognize this semantic defect.
    # This value is never ingested or presented as approved public metadata.
    title = "Confidential participant interview; synthetic sample not approved for publication"
    wire["title"] = title
    result = classify_feed_record(
        FeedRecordInput(wire["uuid"], json.dumps(wire).encode("utf-8")),
        cutoff=datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC),
        since=None,
        max_record_bytes=65536,
    )
    assert isinstance(result, dict) and result["title"] == title


def test_every_stable_requirement_maps_to_literal_behavior_docstrings_and_external_evidence():
    """Check every stable requirement maps to literal behavior docstrings and external evidence."""
    contract = (PROJECT_ROOT / "docs/architecture/source-b-ingestion-contract.md").read_text(
        encoding="utf-8"
    )
    normative_ids = re.findall(r"^- \*\*(SB-(?:DISC|VIS|TRANS)-\d{3}) —", contract, re.MULTILINE)
    assert len(normative_ids) == len(_EXPECTED_IDS) == 22
    assert set(normative_ids) == _EXPECTED_IDS
    evidence = _evidence()
    assert set(evidence) == {
        "schema_version",
        "evidence_limit",
        "operational_evidence",
        "requirements",
    }
    assert evidence["schema_version"] == 1
    assert set(evidence["requirements"]) == _EXPECTED_IDS
    assert set(evidence["operational_evidence"]) == {
        "source_owner_approval",
        "real_feed_acceptance",
        "representative_encrypted_restore",
    }
    assert all(
        isinstance(value, str) and value.strip()
        for value in evidence["operational_evidence"].values()
    )
    for requirement, entry in evidence["requirements"].items():
        assert set(entry) == {"tests", "operational_evidence"}, requirement
        assert entry["tests"] and len(entry["tests"]) == len(set(entry["tests"])), requirement
        external = entry["operational_evidence"]
        assert len(external) == len(set(external))
        assert set(external) <= set(evidence["operational_evidence"]), requirement
        for nodeid in entry["tests"]:
            assert requirement in _ID.findall(ast.get_docstring(_function(nodeid)) or ""), nodeid
    for requirement in ("SB-DISC-002", "SB-DISC-003", "SB-DISC-004", "SB-DISC-005", "SB-DISC-009"):
        assert (
            "source_owner_approval" in evidence["requirements"][requirement]["operational_evidence"]
        )
    assert (
        "representative_encrypted_restore"
        in evidence["requirements"]["SB-VIS-009"]["operational_evidence"]
    )


def test_mapped_behavior_nodes_collect_without_skip_or_xfail_placeholders(tmp_path):
    """The map resolves real parameter cases; a green collection does not establish a pass."""
    output = tmp_path / "collected-evidence.json"
    expected = set(_mapped_nodes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _COLLECT,
            str(output),
            "--collect-only",
            "-q",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            *sorted(expected),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout + result.stderr)[-6000:]
    collected = json.loads(output.read_text(encoding="utf-8"))
    assert collected
    assert {item["nodeid"].split("[", 1)[0] for item in collected} == expected
    assert not [item for item in collected if {"skip", "skipif", "xfail"} & set(item["markers"])]
