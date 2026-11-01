"""Keep the standalone deployment verifier aligned with current view contracts."""

import importlib.util
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT

_SCRIPT = PROJECT_ROOT / "scripts/check_runtime_verifier.py"
_VERIFIER = PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"


def _checker():
    """Load and execute the selected repository script in an isolated module."""
    spec = importlib.util.spec_from_file_location("runtime_verifier_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipped_verifier_matches_all_current_view_contracts():
    """Check shipped verifier matches all current view contracts."""
    _checker().verify_view_contracts(_VERIFIER.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("catalogue_search_candidates() AS id", "legacy_search_candidates() AS id"),
        ("quarantine.uuid = stored.uuid", "quarantine.uuid <> stored.uuid"),
        ("'id:integer'", "'id:bigint'"),
        ("'catalogue_search_candidates', ARRAY", "'unmanaged_view', ARRAY"),
    ],
)
def test_checker_rejects_stale_definitions_and_projections(before, after):
    """Check checker rejects stale definitions and projections (ValueError)."""
    text = _VERIFIER.read_text(encoding="utf-8")
    assert before in text
    with pytest.raises(ValueError, match="view contracts differ"):
        _checker().verify_view_contracts(text.replace(before, after))


def test_checker_rejects_duplicate_and_missing_view_contracts():
    """Check checker rejects duplicate and missing view contracts (ValueError)."""
    checker = _checker()
    text = _VERIFIER.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate embedded view contract"):
        checker.verify_view_contracts(text + text)
    with pytest.raises(ValueError, match="view contracts differ"):
        checker.verify_view_contracts("")


def test_command_returns_failure_for_an_unreadable_asset(monkeypatch, tmp_path):
    """Check command returns failure for an unreadable asset."""
    checker = _checker()
    monkeypatch.setattr(checker, "_VERIFIER_PATH", Path(tmp_path / "missing.sql"))
    assert checker.main() == 1
