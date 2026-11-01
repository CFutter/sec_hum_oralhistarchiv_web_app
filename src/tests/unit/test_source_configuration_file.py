"""The flat source TOML boundary, before runtime startup activation."""

from pathlib import Path
from unittest.mock import patch

import pytest

from app.paths import PROJECT_ROOT
from app.sources.configuration import configure_sources_from_toml, load_sources_file
from app.sources.oai_pmh_cmdi import OaiPmhCmdiAdapter

_DOCUMENT = """[[sources]]
name = "example_archive"
adapter = "oai_pmh_cmdi"
label = "Example archive"
resource_link_label = "Download"
landing_link_label = "Catalogue"
sensitivity_badge = "Example collection"
endpoint = "https://archive.example.org/oai"
institution_filter = "Example University"
max_visibility = "registered"
requires_record_tier = false
incremental_interval_seconds = 900
rebuild_interval_seconds = 43200
write_timeout_seconds = 240
rebuild_max_inferred_delete_count = 1
rebuild_max_inferred_delete_ratio_percent = 34
max_pages = 7
"""


def test_flat_toml_constructs_the_complete_source_without_fetching() -> None:
    """Check flat toml constructs the complete source without fetching."""
    with patch.object(OaiPmhCmdiAdapter, "fetch", autospec=True) as fetch:
        sources = configure_sources_from_toml(_DOCUMENT)
    fetch.assert_not_called()
    assert len(sources) == 1
    source = sources[0]
    assert source.name == "example_archive"
    assert source.display.label == "Example archive"
    assert source.display.resource_link_label == "Download"
    assert source.display.landing_link_label == "Catalogue"
    assert source.display.sensitivity_badge == "Example collection"
    assert source.schedule.incremental_interval_seconds == 900
    assert source.schedule.rebuild_interval_seconds == 43200
    assert source.schedule.write_timeout_seconds == 240
    assert source.schedule.rebuild_max_inferred_delete_count == 1
    assert source.schedule.rebuild_max_inferred_delete_ratio_percent == 34
    assert source.policy.max_visibility == "registered"
    assert source.policy.requires_record_tier is False
    assert isinstance(source.adapter, OaiPmhCmdiAdapter)
    assert source.adapter.oai_url == "https://archive.example.org/oai"
    assert source.adapter.institution_filter == "Example University"
    assert source.adapter.max_pages == 7


def test_two_flat_entries_keep_configuration_order_and_independent_policies() -> None:
    """Check two flat entries keep configuration order and independent policies."""
    second = _DOCUMENT.replace("example_archive", "second_archive")
    sources = configure_sources_from_toml(_DOCUMENT + "\n" + second)
    assert tuple(source.name for source in sources) == ("example_archive", "second_archive")
    assert sources[0].policy is not sources[1].policy
    assert sources[0].adapter.config_fingerprint() != sources[1].adapter.config_fingerprint()


@pytest.mark.parametrize(
    "document",
    [
        "",
        "sources = []",
        'sources = ["wrong"]',
        "[",
        "unknown = true\n" + _DOCUMENT,
        _DOCUMENT + "\nmax_page = 7\n",
        _DOCUMENT + "\n" + _DOCUMENT,
        _DOCUMENT.replace('adapter = "oai_pmh_cmdi"', 'adapter = "unknown"'),
        _DOCUMENT.replace('adapter = "oai_pmh_cmdi"\n', ""),
        _DOCUMENT.replace('adapter = "oai_pmh_cmdi"', "adapter = true"),
        _DOCUMENT + '\n[sources.display]\nlabel = "Nested"\n',
        _DOCUMENT + "\n[sources.schedule]\nwrite_timeout_seconds = 1\n",
    ],
)
def test_invalid_toml_source_documents_are_rejected(document: str) -> None:
    """Check invalid toml source documents are rejected (ValueError)."""
    with pytest.raises(ValueError):
        configure_sources_from_toml(document)


@pytest.mark.parametrize(
    "replacement",
    [
        "max_pages = true",
        "max_pages = 0",
        'max_pages = "7"',
        'requires_record_tier = "true"',
        "rebuild_max_inferred_delete_count = true",
        "rebuild_max_inferred_delete_count = -1",
        'rebuild_max_inferred_delete_count = "1"',
        "rebuild_max_inferred_delete_ratio_percent = false",
        "rebuild_max_inferred_delete_ratio_percent = 101",
        'rebuild_max_inferred_delete_ratio_percent = "34"',
    ],
)
def test_file_values_keep_strict_model_types(replacement: str) -> None:
    """Check file values keep strict model types (ValueError)."""
    originals = {
        "requires_record_tier": "requires_record_tier = false",
        "max_pages": "max_pages = 7",
        "rebuild_max_inferred_delete_count": "rebuild_max_inferred_delete_count = 1",
        "rebuild_max_inferred_delete_ratio_percent": "rebuild_max_inferred_delete_ratio_percent = 34",
    }
    original = originals[replacement.split(" = ", 1)[0]]
    with pytest.raises(ValueError):
        configure_sources_from_toml(_DOCUMENT.replace(original, replacement))


def test_explicit_file_loader_reads_utf8(tmp_path: Path) -> None:
    """Check explicit file loader reads utf8."""
    file = tmp_path / "sources.toml"
    file.write_text(_DOCUMENT.replace("Example archive", "Example café"), encoding="utf-8")
    sources = load_sources_file(str(file))
    assert sources[0].display.label == "Example café"


@pytest.mark.parametrize(
    ("contents", "error"),
    [(None, FileNotFoundError), (b"\xff", UnicodeDecodeError)],
)
def test_file_errors_propagate(
    tmp_path: Path, contents: bytes | None, error: type[Exception]
) -> None:
    """Check file errors propagate."""
    file = tmp_path / "sources.toml"
    if contents is not None:
        file.write_bytes(contents)
    with pytest.raises(error):
        load_sources_file(file)


def test_shipped_source_example_uses_the_flat_format() -> None:
    """Check shipped source example uses the flat format."""
    sources = load_sources_file(PROJECT_ROOT / "deploy/environment/sources.example.toml")
    assert tuple(source.name for source in sources) == ("example_archive", "fixture_demo")


def test_flat_presentation_and_budget_changes_preserve_the_binding() -> None:
    """Check flat presentation and budget changes preserve the binding."""
    changed = (
        _DOCUMENT.replace('label = "Example archive"', 'label = "Renamed archive"')
        .replace("incremental_interval_seconds = 900", "incremental_interval_seconds = 1800")
        .replace("rebuild_interval_seconds = 43200", "rebuild_interval_seconds = 86400")
        .replace("write_timeout_seconds = 240", "write_timeout_seconds = 120")
        .replace("rebuild_max_inferred_delete_count = 1", "rebuild_max_inferred_delete_count = 100")
        .replace(
            "rebuild_max_inferred_delete_ratio_percent = 34",
            "rebuild_max_inferred_delete_ratio_percent = 25",
        )
        .replace("max_pages = 7", "max_pages = 11")
    )
    first = configure_sources_from_toml(_DOCUMENT)[0]
    second = configure_sources_from_toml(changed)[0]
    assert first.adapter.config_fingerprint() == second.adapter.config_fingerprint()
