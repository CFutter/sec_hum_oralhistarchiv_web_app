"""The live OAI adapter preserves transport results and configuration binding."""

import os
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.paths import PROJECT_ROOT
from app.services.harvest import HarvestResult
from app.sources import oai_client, oai_pmh_cmdi
from app.sources.base import SourceAdapter, SourcePolicy
from app.sources.oai_pmh_cmdi import OaiPmhCmdiAdapter
from config import settings


def _classify_access(raw: str | None) -> str:
    """Map a falsey raw access value to public; preserve any truthy value."""
    return raw or "public"


def _adapter() -> OaiPmhCmdiAdapter:
    """Build an OAI adapter with the sample classification policy and seven-page limit."""
    return OaiPmhCmdiAdapter(
        policy=SourcePolicy(
            name="example_archive",
            max_visibility="registered",
            classify_access=_classify_access,
            requires_record_tier=False,
        ),
        oai_url="https://archive.example/oai",
        institution_filter="Example University",
        max_pages=7,
    )


def test_fetch_forwards_configuration_and_preserves_the_result_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Check fetch forwards configuration and preserves the result object."""
    monkeypatch.setattr(settings, "log_level", "DEBUG")
    monkeypatch.setattr(settings, "log_format", "text")
    adapter: SourceAdapter = _adapter()
    expected = HarvestResult(
        source_cursor=datetime(2026, 10, 1, tzinfo=UTC),
        deleted_uuids={"oai:example:withdrawn"},
        nonmatching_uuids={"oai:example:elsewhere"},
        uncertain_records={"oai:example:uncertain": "metadata unavailable"},
    )

    with patch(
        "app.sources.oai_client.fetch_updates_isolated",
        autospec=True,
        return_value=expected,
    ) as fetch:
        result = adapter.fetch(since=datetime.fromisoformat("2026-09-30T00:30:00+01:00"))

    fetch.assert_called_once_with(
        oai_url="https://archive.example/oai",
        since="2026-09-29",
        institution_filter="Example University",
        max_pages=7,
        source="example_archive",
        log_level=settings.log_level,
        log_format=settings.log_format,
        cancel_event=None,
    )
    assert result is expected


def test_fingerprint_binds_access_mapping_and_injected_policy() -> None:
    """Check fingerprint binds access mapping and injected policy."""
    adapter = _adapter()
    # Bind exact access mapping and CMDI parser generation 2.
    expected = "0eb253b547ebff43670aa1b3bc6bfc7c9eaf8ba8955dfde6910524be8c409e70"

    assert adapter.name == "example_archive"
    assert adapter.config_fingerprint() == expected
    assert replace(adapter, max_pages=11).config_fingerprint() == expected

    for changed in (
        replace(adapter, policy=replace(adapter.policy, name="other_archive")),
        replace(adapter, oai_url="https://other.example/oai"),
        replace(adapter, institution_filter="Other University"),
        replace(adapter, policy=replace(adapter.policy, max_visibility="vetted")),
    ):
        assert changed.config_fingerprint() != expected

    # Unicode escaping and surrounding whitespace are compatibility inputs.
    unicode_adapter = replace(
        adapter,
        institution_filter="  Universität Example  ",
    )
    assert unicode_adapter.config_fingerprint() == (
        "ec5f40f97261938de554d3f644e4e460ba8dbfd53926bafb434e7209ee0dd27a"
    )


def test_fingerprint_changes_with_cmdi_parser_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check fingerprint changes with CMDI parser contract."""
    adapter = _adapter()
    original = adapter.config_fingerprint()

    monkeypatch.setattr(
        oai_pmh_cmdi,
        "OAI_CMDI_PARSER_CONTRACT_VERSION",
        oai_pmh_cmdi.OAI_CMDI_PARSER_CONTRACT_VERSION + 1,
    )

    assert adapter.config_fingerprint() != original


def test_fetch_preserves_the_transport_failure() -> None:
    """Check fetch preserves the transport failure."""
    failure = oai_client.OAIProtocolError("pagination_loop", "source page limit reached")

    with (
        patch("app.sources.oai_client.fetch_updates_isolated", autospec=True, side_effect=failure),
        pytest.raises(oai_client.OAIProtocolError) as exc_info,
    ):
        _adapter().fetch(since=None)

    assert exc_info.value is failure


@pytest.mark.parametrize("adapter_first", [True, False], ids=["adapter-first", "services-first"])
def test_adapters_and_services_import_in_either_order(adapter_first: bool) -> None:
    """Check adapters and services import in either order."""
    adapter_imports = (
        "from app.sources import configure_sources\n"
        "from app.sources import SourceAdapter, SourceDisplay\n"
        "from app.sources import OaiPmhCmdiAdapter, OaiPmhCmdiConfig\n"
        "from app.sources import oai_client\n"
        "assert oai_client._harvest_worker.__module__ == 'app.sources.oai_client'\n"
        "sources = configure_sources([OaiPmhCmdiConfig(\n"
        "    name='example_archive',\n"
        "    display=SourceDisplay(label='Example archive'),\n"
        "    endpoint='https://archive.example.org/oai',\n"
        "    institution_filter='Example University',\n"
        ")])\n"
        "assert sources[0].name == 'example_archive'\n"
        "assert len(sources[0].adapter.config_fingerprint()) == 64\n"
    )
    adapter_imports += (
        "from app.sources.configuration import configure_sources_from_toml\n"
        "toml_sources = configure_sources_from_toml('''\n"
        "[[sources]]\n"
        'name = "example_archive"\n'
        'adapter = "oai_pmh_cmdi"\n'
        'label = "Example archive"\n'
        'endpoint = "https://archive.example.org/oai"\n'
        'institution_filter = "Example University"\n'
        "''')\n"
        "assert toml_sources[0].name == 'example_archive'\n"
    )
    adapter_imports += (
        "from app.sources import FixtureAdapter, FixtureConfig\n"
        "fixture = configure_sources([FixtureConfig(\n"
        "    name='offline_archive',\n"
        "    display=SourceDisplay(label='Offline archive'),\n"
        ")])[0]\n"
        "assert isinstance(fixture.adapter, FixtureAdapter)\n"
        "assert len(fixture.adapter.config_fingerprint()) == 64\n"
        "fixture_sources = configure_sources_from_toml('''\n"
        "[[sources]]\n"
        'name = "offline_archive"\n'
        'adapter = "fixture"\n'
        'label = "Offline archive"\n'
        "''')\n"
        "assert fixture_sources[0].name == 'offline_archive'\n"
        "from app.sources import validate_source_startup\n"
        "validate_source_startup(sources, environment='dev')\n"
        "validate_source_startup(toml_sources, environment='dev')\n"
        "validate_source_startup(fixture_sources, environment='dev')\n"
    )
    adapter_imports += (
        "from pathlib import Path\n"
        "from tempfile import TemporaryDirectory\n"
        "from app.sources import load_sources_for_startup\n"
        "with TemporaryDirectory() as temporary:\n"
        "    source_file = Path(temporary) / 'sources.toml'\n"
        "    source_file.write_text('''\n"
        "[[sources]]\n"
        'name = "offline_startup"\n'
        'adapter = "fixture"\n'
        'label = "Offline startup"\n'
        "''', encoding='utf-8')\n"
        "    startup_sources = load_sources_for_startup(source_file, environment='dev')\n"
        "assert startup_sources[0].name == 'offline_startup'\n"
    )
    service_import = "from app.services import ingestion as sync\n"
    script = "import sys\n"
    if adapter_first:
        script += (
            adapter_imports
            + "assert 'app.services' not in sys.modules\n"
            + "assert 'config' not in sys.modules\n"
            + service_import
        )
    else:
        script += service_import + adapter_imports
    script += "assert sys.modules['app.services.ingestion'] is sync\n"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize(
    ("since", "error"),
    [
        ("2026-09-29", TypeError),
        (123, TypeError),
        (datetime(2026, 9, 29, tzinfo=UTC).replace(tzinfo=None), ValueError),
    ],
)
def test_fetch_rejects_invalid_boundaries_before_transport(
    since: object, error: type[Exception]
) -> None:
    """Check fetch rejects invalid boundaries before transport (error)."""
    with (
        patch("app.sources.oai_client.fetch_updates_isolated", autospec=True) as fetch,
        pytest.raises(error),
    ):
        _adapter().fetch(since=since)  # type: ignore[arg-type]
    fetch.assert_not_called()


def test_full_fetch_preserves_existing_oai_baseline() -> None:
    """Check full fetch preserves existing OAI baseline."""
    expected = HarvestResult(source_cursor=datetime(2026, 10, 1, tzinfo=UTC))
    with patch(
        "app.sources.oai_client.fetch_updates_isolated",
        autospec=True,
        return_value=expected,
    ) as fetch:
        result = _adapter().fetch(since=None)

    fetch.assert_called_once_with(
        oai_url="https://archive.example/oai",
        since="1900-01-01",
        institution_filter="Example University",
        max_pages=7,
        source="example_archive",
        log_level=settings.log_level,
        log_format=settings.log_format,
        cancel_event=None,
    )
    assert result is expected
