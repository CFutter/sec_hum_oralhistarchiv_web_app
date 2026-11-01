"""Actual source processing stays independent of services and runtime settings."""

import os
import subprocess
import sys
from textwrap import dedent

import pytest

from app.paths import PROJECT_ROOT

_IMPORT_GUARD = """
'''Reject source-processing imports of runtime services/settings.'''
import importlib.abc
import sys

class RejectRuntimeImports(importlib.abc.MetaPathFinder):
    '''Reject app.services/config imports while delegating other module searches.'''
    def find_spec(self, fullname, path=None, target=None):
        '''Raise AssertionError for runtime service/settings imports; otherwise return None.'''
        if (
            fullname == 'app.services' or fullname.startswith('app.services.')
            or fullname == 'config' or fullname.startswith('config.')
        ):
            raise AssertionError('Source processing imported ' + fullname)

def assert_no_runtime_modules():
    '''Raise AssertionError if runtime services/settings are already imported.'''
    assert not [
        name for name in sys.modules
        if name == 'app.services' or name.startswith('app.services.')
        or name == 'config' or name.startswith('config.')
    ]

assert_no_runtime_modules()
sys.meta_path.insert(0, RejectRuntimeImports())
"""


def _run_in_fresh_process(body: str, *, reject_runtime: bool = True) -> None:
    """Run the supplied code with an optional import guard and require success within 20 seconds."""
    prefix = dedent(_IMPORT_GUARD) if reject_runtime else ""
    suffix = "\nassert_no_runtime_modules()\n" if reject_runtime else ""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-c", prefix + dedent(body) + suffix],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize(
    ("adapter", "configuration"),
    [("FixtureAdapter", "FixtureConfig"), ("StaticJsonAdapter", "StaticJsonConfig")],
)
def test_package_adapter_fetches_and_round_trips_without_runtime_imports(adapter, configuration):
    """Package adapter fetches and round trips without runtime imports."""
    _run_in_fresh_process(
        f"""
        import json
        from app import sources
        from app.ingestion_contracts import (
            HarvestResult, encode_harvest_result, harvest_result_from_document,
        )

        config = getattr(sources, {configuration!r})(
            name='isolated_archive',
            display=sources.SourceDisplay(label='Isolated archive'),
            max_visibility='public',
        )
        adapter = getattr(sources, {adapter!r}).from_config(config)
        first = adapter.fetch(since=None)
        second = adapter.fetch(since=None)
        assert isinstance(first, HarvestResult) and first == second
        assert first.matching_records and first.matching_records is not second.matching_records
        assert first.validate().utcoffset() is not None
        assert harvest_result_from_document(json.loads(encode_harvest_result(first))) == first
        first.matching_records[0]['title'] = 'Local mutation'
        assert adapter.fetch(since=None) == second
        """
    )


def test_oai_parse_fetch_and_worker_codec_do_not_import_runtime_services():
    """Oai parse fetch and worker codec do not import runtime services."""
    _run_in_fresh_process(
        """
        from unittest.mock import patch
        from lxml import etree
        from app.ingestion_contracts import (
            HarvestResult, encode_harvest_result, validate_parsed_record,
        )
        from app.sources import oai_client
        from tests.oai_fixtures import SAMPLE_CMDI_XML, SOURCE_CURSOR

        record = etree.fromstring(SAMPLE_CMDI_XML.encode())
        parsed = oai_client._parse_cmdi_to_dict(record)
        validate_parsed_record(parsed)

        def records(oai_url, metadata_prefix, since, *, max_pages, budget):
            assert oai_url == 'https://archive.example.org/oai'
            assert metadata_prefix == 'oai_cmdi12' and since == '2026-03-01'
            assert max_pages == 2
            budget.source_cursor = SOURCE_CURSOR
            yield record

        with patch.object(oai_client, '_oai_list_records', autospec=True, side_effect=records) as read:
            result = oai_client.fetch_updates(
                'https://archive.example.org/oai', '2026-03-01',
                'Universität Beispielstadt', max_pages=2,
            )
        read.assert_called_once()
        assert isinstance(result, HarvestResult) and result.source_cursor == SOURCE_CURSOR
        assert result.matching_records == [parsed]
        assert not result.uncertain_records
        assert not result.deleted_uuids and not result.nonmatching_uuids
        payload = oai_client._encode_worker_harvest_result(result)
        assert payload == oai_client.encode_harvest_result(result) == encode_harvest_result(result)
        restored = oai_client._decode_worker_harvest_result(payload)
        assert type(restored) is HarvestResult and restored == result
        assert encode_harvest_result(restored) == payload
        """
    )


def test_complete_json_feed_chain_uses_neutral_validation_and_serialization():
    """Complete JSON feed chain uses neutral validation and serialization."""
    _run_in_fresh_process(
        """
        import json
        from datetime import datetime
        from pathlib import Path
        from app.ingestion_contracts import HarvestResult, harvest_result_from_document
        from app.sources import (
            AuthenticatedFeedPage, FeedRequest, JsonFeedConfig, JsonFeedHarvestBuilder,
        )

        config = JsonFeedConfig.model_validate({
            'name': 'isolated_feed', 'display': {'label': 'Isolated feed'},
            'endpoint': 'https://archive.example.org/feed',
            'credential_env': 'ISOLATED_BEARER', 'signing_key_env': 'ISOLATED_SIGNING_KEY',
        })
        builder = JsonFeedHarvestBuilder(config, since=None)
        for number in (1, 2):
            path = Path('docs/sources/examples') / f'feed-v1-full-page-{number}.json'
            document = json.loads(path.read_text(encoding='utf-8'))
            now = datetime.fromisoformat(document['generated_at'].replace('Z', '+00:00'))
            page = AuthenticatedFeedPage(
                FeedRequest(**document['request']), json.dumps(document).encode(),
            )
            builder.accept(page, now=now)
            assert builder.complete is (number == 2)
        result = harvest_result_from_document(json.loads(builder.finish()))
        assert type(result) is HarvestResult and result.validate() == now
        assert [item['visibility_tier'] for item in result.matching_records] == [
            'public', 'registered', 'vetted',
        ]
        assert result.deleted_uuids and not result.uncertain_records
        """
    )


@pytest.mark.parametrize("services_first", [False, True], ids=["contracts-first", "services-first"])
def test_neutral_facade_and_service_compatibility_exports_preserve_identity(services_first):
    """Neutral facade and service compatibility exports preserve identity."""
    imports = [
        "from app import ingestion_contracts as contracts\n",
        "from app import services\n",
    ]
    if services_first:
        imports.reverse()
    _run_in_fresh_process(
        "".join(imports)
        + """
import importlib
import pickle
from datetime import UTC, datetime
from app import sources
from app.services import harvest as legacy_harvest, parsed_record as legacy_record

owners = {
    'harvest': importlib.import_module('app.ingestion_contracts.harvest'),
    'record': importlib.import_module('app.ingestion_contracts.parsed_record'),
    'tiers': importlib.import_module('app.ingestion_contracts.types'),
}
assert contracts.harvest is owners['harvest']
assert len(contracts.__all__) == len(set(contracts.__all__))
for name in legacy_harvest.__all__:
    assert getattr(legacy_harvest, name) is getattr(contracts, name)
    assert getattr(contracts, name) is getattr(owners['harvest'], name)
for name in legacy_record.__all__:
    assert getattr(legacy_record, name) is getattr(contracts, name)
    assert getattr(contracts, name) is getattr(owners['record'], name)
for name in (
    'HarvestResult', 'HarvestResultSizeError', 'encode_harvest_result',
    'harvest_result_from_document', 'harvest_result_to_json', 'validate_parsed_record',
):
    assert services.__all__.count(name) == 1
    assert getattr(services, name) is getattr(contracts, name)
assert sources.AccessTier is contracts.AccessTier is owners['tiers'].AccessTier
assert contracts.PARSED_RECORD_CONTRACT_VERSION == 4
value = contracts.HarvestResult(source_cursor=datetime(2026, 1, 1, tzinfo=UTC))
restored = pickle.loads(pickle.dumps(value))
assert type(restored) is contracts.HarvestResult and restored == value
""",
        reject_runtime=False,
    )
