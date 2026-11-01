"""The owner policy command has no dependency on authentication or feed keys."""

import subprocess
import sys
from pathlib import Path

from app.services import build_catalogue_policy, compile_default_catalogue_policy
from app.sources import load_catalogue_sources_for_startup

_ROOT = Path(__file__).resolve().parents[3]
_SOURCE_DOCUMENT = """[[sources]]
name = "policy_archive"
adapter = "json_feed"
label = "Policy archive"
endpoint = "https://archive.example.org/feed"
credential_env = "POLICY_FEED_BEARER"
signing_key_env = "POLICY_FEED_SIGNING_KEY"
max_visibility = "public"
[sources.field_visibility]
description = "vetted"
"""


def test_default_compiler_retains_the_web_policy_fingerprint_and_masks(tmp_path):
    """Check default compiler retains the web policy fingerprint and masks."""
    path = tmp_path / "sources.toml"
    path.write_text(_SOURCE_DOCUMENT)
    sources = load_catalogue_sources_for_startup(path, environment="dev")
    compiled = compile_default_catalogue_policy(sources)
    web = build_catalogue_policy(sources)
    assert compiled.fingerprint == web.fingerprint
    assert compiled.page_masks == web.page_masks
    assert compiled.document_masks_json == web.document_masks_json
    assert set(compiled.field_names) == set(web.field_names)


def test_cli_uses_only_three_environment_values_and_the_owner_compare_and_swap(tmp_path):
    """Check CLI uses only three environment values and the owner compare and swap."""
    path = tmp_path / "sources.toml"
    path.write_text(_SOURCE_DOCUMENT)
    program = r"""
'''Run argv[2] with a fake owner connection; argv[1] supplies application sources.'''
import runpy
import sys
sys.path.insert(0, sys.argv[1])
import psycopg
calls = []
class Connection:
    '''Validate and record the policy replacement transaction.'''
    def __enter__(self):
        '''Return this fake connection.'''
        return self
    def __exit__(self, kind, value, traceback):
        '''Require a clean exit and append the commit marker.'''
        assert kind is None
        calls.append('committed')
    def execute(self, statement, values):
        '''Assert the replacement SQL, fingerprints and masks, then record the call.'''
        assert statement == 'SELECT public.catalogue_replace_search_policy(%s, %s, %s)'
        assert values[0] == 'a' * 64
        assert len(values[1]) == 64
        assert set(values[2].obj) == {'0', '1', '2'}
        assert values[2].obj['0']['policy_archive'] & 1 == 0
        calls.append('replacement')
def connect(url, **options):
    '''Assert owner URL/timeouts and return a fake connection without network I/O.'''
    assert url == 'postgresql://policy-owner@127.0.0.1:1/archive'
    assert options['connect_timeout'] == 10
    assert options['options'] == '-c statement_timeout=600000 -c lock_timeout=10000'
    return Connection()
psycopg.connect = connect
script = sys.argv[2]
sys.argv = [script, '--expected-fingerprint', 'a' * 64]
try:
    runpy.run_path(script, run_name='__main__')
except SystemExit as ended:
    assert ended.code == 0
assert calls == ['replacement', 'committed']
assert not any(name == 'config' or name.startswith('config.') for name in sys.modules)
assert 'app.services.datasets' not in sys.modules
assert 'app.services.search_cursor' not in sys.modules
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(_ROOT / "src"),
            str(_ROOT / "scripts/rebuild_search_policy.py"),
        ],
        env={
            "DATABASE_URL": "postgresql://policy-owner@127.0.0.1:1/archive",
            "SOURCES_CONFIG_FILE": str(path),
            "ENV_STATE": "dev",
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("Search policy installed: ")
    assert result.stderr == ""
