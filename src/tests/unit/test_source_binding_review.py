"""A changed source requires an owner-approved binding pair before any harvest."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from app.services import ingestion, scheduler
from tests.fixtures import make_async_cursor, make_mock_catalogue_stats_cache
from tests.source_fixtures import legacy_source

_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("previous", [None, "b" * 64])
async def test_first_use_and_identical_bindings_need_no_acknowledgement(previous):
    """Check first use and identical bindings need no acknowledgement."""
    cur = make_async_cursor()
    await ingestion._require_source_binding_acknowledgement_cur(
        cur, source="archive", previous_fingerprint=previous, new_fingerprint="b" * 64
    )
    cur.execute.assert_not_awaited()


async def test_changed_binding_requires_the_exact_reviewed_pair():
    """Check changed binding requires the exact reviewed pair."""
    cur = make_async_cursor(fetchone=None)
    with pytest.raises(ingestion._SourceBindingAcknowledgementRequired):
        await ingestion._require_source_binding_acknowledgement_cur(
            cur, source="archive", previous_fingerprint="a" * 64, new_fingerprint="b" * 64
        )
    assert cur.execute.await_args.args[1] == ("archive", "a" * 64, "b" * 64)
    cur.fetchone.return_value = {"acknowledged": 1}
    await ingestion._require_source_binding_acknowledgement_cur(
        cur, source="archive", previous_fingerprint="a" * 64, new_fingerprint="b" * 64
    )


async def test_scheduler_never_automatically_rebuilds_a_binding_awaiting_review(monkeypatch):
    """Check scheduler never automatically rebuilds a binding awaiting review."""
    outcome = ingestion.SyncOutcome(
        "failed", requires_full_rebuild=True, requires_source_acknowledgement=True
    )
    monkeypatch.setattr(
        scheduler, "run_sync", create_autospec(ingestion.run_sync, return_value=outcome)
    )
    rebuild = create_autospec(ingestion.run_full_rebuild)
    monkeypatch.setattr(scheduler, "run_full_rebuild", rebuild)
    cache = make_mock_catalogue_stats_cache()
    assert await scheduler.sync_and_invalidate(object(), cache, legacy_source()) is outcome
    rebuild.assert_not_awaited()
    cache.invalidate_cache.assert_called_once()


def test_owner_acknowledgement_command_needs_no_application_or_source_credentials(tmp_path):
    """Check owner acknowledgement command needs no application or source credentials."""
    program = r"""
'''Run argv[2] with a fake owner connection; argv[1] supplies application sources.'''
import runpy, sys
sys.path.insert(0, sys.argv[1])
import psycopg
calls = []
class Cursor:
    '''Return the stored source fingerprint for the acknowledgement probe.'''
    def fetchone(self):
        '''Return one row containing the old fingerprint.'''
        return ('a' * 64,)
class Connection:
    '''Validate and record source comparison, acknowledgement and audit writes.'''
    def __enter__(self):
        '''Return this fake connection.'''
        return self
    def __exit__(self, kind, value, traceback):
        '''Require a clean exit and record the commit.'''
        assert kind is None
        calls.append('commit')
    def execute(self, statement, parameters):
        '''Assert source/revision parameters and record comparison or durable writes.'''
        if statement.startswith('SELECT'):
            assert 'FOR UPDATE' in statement
            assert parameters == ('archive',)
            calls.append('compare')
            return Cursor()
        if 'security_audit_events' in statement:
            assert 'source_binding_acknowledged' in statement
            assert parameters == ('archive', 'a' * 64, 'b' * 64)
            calls.append('event')
            return
        assert 'source_binding_acknowledgements' in statement
        assert parameters == ('archive', 'a' * 64, 'b' * 64)
        calls.append('acknowledge')
def connect(url, **options):
    '''Assert the owner URL/connect timeout and return a fake connection.'''
    assert url == 'postgresql://owner@127.0.0.1:1/archive'
    assert options['connect_timeout'] == 10
    return Connection()
psycopg.connect = connect
script = sys.argv[2]
sys.argv = [script, '--source', 'archive', '--expected-fingerprint', 'a' * 64,
            '--new-fingerprint', 'b' * 64]
try:
    runpy.run_path(script, run_name='__main__')
except SystemExit as ended:
    assert ended.code == 0
assert calls == ['compare', 'acknowledge', 'event', 'commit']
assert not any(name == 'config' or name.startswith('config.') for name in sys.modules)
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(_ROOT / "src"),
            str(_ROOT / "scripts/acknowledge_source_binding.py"),
        ],
        env={"ENV_STATE": "dev", "DATABASE_URL": "postgresql://owner@127.0.0.1:1/archive"},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stderr == ""
    assert completed.stdout.startswith("Source binding acknowledged")
