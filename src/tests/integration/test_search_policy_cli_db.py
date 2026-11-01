"""Run the standalone owner policy command with a real database and no app keys."""

import subprocess
import sys
from pathlib import Path

from app.services import compile_default_catalogue_policy, synchronize_search_policy
from app.sources import load_catalogue_sources_for_startup

_ROOT = Path(__file__).resolve().parents[3]


async def test_policy_cli_replaces_with_only_database_source_file_and_environment(
    db_pool, sync_conn, tmp_path
):
    """Verify policy cli replaces with only database source file and environment."""
    path = tmp_path / "sources.toml"
    base = """[[sources]]
name = "policy_archive"
adapter = "json_feed"
label = "Policy archive"
endpoint = "https://archive.example.org/feed"
credential_env = "UNAVAILABLE_FEED_BEARER"
signing_key_env = "UNAVAILABLE_FEED_SIGNING_KEY"
max_visibility = "public"
"""
    path.write_text(base)
    before = compile_default_catalogue_policy(
        load_catalogue_sources_for_startup(path, environment="dev")
    )
    await synchronize_search_policy(db_pool, before)
    path.write_text(base + '[sources.field_visibility]\ndescription = "vetted"\n')
    after = compile_default_catalogue_policy(
        load_catalogue_sources_for_startup(path, environment="dev")
    )
    assert after.fingerprint != before.fingerprint
    program = (
        "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
        "sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    )

    def run(expected):
        """Execute the search-policy CLI with explicit configuration and expected fingerprint."""
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                program,
                str(_ROOT / "src"),
                str(_ROOT / "scripts/rebuild_search_policy.py"),
                "--expected-fingerprint",
                expected,
            ],
            env={
                "DATABASE_URL": db_pool.conninfo,
                "SOURCES_CONFIG_FILE": str(path),
                "ENV_STATE": "dev",
            },
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    rejected = run("0" * 64)
    assert rejected.returncode == 1
    assert "Search policy replacement failed" in rejected.stderr
    assert sync_conn.execute("SELECT fingerprint FROM catalogue_search_policy").fetchone() == (
        before.fingerprint,
    )
    sync_conn.commit()
    accepted = run(before.fingerprint)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert accepted.stdout.strip() == f"Search policy installed: {after.fingerprint}"
    assert sync_conn.execute("SELECT fingerprint FROM catalogue_search_policy").fetchone() == (
        after.fingerprint,
    )
    sync_conn.commit()
