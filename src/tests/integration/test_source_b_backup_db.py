"""Encrypted synthetic recovery; production roles, custody and hosts remain external."""

import os
import re
import shutil
import subprocess
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import create_autospec
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg_pool import AsyncConnectionPool

from app.services import DatasetAdminContext, change_dataset_admin_state, ingestion
from app.services.datasets import get_dataset_by_id
from config import settings
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_A, _B, _C, _E = map(feed_uuid, (1, 2, 3, 5))
_TEST_DATABASE = re.compile(r".*_test(?:_gw\d+)?")
_TIMEOUT = 60
_PG_ENV = {
    "dbname": "PGDATABASE",
    "host": "PGHOST",
    "hostaddr": "PGHOSTADDR",
    "port": "PGPORT",
    "user": "PGUSER",
    "password": "PGPASSWORD",
    "sslmode": "PGSSLMODE",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR",
    "channel_binding": "PGCHANNELBINDING",
    "gssencmode": "PGGSSENCMODE",
    "requirepeer": "PGREQUIREPEER",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "application_name": "PGAPPNAME",
}


def _environment(conninfo):
    """Use only the selected URL's libpq inputs; never put passwords in argv."""
    parameters = conninfo_to_dict(conninfo)
    assert not parameters.keys() - _PG_ENV.keys(), (
        "Recovery test requires an explicit database URL without service/options/passfile overrides"
    )
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    environment.update({_PG_ENV[key]: value for key, value in parameters.items()})
    environment.update(
        PGPASSFILE="/dev/null", PGCONNECT_TIMEOUT="5", PGAPPNAME="oha-synthetic-recovery"
    )
    return environment


def _tools(server_version):
    """Require PostgreSQL 18 server/matching clients plus age executables."""
    tools = {}
    for name in ("pg_dump", "pg_restore", "age", "age-keygen"):
        path = shutil.which(name)
        assert path is not None, f"Encrypted recovery acceptance requires {name} on PATH"
        tools[name] = path
    versions = []
    for name in ("pg_dump", "pg_restore"):
        result = subprocess.run(
            [tools[name], "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        match = re.search(r"PostgreSQL\) (\d+)\.", result.stdout)
        assert result.returncode == 0 and match, f"Cannot determine {name} version"
        versions.append(int(match[1]))
    assert 180000 <= server_version < 190000, "Encrypted recovery acceptance requires PostgreSQL 18"
    assert versions == [server_version // 10000] * 2, (
        "Recovery acceptance requires pg_dump and pg_restore to match the server major version"
    )
    return tools


def _stop(process):
    """Terminate the child, escalating to kill after five seconds, and reap it."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _pipeline(first, second, environment, output):
    """Stream plaintext only through a pipe, checking and reaping both children."""
    processes = []
    try:
        producer = subprocess.Popen(
            first, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment
        )
        processes.append(producer)
        assert producer.stdout is not None
        consumer = subprocess.Popen(
            second,
            stdin=producer.stdout,
            stdout=output,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
        processes.append(consumer)
        producer.stdout.close()
        deadline = time.monotonic() + _TIMEOUT
        statuses = [
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            for process in reversed(processes)
        ]
        assert statuses == [0, 0], f"Encrypted recovery pipeline failed with statuses {statuses}"
    except subprocess.TimeoutExpired:
        pytest.fail("Encrypted recovery pipeline exceeded its bounded deadline", pytrace=False)
    finally:
        if processes and processes[0].stdout is not None:
            processes[0].stdout.close()
        for process in reversed(processes):
            _stop(process)


def _key(tools, directory):
    """Generate a private temporary age identity and return it with its recipient."""
    directory.chmod(0o700)
    identity = directory / "synthetic.agekey"
    try:
        result = subprocess.run(
            [tools["age-keygen"], "--output", str(identity)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, "Cannot generate the transient synthetic recovery identity"
        identity.chmod(0o600)
        result = subprocess.run(
            [tools["age-keygen"], "-y", str(identity)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0 and result.stdout.strip().startswith("age1")
        return identity, result.stdout.strip()
    except BaseException:
        identity.unlink(missing_ok=True)
        raise


def _snapshot(connection, source):
    # to_jsonb(timestamptz) uses the observer session's TimeZone.
    """Read the source's catalogue and progress snapshot for comparison."""
    connection.execute("SET TIME ZONE 'UTC'")
    return snapshot_feed_source(connection, source.name)


def _assert_source_tier(connection, source, uuid, tier):
    """Check the durable source tier and close the observer transaction."""
    assert connection.execute(
        "SELECT visibility_tier FROM source_security_state WHERE source=%s AND uuid=%s",
        (source.name, uuid),
    ).fetchone() == (tier,)
    connection.commit()


async def _rebuild(pool, feed, source, records):
    """Provision the source and require a successful rebuild of the selected snapshot."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(records)
    assert (await ingestion.run_full_rebuild(pool, configured_source=source)).status == "success"


async def _stage_after_one_commit(pool, feed, source, monkeypatch, replacement_tier):
    """Interrupt native ingestion after its first committed item, leaving staged replay state."""
    feed.set_snapshot(
        [
            feed.record(_E, marker="stagedfirstprivate"),
            feed.record(
                _A,
                marker="correctedprivate",
                title="Corrected discovery",
                visibility_tier=replacement_tier,
            ),
            feed.record(_C, marker="newlyvalidprivate"),
        ],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=2),
    )
    real = ingestion._upsert_public_catalogue_record
    calls = 0

    async def interrupt_second(cur, record, policy):
        """Raise OperationalError on the second write and delegate the first."""
        nonlocal calls
        calls += 1
        if calls == 2:
            raise psycopg.OperationalError("synthetic interruption after one committed item")
        return await real(cur, record, policy)

    with monkeypatch.context() as crash:
        crash.setattr(ingestion, "_INCREMENTAL_COMMIT_BATCH_SIZE", 1)
        crash.setattr(
            ingestion,
            "_upsert_public_catalogue_record",
            create_autospec(real, spec_set=True, side_effect=interrupt_second),
        )
        with pytest.raises(RuntimeError, match="JSON feed ingestion write failed"):
            await ingestion.run_sync(pool, configured_source=source)


async def _prepare_state(db_pool, sync_conn, feed, monkeypatch, admin_actor, replacement_tier):
    """Build retained, quarantined and partially staged source state for encrypted recovery."""
    source, foreign = feed.source(floor="registered"), feed.source(name="retained_archive")
    await _rebuild(
        db_pool,
        feed,
        source,
        [feed.record(_A, marker="lastgoodprivate", visibility_tier="vetted"), feed.record(_B)],
    )
    await _rebuild(db_pool, feed, foreign, [feed.record(_A, marker="foreignprivate")])
    original = _snapshot(sync_conn, source)
    invalid = feed.record(_A, marker="rejectedprivate")
    del invalid["visibility_tier"]
    feed.set_snapshot(
        [invalid, feed.record(_C, visibility_tier=None), feed.record(_B)],
        cutoff=DEFAULT_CUTOFF + timedelta(hours=1),
    )
    partial = await ingestion.run_sync(db_pool, configured_source=source)
    assert (partial.status, partial.failed_count) == ("partial", 2)
    dataset_id = next(row["id"] for row in original["rows"] if row["uuid"] == _B)
    context = DatasetAdminContext(actor_id=admin_actor.id, actor_session_id=admin_actor.session_id)
    await change_dataset_admin_state(
        db_pool,
        dataset_id,
        "raise_tier",
        context=context,
        new_tier="vetted",
        configured_sources=(source,),
    )
    await change_dataset_admin_state(
        db_pool, dataset_id, "hide", context=context, configured_sources=(source, foreign)
    )
    await _stage_after_one_commit(db_pool, feed, source, monkeypatch, replacement_tier)
    before = {selected.name: _snapshot(sync_conn, selected) for selected in (source, foreign)}
    state = before[source.name]
    assert state["state"]["incremental_harvest"] is not None
    assert (state["state"]["incremental_position"], state["state"]["incremental_affected"]) == (
        1,
        1,
    )
    assert state["state"]["source_cursor"] == original["state"]["source_cursor"]
    assert state["state"]["source_fingerprint"] == source.adapter.config_fingerprint()
    assert {row["uuid"] for row in state["failures"]} == {_A, _C}
    assert next(row for row in state["rows"] if row["uuid"] == _A) == next(
        row for row in original["rows"] if row["uuid"] == _A
    )
    assert next(row for row in state["rows"] if row["uuid"] == _A)["visibility_tier"] == "vetted"
    assert state["admin"][0]["visibility_tier"] == "vetted"
    assert state["admin"][0]["hidden_at"] is not None
    assert "rejectedprivate" not in repr(before)
    return source, foreign, before, dataset_id


def _connection(monkeypatch):
    """Require a test database, clear inherited PostgreSQL settings and return URL plus tool
    environment.
    """
    base = settings.database_url.get_secret_value()
    database = conninfo_to_dict(base).get("dbname", "")
    assert isinstance(database, str) and _TEST_DATABASE.fullmatch(database), (
        "Refusing recovery acceptance outside a test database"
    )
    environment = _environment(base)
    # The CLI environment is explicit; clear ambient libpq inputs for the
    # psycopg control/observer/pool connections as well. pytest restores them.
    for key in tuple(os.environ):
        if key.startswith("PG"):
            monkeypatch.delenv(key)
    return base, environment


@pytest.mark.parametrize(
    ("replacement_tier", "expected_tier"),
    [("public", "registered"), ("vetted", "vetted")],
    ids=["explicit-tier-correction", "unchanged-classification"],
)
async def test_encrypted_native_feed_backup_restores_state_and_resumes_staging(
    bind_catalogue_policy,
    db_pool,
    sync_conn,
    monkeypatch,
    tmp_path: Path,
    admin_actor,
    replacement_tier,
    expected_tier,
):
    """SB-VIS-009, SB-VIS-007, SB-TRANS-004: recover encrypted feed state and resume staging.

    Disposable identities do not prove deployment custody.
    """
    base, environment = _connection(monkeypatch)
    tools = _tools(sync_conn.info.server_version)
    feed = SignedFeed(monkeypatch)
    source, foreign, before, dataset_id = await _prepare_state(
        db_pool, sync_conn, feed, monkeypatch, admin_actor, replacement_tier
    )
    bind_catalogue_policy((source, foreign))
    state = before[source.name]
    identity, recipient = _key(tools, tmp_path)
    archive = tmp_path / "synthetic.dump.age"
    target = f"oha_native_restore_{uuid4().hex}_test"
    restored = make_conninfo(base, dbname=target)
    created = False
    try:
        with psycopg.connect(make_conninfo(base, dbname="postgres"), autocommit=True) as control:
            try:
                # No existing target and no caller-selected restore destination.
                control.execute(
                    sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(target))
                )
                created = True
                with archive.open("xb") as ciphertext:
                    archive.chmod(0o600)
                    _pipeline(
                        [
                            tools["pg_dump"],
                            "--format=custom",
                            "--no-owner",
                            "--no-privileges",
                            "--no-password",
                        ],
                        [tools["age"], "--encrypt", "--recipient", recipient],
                        environment,
                        ciphertext,
                    )
                assert archive.stat().st_size > 0 and archive.stat().st_mode & 0o777 == 0o600
                _pipeline(
                    [tools["age"], "--decrypt", "--identity", str(identity), str(archive)],
                    [
                        tools["pg_restore"],
                        "--exit-on-error",
                        "--single-transaction",
                        "--no-owner",
                        "--no-privileges",
                        "--no-password",
                        "--dbname",
                        target,
                    ],
                    _environment(restored),
                    subprocess.DEVNULL,
                )
                with psycopg.connect(restored) as observer:
                    assert {
                        selected.name: _snapshot(observer, selected)
                        for selected in (source, foreign)
                    } == before
                    _assert_source_tier(observer, source, _A, "vetted")
                    pool = AsyncConnectionPool(restored, min_size=1, max_size=2, open=False)
                    try:
                        await pool.open(wait=True, timeout=10)
                        assert (
                            await get_dataset_by_id(
                                pool,
                                dataset_id,
                                "vetted",
                                configured_sources=(source, foreign),
                            )
                            is None
                        )
                        real_fetch = type(source.adapter).fetch
                        guard = create_autospec(
                            real_fetch,
                            spec_set=True,
                            side_effect=AssertionError("Restored staged work must not fetch again"),
                        )
                        with monkeypatch.context() as replay:
                            replay.setattr(type(source.adapter), "fetch", guard)
                            feed.clear_calls()
                            feed.status_code = 503
                            outcome = await ingestion.run_sync(pool, configured_source=source)
                            guard.assert_not_called()
                        assert (outcome.status, outcome.affected_count, outcome.failed_count) == (
                            "success",
                            3,
                            0,
                        )
                        assert feed.requests == feed.worker_calls == []
                        after = _snapshot(observer, source)
                        assert after["failures"] == [] and after["admin"] == state["admin"]
                        assert after["state"]["incremental_harvest"] is None
                        assert (
                            after["state"]["incremental_position"],
                            after["state"]["incremental_affected"],
                        ) == (0, 0)
                        assert (
                            after["state"]["source_cursor"]
                            == (DEFAULT_CUTOFF + timedelta(hours=2)).isoformat()
                        )
                        assert {row["uuid"] for row in after["rows"]} == {_A, _B, _C, _E}
                        corrected = next(row for row in after["rows"] if row["uuid"] == _A)
                        assert (
                            corrected["visibility_tier"],
                            corrected["data"]["visibility_tier"],
                        ) == (expected_tier, replacement_tier)
                        _assert_source_tier(observer, source, _A, expected_tier)
                        assert (
                            await get_dataset_by_id(
                                pool,
                                dataset_id,
                                "vetted",
                                configured_sources=(source, foreign),
                            )
                            is None
                        )
                        assert _snapshot(observer, foreign) == before[foreign.name]
                    finally:
                        await pool.close()
            finally:
                if created:
                    control.execute(
                        sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(target))
                    )
    finally:
        identity.unlink(missing_ok=True)
