"""Bad source data is isolated; infrastructure failures and recovery stay visible."""

import base64
import hashlib
from contextlib import asynccontextmanager
from unittest.mock import create_autospec

import pytest
from psycopg import DataError, IntegrityError, OperationalError, ProgrammingError
from psycopg.errors import (
    DeadlockDetected,
    InFailedSqlTransaction,
    ProgramLimitExceeded,
    QueryCanceled,
    SerializationFailure,
    UndefinedColumn,
)
from psycopg.sql import Composable

from app.services import ingestion
from app.services.harvest import HarvestResult
from app.services.ingestion_audit import DatasetWriteState
from app.sources import JsonFeedConfig, configure_sources, prepare_json_feed_startup
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.oai_fixtures import SOURCE_CURSOR, parsed_record
from tests.source_fixtures import legacy_source


@pytest.fixture(params=[False, True], ids=["public", "private"])
def source(request):
    """Select a legacy or synthetic JSON-feed source from the fixture parameter."""
    if not request.param:
        return legacy_source()
    config = JsonFeedConfig.model_validate(
        {
            "name": "recovery_feed",
            "display": {"label": "Recovery feed"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "RECOVERY_BEARER",
            "signing_key_env": "RECOVERY_SIGNING_KEY",
        }
    )
    environ = {
        name: base64.urlsafe_b64encode(hashlib.sha256(material).digest()).decode().rstrip("=")
        for name, material in (
            ("RECOVERY_BEARER", b"recovery synthetic bearer"),
            ("RECOVERY_SIGNING_KEY", b"recovery separate synthetic signing key"),
        )
    }
    credentials = prepare_json_feed_startup((config,), environment="dev", environ=environ)
    return configure_sources((config,), credentials=credentials)[0]


@pytest.mark.parametrize(
    "error_type", [DataError, IntegrityError, ProgramLimitExceeded, ValueError, KeyError, TypeError]
)
async def test_escaping_data_failure_requests_recovery_before_private_rewrite(
    monkeypatch, source, error_type
):
    """Escaping data failure requests recovery before private rewrite."""
    apply = create_autospec(ingestion._apply_incremental_harvest, side_effect=error_type("CANARY"))
    report = create_autospec(ingestion._report_write_failure)
    monkeypatch.setattr(ingestion, "_apply_incremental_harvest", apply)
    monkeypatch.setattr(ingestion, "_report_write_failure", report)

    with pytest.raises(
        ingestion._FullReharvestRequired, match="staged harvest cannot be replayed"
    ) as caught:
        await ingestion._write_incremental(
            make_mock_pool(),
            HarvestResult(source_cursor=SOURCE_CURSOR),
            SOURCE_CURSOR,
            configured_source=source,
        )

    assert caught.value.__suppress_context__ is True
    assert "CANARY" not in str(caught.value)
    report.assert_awaited_once()
    assert report.await_args.kwargs["private_errors"] is isinstance(source.config, JsonFeedConfig)


@pytest.mark.parametrize(
    "error_type",
    [
        OperationalError,
        DeadlockDetected,
        SerializationFailure,
        QueryCanceled,
        ProgrammingError,
        AssertionError,
    ],
)
async def test_other_write_failures_do_not_request_full_recovery(monkeypatch, error_type):
    """Other write failures do not request full recovery."""
    error = error_type("controlled failure")
    monkeypatch.setattr(
        ingestion,
        "_apply_incremental_harvest",
        create_autospec(ingestion._apply_incremental_harvest, side_effect=error),
    )
    monkeypatch.setattr(
        ingestion, "_report_write_failure", create_autospec(ingestion._report_write_failure)
    )

    with pytest.raises(error_type) as caught:
        await ingestion._write_incremental(
            make_mock_pool(),
            HarvestResult(source_cursor=SOURCE_CURSOR),
            SOURCE_CURSOR,
            configured_source=legacy_source(),
        )
    assert caught.value is error


@pytest.mark.parametrize("mode", ["incremental", "rebuild"])
@pytest.mark.parametrize(
    "error_type", [DataError, IntegrityError, ProgramLimitExceeded, ValueError, KeyError, TypeError]
)
async def test_both_writers_isolate_bad_records_and_keep_good_records(
    monkeypatch, mode, error_type
):
    """Both writers isolate bad records and keep good records."""
    source = legacy_source()
    cursor = make_async_cursor(fetchone={"incremental_position": 0, "incremental_affected": 0})
    records = [parsed_record("bad", doi=None), parsed_record("good", doi=None)]
    failures = []
    savepoints = []

    @asynccontextmanager
    async def savepoint():
        """Record savepoint release/rollback and propagate write failures."""
        try:
            yield
        except Exception:
            savepoints.append("rolled back")
            raise
        else:
            savepoints.append("released")

    cursor.connection.transaction.side_effect = savepoint

    async def upsert(_cur, record, policy, _audit):
        """Reject UUID "bad" with error_type and return a write-state for other records."""
        if record["uuid"] == "bad":
            raise error_type("bad source record")
        return DatasetWriteState(1, policy.name, record["uuid"], "public")

    async def record_failure(_cur, _source, uuid, message):
        """Append the rejected identity and diagnostic to the failure list."""
        failures.append((uuid, message))

    async def finalize(_pool, **_kwargs):
        """Return the accumulated record failures."""
        return failures

    monkeypatch.setattr(ingestion, "get_db_cursor", lambda _pool: FakeCursorCtx(cursor))
    monkeypatch.setattr(
        ingestion,
        "_upsert_audited_record",
        create_autospec(ingestion._upsert_audited_record, side_effect=upsert),
    )
    monkeypatch.setattr(
        ingestion,
        "_set_ingestion_failure_cur",
        create_autospec(ingestion._set_ingestion_failure_cur, side_effect=record_failure),
    )
    monkeypatch.setattr(
        ingestion,
        "_finalize_incremental_harvest",
        create_autospec(ingestion._finalize_incremental_harvest, side_effect=finalize),
    )

    if mode == "incremental":
        outcome = await ingestion._apply_incremental_harvest(
            make_mock_pool(),
            HarvestResult(source_cursor=SOURCE_CURSOR, matching_records=records),
            SOURCE_CURSOR,
            configured_source=source,
        )
        assert outcome.status == "partial"
        assert outcome.affected_count == outcome.failed_count == 1
    else:
        successes, failures = await ingestion._reconcile_rebuild_records(
            cursor,
            records,
            policy=source.policy,
            private_errors=False,
        )
        assert successes == 1

    assert [uuid for uuid, _message in failures] == ["bad"]
    assert savepoints == ["rolled back", "released"]


class _DiagnosticCursor:
    """Model PostgreSQL's aborted state and savepoint rollback, without a server."""

    def __init__(self):
        """Start with a usable fake connection and no recorded writes."""
        self.connection = self
        self.aborted = False
        self.writes = []

    @asynccontextmanager
    async def transaction(self):
        """Restore writes and clear aborted state when the savepoint raises."""
        before = list(self.writes)
        try:
            yield
        except Exception:
            self.aborted = False
            self.writes = before
            raise

    async def execute(self, statement, params=None):
        """Reject aborted transactions; diagnostic updates abort the cursor with UndefinedColumn."""
        text = statement.as_string(None) if isinstance(statement, Composable) else statement
        if self.aborted:
            raise InFailedSqlTransaction("transaction is aborted")
        if "last_sync_error" in text:
            self.aborted = True
            raise UndefinedColumn("diagnostic update failed")
        self.writes.append((text, params))


async def test_diagnostic_failure_keeps_prior_writes_and_allows_later_work():
    """Diagnostic failure keeps prior writes and allows later work."""
    cursor = _DiagnosticCursor()
    await cursor.execute("persist quarantine")

    await ingestion._record_sync_error(
        cursor,
        "diagnostic",
        source="example",
        channel="incremental",
        private_errors=False,
    )
    await cursor.execute("publish fetch progress")

    assert cursor.aborted is False
    assert [text for text, _params in cursor.writes] == [
        "persist quarantine",
        "publish fetch progress",
    ]


@pytest.mark.parametrize(
    "helper,kwargs",
    [
        (
            ingestion._record_sync_error,
            {"error_msg": "failure", "source": "example", "channel": "incremental"},
        ),
        (
            ingestion._report_write_failure,
            {"channel": "incremental", "exc": ValueError("failure"), "source": "example"},
        ),
        (
            ingestion._finalize_incremental_harvest,
            {
                "source": "example",
                "harvest_started_at": SOURCE_CURSOR,
                "source_cursor": SOURCE_CURSOR,
                "source_fingerprint": "f" * 64,
                "had_work": False,
            },
        ),
    ],
)
async def test_diagnostic_policy_cannot_be_omitted(helper, kwargs):
    """Diagnostic policy cannot be omitted."""
    with pytest.raises(TypeError, match="private_errors"):
        await helper(make_mock_pool(), **kwargs)


async def test_recovery_reason_uses_the_boolean_policy_not_mapping_truthiness(monkeypatch, source):
    """Recovery reason uses the boolean policy not mapping truthiness."""
    cursor = make_async_cursor()
    monkeypatch.setattr(ingestion, "get_db_cursor", lambda _pool: FakeCursorCtx(cursor))
    monkeypatch.setattr(
        ingestion,
        "_sync_source",
        create_autospec(
            ingestion._sync_source,
            side_effect=ingestion._FullReharvestRequired("public binding detail"),
        ),
    )
    record = create_autospec(ingestion._record_sync_error)
    monkeypatch.setattr(ingestion, "_record_sync_error", record)

    outcome = await ingestion._run_sync_on_locked_connection(
        make_mock_pool(), configured_source=source
    )

    private = isinstance(source.config, JsonFeedConfig)
    assert ingestion._private_errors(source) == {"private_errors": private}
    assert outcome.requires_full_rebuild
    assert record.await_args.kwargs["private_errors"] is private
    message = record.await_args.args[1]
    assert ("public binding detail" in message) is not private
    assert ("full_reharvest_required" in message) is private
