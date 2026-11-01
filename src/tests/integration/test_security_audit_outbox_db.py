"""Real transaction boundaries retain event evidence across rollback and delivery failure."""

from uuid import uuid4

import pytest

from app.services import audit as audit_service
from app.services import audit_outbox, dataset_admin, ingestion
from app.services.db import get_db_cursor
from tests.json_feed_fixtures import SignedFeed, feed_uuid, provision_feed_source
from tests.source_fixtures import legacy_source


async def test_event_and_catalogue_mutation_commit_or_roll_back_together(
    db_pool, sync_conn, dataset_factory
):
    """Verify event and catalogue mutation commit or roll back together."""
    identity = dataset_factory(source="durable_archive", uuid="identity")
    identifier = uuid4()
    with pytest.raises(RuntimeError, match="abort mutation"):
        async with get_db_cursor(db_pool) as cur:
            await cur.execute(
                "UPDATE oral_history_datasets SET description = 'tentative' WHERE id = %s",
                (identity,),
            )
            await audit_outbox.append_security_event_cur(
                cur, "dataset_hidden", {"dataset_id": identity}, event_id=identifier
            )
            raise RuntimeError("abort mutation")
    assert (
        sync_conn.execute(
            "SELECT count(*) FROM security_audit_events WHERE event_id = %s", (identifier,)
        ).fetchone()[0]
        == 0
    )
    assert (
        sync_conn.execute(
            "SELECT description FROM oral_history_datasets WHERE id = %s", (identity,)
        ).fetchone()[0]
        != "tentative"
    )
    sync_conn.commit()
    async with get_db_cursor(db_pool) as cur:
        await audit_outbox.append_security_event_cur(
            cur, "dataset_hidden", {"dataset_id": identity}, event_id=identifier
        )
    # Deleting metadata cannot erase its independently retained event identity.
    sync_conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (identity,))
    sync_conn.commit()
    assert sync_conn.execute(
        "SELECT payload FROM security_audit_events WHERE event_id = %s", (identifier,)
    ).fetchone()[0] == {"dataset_id": identity}


async def test_post_commit_logging_failure_cannot_lose_administrator_event(
    monkeypatch, db_pool, sync_conn, dataset_factory, admin_actor, bind_catalogue_policy
):
    """Verify post commit logging failure cannot lose administrator event."""
    identity = dataset_factory(source="durable_archive", uuid="identity")
    source = legacy_source(name="durable_archive", max_visibility="public")
    bind_catalogue_policy((source,))

    def fail_local_log(*_args):
        """Raise after commit to simulate process-local audit emission failure."""
        raise RuntimeError("process stops after commit")

    monkeypatch.setattr(dataset_admin, "audit_dataset_admin_action", fail_local_log)
    with pytest.raises(RuntimeError, match="process stops after commit"):
        await dataset_admin.change_dataset_admin_state(
            db_pool,
            identity,
            "hide",
            context=dataset_admin.DatasetAdminContext(admin_actor.id, admin_actor.session_id),
            configured_sources=(source,),
        )
    assert sync_conn.execute(
        "SELECT hidden_at IS NOT NULL FROM dataset_admin_state "
        "WHERE source = 'durable_archive' AND uuid = 'identity'"
    ).fetchone()[0]
    events = sync_conn.execute(
        "SELECT event_id, payload FROM security_audit_events "
        "WHERE event_type = 'admin_dataset_hidden'"
    ).fetchall()
    assert len(events) == 1
    assert events[0][1]["dataset_id"] == identity
    assert events[0][1]["actor_admin_id"] == admin_actor.id
    assert "description" not in repr(events)


async def test_event_append_failure_rolls_back_administrator_restriction(
    monkeypatch, db_pool, sync_conn, dataset_factory, admin_actor, bind_catalogue_policy
):
    """Verify event append failure rolls back administrator restriction."""
    identity = dataset_factory(source="durable_archive", uuid="identity")
    source = legacy_source(name="durable_archive", max_visibility="public")
    bind_catalogue_policy((source,))

    async def fail_event(*_args):
        """Raise the injected audit-storage failure."""
        raise RuntimeError("event storage unavailable")

    monkeypatch.setattr(audit_service, "append_security_event_cur", fail_event)
    with pytest.raises(RuntimeError, match="event storage unavailable"):
        await dataset_admin.change_dataset_admin_state(
            db_pool,
            identity,
            "hide",
            context=dataset_admin.DatasetAdminContext(admin_actor.id, admin_actor.session_id),
            configured_sources=(source,),
        )
    assert (
        sync_conn.execute(
            "SELECT count(*) FROM dataset_admin_state "
            "WHERE source = 'durable_archive' AND uuid = 'identity'"
        ).fetchone()[0]
        == 0
    )


async def test_failed_export_preserves_events_and_retry_reuses_stable_ids(
    monkeypatch, db_pool, sync_conn
):
    """Verify failed export preserves events and retry reuses stable IDs."""
    identifiers = [uuid4(), uuid4()]
    async with get_db_cursor(db_pool) as cur:
        for number, identifier in enumerate(identifiers, 1):
            await audit_outbox.append_security_event_cur(
                cur, "dataset_hidden", {"dataset_id": number}, event_id=identifier
            )
    delivered = []

    def unreliable_sink(_session, _url, event):
        """Record delivery IDs and raise AuditDeliveryError on the second event."""
        delivered.append(event["event_id"])
        if len(delivered) == 2:
            raise audit_outbox.AuditDeliveryError("sink unavailable")

    monkeypatch.setattr(audit_outbox, "_send_event", unreliable_sink)
    with pytest.raises(audit_outbox.AuditDeliveryError):
        audit_outbox.export_security_audit_events(
            sync_conn, sink_url="https://sink.example/events", bearer_token="synthetic-token"
        )
    assert sync_conn.execute("SELECT count(*) FROM security_audit_receipts").fetchone()[0] == 0
    sync_conn.commit()
    monkeypatch.setattr(
        audit_outbox,
        "_send_event",
        lambda _session, _url, event: delivered.append(event["event_id"]),
    )
    assert (
        audit_outbox.export_security_audit_events(
            sync_conn, sink_url="https://sink.example/events", bearer_token="synthetic-token"
        )
        == 2
    )
    assert delivered[:2] == delivered[2:]
    assert (
        audit_outbox.export_security_audit_events(
            sync_conn, sink_url="https://sink.example/events", bearer_token="synthetic-token"
        )
        == 0
    )
    assert sync_conn.execute("SELECT count(*) FROM security_audit_events").fetchone()[0] == 2
    assert sync_conn.execute("SELECT count(*) FROM security_audit_receipts").fetchone()[0] == 2


@pytest.mark.parametrize("run", [ingestion.run_sync, ingestion.run_full_rebuild])
async def test_ingestion_tier_change_has_durable_evidence_before_optional_log_copy(
    monkeypatch, db_pool, sync_conn, run
):
    """Verify ingestion tier change has durable evidence before optional log copy."""
    feed = SignedFeed(monkeypatch)
    source = feed.source()
    identity = feed_uuid(1)
    await provision_feed_source(db_pool, source)
    feed.set_snapshot([feed.record(identity)])
    assert (await ingestion.run_full_rebuild(db_pool, configured_source=source)).status == "success"
    # Dropping the local copy simulates a process stopping before stdout emission.
    monkeypatch.setattr(ingestion.IngestionAudit, "emit", lambda _self: None)
    feed.set_snapshot([feed.record(identity, visibility_tier="registered")])
    assert (await run(db_pool, configured_source=source)).status == "success"
    events = sync_conn.execute(
        "SELECT event_id, payload FROM security_audit_events WHERE event_type = 'tier_changed'"
    ).fetchall()
    assert len(events) == 1
    assert events[0][1] == {
        "dataset_id": sync_conn.execute(
            "SELECT id FROM oral_history_datasets WHERE source = %s AND uuid = %s",
            (source.name, identity),
        ).fetchone()[0],
        "source": source.name,
        "uuid": identity,
        "old_tier": "public",
        "new_tier": "registered",
    }
    assert "privatefeedcanary" not in repr(events)
