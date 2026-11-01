"""D2: real signed ingestion, catalogue SQL, sessions and HTTP resource access."""

import logging
from datetime import timedelta

import pytest
from lxml import html

from app.services import DatasetAdminContext, change_dataset_admin_state, ingestion
from app.services.totp_crypto import encrypt_value
from config import settings
from tests.fixtures import sign_session_id
from tests.json_feed_fixtures import (
    DEFAULT_CUTOFF,
    SignedFeed,
    feed_uuid,
    provision_feed_source,
    snapshot_feed_source,
)

_TIERS = ("public", "registered", "vetted")
_VIEWERS = ("guest", *_TIERS, "public_admin")
_LOG_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


@pytest.fixture
def feed(monkeypatch):
    """Install the signed-feed fixture with real authentication and in-process collection."""
    return SignedFeed(monkeypatch)


@pytest.fixture
def resource_audit(caplog):
    """Capture the real audit channel even when application logging disables propagation."""
    logger = logging.getLogger("audit")
    handlers, propagate = logger.handlers[:], logger.propagate
    if caplog.handler not in logger.handlers:
        logger.addHandler(caplog.handler)
    logger.propagate = False
    try:
        with caplog.at_level(logging.INFO, logger="audit"):
            yield caplog
    finally:
        logger.handlers, logger.propagate = handlers, propagate


def _events(capture):
    """Select the relevant captured audit events for this scenario."""
    return [
        record
        for record in capture.records
        if getattr(record, "event_type", "") == "resource_access"
    ]


def _sign_in(client, viewer, user_factory, session_factory):
    """Replace browser cookies with the selected viewer session; return user ID (None for guest)
    and metadata tier.
    """
    client.cookies.clear()
    tier = "public" if viewer in ("guest", "public_admin") else viewer
    if viewer == "guest":
        return None, tier
    user = user_factory(
        access_tier=tier,
        is_admin=viewer == "public_admin",
        totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"),
    )
    session = session_factory(user.id, purpose="full")
    client.cookies.set(settings.session_cookie_name, sign_session_id(session))
    return user.id, tier


async def _populate(pool, conn, feed, source, records):
    """Rebuild the supplied source snapshot and return stored dataset IDs keyed by UUID."""
    await provision_feed_source(pool, source)
    feed.set_snapshot(records)
    result = await ingestion.run_full_rebuild(pool, configured_source=source)
    assert result.status == "success"
    stored = snapshot_feed_source(conn, source.name)["rows"]
    assert len(stored) == len(records)
    return {row["uuid"]: row["id"] for row in stored}


def _detail(client, dataset_id, wire, *, index, allowed=True, label="Open resource"):
    """Check the detail page exposes only the expected resource links and return the route path."""
    response = client.get(f"/dataset/{dataset_id}")
    assert response.status_code == 200
    tree = html.fromstring(response.text)
    links = tree.xpath("//a[contains(@href, '/resource/')]")
    path = f"/dataset/{dataset_id}/resource/{index}"
    assert [link.get("href") for link in links] == ([path] if allowed else [])
    if allowed:
        assert links[0].text_content().strip() == label
        assert links[0].get("target") == "_blank"
        assert "noopener" in links[0].get("rel", "").split()
    for proxy in wire["resource_proxies"]:
        if proxy["ref"]:
            assert proxy["ref"] not in response.text
    return path


def _follow(client, path, capture, *, target=None, expected=None):
    """Check resource redirects and their exact audit event, or a quiet 404."""
    before = len(_events(capture))
    response = client.get(path, follow_redirects=False)
    events = _events(capture)[before:]
    if target is None:
        assert response.status_code == 404
        assert "location" not in response.headers
        assert events == []
        return
    assert response.status_code == 303
    assert response.headers["location"] == target
    assert len(events) == 1
    event = events[0]
    assert event.name == "audit" and event.levelno == logging.INFO
    assert event.msg == "resource_access" and event.args == ()
    assert not event.exc_info and event.stack_info is None
    fields = {key: value for key, value in vars(event).items() if key not in _LOG_FIELDS}
    assert fields == {
        "event_type": "resource_access",
        "client_ip": "testclient",
        "request_id": response.headers["x-request-id"],
        **expected,
    }
    assert fields["request_id"]
    assert target not in repr(vars(event))


def _identity(dataset_id, source, user_id, tier, index):
    """Build the expected resource-access audit identity fields."""
    return {
        "dataset_id": dataset_id,
        "source": source.name,
        "user_id": user_id,
        "user_tier": tier,
        "proxy_index": index,
    }


@pytest.mark.parametrize("viewer", _VIEWERS)
async def test_real_catalogue_tiers_and_sessions_audit_only_successful_redirects(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    resource_audit,
    viewer,
):
    """Guests, full sessions and public administrators obey the same metadata tiers."""
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    records = [
        feed.record(feed_uuid(number), marker=f"private{tier}", visibility_tier=tier)
        for number, tier in enumerate(_TIERS, start=1)
    ]
    ids = await _populate(db_pool, sync_conn, feed, source, records)
    user_id, tier = _sign_in(e2e_client, viewer, user_factory, session_factory)
    successes = 0
    for wire in records:
        dataset_id = ids[wire["uuid"]]
        allowed = _TIERS.index(tier) >= _TIERS.index(wire["visibility_tier"])
        path = _detail(e2e_client, dataset_id, wire, index=0, allowed=allowed)
        _follow(
            e2e_client,
            path,
            resource_audit,
            target=wire["resource_proxies"][0]["ref"] if allowed else None,
            expected=_identity(dataset_id, source, user_id, tier, 0),
        )
        successes += allowed
        for index in ("-1", "2", "not-an-index"):
            _follow(e2e_client, f"/dataset/{dataset_id}/resource/{index}", resource_audit)
    _follow(e2e_client, "/dataset/2147483647/resource/0", resource_audit)
    assert len(_events(resource_audit)) == successes
    contents = repr([vars(event) for event in _events(resource_audit)])
    assert all(wire["uuid"] not in contents and wire["title"] not in contents for wire in records)


@pytest.mark.parametrize("viewer", _VIEWERS)
async def test_stale_links_obey_durable_hide_restore_and_tier_changes_per_source(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    resource_audit,
    admin_actor,
    viewer,
):
    """Committed administrator restrictions affect the next request, including stale links."""
    source, other = feed.source(), feed.source(name="other_resource_archive")
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source, other))
    uuid = feed_uuid(1)
    wire = feed.record(uuid, marker="targetprivate")
    foreign = feed.record(uuid, marker="foreignprivate")
    dataset_id = (await _populate(db_pool, sync_conn, feed, source, [wire]))[uuid]
    foreign_id = (await _populate(db_pool, sync_conn, feed, other, [foreign]))[uuid]
    untouched = snapshot_feed_source(sync_conn, other.name)
    user_id, tier = _sign_in(e2e_client, viewer, user_factory, session_factory)
    path = _detail(e2e_client, dataset_id, wire, index=0)
    identity = _identity(dataset_id, source, user_id, tier, 0)
    target = wire["resource_proxies"][0]["ref"]
    _follow(e2e_client, path, resource_audit, target=target, expected=identity)
    context = DatasetAdminContext(actor_id=admin_actor.id, actor_session_id=admin_actor.session_id)
    successes = 1
    for action, new_tier, required in (
        ("raise_tier", "registered", "registered"),
        ("hide", None, None),
        ("restore", None, "registered"),
        ("raise_tier", "vetted", "vetted"),
    ):
        change = await change_dataset_admin_state(
            db_pool,
            dataset_id,
            action,
            context=context,
            new_tier=new_tier,
            configured_sources=(source, other),
        )
        assert change.changed
        allowed = required is not None and _TIERS.index(tier) >= _TIERS.index(required)
        _follow(
            e2e_client,
            path,
            resource_audit,
            target=target if allowed else None,
            expected=identity,
        )
        successes += allowed
        if action == "hide":
            assert e2e_client.get(f"/dataset/{dataset_id}").status_code == 404
        else:
            _detail(e2e_client, dataset_id, wire, index=0, allowed=allowed)
        _follow(
            e2e_client,
            f"/dataset/{foreign_id}/resource/0",
            resource_audit,
            target=foreign["resource_proxies"][0]["ref"],
            expected=_identity(foreign_id, other, user_id, tier, 0),
        )
        successes += 1
        assert snapshot_feed_source(sync_conn, other.name) == untouched
    stored = snapshot_feed_source(sync_conn, source.name)
    assert stored["rows"][0]["visibility_tier"] == "public"
    assert stored["admin"][0]["visibility_tier"] == "vetted"
    assert stored["admin"][0]["hidden_at"] is None
    assert len(_events(resource_audit)) == successes


@pytest.mark.parametrize("runner", (ingestion.run_sync, ingestion.run_full_rebuild))
async def test_source_tier_corrections_recheck_the_same_session_and_stale_link(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    user_factory,
    session_factory,
    monkeypatch,
    resource_audit,
    runner,
):
    """Both ingestion paths recheck tightened and relaxed explicit assertions."""
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    wire = feed.record(feed_uuid(1))
    dataset_id = (await _populate(db_pool, sync_conn, feed, source, [wire]))[wire["uuid"]]
    user_id, tier = _sign_in(e2e_client, "registered", user_factory, session_factory)
    path = _detail(e2e_client, dataset_id, wire, index=0)
    _follow(
        e2e_client,
        path,
        resource_audit,
        target=wire["resource_proxies"][0]["ref"],
        expected=_identity(dataset_id, source, user_id, tier, 0),
    )
    for hour, incoming_tier in enumerate(("vetted", "public"), start=1):
        corrected = {
            **wire,
            "visibility_tier": incoming_tier,
            "modified_at": f"2030-01-04T0{hour}:00:00Z",
        }
        feed.set_snapshot([corrected], cutoff=DEFAULT_CUTOFF + timedelta(hours=hour + 1))
        assert (await runner(db_pool, configured_source=source)).status == "success"
        stored = snapshot_feed_source(sync_conn, source.name)["rows"]
        assert [(row["id"], row["visibility_tier"]) for row in stored] == [
            (dataset_id, incoming_tier)
        ]
        allowed = incoming_tier == "public"
        _detail(e2e_client, dataset_id, corrected, index=0, allowed=allowed)
        _follow(
            e2e_client,
            path,
            resource_audit,
            target=wire["resource_proxies"][0]["ref"] if allowed else None,
            expected=_identity(dataset_id, source, user_id, tier, 0) if allowed else None,
        )
    assert len(_events(resource_audit)) == 2


@pytest.mark.parametrize(
    ("resource_index", "label"),
    ((2, "Open resource"), (None, "View source record")),
    ids=("later-safe-resource", "safe-landing-fallback"),
)
async def test_native_proxy_selection_preserves_original_indexes_and_hides_targets(
    replace_bound_catalogue_sources,
    db_pool,
    sync_conn,
    feed,
    e2e_client,
    monkeypatch,
    resource_audit,
    resource_index,
    label,
):
    """Nullable native proxies are skipped without renumbering; Resource precedes LandingPage."""
    source = feed.source()
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    proxies = [
        {"type": "Resource", "ref": None},
        {"type": "LandingPage", "ref": "https://archive.example.org/private/landing"},
    ]
    if resource_index is not None:
        proxies.append({"type": "Resource", "ref": "https://archive.example.org/private/resource"})
    wire = feed.record(feed_uuid(1), resource_proxies=proxies)
    dataset_id = (await _populate(db_pool, sync_conn, feed, source, [wire]))[wire["uuid"]]
    index = resource_index if resource_index is not None else 1
    path = _detail(e2e_client, dataset_id, wire, index=index, label=label)
    _follow(e2e_client, f"/dataset/{dataset_id}/resource/0", resource_audit)
    _follow(
        e2e_client,
        path,
        resource_audit,
        target=proxies[index]["ref"],
        expected=_identity(dataset_id, source, None, "public", index),
    )
    assert len(_events(resource_audit)) == 1
