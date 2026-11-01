"""Rehearse withdrawal through real HTTP guards, transactions and catalogue reads."""

import logging

import pytest

from app.services.totp_crypto import encrypt_value
from config import settings
from tests.fixtures import sign_session_id
from tests.source_fixtures import legacy_source


def _post_state(client, dataset_id, action, **values):
    """Fetch the admin form and submit a CSRF-bound dataset-state change."""
    page = client.get(f"/admin/datasets/{dataset_id}")
    assert page.status_code == 200, page.text
    return client.post(
        f"/admin/datasets/{dataset_id}/state",
        data={"action": action, "csrf_token": client.cookies.get("csrf_token"), **values},
        follow_redirects=False,
    )


def test_withdrawal_ui_rehearsal(
    replace_bound_catalogue_sources,
    e2e_client,
    sync_conn,
    dataset_factory,
    user_factory,
    session_factory,
    monkeypatch,
    caplog,
):
    """Raise/reject/hide/restore is durable, immediate and audited once per change."""
    source = legacy_source(name="archive_alpha", max_visibility="registered")
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    dataset_id = dataset_factory(
        source=source.name,
        uuid="withdrawal-rehearsal",
        title="Withdrawal rehearsal record",
        visibility_tier="public",
        description="privaterehearsalmarker",
        keywords=["hiddenrehearsal", "hiddenrehearsal"],
        languages=["HiddenRehearsalLanguage"],
    )
    dataset_factory(source=source.name, uuid="visible-canary", title="Visible canary")
    admin = user_factory(is_admin=True, access_tier="public")
    admin_session = session_factory(admin.id)
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(admin_session))
    audit = logging.getLogger("audit")
    old_handlers, old_propagate = audit.handlers[:], audit.propagate
    audit.addHandler(caplog.handler)
    audit.propagate = False
    caplog.set_level(logging.INFO, logger="audit")
    try:
        rejected = _post_state(e2e_client, dataset_id, "raise_tier", new_tier="public")
        assert rejected.status_code == 409
        assert sync_conn.execute("SELECT count(*) FROM dataset_admin_state").fetchone()[0] == 0
        sync_conn.commit()
        raised = _post_state(e2e_client, dataset_id, "raise_tier", new_tier="vetted")
        assert raised.status_code == 303
        public_detail = e2e_client.get(f"/dataset/{dataset_id}")
        assert public_detail.status_code == 200
        assert public_detail.context["user_tier"] == "public"
        assert public_detail.context["dataset"].description is None
        assert "privaterehearsalmarker" not in public_detail.text
        assert f'href="/admin/datasets/{dataset_id}"' in public_detail.text
        repeated = _post_state(e2e_client, dataset_id, "raise_tier", new_tier="vetted")
        assert repeated.headers["location"].endswith("?notice=unchanged")
        assert _post_state(e2e_client, dataset_id, "hide").status_code == 303
        controls = e2e_client.get(f"/admin/datasets/{dataset_id}")
        assert controls.context["record"].state.hidden_at is not None
        listing = e2e_client.get("/admin/datasets", params={"uuid": "withdrawal-rehearsal"})
        assert listing.status_code == 200
        assert [record.dataset_id for record in listing.context["records"]] == [dataset_id]
        assert listing.context["newer_id"] is listing.context["older_id"] is None
        assert "privaterehearsalmarker" not in controls.text + listing.text
        assert "Withdrawal rehearsal record" not in controls.text + listing.text
        assert controls.context["record"].public_title is None
        _assert_hidden_for_all_tiers(e2e_client, dataset_id, user_factory, session_factory)
        e2e_client.cookies.clear()
        e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(admin_session))
        assert _post_state(e2e_client, dataset_id, "restore").status_code == 303
        restored = e2e_client.get(f"/dataset/{dataset_id}")
        assert restored.status_code == 200
        assert restored.context["dataset"].visibility_tier == "vetted"
        assert restored.context["dataset"].description is None
        events = [
            r for r in caplog.records if getattr(r, "event_type", "").startswith("admin_dataset_")
        ]
        assert [r.event_type for r in events] == [
            "admin_dataset_tier_raised",
            "admin_dataset_hidden",
            "admin_dataset_restored",
        ]
        assert all(r.actor_admin_id == admin.id and r.dataset_id == dataset_id for r in events)
        assert all(
            r.dataset_source == source.name and r.dataset_uuid == "withdrawal-rehearsal"
            for r in events
        )
        assert events[-1].after["admin_tier"] == "vetted"
        assert events[-1].after["hidden_at"] is None
        assert "privaterehearsalmarker" not in repr([vars(r) for r in events])
    finally:
        audit.handlers[:] = old_handlers
        audit.propagate = old_propagate


@pytest.mark.parametrize("tier", ["public", "registered", "vetted"])
def test_admin_controls_release_only_public_titles(
    replace_bound_catalogue_sources,
    e2e_client,
    sync_conn,
    dataset_factory,
    user_factory,
    session_factory,
    monkeypatch,
    tier,
):
    """Verify admin controls release only public titles."""
    source = legacy_source(name="archive_alpha", max_visibility="vetted")
    replace_bound_catalogue_sources(monkeypatch, e2e_client.app, (source,))
    visible_id = dataset_factory(
        source=source.name,
        uuid="visible-reference",
        title="Approved public title",
        visibility_tier="vetted",
        description="protected description needle",
        authors=["protected author needle"],
    )
    hidden_id = dataset_factory(
        source=source.name, uuid="hidden-reference", title="Hidden title needle"
    )
    sync_conn.execute(
        "INSERT INTO dataset_admin_state (source, uuid, hidden_at) "
        "VALUES (%s, 'hidden-reference', clock_timestamp())",
        (source.name,),
    )
    sync_conn.commit()
    admin = user_factory(is_admin=True, access_tier=tier)
    token = session_factory(admin.id)
    e2e_client.cookies.set(settings.session_cookie_name, sign_session_id(token))
    listing = e2e_client.get("/admin/datasets")
    visible = e2e_client.get(f"/admin/datasets/{visible_id}")
    hidden = e2e_client.get(f"/admin/datasets/{hidden_id}")
    assert listing.status_code == visible.status_code == hidden.status_code == 200
    assert "Approved public title" in listing.text and "Approved public title" in visible.text
    assert "hidden-reference" in listing.text and "hidden-reference" in hidden.text
    for response in (listing, visible, hidden):
        assert "Hidden title needle" not in response.text
        assert "protected description needle" not in response.text
        assert "protected author needle" not in response.text
    assert visible.context["record"].public_title == "Approved public title"
    assert hidden.context["record"].public_title is None
    for needle in ("Approved public title", "Hidden title needle", "protected description needle"):
        result = e2e_client.get("/admin/datasets", params={"uuid": needle})
        assert result.status_code == 200 and result.context["records"] == []


def _assert_hidden_for_all_tiers(client, dataset_id, user_factory, session_factory):
    """Check withdrawal hides detail and discovery metadata from every tier."""
    for tier in ("public", "registered", "vetted"):
        client.cookies.clear()
        if tier != "public":
            viewer = user_factory(access_tier=tier, totp_secret=encrypt_value("JBSWY3DPEHPK3PXP"))
            token = session_factory(viewer.id)
            client.cookies.set(settings.session_cookie_name, sign_session_id(token))
        assert client.get(f"/dataset/{dataset_id}").status_code == 404
        search = client.get("/search")
        home = client.get("/")
        assert search.status_code == home.status_code == 200
        assert search.context["user_tier"] == home.context["user_tier"] == tier
        assert search.context["result_count"] is None
        assert len(search.context["results"]) == home.context["total_datasets"] == 1
        assert "Withdrawal rehearsal record" not in search.text + home.text
        assert "hiddenrehearsal" not in search.text + home.text
