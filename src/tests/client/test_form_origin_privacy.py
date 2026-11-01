"""Sensitive forms retain browser-origin checks without disclosing source URLs."""

from unittest.mock import create_autospec, patch

import pytest
from lxml import html

from app.routes.auth import admin
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

_BROWSER_ORIGIN = "https://localhost"


def _navigation_headers(response):
    """Model same-origin form headers from no-referrer or strict-origin; TestClient does not do this
    itself.
    """
    policy = response.headers["referrer-policy"]
    if policy == "no-referrer":
        return {"Origin": "null"}
    assert policy == "strict-origin"
    return {"Origin": _BROWSER_ORIGIN, "Referer": f"{_BROWSER_ORIGIN}/"}


@pytest.fixture
def browser_admin(client_builder, monkeypatch):
    """Configure a secure browser-origin admin client and return it with its actor."""
    monkeypatch.setattr(settings, "public_base_url", _BROWSER_ORIGIN)
    monkeypatch.setattr(settings, "cookies_secure", True)
    actor = make_sample_user(id=1, is_admin=True, access_tier="public")
    client = client_builder(session_user=actor)
    client.base_url = _BROWSER_ORIGIN
    return client, actor


def _tier_form(client, actor, target_id):
    """Extract the admin tier form and return its page, action, and valid fields."""
    target = (
        actor if target_id == actor.id else make_sample_user(id=target_id, access_tier="public")
    )
    with (
        patch.object(
            admin,
            "get_user_by_email",
            create_autospec(admin.get_user_by_email, return_value=target),
        ),
        patch.object(
            admin,
            "list_admin_promotion_states",
            create_autospec(admin.list_admin_promotion_states, return_value={}),
        ),
    ):
        page = client.get("/admin?email=private-lookup%40example.org")
    assert page.status_code == 200
    document = html.fromstring(page.text)
    forms = document.xpath(f'//form[@action="/admin/users/{target_id}/set-tier"]')
    assert len(forms) == 1
    form = forms[0]
    data = {
        field.get("name"): field.get("value", "")
        for field in form.xpath('.//input[@type="hidden"]')
    }
    assert data["csrf_token"] == client.cookies.get(settings.csrf_cookie_name)
    return page, form.get("action"), {**data, "access_tier": "vetted"}


@pytest.mark.parametrize("target_id", [1, 7], ids=["own-account", "other-account"])
def test_rendered_admin_tier_form_submits_with_browser_origin(browser_admin, target_id):
    """Check rendered admin tier form submits with browser origin (HTTP 303)."""
    client, actor = browser_admin
    page, action, data = _tier_form(client, actor, target_id)
    headers = _navigation_headers(page)
    assert "private-lookup" not in repr(headers)
    with (
        patch.object(
            admin,
            "update_access_tier",
            create_autospec(admin.update_access_tier, return_value=("public", "vetted")),
        ) as update,
        patch.object(admin, "set_flash_if_exists", create_autospec(admin.set_flash_if_exists)),
    ):
        response = client.post(action, data=data, headers=headers, follow_redirects=False)
    assert response.status_code == 303
    update.assert_awaited_once_with(
        client.mock_pool,
        target_id,
        "vetted",
        actor_id=actor.id,
        actor_session_id=RAW_SESSION_ID,
    )


@pytest.mark.parametrize(
    "origin", ["null", "https://attacker.example.org", "https://localhost:444"]
)
def test_valid_admin_form_proof_does_not_override_an_untrusted_origin(browser_admin, origin):
    """Check valid admin form proof does not override an untrusted origin (HTTP 403)."""
    client, actor = browser_admin
    _page, action, data = _tier_form(client, actor, actor.id)
    with patch.object(
        admin, "update_access_tier", create_autospec(admin.update_access_tier)
    ) as update:
        response = client.post(
            action,
            data=data,
            headers={"Origin": origin, "Referer": f"{_BROWSER_ORIGIN}/"},
            follow_redirects=False,
        )
    assert response.status_code == 403
    update.assert_not_awaited()


@pytest.mark.parametrize(
    "path",
    [
        "/recover-totp",
        "/reset-password/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/verify-email/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "/account/confirm-email/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_sensitive_landing_forms_keep_a_browser_usable_origin(guest_client, monkeypatch, path):
    """Check sensitive landing forms keep a browser usable origin (HTTP 200)."""
    monkeypatch.setattr(settings, "public_base_url", _BROWSER_ORIGIN)
    guest_client.base_url = _BROWSER_ORIGIN
    page = guest_client.get(path)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert html.fromstring(page.text).xpath('//form[@method="post"]')
    assert _navigation_headers(page) == {
        "Origin": _BROWSER_ORIGIN,
        "Referer": f"{_BROWSER_ORIGIN}/",
    }
