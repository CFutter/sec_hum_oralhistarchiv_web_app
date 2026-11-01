"""Cookie ambiguity is rejected by real middleware before account services."""

import pytest

from config import settings


@pytest.mark.parametrize(
    "attribute", ["session_cookie_name", "csrf_cookie_name", "pre_session_cookie_name"]
)
def test_duplicate_security_cookie_header_returns_400(guest_client, attribute):
    """Check duplicate security cookie header returns 400."""
    name = getattr(settings, attribute)
    response = guest_client.get("/about", headers={"Cookie": f"{name}=first; {name}=second"})
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "headers", [{}, {"Origin": "https://sibling.example.org"}, {"Origin": "null"}]
)
def test_hardened_post_with_valid_hmac_still_requires_canonical_origin(
    client_builder, monkeypatch, headers
):
    """Check hardened POST with valid HMAC still requires canonical origin."""
    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "session_cookie_name", "__Host-oha_session")
    monkeypatch.setattr(settings, "cookies_secure", True)
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")
    client = client_builder()
    rejected = client.post(
        "/logout", data={"csrf_token": client.csrf_token}, headers=headers, follow_redirects=False
    )
    assert rejected.status_code == 403
    accepted = client.post(
        "/logout",
        data={"csrf_token": client.csrf_token},
        headers={"Origin": "https://archive.example.org"},
        follow_redirects=False,
    )
    assert accepted.status_code == 303
