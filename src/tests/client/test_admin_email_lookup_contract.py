"""Administrator lookup accepts the full stored local/federated identity contract."""

from unittest.mock import patch

import pytest
from lxml import html

from app.credentials import normalize_email
from app.federation_contract import EMAIL_MAX_LENGTH
from app.services.federated_authentication import build_federated_principal
from tests.fixtures import make_sample_user

_LONG_EMAIL = "long-local-name@" + ".".join(["a" * 60, "b" * 60, "c" * 60, "example", "org"])


@pytest.mark.parametrize("email", ["müller@example.org", _LONG_EMAIL, "local@example.org"])
def test_admin_lookup_accepts_federated_producer_identities(admin_client, email):
    """Check admin lookup accepts federated producer identities (HTTP 200)."""
    principal = build_federated_principal(
        issuer="https://idp.example.org",
        subject_id="subject-1",
        email=email,
        authn_context="https://refeds.org/profile/mfa",
    )
    target = make_sample_user(email=principal.email, auth_method="shibboleth")
    with (
        patch(
            "app.routes.auth.admin.get_user_by_email", autospec=True, return_value=target
        ) as lookup,
        patch("app.routes.auth.admin.list_users", autospec=True) as list_users,
        patch("app.routes.auth.admin.list_admin_promotion_states", autospec=True, return_value={}),
        patch("app.routes.auth.admin.list_federated_reviews", autospec=True, return_value={}),
    ):
        response = admin_client.get("/admin", params={"email": email})
    assert response.status_code == 200
    lookup.assert_awaited_once_with(admin_client.mock_pool, principal.email)
    list_users.assert_not_awaited()
    field = html.fromstring(response.text).get_element_by_id("account-email")
    assert field.get("maxlength") == str(EMAIL_MAX_LENGTH)
    # Native HTML email validation rejects valid SMTPUTF8 local parts.
    assert field.get("type") == "text"
    assert field.get("inputmode") == "email"
    assert field.get("value") == principal.email


@pytest.mark.parametrize("email", ["not-an-email", "x" * (EMAIL_MAX_LENGTH + 1)])
def test_admin_lookup_rejects_invalid_or_oversized_input_before_query(admin_client, email):
    """Check admin lookup rejects invalid or oversized input before query (HTTP 422)."""
    with patch("app.routes.auth.admin.get_user_by_email", autospec=True) as lookup:
        response = admin_client.get("/admin", params={"email": email})
    assert response.status_code == 422
    lookup.assert_not_awaited()


@pytest.mark.parametrize("email", ["müller@example.org", _LONG_EMAIL])
def test_lookup_does_not_relax_local_account_email_policy(email):
    """Check lookup does not relax local account email policy."""
    assert normalize_email(email) is None
