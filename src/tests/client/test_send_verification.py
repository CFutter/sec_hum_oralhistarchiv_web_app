"""Resend-verification flow — enumeration-neutral by construction.

Guards (ported from legacy test_register_resend.py, re-verified against the
current route): POST /send_verification must return the SAME generic success
page whether the email is unknown, already verified, non-local, or genuinely
resent — the response may never confirm account existence. The email is only
actually (re)issued for an unverified LOCAL account.

Rate limit note: the route is 3/hour — at most 3 POSTs per test (the limiter
resets between tests).
"""
from unittest.mock import patch

from tests.fixtures import make_sample_user

# The template ignores the route's message text and renders a fixed success
# block ({% if success %} → "Check your email"), which is what makes the
# response inherently uniform across all outcomes.
GENERIC_SUCCESS = "Check your email"


def _post(client, email):
    return client.post(
        "/send_verification",
        data={"email": email, "csrf_token": client.csrf_token},
    )


def test_get_page_prefills_email(guest_client):
    response = guest_client.get("/send_verification?email=alice%40uzh.ch")
    assert response.status_code == 200
    assert "alice@uzh.ch" in response.text


def test_unverified_local_user_gets_resend(guest_client):
    """The one case that actually sends: unverified + local. A fresh token is
    stored (overwriting the old hash — one outstanding link per user)."""
    user = make_sample_user(email_verified=False)
    with patch("app.routes.auth.register.get_user_by_email",
               autospec=True, return_value=user), \
         patch("app.routes.auth.register.store_verification_token_hash", autospec=True) as store, \
         patch("app.routes.auth.register.send_verification_email", autospec=True) as send:
        response = _post(guest_client, user.email)
    assert response.status_code == 200
    assert GENERIC_SUCCESS in response.text
    store.assert_awaited_once()
    send.assert_called_once()  # queued as a background task, then executed


def test_verified_and_unknown_emails_are_indistinguishable(guest_client):
    """No enumeration: an existing-but-verified account and a completely
    unknown address yield BYTE-IDENTICAL responses (same submitted email, so
    the echoed value matches too), and nothing is sent either way."""
    verified = make_sample_user(email="probe@uzh.ch", email_verified=True)
    with patch("app.routes.auth.register.get_user_by_email",
               autospec=True, side_effect=[verified, None]), \
         patch("app.routes.auth.register.store_verification_token_hash", autospec=True) as store, \
         patch("app.routes.auth.register.send_verification_email", autospec=True) as send:
        exists = _post(guest_client, "probe@uzh.ch")
        unknown = _post(guest_client, "probe@uzh.ch")
    assert exists.status_code == unknown.status_code == 200
    assert exists.text == unknown.text
    assert GENERIC_SUCCESS in exists.text
    store.assert_not_awaited()
    send.assert_not_called()


def test_invalid_email_gets_same_generic_page(guest_client):
    """A syntactically invalid address short-circuits before any lookup but
    still renders the same success page — validation errors must not become
    an enumeration side channel either."""
    with patch("app.routes.auth.register.get_user_by_email", autospec=True) as lookup:
        response = _post(guest_client, "not-an-email")
    assert response.status_code == 200
    assert GENERIC_SUCCESS in response.text
    lookup.assert_not_awaited()


def test_shibboleth_account_never_resent(guest_client):
    """Non-local accounts are verified at the IdP — no token, same page."""
    shib = make_sample_user(auth_method="shibboleth", email_verified=False)
    with patch("app.routes.auth.register.get_user_by_email",
               autospec=True, return_value=shib), \
         patch("app.routes.auth.register.store_verification_token_hash", autospec=True) as store:
        response = _post(guest_client, shib.email)
    assert response.status_code == 200
    assert GENERIC_SUCCESS in response.text
    store.assert_not_awaited()
