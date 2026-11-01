"""Non-secret action paths cannot retrieve or present an email capability."""

from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import pytest
from lxml import html

from app.routes.auth import email_change, password_reset, verify_email
from app.services.email_change import generate_email_change_token
from app.services.email_verification import generate_verification_token
from app.services.password_reset import generate_reset_token
from app.services.tokens import action_token_public_id

TOKEN = "private-action-capability-canary.invalid.signature"
PASSWORD = "Action-Link-Owner-Password!73"
FLOWS = (
    ("/reset-password", password_reset, "validate_reset_token", "update_password_with_token", 422),
    (
        "/verify-email",
        verify_email,
        "inspect_local_registration",
        "complete_local_registration",
        400,
    ),
    (
        "/account/confirm-email",
        email_change,
        "validate_email_change_token",
        "confirm_email_change",
        400,
    ),
)


@contextmanager
def flow_boundaries(flow):
    """Yield signature-checked validator and mutation mocks for the selected flow."""
    _, module, validator_name, mutation_name, _ = flow
    with ExitStack() as stack:
        validator = stack.enter_context(patch.object(module, validator_name, autospec=True))
        mutation = stack.enter_context(patch.object(module, mutation_name, autospec=True))
        yield validator, mutation


def post_fields(client, **changes):
    """Build the valid form with caller overrides and the current CSRF token."""
    return {
        "public_id": action_token_public_id(TOKEN),
        "token": TOKEN,
        "password": PASSWORD,
        "password_confirm": PASSWORD,
        "display_name": "Mailbox Owner",
        "csrf_token": client.csrf_token,
        **changes,
    }


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
def test_identifier_only_landing_page_does_not_resolve_a_secret_or_account(guest_client, flow):
    """Check identifier only landing page does not resolve a secret or account (HTTP 200)."""
    prefix = flow[0]
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.get(f"{prefix}/{action_token_public_id(TOKEN)}")
    assert response.status_code == 200
    assert 'name="public_id"' in response.text and 'name="token"' in response.text
    assert f'value="{action_token_public_id(TOKEN)}"' in response.text
    assert TOKEN not in response.text and "owner@example.org" not in response.text
    document = html.fromstring(response.text)
    token_fields = document.xpath('//form//input[@name="token"]')
    assert len(token_fields) == (2 if prefix == "/reset-password" else 1)
    assert len({field.get("id") for field in token_fields}) == len(token_fields)
    for token_field in token_fields:
        assert token_field.get("type") == "text"
        assert token_field.get("value") == ""
        assert "required" in token_field.attrib
        assert not token_field.xpath("ancestor-or-self::*[@hidden]")
    assert document.xpath('//label[@for="action-token"]/text()') == [
        "Security code from your email"
    ]
    assert not document.xpath("//script | //noscript")
    assert not document.xpath("//*[@data-action-token or @data-token-input]")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "strict-origin"
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
def test_query_string_cannot_populate_or_authorize_the_landing_form(guest_client, flow):
    """Check query string cannot populate or authorize the landing form (HTTP 200)."""
    prefix = flow[0]
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.get(
            f"{prefix}/{action_token_public_id(TOKEN)}",
            params={"token": TOKEN, "email": "victim@example.org", "public_id": "attacker"},
        )
    assert response.status_code == 200
    assert TOKEN not in response.text and "victim@example.org" not in response.text
    assert 'name="token" value=""' in response.text or 'value=""' in response.text
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
@pytest.mark.parametrize("field", ["token", "public_id"])
def test_secret_and_identifier_must_both_be_present_in_the_post_body(guest_client, flow, field):
    """Check secret and identifier must both be present in the POST body (HTTP 422)."""
    fields = post_fields(guest_client)
    omitted = fields.pop(field)
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.post(flow[0], params={field: omitted}, data=fields)
    assert response.status_code == 422
    assert TOKEN not in response.text and PASSWORD not in response.text
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
@pytest.mark.parametrize("public_id", ["short", "A" * 43])
def test_mismatched_identifier_rejects_before_capability_or_account_processing(
    guest_client, flow, public_id
):
    """Check mismatched identifier rejects before capability or account processing."""
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.post(flow[0], data=post_fields(guest_client, public_id=public_id))
    assert response.status_code == flow[4]
    assert TOKEN not in response.text and PASSWORD not in response.text
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
@pytest.mark.parametrize("public_id", ["short", "A" * 42, "A" * 44, "é" * 43, "A" * 42 + "."])
def test_malformed_public_identifier_is_404_without_capability_processing(
    guest_client, flow, public_id
):
    """Check malformed public identifier is 404 without capability processing."""
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.get(f"{flow[0]}/{public_id}")
    assert response.status_code == 404
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
def test_old_secret_bearing_path_is_404_even_for_a_valid_signed_capability(guest_client, flow):
    """Check old secret bearing path is 404 even for a valid signed capability."""
    prefix = flow[0]
    token = {
        "/reset-password": lambda: generate_reset_token(7, "owner@example.org"),
        "/verify-email": lambda: generate_verification_token(7, "owner@example.org"),
        "/account/confirm-email": lambda: generate_email_change_token(
            7, "replacement@example.org", auth_revision=0
        ),
    }[prefix]()
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.get(f"{prefix}/{token}")
    assert response.status_code == 404
    assert token not in response.text
    validator.assert_not_called()
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
def test_matching_public_digest_does_not_make_an_invalid_secret_authoritative(guest_client, flow):
    """Check matching public digest does not make an invalid secret authoritative."""
    _, module, _, mutation_name, expected_status = flow
    with patch.object(module, mutation_name, autospec=True) as mutation:
        response = guest_client.post(flow[0], data=post_fields(guest_client))
    assert response.status_code == expected_status
    assert TOKEN not in response.text and PASSWORD not in response.text
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()


@pytest.mark.parametrize("flow", FLOWS, ids=["reset", "verification", "email-change"])
def test_malformed_identifier_is_not_reflected_as_markup(guest_client, flow):
    """Check malformed identifier is not reflected as markup."""
    value = '<img src=x onerror="alert(1)">'
    with flow_boundaries(flow) as (validator, mutation):
        response = guest_client.post(flow[0], data=post_fields(guest_client, public_id=value))
    assert response.status_code == flow[4]
    assert value not in response.text and 'onerror="alert(1)"' not in response.text
    validator.assert_not_called()
    mutation.assert_not_called()


@pytest.mark.parametrize(
    ("source", "destination"),
    [(a, b) for a in range(3) for b in range(3) if a != b],
    ids=[
        "reset-to-verification",
        "reset-to-email-change",
        "verification-to-reset",
        "verification-to-email-change",
        "email-change-to-reset",
        "email-change-to-verification",
    ],
)
def test_a_signed_capability_from_another_flow_does_not_gain_authority(
    guest_client, source, destination
):
    """Check a signed capability from another flow does not gain authority."""
    token = (
        generate_reset_token(7, "owner@example.org"),
        generate_verification_token(7, "owner@example.org"),
        generate_email_change_token(7, "replacement@example.org", auth_revision=0),
    )[source]
    flow = FLOWS[destination]
    with patch.object(flow[1], flow[3], autospec=True) as mutation:
        response = guest_client.post(
            flow[0],
            data=post_fields(guest_client, token=token, public_id=action_token_public_id(token)),
        )
    assert response.status_code == flow[4]
    assert token not in response.text and "owner@example.org" not in response.text
    mutation.assert_not_called()
    guest_client.mock_pool.connection.assert_not_called()
