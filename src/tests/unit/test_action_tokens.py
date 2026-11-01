"""Signed action capabilities and nonauthorizing browser landing identifiers."""

import base64
import logging
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from pydantic import SecretStr

from app.services.email_change import generate_email_change_token, validate_email_change_token
from app.services.email_verification import (
    generate_verification_token,
    validate_verification_token,
)
from app.services.password_reset import generate_reset_token, validate_reset_token
from app.services.tokens import (
    SignedActionToken,
    action_token_public_id,
    action_token_url,
    hash_token,
    valid_action_public_id,
)
from config import settings


@pytest.mark.parametrize("salt", ["", "  ", None, 1])
def test_signer_requires_a_nonempty_signature_domain(salt):
    """Signer requires a nonempty signature domain."""
    with pytest.raises(ValueError, match="salt"):
        SignedActionToken(salt, 30)


@pytest.mark.parametrize("lifetime", [True, False, 0, -1, 1.5, "30"])
def test_signer_lifetime_cannot_be_a_boolean_or_nonpositive_noninteger(lifetime):
    """Signer lifetime cannot be a boolean or nonpositive noninteger."""
    with pytest.raises(ValueError, match="lifetime"):
        SignedActionToken("test-flow", lifetime)


def test_signer_copies_payload_and_injects_an_independent_nonce():
    """Signer copies payload and injects an independent nonce."""
    signer = SignedActionToken("test-flow", 30)
    payload = {"user_id": 17, "email": "person@example.org", "nonce": "caller-value"}
    first, second = signer.issue(payload), signer.issue(payload)
    decoded = signer.loads(first)
    assert isinstance(decoded, dict)
    assert decoded["user_id"] == 17
    assert decoded["email"] == "person@example.org"
    assert decoded["nonce"] != payload["nonce"]
    assert len(decoded["nonce"]) >= 22
    assert first != second
    assert payload == {"user_id": 17, "email": "person@example.org", "nonce": "caller-value"}
    assert first not in repr(signer)
    with pytest.raises(FrozenInstanceError):
        signer.salt = "different-flow"


def test_signer_separates_domains_and_keeps_its_original_signed_deadline(monkeypatch):
    """Signer separates domains and keeps its original signed deadline."""
    now = datetime(2030, 1, 1, tzinfo=UTC)
    timestamp = int(now.timestamp())
    monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda _self: timestamp)
    signer = SignedActionToken("test-flow", 30)
    token = signer.issue({"user_id": 17})
    timestamp += 10
    metadata = signer.email_metadata(token)
    assert metadata.expires_at == now + timedelta(seconds=30)
    assert metadata.token_hash == hash_token(token)
    assert metadata.token_hash not in repr(metadata)
    with pytest.raises(BadSignature):
        SignedActionToken("different-flow", 30).loads(token)
    timestamp += 21
    with pytest.raises(SignatureExpired):
        signer.loads(token)
    with pytest.raises(SignatureExpired):
        signer.email_metadata(token)


def test_existing_signer_reads_the_current_key_for_each_operation(monkeypatch):
    """Existing signer reads the current key for each operation."""
    signer = SignedActionToken("test-flow", 30)
    old_token = signer.issue({"user_id": 17})
    monkeypatch.setattr(
        settings,
        "secret_key",
        SecretStr("replacement-kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7"),
    )
    with pytest.raises(BadSignature):
        signer.loads(old_token)
    assert signer.loads(signer.issue({"user_id": 18}))["user_id"] == 18


@pytest.mark.parametrize(
    ("flow_path", "generate", "validate"),
    [
        ("/verify-email", generate_verification_token, validate_verification_token),
        ("/reset-password", generate_reset_token, validate_reset_token),
        (
            "/account/confirm-email",
            lambda user_id, email: generate_email_change_token(user_id, email, auth_revision=4),
            validate_email_change_token,
        ),
    ],
)
def test_each_flow_url_keeps_the_capability_out_of_path_and_query(flow_path, generate, validate):
    """Each flow URL keeps the capability out of path and query."""
    token = generate(17, "person@example.org")
    link = action_token_url(flow_path, token)
    parts = urlsplit(link)
    public_id = parts.path.rsplit("/", 1)[1]
    assert parts.scheme == parts.netloc == parts.query == ""
    assert parts.path == f"{flow_path}/{public_id}"
    assert valid_action_public_id(public_id)
    assert len(base64.urlsafe_b64decode(public_id + "=")) == 32
    assert public_id != hash_token(token)
    assert token not in link
    assert parts.fragment == ""
    assert validate(public_id) is None
    assert validate(token) is not None
    assert action_token_public_id(token) == public_id
    assert action_token_public_id(generate(17, "person@example.org")) != public_id


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 42,
        "a" * 44,
        "A" * 42 + ".",
        "A" * 42 + "=",
        "é" * 43,
        "\uff21" * 43,
        "A" * 43 + "\n",
        None,
    ],
)
def test_public_identifier_accepts_only_the_fixed_ascii_shape(value):
    """Public identifier accepts only the fixed ascii shape."""
    assert not valid_action_public_id(value)


@pytest.mark.parametrize(
    "path",
    [
        "https://attacker.example/reset-password",
        "//attacker.example/reset-password",
        "/reset-password/",
        "/reset-password?next=outside",
        "/other-flow",
    ],
)
def test_url_builder_cannot_select_an_external_or_unreviewed_flow(path):
    """URL builder cannot select an external or unreviewed flow."""
    with pytest.raises(ValueError, match="flow"):
        action_token_url(path, "secret-token")


def test_secret_delimiters_cannot_create_another_url_component():
    """Secret delimiters cannot create another URL component."""
    token = "secret/with?components#and=delimiters&plus+unicodeé"
    parts = urlsplit(action_token_url("/reset-password", token))
    assert parts.query == parts.fragment == ""
    assert parts.path == f"/reset-password/{action_token_public_id(token)}"
    assert token not in parts.geturl()


@pytest.mark.parametrize(
    "validate", [validate_verification_token, validate_reset_token, validate_email_change_token]
)
def test_flow_rejection_logs_never_echo_supplied_signature_bytes(validate, caplog):
    """Flow rejection logs never echo supplied signature bytes."""
    canary = "secret-supplied-invalid-signature-canary"
    with caplog.at_level(logging.WARNING):
        assert validate(f"invalid.payload.{canary}") is None
    assert "Invalid or expired" in caplog.text
    assert canary not in caplog.text
