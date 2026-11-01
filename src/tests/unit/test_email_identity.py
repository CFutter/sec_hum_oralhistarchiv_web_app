"""Configured site identity reaches every email without changing action links."""

from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest

from app.services.email import (
    build_account_credential_fault_notice,
    build_account_locked_notice,
    build_duplicate_registration_notice,
    build_email_change_notice,
    build_email_change_verification,
    build_password_changed_email,
    build_password_reset_email,
    build_verification_email,
)
from app.services.tokens import action_token_url
from config import settings
from tests.action_links import token_from_action_email

_ACTION_CODE = "configured-identity-capability.canary.81d2"
_RESET_URL = f"https://archive.example.org{action_token_url('/reset-password', _ACTION_CODE)}"
_VERIFY_URL = f"https://archive.example.org{action_token_url('/verify-email', _ACTION_CODE)}"
_CHANGE_URL = (
    f"https://archive.example.org{action_token_url('/account/confirm-email', _ACTION_CODE)}"
)
_EXPIRY = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    ("builder", "extra_args", "kwargs", "message_type", "expected_text"),
    [
        pytest.param(
            build_password_changed_email,
            (),
            {},
            "password_changed_notice",
            ("https://archive.example.org/login",),
            id="password-changed",
        ),
        pytest.param(
            build_password_reset_email,
            (_RESET_URL,),
            {"expires_at": _EXPIRY, "security_code": _ACTION_CODE},
            "password_reset",
            (_RESET_URL, "2030-01-02 03:04:05 UTC", _ACTION_CODE),
            id="password-reset",
        ),
        pytest.param(
            build_verification_email,
            (_VERIFY_URL,),
            {"expires_at": _EXPIRY, "security_code": _ACTION_CODE},
            "email_verification",
            (_VERIFY_URL, "2030-01-02 03:04:05 UTC", _ACTION_CODE),
            id="email-verification",
        ),
        pytest.param(
            build_duplicate_registration_notice,
            (),
            {},
            "duplicate_registration_notice",
            (
                "https://archive.example.org/login",
                "https://archive.example.org/forgot-password",
            ),
            id="duplicate-registration",
        ),
        pytest.param(
            build_email_change_verification,
            (_CHANGE_URL,),
            {"expires_at": _EXPIRY, "security_code": _ACTION_CODE},
            "email_change_verification",
            (_CHANGE_URL, "2030-01-02 03:04:05 UTC", _ACTION_CODE),
            id="email-change-verification",
        ),
        pytest.param(
            build_email_change_notice,
            ("new-address@example.org",),
            {},
            "email_change_notice",
            ("new-address@example.org",),
            id="email-change-notice",
        ),
        pytest.param(
            build_account_credential_fault_notice,
            (),
            {},
            "account_credential_fault_notice",
            ("https://archive.example.org/forgot-password",),
            id="credential-fault",
        ),
        pytest.param(
            build_account_locked_notice,
            (),
            {},
            "account_locked_notice",
            ("https://archive.example.org/forgot-password",),
            id="account-locked",
        ),
    ],
)
def test_email_uses_configured_identity_and_preserves_actions(
    monkeypatch, builder, extra_args, kwargs, message_type, expected_text
):
    """Builders brand their messages while keeping recipients and capability text intact."""
    monkeypatch.setattr(settings, "site_name", "Community Memory Catalogue")
    monkeypatch.setattr(settings, "institution_name", "Example Research Institute")
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")

    message = builder("recipient@example.org", *extra_args, **kwargs)

    assert message.recipient == "recipient@example.org"
    assert message.message_type == message_type
    assert message.subject.endswith(" — Community Memory Catalogue")
    assert "Community Memory Catalogue" in message.body.splitlines()[0]
    assert message.body.endswith("— Community Memory Catalogue\nExample Research Institute")
    assert "Oral History Archive" not in message.subject + message.body
    for value in expected_text:
        assert value in message.body
    if "security_code" in kwargs:
        link = urlsplit(extra_args[0])
        assert not link.query and not link.fragment
        assert _ACTION_CODE not in extra_args[0]
        assert token_from_action_email(message.body, extra_args[0]) == _ACTION_CODE
