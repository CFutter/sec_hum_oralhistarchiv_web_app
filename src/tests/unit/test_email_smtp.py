"""Classified SMTP failures, action-email builders and email normalization."""

import logging
import smtplib
import ssl
import unicodedata
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from unittest.mock import MagicMock, create_autospec, patch
from urllib.parse import urlsplit

import pytest
from pydantic import SecretStr

import app.services.email as email_module
from app.credentials import normalize_email as normalize_credential_email
from app.services import (
    build_duplicate_registration_notice,
    build_verification_email,
)
from app.services import normalize_email as reexported_normalize_email
from app.services.crypto import audit_email_hash
from app.services.email import (
    _send_security_email,
    build_password_reset_email,
    send_email,
)
from app.services.email_utils import normalize_email
from app.services.tokens import action_token_url
from config import settings
from tests.action_links import token_from_action_email

_SMTP_PATCH_TARGET = "app.services.email.smtplib.SMTP"


def _make_smtp_mock():
    """Autospecced stand-in for smtplib.SMTP used as a context manager.

    Returns (smtp_class_mock, server_mock) where server_mock is what the
    `with smtplib.SMTP(...) as server:` block sees; the class spec makes a
    constructor or method call that drifts from the real signature fail here.
    """
    smtp_cls = create_autospec(smtplib.SMTP, spec_set=True)
    server = smtp_cls.return_value
    server.__enter__.return_value = server
    return smtp_cls, server


@pytest.fixture
def smtp_on(monkeypatch):
    """Enable SMTP with deterministic host/port and no auth (per-test only).

    settings is a mutable pydantic object; monkeypatch restores afterwards.
    """
    monkeypatch.setattr(settings, "smtp_enabled", True)
    monkeypatch.setattr(settings, "smtp_host", "relay.test")
    monkeypatch.setattr(settings, "smtp_port", 2525)
    monkeypatch.setattr(settings, "smtp_user", "")
    monkeypatch.setattr(settings, "smtp_password", None)


class TestTransportConfiguration:
    """Every SMTP construction is bounded and TLS is applied explicitly."""

    @pytest.mark.usefixtures("smtp_on")
    @pytest.mark.parametrize("use_tls", [True, False], ids=["tls", "plain"])
    def test_send_email_constructs_smtp_with_bounded_keyword_timeout(self, monkeypatch, use_tls):
        """Pass SMTP timeout by keyword and an explicit SSL context to STARTTLS."""
        monkeypatch.setattr(settings, "smtp_use_tls", use_tls)
        smtp_cls, server = _make_smtp_mock()

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "sent"
        assert result.reason == "smtp_accepted"

        smtp_cls.assert_called_once_with(
            "relay.test", 2525, timeout=email_module._SMTP_SEND_TIMEOUT
        )
        assert smtp_cls.call_args.kwargs["timeout"] == email_module._SMTP_SEND_TIMEOUT
        if use_tls:
            server.starttls.assert_called_once()
            assert isinstance(server.starttls.call_args.kwargs["context"], ssl.SSLContext)
        else:
            server.starttls.assert_not_called()
        server.send_message.assert_called_once()


class TestInternationalizedAddressDelivery:
    """Encode IDN mailbox domains with IDNA without negotiating SMTPUTF8."""

    @pytest.mark.parametrize(
        "domain",
        ["bücher.ch", "xn--bcher-kva.ch"],
        ids=["unicode_domain", "punycode_domain"],
    )
    def test_idn_sender_and_recipient_are_idna_encoded_without_smtputf8(self, monkeypatch, domain):
        """Use IDNA ASCII sender/recipient domains without SMTPUTF8."""
        server = smtplib.SMTP()
        server.ehlo_or_helo_if_needed = MagicMock()
        server.has_extn = MagicMock(return_value=False)
        server.sendmail = MagicMock(return_value={})
        smtp_ctor = create_autospec(smtplib.SMTP, spec_set=True)
        smtp_ctor.return_value = server
        monkeypatch.setattr(email_module.smtplib, "SMTP", smtp_ctor)
        monkeypatch.setattr(settings, "smtp_enabled", True)
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        monkeypatch.setattr(settings, "smtp_user", "")
        monkeypatch.setattr(settings, "smtp_from_address", f"sender@{domain}")

        identity = normalize_credential_email(f"reader@{domain}")
        assert identity == "reader@bücher.ch"
        result = send_email(identity, "Subject", "Body")

        assert result.status == "sent"
        assert result.reason == "smtp_accepted"
        args = server.sendmail.call_args.args
        assert args[:2] == ("sender@xn--bcher-kva.ch", ["reader@xn--bcher-kva.ch"])
        assert b"reader@xn--bcher-kva.ch" in args[2]


class TestSenderIdentityEncoding:
    """Keep the configured From display name in a single encoded mailbox."""

    def test_display_name_with_comma_and_quote_stays_a_single_mailbox(self, monkeypatch):
        """Keep commas and quotes inside the single From display name."""
        monkeypatch.setattr(settings, "smtp_enabled", True)
        monkeypatch.setattr(settings, "smtp_from_name", 'Archive, University "Zurich"')
        monkeypatch.setattr(settings, "smtp_from_address", "archive@example.org")
        smtp_cls, server = _make_smtp_mock()

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("person@example.org", "Subject", "Body")

        assert result.status == "sent"
        header = server.send_message.call_args.args[0]["From"]
        assert len(header.addresses) == 1
        assert header.addresses[0].display_name == 'Archive, University "Zurich"'


class TestSendFailureClassification:
    """Every SMTP or transport failure mode is classified, never raised."""

    @pytest.mark.usefixtures("smtp_on")
    @pytest.mark.parametrize(
        "exc",
        [TimeoutError("timed out"), OSError("connection refused")],
        ids=["socket_timeout", "oserror"],
    )
    def test_connection_failure_is_reported_as_temporary_failure(self, monkeypatch, exc):
        """Connection failure is reported as temporary failure."""
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        smtp_cls = create_autospec(smtplib.SMTP, spec_set=True, side_effect=exc)

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "temporary_failure"
        assert result.reason == "smtp_transport_error"

    @pytest.mark.usefixtures("smtp_on")
    @pytest.mark.parametrize(
        "exc,expected_reason",
        [
            (smtplib.SMTPRecipientsRefused({}), "smtp_recipient_refused_temporary"),
            (Exception("boom"), "email_unexpected_error"),
            (smtplib.SMTPServerDisconnected("relay hung up"), "smtp_protocol_error"),
        ],
        ids=[
            "recipients_refused_temporary",
            "unexpected_exception_is_caught_by_the_backstop",
            "generic_smtp_exception_is_a_protocol_error",
        ],
    )
    def test_send_message_failure_is_classified_as_temporary(
        self, monkeypatch, exc, expected_reason
    ):
        """Send message failure is classified as temporary."""
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        smtp_cls, server = _make_smtp_mock()
        server.send_message.side_effect = exc

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "temporary_failure"
        assert result.reason == expected_reason

    @pytest.mark.usefixtures("smtp_on")
    def test_authentication_failure_reports_code_and_logs_error(self, monkeypatch, caplog):
        """Authentication failure reports code and logs error."""
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        monkeypatch.setattr(settings, "smtp_user", "mailer")
        monkeypatch.setattr(settings, "smtp_password", SecretStr("s3cret"))
        smtp_cls, server = _make_smtp_mock()
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"no")

        with (
            patch(_SMTP_PATCH_TARGET, smtp_cls),
            caplog.at_level(logging.ERROR, logger="app.services.email"),
        ):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "temporary_failure"
        assert result.reason == "smtp_authentication_failed"
        assert result.smtp_code == 535

        auth_records = [r for r in caplog.records if r.getMessage() == "smtp_auth_failed"]
        assert len(auth_records) == 1
        assert auth_records[0].event_type == "smtp_auth_failed"

    @pytest.mark.usefixtures("smtp_on")
    def test_acceptance_is_reported_sent_even_when_connection_cleanup_fails(self):
        """Acceptance is reported sent even when connection cleanup fails."""
        smtp_cls, server = _make_smtp_mock()
        server.close.side_effect = OSError("cleanup failed after acceptance")

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "sent"
        assert result.reason == "smtp_accepted"
        server.send_message.assert_called_once()
        server.quit.assert_not_called()

    @pytest.mark.usefixtures("smtp_on")
    def test_message_construction_failure_is_caught_by_the_no_raise_backstop(self):
        """Message construction failure is caught by the no raise backstop."""
        with patch(_SMTP_PATCH_TARGET) as smtp:
            result = send_email("alice@example.org", "subject\nInjected: header", "body")

        assert result.status == "temporary_failure"
        assert result.reason == "email_unexpected_error"
        smtp.assert_not_called()


class TestAuthenticationGating:
    """`_maybe_login` is called only when a username is configured."""

    @pytest.mark.usefixtures("smtp_on")
    def test_login_called_with_configured_credentials(self, monkeypatch):
        """smtp_user + smtp_password set -> server.login is called with
        exactly that pair (secret unwrapped): auth must actually be used
        when configured.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        monkeypatch.setattr(settings, "smtp_user", "mailer")
        monkeypatch.setattr(settings, "smtp_password", SecretStr("s3cret"))
        smtp_cls, server = _make_smtp_mock()

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "sent"
        server.login.assert_called_once_with("mailer", "s3cret")

    @pytest.mark.usefixtures("smtp_on")
    def test_login_skipped_when_no_smtp_user(self, monkeypatch):
        """smtp_user '' (unauthenticated relay) -> login is NOT attempted;
        a spurious login against a no-auth relay would fail every send.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        smtp_cls, server = _make_smtp_mock()

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@example.org", "subject", "body")

        assert result.status == "sent"
        server.login.assert_not_called()

    @pytest.mark.usefixtures("smtp_on")
    def test_configured_username_requires_a_password_at_runtime(self, monkeypatch):
        """Reject malformed runtime credentials before attempting SMTP AUTH."""
        monkeypatch.setattr(settings, "smtp_user", "mailer")
        monkeypatch.setattr(settings, "smtp_password", None)
        _, server = _make_smtp_mock()

        with pytest.raises(RuntimeError, match="SMTP_PASSWORD is required when SMTP_USER is set"):
            email_module._maybe_login(server)

        server.login.assert_not_called()


class TestDevelopmentMailbox:
    """Disabled SMTP (the test-environment default) saves to a private mailbox."""

    def test_disabled_smtp_saves_usable_private_message_without_logging_body(
        self, caplog, tmp_path, monkeypatch
    ):
        """Disabled SMTP saves usable private message without logging body."""
        mailbox = tmp_path / "mailbox"
        monkeypatch.setattr(settings, "dev_mailbox_dir", str(mailbox))
        body = "Click here: http://127.0.0.1:5000/reset-password/tok-abc123"
        with patch(_SMTP_PATCH_TARGET) as smtp, caplog.at_level(logging.DEBUG):
            result = send_email("alice@example.org", "Reset", body)
        assert result.status == "sent"
        assert result.reason == "development_mailbox_saved"
        smtp.assert_not_called()
        messages = list(mailbox.glob("*.eml"))
        assert len(messages) == 1
        assert (
            body
            in BytesParser(policy=policy.default).parsebytes(messages[0].read_bytes()).get_content()
        )
        assert mailbox.stat().st_mode & 0o777 == 0o700
        assert messages[0].stat().st_mode & 0o777 == 0o600
        assert "tok-abc123" not in caplog.text

    @pytest.mark.parametrize("environment", ["staging", "prod"])
    def test_disabled_smtp_outside_development_never_reaches_the_mailbox(
        self, environment, monkeypatch, tmp_path
    ):
        """Disabled SMTP outside development never reaches the mailbox."""
        monkeypatch.setattr(settings, "env_state", environment)
        monkeypatch.setattr(settings, "smtp_enabled", False)
        monkeypatch.setattr(settings, "dev_mailbox_dir", str(tmp_path / "mailbox"))
        result = send_email("a@example.org", "subject", "body")
        assert result.status == "temporary_failure"
        assert result.reason == "smtp_disabled"
        assert not (tmp_path / "mailbox").exists()

    def test_mailbox_write_failure_does_not_report_delivery_success(self, monkeypatch, tmp_path):
        """Mailbox write failure does not report delivery success."""
        mailbox = tmp_path / "mailbox"
        mailbox.mkdir(mode=0o755)
        monkeypatch.setattr(settings, "dev_mailbox_dir", str(mailbox))
        result = send_email("a@example.org", "subject", "body")
        assert result.status == "temporary_failure"
        assert result.reason == "development_mailbox_write_failed"
        assert not list(mailbox.iterdir())


class TestSecurityEmailAuditAttribution:
    """`_send_security_email` attributes failure without leaking the address."""

    def test_failure_emits_hashed_audit_event(self, caplog):
        """Failure emits hashed audit event."""
        raw_email = "victim@example.org"
        failure = email_module.DeliveryResult(
            status="temporary_failure", reason="smtp_transport_error"
        )
        with (
            patch("app.services.email.send_email", autospec=True) as send_mock,
            caplog.at_level(logging.ERROR, logger="audit"),
        ):
            send_mock.return_value = failure
            result = _send_security_email("password_reset", raw_email, "s", "b")

        assert result.status == "temporary_failure"
        send_mock.assert_called_once_with(raw_email, "s", "b")
        audit_records = [
            r
            for r in caplog.records
            if r.name == "audit" and r.getMessage() == "security_email_failed"
        ]
        assert len(audit_records) == 1
        record = audit_records[0]
        assert record.event_type == "security_email_failed"
        assert record.email_type == "password_reset"
        assert record.recipient_hash == audit_email_hash(raw_email)
        for key, value in vars(record).items():
            assert raw_email not in str(value), f"raw email leaked via record.{key}"

    def test_success_emits_no_audit_error(self, caplog):
        """Return successful delivery unchanged without emitting an audit error."""
        sent = email_module.DeliveryResult(status="sent", reason="smtp_accepted")
        with (
            patch("app.services.email.send_email", autospec=True) as send_mock,
            caplog.at_level(logging.ERROR, logger="audit"),
        ):
            send_mock.return_value = sent
            result = _send_security_email("password_reset", "a@example.org", "s", "b")

        assert result.status == "sent"
        assert [r for r in caplog.records if r.name == "audit"] == []


class TestMessageBuilders:
    """Builder bodies carry their link, absolute expiry, and scoped recipient."""

    def test_password_reset_email_body_has_link_and_absolute_expiry(self):
        """The reset email has a public link and a separately entered security code."""
        token = "reset-capability-canary.for-mail.7f8120"
        link = f"http://127.0.0.1:5000{action_token_url('/reset-password', token)}"

        email = build_password_reset_email(
            "alice@example.org",
            link,
            expires_at=datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            security_code=token,
        )

        assert email.message_type == "password_reset"
        assert email.recipient == "alice@example.org"
        assert "Password Reset" in email.subject
        assert link in email.body
        target = urlsplit(link)
        assert token not in link
        assert not target.query and not target.fragment
        assert token_from_action_email(email.body, link) == token
        assert "copy this code into the form, then submit" in email.body
        assert "expires at 2030-01-01 12:00:00 UTC" in email.body
        assert "expires in" not in email.body

    def test_duplicate_registration_notice_only_to_existing_address(self):
        """The notice targets only the already-registered address — the
        single designed channel that confirms account existence.
        """
        email = build_duplicate_registration_notice("existing@example.org")

        assert email.message_type == "duplicate_registration_notice"
        assert email.recipient == "existing@example.org"
        assert "already have an account" in email.subject
        assert f"{settings.public_base_url}/login" in email.body
        assert f"{settings.public_base_url}/forgot-password" in email.body

    def test_verification_email_body_has_link_expiry_and_reaper_notice(self):
        """The rendered verification email contains all operational details."""
        token = "verification-capability-canary.for-mail.9c4301"
        link = f"https://archive.example{action_token_url('/verify-email', token)}"

        email = build_verification_email(
            "newcomer@example.org",
            link,
            expires_at=datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
            security_code=token,
        )

        assert email.message_type == "email_verification"
        assert email.recipient == "newcomer@example.org"
        assert "Verify your email" in email.subject
        assert link in email.body
        target = urlsplit(link)
        assert token not in link
        assert not target.query and not target.fragment
        assert token_from_action_email(email.body, link) == token
        assert "copy this code into the form, then submit" in email.body
        assert "expires at 2030-01-01 12:00:00 UTC" in email.body
        assert "expires in" not in email.body
        assert str(settings.unverified_reap_after_days) in email.body


@pytest.mark.parametrize(
    ("builder", "flow"),
    [
        (email_module.build_password_reset_email, "/reset-password"),
        (email_module.build_verification_email, "/verify-email"),
        (email_module.build_email_change_verification, "/account/confirm-email"),
    ],
)
class TestActionEmailCodeContract:
    """Require a separate nonempty security code in action-email builders."""

    def test_security_code_is_required(self, builder, flow):
        """Security code is required."""
        link = f"https://archive.example.org{action_token_url(flow, 'required-code')}"
        with pytest.raises(TypeError, match="security_code"):
            builder("recipient@example.org", link, expires_at=datetime(2030, 1, 1, tzinfo=UTC))

    @pytest.mark.parametrize("code", [None, "", " ", "\t\r\n", "\u2003", 1, False, b"code", [], {}])
    def test_invalid_security_code_is_rejected(self, builder, flow, code):
        """Invalid security code is rejected."""
        link = f"https://archive.example.org{action_token_url(flow, 'required-code')}"
        with pytest.raises(ValueError, match=r"^Action email requires a nonempty security code$"):
            builder(
                "recipient@example.org",
                link,
                expires_at=datetime(2030, 1, 1, tzinfo=UTC),
                security_code=code,
            )

    def test_valid_security_code_is_preserved_separately(self, builder, flow):
        """Valid security code is preserved separately."""
        code = "Exact-action_code.signed-7f81"
        link = f"https://archive.example.org{action_token_url(flow, code)}"
        message = builder(
            "recipient@example.org",
            link,
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
            security_code=code,
        )
        assert code not in link
        assert f"\n\nSecurity code:\n\n{code}\n\n" in message.body
        assert token_from_action_email(message.body, link) == code


class TestAddressNormalization:
    """`normalize_email` — the single normalization point for stored addresses."""

    def test_valid_mixed_case_address_is_lowercased_and_normalized(self):
        """A syntactically valid, mixed-case address comes back fully lowercased."""
        assert normalize_email("User@Example.COM") == "user@example.com"

    def test_invalid_input_returns_none_never_raises(self):
        """Return None for the parametrized syntactically invalid addresses."""
        assert normalize_email("not-an-email") is None
        assert normalize_email("") is None
        assert normalize_email("a@b") is None
        assert normalize_email("a@b.c") == "a@b.c"

    def test_idn_unicode_forms_normalize_to_the_same_stable_string(self):
        """NFC and NFD spellings of the same Unicode email collapse identically."""
        base = "u@exämple.com"
        nfc_form = unicodedata.normalize("NFC", base)
        nfd_form = unicodedata.normalize("NFD", base)
        assert nfc_form != nfd_form

        expected = "u@exämple.com"
        assert normalize_email(nfc_form) == expected
        assert normalize_email(nfd_form) == expected

    def test_idempotent_for_a_valid_address(self):
        """Re-normalizing an already-normalized address is a no-op."""
        raw = "User@Example.COM"
        once = normalize_email(raw)
        twice = normalize_email(once)
        assert once == twice == "user@example.com"

    def test_reexport_from_services_package_is_the_same_object(self):
        """Re-export the identical normalize_email function from app.services."""
        assert reexported_normalize_email is normalize_email
