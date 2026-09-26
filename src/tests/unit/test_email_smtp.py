"""Email service unit tests: SMTP transport, message builders, address normalization.

Covers `app.services.email` (the SMTP transport, its TLS/credential handling,
the never-raises delivery contract, the security-email audit hook, and the
plain-text message builders) and `app.services.email_utils` (the single
normalization point re-exported as `app.services.normalize_email`).

Pinned invariants:
- every `smtplib.SMTP(...)` construction passes a bounded `timeout=` keyword
  argument, and the TLS branch additionally calls `starttls` with an explicit
  SSL context;
- `send_email` never raises: every SMTP or transport failure is classified
  into a `DeliveryResult`, so callers (registration, password reset, lockout
  notices) cannot fail because delivery failed;
- login (`_maybe_login`) is attempted only when `smtp_user` is configured;
- when SMTP is disabled (the test-environment default), the message is saved
  to the private development mailbox instead, and the action link never
  reaches the application log;
- `_send_security_email` attributes delivery failure to an audit event keyed
  by a hashed recipient, never the raw address;
- builder bodies carry their link and absolute expiry, and the
  duplicate-registration notice goes only to the address that already exists
  (the designed enumeration channel);
- `normalize_email` lowercases and Unicode-normalizes (NFC) an address so two
  visually identical addresses in different Unicode forms collapse to the
  same stored/looked-up string, is idempotent, returns `None` (never raises)
  on syntactically invalid input, and is the same function object whether
  imported from `app.services` or `app.services.email_utils`.

Pure unit tests: no DB, no client, no real SMTP. `smtplib.SMTP` is patched in
the email module's namespace.
"""

import logging
import smtplib
import ssl
import unicodedata
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from unittest.mock import MagicMock, create_autospec, patch

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
from config import settings

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
        """Both send branches construct SMTP with `timeout=` as a keyword
        argument; the TLS branch additionally calls starttls with an
        explicit SSL context. A positional or missing timeout would let a
        hung relay pin a threadpool slot per send, unbounded.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", use_tls)
        smtp_cls, server = _make_smtp_mock()

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@uzh.ch", "subject", "body")

        assert result.status == "sent"
        assert result.reason == "smtp_accepted"

        # Exact-call match: timeout matches only as a kwarg (mock
        # distinguishes positional from keyword), proving the kwarg form.
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
    """IDN sender/recipient addresses are sent as IDNA ASCII, never by
    negotiating the SMTPUTF8 extension.

    These exercise the real stdlib envelope and MIME implementation (only
    `smtplib.SMTP` is replaced, with a real, unconnected `smtplib.SMTP()`
    instance) instead of a full mock, so a change to smtplib's own
    ASCII-only envelope encoding would be caught here.
    """

    @pytest.mark.parametrize(
        "domain",
        ["bücher.ch", "xn--bcher-kva.ch"],
        ids=["unicode_domain", "punycode_domain"],
    )
    def test_idn_sender_and_recipient_are_idna_encoded_without_smtputf8(self, monkeypatch, domain):
        """Whether the configured sender domain is typed as Unicode or
        already as punycode, the outgoing envelope's sender and recipient
        are always the punycode (IDNA) form, and the SMTPUTF8 extension is
        never relied on (`has_extn` is stubbed to report it unsupported)."""
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
    """The configured sender display name is encoded as a single mailbox
    address in the From header, even when it contains characters (a comma,
    an embedded quote) that would otherwise be mistaken for a second,
    comma-separated address.
    """

    def test_display_name_with_comma_and_quote_stays_a_single_mailbox(self, monkeypatch):
        """A comma and an embedded quote inside `smtp_from_name` must not
        split the From header into multiple addresses: the whole
        configured string remains one mailbox's display name.
        """
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
        """A TimeoutError/OSError raised while connecting is swallowed and
        `send_email` reports a temporary failure — a hung or dead relay must
        never take the caller (e.g. the registration request) down with it.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        smtp_cls = create_autospec(smtplib.SMTP, spec_set=True, side_effect=exc)

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@uzh.ch", "subject", "body")

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
        """A failure raised from `send_message` — a refused-recipients
        reply, a plain `smtplib.SMTPException` (e.g. an unexpected
        disconnect), or a completely unrelated exception — is always caught
        and reported as a temporary failure, never propagated to the caller.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        smtp_cls, server = _make_smtp_mock()
        server.send_message.side_effect = exc

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@uzh.ch", "subject", "body")

        assert result.status == "temporary_failure"
        assert result.reason == expected_reason

    @pytest.mark.usefixtures("smtp_on")
    def test_authentication_failure_reports_code_and_logs_error(self, monkeypatch, caplog):
        """`SMTPAuthenticationError` from `login()` becomes a temporary
        failure carrying the SMTP code (never raised), and a
        'smtp_auth_failed' event is logged at ERROR so a broken relay
        credential is visible in ops logs instead of vanishing into a
        generic failure.
        """
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        monkeypatch.setattr(settings, "smtp_user", "mailer")
        monkeypatch.setattr(settings, "smtp_password", SecretStr("s3cret"))
        smtp_cls, server = _make_smtp_mock()
        server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"no")

        with (
            patch(_SMTP_PATCH_TARGET, smtp_cls),
            caplog.at_level(logging.ERROR, logger="app.services.email"),
        ):
            result = send_email("alice@uzh.ch", "subject", "body")

        assert result.status == "temporary_failure"
        assert result.reason == "smtp_authentication_failed"
        assert result.smtp_code == 535

        auth_records = [r for r in caplog.records if r.getMessage() == "smtp_auth_failed"]
        assert len(auth_records) == 1
        assert auth_records[0].event_type == "smtp_auth_failed"

    @pytest.mark.usefixtures("smtp_on")
    def test_acceptance_is_reported_sent_even_when_connection_cleanup_fails(self):
        """The message is already accepted by the relay (`send_message`
        returned) before the `with` block exits; a subsequent OSError from
        the server's own `close()` during cleanup must not downgrade a
        successful send to a failure, and `quit()` must not be attempted
        against a connection that failed to close."""
        smtp_cls, server = _make_smtp_mock()
        server.close.side_effect = OSError("cleanup failed after acceptance")

        with patch(_SMTP_PATCH_TARGET, smtp_cls):
            result = send_email("alice@uzh.ch", "subject", "body")

        assert result.status == "sent"
        assert result.reason == "smtp_accepted"
        server.send_message.assert_called_once()
        server.quit.assert_not_called()

    @pytest.mark.usefixtures("smtp_on")
    def test_message_construction_failure_is_caught_by_the_no_raise_backstop(self):
        """A message that fails to construct (e.g. a header-injection
        subject) never reaches `smtplib.SMTP` at all, and is classified as a
        temporary failure by the same backstop that catches unexpected
        exceptions — `send_email` never raises regardless of which stage
        fails."""
        with patch(_SMTP_PATCH_TARGET) as smtp:
            result = send_email("alice@uzh.ch", "subject\nInjected: header", "body")

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
            result = send_email("alice@uzh.ch", "subject", "body")

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
            result = send_email("alice@uzh.ch", "subject", "body")

        assert result.status == "sent"
        server.login.assert_not_called()


class TestDevelopmentMailbox:
    """Disabled SMTP (the test-environment default) saves to a private mailbox."""

    def test_disabled_smtp_saves_usable_private_message_without_logging_body(
        self, caplog, tmp_path, monkeypatch
    ):
        """With SMTP disabled, the full message is saved atomically to a
        0700 mailbox directory as a 0600 `.eml` file usable by the
        copy-the-link dev affordance, while the action link never reaches
        the application log.
        """
        mailbox = tmp_path / "mailbox"
        monkeypatch.setattr(settings, "dev_mailbox_dir", str(mailbox))
        body = "Click here: http://127.0.0.1:5000/reset-password/tok-abc123"
        with patch(_SMTP_PATCH_TARGET) as smtp, caplog.at_level(logging.DEBUG):
            result = send_email("alice@uzh.ch", "Reset", body)
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
        """Outside development, disabled SMTP is a temporary failure and
        never falls back to the private mailbox — that fallback exists only
        to make the local developer experience usable without a real relay,
        never as a substitute delivery path in staging or production."""
        monkeypatch.setattr(settings, "env_state", environment)
        monkeypatch.setattr(settings, "smtp_enabled", False)
        monkeypatch.setattr(settings, "dev_mailbox_dir", str(tmp_path / "mailbox"))
        result = send_email("a@example.org", "subject", "body")
        assert result.status == "temporary_failure"
        assert result.reason == "smtp_disabled"
        assert not (tmp_path / "mailbox").exists()

    def test_mailbox_write_failure_does_not_report_delivery_success(self, monkeypatch, tmp_path):
        """A mailbox directory that fails the private-directory check (here:
        pre-existing with permissive 0755 permissions) must be reported as a
        temporary failure, never as `sent` — a silently swallowed write
        failure would look like a delivered password reset or verification
        email that the recipient never gets."""
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
        """A non-sent `DeliveryResult` makes `_send_security_email` emit an
        audit-channel 'security_email_failed' record carrying the
        email_type tag and a keyed recipient_hash — and never the raw
        address (SIEM operators must not be able to harvest addresses from
        logs).
        """
        raw_email = "victim@uzh.ch"
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
        # The raw address must not leak through ANY field of the record.
        for key, value in vars(record).items():
            assert raw_email not in str(value), f"raw email leaked via record.{key}"

    def test_success_emits_no_audit_error(self, caplog):
        """A sent `DeliveryResult` passes through unchanged and stays silent
        on the audit channel (no false alarms for the SIEM to page on) —
        the positive control for the failure case above.
        """
        sent = email_module.DeliveryResult(status="sent", reason="smtp_accepted")
        with (
            patch("app.services.email.send_email", autospec=True) as send_mock,
            caplog.at_level(logging.ERROR, logger="audit"),
        ):
            send_mock.return_value = sent
            result = _send_security_email("password_reset", "a@uzh.ch", "s", "b")

        assert result.status == "sent"
        assert [r for r in caplog.records if r.name == "audit"] == []


class TestMessageBuilders:
    """Builder bodies carry their link, absolute expiry, and scoped recipient."""

    def test_password_reset_email_body_has_link_and_absolute_expiry(self):
        """The rendered reset email contains its link and signed expiry."""
        link = "http://127.0.0.1:5000/reset-password/tok-xyz789"

        email = build_password_reset_email(
            "alice@uzh.ch",
            link,
            expires_at=datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        )

        assert email.message_type == "password_reset"
        assert email.recipient == "alice@uzh.ch"
        assert "Password Reset" in email.subject
        assert link in email.body
        assert "expires at 2030-01-01 12:00:00 UTC" in email.body
        assert "expires in" not in email.body

    def test_duplicate_registration_notice_only_to_existing_address(self):
        """The notice targets only the already-registered address — the
        single designed channel that confirms account existence.
        """
        email = build_duplicate_registration_notice("existing@uzh.ch")

        assert email.message_type == "duplicate_registration_notice"
        assert email.recipient == "existing@uzh.ch"
        assert "already have an account" in email.subject
        assert f"{settings.public_base_url}/login" in email.body
        assert f"{settings.public_base_url}/forgot-password" in email.body

    def test_verification_email_body_has_link_expiry_and_reaper_notice(self):
        """The rendered verification email contains all operational details."""
        link = "https://archive.example/verify-email/tok123"

        email = build_verification_email(
            "newcomer@uzh.ch",
            link,
            expires_at=datetime(2030, 1, 1, 12, 0, tzinfo=UTC),
        )

        assert email.message_type == "email_verification"
        assert email.recipient == "newcomer@uzh.ch"
        assert "Verify your email" in email.subject
        assert link in email.body
        assert "expires at 2030-01-01 12:00:00 UTC" in email.body
        assert "expires in" not in email.body
        assert str(settings.unverified_reap_after_days) in email.body


class TestAddressNormalization:
    """`normalize_email` — the single normalization point for stored addresses.

    Pins `app.services.email_utils.normalize_email`, the helper that
    registration, password-reset and login now all call instead of each
    carrying its own inline `email_validator.validate_email(...)` block.
    Its whole reason to exist is that `.strip().lower()` is NOT a safe
    stand-in: `email_validator` also does Unicode normalization (NFC) on the
    local/domain parts, so two visually identical addresses typed in
    different Unicode forms must collapse to the same stored/looked-up
    string. Losing that behavior in a future simplification would silently
    reopen a bug where a user who registers with one Unicode form of their
    address and later logs in with an equally valid other form gets
    rejected, because a naive lowercase-only comparison sees two different
    strings.

    Pure unit tier: no DB, no client, no network — `check_deliverability=False`
    keeps `email_validator` fully offline.
    """

    def test_valid_mixed_case_address_is_lowercased_and_normalized(self):
        """A syntactically valid, mixed-case address comes back fully
        lowercased. This is the common case every registration/login
        submission hits; losing the casing rule would make email-based
        lookups miss on any address that wasn't already all-lowercase in
        storage.
        """
        assert normalize_email("User@Example.COM") == "user@example.com"

    def test_invalid_input_returns_none_never_raises(self):
        """Syntactically invalid input yields None, never a raised exception.

        Every caller (register/login/password-reset) treats None as "reject
        the form input" without a try/except of its own, so a raised
        EmailNotValidError here would surface as an unhandled 500 at each
        call site.

        Positive control: "not-an-email" (no @) and "" (empty) are
        unambiguous garbage. "a@b" is a domain-shape negative — verified by
        running the helper directly against the installed email_validator:
        it rejects a single-label domain (no dot, so no discoverable TLD)
        with EmailNotValidError, distinct from "a@b.c" which email_validator
        DOES accept (single-character TLDs are syntactically legal) and is
        used below as that assertion's positive control.
        """
        assert normalize_email("not-an-email") is None
        assert normalize_email("") is None
        assert normalize_email("a@b") is None
        # Positive control: same shape, minimal-but-present TLD label -> valid.
        assert normalize_email("a@b.c") == "a@b.c"

    def test_idn_unicode_forms_normalize_to_the_same_stable_string(self):
        """NFC and NFD spellings of the same Unicode email collapse identically.

        This is the concrete case that justifies the helper's existence over
        plain `.strip().lower()`: the letter a-with-diaeresis can be encoded
        either as one precomposed codepoint (NFC) or as "a" plus a separate
        combining-diaeresis codepoint (NFD). Both spellings are the same
        email address to a human and to any mail system, but `str.lower()`
        alone would leave them as two different Python strings, breaking a
        DB lookup keyed on the stored (registration) form when a user later
        logs in with the other form.

        The two input forms are built via unicodedata.normalize rather than
        typed as two source literals: a source file (and most tools in a
        write pipeline) can silently coerce typed Unicode to one canonical
        form, which would make "two forms" collapse into the same string by
        accident and defeat the point of the test.

        Expected value computed by running normalize_email() directly
        against the installed email_validator (not asserted structurally) so
        this test pins the actual behavior of the dependency, not an
        assumption about it; a dependency upgrade that changes the
        normalized form will legitimately fail this test and must be
        re-verified deliberately.
        """
        base = "u@exämple.com"  # domain contains a-with-diaeresis
        nfc_form = unicodedata.normalize("NFC", base)  # precomposed ä
        nfd_form = unicodedata.normalize("NFD", base)  # "a" + combining ̈
        assert nfc_form != nfd_form  # distinct Python strings going in

        expected = "u@exämple.com"  # verified: email_validator's NFC output
        assert normalize_email(nfc_form) == expected
        assert normalize_email(nfd_form) == expected

    def test_idempotent_for_a_valid_address(self):
        """Re-normalizing an already-normalized address is a no-op.

        Callers may pass a value through the helper more than once across a
        multi-step flow (e.g. validate on submit, then again on confirm);
        the helper must be a stable fixed point, not something that keeps
        mutating its own output.
        """
        raw = "User@Example.COM"
        once = normalize_email(raw)
        twice = normalize_email(once)
        assert once == twice == "user@example.com"

    def test_reexport_from_services_package_is_the_same_object(self):
        """`app.services.normalize_email` is the identical function object as
        `app.services.email_utils.normalize_email`, not a copy or wrapper.

        Callers import it via `from app.services import normalize_email`,
        and a future refactor that shadows/rebinds the name at the package
        level (rather than re-exporting the real thing) would desync
        behavior between the two import paths without any test noticing
        unless identity is checked directly.
        """
        assert reexported_normalize_email is normalize_email
