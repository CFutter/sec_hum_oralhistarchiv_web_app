"""Email service: SMTP send contract, TLS startup probe, message builders.

Backlog §6.1 — all `smtplib.SMTP(...)` constructions must pass a bounded
`timeout=` kwarg (a hung relay would otherwise leak a threadpool slot per
send, unbounded), and `send_email` must NEVER raise: callers (registration,
password reset, lockout notices) must not fail because delivery failed.

Also pinned here:
- auth gating (`_maybe_login`): login only when `smtp_user` is set;
- disabled-SMTP behavior (test-env default): suppressed + logged, dev body
  at DEBUG (the copy-the-link dev affordance);
- `_send_security_email` audit attribution on failure (hashed recipient,
  never the raw address — SIEM-safe);
- `verify_smtp_tls` fail-closed startup probe (RuntimeError with host:port
  and the SMTP_CA_BUNDLE remediation hint);
- builder bodies (reset link + expiry minutes; duplicate-registration notice
  goes ONLY to the existing address — the designed enumeration channel).

Pure unit tests: no DB, no client, no real SMTP. `smtplib.SMTP` is patched
in the email module's namespace.
"""
import logging
import smtplib
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

import app.services.email as email_module
from app.services.crypto import audit_email_hash
from app.services.email import (
    _send_security_email,
    send_duplicate_registration_notice,
    send_email,
    send_password_reset_email,
    verify_smtp_tls,
)
from config import settings

_SMTP_PATCH_TARGET = "app.services.email.smtplib.SMTP"


def _make_smtp_mock():
    """MagicMock standing in for smtplib.SMTP used as a context manager.

    Returns (smtp_class_mock, server_mock) where server_mock is what the
    `with smtplib.SMTP(...) as server:` block sees.
    """
    smtp_cls = MagicMock(name="SMTP")
    server = smtp_cls.return_value.__enter__.return_value
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


# ---------------------------------------------------------------------------
# §6.1 — bounded timeout on every SMTP construction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("use_tls", [True, False], ids=["tls", "plain"])
def test_send_email_passes_bounded_timeout_kwarg(smtp_on, monkeypatch, use_tls):
    """§6.1: both send branches construct SMTP with timeout=_SMTP_SEND_TIMEOUT
    as a KEYWORD argument; the TLS branch additionally calls starttls with an
    explicit ssl context. Regression: dropping the timeout lets a hung relay
    pin a threadpool slot per send, unbounded.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", use_tls)
    smtp_cls, server = _make_smtp_mock()

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is True

    # Exact-call match: timeout matches only as a kwarg (mock distinguishes
    # positional from keyword), proving the kwarg form the backlog demands.
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


# ---------------------------------------------------------------------------
# never-raises contract (send_email returns False on every failure mode)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "exc",
    [socket.timeout("timed out"), OSError("connection refused")],
    ids=["socket-timeout", "oserror"],
)
def test_send_email_returns_false_when_connect_fails(smtp_on, monkeypatch, exc):
    """§6.1 contract: a socket.timeout/OSError raised while connecting is
    swallowed and send_email returns False — a hung or dead relay must never
    take the caller (e.g. the registration request) down with it.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    smtp_cls = MagicMock(name="SMTP", side_effect=exc)

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is False


def test_send_email_returns_false_and_logs_on_auth_failure(
    smtp_on, monkeypatch, caplog
):
    """SMTPAuthenticationError from login() -> False (never raises) and the
    'smtp_auth_failed' event is logged at ERROR so a broken relay credential
    is visible in ops logs instead of vanishing into a generic failure.
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
        assert send_email("alice@uzh.ch", "subject", "body") is False

    auth_records = [
        r for r in caplog.records if r.getMessage() == "smtp_auth_failed"
    ]
    assert len(auth_records) == 1
    assert auth_records[0].event_type == "smtp_auth_failed"


def test_send_email_returns_false_on_recipients_refused(smtp_on, monkeypatch):
    """SMTPRecipientsRefused from send_message -> False, no raise (the
    never-raises contract covers post-connect failures too).
    """
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    smtp_cls, server = _make_smtp_mock()
    server.send_message.side_effect = smtplib.SMTPRecipientsRefused({})

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is False


def test_send_email_returns_false_on_unexpected_exception(smtp_on, monkeypatch):
    """A completely unexpected exception from the send path is caught by the
    final `except Exception` and returns False — the catch-all backstop of
    the never-raises contract.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    smtp_cls, server = _make_smtp_mock()
    server.send_message.side_effect = Exception("boom")

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is False


# ---------------------------------------------------------------------------
# auth gating (_maybe_login)
# ---------------------------------------------------------------------------

def test_login_called_with_configured_credentials(smtp_on, monkeypatch):
    """smtp_user + smtp_password set -> server.login is called with exactly
    that pair (secret unwrapped). Guards the §6.3-adjacent call site: auth
    must actually be used when configured.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    monkeypatch.setattr(settings, "smtp_user", "mailer")
    monkeypatch.setattr(settings, "smtp_password", SecretStr("s3cret"))
    smtp_cls, server = _make_smtp_mock()

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is True

    server.login.assert_called_once_with("mailer", "s3cret")


def test_login_skipped_when_no_smtp_user(smtp_on, monkeypatch):
    """smtp_user '' (unauthenticated relay) -> login is NOT attempted; a
    spurious login against a no-auth relay would fail every send.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    smtp_cls, server = _make_smtp_mock()

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        assert send_email("alice@uzh.ch", "subject", "body") is True

    server.login.assert_not_called()


# ---------------------------------------------------------------------------
# disabled SMTP (the test-env default)
# ---------------------------------------------------------------------------

def test_disabled_smtp_suppresses_send_and_logs_body_in_dev(caplog):
    """smtp_enabled False (test-env default): send_email returns True without
    constructing SMTP, logs 'Email suppressed' at INFO, and — because
    env_state is 'dev' — logs the body at DEBUG (the copy-the-link dev
    affordance that lets the full reset flow run without a relay).
    """
    assert settings.smtp_enabled is False  # test-env default
    assert settings.env_state == "dev"
    smtp_cls, _ = _make_smtp_mock()
    body = "Click here: http://127.0.0.1:5000/reset-password/tok-abc123"

    with (
        patch(_SMTP_PATCH_TARGET, smtp_cls),
        caplog.at_level(logging.DEBUG, logger="app.services.email"),
    ):
        assert send_email("alice@uzh.ch", "Reset", body) is True

    smtp_cls.assert_not_called()
    suppressed = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "Email suppressed" in r.getMessage()
    ]
    assert len(suppressed) == 1
    debug_bodies = [
        r for r in caplog.records
        if r.levelno == logging.DEBUG and body in r.getMessage()
    ]
    assert len(debug_bodies) == 1


# ---------------------------------------------------------------------------
# _send_security_email — attributed audit event on failure, no raw address
# ---------------------------------------------------------------------------

def test_security_email_failure_emits_hashed_audit_event(caplog):
    """send_email -> False makes _send_security_email emit an audit-channel
    'security_email_failed' record carrying the email_type tag and a keyed
    recipient_hash — and NEVER the raw address (SIEM operators must not be
    able to harvest addresses from logs). Backlog §6.1/§6.2 failure channel.
    """
    raw_email = "victim@uzh.ch"
    with (
        patch(
            "app.services.email.send_email", MagicMock(return_value=False)
        ) as send_mock,
        caplog.at_level(logging.ERROR, logger="audit"),
    ):
        assert _send_security_email("password_reset", raw_email, "s", "b") is False

    send_mock.assert_called_once_with(raw_email, "s", "b")
    audit_records = [
        r for r in caplog.records
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


def test_security_email_success_emits_no_audit_error(caplog):
    """send_email -> True: _send_security_email returns True and stays silent
    on the audit channel (no false alarms for the SIEM to page on).
    """
    with (
        patch("app.services.email.send_email", MagicMock(return_value=True)),
        caplog.at_level(logging.ERROR, logger="audit"),
    ):
        assert _send_security_email("password_reset", "a@uzh.ch", "s", "b") is True

    assert [r for r in caplog.records if r.name == "audit"] == []


# ---------------------------------------------------------------------------
# verify_smtp_tls — fail-closed startup probe
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("enabled", "use_tls"),
    [(False, True), (True, False)],
    ids=["smtp-disabled", "tls-disabled"],
)
def test_verify_smtp_tls_is_noop_when_not_applicable(
    monkeypatch, enabled, use_tls
):
    """SMTP disabled (or TLS disabled): verify_smtp_tls returns without ever
    constructing an SMTP connection — no startup probe against nothing.
    """
    monkeypatch.setattr(settings, "smtp_enabled", enabled)
    monkeypatch.setattr(settings, "smtp_use_tls", use_tls)
    smtp_cls, _ = _make_smtp_mock()

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        verify_smtp_tls()  # must not raise

    smtp_cls.assert_not_called()


def test_verify_smtp_tls_probes_starttls_with_timeout(smtp_on, monkeypatch):
    """Enabled + TLS with a healthy relay: the probe connects with the bounded
    timeout kwarg (§6.1 covers the probe construction too) and exercises
    starttls; no exception escapes.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", True)
    smtp_cls, server = _make_smtp_mock()

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        verify_smtp_tls()  # must not raise

    smtp_cls.assert_called_once_with(
        "relay.test", 2525, timeout=email_module._SMTP_SEND_TIMEOUT
    )
    server.starttls.assert_called_once()
    assert isinstance(server.starttls.call_args.kwargs["context"], ssl.SSLContext)


def test_verify_smtp_tls_failure_raises_actionable_runtime_error(
    smtp_on, monkeypatch
):
    """starttls raising ssl.SSLError -> RuntimeError naming host:port and the
    SMTP_CA_BUNDLE remediation. Fail-closed at startup: a misconfigured relay
    certificate must abort boot, not surface months later as a recovery email
    that silently never arrives.
    """
    monkeypatch.setattr(settings, "smtp_use_tls", True)
    smtp_cls, server = _make_smtp_mock()
    server.starttls.side_effect = ssl.SSLError(1, "certificate verify failed")

    with patch(_SMTP_PATCH_TARGET, smtp_cls):
        with pytest.raises(RuntimeError) as excinfo:
            verify_smtp_tls()

    message = str(excinfo.value)
    assert "relay.test:2525" in message
    assert "SMTP_CA_BUNDLE" in message


# ---------------------------------------------------------------------------
# message builders
# ---------------------------------------------------------------------------

def test_password_reset_email_body_has_link_and_expiry_minutes():
    """The reset email body must contain the actual reset link and the real
    expiry window (RESET_TOKEN_MAX_AGE_SECONDS // 60 minutes) — a stale
    hardcoded number here would lie to users about how long the link lives.
    """
    link = "http://127.0.0.1:5000/reset-password/tok-xyz789"
    with patch(
        "app.services.email.send_email", MagicMock(return_value=True)
    ) as send_mock:
        assert send_password_reset_email("alice@uzh.ch", link) is True

    send_mock.assert_called_once()
    to, subject, body = send_mock.call_args.args
    assert to == "alice@uzh.ch"
    assert "Password Reset" in subject
    assert link in body
    expected_minutes = email_module.RESET_TOKEN_MAX_AGE_SECONDS // 60
    assert f"expires in {expected_minutes} minutes" in body


def test_duplicate_registration_notice_only_to_existing_address():
    """The duplicate-registration notice is the SINGLE designed channel that
    confirms account existence: it must go only to the already-registered
    address and offer both the login and password-reset URLs, so the public
    registration form can stay generic (enumeration-resistant).
    """
    with patch(
        "app.services.email.send_email", MagicMock(return_value=True)
    ) as send_mock:
        assert send_duplicate_registration_notice("existing@uzh.ch") is True

    send_mock.assert_called_once()  # exactly one recipient, no cc/broadcast
    to, subject, body = send_mock.call_args.args
    assert to == "existing@uzh.ch"
    assert "already have an account" in subject
    assert f"{settings.public_base_url}/login" in body
    assert f"{settings.public_base_url}/forgot-password" in body


def test_builders_return_true_when_smtp_disabled():
    """With smtp_enabled False (test-env default) the real, unpatched builder
    path returns True end-to-end: suppressed delivery must not be reported as
    failure, or every dev registration/reset flow would flash errors.
    """
    assert settings.smtp_enabled is False  # test-env default
    assert send_password_reset_email("alice@uzh.ch", "http://x/reset/t") is True
    assert send_duplicate_registration_notice("existing@uzh.ch") is True
