"""Email service — generic SMTP sender with typed message builders.

Provides a low-level `send_email()` function and high-level builders
for specific email types (password reset, verification, email change,
duplicate-registration and account-locked notices). All emails are
plain text — no HTML templates needed for transactional messages.

When `smtp_enabled` is False (the default in dev), sending is
suppressed in every environment: the subject is logged at INFO and
send_email() returns True. In dev only, the full body — including any
verification or reset link — is additionally logged at DEBUG, so the
flows can be tested end to end without an SMTP server.
"""
import ssl
import logging
import smtplib
from email.message import EmailMessage
from .password_reset import RESET_TOKEN_MAX_AGE_SECONDS
from .email_verification import VERIFICATION_TOKEN_MAX_AGE_SECONDS
from .email_change import EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS
from .crypto import audit_email_hash

from config import settings
_EMAIL_CHANGE_MAX_AGE_MINUTES = EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS // 60

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")

def _send_security_email(email_type: str, to: str, subject: str, body: str) -> bool:
    """Send a security-relevant email and emit an attributed audit event on failure.
    email_type is a stable tag ('password_reset', 'email_verification', ...) so SIEM
    can alert on a specific broken flow, not just 'SMTP failed'."""
    ok = send_email(to, subject, body)
    if not ok:
        audit_logger.error("security_email_failed", extra={
            "event_type": "security_email_failed",
            "email_type": email_type,
            "recipient_hash": audit_email_hash(to), 
        })
    return ok

def _build_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context() 
    if settings.smtp_ca_bundle:
        ctx.load_verify_locations(cafile=settings.smtp_ca_bundle)
    return ctx

def _maybe_login(server: smtplib.SMTP) -> None:
    if settings.smtp_user:
        # smtp_password is guaranteed non-None by validate_smtp_auth_pair;
        # assert narrows the type for mypy (safe to strip under -O)
        assert settings.smtp_password is not None  # nosec B101  # mypy type-narrowing; non-None guaranteed by validate_smtp_auth_pair, safe to strip under -O
        server.login(settings.smtp_user, settings.smtp_password.get_secret_value())

_TLS_CONTEXT = _build_tls_context()
_SMTP_SEND_TIMEOUT = 15

def verify_smtp_tls() -> None:
    """Exercise STARTTLS + cert verification at startup so a misconfigured relay
    fails here, not silently when a recovery email never arrives."""
    if not settings.smtp_enabled or not settings.smtp_use_tls:
        return
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=_SMTP_SEND_TIMEOUT) as server:
            server.starttls(context=_TLS_CONTEXT)
    except (ssl.SSLError, OSError) as e:
        raise RuntimeError(
            f"SMTP TLS verification failed for {settings.smtp_host}:{settings.smtp_port}: {e}. "
            "Fix the relay certificate, connect by the name on the cert, or set "
            "SMTP_CA_BUNDLE to the issuing CA. Refusing to start with unverifiable mail TLS."
        ) from e

def send_email(to: str, subject: str, body: str) -> bool:
    """Send a plain-text email via SMTP.

    Returns True on success, False on failure. Never raises —
    callers should not fail because email delivery failed.

    When SMTP is disabled (development mode), the email is logged
    at INFO level instead of sent.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Plain-text email body.
    """
    if not settings.smtp_enabled:
        logger.info(
            "Email suppressed (SMTP disabled) — subject: %s", subject
        )
        # link convenience, dev only
        if settings.env_state == "dev":
            logger.debug("Email body:\n%s", body)
        return True

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_address}>"
    msg["To"] = to
    msg.set_content(body)

    try:
        if settings.smtp_use_tls:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=_SMTP_SEND_TIMEOUT) as server:
                server.starttls(context=_TLS_CONTEXT)
                _maybe_login(server)
                server.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=_SMTP_SEND_TIMEOUT) as server:
                _maybe_login(server)
                server.send_message(msg)

        logger.info("Email sent: %s", subject)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("smtp_auth_failed", extra={"event_type": "smtp_auth_failed",
                                                 "smtp_user": settings.smtp_user})
        return False
    except smtplib.SMTPRecipientsRefused as e:
        logger.error("smtp_recipient_refused", extra={"event_type": "smtp_recipient_refused",
                                                "error": str(e)[:200]})
        return False
    except smtplib.SMTPException as e:
        logger.error("smtp_send_error", extra={"event_type": "smtp_send_error",
                                                "error": str(e)[:200]})
        return False
    except Exception as e:
        logger.exception("email_unexpected_error", extra={"event_type": "email_unexpected_error",
                                                "error": str(e)[:200]})
        return False


# =============================================================================
# Message builders
# =============================================================================

def send_password_reset_email(to: str, reset_link: str) -> bool:
    """Send a password reset email with the given link.

    Args:
        to: Recipient email address.
        reset_link: Full URL to the password reset page (e.g., /reset-password/<token>).
    """
    reset_max_age_minutes = RESET_TOKEN_MAX_AGE_SECONDS // 60
    subject = "Password Reset — Oral History Archive"

    body = f"""You requested a password reset for your Oral History Archive account.

Click the link below to set a new password:

{reset_link}

This link expires in {reset_max_age_minutes} minutes and can only be used once.

If you did not request this, you can safely ignore this email.
Your password will not be changed unless you click the link above.

— Oral History Archive
University of Zurich"""

    return _send_security_email("password_reset", to, subject, body)


def send_verification_email(to: str, verification_link: str) -> bool:
    """Send a verification email with the given link.

    Args:
        to: Recipient email address.
        verification_link: Full URL to verify the email (e.g., /verify-email/<token>).
    """
    verification_max_age_hours = VERIFICATION_TOKEN_MAX_AGE_SECONDS // 3600
    subject = "Verify your email — Oral History Archive"

    body = f"""Welcome to the Oral History Archive.

To complete your registration and set up two-factor authentication,
please verify your email address by clicking the link below:

{verification_link}

This link expires in {verification_max_age_hours} hours. If you need
a new link after that, you can request one from the login page.

For security, accounts that aren't verified within {settings.unverified_reap_after_days} days are
automatically removed.

If you did not register for this account, you can safely ignore
this email.

— Oral History Archive
University of Zurich"""

    return _send_security_email("email_verification", to, subject, body)



def send_duplicate_registration_notice(to: str) -> bool:
    """Notify an existing account holder that someone tried to register with their address.

    Sent only to the address that already exists, so it is the single channel that
    confirms account existence — the registration form itself stays generic.
    """
    login_url = f"{settings.public_base_url}/login"
    reset_url = f"{settings.public_base_url}/forgot-password"
    subject = "You already have an account — Oral History Archive"
    body = f"""Someone just tried to register a new Oral History Archive account using this email address.

You already have an account with us, so no new account was created and nothing has changed.

If this was you — perhaps you forgot you'd already signed up — you can log in as usual:

  {login_url}

If you don't remember your password, you can reset it here:

  {reset_url}

If this wasn't you, no action is needed. Your existing account is unaffected, and whoever
entered your address cannot access it. If you have any concerns, contact us at {settings.contact_email}.

— Oral History Archive
University of Zurich"""
    return _send_security_email("duplicate_registration_notice", to, subject, body)



def send_email_change_verification(to: str, confirm_link: str) -> bool:
    """Send the email-change confirmation link to the NEW address.

    Sent only to the new address — clicking the link proves the user
    controls it, which is the whole point of the verification step.
    """
    subject = "Confirm your new email — Oral History Archive"
    body = f"""You requested to change the email address on your Oral History Archive account to this one.

Click the link below to confirm the change:

{confirm_link}

This link expires in {_EMAIL_CHANGE_MAX_AGE_MINUTES} minutes and can only be used once.

If you did not request this, you can safely ignore this email.
No change will be made unless you click the link above.

— Oral History Archive
University of Zurich"""
    return _send_security_email("email_change_verification", to, subject, body)

def send_email_change_notice(to: str, new_email: str) -> bool:
    """Notify the OLD address that a change was requested (security awareness)."""
    subject = "Email change requested — Oral History Archive"
    body = f"""Someone requested to change the email address on your Oral History Archive account to:

{new_email}

If this was you, no action is needed here — confirm the change using the
link sent to the new address.

If this was NOT you, your account may be compromised. Contact us at
{settings.contact_email} and consider changing your password.

— Oral History Archive
University of Zurich"""
    return _send_security_email("email_change_notice", to, subject, body)



def send_account_locked_notice(to: str) -> bool:
    """Notify an account holder that their account was locked after repeated failed logins.

    Sent once, on transition into the locked state, and only to the address that owns
    the account — so it never confirms account existence to an attacker.
    """
    reset_url = f"{settings.public_base_url}/forgot-password"
    subject = "Your account was locked — Oral History Archive"
    body = f"""Your Oral History Archive account was just locked after too many failed login attempts.

It will unlock automatically in {settings.login_lockout_minutes} minutes — you don't need to do anything to restore access.

If this was you and you've forgotten your password, you can reset it here (resetting also unlocks the account):

  {reset_url}

If this wasn't you, someone may be trying to access your account. The attempts failed and your password still works, but we recommend resetting it as a precaution — and contact us at {settings.contact_email} if you have concerns.

— Oral History Archive
University of Zurich"""
    return _send_security_email("account_locked_notice", to, subject, body)



