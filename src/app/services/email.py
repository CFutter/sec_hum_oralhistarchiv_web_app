"""Plain-text SMTP delivery and side-effect-free message builders.

SMTP_* settings control transport; the TLS context is built at import
and SMTP_CA_BUNDLE errors propagate then. Disabled SMTP writes complete
messages to DEV_MAILBOX_DIR only in dev; elsewhere it returns failure.
"""

import contextlib
import logging
import os
import smtplib
import ssl
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path
from typing import Literal

from email_validator import validate_email

from config import settings

from .crypto import audit_email_hash
from .email_outbox import OutboundEmail

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("audit")


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Delivery classification; inspect status because truth testing raises TypeError.

    Senders supply stable reason codes and an optional SMTP reply code;
    this dataclass itself does not validate those fields.
    """

    status: Literal["sent", "temporary_failure", "permanent_failure"]
    reason: str
    smtp_code: int | None = None

    def __bool__(self) -> bool:
        """Raise TypeError; callers must inspect status."""
        raise TypeError("Inspect DeliveryResult.status instead of its truth value")


def _format_action_expiry(expires_at: datetime) -> str:
    """Format an aware expiry as YYYY-MM-DD HH:MM:SS UTC; reject naive values with ValueError."""
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("Action expiry must be timezone-aware")

    return expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _send_security_email(
    email_type: str,
    to: str,
    subject: str,
    body: str,
) -> DeliveryResult:
    """Send mail and audit non-sent results with email_type and a recipient hash."""
    result = send_email(to, subject, body)
    if result.status != "sent":
        audit_logger.error(
            "security_email_failed",
            extra={
                "event_type": "security_email_failed",
                "email_type": email_type,
                "recipient_hash": audit_email_hash(to),
                "delivery_status": result.status,
                "delivery_reason": result.reason,
                "smtp_code": result.smtp_code,
            },
        )
    return result


def _build_tls_context() -> ssl.SSLContext:
    """Build verified TLS defaults plus SMTP_CA_BUNDLE; certificate/file errors propagate."""
    ctx = ssl.create_default_context()
    if settings.smtp_ca_bundle:
        ctx.load_verify_locations(cafile=settings.smtp_ca_bundle)
    return ctx


def _maybe_login(server: smtplib.SMTP) -> None:
    """Authenticate when SMTP_USER is set; require its validated SMTP_PASSWORD and propagate SMTP errors."""
    if settings.smtp_user:
        assert settings.smtp_password is not None  # nosec B101  # mypy type-narrowing; non-None guaranteed by validate_smtp_auth_pair, safe to strip under -O
        server.login(settings.smtp_user, settings.smtp_password.get_secret_value())


_TLS_CONTEXT = _build_tls_context()
_SMTP_SEND_TIMEOUT = 15
_SMTP_PERMANENT_FAILURE_FIRST = 500
_SMTP_PERMANENT_FAILURE_LAST = 599


def _save_development_email(to: str, subject: str, body: str) -> DeliveryResult:
    """Atomically write a private .eml under DEV_MAILBOX_DIR.

    Reject symlink or group/world-accessible mailbox directories. OSError
    and ValueError become temporary failures; successful files contain the
    complete message and are reported as sent.
    """
    temporary: Path | None = None
    try:
        mailbox = Path(settings.dev_mailbox_dir)
        mailbox.mkdir(mode=0o700, parents=True, exist_ok=True)
        if mailbox.is_symlink() or mailbox.stat().st_mode & 0o077:
            raise OSError("Development mailbox must be a private directory (0700)")  # noqa: TRY301
        message = EmailMessage()
        message["To"] = to
        message["From"] = settings.smtp_from_address
        message["Subject"] = subject
        message.set_content(body)
        with tempfile.NamedTemporaryFile(dir=mailbox, prefix=".pending-", delete=False) as output:
            temporary = Path(output.name)
            output.write(message.as_bytes())
            output.flush()
            os.fsync(output.fileno())
        final = temporary.with_name(temporary.name.removeprefix(".pending-") + ".eml")
        temporary.replace(final)
        logger.info("Development email saved to %s", final)
        return DeliveryResult(status="sent", reason="development_mailbox_saved")
    except (OSError, ValueError):
        logger.exception("Could not save development email")
        return DeliveryResult(
            status="temporary_failure",
            reason="development_mailbox_write_failed",
        )
    finally:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)


def _recipient_refusal_result(exc: smtplib.SMTPRecipientsRefused) -> DeliveryResult:
    """Classify retained integer reply codes as permanent only when all are 5xx.

    Ignore malformed entries; no retained codes means temporary failure.
    smtp_code is populated only when retained codes agree.
    """
    codes = [
        response[0]
        for response in exc.recipients.values()
        if isinstance(response, tuple) and response and isinstance(response[0], int)
    ]
    smtp_code = codes[0] if len(set(codes)) == 1 else None
    if codes and all(
        _SMTP_PERMANENT_FAILURE_FIRST <= code <= _SMTP_PERMANENT_FAILURE_LAST for code in codes
    ):
        return DeliveryResult(
            status="permanent_failure",
            reason="smtp_recipient_refused_permanent",
            smtp_code=smtp_code,
        )
    return DeliveryResult(
        status="temporary_failure",
        reason="smtp_recipient_refused_temporary",
        smtp_code=smtp_code,
    )


def send_email(to: str, subject: str, body: str) -> DeliveryResult:
    """Synchronously deliver plain text using SMTP_* settings.

    Use STARTTLS when enabled, optional login, and a 15-second socket
    timeout, not a whole-operation deadline. Disabled SMTP saves to the
    private dev mailbox only in dev. Return DeliveryResult: recipient 5xx
    refusals may be permanent; other caught Exceptions are temporary.
    BaseException subclasses propagate. Messages and failures are logged.
    """
    if not settings.smtp_enabled:
        if settings.env_state != "dev":
            logger.error("Email delivery unavailable: SMTP disabled outside development")
            return DeliveryResult(status="temporary_failure", reason="smtp_disabled")
        return _save_development_email(to, subject, body)

    try:
        # Identity stays Unicode-normalized in the database. Use IDNA domains
        # on the wire so ASCII mailboxes do not depend on SMTPUTF8.
        sender = _smtp_address(settings.smtp_from_address)
        recipient = _smtp_address(to)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = Address(display_name=settings.smtp_from_name, addr_spec=sender)
        msg["To"] = recipient
        msg.set_content(body)
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=_SMTP_SEND_TIMEOUT)
        try:
            if settings.smtp_use_tls:
                server.starttls(context=_TLS_CONTEXT)
            _maybe_login(server)
            server.send_message(msg, from_addr=sender, to_addrs=[recipient])
        finally:
            # DATA acceptance is authoritative. No second protocol exchange
            # may overwrite it; transport cleanup never changes the outcome.
            try:
                server.close()
            except Exception:
                logger.warning("SMTP transport cleanup failed", exc_info=True)

        logger.info("Email sent: %s", subject)
        return DeliveryResult(status="sent", reason="smtp_accepted")

    except smtplib.SMTPAuthenticationError as exc:
        logger.exception(
            "smtp_auth_failed",
            extra={
                "event_type": "smtp_auth_failed",
                "smtp_user": settings.smtp_user,
                "smtp_code": exc.smtp_code,
            },
        )
        return DeliveryResult(
            status="temporary_failure",
            reason="smtp_authentication_failed",
            smtp_code=exc.smtp_code,
        )
    except smtplib.SMTPRecipientsRefused as exc:
        logger.exception(
            "smtp_recipient_refused",
            extra={"event_type": "smtp_recipient_refused", "error": str(exc)[:200]},
        )
        return _recipient_refusal_result(exc)
    except smtplib.SMTPResponseException as exc:
        logger.exception(
            "smtp_response_error",
            extra={
                "event_type": "smtp_response_error",
                "smtp_code": exc.smtp_code,
                "error": str(exc)[:200],
            },
        )
        return DeliveryResult(
            status="temporary_failure",
            reason="smtp_response_error",
            smtp_code=exc.smtp_code,
        )
    except smtplib.SMTPException as exc:
        logger.exception(
            "smtp_send_error",
            extra={"event_type": "smtp_send_error", "error": str(exc)[:200]},
        )
        return DeliveryResult(status="temporary_failure", reason="smtp_protocol_error")
    except OSError as exc:
        logger.exception(
            "smtp_transport_error",
            extra={"event_type": "smtp_transport_error", "error": str(exc)[:200]},
        )
        return DeliveryResult(status="temporary_failure", reason="smtp_transport_error")
    except Exception as exc:
        logger.exception(
            "email_unexpected_error",
            extra={"event_type": "email_unexpected_error", "error": str(exc)[:200]},
        )
        return DeliveryResult(status="temporary_failure", reason="email_unexpected_error")


def _smtp_address(address: str) -> str:
    """Validate without DNS delivery checks; return an ASCII domain/address when possible.

    Unicode local parts remain normalized Unicode; invalid addresses raise
    email_validator.EmailNotValidError.
    """
    parsed = validate_email(address, check_deliverability=False)
    # Preserve delivery compatibility for legacy Unicode-local-part rows:
    # smtplib explicitly requires SMTPUTF8 for those envelopes.
    return parsed.ascii_email or parsed.normalized


def send_outbound_email(email: OutboundEmail) -> DeliveryResult:
    """Deliver immediately and audit failures; the caller persists the returned disposition."""
    return _send_security_email(
        email.message_type,
        email.recipient,
        email.subject,
        email.body,
    )


def build_password_reset_email(
    to: str,
    reset_link: str,
    *,
    expires_at: datetime,
) -> OutboundEmail:
    """Build a reset message without sending; naive expires_at raises ValueError."""
    expiry = _format_action_expiry(expires_at)
    subject = "Password Reset — Oral History Archive"

    body = f"""You requested a password reset for your Oral History Archive account.

Click the link below to set a new password:

{reset_link}

This link expires at {expiry} and can only be used once.

If you did not request this, you can safely ignore this email.
Your password will not be changed unless you click the link above.

— Oral History Archive
University of Zurich"""

    return OutboundEmail(
        message_type="password_reset",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_verification_email(
    to: str,
    verification_link: str,
    *,
    expires_at: datetime,
) -> OutboundEmail:
    """Build a verification message without sending; naive expires_at raises ValueError."""
    expiry = _format_action_expiry(expires_at)
    subject = "Verify your email — Oral History Archive"

    body = f"""Welcome to the Oral History Archive.

To complete your registration and set up two-factor authentication,
please verify your email address by clicking the link below:

{verification_link}

This link expires at {expiry}. If you need
a new link after that, you can request one from the login page.

For security, accounts that aren't verified within {settings.unverified_reap_after_days} days are
automatically removed.

If you did not register for this account, you can safely ignore
this email.

— Oral History Archive
University of Zurich"""

    return OutboundEmail(
        message_type="email_verification",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_duplicate_registration_notice(
    to: str,
) -> OutboundEmail:
    """Build an existing-account notice without sending or checking account existence."""
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
    return OutboundEmail(
        message_type="duplicate_registration_notice",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_email_change_verification(
    to: str,
    confirm_link: str,
    *,
    expires_at: datetime,
) -> OutboundEmail:
    """Build a new-address confirmation without sending; naive expires_at raises ValueError."""
    expiry = _format_action_expiry(expires_at)
    subject = "Confirm your new email — Oral History Archive"
    body = f"""You requested to change the email address on your Oral History Archive account to this one.

Click the link below to confirm the change:

{confirm_link}

This link expires at {expiry} and can only be used once.

If you did not request this, you can safely ignore this email.
No change will be made unless you click the link above.

— Oral History Archive
University of Zurich"""

    return OutboundEmail(
        message_type="email_change_verification",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_email_change_notice(
    to: str,
    new_email: str,
) -> OutboundEmail:
    """Build the membership-neutral notice sent to the current address."""
    subject = "Email change requested — Oral History Archive"
    body = f"""A request was received to change the email address on your Oral History Archive account to:

{new_email}

If that address can be used, a confirmation link will be sent there. Your
current email address remains unchanged unless a valid confirmation succeeds.
For privacy, this notice does not say whether the requested address can be used.

If this was NOT you, your account may be compromised. Change your password and
contact us at {settings.contact_email}.

— Oral History Archive
University of Zurich"""

    return OutboundEmail(
        message_type="email_change_notice",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_account_credential_fault_notice(
    to: str,
) -> OutboundEmail:
    """Build a stored-credential failure notice without delivering it."""
    reset_url = f"{settings.public_base_url}/forgot-password"
    subject = "Action needed to access your account — Oral History Archive"
    body = f"""We could not verify the sign-in credentials stored for your Oral History Archive account.

This is a problem on our side, not something you did wrong, and waiting will not resolve it.

To restore access, please set a new password here:

  {reset_url}

That link issues you fresh credentials and restores access immediately.

If you did not attempt to sign in, or you have any concerns, contact us at {settings.contact_email}.

— Oral History Archive
University of Zurich"""

    return OutboundEmail(
        message_type="account_credential_fault_notice",
        recipient=to,
        subject=subject,
        body=body,
    )


def build_account_locked_notice(to: str) -> OutboundEmail:
    """Build an account-lockout notice without delivering it."""
    reset_url = f"{settings.public_base_url}/forgot-password"
    subject = "Your account was locked — Oral History Archive"
    body = f"""Your Oral History Archive account was just locked after too many failed login attempts.

It will unlock automatically in {settings.login_lockout_minutes} minutes — you don't need to do anything to restore access.

If this was you and you've forgotten your password, you can reset it here (resetting also unlocks the account):

  {reset_url}

If this wasn't you, someone may be trying to access your account. The attempts failed and your password still works, but we recommend resetting it as a precaution — and contact us at {settings.contact_email} if you have concerns.

— Oral History Archive
University of Zurich"""
    return OutboundEmail(
        message_type="account_locked_notice",
        recipient=to,
        subject=subject,
        body=body,
    )
