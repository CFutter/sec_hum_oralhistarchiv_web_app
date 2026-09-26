"""Complete Shibboleth logins from proxy-authenticated principals.

Callers authenticate the reverse proxy; this service enforces canonical
attribute shape, configured issuer trust, MFA context, and persisted policy.
"""

from dataclasses import dataclass, field
from typing import Literal

from email_validator import EmailNotValidError, validate_email
from psycopg import sql
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from config import settings

from ..federation_contract import (
    AFFILIATION_MAX_LENGTH,
    AUTHN_CONTEXT_MAX_LENGTH,
    COUNTRY_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    ISSUER_MAX_LENGTH,
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_COUNTRY_HEADER,
    SHIBBOLETH_DISPLAY_NAME_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
    SUBJECT_MAX_LENGTH,
    InvalidFederatedPrincipal,
    exact_security_value,
)
from .db import get_db_cursor
from .federated_session_policy import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    federation_policy_is_current_cur,
)
from .sessions import create_session_cur
from .users import USER_COLUMNS_SQL, User, create_shibboleth_user_cur, parse_user

__all__ = [
    "SHIBBOLETH_AFFILIATION_HEADER",
    "SHIBBOLETH_AUTHN_CONTEXT_HEADER",
    "SHIBBOLETH_COUNTRY_HEADER",
    "SHIBBOLETH_DISPLAY_NAME_HEADER",
    "SHIBBOLETH_INTERNAL_AUTH_HEADER",
    "SHIBBOLETH_ISSUER_HEADER",
    "SHIBBOLETH_MAIL_HEADER",
    "SHIBBOLETH_SUBJECT_HEADER",
    "FederatedLoginFailure",
    "FederatedLoginSuccess",
    "FederatedPrincipal",
    "InvalidFederatedPrincipal",
    "build_federated_principal",
    "finalize_shibboleth_login",
    "is_trusted_federated_principal",
]


@dataclass(frozen=True, slots=True)
class FederatedPrincipal:
    """Normalized attributes from one proxy-authenticated SAML assertion."""

    issuer: str
    subject_id: str
    email: str
    authn_context: str
    display_name: str | None = None
    affiliation: str | None = None
    country: str | None = None


def _normalized_profile_value(value: str | None, *, name: str, max_length: int) -> str | None:
    """Strip an optional profile value, mapping whitespace-only text to None.

    Raise InvalidFederatedPrincipal for non-strings, oversized raw values, or
    nonprintable text (including an empty string).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidFederatedPrincipal(f"{name}:invalid_type")
    if len(value) > max_length:
        raise InvalidFederatedPrincipal(f"{name}:oversized")
    if not value.isprintable():
        raise InvalidFederatedPrincipal(f"{name}:nonprintable")
    normalized = value.strip()
    if not normalized:
        return None
    return normalized


def build_federated_principal(
    *,
    issuer: str,
    subject_id: str,
    email: str,
    authn_context: str,
    display_name: str | None = None,
    affiliation: str | None = None,
    country: str | None = None,
) -> FederatedPrincipal:
    """Validate trusted assertion attributes; raise InvalidFederatedPrincipal.

    Security values must satisfy federation_contract exact-value limits. Email
    is stripped, validated without DNS lookup, and lowercased; optional profile
    values are stripped. Raw length/printability limits apply before stripping.
    This function neither authenticates the proxy nor checks issuer trust/MFA.
    """
    exact_issuer = exact_security_value(
        issuer,
        name="issuer",
        max_length=ISSUER_MAX_LENGTH,
    )
    exact_subject = exact_security_value(
        subject_id,
        name="subject",
        max_length=SUBJECT_MAX_LENGTH,
    )
    exact_authn_context = exact_security_value(
        authn_context,
        name="authn_context",
        max_length=AUTHN_CONTEXT_MAX_LENGTH,
    )

    if not isinstance(email, str):
        raise InvalidFederatedPrincipal("invalid_email")
    if len(email) > EMAIL_MAX_LENGTH or not email.isprintable():
        raise InvalidFederatedPrincipal("invalid_email")
    email_input = email.strip()
    if not email_input:
        raise InvalidFederatedPrincipal("invalid_email")
    try:
        email_info = validate_email(email_input, check_deliverability=False)
    except EmailNotValidError as exc:
        raise InvalidFederatedPrincipal("invalid_email") from exc

    return FederatedPrincipal(
        issuer=exact_issuer,
        subject_id=exact_subject,
        email=email_info.normalized.lower(),
        authn_context=exact_authn_context,
        display_name=_normalized_profile_value(
            display_name,
            name="display_name",
            max_length=DISPLAY_NAME_MAX_LENGTH,
        ),
        affiliation=_normalized_profile_value(
            affiliation,
            name="affiliation",
            max_length=AFFILIATION_MAX_LENGTH,
        ),
        country=_normalized_profile_value(
            country,
            name="country",
            max_length=COUNTRY_MAX_LENGTH,
        ),
    )


def is_trusted_federated_principal(principal: FederatedPrincipal) -> bool:
    """Validate canonical shape, the live gate, MFA, and exact issuer policy."""
    if not settings.shibboleth_enabled or not isinstance(principal, FederatedPrincipal):
        return False
    try:
        canonical = build_federated_principal(
            issuer=principal.issuer,
            subject_id=principal.subject_id,
            email=principal.email,
            authn_context=principal.authn_context,
            display_name=principal.display_name,
            affiliation=principal.affiliation,
            country=principal.country,
        )
    except InvalidFederatedPrincipal:
        return False

    return (
        canonical == principal
        and principal.authn_context == REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
        and principal.issuer in settings.shibboleth_trusted_issuers
    )


@dataclass(frozen=True, slots=True)
class FederatedLoginSuccess:
    """Committed federated login with the user and raw full-session token."""

    user: User
    session_id: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class FederatedLoginFailure:
    """Expected rejection, with the account only for inactive_account."""

    reason: Literal["account_conflict", "inactive_account", "untrusted_assertion"]
    user: User | None = None


async def finalize_shibboleth_login(
    pool: AsyncConnectionPool,
    *,
    principal: FederatedPrincipal,
    ip_address: str,
) -> FederatedLoginSuccess | FederatedLoginFailure:
    """Recheck trusted policy and atomically update an identity and full session.

    The caller must authenticate the proxy. A new identity is inactive, public,
    and unverified pending review; it receives no session. Inactive/unapproved
    identities return inactive_account without profile refresh; an email
    collision returns account_conflict. Active approved identities refresh
    profile/last_login and receive a SESSION_MAX_AGE_SECONDS token. Policy
    mismatch returns untrusted_assertion. Other database failures propagate and
    roll back; a disappearing locked identity raises RuntimeError.
    """
    if not is_trusted_federated_principal(principal):
        return FederatedLoginFailure("untrusted_assertion")

    try:
        async with get_db_cursor(pool) as cur:
            if not await federation_policy_is_current_cur(cur):
                return FederatedLoginFailure("untrusted_assertion")
            user = await create_shibboleth_user_cur(
                cur,
                issuer=principal.issuer,
                subject_id=principal.subject_id,
                email=principal.email,
                display_name=principal.display_name,
                affiliation=principal.affiliation,
                country=principal.country,
            )
            if user is None or user.auth_method != "shibboleth":
                return FederatedLoginFailure("account_conflict")
            if not user.is_active or user.federated_status != "approved":
                return FederatedLoginFailure("inactive_account", user)
            await cur.execute(
                sql.SQL("""UPDATE users SET last_login = clock_timestamp()
                           WHERE id = %s RETURNING {}""").format(USER_COLUMNS_SQL),
                (user.id,),
            )
            row = await cur.fetchone()
            if row is None:
                raise RuntimeError("Federated identity disappeared while locked")
            user = parse_user(row)
            session_id = await create_session_cur(
                cur,
                user_id=user.id,
                ip_address=ip_address,
                purpose="full",
                max_age_seconds=settings.session_max_age_seconds,
            )
    except UniqueViolation as exc:
        if exc.diag.constraint_name != "idx_users_email_lower":
            raise
        return FederatedLoginFailure("account_conflict")
    return FederatedLoginSuccess(user, session_id)
