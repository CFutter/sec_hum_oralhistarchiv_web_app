"""Complete Shibboleth logins from proxy-authenticated principals.

Callers authenticate the reverse proxy; this service enforces canonical
attribute shape, configured issuer trust, MFA context, and persisted policy.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from email_validator import EmailNotValidError, validate_email
from psycopg import AsyncCursor, sql
from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from config import settings

from ..federation_contract import (
    AFFILIATION_MAX_LENGTH,
    AUTHN_CONTEXT_MAX_LENGTH,
    COUNTRY_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    ENTITLEMENT_MAX_LENGTH,
    ISSUER_MAX_LENGTH,
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_COUNTRY_HEADER,
    SHIBBOLETH_DISPLAY_NAME_HEADER,
    SHIBBOLETH_ENTITLEMENT_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
    SUBJECT_MAX_LENGTH,
    InvalidFederatedPrincipal,
    exact_security_value,
)
from .crypto import audit_email_hash
from .db import get_db_cursor
from .db_constraints import is_users_email_collision
from .federated_review import record_federated_review_cur
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
    "SHIBBOLETH_ENTITLEMENT_HEADER",
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
    entitlement: str | None = None


def _normalized_profile_value(value: str | None, *, name: str, max_length: int) -> str | None:
    """Strip a bounded printable profile value; return None for absent/blank text.

    Raise InvalidFederatedPrincipal for non-strings, excessive raw length or
    nonprintable characters, including tabs/newlines.
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
    entitlement: str | None = None,
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
        entitlement=_normalized_profile_value(
            entitlement,
            name="entitlement",
            max_length=ENTITLEMENT_MAX_LENGTH,
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
            entitlement=principal.entitlement,
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
    """Revalidate trusted policy and commit provisioning plus any full session.

    New identities are public/inactive/unverified/pending and receive no session.
    An unverified local nonadmin reservation may be deleted with cascading state
    to create a new identity; rows are never merged. Existing active approved
    identities refresh supplied profile values and last_login, then receive a raw
    full-session token. Other identities return inactive_account; conflicting
    addresses return account_conflict and policy mismatch returns untrusted_assertion.
    Reservation audit follows commit; other database failures roll back all writes.
    """
    if not is_trusted_federated_principal(principal):
        return FederatedLoginFailure("untrusted_assertion")

    claim = None
    try:
        async with get_db_cursor(pool) as cur:
            if not await federation_policy_is_current_cur(cur):
                return FederatedLoginFailure("untrusted_assertion")
            user, claim = await _provision_with_reservation_claim_cur(cur, principal)
            if user is None or user.auth_method != "shibboleth":
                return FederatedLoginFailure("account_conflict")
            await record_federated_review_cur(
                cur,
                user_id=user.id,
                issuer=principal.issuer,
                affiliation=principal.affiliation,
                entitlement=principal.entitlement,
            )
            if not user.is_active or user.federated_status != "approved":
                result: FederatedLoginSuccess | FederatedLoginFailure = FederatedLoginFailure(
                    "inactive_account", user
                )
            else:
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
                result = FederatedLoginSuccess(user, session_id)
    except _ReservationClaimRejected:
        return FederatedLoginFailure("account_conflict")
    except UniqueViolation as exc:
        if not is_users_email_collision(exc):
            raise
        return FederatedLoginFailure("account_conflict")
    if claim is not None:
        logging.getLogger("audit").info(
            "federated_email_reservation_claimed",
            extra={
                "event_type": "federated_email_reservation_claimed",
                "removed_user_id": claim.removed_user_id,
                "user_id": user.id,
                "email_hash": claim.email_hash,
                "client_ip": ip_address,
            },
        )
    return result


@dataclass(frozen=True, slots=True)
class _ReservationClaim:
    """Pseudonymous audit data retained until the deletion transaction commits."""

    removed_user_id: int
    email_hash: str


class _ReservationClaimRejected(Exception):
    """Roll back an expected reservation conflict, including any tentative deletion."""


async def _provision_with_reservation_claim_cur(
    cur: AsyncCursor[Any], principal: FederatedPrincipal
) -> tuple[User | None, _ReservationClaim | None]:
    """Try normal provisioning, then replace only a new identity's local reservation.

    The trusted finalizer owns the transaction and has checked persisted policy.
    A savepoint recovers from the original email collision. Existing federated
    identities never claim reservations through this path. The locked local row
    must remain unverified and nonadministrator. A fresh insert, rather than an
    upsert, fences concurrent creation of the same issuer/subject: losing that
    race raises so the outer transaction restores the deleted reservation.
    """
    try:
        async with cur.connection.transaction():
            user = await create_shibboleth_user_cur(
                cur,
                issuer=principal.issuer,
                subject_id=principal.subject_id,
                email=principal.email,
                display_name=principal.display_name,
                affiliation=principal.affiliation,
                country=principal.country,
            )
        return user, None
    except UniqueViolation as exc:
        if not is_users_email_collision(exc):
            raise

    await cur.execute(
        """SELECT id FROM users
           WHERE shibboleth_issuer = %s AND shibboleth_subject_id = %s
           FOR UPDATE""",
        (principal.issuer, principal.subject_id),
    )
    if await cur.fetchone() is not None:
        raise _ReservationClaimRejected
    await cur.execute(
        """SELECT id, email, auth_method, email_verified, is_admin
           FROM users WHERE LOWER(email) = LOWER(%s) FOR UPDATE""",
        (principal.email,),
    )
    reservation = await cur.fetchone()
    if (
        reservation is None
        or reservation["auth_method"] != "local"
        or reservation["email_verified"]
        or reservation["is_admin"]
    ):
        raise _ReservationClaimRejected
    await cur.execute("DELETE FROM users WHERE id = %s", (reservation["id"],))
    if cur.rowcount != 1:
        raise RuntimeError("Locked email reservation disappeared")
    await cur.execute(
        sql.SQL("""INSERT INTO users (
            shibboleth_issuer, shibboleth_subject_id,
            email, display_name, affiliation, country,
            auth_method, access_tier, email_verified, is_active, federated_status
        ) VALUES (%s, %s, %s, %s, %s, %s,
                  'shibboleth', 'public', false, false, 'pending')
        ON CONFLICT ON CONSTRAINT users_shibboleth_identity_key DO NOTHING
        RETURNING {}""").format(USER_COLUMNS_SQL),
        (
            principal.issuer,
            principal.subject_id,
            principal.email,
            principal.display_name,
            principal.affiliation,
            principal.country,
        ),
    )
    row = await cur.fetchone()
    if row is None:
        raise _ReservationClaimRejected
    return parse_user(row), _ReservationClaim(
        removed_user_id=reservation["id"], email_hash=audit_email_hash(reservation["email"])
    )
