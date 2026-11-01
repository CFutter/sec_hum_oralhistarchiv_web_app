"""Sign action capabilities and build non-secret landing-page identifiers.

Only the form POST presents the secret capability to the application. Emails
provide a public link and a separate security code to enter into the form;
the public identifier cannot retrieve a token, account details, or authority.
"""

import base64
import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TypedDict

from itsdangerous import URLSafeTimedSerializer

from app.action_token_contract import ACTION_PUBLIC_ID_CHARS
from config import settings

RESET_TOKEN_MAX_AGE_SECONDS = 1800  # 30 minutes
VERIFICATION_TOKEN_MAX_AGE_SECONDS = 86400
EMAIL_CHANGE_TOKEN_MAX_AGE_SECONDS = 3600

_PUBLIC_ID_DOMAIN = b"oralhistarchiv/action-public-id/v1\x00"
_PUBLIC_ID_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{ACTION_PUBLIC_ID_CHARS}}}", re.ASCII)
_ACTION_FLOW_PATHS = frozenset({"/verify-email", "/reset-password", "/account/confirm-email"})


@dataclass(frozen=True, slots=True)
class ActionEmailMetadata:
    """Token hash and timezone-aware signed expiration for an action email."""

    token_hash: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SignedActionToken:
    """One signature domain and lifetime, using the current SECRET_KEY per call.

    Salt separation, nonce generation, signed timestamps and expiry metadata
    are shared by verification, reset and email-change flows. Callers validate
    each flow's payload and current database state separately. Invalid or
    expired signatures propagate the original itsdangerous exception types.
    """

    salt: str
    max_age: int

    def __post_init__(self) -> None:
        """Reject a missing signature domain or a nonpositive/noninteger lifetime."""
        if not isinstance(self.salt, str) or not self.salt.strip():
            raise ValueError("Action-token salt must be a nonempty string")
        if type(self.max_age) is not int or self.max_age <= 0:
            raise ValueError("Action-token lifetime must be a positive integer")

    def issue(self, payload: Mapping[str, object]) -> str:
        """Sign a copied payload with a new nonce, without retaining secret material."""
        signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        return signer.dumps(
            {**payload, "nonce": secrets.token_urlsafe(16)},
            salt=self.salt,
        )

    def loads(self, token: str) -> object:
        """Validate the signature and lifetime without checking or consuming DB state."""
        signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        payload: object = signer.loads(token, salt=self.salt, max_age=self.max_age)
        return payload

    def email_metadata(self, token: str) -> ActionEmailMetadata:
        """Return its storage hash and original signed UTC expiration deadline."""
        signer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        _, issued_at = signer.loads(
            token,
            salt=self.salt,
            max_age=self.max_age,
            return_timestamp=True,
        )
        return ActionEmailMetadata(
            token_hash=hash_token(token),
            expires_at=issued_at + timedelta(seconds=self.max_age),
        )


def action_token_public_id(token: str) -> str:
    """Return a domain-separated non-secret SHA-256 landing identifier.

    Its 43 ASCII characters encode the full digest without padding. The
    token's random nonce makes identifiers unguessable; knowing a digest
    cannot reconstruct the capability or authorize an account action.
    """
    digest = hashlib.sha256(_PUBLIC_ID_DOMAIN + token.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def valid_action_public_id(value: str) -> bool:
    """Accept only the fixed ASCII public-ID shape, including on anonymous GETs."""
    return isinstance(value, str) and _PUBLIC_ID_PATTERN.fullmatch(value) is not None


def action_token_url(flow_path: str, token: str) -> str:
    """Build a relative allowlisted public URL without a query or secret fragment."""
    if flow_path not in _ACTION_FLOW_PATHS:
        raise ValueError("Unknown action-token flow path")
    return f"{flow_path}/{action_token_public_id(token)}"


class EmailUserPayload(TypedDict):
    """Signed account reference: an email string and positive, non-boolean user ID."""

    email: str
    user_id: int


def as_email_user_payload(raw: object) -> EmailUserPayload | None:
    """Return email/user_id from a dict, or None for invalid field types/ID.

    IDs must be positive integers, excluding bool; email syntax is unchecked.
    Extra keys are discarded.
    """
    if not isinstance(raw, dict):
        return None
    email = raw.get("email")
    user_id = raw.get("user_id")
    if (
        not isinstance(email, str)
        or not isinstance(user_id, int)
        or isinstance(user_id, bool)
        or user_id <= 0
    ):
        return None
    return EmailUserPayload(email=email, user_id=user_id)


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a token, for storage in the database."""
    return hashlib.sha256(token.encode()).hexdigest()
