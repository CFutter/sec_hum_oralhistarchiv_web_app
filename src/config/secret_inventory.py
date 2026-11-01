"""Explicit secret inventory and the existing credential-independence policies.

Keep credential extraction separate from policy: SMTP and seed passwords are
inventoried, but neither existing comparison policy forbids their reuse. Changing
that policy would reject previously accepted deployments and needs a deliberate
configuration migration.
"""

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import unquote, urlsplit

from pydantic import SecretStr


class SecretSettings(Protocol):
    """Only the secret-bearing settings needed by the pure inventory builder."""

    secret_key: SecretStr
    session_secret: SecretStr
    totp_encryption_keys: list[SecretStr]
    outbox_encryption_keys: list[SecretStr]
    health_detail_token: SecretStr | None
    shibboleth_internal_secret: SecretStr | None
    database_url: SecretStr
    redis_url: SecretStr
    rate_limit_redis_url: SecretStr
    smtp_password: SecretStr | None
    admin_seed_password: SecretStr | None


def _optional_value(value: SecretStr | None) -> tuple[str, ...]:
    """Return the raw secret as a singleton tuple, or () for None."""
    return (value.get_secret_value(),) if value is not None else ()


def _url_password(value: SecretStr) -> tuple[str, ...]:
    """Return the percent-decoded URL password tuple, or (); malformed URLs may raise ValueError."""
    password = urlsplit(value.get_secret_value().strip()).password
    return (unquote(password),) if password else ()


@dataclass(frozen=True, repr=False)
class SecretInventory:
    """One immutable snapshot; repr intentionally never displays secret values."""

    secret_key: tuple[str, ...]
    session_secret: tuple[str, ...]
    totp_encryption_keys: tuple[str, ...]
    outbox_encryption_keys: tuple[str, ...]
    health_detail_token: tuple[str, ...]
    shibboleth_internal_secret: tuple[str, ...]
    database_url: tuple[str, ...]
    redis_url: tuple[str, ...]
    rate_limit_redis_url: tuple[str, ...]
    smtp_password: tuple[str, ...]
    admin_seed_password: tuple[str, ...]

    def federation_peers(self) -> frozenset[str]:
        """Return signing/session/encryption/health secrets; omit URL/SMTP/seed passwords."""
        return frozenset(
            self.secret_key
            + self.session_secret
            + self.totp_encryption_keys
            + self.outbox_encryption_keys
            + self.health_detail_token
        )

    def rate_limiter_peers(self) -> frozenset[str]:
        """Add federation and decoded DB/general-Redis passwords to federation_peers()."""
        return self.federation_peers() | frozenset(
            self.shibboleth_internal_secret + self.database_url + self.redis_url
        )


def collect_secret_inventory(settings: SecretSettings) -> SecretInventory:
    """Snapshot raw configured secrets and decoded URL passwords; URL errors propagate."""
    return SecretInventory(
        secret_key=(settings.secret_key.get_secret_value(),),
        session_secret=(settings.session_secret.get_secret_value(),),
        totp_encryption_keys=tuple(key.get_secret_value() for key in settings.totp_encryption_keys),
        outbox_encryption_keys=tuple(
            key.get_secret_value() for key in settings.outbox_encryption_keys
        ),
        health_detail_token=_optional_value(settings.health_detail_token),
        shibboleth_internal_secret=_optional_value(settings.shibboleth_internal_secret),
        database_url=_url_password(settings.database_url),
        redis_url=_url_password(settings.redis_url),
        rate_limit_redis_url=_url_password(settings.rate_limit_redis_url),
        smtp_password=_optional_value(settings.smtp_password),
        admin_seed_password=_optional_value(settings.admin_seed_password),
    )
