"""Credential extraction and intentionally different independence policies."""

from dataclasses import fields
from typing import get_args
from urllib.parse import quote

import pytest
from pydantic import SecretStr, ValidationError

from app.middleware import validators
from config.secret_inventory import SecretInventory, collect_secret_inventory
from config.settings import Settings
from tests.unit.settings_builders import base_kwargs, make_settings

_SECRET = "uB8k4Pq7Nw2Yx6Ds9Fm3Ha5Jv1Rc8Tz4Lg7Ke2Qp9Ws6Bn3Xf5Mh8Cy1Vr4Zd7Aa"


def _contains_secret(annotation: object) -> bool:
    """Recognize SecretStr directly or recursively inside generic annotations."""
    return annotation is SecretStr or any(_contains_secret(arg) for arg in get_args(annotation))


def test_every_secret_setting_has_an_inventory_entry():
    """Check every secret setting has an inventory entry."""
    secret_fields = {
        name for name, field in Settings.model_fields.items() if _contains_secret(field.annotation)
    }
    assert {field.name for field in fields(SecretInventory)} == secret_fields


def test_inventory_extracts_url_passwords_and_optional_credentials_without_repr_leaks():
    """Check inventory extracts URL passwords and optional credentials without repr leaks."""
    password = "credential/with:@%encoding"
    encoded = quote(password, safe="")
    configured = make_settings(
        **base_kwargs(
            database_url=f"postgresql://user:{encoded}@localhost/archive",
            redis_url=f"redis://:{encoded}@cache.example.org/0",
            rate_limit_redis_url="redis://:distinct@limiter.example.org/0",
            smtp_user="relay-user",
            smtp_password=password,
        )
    )
    # The inventory still redacts accidentally injected legacy material even
    # though normal Settings construction rejects it.
    configured.admin_seed_password = SecretStr("Seed-password-unique-0123456789")
    inventory = collect_secret_inventory(configured)
    assert inventory.database_url == (password,)
    assert inventory.redis_url == (password,)
    assert inventory.smtp_password == (password,)
    assert inventory.admin_seed_password == ("Seed-password-unique-0123456789",)
    assert inventory.shibboleth_internal_secret == ()
    assert password not in repr(inventory)
    assert configured.database_url.get_secret_value() not in inventory.rate_limiter_peers()


@pytest.mark.parametrize(
    "field_name",
    [
        "secret_key",
        "session_secret",
        "totp_encryption_keys",
        "outbox_encryption_keys",
        "health_detail_token",
    ],
)
def test_federation_construction_and_startup_share_the_same_comparison_policy(
    monkeypatch, field_name
):
    """Check federation construction and startup share the same comparison policy."""
    kwargs = base_kwargs(
        shibboleth_enabled=True,
        shibboleth_internal_secret=_SECRET,
        shibboleth_trusted_issuers=["https://idp.example.org/idp/shibboleth"],
        public_base_url="https://archive.example.org",
        cookies_secure=True,
    )
    configured = make_settings(**kwargs)
    value = [_SECRET] if field_name.endswith("_keys") else _SECRET
    with pytest.raises(ValidationError, match="must not reuse"):
        make_settings(**{**kwargs, field_name: value})
    changed_value = [SecretStr(_SECRET)] if isinstance(value, list) else SecretStr(_SECRET)
    monkeypatch.setattr(configured, field_name, changed_value)
    monkeypatch.setattr(validators, "settings", configured)
    with pytest.raises(RuntimeError, match="must not reuse"):
        validators.validate_security_settings()


def test_policy_exclusions_preserve_existing_deployment_compatibility():
    """Check policy exclusions preserve existing deployment compatibility."""
    configured = make_settings(
        **base_kwargs(
            database_url=f"postgresql://user:{_SECRET}@localhost/archive",
            smtp_user="relay-user",
            smtp_password=_SECRET,
            shibboleth_internal_secret=_SECRET,
            shibboleth_enabled=True,
            shibboleth_trusted_issuers=["https://idp.example.org/idp/shibboleth"],
            public_base_url="https://archive.example.org",
        )
    )
    inventory = collect_secret_inventory(configured)
    assert _SECRET not in inventory.federation_peers()
    assert _SECRET in inventory.rate_limiter_peers()
    smtp_only = make_settings(
        **base_kwargs(
            smtp_user="relay-user",
            smtp_password=_SECRET,
            rate_limit_redis_url=f"redis://:{_SECRET}@limiter.example.org/0",
        )
    )
    assert _SECRET not in collect_secret_inventory(smtp_only).rate_limiter_peers()
