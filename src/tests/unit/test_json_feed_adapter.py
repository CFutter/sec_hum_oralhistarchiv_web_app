"""Strict adapter construction, binding and the complete-worker delegation seam."""

import base64
import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from threading import Event
from unittest.mock import create_autospec, patch

import pytest
from pydantic import SecretBytes, SecretStr

from app.sources import (
    JsonFeedAdapter,
    JsonFeedConfig,
    JsonFeedCredentials,
    SourceConfig,
    SourceDisplay,
    classify_json_feed_access,
    configure_sources,
    prepare_json_feed_startup,
)

_BEARER = "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"
_OTHER_BEARER = "aQ3eT6yU9iP2sD5fG8hJ1kL4zX7cV0bN3mW6rE9tY2uI5oS8"
_KEY = hashlib.sha256(b"feed adapter signing material").digest()
_OTHER_KEY = hashlib.sha256(b"feed adapter other signing material").digest()
_BUDGETS = (
    "max_page_bytes",
    "max_total_bytes",
    "max_record_bytes",
    "max_records",
    "max_pages",
    "max_result_bytes",
    "fetch_deadline_seconds",
)


def _config(**changes):
    """Validate a synthetic feed configuration with explicit overrides."""
    return JsonFeedConfig.model_validate(
        {
            "name": "private_archive",
            "display": {"label": "Private archive"},
            "endpoint": "https://archive.example.edu/feed",
            "credential_env": "FEED_BEARER",
            "signing_key_env": "FEED_SIGNING_KEY",
            **changes,
        }
    )


def _credentials(config, *, bearer=_BEARER, key=_KEY):
    """Prepare development credentials from bearer and raw signing-key bytes."""
    return prepare_json_feed_startup(
        [config],
        environment="dev",
        environ={
            config.credential_env: bearer,
            config.signing_key_env: base64.urlsafe_b64encode(key).decode().rstrip("="),
        },
    )[0]


def _adapter(**changes):
    """Construct an adapter from the overridden configuration and matching credentials."""
    config = _config(**changes)
    return JsonFeedAdapter(config, _credentials(config))


def test_adapter_snapshots_are_frozen_and_secret_safe_without_io(monkeypatch):
    """Adapter snapshots are frozen and secret safe without I/O."""
    config = _config()
    credentials = _credentials(config)
    monkeypatch.setenv(config.credential_env, "unusable ambient value")
    with patch("socket.getaddrinfo", autospec=True) as resolve:
        adapter = JsonFeedAdapter(config, credentials)
        fingerprint = adapter.config_fingerprint()
    assert adapter.config is not config and adapter.credentials is not credentials
    assert adapter.name == config.name
    assert adapter.policy.requires_record_tier is True
    assert adapter.policy.max_visibility == "vetted"
    assert adapter.policy.classify_access is classify_json_feed_access
    assert len(fingerprint) == 64
    assert _BEARER not in repr(adapter) and _KEY.hex() not in repr(adapter)
    with pytest.raises(FrozenInstanceError):
        adapter.config = config
    resolve.assert_not_called()


@pytest.mark.parametrize(
    "raw,expected", [("Public access", "public"), ("Restricted access", "restricted")]
)
def test_reviewed_material_access_labels(raw, expected):
    """Reviewed material access labels."""
    assert classify_json_feed_access(raw) == expected


@pytest.mark.parametrize("raw", [None, True, 1, [], {}])
def test_invalid_material_access_types_fail_before_persistence(raw):
    """Invalid material access types fail before persistence."""
    with pytest.raises(TypeError, match="access label must be text"):
        classify_json_feed_access(raw)


@pytest.mark.parametrize("raw", ["", "public", "Public access ", "PRIVATE-CANARY"])
def test_unreviewed_material_access_labels_fail_without_echo(raw):
    """Unreviewed material access labels fail without echo."""
    with pytest.raises(ValueError) as error:
        classify_json_feed_access(raw)
    assert "PRIVATE-CANARY" not in str(error.value)


@pytest.mark.parametrize(
    "credentials",
    [
        None,
        JsonFeedCredentials("other_source", SecretStr(_BEARER), SecretBytes(_KEY)),
        JsonFeedCredentials("private_archive", SecretStr("invalid"), SecretBytes(_KEY)),
        JsonFeedCredentials("private_archive", SecretStr(_BEARER), SecretBytes(b"bad")),
    ],
)
def test_direct_construction_rejects_missing_mismatched_or_invalid_credentials(credentials):
    """Direct construction rejects missing mismatched or invalid credentials."""
    with pytest.raises((TypeError, ValueError)):
        JsonFeedAdapter(_config(), credentials)


def test_direct_construction_revalidates_forged_configuration_and_exact_model():
    """Direct construction revalidates forged configuration and exact model."""
    config = _config().model_copy(update={"requires_record_tier": False})
    with pytest.raises(ValueError):
        JsonFeedAdapter(
            config, JsonFeedCredentials(config.name, SecretStr(_BEARER), SecretBytes(_KEY))
        )
    with pytest.raises(TypeError, match="requires JsonFeedConfig"):
        JsonFeedAdapter.from_config(
            SourceConfig(name="bare", adapter="json_feed", display=SourceDisplay(label="Bare"))
        )


def test_credential_value_rotation_keeps_binding_and_never_reads_ambient_values():
    """Credential value rotation keeps binding and never reads ambient values."""
    config = _config()
    first = JsonFeedAdapter(config, _credentials(config))
    rotated = JsonFeedAdapter(config, _credentials(config, bearer=_OTHER_BEARER, key=_OTHER_KEY))
    assert first.config_fingerprint() == rotated.config_fingerprint()


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, "147610bd0766414525b808c0db34203c39988554812a9b6e8f8cb65eaf137c57"),
        (
            {"max_visibility": "public"},
            "c3db00f25dbdf921367630787ea853ac4fba0ed73e811992a1c7968ee5b2be7a",
        ),
        (
            {"name": "another_source"},
            "8d39c769206bff54c16fc5dbce1c1e9d5cb406af51e0c90d9af8c613fcf5b748",
        ),
    ],
)
def test_project_title_policy_has_stable_versioned_source_bindings(changes, expected):
    """Pin the revised interpretation and default title cap in the canonical binding."""
    assert _adapter(**changes).config_fingerprint() == expected


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "another_source"},
        {"endpoint": "https://archive.example.edu/another-feed"},
        {"max_visibility": "registered"},
        {"credential_env": "ANOTHER_BEARER"},
        {"signing_key_env": "ANOTHER_SIGNING_KEY"},
        {"max_project_title_chars": 8192},
    ],
)
def test_source_binding_changes_require_a_new_fingerprint(changes):
    """Source binding changes require a new fingerprint."""
    assert _adapter().config_fingerprint() != _adapter(**changes).config_fingerprint()


@pytest.mark.parametrize("field", _BUDGETS)
def test_operational_budgets_do_not_change_interpretation_binding(field):
    """Operational budgets do not change interpretation binding."""
    assert _adapter().config_fingerprint() == _adapter(**{field: 1}).config_fingerprint()


@pytest.mark.parametrize(
    "changes",
    [
        {"display": {"label": "Another label", "sensitivity_badge": "Sensitive"}},
        {"schedule": {"incremental_interval_seconds": 45, "write_timeout_seconds": 30}},
    ],
)
def test_display_and_schedule_do_not_change_interpretation_binding(changes):
    """Display and schedule do not change interpretation binding."""
    assert _adapter().config_fingerprint() == _adapter(**changes).config_fingerprint()


@pytest.mark.parametrize(
    "since", ["2030-01-01T00:00:00Z", 1, datetime(2030, 1, 1, tzinfo=UTC).replace(tzinfo=None)]
)
def test_invalid_caller_boundary_fails_before_worker_import_or_io(since):
    """Invalid caller boundary fails before worker import or I/O."""
    with (
        patch("socket.getaddrinfo", autospec=True) as resolve,
        pytest.raises((TypeError, ValueError)),
    ):
        _adapter().fetch(since=since)
    resolve.assert_not_called()


def test_fetch_normalizes_and_delegates_to_the_real_isolated_boundary(monkeypatch):
    """Fetch normalizes and delegates to the real isolated boundary."""
    from app.sources import json_feed_fetch  # noqa: PLC0415

    real = json_feed_fetch.fetch_json_feed_isolated
    marker = object()
    isolated = create_autospec(real, spec_set=True, return_value=marker)
    monkeypatch.setattr(json_feed_fetch, "fetch_json_feed_isolated", isolated)
    adapter = _adapter()
    local = datetime(2030, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    cancel_event = Event()
    assert adapter.fetch(since=local, cancel_event=cancel_event) is marker
    isolated.assert_called_once_with(
        adapter.config, adapter.credentials, since=local.astimezone(UTC), cancel_event=cancel_event
    )


@pytest.mark.parametrize("failure", ["same_key", "cross_role", "shared_ref_different_value"])
def test_direct_registry_construction_rejects_cross_source_credential_conflicts(failure):
    """Direct registry construction rejects cross source credential conflicts."""
    first = _config()
    second = _config(
        name="another_source", credential_env="OTHER_BEARER", signing_key_env="OTHER_KEY"
    )
    first_credentials = _credentials(first)
    second_credentials = _credentials(second, key=_OTHER_KEY)
    if failure == "same_key":
        second_credentials = replace(second_credentials, signing_key=SecretBytes(_KEY))
    elif failure == "cross_role":
        second_credentials = replace(
            second_credentials,
            bearer_token=SecretStr(base64.urlsafe_b64encode(_KEY).decode().rstrip("=")),
        )
    else:
        second = _config(name="another_source", signing_key_env="OTHER_KEY")
        second_credentials = _credentials(second, bearer=_OTHER_BEARER, key=_OTHER_KEY)
    with pytest.raises(ValueError):
        configure_sources((first, second), credentials=(first_credentials, second_credentials))


def test_reference_separation_is_validated_before_prepared_secret_inspection():
    """Reference separation is validated before prepared secret inspection."""
    first = _config()
    second = _config(name="another_source", credential_env="OTHER_BEARER")
    credentials = (_credentials(first), _credentials(second, key=_OTHER_KEY))
    real_bearer_value = SecretStr.get_secret_value
    real_key_value = SecretBytes.get_secret_value
    with (
        patch.object(
            SecretStr,
            "get_secret_value",
            create_autospec(real_bearer_value, spec_set=True, side_effect=real_bearer_value),
        ) as bearer,
        patch.object(
            SecretBytes,
            "get_secret_value",
            create_autospec(real_key_value, spec_set=True, side_effect=real_key_value),
        ) as key,
        pytest.raises(ValueError, match="references must be unique"),
    ):
        configure_sources((first, second), credentials=credentials)
    bearer.assert_not_called()
    key.assert_not_called()
