"""Pure feed configuration and explicit credential preparation, without transport."""

import base64
import hashlib
import subprocess
import sys
import traceback
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest
from pydantic import SecretBytes, SecretStr, ValidationError

from app.paths import PROJECT_ROOT
from app.sources import JsonFeedConfig, JsonFeedCredentials, prepare_json_feed_startup

_BEARER = "kR9vT2xW7pL4qN8mZ3cB6fH1jD5gS0aY4eU9iO2wQ7rM5tK8"
_KEY_BYTES = hashlib.sha256(b"synthetic feed signing material one").digest()
_KEY = base64.urlsafe_b64encode(_KEY_BYTES).decode("ascii").rstrip("=")
_OTHER_KEY = (
    base64.urlsafe_b64encode(hashlib.sha256(b"synthetic feed signing material two").digest())
    .decode("ascii")
    .rstrip("=")
)
_BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_NONCANONICAL_KEY = _KEY[:-1] + _BASE64URL[_BASE64URL.index(_KEY[-1]) + 1]
_LIMITS = {
    "max_page_bytes": 1_048_576,
    "max_total_bytes": 8_388_608,
    "max_record_bytes": 65_536,
    "max_records": 10_000,
    "max_pages": 100,
    "max_result_bytes": 16_777_216,
    "fetch_deadline_seconds": 120,
}


def _config(**changes: object) -> JsonFeedConfig:
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


def _environment(**changes: str) -> dict[str, str]:
    """Return synthetic bearer/signing variables with explicit overrides."""
    return {"FEED_BEARER": _BEARER, "FEED_SIGNING_KEY": _KEY, **changes}


def test_profile_defaults_and_frozen_configuration():
    """Profile defaults and frozen configuration."""
    config = _config()
    assert config.adapter == "json_feed"
    assert config.max_visibility == "vetted" and config.requires_record_tier is True
    assert config.max_project_title_chars == 4096
    assert {field: getattr(config, field) for field in _LIMITS} == _LIMITS
    with pytest.raises(ValidationError):
        config.endpoint = "https://changed.example.edu/feed"


@pytest.mark.parametrize("field,maximum", _LIMITS.items())
@pytest.mark.parametrize("invalid", [0, -1, True, "1", 1.0])
def test_budgets_are_strict_positive_integers(field, maximum, invalid):
    """Budgets are strict positive integers."""
    with pytest.raises(ValidationError):
        _config(**{field: invalid})
    with pytest.raises(ValidationError):
        _config(**{field: maximum + 1})


def test_each_budget_can_be_tightened_independently():
    """Each budget can be tightened independently."""
    for field in _LIMITS:
        assert getattr(_config(**{field: 1}), field) == 1


@pytest.mark.parametrize("maximum", [1, 4096, 16384])
def test_project_title_limit_can_be_selected_within_the_wire_ceiling(maximum):
    """Accept explicit project-title character caps without changing other budgets."""
    config = _config(max_project_title_chars=maximum)
    assert config.max_project_title_chars == maximum
    assert {field: getattr(config, field) for field in _LIMITS} == _LIMITS


@pytest.mark.parametrize("invalid", [0, -1, True, "4096", 4096.0, 16385])
def test_project_title_limit_rejects_coercion_and_out_of_range_values(invalid):
    """Require an exact integer cap in 1..16384 characters."""
    with pytest.raises(ValidationError):
        _config(max_project_title_chars=invalid)


@pytest.mark.parametrize(
    "changes",
    [
        {"requires_record_tier": False},
        {"requires_record_tier": 1},
        {"requires_record_tier": "true"},
        {"credential_env": "FEED_SIGNING_KEY"},
        {"bearer_token": _BEARER},
        {"signing_key": _KEY},
    ],
)
def test_tier_requirement_separate_references_and_reference_only_input(changes):
    """Tier requirement separate references and reference only input."""
    with pytest.raises(ValidationError):
        _config(**changes)


@pytest.mark.parametrize("field", ["credential_env", "signing_key_env"])
@pytest.mark.parametrize(
    "value", ["", "lower_case", "HAS-DASH", "1FIRST", "WITH SPACE", "A\n", "É", "A" * 129]
)
def test_environment_references_are_bounded_uppercase_ascii_names(field, value):
    """Environment references are bounded uppercase ascii names."""
    with pytest.raises(ValidationError):
        _config(**{field: value})


@pytest.mark.parametrize("field", ["endpoint", "credential_env", "signing_key_env"])
def test_connection_fields_are_required(field):
    """Connection fields are required."""
    values = _config().model_dump()
    del values[field]
    with pytest.raises(ValidationError):
        JsonFeedConfig.model_validate(values)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://archive.example.edu/feed",
        "/feed",
        "https://",
        "https://user:private-canary@archive.example.edu/feed",
        "https://archive.example.edu/feed?",
        "https://archive.example.edu/feed#",
        "https://archive.example.edu/feed?cursor=one",
        " https://archive.example.edu/feed",
        "https://archive.example.edu/feed\n",
        "https://archive.example.edu/a b",
        "https://archive.example.edu/a\\b",
        "https://archive.example.edu/a\x00b",
        "https://archive.example.edu:0/feed",
        "https://archive.example.edu:65536/feed",
        "https://archive.example.edu:notaport/feed",
        "https://[broken/feed",
        "https://bad_host.example.edu/feed",
        "https://archive.example.edu/" + "x" * 2048,
    ],
)
def test_endpoint_is_strict_absolute_https_without_url_credentials_or_query(endpoint):
    """Endpoint is strict absolute HTTPS without URL credentials or query."""
    with pytest.raises(ValidationError) as error:
        _config(endpoint=endpoint)
    assert "private-canary" not in str(error.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://Archive.Example.EDU:443/feed/%2Fpath",
        "https://éxample.edu/feed",
        "https://[2001:db8::1]/feed",
    ],
)
def test_endpoint_is_not_rewritten_and_validation_has_no_network_effects(endpoint):
    """Endpoint is not rewritten and validation has no network effects."""
    with patch("socket.getaddrinfo", autospec=True) as resolve:
        config = _config(endpoint=endpoint)
        prepared = prepare_json_feed_startup(
            [config], environment="staging", environ=_environment()
        )
    assert config.endpoint == endpoint and prepared[0].source_name == config.name
    resolve.assert_not_called()


def test_prepared_credentials_are_immutable_secret_values_and_inputs_are_unchanged():
    """Prepared credentials are immutable secret values and inputs are unchanged."""
    config = _config()
    before = config.model_dump()
    environment = _environment()
    snapshot = dict(environment)
    prepared = prepare_json_feed_startup([config], environment="production", environ=environment)
    assert isinstance(prepared, tuple) and len(prepared) == 1
    credential = prepared[0]
    assert isinstance(credential, JsonFeedCredentials)
    assert credential.source_name == config.name
    assert isinstance(credential.bearer_token, SecretStr)
    assert isinstance(credential.signing_key, SecretBytes)
    assert credential.bearer_token.get_secret_value() == _BEARER
    assert credential.signing_key.get_secret_value() == _KEY_BYTES
    assert _BEARER not in repr(credential) and _KEY not in repr(credential)
    assert repr(_KEY_BYTES) not in repr(credential)
    with pytest.raises(FrozenInstanceError):
        credential.source_name = "changed"
    assert config.model_dump() == before and environment == snapshot
    environment["FEED_BEARER"] = "changed"
    assert credential.bearer_token.get_secret_value() == _BEARER


class _UnreadableEnvironment(Mapping[str, str]):
    """Represent an empty environment that fails if a value is read."""

    def __getitem__(self, key: str) -> str:
        """Fail if credential values are read before configuration validation."""
        raise AssertionError("Environment was read before configuration validation")

    def __iter__(self) -> Iterator[str]:
        """Iterate no environment variable names."""
        return iter(())

    def __len__(self) -> int:
        """Report an empty environment."""
        return 0


@pytest.mark.parametrize(
    "case",
    [
        "environment",
        "duplicate_name",
        "copied_endpoint",
        "copied_tier",
        "copied_budget",
        "placeholder",
        "shared_key_ref",
        "cross_role_ref",
    ],
)
def test_entire_configuration_batch_is_revalidated_before_secret_reads(case):
    """Entire configuration batch is revalidated before secret reads."""
    configs = [_config()]
    environment = "production"
    if case == "environment":
        environment = "unknown"
    elif case == "duplicate_name":
        configs.append(_config())
    elif case.startswith("copied_"):
        field, value = {
            "copied_endpoint": ("endpoint", "http://unsafe.example.edu/feed"),
            "copied_tier": ("requires_record_tier", False),
            "copied_budget": ("max_pages", 0),
        }[case]
        configs.append(_config(name="second_archive").model_copy(update={field: value}))
    elif case == "placeholder":
        configs.append(_config(name="second_archive", endpoint="https://archive.example.org/feed"))
    elif case == "shared_key_ref":
        configs.append(_config(name="second_archive", credential_env="SECOND_BEARER"))
    else:
        configs.append(
            _config(
                name="second_archive", signing_key_env="FEED_BEARER", credential_env="SECOND_BEARER"
            )
        )
    with pytest.raises(ValueError):
        prepare_json_feed_startup(
            configs, environment=environment, environ=_UnreadableEnvironment()
        )


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_hardened_environments_reject_placeholder_hosts(environment):
    """Hardened environments reject placeholder hosts."""
    for host in (
        "example.com",
        "ARCHIVE.EXAMPLE.NET.",
        "archive.invalid",
        "archive.localhost",
        "archive.example。org",
    ):
        with pytest.raises(ValueError):
            prepare_json_feed_startup(
                [_config(endpoint=f"https://{host}/feed")],
                environment=environment,
                environ=_UnreadableEnvironment(),
            )


def test_dev_allows_placeholder_https_and_empty_batches_are_valid():
    """Dev allows placeholder HTTPS and empty batches are valid."""
    assert prepare_json_feed_startup([], environment="dev", environ={}) == ()
    assert prepare_json_feed_startup(
        [_config(endpoint="https://archive.example.org/feed")],
        environment="dev",
        environ=_environment(),
    )


@pytest.mark.parametrize("field", ["FEED_BEARER", "FEED_SIGNING_KEY"])
def test_missing_credentials_use_only_the_explicit_mapping(monkeypatch, field):
    """Missing credentials use only the explicit mapping."""
    monkeypatch.setenv(field, _BEARER if field == "FEED_BEARER" else _KEY)
    environment = _environment()
    del environment[field]
    with pytest.raises(ValueError):
        prepare_json_feed_startup([_config()], environment="dev", environ=environment)


@pytest.mark.parametrize("field", ["FEED_BEARER", "FEED_SIGNING_KEY"])
@pytest.mark.parametrize("value", [None, 1, True, b"bytes-are-not-environment-text"])
def test_environment_values_are_not_coerced(field, value):
    """Environment values are not coerced."""
    environment = {**_environment(), field: value}
    with pytest.raises((TypeError, ValueError)):
        prepare_json_feed_startup([_config()], environment="dev", environ=environment)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 50,
        "password" + _BEARER,
        _BEARER + "\r\nInjected: yes",
        " " + _BEARER,
        _BEARER + "é",
        _BEARER + "=middle",
        _BEARER * 6,
    ],
)
def test_bearer_rejects_weak_non_rfc6750_or_unbounded_values(value, caplog):
    """Bearer rejects weak non rfc6750 or unbounded values."""
    with pytest.raises(ValueError) as error:
        prepare_json_feed_startup(
            [_config()], environment="dev", environ=_environment(FEED_BEARER=value)
        )
    rendered = "".join(traceback.format_exception(error.value))
    assert _BEARER not in rendered and "FEED_BEARER" not in str(error.value)
    assert not caplog.records


@pytest.mark.parametrize("suffix", ["", "=", "=="])
def test_bearer_accepts_rfc6750_alphabet_and_trailing_padding(suffix):
    """Bearer accepts rfc6750 alphabet and trailing padding."""
    bearer = _BEARER + "+/.~_-" + suffix
    prepared = prepare_json_feed_startup(
        [_config()], environment="dev", environ=_environment(FEED_BEARER=bearer)
    )
    assert prepared[0].bearer_token.get_secret_value() == bearer


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a" * 43,
        "A" * 43,
        _KEY + "=",
        _KEY[:-1],
        _KEY + "x",
        _KEY + "\n",
        _NONCANONICAL_KEY,
        "+" + _KEY[1:],
        _KEY[:-1] + "!",
    ],
)
def test_signing_key_requires_strong_canonical_unpadded_32_byte_base64url(value, caplog):
    """Signing key requires strong canonical unpadded 32 byte base64url."""
    with pytest.raises(ValueError) as error:
        prepare_json_feed_startup(
            [_config()], environment="dev", environ=_environment(FEED_SIGNING_KEY=value)
        )
    assert _KEY not in "".join(traceback.format_exception(error.value))
    assert "FEED_SIGNING_KEY" not in str(error.value) and not caplog.records


def test_shared_bearer_is_allowed_but_signing_keys_are_unique_and_role_separated():
    """Shared bearer is allowed but signing keys are unique and role separated."""
    configs = [_config(), _config(name="second_archive", signing_key_env="SECOND_SIGNING_KEY")]
    environment = _environment(SECOND_SIGNING_KEY=_OTHER_KEY)
    assert [
        item.source_name
        for item in prepare_json_feed_startup(configs, environment="dev", environ=environment)
    ] == ["private_archive", "second_archive"]
    for replacement in (_KEY, _BEARER):
        environment["SECOND_SIGNING_KEY"] = replacement
        with pytest.raises(ValueError):
            prepare_json_feed_startup(configs, environment="dev", environ=environment)
    environment = _environment(FEED_BEARER=_OTHER_KEY, SECOND_SIGNING_KEY=_OTHER_KEY)
    with pytest.raises(ValueError):
        prepare_json_feed_startup(configs, environment="dev", environ=environment)
    # A standard-base64 spelling and padding must not disguise bearer/key reuse.
    environment = _environment(FEED_BEARER=base64.b64encode(_KEY_BYTES).decode("ascii"))
    with pytest.raises(ValueError):
        prepare_json_feed_startup([_config()], environment="dev", environ=environment)


def test_pure_import_and_preparation_need_no_runtime_settings_or_environment():
    """Pure import and preparation need no runtime settings or environment."""
    script = f"""
import sys
from app.sources import JsonFeedConfig, prepare_json_feed_startup
config = JsonFeedConfig.model_validate({{
    'name': 'private_archive', 'display': {{'label': 'Private archive'}},
    'endpoint': 'https://archive.example.edu/feed',
    'credential_env': 'FEED_BEARER', 'signing_key_env': 'FEED_SIGNING_KEY',
}})
result = prepare_json_feed_startup([config], environment='production', environ={{
    'FEED_BEARER': {_BEARER!r}, 'FEED_SIGNING_KEY': {_KEY!r},
}})
assert len(result) == 1
assert 'config' not in sys.modules and 'app.services' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PROJECT_ROOT,
        env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
