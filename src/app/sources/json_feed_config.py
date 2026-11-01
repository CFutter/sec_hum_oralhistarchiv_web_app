"""Feed descriptions and explicit credential preparation before runtime activation.

No adapter, network request, implicit environment lookup or global settings
import occurs here. Callers supply the mapping for a fresh, secret-safe snapshot.
"""

import base64
import binascii
import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Self

from pydantic import ConfigDict, Field, SecretBytes, SecretStr, field_validator, model_validator

from app.credentials import check_secret_strength
from app.ingestion_contracts import PROJECT_TITLE_MAX_CHARS
from app.url_safety import parse_http_url

from .base import SourceConfig
from .startup import _validate_source_endpoint, _validate_startup_options

_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")
_DNS_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")
_SIGNING_KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_BASE64URL_TRANSLATION = str.maketrans("+/", "-_")
_BEARER_MIN_CHARS = 43
_BEARER_MAX_CHARS = 256
_SIGNING_KEY_BYTES = 32
_BEARER_ERROR = "JSON feed bearer credential is missing or invalid"
_SIGNING_KEY_ERROR = "JSON feed signing key is missing or invalid"
_ENDPOINT_ERROR = "JSON feed endpoint must be a fixed, credential-free absolute HTTPS URL"


def _valid_host(host: str) -> bool:
    """Accept an IP literal or IDNA DNS name; reject IPv6 zone identifiers."""
    if "%" in host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").casefold().rstrip(".")
        except UnicodeError:
            return False
        return _DNS_HOST.fullmatch(ascii_host) is not None
    return True


class JsonFeedConfig(SourceConfig):
    """Strict nonsecret v1 description; budgets may only tighten the profile caps."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )
    adapter: Literal["json_feed"] = "json_feed"
    endpoint: str = Field(min_length=1, max_length=2048)
    credential_env: str = Field(min_length=1, max_length=128)
    signing_key_env: str = Field(min_length=1, max_length=128)
    requires_record_tier: bool = True
    max_project_title_chars: int = Field(default=4096, ge=1, le=PROJECT_TITLE_MAX_CHARS)
    max_page_bytes: int = Field(default=1048576, ge=1, le=1048576)
    max_total_bytes: int = Field(default=8388608, ge=1, le=8388608)
    max_record_bytes: int = Field(default=65536, ge=1, le=65536)
    max_records: int = Field(default=10000, ge=1, le=10000)
    max_pages: int = Field(default=100, ge=1, le=100)
    max_result_bytes: int = Field(default=16777216, ge=1, le=16777216)
    fetch_deadline_seconds: int = Field(default=120, ge=1, le=120)

    @field_validator("endpoint")
    @classmethod
    def fixed_https_endpoint(cls, value: str) -> str:
        """Validate without DNS, trimming, or changing the configured binding."""
        if any(char.isspace() or not char.isprintable() for char in value) or any(
            char in value for char in "\\?#"
        ):
            raise ValueError(_ENDPOINT_ERROR)
        try:
            parsed = parse_http_url(value, require_https=True)
        except ValueError:
            raise ValueError(_ENDPOINT_ERROR) from None
        if parsed.port == 0 or not _valid_host(parsed.hostname or ""):
            raise ValueError(_ENDPOINT_ERROR)
        return value

    @field_validator("credential_env", "signing_key_env")
    @classmethod
    def environment_reference(cls, value: str) -> str:
        """Accept only bounded uppercase ASCII environment-variable names."""
        if _ENV_NAME.fullmatch(value) is None:
            raise ValueError("JSON feed credentials require uppercase environment-variable names")
        return value

    @field_validator("requires_record_tier")
    @classmethod
    def mandatory_record_tier(cls, value: bool) -> bool:
        """Retain strict bool validation and prohibit optional source classification."""
        if not value:
            raise ValueError("JSON feed requires explicit record tiers")
        return value

    @model_validator(mode="after")
    def separate_credential_roles(self) -> Self:
        """A bearer credential and signing key cannot share an environment reference."""
        if self.credential_env == self.signing_key_env:
            raise ValueError("JSON feed credential roles require separate environment references")
        return self


@dataclass(frozen=True, slots=True)
class JsonFeedCredentials:
    """Resolved per-source secrets; neither secret participates in representations."""

    source_name: str
    bearer_token: SecretStr = field(repr=False)
    signing_key: SecretBytes = field(repr=False)


def snapshot_json_feed_credentials(
    config: JsonFeedConfig, credentials: JsonFeedCredentials
) -> JsonFeedCredentials:
    """Revalidate direct construction and return a fresh source-bound snapshot.

    Only explicit values are inspected; this helper never reads the process
    environment, settings or a network endpoint. Cross-source role separation
    remains the responsibility of whole-selection startup preparation.
    """
    if not isinstance(config, JsonFeedConfig):
        raise TypeError("JSON feed credential snapshot requires JsonFeedConfig")
    snapshot = JsonFeedConfig.model_validate(config)
    if not isinstance(credentials, JsonFeedCredentials) or (
        not isinstance(credentials.bearer_token, SecretStr)
        or not isinstance(credentials.signing_key, SecretBytes)
    ):
        raise TypeError("JSON feed requires prepared credentials")
    if credentials.source_name != snapshot.name:
        raise ValueError("JSON feed credentials belong to another source")
    key = credentials.signing_key.get_secret_value()
    if len(key) != _SIGNING_KEY_BYTES:
        raise ValueError(_SIGNING_KEY_ERROR)
    return prepare_json_feed_startup(
        [snapshot],
        environment="dev",
        environ={
            snapshot.credential_env: credentials.bearer_token.get_secret_value(),
            snapshot.signing_key_env: base64.urlsafe_b64encode(key).decode("ascii").rstrip("="),
        },
    )[0]


def _bearer_value(environ: Mapping[str, str], name: str) -> str:
    """Return a strong 43..256-character bearer token; raise TypeError/ValueError if invalid."""
    value = environ.get(name)
    if value is None:
        raise ValueError(_BEARER_ERROR)
    if not isinstance(value, str):
        raise TypeError(_BEARER_ERROR)
    if not _BEARER_MIN_CHARS <= len(value) <= _BEARER_MAX_CHARS or _BEARER.fullmatch(value) is None:
        raise ValueError(_BEARER_ERROR)
    blockers, _ = check_secret_strength(value)
    if blockers:
        raise ValueError(_BEARER_ERROR)
    return value


def _signing_key_value(environ: Mapping[str, str], name: str) -> tuple[str, bytes]:
    """Return canonical unpadded base64url text and its strong 32-byte key.

    Raise TypeError/ValueError for missing or invalid values without echoing secrets.
    """
    value = environ.get(name)
    if value is None:
        raise ValueError(_SIGNING_KEY_ERROR)
    if not isinstance(value, str):
        raise TypeError(_SIGNING_KEY_ERROR)
    if _SIGNING_KEY.fullmatch(value) is None:
        raise ValueError(_SIGNING_KEY_ERROR)
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except binascii.Error:
        raise ValueError(_SIGNING_KEY_ERROR) from None
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != _SIGNING_KEY_BYTES or canonical != value:
        raise ValueError(_SIGNING_KEY_ERROR)
    blockers, _ = check_secret_strength(value)
    if blockers:
        raise ValueError(_SIGNING_KEY_ERROR)
    return value, decoded


def validate_json_feed_configs(
    configs: Sequence[JsonFeedConfig],
    *,
    environment: str,
) -> tuple[JsonFeedConfig, ...]:
    """Validate the whole description/reference set before credential inspection."""
    _validate_startup_options(environment=environment, allow_fixture=False)
    snapshots: list[JsonFeedConfig] = []
    names: set[str] = set()
    key_refs: set[str] = set()
    for config in configs:
        if not isinstance(config, JsonFeedConfig):
            raise TypeError("JSON feed startup requires JsonFeedConfig descriptions")
        snapshot = JsonFeedConfig.model_validate(config)
        _validate_source_endpoint(
            snapshot.name,
            snapshot.endpoint,
            hardened=environment in {"staging", "production"},
        )
        if snapshot.name in names:
            raise ValueError("JSON feed source names must be unique")
        if snapshot.signing_key_env in key_refs:
            raise ValueError("JSON feed signing-key references must be unique per source")
        names.add(snapshot.name)
        key_refs.add(snapshot.signing_key_env)
        snapshots.append(snapshot)
    if key_refs & {config.credential_env for config in snapshots}:
        raise ValueError("JSON feed signing-key references cannot be bearer references")
    return tuple(snapshots)


def prepare_json_feed_startup(
    configs: Sequence[JsonFeedConfig],
    *,
    environment: str,
    environ: Mapping[str, str],
) -> tuple[JsonFeedCredentials, ...]:
    """Validate descriptions and snapshot credentials without I/O or global settings.

    The explicit mapping is the only credential source. Validate all descriptions
    and reference separation before reading it. Signing keys are unique per feed
    and cannot reuse any bearer material, including base64 padding/alphabet aliases.
    Bearer credentials may be shared by feeds authorized under the same account.
    Empty input returns an empty tuple. Errors never include credential values.
    Runtime construction consumes these prepared snapshots explicitly.
    """
    snapshots = validate_json_feed_configs(configs, environment=environment)

    resolved: list[JsonFeedCredentials] = []
    keys: set[bytes] = set()
    encoded_keys: set[str] = set()
    bearers: set[str] = set()
    for config in snapshots:
        bearer = _bearer_value(environ, config.credential_env)
        encoded_key, key = _signing_key_value(environ, config.signing_key_env)
        if key in keys:
            raise ValueError("JSON feed signing keys must be unique per source")
        keys.add(key)
        encoded_keys.add(encoded_key)
        bearers.add(bearer.translate(_BASE64URL_TRANSLATION).rstrip("="))
        resolved.append(JsonFeedCredentials(config.name, SecretStr(bearer), SecretBytes(key)))
    if encoded_keys & bearers:
        raise ValueError("JSON feed signing keys cannot reuse bearer credential material")
    return tuple(resolved)


def snapshot_json_feed_selection(
    configs: Sequence[JsonFeedConfig], credentials: Sequence[JsonFeedCredentials]
) -> dict[str, JsonFeedCredentials]:
    """Validate exact prepared identities and cross-source secret separation."""
    snapshots = validate_json_feed_configs(configs, environment="dev")
    configs_by_name = {config.name: config for config in snapshots}
    prepared: dict[str, JsonFeedCredentials] = {}
    for credential in credentials:
        if not isinstance(credential, JsonFeedCredentials) or not isinstance(
            credential.source_name, str
        ):
            raise TypeError("JSON feed construction requires prepared credentials")
        if credential.source_name in prepared:
            raise ValueError("JSON feed prepared credential identities must be unique")
        if credential.source_name not in configs_by_name:
            raise ValueError("JSON feed prepared credentials do not match the selection")
        if not isinstance(credential.bearer_token, SecretStr) or not isinstance(
            credential.signing_key, SecretBytes
        ):
            raise TypeError("JSON feed construction requires prepared credentials")
        prepared[credential.source_name] = credential
    if set(prepared) != set(configs_by_name):
        raise ValueError("JSON feed requires prepared credentials for every selected source")

    explicit: dict[str, str] = {}
    for name, config in configs_by_name.items():
        credential = prepared[name]
        key = credential.signing_key.get_secret_value()
        if len(key) != _SIGNING_KEY_BYTES:
            raise ValueError("JSON feed signing key is missing or invalid")
        values = (
            (config.credential_env, credential.bearer_token.get_secret_value()),
            (
                config.signing_key_env,
                base64.urlsafe_b64encode(key).decode("ascii").rstrip("="),
            ),
        )
        for reference, value in values:
            if reference in explicit and explicit[reference] != value:
                raise ValueError("JSON feed prepared credential references disagree")
            explicit[reference] = value
    return {
        credential.source_name: credential
        for credential in prepare_json_feed_startup(snapshots, environment="dev", environ=explicit)
    }
