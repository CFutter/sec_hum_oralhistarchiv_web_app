"""Immutable advisory tier rules, independent of settings and login authority.

The caller supplies canonical, proxy-authenticated assertion attributes. A
proposal never approves an account, changes its tier or creates a session.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, field_validator, model_serializer, model_validator

from app.federation_contract import (
    AFFILIATION_MAX_LENGTH,
    ENTITLEMENT_MAX_LENGTH,
    ISSUER_MAX_LENGTH,
    InvalidFederatedPrincipal,
    exact_security_value,
)
from app.url_safety import parse_http_url

__all__ = [
    "FederatedEntitlementPrefix",
    "FederatedTierMatch",
    "FederatedTierProposal",
    "FederatedTierRule",
    "parse_federated_entitlements",
    "propose_federated_tier",
]


def _match_value(value: object, *, name: str, limit: int) -> str:
    """Validate one literal predicate without coercion or normalization."""
    try:
        return exact_security_value(cast("str", value), name=name, max_length=limit)
    except InvalidFederatedPrincipal as error:
        raise ValueError(str(error)) from error


class FederatedEntitlementPrefix(BaseModel):
    """An explicit prefix of one decoded entitlement value, never a pattern."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    prefix: str

    @field_validator("prefix", mode="before")
    @classmethod
    def validate_prefix(cls, value: object) -> str:
        """Reject blank, ambiguous, oversized or noncanonical prefixes."""
        return _match_value(value, name="entitlement prefix", limit=ENTITLEMENT_MAX_LENGTH)


class FederatedTierMatch(BaseModel):
    """Nonempty conjunction of exact issuer/profile and entitlement predicates."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    issuer: str | None = None
    affiliation: str | None = None
    entitlement: str | FederatedEntitlementPrefix | None = None

    @field_validator("issuer", mode="before")
    @classmethod
    def validate_issuer(cls, value: object) -> str:
        """Require an exact absolute HTTPS issuer without wildcard syntax."""
        issuer = _match_value(value, name="issuer", limit=ISSUER_MAX_LENGTH)
        if "*" in issuer or "\\" in issuer or any(character.isspace() for character in issuer):
            raise ValueError("issuer must be an exact absolute HTTPS issuer")
        parse_http_url(issuer, require_https=True)
        return issuer

    @field_validator("affiliation", mode="before")
    @classmethod
    def validate_affiliation(cls, value: object) -> str:
        """Use the canonical affiliation scalar without rewriting it."""
        return _match_value(value, name="affiliation", limit=AFFILIATION_MAX_LENGTH)

    @field_validator("entitlement", mode="before")
    @classmethod
    def validate_entitlement(cls, value: object) -> str | FederatedEntitlementPrefix:
        """Accept a literal exact value or the single explicit prefix form."""
        if isinstance(value, FederatedEntitlementPrefix):
            return value
        if isinstance(value, dict):
            return FederatedEntitlementPrefix.model_validate(value)
        return _match_value(value, name="entitlement", limit=ENTITLEMENT_MAX_LENGTH)

    @model_validator(mode="after")
    def require_predicate(self) -> "FederatedTierMatch":
        """A rule cannot silently become a global catch-all."""
        if self.issuer is None and self.affiliation is None and self.entitlement is None:
            raise ValueError("match must contain at least one predicate")
        return self

    @model_serializer
    def serialize_match(self) -> dict[str, Any]:
        """Keep omitted predicates omitted in Python/JSON configuration round trips."""
        return {
            name: value
            for name, value in (
                ("issuer", self.issuer),
                ("affiliation", self.affiliation),
                ("entitlement", self.entitlement),
            )
            if value is not None
        }


class FederatedTierRule(BaseModel):
    """One immutable advisory rule; array order supplies its priority."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    match: FederatedTierMatch
    tier: Literal["public", "registered", "vetted"]


@dataclass(frozen=True, slots=True)
class FederatedTierProposal:
    """Advisory result with the matched 1-based index and immutable rule."""

    tier: Literal["public", "registered", "vetted"]
    rule_index: int
    rule: FederatedTierRule

    @property
    def rule_snapshot(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible snapshot for later review/persistence."""
        return {"index": self.rule_index, **self.rule.model_dump(mode="json")}


def parse_federated_entitlements(value: str | None) -> tuple[str, ...] | None:
    r"""Decode bounded SP serialization; None means malformed, () means absent.

    Unescaped semicolons separate values. Only ``\;`` and ``\\`` escapes are
    accepted; values are never joined for matching. Empty values, unknown or
    trailing escapes, commas, controls and outer value whitespace fail closed.
    """
    if value is None or value == "":
        return ()
    if (
        not isinstance(value, str)
        or len(value) > ENTITLEMENT_MAX_LENGTH
        or not value.isprintable()
        or value != value.strip()
        or "," in value
    ):
        return None
    values: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            if character not in {";", "\\"}:
                return None
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ";":
            item = "".join(current)
            if not item or item != item.strip():
                return None
            values.append(item)
            current.clear()
        else:
            current.append(character)
    item = "".join(current)
    if escaped or not item or item != item.strip():
        return None
    values.append(item)
    return tuple(values)


def propose_federated_tier(
    rules: Sequence[FederatedTierRule],
    *,
    issuer: str,
    affiliation: str | None = None,
    entitlement: str | None = None,
) -> FederatedTierProposal | None:
    """Return the first matching advisory rule, or None for no/invalid assertion.

    Supplied predicates combine with AND. Entitlement predicates match one
    decoded value at a time. This function does not authenticate the assertion
    or read settings; callers must retain the existing trusted proxy/MFA checks.
    """
    try:
        _match_value(issuer, name="issuer", limit=ISSUER_MAX_LENGTH)
        if affiliation is not None:
            _match_value(affiliation, name="affiliation", limit=AFFILIATION_MAX_LENGTH)
    except ValueError:
        return None
    entitlements = parse_federated_entitlements(entitlement)
    if entitlements is None:
        return None
    for index, rule in enumerate(rules, start=1):
        match = rule.match
        if match.issuer is not None and match.issuer != issuer:
            continue
        if match.affiliation is not None and match.affiliation != affiliation:
            continue
        if isinstance(match.entitlement, str):
            if match.entitlement not in entitlements:
                continue
        elif match.entitlement is not None and not any(
            value.startswith(match.entitlement.prefix) for value in entitlements
        ):
            continue
        return FederatedTierProposal(rule.tier, index, rule)
    return None
