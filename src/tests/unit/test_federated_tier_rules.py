"""Ordered federation rules propose tiers without granting account authority."""

import json

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.federated_tier_rules import (
    FederatedEntitlementPrefix,
    FederatedTierMatch,
    FederatedTierRule,
    parse_federated_entitlements,
    propose_federated_tier,
)
from app.federation_contract import ENTITLEMENT_MAX_LENGTH
from app.services.federated_session_policy import federated_session_policy_fingerprint
from config import settings
from config.settings import Settings
from tests.unit.settings_builders import base_kwargs, make_settings

_ISSUER = "https://idp.example.org/idp"
_OTHER_ISSUER = "https://other-idp.example.org/idp"


def _rule(match, tier="vetted"):
    """Validate the requested match/tier pair as a federation proposal rule."""
    return FederatedTierRule.model_validate({"match": match, "tier": tier})


def test_rule_predicates_are_conjoined_and_first_match_wins():
    """Rule predicates are conjoined and first match wins."""
    rules = (
        _rule(
            {
                "issuer": _ISSUER,
                "affiliation": "member",
                "entitlement": "urn:example:archive:vetted",
            },
            "registered",
        ),
        _rule({"issuer": _ISSUER}, "public"),
    )

    proposal = propose_federated_tier(
        rules,
        issuer=_ISSUER,
        affiliation="member",
        entitlement="urn:example:archive:vetted",
    )

    assert proposal is not None
    assert proposal.tier == "registered"
    assert proposal.rule_index == 1
    assert proposal.rule == rules[0]
    assert (
        propose_federated_tier(
            rules, issuer=_ISSUER, affiliation="visitor", entitlement="urn:example:archive:vetted"
        ).rule_index
        == 2
    )
    assert (
        propose_federated_tier(
            rules, issuer=_ISSUER, affiliation="member", entitlement="urn:example:archive:other"
        ).rule_index
        == 2
    )
    assert (
        propose_federated_tier(
            rules,
            issuer=_OTHER_ISSUER,
            affiliation="member",
            entitlement="urn:example:archive:vetted",
        )
        is None
    )


def test_rule_order_is_independent_of_entitlement_value_order():
    """Rule order is independent of entitlement value order."""
    first = _rule({"entitlement": "urn:example:archive:first"}, "registered")
    second = _rule({"entitlement": "urn:example:archive:second"}, "vetted")

    proposal = propose_federated_tier(
        (first, second),
        issuer=_ISSUER,
        entitlement="urn:example:archive:second;urn:example:archive:first",
    )

    assert proposal is not None and proposal.tier == "registered" and proposal.rule_index == 1
    reordered = propose_federated_tier(
        (second, first),
        issuer=_ISSUER,
        entitlement="urn:example:archive:second;urn:example:archive:first",
    )
    assert reordered is not None and reordered.tier == "vetted" and reordered.rule_index == 1


@pytest.mark.parametrize(
    ("predicate", "asserted", "matches"),
    [
        ("urn:example:role:member", "urn:example:role:member", True),
        ("urn:example:role:member", "urn:example:role:member-extra", False),
        ("urn:example:role:*", "urn:example:role:member", False),
        ("urn:example:role:*", "urn:example:role:*", True),
        ({"prefix": "urn:example:role:"}, "urn:example:role:member", True),
        ({"prefix": "urn:example:role:"}, "urn:example:role:", True),
        ({"prefix": "urn:example:role:"}, "other;urn:example:role:member", True),
        ({"prefix": "urn:example:role:"}, "urn:example:role;member", False),
        ({"prefix": "role;admin"}, "role;admin", False),
        ({"prefix": "role;admin"}, r"role\;admin:reviewer", True),
        ("urn:example:role:member", "URN:example:role:member", False),
    ],
)
def test_entitlement_exact_and_explicit_prefix_match_one_decoded_value(
    predicate, asserted, matches
):
    """Entitlement exact and explicit prefix match one decoded value."""
    proposal = propose_federated_tier(
        (_rule({"entitlement": predicate}),), issuer=_ISSUER, entitlement=asserted
    )
    assert (proposal is not None) is matches


@pytest.mark.parametrize(
    ("raw", "values"),
    [
        (None, ()),
        ("", ()),
        ("member", ("member",)),
        ("member;reviewer", ("member", "reviewer")),
        ("member;member", ("member", "member")),
        (r"role\;admin;member", ("role;admin", "member")),
        (r"role\\admin;member", (r"role\admin", "member")),
        (r"role\\;member", ("role\\", "member")),
        ("role with internal space", ("role with internal space",)),
        ("x" * ENTITLEMENT_MAX_LENGTH, ("x" * ENTITLEMENT_MAX_LENGTH,)),
    ],
)
def test_bounded_entitlement_serialization_preserves_values_and_supported_escapes(raw, values):
    """Bounded entitlement serialization preserves values and supported escapes."""
    assert parse_federated_entitlements(raw) == values


@pytest.mark.parametrize(
    "raw",
    [
        True,
        1,
        [],
        " ",
        " member",
        "member ",
        ";member",
        "member;",
        "member;;reviewer",
        "member; reviewer",
        "member ;reviewer",
        "member,reviewer",
        "member\nreviewer",
        "member\u202ereviewer",
        "member\\",
        r"member\q",
        "x" * (ENTITLEMENT_MAX_LENGTH + 1),
    ],
)
def test_malformed_entitlement_serialization_produces_no_proposal(raw):
    """Malformed entitlement serialization produces no proposal."""
    assert parse_federated_entitlements(raw) is None
    # A malformed supplied attribute cannot fall through to an issuer-only rule.
    assert (
        propose_federated_tier((_rule({"issuer": _ISSUER}),), issuer=_ISSUER, entitlement=raw)
        is None
    )


def test_decoded_literal_delimiters_and_backslashes_match_exact_rules():
    """Decoded literal delimiters and backslashes match exact rules."""
    rules = (_rule({"entitlement": r"role;archive\reviewer"}),)
    proposal = propose_federated_tier(rules, issuer=_ISSUER, entitlement=r"role\;archive\\reviewer")
    assert proposal is not None and proposal.rule == rules[0]


@pytest.mark.parametrize("affiliation", [None, "unknown", "Member", "visitor"])
def test_unknown_or_missing_predicate_values_produce_no_proposal(affiliation):
    """Unknown or missing predicate values produce no proposal."""
    rules = (_rule({"affiliation": "member", "entitlement": "archive-reviewer"}),)
    assert (
        propose_federated_tier(
            rules, issuer=_ISSUER, affiliation=affiliation, entitlement="archive-reviewer"
        )
        is None
    )
    assert (
        propose_federated_tier(rules, issuer=_ISSUER, affiliation="member", entitlement=None)
        is None
    )
    assert propose_federated_tier((), issuer=_ISSUER, affiliation="member") is None


@pytest.mark.parametrize(
    ("issuer", "affiliation"),
    [
        (None, None),
        (True, "member"),
        ("", "member"),
        (f" {_ISSUER}", "member"),
        (_ISSUER, " member"),
        (_ISSUER, "member "),
        (_ISSUER, "member\nreviewer"),
    ],
)
def test_malformed_scalar_assertions_do_not_match(issuer, affiliation):
    """Malformed scalar assertions do not match."""
    assert (
        propose_federated_tier(
            (_rule({"issuer": _ISSUER}),), issuer=issuer, affiliation=affiliation
        )
        is None
    )


@pytest.mark.parametrize(
    "document",
    [
        None,
        True,
        [],
        "vetted",
        {},
        {"match": {}, "tier": "vetted"},
        {"match": {"unknown": "member"}, "tier": "vetted"},
        {"match": {"issuer": _ISSUER}, "tier": "admin"},
        {"match": {"issuer": _ISSUER}, "tier": "VETTED"},
        {"match": {"issuer": _ISSUER}, "tier": True},
        {"match": {"issuer": _ISSUER}, "tier": "vetted", "automatic": True},
        {"match": {"affiliation": None}, "tier": "vetted"},
        {"match": {"affiliation": 1}, "tier": "vetted"},
        {"match": {"affiliation": ""}, "tier": "vetted"},
        {"match": {"affiliation": " member"}, "tier": "vetted"},
        {"match": {"entitlement": None}, "tier": "vetted"},
        {"match": {"entitlement": {"prefix": ""}}, "tier": "vetted"},
        {"match": {"entitlement": {"prefix": "x", "exact": "y"}}, "tier": "vetted"},
        {"match": {"entitlement": {"prefix": True}}, "tier": "vetted"},
        {"match": {"entitlement": {"exact": "member"}}, "tier": "vetted"},
        {"match": {"entitlement": "member,reviewer"}, "tier": "vetted"},
        {
            "match": {"entitlement": "x" * (ENTITLEMENT_MAX_LENGTH + 1)},
            "tier": "vetted",
        },
    ],
)
def test_rule_configuration_rejects_unknown_ambiguous_or_coerced_shapes(document):
    """Rule configuration rejects unknown ambiguous or coerced shapes."""
    with pytest.raises(ValidationError):
        FederatedTierRule.model_validate(document)


def test_rule_and_nested_prefix_are_immutable_and_json_round_trip():
    """Rule and nested prefix are immutable and JSON round trip."""
    rule = _rule(
        {"issuer": _ISSUER, "entitlement": {"prefix": "urn:example:archive:"}},
        "registered",
    )
    assert isinstance(rule.match, FederatedTierMatch)
    assert isinstance(rule.match.entitlement, FederatedEntitlementPrefix)
    with pytest.raises(ValidationError):
        rule.tier = "vetted"
    with pytest.raises(ValidationError):
        rule.match.issuer = _OTHER_ISSUER
    with pytest.raises(ValidationError):
        rule.match.entitlement.prefix = "other"
    assert FederatedTierRule.model_validate_json(rule.model_dump_json()) == rule
    assert rule.model_dump() == {
        "match": {"issuer": _ISSUER, "entitlement": {"prefix": "urn:example:archive:"}},
        "tier": "registered",
    }


def test_proposal_rule_snapshot_is_a_fresh_complete_json_value():
    """Proposal rule snapshot is a fresh complete JSON value."""
    rule = _rule({"entitlement": {"prefix": "urn:example:archive:"}}, "registered")
    proposal = propose_federated_tier(
        (rule,), issuer=_ISSUER, entitlement="urn:example:archive:reviewer"
    )
    assert proposal is not None
    expected = {
        "index": 1,
        "match": {"entitlement": {"prefix": "urn:example:archive:"}},
        "tier": "registered",
    }
    snapshot = proposal.rule_snapshot
    assert snapshot == expected
    assert json.loads(json.dumps(snapshot)) == expected
    snapshot["match"]["entitlement"]["prefix"] = "changed-by-caller"
    snapshot["tier"] = "vetted"
    assert proposal.rule_snapshot == expected
    assert rule.match.entitlement.prefix == "urn:example:archive:"


def test_settings_default_to_an_empty_immutable_proposal_rule_selection(monkeypatch):
    """Settings default to an empty immutable proposal rule selection."""
    monkeypatch.delenv("FEDERATED_TIER_RULES", raising=False)
    kwargs = base_kwargs()
    kwargs.pop("federated_tier_rules")
    configured = make_settings(**kwargs)
    assert configured.federated_tier_rules == ()


def test_settings_parse_real_json_environment_without_enabling_federation(monkeypatch):
    """Settings parse real JSON environment without enabling federation."""
    document = [
        {"match": {"affiliation": "member"}, "tier": "registered"},
        {"match": {"entitlement": {"prefix": "urn:example:review:"}}, "tier": "vetted"},
    ]
    monkeypatch.setenv("FEDERATED_TIER_RULES", json.dumps(document))
    kwargs = base_kwargs()
    kwargs.pop("federated_tier_rules")

    configured = make_settings(**kwargs)

    assert configured.shibboleth_enabled is False
    assert isinstance(configured.federated_tier_rules, tuple)
    assert [rule.model_dump() for rule in configured.federated_tier_rules] == document
    assert configured.model_dump(mode="json")["federated_tier_rules"] == document
    # SecretStr fields intentionally serialize masked values. Use the synthetic
    # constructor inputs for the complete Settings JSON validation witness.
    restored = Settings.model_validate_json(json.dumps(base_kwargs(federated_tier_rules=document)))
    assert restored.federated_tier_rules == configured.federated_tier_rules


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "null",
        "true",
        "{}",
        '[{"match":{},"tier":"vetted"}]',
        '[{"match":{"affiliation":"member"},"tier":"unknown"}]',
        '[{"match":{"entitlement":{"prefix":""}},"tier":"vetted"}]',
        '[{"match":{"affiliation":"member"},"tier":"public","tier":"vetted"}]',
        '[{"match":{"affiliation":"visitor"},"match":{"affiliation":"member"},"tier":"vetted"}]',
        '[{"match":{"entitlement":{"prefix":"a","prefix":"b"}},"tier":"vetted"}]',
        '[{"match":{"affiliation":"member"},"tier":NaN}]',
        '[{"match":{"affiliation":"member"},"tier":Infinity}]',
        '[{"match":{"affiliation":"member"},"tier":-Infinity}]',
    ],
)
def test_invalid_json_rule_environment_fails_even_when_federation_is_disabled(monkeypatch, raw):
    """Invalid JSON rule environment fails even when federation is disabled."""
    monkeypatch.setenv("FEDERATED_TIER_RULES", raw)
    kwargs = base_kwargs()
    kwargs.pop("federated_tier_rules")
    with pytest.raises((ValidationError, SettingsError)):
        make_settings(**kwargs)


@pytest.mark.parametrize(
    "raw",
    ['[{"match":{"affiliation":"member"},"tier":"vetted"}]', "not-json", "null"],
)
def test_settings_builder_does_not_inherit_ambient_proposal_rules(monkeypatch, raw):
    """Settings builder does not inherit ambient proposal rules."""
    monkeypatch.setenv("FEDERATED_TIER_RULES", raw)
    assert make_settings(**base_kwargs()).federated_tier_rules == ()


@pytest.mark.parametrize(
    "rules",
    [
        pytest.param({}, id="mapping"),
        pytest.param(set(), id="set"),
        pytest.param(frozenset(), id="frozenset"),
        pytest.param(iter(()), id="iterator"),
    ],
)
def test_settings_reject_unordered_or_lazy_rule_collections(rules):
    """Settings reject unordered or lazy rule collections."""
    with pytest.raises(ValidationError):
        make_settings(**base_kwargs(federated_tier_rules=rules))


def test_settings_accept_explicit_ordered_inputs_and_snapshot_mutable_data():
    """Settings accept explicit ordered inputs and snapshot mutable data."""
    document = [{"match": {"affiliation": "member"}, "tier": "registered"}]
    from_json = make_settings(**base_kwargs(federated_tier_rules=json.dumps(document)))
    from_list = make_settings(**base_kwargs(federated_tier_rules=document))
    from_tuple = make_settings(**base_kwargs(federated_tier_rules=tuple(document)))
    assert from_json.federated_tier_rules == from_list.federated_tier_rules
    assert from_list.federated_tier_rules == from_tuple.federated_tier_rules
    document[0]["tier"] = "vetted"
    document[0]["match"]["affiliation"] = "visitor"
    assert from_list.federated_tier_rules[0].tier == "registered"
    assert from_list.federated_tier_rules[0].match.affiliation == "member"


@pytest.mark.parametrize("raw", ["null", "{}", '[{"match":{},"tier":"vetted"}]'])
def test_malformed_selected_dotenv_rules_fail_even_when_federation_is_disabled(
    monkeypatch, tmp_path, raw
):
    """Malformed selected dotenv rules fail even when federation is disabled."""
    monkeypatch.delenv("FEDERATED_TIER_RULES", raising=False)
    selected = tmp_path / ".env"
    selected.write_text(f"FEDERATED_TIER_RULES='{raw}'\n", encoding="utf-8")
    kwargs = base_kwargs()
    kwargs.pop("federated_tier_rules")
    with pytest.raises((ValidationError, SettingsError)):
        Settings(_env_file=selected, **kwargs)


def test_advisory_rule_changes_do_not_change_session_authority_fingerprint(monkeypatch):
    """Advisory rule changes do not change session authority fingerprint."""
    monkeypatch.setattr(settings, "federated_tier_rules", ())
    before = federated_session_policy_fingerprint()
    monkeypatch.setattr(
        settings,
        "federated_tier_rules",
        (_rule({"affiliation": "member"}, "vetted"),),
    )
    assert federated_session_policy_fingerprint() == before
