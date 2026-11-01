"""Opaque search bookmarks authenticate strict state and retain one scan deadline."""

import base64
import json
import re
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

import pytest
import time_machine
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from itsdangerous import BadSignature
from pydantic import SecretStr

from app.services import search_cursor
from app.services.search_cursor import (
    NUMBERED_SEARCH_PAGES,
    SEARCH_CURSOR_MAX_AGE_SECONDS,
    SEARCH_CURSOR_MAX_LENGTH,
    SearchCursor,
    SearchCursorInvalid,
    cursor_context_digest,
    issue_search_cursor,
    read_search_cursor,
)
from app.services.tokens import SignedActionToken, action_token_public_id
from config import settings

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
NOW_SECONDS = int(NOW.timestamp())
DOMAIN = b"oralhistarchiv-search-cursor-v2"
INVALID_MESSAGE = "Search bookmark is no longer valid"
SECRET_TERM = "private-Caf\u00e9-interview-query-marker"
pytestmark = pytest.mark.usefixtures("frozen_clock")


@pytest.fixture
def frozen_clock():
    """Freeze UTC time at NOW without ticking and yield its controllable clock."""
    with time_machine.travel(NOW, tick=False) as clock:
        yield clock


def context_values():
    """Build independent query, viewer, policy, and ordering context values."""
    return {
        "query": {"term": SECRET_TERM, "mode": "auto", "keyword": "history"},
        "viewer": {"id": 1_900_000_007, "tier": "vetted", "auth_revision": 4},
        "policy": {"archive": {"description": "vetted", "authors": "registered"}},
        "ordering": ["upstream_modified_at", "id"],
    }


@pytest.fixture
def context():
    """Hash the sample bookmark context with the public digest function."""
    return cursor_context_digest(context_values())


def valid_state(**changes):
    """Build a valid continuation bookmark with dataclass field overrides."""
    state = SearchCursor(
        anchor_id=2_000_000_001,
        ceiling_id=2_000_000_099,
        page=101,
        direction="next",
        issued_at=NOW_SECONDS,
    )
    return replace(state, **changes)


def cipher_for_domain(domain=DOMAIN):
    """Independent test implementation of the declared domain/key protocol."""
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=domain).derive(
        settings.secret_key.get_secret_value().encode("utf-8")
    )
    return Fernet(base64.urlsafe_b64encode(derived))


def valid_payload(context):
    """Encode valid bookmark fields with the supplied context digest."""
    state = valid_state()
    return {
        "v": 2,
        "a": state.anchor_id,
        "h": state.ceiling_id,
        "p": state.page,
        "d": state.direction,
        "i": state.issued_at,
        "c": context,
    }


def authenticated_bytes(raw, *, timestamp=NOW_SECONDS, domain=DOMAIN):
    """Encrypt raw bytes under the chosen test domain and timestamp; return ASCII ciphertext."""
    return cipher_for_domain(domain).encrypt_at_time(raw, current_time=timestamp).decode("ascii")


def authenticated_payload(payload, *, timestamp=NOW_SECONDS):
    """Serialize compact ASCII JSON and encrypt it with the selected timestamp."""
    return authenticated_bytes(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii"),
        timestamp=timestamp,
    )


def assert_invalid(token, context):
    """Require generic, query-free bookmark rejection and return the captured exception."""
    with pytest.raises(SearchCursorInvalid) as error:
        read_search_cursor(token, context=context)
    assert str(error.value) == INVALID_MESSAGE
    assert SECRET_TERM not in repr(error.value)
    return error.value


def test_randomized_authenticated_roundtrip_keeps_ids_and_query_opaque(context):
    """Check randomized authenticated roundtrip keeps IDs and query opaque (FrozenInstanceError)."""
    state = valid_state()
    first = issue_search_cursor(state, context=context)
    second = issue_search_cursor(state, context=context)
    assert first != second
    for token in (first, second):
        assert token.isascii()
        assert 1 <= len(token) <= SEARCH_CURSOR_MAX_LENGTH == 2048
        assert re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", token)
        assert base64.urlsafe_b64encode(base64.urlsafe_b64decode(token)).decode("ascii") == token
        assert str(state.anchor_id) not in token
        assert str(state.ceiling_id) not in token
        assert SECRET_TERM not in token
        encrypted = base64.urlsafe_b64decode(token)
        assert b'"a":2000000001' not in encrypted
        assert b'"h":2000000099' not in encrypted
        raw = cipher_for_domain().decrypt_at_time(
            token.encode("ascii"), ttl=3600, current_time=NOW_SECONDS
        )
        assert json.loads(raw) == valid_payload(context)
        assert SECRET_TERM.encode() not in raw
        assert cipher_for_domain().extract_timestamp(token.encode("ascii")) == NOW_SECONDS
        assert read_search_cursor(token, context=context) == state
    with pytest.raises(FrozenInstanceError):
        state.page = 102


def test_context_hash_is_canonical_recursively_without_mutating_input():
    """Check context hash is canonical recursively without mutating input."""
    original = context_values()
    reordered = {
        "ordering": ["upstream_modified_at", "id"],
        "policy": {"archive": {"authors": "registered", "description": "vetted"}},
        "viewer": {"auth_revision": 4, "tier": "vetted", "id": 1_900_000_007},
        "query": {"keyword": "history", "mode": "auto", "term": SECRET_TERM},
    }
    before = json.dumps(original, ensure_ascii=False)
    digest = cursor_context_digest(original)
    assert re.fullmatch(r"[a-f0-9]{64}", digest)
    assert digest == cursor_context_digest(reordered)
    assert digest == cursor_context_digest(MappingProxyType(reordered))
    assert json.dumps(original, ensure_ascii=False) == before
    assert SECRET_TERM not in digest


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("query", "term", SECRET_TERM.upper()),
        ("query", "term", SECRET_TERM + " "),
        ("query", "mode", "web"),
        ("query", "keyword", "testimony"),
        ("query", "language", "German"),
        ("query", "access_level", "restricted"),
        ("viewer", "id", 1_900_000_008),
        ("viewer", "tier", "registered"),
        ("viewer", "auth_revision", 5),
        ("policy", "archive", {"description": "public", "authors": "registered"}),
        ("policy", "unselected_archive", {"description": "vetted"}),
    ],
)
def test_meaningful_context_change_invalidates_a_bookmark(context, section, key, value):
    """Check meaningful context change invalidates a bookmark."""
    token = issue_search_cursor(valid_state(), context=context)
    changed = context_values()
    changed[section][key] = value
    other_context = cursor_context_digest(changed)
    assert other_context != context
    assert_invalid(token, other_context)


def test_context_list_order_and_scalar_types_are_significant():
    """Check context list order and scalar types are significant."""
    assert cursor_context_digest({"order": ["date", "id"]}) != cursor_context_digest(
        {"order": ["id", "date"]}
    )
    assert cursor_context_digest({"user": 1}) != cursor_context_digest({"user": True})
    assert cursor_context_digest({"user": 1}) != cursor_context_digest({"user": "1"})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_context_hash_refuses_nonfinite_json_numbers(value):
    """Check context hash refuses nonfinite JSON numbers (ValueError)."""
    with pytest.raises(ValueError):
        cursor_context_digest({"query": SECRET_TERM, "invalid": value})


def test_chained_links_keep_the_first_scan_time_and_exact_hour_boundary(context, frozen_clock):
    """Check chained links keep the first scan time and exact hour boundary (SearchCursorInvalid)."""
    assert NUMBERED_SEARCH_PAGES == 100
    assert SEARCH_CURSOR_MAX_AGE_SECONDS == 3600
    first = issue_search_cursor(valid_state(), context=context)
    frozen_clock.shift(timedelta(minutes=20))
    later_state = replace(
        read_search_cursor(first, context=context), anchor_id=1_999_999_999, page=102
    )
    second = issue_search_cursor(later_state, context=context)
    assert cipher_for_domain().extract_timestamp(second.encode("ascii")) == NOW_SECONDS
    frozen_clock.shift(timedelta(minutes=40))
    assert read_search_cursor(first, context=context).issued_at == NOW_SECONDS
    assert read_search_cursor(second, context=context) == later_state
    frozen_clock.shift(timedelta(seconds=1))
    assert_invalid(first, context)
    assert_invalid(second, context)
    with pytest.raises(SearchCursorInvalid, match=f"^{INVALID_MESSAGE}$"):
        issue_search_cursor(later_state, context=context)


def test_current_secret_is_read_per_operation_and_rekey_revokes_old_tokens(context, monkeypatch):
    """Check current secret is read per operation and rekey revokes old tokens."""
    first = issue_search_cursor(valid_state(), context=context)
    with monkeypatch.context() as changed:
        changed.setattr(
            settings,
            "secret_key",
            SecretStr("replacement-credential-L7wN2pR6hJ9cB3zF5tQ8mV1yK4sD0aE"),
        )
        assert cursor_context_digest(context_values()) == context
        assert_invalid(first, context)
        second = issue_search_cursor(valid_state(), context=context)
        assert read_search_cursor(second, context=context) == valid_state()
    assert read_search_cursor(first, context=context) == valid_state()
    assert_invalid(second, context)


@pytest.mark.parametrize("domain", [b"password-reset", b"session-cookie-v1", DOMAIN + b"-other"])
def test_an_authenticated_token_from_another_encryption_domain_is_not_a_cursor(context, domain):
    """Check an authenticated token from another encryption domain is not a cursor."""
    token = authenticated_bytes(json.dumps(valid_payload(context)).encode("ascii"), domain=domain)
    assert_invalid(token, context)


@pytest.mark.parametrize("salt", ["password-reset", "email-verification", "email-change"])
def test_email_action_capabilities_and_public_ids_cannot_cross_the_cursor_domain(context, salt):
    """Check email action capabilities and public IDs cannot cross the cursor domain (BadSignature)."""
    signer = SignedActionToken(salt, 3600)
    action = signer.issue({"user_id": 17, "email": "cursor-test@example.org"})
    assert_invalid(action, context)
    assert_invalid(action_token_public_id(action), context)
    cursor = issue_search_cursor(valid_state(), context=context)
    with pytest.raises(BadSignature):
        signer.loads(cursor)


@pytest.mark.parametrize(
    "field,value",
    [
        (field, value)
        for field in ("anchor_id", "ceiling_id", "page", "issued_at")
        for value in (True, False, None, 1.5, "101")
    ]
    + [
        ("anchor_id", 0),
        ("anchor_id", -1),
        ("anchor_id", 2_000_000_100),
        ("ceiling_id", 0),
        ("ceiling_id", -1),
        ("ceiling_id", 2_000_000_000),
        ("ceiling_id", 2_147_483_648),
        ("page", 0),
        ("page", 99),
        ("page", 100),
        ("page", 2_147_483_648),
        ("issued_at", -1),
        ("issued_at", NOW_SECONDS + 1),
        ("issued_at", NOW_SECONDS - 3601),
        ("direction", "NEXT"),
        ("direction", "prev"),
        ("direction", ""),
        ("direction", None),
        ("direction", True),
        ("direction", 1),
        ("direction", ["next"]),
    ],
)
def test_invalid_state_is_refused_before_issuance_and_after_valid_authentication(
    context, field, value
):
    """Check invalid state is refused before issuance and after valid authentication
    (SearchCursorInvalid).
    """
    with pytest.raises(SearchCursorInvalid, match=f"^{INVALID_MESSAGE}$"):
        issue_search_cursor(valid_state(**{field: value}), context=context)
    payload = valid_payload(context)
    key = {"anchor_id": "a", "ceiling_id": "h", "page": "p", "issued_at": "i", "direction": "d"}[
        field
    ]
    payload[key] = value
    assert_invalid(authenticated_payload(payload), context)


@pytest.mark.parametrize(
    "changes",
    [
        {"anchor_id": 1, "ceiling_id": 1},
        {"anchor_id": 2_147_483_647, "ceiling_id": 2_147_483_647, "page": 2_147_483_647},
        {"page": 100, "direction": "previous"},
        {"page": 101, "direction": "previous"},
        {"issued_at": NOW_SECONDS - 3600},
    ],
)
def test_valid_identity_page_and_time_boundaries_are_inclusive(context, changes):
    """Check valid identity page and time boundaries are inclusive."""
    state = valid_state(**changes)
    assert read_search_cursor(issue_search_cursor(state, context=context), context=context) == state


@pytest.mark.parametrize("state", [None, True, {}, [], "private-state-marker", 101])
def test_issuance_requires_the_cursor_state_object(context, state):
    """Check issuance requires the cursor state object (SearchCursorInvalid)."""
    with pytest.raises(SearchCursorInvalid, match=f"^{INVALID_MESSAGE}$"):
        issue_search_cursor(state, context=context)


@pytest.mark.parametrize(
    "bad_context",
    [
        None,
        True,
        1,
        b"a" * 64,
        [],
        "",
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "z" * 64,
        "\u00e9" * 64,
        "a" * 64 + "\n",
    ],
)
def test_context_shape_is_validated_on_both_public_operations(context, bad_context):
    """Check context shape is validated on both public operations (ValueError)."""
    token = issue_search_cursor(valid_state(), context=context)
    with pytest.raises(ValueError, match=r"^Invalid search context digest$"):
        issue_search_cursor(valid_state(), context=bad_context)
    assert_invalid(token, bad_context)


@pytest.mark.parametrize("version", [True, False, 0, 1, 3, 2.0, "2", None])
def test_authenticated_payload_version_has_an_exact_nonboolean_integer_type(context, version):
    """Check authenticated payload version has an exact nonboolean integer type."""
    payload = valid_payload(context)
    payload["v"] = version
    assert_invalid(authenticated_payload(payload), context)


def test_v1_domain_and_payload_are_revoked_by_the_v2_protocol(context):
    """Check v1 domain and payload are revoked by the v2 protocol."""
    payload = valid_payload(context)
    payload["v"] = 1
    old_token = authenticated_bytes(
        json.dumps(payload).encode("ascii"), domain=b"oralhistarchiv-search-cursor-v1"
    )
    assert_invalid(old_token, context)
    # Version refusal is independent of the changed encryption domain.
    assert_invalid(authenticated_payload(payload), context)


@pytest.mark.parametrize("key", ["v", "a", "h", "p", "d", "i", "c"])
def test_authenticated_payload_cannot_omit_any_protocol_field(context, key):
    """Check authenticated payload cannot omit any protocol field."""
    payload = valid_payload(context)
    del payload[key]
    assert_invalid(authenticated_payload(payload), context)


def test_authenticated_payload_cannot_add_unknown_fields(context):
    """Check authenticated payload cannot add unknown fields."""
    payload = valid_payload(context)
    payload["private-upstream-marker"] = SECRET_TERM
    assert_invalid(authenticated_payload(payload), context)


@pytest.mark.parametrize("body", [b"null", b"[]", b"true", b"17", b'"string"', b"{", b"\xff"])
def test_authenticated_plaintext_must_be_a_complete_utf8_json_object(context, body):
    """Check authenticated plaintext must be a complete utf8 JSON object."""
    assert_invalid(authenticated_bytes(body), context)


@pytest.mark.parametrize("key", ["v", "a", "h", "p", "d", "i", "c"])
@pytest.mark.parametrize("conflicting", [False, True])
def test_authenticated_duplicate_json_keys_refuse_even_when_last_values_are_valid(
    context, key, conflicting
):
    """Check authenticated duplicate JSON keys refuse even when last values are valid."""
    payload = valid_payload(context)
    earlier = "conflicting-private-marker" if conflicting else payload[key]
    pairs = [(key, earlier), *payload.items()]
    body = "{" + ",".join(json.dumps(name) + ":" + json.dumps(value) for name, value in pairs) + "}"
    assert_invalid(authenticated_bytes(body.encode("ascii")), context)


@pytest.mark.parametrize("offset", [-1, 1])
def test_authenticated_issue_time_must_equal_the_fernet_header(context, offset):
    """Check authenticated issue time must equal the fernet header."""
    assert_invalid(
        authenticated_payload(valid_payload(context), timestamp=NOW_SECONDS + offset), context
    )


@pytest.mark.parametrize("seconds_ahead", [1, 60])
def test_matching_authenticated_future_times_refuse_even_inside_fernet_clock_leeway(
    context, seconds_ahead
):
    """Check matching authenticated future times refuse even inside fernet clock leeway."""
    payload = valid_payload(context)
    payload["i"] = NOW_SECONDS + seconds_ahead
    token = authenticated_payload(payload, timestamp=payload["i"])
    # Fernet itself tolerates this clock skew. A bookmark still cannot start
    # its original scan deadline in the future, even with a matching header.
    assert cipher_for_domain().decrypt_at_time(
        token.encode("ascii"), ttl=3600, current_time=NOW_SECONDS
    )
    assert_invalid(token, context)


@pytest.mark.parametrize(
    "token",
    [
        None,
        True,
        False,
        42,
        1.5,
        b"cursor",
        {},
        [],
        "",
        " ",
        "\u00e9",
        "abc\n",
        "A?",
        "AA===",
        "A" * 2048,
        "A" * 2049,
    ],
)
def test_wire_shape_type_and_length_refuse_with_one_generic_error(context, token):
    """Check wire shape type and length refuse with one generic error."""
    assert_invalid(token, context)


def test_oversized_but_authentic_valid_json_cannot_bypass_the_wire_bound(context):
    """Check oversized but authentic valid JSON cannot bypass the wire bound."""
    body = json.dumps(valid_payload(context)).encode("ascii") + b" " * 2048
    token = authenticated_bytes(body)
    assert len(token) > SEARCH_CURSOR_MAX_LENGTH
    assert json.loads(
        cipher_for_domain().decrypt_at_time(
            token.encode("ascii"), ttl=3600, current_time=NOW_SECONDS
        )
    ) == valid_payload(context)
    assert_invalid(token, context)


def test_noncanonical_base64_cannot_represent_the_same_authenticated_token(context):
    """Check noncanonical base64 cannot represent the same authenticated token."""
    token = issue_search_cursor(valid_state(), context=context)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if token.endswith("=="):
        position = -3
    elif token.endswith("="):
        position = -2
    else:
        alternative = token + "="
        position = None
    if position is not None:
        replacement = alphabet[alphabet.index(token[position]) + 1]
        alternative = token[:position] + replacement + token[position + 1 :]
    assert alternative != token
    assert base64.urlsafe_b64decode(alternative) == base64.urlsafe_b64decode(token)
    assert cipher_for_domain().decrypt_at_time(
        alternative.encode("ascii"), ttl=3600, current_time=NOW_SECONDS
    ) == cipher_for_domain().decrypt_at_time(
        token.encode("ascii"), ttl=3600, current_time=NOW_SECONDS
    )
    assert_invalid(alternative, context)


@pytest.mark.parametrize("position", [0, 1, 9, 25, -1])
def test_version_timestamp_iv_ciphertext_and_signature_tampering_are_not_authenticated(
    context, position
):
    """Check version timestamp iv ciphertext and signature tampering are not authenticated."""
    token = issue_search_cursor(valid_state(), context=context)
    changed = bytearray(base64.urlsafe_b64decode(token))
    changed[position] ^= 1
    assert_invalid(base64.urlsafe_b64encode(changed).decode("ascii"), context)


def test_invalid_encrypted_content_is_neither_echoed_nor_logged(context, caplog):
    """Check invalid encrypted content is neither echoed nor logged."""
    token = authenticated_bytes(("not-json-" + SECRET_TERM).encode("utf-8"))
    caplog.clear()
    error = assert_invalid(token, context)
    assert token not in str(error)
    assert SECRET_TERM not in str(error)
    assert not caplog.records


def test_cursor_cipher_derivation_is_reused_and_rotation_evicts_old_keys(monkeypatch, context):
    """Check cursor cipher derivation is reused and rotation evicts old keys (SearchCursorInvalid)."""
    search_cursor._cipher_for_secret.cache_clear()
    original = settings.secret_key
    token = issue_search_cursor(valid_state(), context=context)
    assert read_search_cursor(token, context=context) == valid_state()
    assert search_cursor._cipher_for_secret.cache_info().misses == 1
    assert search_cursor._cipher_for_secret.cache_info().hits == 1
    monkeypatch.setattr(settings, "secret_key", SecretStr("rotated-search-key-" * 4))
    with pytest.raises(SearchCursorInvalid):
        read_search_cursor(token, context=context)
    assert search_cursor._cipher_for_secret.cache_info().currsize == 1
    monkeypatch.setattr(settings, "secret_key", original)
    assert read_search_cursor(token, context=context) == valid_state()
    assert search_cursor._cipher_for_secret.cache_info().misses == 3
    assert search_cursor._cipher_for_secret.cache_info().currsize == 1
    search_cursor._cipher_for_secret.cache_clear()
