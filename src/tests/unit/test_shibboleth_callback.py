"""Shibboleth callback trust boundary (ported from legacy edge-case tests)."""

import logging
from collections.abc import Mapping, Sequence
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr
from starlette.requests import Request

from app.federation_contract import ENTITLEMENT_MAX_LENGTH
from app.main import app as application
from app.middleware.cookies import SESSION_SIGNER
from app.routes.auth.login import (
    _FederatedHeaderRejected,
    _single_federated_header,
    shibboleth_callback,
)
from app.services.federated_authentication import (
    SHIBBOLETH_AFFILIATION_HEADER,
    SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    SHIBBOLETH_COUNTRY_HEADER,
    SHIBBOLETH_DISPLAY_NAME_HEADER,
    SHIBBOLETH_ENTITLEMENT_HEADER,
    SHIBBOLETH_INTERNAL_AUTH_HEADER,
    SHIBBOLETH_ISSUER_HEADER,
    SHIBBOLETH_MAIL_HEADER,
    SHIBBOLETH_SUBJECT_HEADER,
    FederatedLoginFailure,
    FederatedLoginSuccess,
)
from app.services.federated_session_policy import REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
from config import settings
from tests.fixtures import make_sample_user

SECRET = "shib-internal-secret-value-for-tests-0123456789"
ISSUER = "https://idp.example.org/idp/shibboleth"

VALID_SHIB_HEADERS = {
    SHIBBOLETH_INTERNAL_AUTH_HEADER: SECRET,
    SHIBBOLETH_SUBJECT_HEADER: "stable-subject-123",
    SHIBBOLETH_ISSUER_HEADER: ISSUER,
    SHIBBOLETH_MAIL_HEADER: "jane@x.org",
    SHIBBOLETH_AUTHN_CONTEXT_HEADER: REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
}


def make_request(
    headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    client=None,
    query: bytes = b"",
):
    """A raw ASGI request: client=None + server=None models the Unix socket."""
    items = headers.items() if isinstance(headers, Mapping) else headers or []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/auth/shibboleth/callback",
        "query_string": query,
        "headers": [(key.lower().encode(), value.encode()) for key, value in items],
        "client": client,
        "server": None,
        "scheme": "http",
        "state": {"user": None},
        "app": SimpleNamespace(
            state=SimpleNamespace(db_pool=MagicMock()),
            url_path_for=application.url_path_for,
        ),
    }
    return Request(scope)


def shib_settings(monkeypatch):
    """Enable federation with the synthetic internal secret and one trusted issuer."""
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SECRET))
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [ISSUER])


async def test_disabled_redirects_to_login():
    """shibboleth_enabled=False → the endpoint is inert (303, no processing)."""
    response = await shibboleth_callback(make_request())
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_tcp_peer_is_refused(monkeypatch):
    """A request with a TCP peer can only mean the app is exposed on TCP —
    refuse even with a valid secret (the socket is the only trusted path)."""
    shib_settings(monkeypatch)
    request = make_request({SHIBBOLETH_INTERNAL_AUTH_HEADER: SECRET}, client=("10.0.0.9", 4321))
    response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_wrong_internal_secret_refused(monkeypatch):
    """The internal credential is the first gate after the Unix-socket tripwire.

    nginx injects it only on this location and
    strips client-supplied copies everywhere."""
    shib_settings(monkeypatch)
    response = await shibboleth_callback(make_request({SHIBBOLETH_INTERNAL_AUTH_HEADER: "wrong"}))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_missing_attributes_refused(monkeypatch):
    """Valid secret but no assertion attributes means no federation session."""
    shib_settings(monkeypatch)
    response = await shibboleth_callback(make_request({SHIBBOLETH_INTERNAL_AUTH_HEADER: SECRET}))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize(
    "missing_header",
    [
        SHIBBOLETH_SUBJECT_HEADER,
        SHIBBOLETH_ISSUER_HEADER,
        SHIBBOLETH_MAIL_HEADER,
        SHIBBOLETH_AUTHN_CONTEXT_HEADER,
    ],
)
async def test_every_required_assertion_header_fails_closed(monkeypatch, missing_header):
    """Check every required assertion header fails closed (HTTP 303)."""
    shib_settings(monkeypatch)
    headers = {key: value for key, value in VALID_SHIB_HEADERS.items() if key != missing_header}
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request(headers))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


@pytest.mark.parametrize(
    "duplicate_header",
    [
        SHIBBOLETH_INTERNAL_AUTH_HEADER,
        SHIBBOLETH_SUBJECT_HEADER,
        SHIBBOLETH_ISSUER_HEADER,
        SHIBBOLETH_MAIL_HEADER,
        SHIBBOLETH_AUTHN_CONTEXT_HEADER,
        SHIBBOLETH_DISPLAY_NAME_HEADER,
        SHIBBOLETH_AFFILIATION_HEADER,
        SHIBBOLETH_ENTITLEMENT_HEADER,
        SHIBBOLETH_COUNTRY_HEADER,
    ],
)
async def test_duplicate_security_or_attribute_header_is_rejected(monkeypatch, duplicate_header):
    """Check duplicate security or attribute header is rejected (HTTP 303)."""
    shib_settings(monkeypatch)
    headers = list(VALID_SHIB_HEADERS.items())
    if duplicate_header not in VALID_SHIB_HEADERS:
        headers.append((duplicate_header, "first"))
    headers.append((duplicate_header, "second"))
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request(headers))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


@pytest.mark.parametrize(
    "duplicate_header",
    [
        SHIBBOLETH_ISSUER_HEADER,
        SHIBBOLETH_SUBJECT_HEADER,
        SHIBBOLETH_AUTHN_CONTEXT_HEADER,
        SHIBBOLETH_ENTITLEMENT_HEADER,
    ],
)
async def test_mixed_case_duplicate_security_header_is_rejected(monkeypatch, duplicate_header):
    """Header names are case-insensitive; casing cannot hide a duplicate."""
    shib_settings(monkeypatch)
    headers = list(VALID_SHIB_HEADERS.items())
    if duplicate_header not in VALID_SHIB_HEADERS:
        headers.append((duplicate_header, "first"))
    headers.append((duplicate_header.swapcase(), "attacker-controlled"))
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request(headers))

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


class TestFederatedHeaderRawDecoding:
    """Cover federated header raw decoding."""

    @pytest.mark.parametrize(
        "value",
        ["Müller", "Université de Zürich", "李明", "Мария"],
        ids=["latin-supplement", "combining-accents", "cjk", "cyrillic"],
    )
    def test_valid_utf8_header_decodes_before_unicode_validation(self, value):
        """Check valid utf8 header decodes before unicode validation."""
        request = Request({"type": "http", "headers": [(b"x-name", value.encode("utf-8"))]})
        assert _single_federated_header(request, "x-name", max_length=200, required=True) == value

    def test_ambiguous_legacy_latin1_header_is_rejected(self):
        """b'M\\xfcller' is valid Latin-1 ('Müller') but not valid UTF-8 —
        decoding it permissively would silently accept mojibake identity
        data, so it must be rejected instead of guessed at."""
        request = Request({"type": "http", "headers": [(b"x-name", b"M\xfcller")]})
        with pytest.raises(_FederatedHeaderRejected, match="invalid_utf8"):
            _single_federated_header(request, "x-name", max_length=200, required=True)


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (SHIBBOLETH_ISSUER_HEADER, f" {ISSUER}"),
        (SHIBBOLETH_ISSUER_HEADER, f"{ISSUER} "),
        (SHIBBOLETH_SUBJECT_HEADER, " stable-subject-123"),
        (SHIBBOLETH_SUBJECT_HEADER, "stable-subject-123 "),
        (
            SHIBBOLETH_AUTHN_CONTEXT_HEADER,
            f" {REQUIRED_SHIBBOLETH_AUTHN_CONTEXT}",
        ),
        (
            SHIBBOLETH_AUTHN_CONTEXT_HEADER,
            f"{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT} ",
        ),
        (SHIBBOLETH_ISSUER_HEADER, f"{ISSUER},https://attacker.example/idp"),
        (SHIBBOLETH_SUBJECT_HEADER, "stable-subject-123,attacker-subject"),
        (
            SHIBBOLETH_AUTHN_CONTEXT_HEADER,
            f"{REQUIRED_SHIBBOLETH_AUTHN_CONTEXT},password",
        ),
    ],
)
async def test_nonexact_or_comma_coalesced_security_value_is_rejected(monkeypatch, header, value):
    """Check nonexact or comma coalesced security value is rejected (HTTP 303)."""
    shib_settings(monkeypatch)
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request({**VALID_SHIB_HEADERS, header: value}))

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (SHIBBOLETH_SUBJECT_HEADER, "subject\twith-control"),
        (SHIBBOLETH_SUBJECT_HEADER, "subject\u0085with-c1-control"),
        (SHIBBOLETH_DISPLAY_NAME_HEADER, "name\u202ewith-bidi-override"),
        (SHIBBOLETH_SUBJECT_HEADER, "s" * 513),
        (SHIBBOLETH_ISSUER_HEADER, "https://idp.example/" + "i" * 2049),
        (SHIBBOLETH_MAIL_HEADER, "m" * 321),
        (SHIBBOLETH_AUTHN_CONTEXT_HEADER, "a" * 1025),
        (SHIBBOLETH_DISPLAY_NAME_HEADER, "d" * 201),
        (SHIBBOLETH_AFFILIATION_HEADER, "a" * 513),
        (SHIBBOLETH_ENTITLEMENT_HEADER, "e" * (ENTITLEMENT_MAX_LENGTH + 1)),
        (SHIBBOLETH_ENTITLEMENT_HEADER, "urn:example:member\tcontrol"),
        (SHIBBOLETH_ENTITLEMENT_HEADER, "urn:example:\u202emember"),
        (SHIBBOLETH_COUNTRY_HEADER, "c" * 129),
    ],
)
async def test_control_or_oversized_assertion_value_is_rejected(monkeypatch, header, value):
    """Check control or oversized assertion value is rejected (HTTP 303)."""
    shib_settings(monkeypatch)
    headers = {**VALID_SHIB_HEADERS, header: value}
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request(headers))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


async def test_assertion_headers_are_not_parsed_before_secret_passes(monkeypatch):
    """Check assertion headers are not parsed before secret passes (HTTP 303)."""
    shib_settings(monkeypatch)
    with (
        patch("app.routes.auth.login._read_federated_principal", autospec=True) as parse,
        patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize,
    ):
        response = await shibboleth_callback(
            make_request({**VALID_SHIB_HEADERS, SHIBBOLETH_INTERNAL_AUTH_HEADER: "wrong"})
        )
    assert response.status_code == 303
    parse.assert_not_called()
    finalize.assert_not_awaited()


@pytest.mark.parametrize(
    ("header", "value"),
    [
        (SHIBBOLETH_ISSUER_HEADER, "https://untrusted.example/idp"),
        (
            SHIBBOLETH_AUTHN_CONTEXT_HEADER,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        ),
    ],
)
async def test_unapproved_issuer_or_password_only_context_never_reaches_db(
    monkeypatch, header, value
):
    """Check unapproved issuer or password only context never reaches database (HTTP 303)."""
    shib_settings(monkeypatch)
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request({**VALID_SHIB_HEADERS, header: value}))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


async def test_legacy_public_header_names_are_not_identity_inputs(monkeypatch):
    """Check legacy public header names are not identity inputs (HTTP 303)."""
    shib_settings(monkeypatch)
    headers = {
        SHIBBOLETH_INTERNAL_AUTH_HEADER: SECRET,
        "REMOTE_USER": "attacker-controlled",
        "mail": "attacker@example.org",
        "Shib-Identity-Provider": ISSUER,
        "Shib-AuthnContext-Class": REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    }
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(make_request(headers))
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


async def test_invalid_email_refused_with_error_param(monkeypatch):
    """Check invalid email refused with error param (HTTP 303)."""
    shib_settings(monkeypatch)
    request = make_request(
        {
            **VALID_SHIB_HEADERS,
            SHIBBOLETH_MAIL_HEADER: "not-an-email",
        }
    )
    response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=shibboleth_invalid_email"


async def test_local_account_collision_never_issues_session(monkeypatch):
    """Check local account collision never issues session (HTTP 401)."""
    shib_settings(monkeypatch)
    request = make_request(VALID_SHIB_HEADERS)
    with (
        patch(
            "app.routes.auth.login.finalize_shibboleth_login",
            autospec=True,
            return_value=FederatedLoginFailure("account_conflict"),
        ),
        patch("app.routes.auth.login.audit_user_event", autospec=True) as audit,
    ):
        response = await shibboleth_callback(request)
    assert response.status_code == 401
    assert "Please contact support" in response.body.decode()
    assert "set-cookie" not in response.headers
    assert audit.call_args.kwargs["event_type"] == "shibboleth_login_blocked_account_conflict"


async def test_valid_callback_provisions_and_sets_cookie(monkeypatch):
    """Check valid callback provisions and sets cookie (HTTP 303)."""
    shib_settings(monkeypatch)
    user = make_sample_user(auth_method="shibboleth", email="jane@x.org")
    request = make_request(
        {
            **VALID_SHIB_HEADERS,
            SHIBBOLETH_MAIL_HEADER: " Jane@X.org ",
            SHIBBOLETH_DISPLAY_NAME_HEADER: " Jane ",
            SHIBBOLETH_AFFILIATION_HEADER: " Example University ",
            SHIBBOLETH_COUNTRY_HEADER: " CH ",
            SHIBBOLETH_ENTITLEMENT_HEADER: r" urn:example:member;urn:example:escaped\;value ",
        }
    )
    with patch(
        "app.routes.auth.login.finalize_shibboleth_login",
        autospec=True,
        return_value=FederatedLoginSuccess(user, "raw-session-id"),
    ) as finalize:
        response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    principal = finalize.await_args.kwargs["principal"]
    assert principal.email == "jane@x.org"
    assert principal.subject_id == "stable-subject-123"
    assert principal.issuer == ISSUER
    assert principal.authn_context == REQUIRED_SHIBBOLETH_AUTHN_CONTEXT
    assert principal.display_name == "Jane"
    assert principal.affiliation == "Example University"
    assert principal.country == "CH"
    assert principal.entitlement == r"urn:example:member;urn:example:escaped\;value"
    assert "HttpOnly" in response.headers["set-cookie"]
    assert settings.session_cookie_name in response.headers["set-cookie"]


async def _valid_callback(
    query: bytes = b"",
    extra_headers: dict[str, Any] | None = None,
    delete_side_effect: Exception | None = None,
):
    """Run a valid callback with mocked finalization/revocation; return the response and revocation
    mock.
    """
    user = make_sample_user(auth_method="shibboleth", email="jane@x.org")
    request = make_request({**VALID_SHIB_HEADERS, **(extra_headers or {})}, query=query)
    with (
        patch(
            "app.routes.auth.login.finalize_shibboleth_login",
            autospec=True,
            return_value=FederatedLoginSuccess(user, "new-raw-session-id"),
        ),
        patch(
            "app.routes.auth.login.delete_session", autospec=True, side_effect=delete_side_effect
        ) as delete_session,
    ):
        response = await shibboleth_callback(request)
    return response, delete_session


async def test_next_param_safe_path_is_honoured(monkeypatch):
    """Check next param safe path is honoured (HTTP 303)."""
    shib_settings(monkeypatch)
    response, _ = await _valid_callback(query=b"next=%2Faccount")
    assert response.status_code == 303
    assert response.headers["location"] == "/account"


async def test_next_param_offsite_url_falls_back_to_root(monkeypatch):
    """Check next param offsite URL falls back to root (HTTP 303)."""
    shib_settings(monkeypatch)
    response, _ = await _valid_callback(query=b"next=https%3A%2F%2Fevil.example.com%2Fphish")
    assert response.status_code == 303
    assert response.headers["location"] == "/"


async def test_no_next_param_defaults_to_root(monkeypatch):
    """IdP-initiated SSO arrives with no next at all: the fallback branch
    must redirect to / rather than raise KeyError or redirect to None."""
    shib_settings(monkeypatch)
    response, _ = await _valid_callback(query=b"")
    assert response.status_code == 303
    assert response.headers["location"] == "/"


async def test_shibboleth_login_revokes_prior_cookie_session(monkeypatch):
    """Check Shibboleth login revokes prior cookie session (HTTP 303)."""
    shib_settings(monkeypatch)
    signed_old_cookie = SESSION_SIGNER.dumps("old-raw-id")
    response, delete_session = await _valid_callback(
        extra_headers={"cookie": f"{settings.session_cookie_name}={signed_old_cookie}"}
    )
    assert response.status_code == 303
    delete_session.assert_awaited_once()
    assert delete_session.await_args.args[1] == "old-raw-id"


async def test_no_prior_cookie_means_no_delete_call(monkeypatch):
    """Check no prior cookie means no delete call (HTTP 303)."""
    shib_settings(monkeypatch)
    response, delete_session = await _valid_callback()
    assert response.status_code == 303
    delete_session.assert_not_called()


async def test_collision_path_preserves_prior_session(monkeypatch):
    """Check collision path preserves prior session (HTTP 401)."""
    shib_settings(monkeypatch)
    signed = SESSION_SIGNER.dumps("old-raw-id")
    request = make_request(
        {**VALID_SHIB_HEADERS, "cookie": f"{settings.session_cookie_name}={signed}"}
    )
    with (
        patch(
            "app.routes.auth.login.finalize_shibboleth_login",
            autospec=True,
            return_value=FederatedLoginFailure("account_conflict"),
        ),
        patch("app.routes.auth.login.delete_session", autospec=True) as delete,
    ):
        response = await shibboleth_callback(request)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    delete.assert_not_awaited()


async def test_wrong_secret_path_preserves_prior_session(monkeypatch):
    """Check wrong secret path preserves prior session (HTTP 303)."""
    shib_settings(monkeypatch)
    signed_old_cookie = SESSION_SIGNER.dumps("old-raw-id")
    request = make_request(
        {
            SHIBBOLETH_INTERNAL_AUTH_HEADER: "wrong",
            "cookie": f"{settings.session_cookie_name}={signed_old_cookie}",
        }
    )
    with patch("app.routes.auth.login.delete_session", autospec=True) as delete_session:
        response = await shibboleth_callback(request)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    delete_session.assert_not_called()


async def test_delete_session_failure_does_not_block_login(monkeypatch, caplog):
    """Check delete session failure does not block login (HTTP 303)."""
    shib_settings(monkeypatch)
    signed_old_cookie = SESSION_SIGNER.dumps("old-raw-id")
    with caplog.at_level(logging.WARNING, logger="app.routes.auth.login"):
        response, delete_session = await _valid_callback(
            extra_headers={"cookie": f"{settings.session_cookie_name}={signed_old_cookie}"},
            delete_side_effect=RuntimeError("db unavailable"),
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    set_cookie = response.headers["set-cookie"]
    assert settings.session_cookie_name in set_cookie
    assert "HttpOnly" in set_cookie
    delete_session.assert_awaited_once()
    assert "Failed to revoke prior session" in caplog.text


async def test_inactive_identity_has_visible_error_and_no_success_side_effects(monkeypatch):
    """Check inactive identity has visible error and no success side effects (HTTP 401)."""
    shib_settings(monkeypatch)
    user = make_sample_user(auth_method="shibboleth", is_active=False)
    request = make_request(VALID_SHIB_HEADERS)
    with (
        patch(
            "app.routes.auth.login.finalize_shibboleth_login",
            autospec=True,
            return_value=FederatedLoginFailure("inactive_account", user),
        ),
        patch("app.routes.auth.login.delete_session", autospec=True) as delete,
        patch("app.routes.auth.login.audit_user_event", autospec=True) as audit,
    ):
        response = await shibboleth_callback(request)
    assert response.status_code == 401
    assert "Please contact support" in response.body.decode()
    assert "set-cookie" not in response.headers
    delete.assert_not_awaited()
    audit.assert_called_once()
    assert audit.call_args.kwargs["event_type"] == "shibboleth_login_blocked_inactive_account"


async def test_invalid_utf8_entitlement_is_refused_before_database(monkeypatch):
    """Check invalid utf8 entitlement is refused before database (HTTP 303)."""
    shib_settings(monkeypatch)
    request = make_request(VALID_SHIB_HEADERS)
    request.scope["headers"].append((SHIBBOLETH_ENTITLEMENT_HEADER.lower().encode(), b"urn:\xff"))
    with patch("app.routes.auth.login.finalize_shibboleth_login", autospec=True) as finalize:
        response = await shibboleth_callback(request)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    finalize.assert_not_awaited()


@pytest.mark.parametrize(
    "entitlement",
    [None, "", "   ", "e" * ENTITLEMENT_MAX_LENGTH],
    ids=["absent", "empty", "blank", "maximum-length"],
)
async def test_optional_entitlement_obeys_header_bound_and_does_not_grant_authority(
    monkeypatch, entitlement
):
    """Check optional entitlement obeys header bound and does not grant authority (HTTP 401)."""
    shib_settings(monkeypatch)
    headers = dict(VALID_SHIB_HEADERS)
    if entitlement is not None:
        headers[SHIBBOLETH_ENTITLEMENT_HEADER] = entitlement
    pending = make_sample_user(auth_method="shibboleth", is_active=False)
    with patch(
        "app.routes.auth.login.finalize_shibboleth_login",
        autospec=True,
        return_value=FederatedLoginFailure("inactive_account", pending),
    ) as finalize:
        response = await shibboleth_callback(make_request(headers))

    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    asserted = finalize.await_args.kwargs["principal"]
    assert asserted.entitlement == (
        entitlement.strip() or None if entitlement is not None else None
    )


@pytest.mark.parametrize("raw_header", ["entitlement", "eduPersonEntitlement"])
async def test_raw_entitlement_names_cannot_populate_the_private_claim(monkeypatch, raw_header):
    """Check raw entitlement names cannot populate the private claim (HTTP 401)."""
    shib_settings(monkeypatch)
    pending = make_sample_user(auth_method="shibboleth", is_active=False)
    with patch(
        "app.routes.auth.login.finalize_shibboleth_login",
        autospec=True,
        return_value=FederatedLoginFailure("inactive_account", pending),
    ) as finalize:
        response = await shibboleth_callback(
            make_request({**VALID_SHIB_HEADERS, raw_header: "urn:example:attacker-entitlement"})
        )

    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert finalize.await_args.kwargs["principal"].entitlement is None
