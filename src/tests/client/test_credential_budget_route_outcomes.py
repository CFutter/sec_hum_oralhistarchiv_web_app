"""Client-level route contracts for credential-attempt budgets.

The database and service tiers own the counters.  These tests pin the HTTP
boundary: an exhausted session-wide step-up budget terminates only the exact
session, while an exhausted TOTP-rotation challenge leaves that session alive
and requires a fresh challenge.  Public recovery failures remain deliberately
indistinguishable.
"""

import logging
from unittest.mock import ANY, call, patch

import pytest

from app.middleware import CSRF_COOKIE_NAME, limiter
from app.services import AdminActionRejected
from app.services.admin_promotion import AdminPromotionRejected
from app.services.email_change import SelfEmailChangeRejected
from app.services.totp import (
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    TotpRotationStartResult,
)
from app.services.totp_recover import (
    TotpRecoveryRedemption,
    TotpRecoveryRedemptionRejected,
    TotpRecoveryRejected,
    TotpRecoveryTarget,
)
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user


def _patch_route(module: str, name: str, **kwargs):
    return patch(f"app.routes.auth.{module}.{name}", autospec=True, **kwargs)


def _assert_auth_cookies_cleared(response) -> None:
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )


def _assert_auth_cookies_kept(response, client) -> None:
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert not any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )
        assert client.cookies.get(cookie_name) is not None


@pytest.mark.parametrize(
    "outcome",
    (
        TotpRotationStartOutcome.ATTEMPTS_EXHAUSTED,
        TotpRotationStartOutcome.SESSION_EXPIRED,
    ),
    ids=("attempts-exhausted", "invalid-session"),
)
def test_totp_rotation_start_session_rejection_clears_exact_session(
    authenticated_client,
    outcome,
):
    result = TotpRotationStartResult(outcome)
    with (
        _patch_route("totp", "begin_totp_rotation", return_value=result) as begin,
        _patch_route("totp", "audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            "/account/reset-totp",
            data={
                "current_password": "correct horse",
                "current_totp_code": "111111",
                "csrf_token": authenticated_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=session_expired"
    _assert_auth_cookies_cleared(response)
    begin.assert_awaited_once_with(
        authenticated_client.mock_pool,
        1,
        "correct horse",
        "111111",
        session_id=RAW_SESSION_ID,
    )
    audit.assert_called_once_with(
        level=logging.WARNING,
        request=ANY,
        event_type="totp_rotation_step_up_session_rejected",
        user_id=1,
        reason=outcome.value,
    )


def test_totp_rotation_confirmation_exhaustion_keeps_session_and_restarts(
    authenticated_client,
):
    with (
        _patch_route(
            "totp",
            "confirm_totp_rotation",
            return_value=TotpRotationOutcome.ATTEMPTS_EXHAUSTED,
        ) as confirm,
        _patch_route("totp", "set_flash_if_exists") as flash,
    ):
        response = authenticated_client.post(
            "/account/reset-totp/confirm",
            data={
                "new_totp_code": "222222",
                "csrf_token": authenticated_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/account/reset-totp"
    assert "GEZDGNBVGY3TQOJQ" not in response.text
    assert "data:image/png;base64" not in response.text
    _assert_auth_cookies_kept(response, authenticated_client)
    confirm.assert_awaited_once_with(
        authenticated_client.mock_pool,
        1,
        "222222",
        session_id=RAW_SESSION_ID,
    )
    flash.assert_awaited_once()
    assert flash.await_args.args[1] == RAW_SESSION_ID


@pytest.mark.parametrize(
    "reason",
    ("step_up_exhausted", "invalid_session"),
    ids=("attempts-exhausted", "invalid-session"),
)
def test_email_change_session_rejection_clears_session_before_follow_up(
    authenticated_client,
    reason,
):
    with (
        _patch_route(
            "email_change",
            "stage_self_email_change",
            side_effect=SelfEmailChangeRejected(reason),
        ) as stage,
        _patch_route("email_change", "set_flash_if_exists") as flash,
        _patch_route("email_change", "audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            "/account/change-email",
            data={
                "new_email": "alice.new@uzh.ch",
                "current_password": "correct horse",
                "csrf_token": authenticated_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=session_expired"
    _assert_auth_cookies_cleared(response)
    stage.assert_awaited_once_with(
        authenticated_client.mock_pool,
        user_id=1,
        session_id=RAW_SESSION_ID,
        current_password="correct horse",
        new_email="alice.new@uzh.ch",
    )
    flash.assert_not_awaited()
    audit.assert_called_once_with(
        level=logging.WARNING,
        request=ANY,
        event_type="email_change_step_up_session_rejected",
        user_id=1,
        reason=reason,
    )


@pytest.mark.parametrize(
    ("path", "service_name", "form", "event_type", "audit_level"),
    [
        (
            "/account/admin-promotion/prepare",
            "prepare_admin_promotion",
            {"current_password": "correct horse", "totp_code": "111111"},
            "admin_promotion_prepare_failed",
            logging.INFO,
        ),
        (
            "/account/admin-promotion/accept",
            "accept_admin_promotion",
            {"recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD"},
            "admin_promotion_accept_failed",
            logging.WARNING,
        ),
    ],
    ids=("prepare", "accept"),
)
@pytest.mark.parametrize(
    "reason",
    ("step_up_exhausted", "invalid_session"),
    ids=("attempts-exhausted", "invalid-session"),
)
def test_admin_promotion_session_rejection_clears_session_without_reload(
    authenticated_client,
    path,
    service_name,
    form,
    event_type,
    audit_level,
    reason,
):
    with (
        _patch_route(
            "admin_promotion",
            service_name,
            side_effect=AdminPromotionRejected(reason),
        ) as mutation,
        _patch_route("admin_promotion", "get_admin_promotion") as reload_promotion,
        _patch_route("admin_promotion", "audit_user_event") as audit,
    ):
        response = authenticated_client.post(
            path,
            data={**form, "csrf_token": authenticated_client.csrf_token},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=session_expired"
    _assert_auth_cookies_cleared(response)
    mutation.assert_awaited_once()
    reload_promotion.assert_not_awaited()
    audit.assert_called_once_with(
        level=audit_level,
        request=ANY,
        event_type=event_type,
        user_id=1,
        reason=reason,
    )


@pytest.mark.parametrize(
    "reason",
    ("actor_step_up_exhausted", "actor_session_invalid"),
    ids=("attempts-exhausted", "invalid-session"),
)
def test_admin_recovery_session_rejection_does_not_reload_target(
    client_builder,
    reason,
):
    admin_client = client_builder(
        session_user=make_sample_user(
            id=99,
            email="admin@uzh.ch",
            display_name="Admin User",
            access_tier="vetted",
            is_admin=True,
            totp_recovery_code_generation=1,
            totp_recovery_codes_available=True,
        )
    )
    target = TotpRecoveryTarget(
        user_id=7,
        email="target@uzh.ch",
        display_name="Target User",
        auth_method="local",
        is_active=True,
        email_verified=True,
        totp_configured=True,
        recovery_required=False,
        recovery_codes_available=True,
        recovery_authorization_active=False,
        recovery_expires_at=None,
    )
    with (
        _patch_route("admin", "get_totp_recovery_target", return_value=target) as lookup,
        _patch_route(
            "admin",
            "authorize_totp_recovery",
            side_effect=TotpRecoveryRejected(reason),
        ) as authorize,
        _patch_route("admin", "audit_admin_action") as audit,
    ):
        response = admin_client.post(
            "/admin/users/7/totp-recovery",
            data={
                "admin_totp_code": "111111",
                "confirm_reset": "true",
                "page": "1",
                "page_size": "25",
                "csrf_token": admin_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=session_expired"
    _assert_auth_cookies_cleared(response)
    lookup.assert_awaited_once_with(admin_client.mock_pool, 7)
    authorize.assert_awaited_once_with(
        admin_client.mock_pool,
        actor_id=99,
        actor_session_id=RAW_SESSION_ID,
        target_user_id=7,
        admin_totp_code="111111",
    )
    audit.assert_called_once_with(
        level=logging.WARNING,
        request=ANY,
        event_type="admin_totp_recovery_blocked",
        target_user_id=7,
        reason=reason,
    )


def test_admin_recovery_final_session_race_clears_cookie(client_builder):
    """A session deleted after reservation fails closed at the final guard."""
    admin_client = client_builder(
        session_user=make_sample_user(
            id=99,
            email="admin@uzh.ch",
            display_name="Admin User",
            access_tier="vetted",
            is_admin=True,
            totp_recovery_code_generation=1,
            totp_recovery_codes_available=True,
        )
    )
    target = TotpRecoveryTarget(
        user_id=7,
        email="target@uzh.ch",
        display_name="Target User",
        auth_method="local",
        is_active=True,
        email_verified=True,
        totp_configured=True,
        recovery_required=False,
        recovery_codes_available=True,
        recovery_authorization_active=False,
        recovery_expires_at=None,
    )
    with (
        _patch_route("admin", "get_totp_recovery_target", return_value=target) as lookup,
        _patch_route(
            "admin",
            "authorize_totp_recovery",
            side_effect=AdminActionRejected("administrator session changed"),
        ),
    ):
        response = admin_client.post(
            "/admin/users/7/totp-recovery",
            data={
                "admin_totp_code": "111111",
                "confirm_reset": "true",
                "page": "1",
                "page_size": "20",
                "csrf_token": admin_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=session_expired"
    _assert_auth_cookies_cleared(response)
    lookup.assert_awaited_once_with(admin_client.mock_pool, 7)


def test_account_locked_response_is_bounded_and_does_not_reflect_credentials(
    authenticated_client,
):
    password_marker = "DO-NOT-REFLECT-PASSWORD-9c37"
    totp_marker = "654321"
    result = TotpRotationStartResult(TotpRotationStartOutcome.ACCOUNT_LOCKED)
    with _patch_route("totp", "begin_totp_rotation", return_value=result):
        response = authenticated_client.post(
            "/account/reset-totp",
            data={
                "current_password": password_marker,
                "current_totp_code": totp_marker,
                "csrf_token": authenticated_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 423
    assert "This account is temporarily unavailable. Try again later." in response.text
    assert password_marker not in response.text
    assert totp_marker not in response.text
    assert len(response.content) < 32_000
    _assert_auth_cookies_kept(response, authenticated_client)


def test_public_recovery_rejection_reasons_have_identical_generic_response(guest_client):
    reasons = (
        "invalid_credentials",
        "account_ineligible",
        "recovery_not_authorized",
        "recovery_expired",
        "auth_state_changed",
    )
    responses = []

    with (
        _patch_route("totp_recover", "redeem_totp_recovery") as redeem,
        _patch_route("totp_recover", "audit_user_event") as audit,
    ):
        for reason in reasons:
            limiter.reset()
            redeem.side_effect = TotpRecoveryRedemptionRejected(reason, user_id=7)
            responses.append(
                guest_client.post(
                    "/recover-totp",
                    data={
                        "email": "target@uzh.ch",
                        "password": "DO-NOT-REFLECT-PASSWORD-9c37",
                        "recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD",
                        "csrf_token": guest_client.csrf_token,
                    },
                    follow_redirects=False,
                )
            )

    assert {response.status_code for response in responses} == {401}
    assert len({response.text for response in responses}) == 1
    for response in responses:
        assert "Invalid email, password, or recovery code." in response.text
        assert "DO-NOT-REFLECT-PASSWORD-9c37" not in response.text
        assert "AAAAA-BBBBB-CCCCC-DDDDD" not in response.text
        assert all(reason not in response.text for reason in reasons)
        assert response.headers["cache-control"] == "no-store"

    assert audit.call_args_list == [
        call(
            level=logging.INFO,
            request=ANY,
            event_type="totp_recovery_redemption_failed",
            user_id=None,
        )
        for _ in reasons
    ]
    for audit_call in audit.call_args_list:
        assert "reason" not in audit_call.kwargs
        assert "email" not in audit_call.kwargs
        assert "password" not in audit_call.kwargs
        assert "recovery_code" not in audit_call.kwargs


def test_public_recovery_page_renders_without_touching_any_service(guest_client):
    """GET /recover-totp only renders the generic recovery form; it never
    consults the redemption service (redemption is POST-only)."""
    with _patch_route("totp_recover", "redeem_totp_recovery") as redeem:
        response = guest_client.get("/recover-totp")

    assert response.status_code == 200
    assert 'name="recovery_code"' in response.text
    redeem.assert_not_awaited()


def test_public_recovery_accepted_redemption_differs_from_every_rejection(guest_client):
    """Positive control for the six typed-rejection parity proven above: the
    one accepted redemption produces a status, body, and redirect that are
    all distinguishable from every rejection's identical generic response."""
    redemption = TotpRecoveryRedemption(user_id=7, session_id="fresh-recovery-session")
    with (
        _patch_route("totp_recover", "redeem_totp_recovery", return_value=redemption) as redeem,
        _patch_route("totp_recover", "audit_user_event") as audit,
    ):
        response = guest_client.post(
            "/recover-totp",
            data={
                "email": "target@uzh.ch",
                "password": "correct horse battery staple",
                "recovery_code": "AAAAA-BBBBB-CCCCC-DDDDD",
                "csrf_token": guest_client.csrf_token,
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/setup-totp"
    assert "Invalid email, password, or recovery code." not in (response.text or "")
    redeem.assert_awaited_once_with(
        guest_client.mock_pool,
        email="target@uzh.ch",
        password="correct horse battery staple",
        recovery_code="AAAAA-BBBBB-CCCCC-DDDDD",
        ip_address=ANY,
    )
    audit.assert_called_once_with(
        level=logging.INFO,
        request=ANY,
        event_type="totp_recovery_redeemed",
        user_id=7,
    )
