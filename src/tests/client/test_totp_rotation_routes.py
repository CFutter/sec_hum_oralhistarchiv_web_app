"""TOTP rotation routes (`POST /account/reset-totp[/confirm]`) — the MFA
step-up flow that replaces an already-enrolled authenticator.

Authenticator rotation is a two-step, freshly authenticated flow: POST
/account/reset-totp (`begin_totp_rotation`) proves the current password and
authenticator, then discloses one replacement seed exactly once on the
confirm page; POST /account/reset-totp/confirm (`confirm_totp_rotation`)
proves the new code and atomically promotes it, revoking every session. GET
/account/reset-totp performs no service call at all — it only renders the
fresh-authentication form. These tests pin every typed outcome's route
mapping for both steps without recreating transaction logic in route mocks,
that CSRF is enforced before either service call, and that backend faults
(pool saturation, QR-encoding failure) fail closed without leaking or
promoting the once-disclosed seed.

The enrollment flow (`/setup-totp`) is the sibling scenario class, in
test_totp_enrollment_routes.py; each module is named for the scenario it
proves. All service calls are patched with autospec so arity drift fails
loudly. The integration tier drives both flows against the real database.
"""

import re
from unittest.mock import patch

import pytest
from psycopg_pool import PoolTimeout

from app.middleware import CSRF_COOKIE_NAME
from app.services.totp import (
    TotpDecryptionError,
    TotpRotationOutcome,
    TotpRotationStartOutcome,
    TotpRotationStartResult,
)
from config import settings
from tests.fixtures import RAW_SESSION_ID, make_sample_user

NEW_SECRET = "GEZDGNBVGY3TQOJQ"


def _patch(name, **kw):
    return patch(f"app.routes.auth.totp.{name}", autospec=True, **kw)


_NEW_SECRET_RE = re.compile(r'class="totp-key">([A-Z2-7]+)<')
_QR_DATA_URI_RE = re.compile(r'data:image/png;base64,([A-Za-z0-9+/=]+)"')


def _extract_new_secret(text: str) -> str:
    """Pull the once-disclosed replacement seed out of reset_totp_confirm.html
    — the same markup the integration tier's `_extract_new_secret` reads, so
    an absence assertion here is bound to what the page would actually show,
    not to a string that merely happens not to appear."""
    match = _NEW_SECRET_RE.search(text)
    assert match, "no replacement secret disclosed on the confirm page"
    return match.group(1)


def _extract_qr_data_uri(text: str) -> str:
    match = _QR_DATA_URI_RE.search(text)
    assert match, "no QR data URI on the confirm page"
    return match.group(1)


def _assert_auth_cookies_cleared(response):
    set_cookie_headers = response.headers.get_list("set-cookie")
    for cookie_name in (settings.session_cookie_name, CSRF_COOKIE_NAME):
        assert any(
            header.startswith(f"{cookie_name}=") and "Max-Age=0" in header
            for header in set_cookie_headers
        )


def _post_reset_start(client, current_password="Password123!", current_totp_code="111111"):
    return client.post(
        "/account/reset-totp",
        data={
            "current_password": current_password,
            "current_totp_code": current_totp_code,
            "csrf_token": client.csrf_token,
        },
        follow_redirects=False,
    )


def _post_reset_confirm(client, new_totp_code="222222"):
    return client.post(
        "/account/reset-totp/confirm",
        data={
            "new_totp_code": new_totp_code,
            "csrf_token": client.csrf_token,
        },
        follow_redirects=False,
    )


def _disclose_rotation_seed(client, secret=NEW_SECRET):
    """Perform one legitimate rotation-start call and return the exact
    (seed, qr_data) pair reset_totp_confirm.html discloses, so a later
    assertion that a *different* response leaks neither is bound to a real
    issued secret rather than an arbitrary literal."""
    with _patch(
        "begin_totp_rotation",
        return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, secret),
    ):
        resp = _post_reset_start(client)
    assert resp.status_code == 200
    return _extract_new_secret(resp.text), _extract_qr_data_uri(resp.text)


# ---------------------------------------------------------------------------
# GET /account/reset-totp — rotation page
# ---------------------------------------------------------------------------


class TestResetTotpPage:
    """GET /account/reset-totp never touches the rotation service; it only
    decides which form (or redirect) a full session is allowed to see."""

    def test_reset_totp_page_renders_fresh_auth_form_without_calling_any_service(
        self, authenticated_client
    ):
        """GET performs no secret access at all: the replacement seed is
        minted only by the POST start step (totp.py:603-625). GET only
        renders the fresh-authentication form, so it can neither disclose a
        pending secret nor fail on decryption — the positive control for the
        secret-access tests of the POST steps."""
        with (
            _patch("get_or_create_pending_totp_secret") as pending,
            _patch("begin_totp_rotation") as begin,
        ):
            resp = authenticated_client.get("/account/reset-totp", follow_redirects=False)

        assert resp.status_code == 200
        assert "current_totp_code" in resp.text  # fresh-authentication form only
        pending.assert_not_awaited()
        begin.assert_not_awaited()

    def test_reset_totp_page_shibboleth_user_flashed_to_account(self, client_builder):
        """Non-local accounts manage MFA at the IdP: 303 to /account with the
        SWITCH edu-ID info flash, and no TOTP work happens."""
        shib = make_sample_user(auth_method="shibboleth")
        client = client_builder(session_user=shib)
        with (
            _patch("set_flash_if_exists") as flash,
            _patch("begin_totp_rotation") as begin,
        ):
            resp = client.get("/account/reset-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        begin.assert_not_awaited()
        flash.assert_awaited_once()
        assert flash.await_args.args[1] == RAW_SESSION_ID
        assert "SWITCH edu-ID" in flash.await_args.args[2]
        assert flash.await_args.args[3] == "info"

    def test_reset_totp_page_for_unenrolled_local_user_redirects_to_enrollment(
        self, client_builder
    ):
        """A local account that has never enrolled an authenticator has
        nothing to rotate: GET /account/reset-totp sends it to first-time
        enrollment (303 /setup-totp) and no rotation service is consulted,
        whichever layer (the full-session policy or the handler's own
        ``totp_configured`` check) makes the decision."""
        unenrolled = make_sample_user(totp_configured=False)
        client = client_builder(session_user=unenrolled)
        with (
            _patch("get_or_create_pending_totp_secret") as pending,
            _patch("begin_totp_rotation") as begin,
        ):
            resp = client.get("/account/reset-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"
        pending.assert_not_awaited()
        begin.assert_not_awaited()


# ---------------------------------------------------------------------------
# POST /account/reset-totp — rotation start (fresh authentication)
# ---------------------------------------------------------------------------


class TestResetTotpStart:
    """POST /account/reset-totp proves the current password and authenticator
    before disclosing exactly one replacement seed."""

    def test_reset_totp_start_ready_returns_confirm_page_with_new_seed(self, authenticated_client):
        """A fresh, valid password + current code discloses the replacement
        seed exactly once, on the confirm page — never through a GET."""
        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, NEW_SECRET),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 200
        assert _extract_new_secret(resp.text) == NEW_SECRET
        assert _extract_qr_data_uri(resp.text)  # a real QR image was rendered
        begin.assert_awaited_once_with(
            authenticated_client.mock_pool,
            1,
            "Password123!",
            "111111",
            session_id=RAW_SESSION_ID,
        )

    @pytest.mark.parametrize(
        "outcome, message, absent_message",
        [
            (
                TotpRotationStartOutcome.INVALID_CREDENTIALS,
                "The password or authenticator code is incorrect.",
                None,
            ),
            (
                TotpRotationStartOutcome.REPLAYED_CURRENT_CODE,
                "already used",
                "The password or authenticator code is incorrect.",
            ),
        ],
        ids=["invalid_credentials", "replayed_current_code"],
    )
    def test_reset_totp_start_invalid_current_proof_is_reported(
        self, authenticated_client, outcome, message, absent_message
    ):
        """An invalid password/current-authenticator proof renders its own
        error, and a replayed current-authenticator code is distinguishable
        from a plain-wrong one. Neither response leaks a seed disclosed by an
        earlier, legitimate rotation-start on the same session."""
        seed, qr_data = _disclose_rotation_seed(authenticated_client)

        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(outcome),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 422
        assert message in resp.text
        if absent_message is not None:
            assert absent_message not in resp.text
        assert seed not in resp.text
        assert qr_data not in resp.text
        begin.assert_awaited_once_with(
            authenticated_client.mock_pool,
            1,
            "Password123!",
            "111111",
            session_id=RAW_SESSION_ID,
        )

    def test_reset_totp_missing_current_secret_goes_to_enrollment(self, authenticated_client):
        """No current secret (never enrolled) → the rotation flow refuses and
        redirects to first-time enrollment."""
        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.CURRENT_SECRET_MISSING),
        ):
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup-totp"

    @pytest.mark.parametrize(
        "outcome, status_code, message",
        [
            (
                TotpRotationStartOutcome.INELIGIBLE,
                403,
                "Authenticator reset unavailable",
            ),
            (
                TotpRotationStartOutcome.ACCOUNT_LOCKED,
                423,
                "temporarily unavailable",
            ),
        ],
        ids=["ineligible_account", "account_locked"],
    )
    def test_reset_totp_start_rejected_by_policy_renders_terminal_page(
        self, authenticated_client, outcome, status_code, message
    ):
        """The service's eligibility decision maps to a terminal error page,
        and an account-locked step-up reservation renders 423, not a generic
        422 — and leaks no seed disclosed by an earlier legitimate start."""
        seed, qr_data = _disclose_rotation_seed(authenticated_client)

        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(outcome),
        ):
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == status_code
        assert message in resp.text
        assert seed not in resp.text
        assert qr_data not in resp.text

    def test_reset_totp_start_session_expired_redirects_to_login(self, authenticated_client):
        """An expired or replay-exhausted step-up session is sent back to
        login with its cookies cleared, never trapped on the reset-totp
        form, and the fresh login page carries no seed disclosed earlier on
        the same session."""
        seed, qr_data = _disclose_rotation_seed(authenticated_client)

        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.SESSION_EXPIRED),
        ):
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=session_expired"
        _assert_auth_cookies_cleared(resp)

        followed = authenticated_client.get(resp.headers["location"], follow_redirects=False)
        assert seed not in followed.text
        assert qr_data not in followed.text

    def test_reset_totp_start_decryption_error_fails_closed_503(self, authenticated_client):
        """A corrupt active secret fails closed with the branded 503 on the
        POST that actually reads the secret."""
        with _patch(
            "begin_totp_rotation",
            side_effect=TotpDecryptionError(1),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 503
        assert "Two-factor temporarily unavailable" in resp.text
        begin.assert_awaited_once_with(
            authenticated_client.mock_pool,
            1,
            "Password123!",
            "111111",
            session_id=RAW_SESSION_ID,
        )

    def test_reset_totp_post_shibboleth_user_never_calls_rotation(self, client_builder):
        """Externally authenticated users cannot invoke local TOTP rotation."""
        shib = make_sample_user(auth_method="shibboleth")
        client = client_builder(session_user=shib)
        with _patch("begin_totp_rotation") as begin:
            resp = _post_reset_start(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        begin.assert_not_awaited()


# ---------------------------------------------------------------------------
# POST /account/reset-totp/confirm — rotation confirmation
# ---------------------------------------------------------------------------


class TestResetTotpConfirm:
    """POST /account/reset-totp/confirm proves the new code and atomically
    promotes it, revoking every other session."""

    def test_reset_totp_confirm_rotated_redirects_to_login(self, authenticated_client):
        """A verified new code atomically promotes it and revokes every
        session: 303 to a fresh login, with auth cookies cleared."""
        with _patch(
            "confirm_totp_rotation",
            return_value=TotpRotationOutcome.ROTATED,
        ) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?totp_changed=1"
        _assert_auth_cookies_cleared(resp)
        confirm.assert_awaited_once_with(
            authenticated_client.mock_pool,
            1,
            "222222",
            session_id=RAW_SESSION_ID,
        )

    def test_reset_totp_invalid_new_code_is_reported(self, authenticated_client):
        """An invalid new-authenticator proof re-renders the confirm page with
        its own error and deliberately does not redisclose the seed
        (routes/auth/totp.py:613-624): the confirm step never rereads the
        staged secret for display. The bound check: the exact seed and QR
        data URI disclosed by this same session's rotation start must not
        reappear here."""
        seed, qr_data = _disclose_rotation_seed(authenticated_client)

        with _patch(
            "confirm_totp_rotation",
            return_value=TotpRotationOutcome.INVALID_NEW_CODE,
        ):
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 422
        assert "The new authenticator code is incorrect." in resp.text
        assert 'class="totp-key"' not in resp.text  # the seed is never shown again
        assert seed not in resp.text
        assert qr_data not in resp.text

    def test_reset_totp_missing_pending_restarts_flow(self, authenticated_client):
        """An absent or expired rotation challenge restarts the flow at the
        fresh-authentication step."""
        with (
            _patch(
                "confirm_totp_rotation",
                return_value=TotpRotationOutcome.PENDING_SECRET_MISSING,
            ),
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account/reset-totp"
        flash.assert_awaited_once()

    def test_reset_totp_confirm_account_locked_restarts_at_fresh_authentication(
        self, authenticated_client
    ):
        """An account-locked confirmation attempt restarts the whole flow at
        step one (fresh password + current code), distinct from the
        attempts-exhausted case, which shares the same destination but a
        different flash message and audit reason."""
        with (
            _patch(
                "confirm_totp_rotation",
                return_value=TotpRotationOutcome.ACCOUNT_LOCKED,
            ) as confirm,
            _patch("set_flash_if_exists") as flash,
        ):
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account/reset-totp"
        assert "temporarily unavailable" in flash.await_args.args[2]
        confirm.assert_awaited_once()

    def test_reset_totp_confirm_decryption_error_fails_closed_503(self, authenticated_client):
        """A corrupt staged secret fails closed on the confirmation step too,
        the same as the rotation-start decryption failure pinned in
        TestResetTotpStart.test_reset_totp_start_decryption_error_fails_closed_503."""
        with _patch(
            "confirm_totp_rotation",
            side_effect=TotpDecryptionError(1),
        ) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 503
        assert "Two-factor temporarily unavailable" in resp.text
        confirm.assert_awaited_once_with(
            authenticated_client.mock_pool,
            1,
            "222222",
            session_id=RAW_SESSION_ID,
        )

    @pytest.mark.parametrize(
        "outcome",
        [TotpRotationOutcome.SESSION_EXPIRED, TotpRotationOutcome.INELIGIBLE],
        ids=["session_expired", "ineligible_account"],
    )
    def test_reset_totp_confirm_session_invalidated_redirects_to_fresh_login(
        self, authenticated_client, outcome
    ):
        """Both a step-up session that expired mid-confirmation and an
        account newly found ineligible are treated the same way: the current
        session cannot be trusted, so they are sent to a fresh login with
        cookies cleared, never left on the confirm form."""
        with _patch("confirm_totp_rotation", return_value=outcome) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/login?error=session_expired"
        _assert_auth_cookies_cleared(resp)
        confirm.assert_awaited_once()

    def test_reset_totp_confirm_shibboleth_user_never_calls_rotation(self, client_builder):
        """Externally authenticated users cannot invoke local TOTP rotation
        confirmation either — the same guard as the rotation-start POST,
        pinned in TestResetTotpStart.test_reset_totp_post_shibboleth_user_never_calls_rotation."""
        shib = make_sample_user(auth_method="shibboleth")
        client = client_builder(session_user=shib)
        with _patch("confirm_totp_rotation") as confirm:
            resp = _post_reset_confirm(client)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        confirm.assert_not_awaited()

    def test_reset_totp_confirm_unrecognised_outcome_fails_closed(self, authenticated_client):
        """confirm_totp_rotation's outcome is a closed enum the route maps
        exhaustively; an unrecognised outcome fails loudly rather than
        silently falling through to the invalid-code re-render."""
        with _patch("confirm_totp_rotation", return_value=object()) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 500
        confirm.assert_awaited_once()


# ---------------------------------------------------------------------------
# Contract violations: begin_totp_rotation reporting READY without a secret
# ---------------------------------------------------------------------------


class TestRotationStartContractViolation:
    """begin_totp_rotation's own contract requires a secret whenever it
    reports READY; a violation fails loudly instead of rendering a QR code
    for `None`, the same invariant guard as enrollment's equivalent
    (test_totp_enrollment_routes.py::TestSetupTotpPendingContractViolation)."""

    def test_ready_outcome_without_a_secret_fails_closed(self, authenticated_client):
        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, None),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 500
        begin.assert_awaited_once()


# ---------------------------------------------------------------------------
# GET /account/reset-totp — best-effort flash with no derivable session id
# ---------------------------------------------------------------------------


class TestResetTotpPageSkipsFlashWithNoDerivableSessionId:
    """The same re-derive-from-cookie pattern as the enrollment restart
    helpers (test_totp_enrollment_routes.py::TestSetupTotpBestEffortRevocation):
    when no session id can be derived, the best-effort flash is skipped
    rather than attempted with `None`, while the redirect itself is
    unaffected."""

    def test_skips_the_flash_when_no_session_id_is_derivable_from_the_cookie(self, client_builder):
        shib = make_sample_user(auth_method="shibboleth")
        client = client_builder(session_user=shib)
        with (
            _patch("set_flash_if_exists") as flash,
            patch(
                "app.routes.auth.totp.get_session_id_from_cookie",
                autospec=True,
                return_value=None,
            ),
        ):
            resp = client.get("/account/reset-totp", follow_redirects=False)

        assert resp.status_code == 303
        assert resp.headers["location"] == "/account"
        flash.assert_not_awaited()

    def test_positive_control_flashes_when_the_session_id_is_derivable(self, client_builder):
        """Positive control: pinned already by
        TestResetTotpPage.test_reset_totp_page_shibboleth_user_flashed_to_account;
        repeated here narrowly to sit beside its no-cookie counterpart."""
        shib = make_sample_user(auth_method="shibboleth")
        client = client_builder(session_user=shib)
        with _patch("set_flash_if_exists") as flash:
            resp = client.get("/account/reset-totp", follow_redirects=False)

        assert resp.status_code == 303
        flash.assert_awaited_once()


# ---------------------------------------------------------------------------
# CSRF is enforced on both rotation POSTs before either service call
# ---------------------------------------------------------------------------


class TestRotationCsrfProtection:
    """Both rotation POSTs are ordinary full-session mutations: a missing or
    mismatched CSRF pair is refused before the corresponding service is ever
    awaited, and the bound pair reaches it."""

    def test_reset_totp_start_missing_csrf_pair_is_refused_before_any_service_call(
        self, authenticated_client
    ):
        with _patch("begin_totp_rotation") as begin:
            resp = authenticated_client.post(
                "/account/reset-totp",
                data={"current_password": "Password123!", "current_totp_code": "111111"},
                follow_redirects=False,
            )

        assert resp.status_code == 403
        begin.assert_not_awaited()

    def test_reset_totp_start_mismatched_csrf_pair_is_refused_before_any_service_call(
        self, authenticated_client
    ):
        with _patch("begin_totp_rotation") as begin:
            resp = authenticated_client.post(
                "/account/reset-totp",
                data={
                    "current_password": "Password123!",
                    "current_totp_code": "111111",
                    "csrf_token": "not-the-bound-token",
                },
                follow_redirects=False,
            )

        assert resp.status_code == 403
        begin.assert_not_awaited()

    def test_reset_totp_start_valid_csrf_pair_reaches_the_service(self, authenticated_client):
        """Positive control for both rejection cases above."""
        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, NEW_SECRET),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 200
        begin.assert_awaited_once()

    def test_reset_totp_confirm_missing_csrf_pair_is_refused_before_any_service_call(
        self, authenticated_client
    ):
        with _patch("confirm_totp_rotation") as confirm:
            resp = authenticated_client.post(
                "/account/reset-totp/confirm",
                data={"new_totp_code": "222222"},
                follow_redirects=False,
            )

        assert resp.status_code == 403
        confirm.assert_not_awaited()

    def test_reset_totp_confirm_mismatched_csrf_pair_is_refused_before_any_service_call(
        self, authenticated_client
    ):
        with _patch("confirm_totp_rotation") as confirm:
            resp = authenticated_client.post(
                "/account/reset-totp/confirm",
                data={"new_totp_code": "222222", "csrf_token": "not-the-bound-token"},
                follow_redirects=False,
            )

        assert resp.status_code == 403
        confirm.assert_not_awaited()

    def test_reset_totp_confirm_valid_csrf_pair_reaches_the_service(self, authenticated_client):
        """Positive control for both rejection cases above."""
        with _patch(
            "confirm_totp_rotation",
            return_value=TotpRotationOutcome.ROTATED,
        ) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 303
        confirm.assert_awaited_once()


# ---------------------------------------------------------------------------
# Backend fault injection during rotation must fail closed without leaking
# or promoting a seed (the decryption-failure 503 is already pinned by
# TestResetTotpStart.test_reset_totp_start_decryption_error_fails_closed_503;
# this covers the remaining fault axes instead of duplicating it).
# ---------------------------------------------------------------------------


class TestRotationFaultInjectionFailsClosed:
    """A pool-capacity failure or a QR-encoding failure during rotation start
    must not promote a replacement authenticator or leak the seed it was
    about to disclose; the response stays no-store with the restrictive
    image-source CSP and carries no redirect."""

    def test_healthy_rotation_start_is_unaffected_by_the_fault_injection_harness(
        self, authenticated_client
    ):
        """Positive control: absent any injected fault, the identical request
        reaches begin_totp_rotation and discloses its seed normally — proof
        that the fault-injection tests below are exercising a real failure
        path, not a harness that would 500 regardless."""
        with _patch(
            "begin_totp_rotation",
            return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, NEW_SECRET),
        ) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 200
        assert NEW_SECRET in resp.text
        begin.assert_awaited_once()

    def test_pool_timeout_during_rotation_start_fails_closed_without_leaking_a_seed(
        self, authenticated_client
    ):
        with _patch("begin_totp_rotation", side_effect=PoolTimeout("pool exhausted")) as begin:
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 503
        assert NEW_SECRET not in resp.text
        assert "location" not in resp.headers
        assert resp.headers["Cache-Control"] == "no-store"
        assert "img-src 'self' data:" in resp.headers["Content-Security-Policy"]
        begin.assert_awaited_once()

    def test_qr_generation_failure_after_a_ready_rotation_fails_closed_without_leaking_a_seed(
        self, authenticated_client
    ):
        with (
            _patch(
                "begin_totp_rotation",
                return_value=TotpRotationStartResult(TotpRotationStartOutcome.READY, NEW_SECRET),
            ),
            _patch("generate_totp_qr", side_effect=RuntimeError("qr encoder unavailable")),
            _patch("confirm_totp_rotation") as confirm,
        ):
            resp = _post_reset_start(authenticated_client)

        assert resp.status_code == 500
        assert NEW_SECRET not in resp.text
        assert "location" not in resp.headers
        assert resp.headers["Cache-Control"] == "no-store"
        assert "img-src 'self' data:" in resp.headers["Content-Security-Policy"]
        confirm.assert_not_awaited()

    def test_pool_timeout_during_rotation_confirmation_fails_closed_without_promoting(
        self, authenticated_client
    ):
        with _patch("confirm_totp_rotation", side_effect=PoolTimeout("pool exhausted")) as confirm:
            resp = _post_reset_confirm(authenticated_client)

        assert resp.status_code == 503
        assert NEW_SECRET not in resp.text
        assert "location" not in resp.headers
        assert resp.headers["Cache-Control"] == "no-store"
        confirm.assert_awaited_once()
