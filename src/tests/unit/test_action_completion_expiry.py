"""Raw action capabilities are revalidated after the final account lock."""

from unittest.mock import create_autospec

import pytest
from itsdangerous import TimestampSigner

from app.services import email_change, password_reset
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool

_USER_ID = 7
_EMAIL = "member@example.org"
_NEW_EMAIL = "updated@example.org"
_NEW_PASSWORD = "Celestial-Forests-824!Snow"


def _issue(flow):
    """Issue the reset token for "reset"; otherwise issue the email-change token."""
    if flow == "reset":
        return password_reset.generate_reset_token(_USER_ID, _EMAIL)
    return email_change.generate_email_change_token(_USER_ID, _NEW_EMAIL, auth_revision=0)


async def _complete(flow, pool, token):
    """Complete the selected flow; successful password reset returns True."""
    if flow == "reset":
        await password_reset.update_password_with_token(
            pool, _USER_ID, token, _NEW_PASSWORD, expected_email=_EMAIL, totp_code="123456"
        )
        return True
    return await email_change.confirm_email_change(
        pool, _USER_ID, _NEW_EMAIL, token, expected_auth_revision=0
    )


@pytest.mark.parametrize("flow", ["reset", "email_change"])
@pytest.mark.parametrize("expires_while_waiting", [False, True])
async def test_signed_expiry_is_checked_after_account_lock(
    monkeypatch, flow, expires_while_waiting
):
    """Signed expiry is checked after account lock."""
    module = password_reset if flow == "reset" else email_change
    clock = [1_800_000_000]
    monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda _self: clock[0])
    token = _issue(flow)
    snapshot = {
        "email": _EMAIL,
        "display_name": "Mira Cole",
        "password_hash": "old-hash",
        "auth_revision": 0,
    }
    rows = ([snapshot, {**snapshot, "id": _USER_ID}] if flow == "reset" else [{"id": _USER_ID}]) + [
        {"id": _USER_ID}
    ]
    cur = make_async_cursor(fetchone=rows)

    async def execute(statement, _params):
        """Advance the fake clock past token expiry while acquiring the account lock."""
        if "FOR UPDATE" in statement and expires_while_waiting:
            # A real signature remains valid initially, but expires while locking.
            clock[0] += module._ACTION_TOKEN.max_age + 1

    cur.execute.side_effect = execute
    monkeypatch.setattr(
        module,
        "get_db_cursor",
        create_autospec(module.get_db_cursor, return_value=FakeCursorCtx(cur)),
    )
    delete = create_autospec(module.delete_user_sessions_cur)
    invalidate = create_autospec(module.invalidate_pending_authentication_state_cur)
    monkeypatch.setattr(module, "delete_user_sessions_cur", delete)
    monkeypatch.setattr(module, "invalidate_pending_authentication_state_cur", invalidate)
    if flow == "reset":
        monkeypatch.setattr(
            password_reset,
            "_is_same_as_current_password",
            create_autospec(password_reset._is_same_as_current_password, return_value=False),
        )
        monkeypatch.setattr(
            password_reset,
            "run_password_work",
            create_autospec(password_reset.run_password_work, return_value="new-hash"),
        )
    if flow == "reset":
        monkeypatch.setattr(
            password_reset,
            "verify_and_consume_totp_cur",
            create_autospec(password_reset.verify_and_consume_totp_cur, return_value=True),
        )
        monkeypatch.setattr(
            password_reset,
            "enqueue_outbound_email_cur",
            create_autospec(password_reset.enqueue_outbound_email_cur),
        )
    pool = make_mock_pool()
    if expires_while_waiting and flow == "reset":
        with pytest.raises(password_reset.InvalidResetToken):
            await _complete(flow, pool, token)
    else:
        assert await _complete(flow, pool, token) is (not expires_while_waiting)
    mutations = [
        call
        for call in cur.execute.await_args_list
        if call.args[0].lstrip().startswith("UPDATE")
        and "password_reset_attempt_count" not in call.args[0]
    ]
    if expires_while_waiting:
        assert not mutations
        delete.assert_not_awaited()
        invalidate.assert_not_awaited()
    else:
        assert len(mutations) == 1
        assert "clock_timestamp()" in mutations[0].args[0]
        delete.assert_awaited_once_with(cur, _USER_ID)
        invalidate.assert_awaited_once_with(cur, _USER_ID)


@pytest.mark.parametrize("flow", ["reset", "email_change"])
@pytest.mark.parametrize("defect", ["tampered", "wrong_user", "wrong_address", "wrong_revision"])
async def test_action_completion_rejects_wrong_signed_identity_before_database(
    monkeypatch, flow, defect
):
    """Action completion rejects wrong signed identity before database."""
    module = password_reset if flow == "reset" else email_change
    if flow == "reset":
        # Reset has no signed revision; a different signature domain is invalid too.
        token = (
            email_change.generate_email_change_token(_USER_ID, _NEW_EMAIL, auth_revision=0)
            if defect == "wrong_revision"
            else password_reset.generate_reset_token(
                _USER_ID + 1 if defect == "wrong_user" else _USER_ID,
                "different@example.org" if defect == "wrong_address" else _EMAIL,
            )
        )
    else:
        token = email_change.generate_email_change_token(
            _USER_ID + 1 if defect == "wrong_user" else _USER_ID,
            "different@example.org" if defect == "wrong_address" else _NEW_EMAIL,
            auth_revision=1 if defect == "wrong_revision" else 0,
        )
    if defect == "tampered":
        token += "invalid"
    cursor = create_autospec(module.get_db_cursor)
    monkeypatch.setattr(module, "get_db_cursor", cursor)
    if flow == "reset":
        with pytest.raises(password_reset.InvalidResetToken):
            await _complete(flow, make_mock_pool(), token)
    else:
        assert not await _complete(flow, make_mock_pool(), token)
    cursor.assert_not_called()
