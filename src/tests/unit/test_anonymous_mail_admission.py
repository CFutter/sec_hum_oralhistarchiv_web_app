"""Anonymous mail admission uses bounded noncascading history and keyed recipients."""

from unittest.mock import create_autospec

import pytest
from psycopg import AsyncCursor

from app.services import mail_issuance


@pytest.mark.parametrize(
    ("field", "value", "allowed"),
    [
        ("global_day", 1_999, True),
        ("global_day", 2_000, False),
        ("global_hour", 499, True),
        ("global_hour", 500, False),
        ("recipient_hour", 4, True),
        ("recipient_hour", 5, False),
        ("recipient_recent", 0, True),
        ("recipient_recent", 1, False),
    ],
)
async def test_each_mail_budget_has_an_enforced_boundary(field, value, allowed):
    """Each mail budget has an enforced boundary."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    row = dict.fromkeys(("global_day", "global_hour", "recipient_hour", "recipient_recent"), 0)
    row[field] = value
    cursor.fetchone.side_effect = [{"admitted": True}, row]
    assert (
        await mail_issuance.anonymous_mail_issuance_allowed_cur(cursor, "owner@example.org")
        is allowed
    )
    timeout, lock, cleanup, count = cursor.execute.await_args_list
    assert "lock_timeout" in timeout.args[0]
    assert "pg_try_advisory_xact_lock" in lock.args[0]
    assert "LIMIT %s" in cleanup.args[0] and cleanup.args[1] == (100,)
    assert "anonymous_mail_issuance" in cleanup.args[0]
    assert "status" not in count.args[0] and "email_outbox" not in count.args[0]
    assert "owner@example.org" not in repr(count.args)
    assert len(count.args[1]["recipient"]) == 64
    assert count.args[1]["recipient"] == mail_issuance._recipient_key(" OWNER@EXAMPLE.ORG ")


async def test_mail_admission_fails_closed_on_storage_failure():
    """Mail admission fails closed on storage failure."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.execute.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        await mail_issuance.anonymous_mail_issuance_allowed_cur(cursor, "owner@example.org")
    cursor.fetchone.assert_not_awaited()


async def test_mail_admission_contention_is_a_generic_noop_without_another_query():
    """Mail admission contention is a generic noop without another query."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    cursor.fetchone.return_value = {"admitted": False}
    assert not await mail_issuance.anonymous_mail_issuance_allowed_cur(cursor, "owner@example.org")
    assert cursor.execute.await_count == 2


async def test_issuance_records_only_a_keyed_recipient_without_account_or_outbox_identity():
    """Issuance records only a keyed recipient without account or outbox identity."""
    cursor = create_autospec(AsyncCursor, instance=True, spec_set=True)
    await mail_issuance.record_mail_issuance_cur(cursor, "owner@example.org")
    statement, values = cursor.execute.await_args.args
    assert "anonymous_mail_issuance" in statement
    assert "user_id" not in statement and "outbox" not in statement
    assert "owner@example.org" not in repr(values)
    assert len(values[1]) == 64 and values[1] == mail_issuance._recipient_key("OWNER@example.org")
