"""Reject unusable durations at startup and before service side effects."""

from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch

import pytest
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import Response
from psycopg import AsyncConnection
from pydantic import ValidationError

from app.middleware import session as session_middleware
from app.middleware.session import set_session_cookie
from app.services import authentication, db, sessions, users
from app.sources.base import SourceSchedule
from app.sources.configuration import configure_sources_from_toml
from config import settings
from tests.fixtures import FakeCursorCtx, make_async_cursor, make_mock_pool
from tests.unit.settings_builders import base_kwargs, make_settings

_INTEGER_DURATION_BOUNDS = [
    ("session_max_age_seconds", 60, 31_536_000),
    ("login_lockout_minutes", 1, 10_080),
    ("unverified_reap_after_days", 1, 3650),
    ("outbox_sent_retention_days", 1, 3650),
    ("outbox_dead_retention_days", 1, 3650),
    ("outbox_retention_interval_seconds", 1, 60),
    ("outbox_stale_after_seconds", 60, 86_400),
]
_VALID_TIMEOUTS = ["0", "1ms", "5s", "500ms", "2min", "2147483647ms", "2147483s", "35791min"]
_INVALID_TIMEOUTS = [
    "0ms",
    "0s",
    "0min",
    "000ms",
    "00",
    "005s",
    "0500ms",
    "5s\n",
    "5s\r\n",
    " 5s",
    "5s ",
    "-5s",
    "+5s",
    "1.5s",
    "1e3s",
    "5 seconds",
    "1h",
    "",
    "\u0665s",
    "\uff15s",
    "2147483648ms",
    "2147484s",
    "35792min",
    pytest.param("9" * 5000 + "min", id="5000-digit-quantity"),
    True,
    0,
    None,
]
_INVALID_SESSION_AGES = [0, -1, 59, 31_536_001, 10**20, True, False, 60.0, "60"]


def test_existing_duration_defaults_are_unchanged(monkeypatch):
    """Existing duration defaults are unchanged."""
    defaults = {
        "session_max_age_seconds": 28_800,
        "login_lockout_minutes": 15,
        "unverified_reap_after_days": 7,
        "outbox_sent_retention_days": 7,
        "outbox_dead_retention_days": 30,
        "outbox_retention_interval_seconds": 60,
        "outbox_stale_after_seconds": 600,
        "db_statement_timeout": "5s",
        "scheduler_statement_timeout": "5min",
    }
    values = base_kwargs()
    for field in defaults:
        values.pop(field, None)
        monkeypatch.delenv(field.upper(), raising=False)
    configured = make_settings(**values)
    assert {field: getattr(configured, field) for field in defaults} == defaults


@pytest.mark.parametrize("field,minimum,maximum", _INTEGER_DURATION_BOUNDS)
@pytest.mark.parametrize("boundary", ["minimum", "maximum", "environment"])
def test_integer_duration_boundaries(field, minimum, maximum, boundary, monkeypatch):
    """Integer duration boundaries."""
    values = base_kwargs()
    if boundary == "environment":
        values.pop(field, None)
        monkeypatch.setenv(field.upper(), str(maximum))
        expected = maximum
    else:
        expected = minimum if boundary == "minimum" else maximum
        values[field] = expected
    assert getattr(make_settings(**values), field) == expected


@pytest.mark.parametrize("field,minimum,maximum", _INTEGER_DURATION_BOUNDS)
@pytest.mark.parametrize("invalid", ["below", "above", "huge", True, False, None])
def test_integer_duration_settings_reject_invalid_values(field, minimum, maximum, invalid):
    """Integer duration settings reject invalid values."""
    if invalid == "below":
        invalid = minimum - 1
    elif invalid == "above":
        invalid = maximum + 1
    elif invalid == "huge":
        invalid = 10**20
    with pytest.raises(ValidationError) as failure:
        make_settings(**base_kwargs(**{field: invalid}))
    assert any(error["loc"] == (field,) for error in failure.value.errors())


@pytest.mark.parametrize("field", ["db_statement_timeout", "scheduler_statement_timeout"])
@pytest.mark.parametrize("value", _VALID_TIMEOUTS)
def test_timeout_settings_accept_values_postgresql_can_use(field, value):
    """Timeout settings accept values postgresql can use."""
    assert getattr(make_settings(**base_kwargs(**{field: value})), field) == value


@pytest.mark.parametrize("field", ["db_statement_timeout", "scheduler_statement_timeout"])
@pytest.mark.parametrize("value", _INVALID_TIMEOUTS)
def test_timeout_settings_reject_zero_units_malformed_and_overflowing_values(field, value):
    """Timeout settings reject zero units malformed and overflowing values."""
    with pytest.raises(ValidationError) as failure:
        make_settings(**base_kwargs(**{field: value}))
    assert any(error["loc"] == (field,) for error in failure.value.errors())


@pytest.mark.parametrize("field", ["db_statement_timeout", "scheduler_statement_timeout"])
@pytest.mark.parametrize("value", ["2147483647ms", "0s", "2147483648ms", "5s\n"])
def test_timeout_environment_values_use_same_contract(field, value, monkeypatch):
    """Timeout environment values use same contract."""
    values = base_kwargs()
    values.pop(field, None)
    monkeypatch.setenv(field.upper(), value)
    if value == "2147483647ms":
        assert getattr(make_settings(**values), field) == value
    else:
        with pytest.raises(ValidationError):
            make_settings(**values)


@pytest.mark.parametrize("value", [value for value in _INVALID_TIMEOUTS if value is not None])
def test_pool_override_fails_before_pool_construction(value):
    """Pool override fails before pool construction."""
    with patch.object(db, "AsyncConnectionPool", autospec=True) as construct:
        with pytest.raises(ValueError, match="statement_timeout"):
            db.create_pool(statement_timeout=value)
        construct.assert_not_called()


@pytest.mark.parametrize("explicit_none", [False, True])
async def test_pool_default_timeout_keeps_none_semantics(explicit_none, monkeypatch):
    """Pool default timeout keeps None semantics."""
    monkeypatch.setattr(settings, "db_statement_timeout", "2min")
    with patch.object(db, "AsyncConnectionPool", autospec=True) as construct:
        db.create_pool(**({"statement_timeout": None} if explicit_none else {}))
        configure = construct.call_args.kwargs["configure"]
    connection = create_autospec(AsyncConnection, instance=True, spec_set=True)
    await configure(connection)
    assert connection.execute.await_args_list[1].args[0].as_string() == (
        "SET statement_timeout = '2min'"
    )


@pytest.mark.parametrize("value", _VALID_TIMEOUTS)
async def test_pool_applies_validated_timeout_to_each_connection(value):
    """Pool applies validated timeout to each connection."""
    with patch.object(db, "AsyncConnectionPool", autospec=True) as construct:
        assert db.create_pool(statement_timeout=value) is construct.return_value
        configure = construct.call_args.kwargs["configure"]
    for _ in range(2):
        connection = create_autospec(AsyncConnection, instance=True, spec_set=True)
        await configure(connection)
        assert [call.args[0] for call in connection.set_autocommit.await_args_list] == [True, False]
        assert connection.execute.await_args_list[1].args[0].as_string() == (
            f"SET statement_timeout = '{value}'"
        )


@pytest.mark.parametrize("value", _INVALID_SESSION_AGES)
async def test_session_cursor_override_rejected_before_token_or_sql(value):
    """Session cursor override rejected before token or SQL."""
    cursor = make_async_cursor()
    with patch.object(sessions.secrets, "token_urlsafe", autospec=True) as token:
        with pytest.raises(ValueError, match="max_age_seconds"):
            await sessions.create_session_cur(
                cursor, user_id=7, ip_address="127.0.0.1", purpose="full", max_age_seconds=value
            )
        token.assert_not_called()
    cursor.execute.assert_not_awaited()


@pytest.mark.parametrize("value", _INVALID_SESSION_AGES)
async def test_session_wrapper_rejects_override_before_acquiring_connection(value):
    """Session wrapper rejects override before acquiring connection."""
    with patch.object(sessions, "get_db_cursor", autospec=True) as acquire:
        with pytest.raises(ValueError, match="max_age_seconds"):
            await sessions.create_session(make_mock_pool(), 7, "127.0.0.1", max_age_seconds=value)
        acquire.assert_not_called()


@pytest.mark.parametrize("value", _INVALID_SESSION_AGES)
def test_cookie_override_rejected_before_signing_or_mutating_headers(value):
    """Cookie override rejected before signing or mutating headers."""
    response = Response()
    before = list(response.raw_headers)
    with patch.object(session_middleware, "SESSION_SIGNER", autospec=True) as signer:
        with pytest.raises(ValueError, match="max_age_seconds"):
            set_session_cookie(response, "raw-session", max_age_seconds=value)
        signer.dumps.assert_not_called()
    assert response.raw_headers == before


@pytest.mark.parametrize("value", [60, 300, 31_536_000])
async def test_valid_session_and_cookie_lifetimes_agree(value):
    """Valid session and cookie lifetimes agree."""
    cursor = make_async_cursor()
    raw = await sessions.create_session_cur(
        cursor, user_id=7, ip_address="127.0.0.1", purpose="full", max_age_seconds=value
    )
    stored_hash, user_id, lifetime, ip, purpose = cursor.execute.await_args.args[1]
    assert stored_hash == sessions.hash_session_id(raw)
    assert (user_id, ip, purpose) == (7, "127.0.0.1", "full")
    assert lifetime == value
    response = Response()
    set_session_cookie(response, raw, max_age_seconds=value)
    assert f"Max-Age={value}" in response.headers["set-cookie"]


@pytest.mark.parametrize("value", [None, 60, 300, 31_536_000])
async def test_session_wrapper_keeps_default_and_override_signature(value, monkeypatch):
    """Session wrapper keeps default and override signature."""
    monkeypatch.setattr(settings, "session_max_age_seconds", 3600)
    cursor = make_async_cursor()
    with patch.object(
        sessions,
        "get_db_cursor",
        autospec=True,
        return_value=FakeCursorCtx(cursor),
    ):
        raw = await sessions.create_session(make_mock_pool(), 7, "127.0.0.1", value, "full")
    assert cursor.execute.await_args.args[1][0] == sessions.hash_session_id(raw)
    expected = 3600 if value is None else value
    lifetime = cursor.execute.await_args.args[1][2]
    assert lifetime == expected
    response = Response()
    set_session_cookie(response, raw, max_age_seconds=value)
    assert f"Max-Age={expected}" in response.headers["set-cookie"]


@pytest.mark.parametrize("value", [0, -1, 3651, 10**20, True, False, 1.0, "1"])
async def test_reaper_rejects_override_before_acquiring_connection(value):
    """Reaper rejects override before acquiring connection."""
    with patch.object(users, "get_db_cursor", autospec=True) as acquire:
        with pytest.raises(ValueError, match="max_age_days"):
            await users.reap_unverified_accounts(make_mock_pool(), max_age_days=value)
        acquire.assert_not_called()


@pytest.mark.parametrize("value", [None, 1, 3650])
async def test_reaper_keeps_default_and_valid_override(value, monkeypatch):
    """Reaper keeps default and valid override."""
    monkeypatch.setattr(settings, "unverified_reap_after_days", 7)
    cursor = make_async_cursor(fetchall=[])
    with patch.object(
        users,
        "get_db_cursor",
        autospec=True,
        return_value=FakeCursorCtx(cursor),
    ):
        assert await users.reap_unverified_accounts(make_mock_pool(), max_age_days=value) == 0
    assert cursor.execute.await_args.args[1] == (
        7 if value is None else value,
        users._REAP_BATCH_SIZE,
    )


async def test_maximum_configured_lockout_is_representable(monkeypatch):
    """Maximum configured lockout is representable."""
    configured = make_settings(**base_kwargs(login_lockout_minutes=10_080))
    monkeypatch.setattr(settings, "login_lockout_minutes", configured.login_lockout_minutes)
    monkeypatch.setattr(settings, "login_failure_threshold", 1)
    now = datetime(2031, 1, 1, tzinfo=UTC)
    cursor = make_async_cursor(
        fetchone=[
            {"failed_login_count": 0, "locked_until": None},
            {"database_now": now},
            {"failed_login_count": 1, "locked_until": now + timedelta(days=7)},
        ]
    )
    assert await authentication.record_login_failure_cur(cursor, 7, expected_auth_revision=1) == (
        1,
        True,
    )
    assert cursor.execute.await_args.args[1][1] == now + timedelta(days=7)


@pytest.mark.parametrize("field", ["incremental_interval_seconds", "rebuild_interval_seconds"])
@pytest.mark.parametrize("value", [1, 31_536_000])
def test_source_schedule_boundaries_construct_real_scheduler_intervals(field, value):
    """Source schedule boundaries construct real scheduler intervals."""
    configured = SourceSchedule.model_validate({field: value})
    now = datetime(2031, 1, 1, tzinfo=UTC)
    trigger = IntervalTrigger(seconds=getattr(configured, field), start_date=now, timezone=UTC)
    assert trigger.get_next_fire_time(now, now) == now + timedelta(seconds=value)


@pytest.mark.parametrize("field", ["incremental_interval_seconds", "rebuild_interval_seconds"])
@pytest.mark.parametrize("value", [0, 31_536_001, 10**20, True, False, 1.0, "1"])
def test_source_schedule_rejects_overflow_and_noninteger_intervals(field, value):
    """Source schedule rejects overflow and noninteger intervals."""
    with pytest.raises(ValidationError):
        SourceSchedule.model_validate({field: value})


@pytest.mark.parametrize("field", ["incremental_interval_seconds", "rebuild_interval_seconds"])
@pytest.mark.parametrize("value", ["31536000", "31536001", "true"])
def test_source_toml_loader_enforces_schedule_limits(field, value):
    """Source toml loader enforces schedule limits."""
    document = (
        '[[sources]]\nname="fixture_demo"\nadapter="fixture"\n'
        'label="Synthetic examples"\ndataset="catalogue_v1"\n'
        f"{field}={value}\n"
    )
    if value == "31536000":
        source = configure_sources_from_toml(document)[0]
        assert getattr(source.schedule, field) == 31_536_000
    else:
        with pytest.raises(ValueError):
            configure_sources_from_toml(document)
