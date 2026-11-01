"""Operator bootstrap owns secret input and cannot leak it into service startup."""

import runpy
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.credentials import validate_seed_credentials
from app.paths import PROJECT_ROOT


@pytest.fixture
def command():
    """Load the bootstrap CLI without executing its __main__ entry point."""
    return runpy.run_path(str(PROJECT_ROOT / "scripts/bootstrap_admin.py"))


@pytest.mark.parametrize(
    "password",
    [
        "change-me-immediately-use-a-strong-password",
        "GENERATE_STRONG_INITIAL_ADMIN_PASSWORD",
        "REPLACE_WITH_STRONG_ADMIN_PASSWORD",
        "REPLACE_WITH_INITIAL_ADMIN_PASSWORD",
    ],
)
def test_published_passwords_are_rejected_by_shared_bootstrap_validation(password):
    """Published passwords are rejected by shared bootstrap validation."""
    with pytest.raises(ValueError, match="published example"):
        validate_seed_credentials("operator@example.org", password)


@pytest.mark.asyncio
async def test_placeholder_does_not_open_the_database(command, monkeypatch):
    """Placeholder does not open the database."""
    create = MagicMock()
    monkeypatch.setitem(command["bootstrap"].__globals__, "create_pool", create)
    with pytest.raises(ValueError, match="published example"):
        await command["bootstrap"]("operator@example.org", "GENERATE_STRONG_INITIAL_ADMIN_PASSWORD")
    create.assert_not_called()


@pytest.mark.asyncio
async def test_command_closes_pool_after_guarded_seed_failure(command, monkeypatch):
    """Command closes pool after guarded seed failure."""
    pool = MagicMock(open=AsyncMock(), close=AsyncMock())
    namespace = command["bootstrap"].__globals__
    seed = AsyncMock(side_effect=RuntimeError("database detail not for stdout"))
    monkeypatch.setitem(namespace, "create_pool", MagicMock(return_value=pool))
    monkeypatch.setitem(namespace, "warm_password_blocklist", MagicMock())
    monkeypatch.setitem(namespace, "seed_admin_user", seed)
    with pytest.raises(RuntimeError):
        await command["bootstrap"]("Operator@Example.ORG", "A9!new-random-bootstrap-passphrase")
    pool.open.assert_awaited_once()
    pool.close.assert_awaited_once()
    seed.assert_awaited_once_with(
        pool, "operator@example.org", "A9!new-random-bootstrap-passphrase"
    )


def test_noninteractive_command_never_reads_a_password(command, monkeypatch, capsys):
    """Noninteractive command never reads a password."""
    namespace = command["main"].__globals__
    monkeypatch.setattr(
        namespace["sys"], "argv", ["bootstrap_admin.py", "--email", "operator@example.org"]
    )
    monkeypatch.setattr(namespace["sys"].stdin, "isatty", lambda: False)
    prompt = MagicMock()
    monkeypatch.setattr(namespace["getpass"], "getpass", prompt)
    assert command["main"]() == 1
    prompt.assert_not_called()
    assert "interactive terminal" in capsys.readouterr().err


def test_interactive_failure_output_excludes_password_and_exception_details(
    command, monkeypatch, capsys
):
    """Interactive failure output excludes password and exception details."""
    namespace = command["main"].__globals__
    password = "Private-canary-secret-123456"
    monkeypatch.setattr(
        namespace["sys"], "argv", ["bootstrap_admin.py", "--email", "operator@example.org"]
    )
    monkeypatch.setattr(namespace["sys"].stdin, "isatty", lambda: True)
    monkeypatch.setattr(namespace["getpass"], "getpass", MagicMock(return_value=password))
    monkeypatch.setitem(namespace, "bootstrap", AsyncMock(side_effect=RuntimeError(password)))
    assert command["main"]() == 1
    output = capsys.readouterr()
    assert "Bootstrap failed" in output.err
    assert password not in output.out + output.err
