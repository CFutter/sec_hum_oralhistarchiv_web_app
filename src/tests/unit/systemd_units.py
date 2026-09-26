"""Helpers for reading the shipped systemd units and running their checks.

Shared by the deployment-unit contract tests and the settings tests, which
both need to know what a unit's processes would actually see at start time.
The rules modelled here are systemd's own: ``Environment=`` is applied first
and every ``EnvironmentFile=`` afterwards in the order written, so a later
file wins; a command line's ``${NAME}`` or ``$NAME`` word is replaced by the
variable's value and split into words, with an unset or empty variable
contributing nothing; and ``ExecStartPre=`` commands run before the main
process, which never starts if one of them exits non-zero.
"""

import re
import subprocess
from pathlib import Path

from app.paths import PROJECT_ROOT

WEB_SERVICE = PROJECT_ROOT / "oralhistarchiv.service"
SCHEDULER_SERVICE = PROJECT_ROOT / "oralhistarchiv-scheduler.service"
MIGRATION_SERVICE = PROJECT_ROOT / "oralhistarchiv-migrate.service"

_VARIABLE_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def unit_directives(path: Path, name: str) -> list[str]:
    """Every value a unit assigns to one directive, in file order."""
    text = "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())
    return re.findall(rf"(?m)^\s*{re.escape(name)}=(.*?)\s*$", text)


def environment_file_paths(unit: Path) -> list[str]:
    """The environment files a unit loads, in order, without systemd's
    leading '-' (which only marks a file as optional)."""
    return [value.removeprefix("-") for value in unit_directives(unit, "EnvironmentFile")]


def effective_environment(unit: Path, file_contents: dict[str, dict[str, str]]) -> dict[str, str]:
    """The environment a unit's processes would actually see.

    ``file_contents`` maps a path named by the unit to the assignments that
    file makes; a file left out contributes nothing.
    """
    environment: dict[str, str] = {}
    for assignment in unit_directives(unit, "Environment"):
        name, _, value = assignment.partition("=")
        environment[name.strip()] = value.strip()
    for path in environment_file_paths(unit):
        environment.update(file_contents.get(path, {}))
    return environment


def command_words(raw_directive: str, environment: dict[str, str]) -> list[str]:
    """Expand a unit command line the way systemd does before running it."""
    words: list[str] = []
    for token in raw_directive.split():
        reference = _VARIABLE_REFERENCE.fullmatch(token)
        if reference is None:
            words.append(token)
            continue
        name = reference.group(1) or reference.group(2)
        words.extend(environment.get(name, "").split())
    return words


def start_guards_accept(unit: Path, file_contents: dict[str, dict[str, str]]) -> bool:
    """Run the unit's start checks and report whether its process would start."""
    environment = effective_environment(unit, file_contents)
    for guard in unit_directives(unit, "ExecStartPre"):
        words = command_words(guard, environment)
        if not words:
            continue
        executable = Path(words[0])
        assert executable.is_absolute() and executable.is_file(), (
            f"{unit.name} names a start check this host cannot run as written: {words[0]!r}. "
            "A systemd prefix such as '-' belongs to the directive, not to the program."
        )
        completed = subprocess.run(words, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            return False
    return True
