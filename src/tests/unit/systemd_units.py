"""Approximate shipped unit directives for tests; this is not a systemd parser.

Strip hash tails, split commands on whitespace and expand only whole-token
variables; brace and bare references both split their values. Quoting, command
prefixes, reset semantics, specifiers and systemd execution context are not
modeled. Guards run as subprocesses with the test process environment.
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
    """Read with default text encoding, strip hash tails and return matching directive values in
    order.
    """
    text = "\n".join(line.split("#", 1)[0] for line in path.read_text().splitlines())
    return re.findall(rf"(?m)^\s*{re.escape(name)}=(.*?)\s*$", text)


def environment_file_paths(unit: Path) -> list[str]:
    """Return EnvironmentFile values in order, removing one optional-file hyphen."""
    return [value.removeprefix("-") for value in unit_directives(unit, "EnvironmentFile")]


def effective_environment(unit: Path, file_contents: dict[str, dict[str, str]]) -> dict[str, str]:
    """Merge parsed Environment assignments then supplied file mappings; missing files contribute
    nothing.
    """
    environment: dict[str, str] = {}
    for assignment in unit_directives(unit, "Environment"):
        name, _, value = assignment.partition("=")
        environment[name.strip()] = value.strip()
    for path in environment_file_paths(unit):
        environment.update(file_contents.get(path, {}))
    return environment


def command_words(raw_directive: str, environment: dict[str, str]) -> list[str]:
    """Split whitespace and expand whole-token $NAME/${NAME}; split either value and omit empty
    ones.
    """
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
    """Run parsed ExecStartPre commands with inherited test environment; return False at first
    nonzero exit.

    Require absolute existing executables or raise AssertionError; OS/subprocess
    errors propagate. Configured unit environment only expands command arguments;
    it is not passed as the child environment. No timeout is imposed.
    """
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
