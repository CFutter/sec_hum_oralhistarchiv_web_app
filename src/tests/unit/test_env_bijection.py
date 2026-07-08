"""Backlog §7.1 — `.env.example` <-> Settings model bijection (both directions).

Guards the config-hygiene cluster: a Settings field added without documenting
it in `.env.example` (e.g. the missing prod-mandatory RATE_LIMIT_TRUST_PROXY),
and dead/typo'd keys lingering in the example (e.g. the historical CACHE_PATH)
that `extra="ignore"` would swallow silently at startup.

The example file is parsed with EXACTLY the same rules as the startup guard
`config.settings.warn_unconsumed_env_keys` (skip blank/comment/no-'=' lines,
strip an 'export ' prefix, uppercase the key), so the test and the runtime
check cannot drift apart on what counts as a "documented" key. A third test
pins the runtime guard itself against a temp .env with a bogus key.

Pure unit tests: no DB, no app, no async (backlog §7.1 "add these now").
"""

import logging
from pathlib import Path

from app.paths import PROJECT_ROOT
from config.settings import Settings, warn_unconsumed_env_keys

ENV_EXAMPLE = PROJECT_ROOT / ".env.example"

# Settings fields deliberately NOT documented in .env.example.
#
# This allowlist is the design element that makes these tests fail only on
# REAL drift: adding a Settings field forces a conscious choice — document it
# in .env.example, or exempt it HERE with an inline comment explaining WHY it
# is intentionally undocumented (e.g. an OS-environment-only field that must
# never live in a .env file). Never add a key here without a reason.
_INTENTIONALLY_UNDOCUMENTED: set[str] = set()


def _parse_documented_keys(env_file: Path) -> set[str]:
    """Parse an env file exactly like warn_unconsumed_env_keys does.

    Mirrors config.settings.warn_unconsumed_env_keys line by line: skip
    blank lines, comments, and lines without '='; take the text before the
    first '='; strip a leading 'export '; uppercase.
    """
    declared: set[str] = set()
    for line_raw in env_file.read_text().splitlines():
        line = line_raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        declared.add(key.upper())
    return declared


def _known_settings_keys() -> set[str]:
    """Uppercased Settings field names plus any explicit field aliases.

    Same "known" set warn_unconsumed_env_keys builds from
    Settings.model_fields — the single source of truth for both directions.
    """
    known: set[str] = set()
    for name, field in Settings.model_fields.items():
        known.add(name.upper())
        alias = getattr(field, "alias", None)
        if alias:
            known.add(alias.upper())
    return known


def test_env_example_documents_every_settings_field():
    """§7.1 direction 1: every Settings field appears in .env.example.

    Regression guarded: adding a config field (like RATE_LIMIT_TRUST_PROXY,
    which is mandatory in production) without documenting it in the example,
    leaving operators no discoverable record that the knob exists.
    """
    assert ENV_EXAMPLE.exists(), f".env.example not found at {ENV_EXAMPLE}"
    known = _known_settings_keys()
    documented = _parse_documented_keys(ENV_EXAMPLE)
    missing = known - documented - _INTENTIONALLY_UNDOCUMENTED
    assert missing == set(), (
        "Settings fields not documented in .env.example (add them there, or "
        "exempt them in _INTENTIONALLY_UNDOCUMENTED with a reason): "
        f"{sorted(missing)}"
    )


def test_env_example_has_no_dead_keys():
    """§7.1 direction 2: no key in .env.example lacks a Settings field.

    Regression guarded: dead config (the historical CACHE_PATH) or typos of
    real keys surviving in the example — extra='ignore' means anyone copying
    the example gets the key silently dropped and the field's default used.
    """
    assert ENV_EXAMPLE.exists(), f".env.example not found at {ENV_EXAMPLE}"
    known = _known_settings_keys()
    documented = _parse_documented_keys(ENV_EXAMPLE)
    dead = documented - known
    assert dead == set(), (
        ".env.example documents keys no Settings field consumes "
        f"(dead config or typos — remove or fix them): {sorted(dead)}"
    )


def test_warn_unconsumed_env_keys_flags_bogus_keys(tmp_path, monkeypatch, caplog):
    """§7.1 mirror pin: the startup guard warns for each unconsumed .env key.

    Regression guarded: warn_unconsumed_env_keys silently passing dead keys
    or typos (the runtime counterpart of test_env_example_has_no_dead_keys).
    The temp .env exercises every parse rule the two set-comparison tests
    rely on — blank lines, comments, a no-'=' line, an 'export ' prefix —
    so this test also fails if the runtime parser and _parse_documented_keys
    ever diverge. Also pins the difflib "did you mean" typo hint.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# a comment line — must be skipped\n"
        "\n"
        "THIS_LINE_HAS_NO_EQUALS_SIGN\n"
        "export SESSION_SECRET=abc\n"  # consumed (real field) — no warning
        "DATABASE_URL=postgresql://x:y@localhost/db\n"  # consumed — no warning
        "CACHE_PATH=/tmp/cache\n"  # dead key — must warn
        "RATE_LIMIT_ENABELD=true\n"  # typo of RATE_LIMIT_ENABLED — must warn + hint
    )
    # warn_unconsumed_env_keys reads the env-file path from model_config;
    # monkeypatch.setitem restores the original entry after the test.
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

    with caplog.at_level(logging.WARNING, logger="config.settings"):
        warn_unconsumed_env_keys()

    records = [r for r in caplog.records if r.name == "config.settings"]
    # logger.warning("Unconsumed .env key: %s%s", key, hint) -> args[0] is the key.
    warned_keys = {r.args[0] for r in records}
    assert warned_keys == {"CACHE_PATH", "RATE_LIMIT_ENABELD"}, (
        "Expected warnings for exactly the two unconsumed keys "
        f"(and none for consumed/skipped lines); got: {sorted(warned_keys)}"
    )
    typo_msgs = [r.getMessage() for r in records if r.args[0] == "RATE_LIMIT_ENABELD"]
    assert any(
        "did you mean RATE_LIMIT_ENABLED" in msg for msg in typo_msgs
    ), f"Typo warning should carry a close-match hint; got: {typo_msgs}"
