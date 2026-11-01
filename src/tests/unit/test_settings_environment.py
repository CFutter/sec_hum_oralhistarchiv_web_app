"""Settings examples and explicit process-environment selection contracts."""

import logging
import os
from pathlib import Path

import pytest

from app.paths import PROJECT_ROOT
from config.settings import Settings, warn_unconsumed_env_keys
from tests.unit.settings_builders import base_kwargs
from tests.unit.systemd_units import (
    WEB_SERVICE,
    environment_file_paths,
    start_guards_accept,
)

ENV_EXAMPLE = PROJECT_ROOT / ".env.example"

# Every omitted example key needs an explicit reason here to keep coverage deliberate.
_INTENTIONALLY_UNDOCUMENTED: set[str] = {
    # Retained solely to reject legacy service inputs and redact accidental values.
    "ADMIN_SEED_EMAIL",
    "ADMIN_SEED_PASSWORD",
}


def _parse_documented_keys(env_file: Path) -> set[str]:
    """Extract uppercased env assignment keys, ignoring blanks/comments and stripping optional export."""
    declared: set[str] = set()
    for line_raw in env_file.read_text().splitlines():
        line = line_raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        declared.add(key.upper())
    return declared


def _known_settings_keys() -> set[str]:
    """Collect uppercased Settings field names and explicit aliases."""
    known: set[str] = set()
    for name, field in Settings.model_fields.items():
        known.add(name.upper())
        alias = getattr(field, "alias", None)
        if alias:
            known.add(alias.upper())
    return known


class TestEnvExampleBijection:
    """`.env.example` and `Settings.model_fields` name exactly the same keys."""

    def test_env_example_documents_every_settings_field(self):
        """Direction 1: every Settings field appears in .env.example."""
        assert ENV_EXAMPLE.exists(), f".env.example not found at {ENV_EXAMPLE}"
        known = _known_settings_keys()
        documented = _parse_documented_keys(ENV_EXAMPLE)
        missing = known - documented - _INTENTIONALLY_UNDOCUMENTED
        assert missing == set(), (
            "Settings fields not documented in .env.example (add them there, or "
            "exempt them in _INTENTIONALLY_UNDOCUMENTED with a reason): "
            f"{sorted(missing)}"
        )

    def test_env_example_has_no_dead_keys(self):
        """Direction 2: no key in .env.example lacks a Settings field."""
        assert ENV_EXAMPLE.exists(), f".env.example not found at {ENV_EXAMPLE}"
        known = _known_settings_keys()
        documented = _parse_documented_keys(ENV_EXAMPLE)
        dead = documented - known
        assert dead == set(), (
            ".env.example documents keys no Settings field consumes "
            f"(dead config or typos — remove or fix them): {sorted(dead)}"
        )

    def test_warn_unconsumed_env_keys_flags_bogus_keys(self, tmp_path, monkeypatch, caplog):
        """The startup guard warns for each unconsumed .env key."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# a comment line — must be skipped\n"
            "\n"
            "THIS_LINE_HAS_NO_EQUALS_SIGN\n"
            "export SESSION_SECRET=abc\n"
            "DATABASE_URL=postgresql://x:y@localhost/db\n"
            "CACHE_PATH=/tmp/cache\n"
            "RATE_LIMIT_ENABELD=true\n"
        )
        # warn_unconsumed_env_keys reads the env-file path from model_config;
        # monkeypatch.setitem restores the original entry after the test.
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        records = [r for r in caplog.records if r.name == "config.settings"]
        warned_keys = {r.args[0] for r in records}
        assert warned_keys == {"CACHE_PATH", "RATE_LIMIT_ENABELD"}, (
            "Expected warnings for exactly the two unconsumed keys "
            f"(and none for consumed/skipped lines); got: {sorted(warned_keys)}"
        )
        typo_msgs = [r.getMessage() for r in records if r.args[0] == "RATE_LIMIT_ENABELD"]
        assert any("did you mean RATE_LIMIT_ENABLED" in msg for msg in typo_msgs), (
            f"Typo warning should carry a close-match hint; got: {typo_msgs}"
        )


class TestEnvExampleValues:
    """The canonical example constructs development Settings on its own."""

    def test_example_loads_without_shell_overrides(self, monkeypatch):
        """Check example loads without shell overrides."""
        known = _known_settings_keys()
        for name in tuple(os.environ):
            if name.upper() in known:
                monkeypatch.delenv(name)

        monkeypatch.setenv("ENV_STATE", "dev")
        configured = Settings(_env_file=ENV_EXAMPLE)

        assert configured.env_state == "dev"
        assert configured.shibboleth_enabled is False


class TestEnvironmentSelectionIsExplicit:
    """All launchers require an exact OS mode before application configuration."""

    def test_missing_process_mode_is_rejected(self, monkeypatch):
        """Check missing process mode is rejected (ValueError)."""
        monkeypatch.delenv("ENV_STATE", raising=False)
        with pytest.raises(ValueError, match="uppercase ENV_STATE"):
            Settings(_env_file=None, **base_kwargs())

    def test_the_production_service_refuses_that_same_absence(self):
        """Check the production service refuses that same absence."""
        environment_files = environment_file_paths(WEB_SERVICE)

        assert start_guards_accept(WEB_SERVICE, {}) is False
        assert (
            start_guards_accept(WEB_SERVICE, {environment_files[0]: {"ENV_STATE": "production"}})
            is True
        )
