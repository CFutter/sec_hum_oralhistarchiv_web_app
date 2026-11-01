"""Source selectors validate syntax without opening source files in Settings."""

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from config.settings import Settings
from tests.unit.settings_builders import KWARGS_FOR_ENV, base_kwargs, make_settings


def test_unset_source_selection_remains_unselected_until_runtime(monkeypatch):
    """Check unset source selection remains unselected until runtime."""
    monkeypatch.delenv("SOURCES_CONFIG_FILE", raising=False)
    monkeypatch.delenv("ALLOW_FIXTURE_SOURCE", raising=False)
    kwargs = base_kwargs()
    del kwargs["sources_config_file"]
    del kwargs["allow_fixture_source"]

    settings = make_settings(**kwargs)

    assert settings.sources_config_file is None
    assert settings.allow_fixture_source is False


def test_empty_environment_source_path_remains_unselected_until_runtime(monkeypatch):
    """Check empty environment source path remains unselected until runtime."""
    monkeypatch.setenv("SOURCES_CONFIG_FILE", "")
    kwargs = base_kwargs()
    del kwargs["sources_config_file"]

    settings = make_settings(**kwargs)

    assert settings.sources_config_file is None


@pytest.mark.parametrize(
    "selected_path",
    ["fixtures/sources.toml", "/missing/source-selection/sources.toml"],
    ids=["relative", "absolute"],
)
def test_source_path_is_preserved_without_opening_it(selected_path):
    """Check source path is preserved without opening it."""
    with (
        patch.object(Path, "open", autospec=True) as open_file,
        patch("app.sources.load_sources_for_startup", autospec=True) as load_sources,
    ):
        settings = make_settings(**base_kwargs(sources_config_file=selected_path))

    assert settings.sources_config_file == selected_path
    open_file.assert_not_called()
    load_sources.assert_not_called()


@pytest.mark.parametrize(
    "selected_path",
    [" ", "\t", " fixtures/sources.toml", "fixtures/sources.toml "],
    ids=["space-only", "tab-only", "leading-space", "trailing-space"],
)
def test_source_path_rejects_whitespace_instead_of_silently_trimming(selected_path):
    """Check source path rejects whitespace instead of silently trimming (ValidationError)."""
    with pytest.raises(ValidationError, match=r"SOURCES_CONFIG_FILE.*surrounding whitespace"):
        make_settings(**base_kwargs(sources_config_file=selected_path))


@pytest.mark.parametrize("permitted", [True, False], ids=["enabled", "disabled"])
def test_fixture_permission_uses_the_explicit_environment_boolean(monkeypatch, permitted):
    """Check fixture permission uses the explicit environment boolean."""
    monkeypatch.setenv("ALLOW_FIXTURE_SOURCE", str(permitted).lower())
    kwargs = base_kwargs()
    del kwargs["allow_fixture_source"]

    settings = make_settings(**kwargs)

    assert settings.allow_fixture_source is permitted


def test_settings_builders_ignore_ambient_source_selectors(monkeypatch):
    """Check settings builders ignore ambient source selectors."""
    monkeypatch.setenv("SOURCES_CONFIG_FILE", "/ambient/production-sources.toml")
    monkeypatch.setenv("ALLOW_FIXTURE_SOURCE", "true")

    settings = make_settings(**base_kwargs())

    assert settings.sources_config_file is None
    assert settings.allow_fixture_source is False


class TestRetiredSeederSetting:
    """Cover retired seeder setting."""

    @pytest.mark.parametrize("key", ["seed_mock_data", "SEED_MOCK_DATA"])
    @pytest.mark.parametrize("value", [True, False, ""])
    def test_constructor_rejects_the_retired_key(self, key, value):
        """Check constructor rejects the retired key (ValidationError)."""
        with pytest.raises(ValidationError, match=r"SEED_MOCK_DATA.*removed"):
            make_settings(**base_kwargs(**{key: value}))

    @pytest.mark.parametrize("key", ["SEED_MOCK_DATA", "seed_mock_data"])
    @pytest.mark.parametrize(
        ("environment", "value"),
        [("dev", "true"), ("staging", "false"), ("production", "")],
    )
    def test_environment_rejects_the_retired_key(self, monkeypatch, key, environment, value):
        """Check environment rejects the retired key (ValidationError)."""
        monkeypatch.setenv("ENV_STATE", environment)
        monkeypatch.setenv(key, value)
        with pytest.raises(ValidationError, match=r"SEED_MOCK_DATA.*removed"):
            make_settings(**KWARGS_FOR_ENV[environment]())

    @pytest.mark.parametrize("key", ["SEED_MOCK_DATA", "seed_mock_data"])
    @pytest.mark.parametrize("value", ["true", "false", ""])
    def test_selected_dotenv_rejects_the_retired_key(self, tmp_path, key, value):
        """Check selected dotenv rejects the retired key (ValidationError)."""
        env_file = tmp_path / ".env"
        env_file.write_text(f'export {key}="{value}"\n', encoding="utf-8")
        with pytest.raises(ValidationError, match=r"SEED_MOCK_DATA.*removed"):
            Settings(_env_file=env_file, **base_kwargs())

    def test_the_retired_key_is_not_a_settings_field(self):
        """Check the retired key is not a settings field."""
        assert "seed_mock_data" not in Settings.model_fields

    def test_disabled_dotenv_does_not_read_a_retired_key(self, tmp_path, monkeypatch):
        """Check disabled dotenv does not read a retired key."""
        env_file = tmp_path / ".env"
        env_file.write_text("SEED_MOCK_DATA=true\n", encoding="utf-8")
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

        configured = Settings(_env_file=None, **base_kwargs())

        assert configured.env_state == "dev"

    def test_rejection_does_not_print_other_setting_values(self):
        """Check rejection does not print other setting values (ValidationError)."""
        canary = "PRIVATE-DATABASE-PASSWORD-CANARY"
        with pytest.raises(ValidationError, match=r"SEED_MOCK_DATA.*removed") as error:
            make_settings(
                **base_kwargs(
                    seed_mock_data=False,
                    database_url=f"postgresql://user:{canary}@localhost/archive_test",
                )
            )
        assert canary not in str(error.value)
        assert "SOURCES_CONFIG_FILE" in str(error.value)
