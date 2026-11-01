"""The optional backup marker setting is a path, never a startup file dependency."""

import pytest
from pydantic import ValidationError

from tests.unit.settings_builders import base_kwargs, make_settings


def test_backup_status_file_defaults_to_disabled(monkeypatch):
    """Backup status file defaults to disabled."""
    monkeypatch.delenv("BACKUP_STATUS_FILE", raising=False)
    assert make_settings(**base_kwargs()).backup_status_file is None


@pytest.mark.parametrize("value", [None, "/var/lib/oralhistarchiv-backup-status/last-success"])
def test_optional_absolute_marker_does_not_need_to_exist(value):
    """Optional absolute marker does not need to exist."""
    assert make_settings(**base_kwargs(backup_status_file=value)).backup_status_file == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "last-success",
        "./last-success",
        "~/last-success",
        "/",
        "//var/lib/marker",
        "/var/lib/../marker",
        "/var/./marker",
        "/var//marker",
        "/var/lib/",
        "/var/lib/marker\n",
        "/var/lib/marker\x00",
        "/var/lib/marker\x7f",
        "/" + "x" * 4096,
        42,
        True,
        ["/var/lib/marker"],
    ],
)
def test_marker_setting_rejects_ambiguous_or_nonstring_paths(value):
    """Marker setting rejects ambiguous or nonstring paths."""
    with pytest.raises(ValidationError, match=r"backup_status_file|BACKUP_STATUS_FILE"):
        make_settings(**base_kwargs(backup_status_file=value))
