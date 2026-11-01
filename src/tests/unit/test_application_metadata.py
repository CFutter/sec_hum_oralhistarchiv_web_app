"""Installed and source-checkout version lookup share project metadata."""

import re
import tomllib
from importlib import metadata
from pathlib import Path

from app import version
from app.credentials import LOCAL_EMAIL_MAX_CHARS, LOCAL_PASSWORD_MAX_CHARS, TOTP_CODE_RAW_MAX_CHARS
from app.template_setup import templates


def _without_distribution(_name):
    """Raise PackageNotFoundError to exercise source-checkout version lookup."""
    raise metadata.PackageNotFoundError


def test_installed_version_is_authoritative(monkeypatch):
    """Installed version is authoritative."""
    monkeypatch.setattr(version.metadata, "version", lambda _name: "7.8.9")
    assert version.application_version() == "7.8.9"


def test_source_version_comes_from_project_toml(monkeypatch):
    """Source version comes from project toml."""
    monkeypatch.setattr(version.metadata, "version", _without_distribution)
    project_file = Path(version.__file__).resolve().parents[2] / "pyproject.toml"
    with project_file.open("rb") as stream:
        expected = tomllib.load(stream)["project"]["version"]
    assert version.application_version() == expected


def test_unpackaged_version_is_explicitly_unknown(monkeypatch, tmp_path):
    """Unpackaged version is explicitly unknown."""
    monkeypatch.setattr(version.metadata, "version", _without_distribution)
    monkeypatch.setattr(version, "__file__", str(tmp_path / "src/app/version.py"))
    assert version.application_version() == "0+unknown"


def test_templates_use_domain_specific_bounds():
    """Templates use domain specific bounds."""
    assert templates.env.globals["local_email_max_chars"] == LOCAL_EMAIL_MAX_CHARS
    assert templates.env.globals["local_password_max_chars"] == LOCAL_PASSWORD_MAX_CHARS
    assert templates.env.globals["totp_code_raw_max_chars"] == TOTP_CODE_RAW_MAX_CHARS


def test_all_totp_browser_patterns_accept_pasted_whitespace():
    # Browser constraint validation must not reject syntax accepted by services.
    """All TOTP browser patterns accept pasted whitespace."""
    template_dir = Path(version.__file__).resolve().parent / "templates"
    found = 0
    for template in template_dir.glob("*.html"):
        for field in re.findall(r"<input\b[^>]*>", template.read_text(encoding="utf-8"), re.S):
            if not re.search(r'name="(?:admin_|current_|new_)?totp_code"', field):
                continue
            found += 1
            assert 'maxlength="{{ totp_code_raw_max_chars }}"' in field, template.name
            pattern = re.search(r'pattern="([^"]+)"', field)
            assert pattern is not None, template.name
            expanded = pattern[1].replace(
                "{{ totp_code_raw_max_chars }}", str(TOTP_CODE_RAW_MAX_CHARS)
            )
            assert re.fullmatch(expanded, "123 456"), template.name
    assert found > 0


def test_password_hint_tracks_the_form_minimum():
    """Password hint tracks the form minimum."""
    template_file = Path(version.__file__).resolve().parent / "templates/reset_password.html"
    hint = re.search(r'<span class="form-hint">Minimum.*?</span>', template_file.read_text())
    assert hint is not None
    rendered = templates.env.from_string(hint[0]).render(local_password_min_chars=17)
    assert "Minimum 17 characters." in rendered
