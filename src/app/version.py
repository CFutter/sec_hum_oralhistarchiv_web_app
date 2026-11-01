"""Application version from its installed distribution or source project metadata."""

import tomllib
from importlib import metadata
from pathlib import Path

_DISTRIBUTION = "Oral-History-Archive"


def application_version() -> str:
    """Return installed version, matching pyproject version, or '0+unknown'.

    Read pyproject.toml only if the distribution is absent; file and TOML errors
    propagate.
    """
    try:
        return metadata.version(_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        project_file = Path(__file__).resolve().parents[2] / "pyproject.toml"
        if project_file.is_file():
            with project_file.open("rb") as stream:
                project = tomllib.load(stream).get("project", {})
            if project.get("name") == _DISTRIBUTION and isinstance(project.get("version"), str):
                return str(project["version"])
        return "0+unknown"
