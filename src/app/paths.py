"""Resolve filesystem asset paths on import; direct zip imports are unsupported.

Migration assets prefer the installed bundle, then an explicit source checkout.
Missing/incomplete migrations raise RuntimeError.
"""

from importlib.resources import files
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR.parent
PROJECT_ROOT = BASE_DIR.parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


def _migration_paths() -> tuple[Path, Path]:
    """Return (INI path, script directory), preferring bundled assets;
    raise RuntimeError if missing.
    """
    bundled = files("app").joinpath("_migration_assets")
    if isinstance(bundled, Path) and bundled.is_dir():
        ini = bundled / "alembic.ini"
        scripts = bundled / "alembic"
    elif SRC_DIR.name == "src" and (PROJECT_ROOT / "pyproject.toml").is_file():
        ini = SRC_DIR / "alembic.ini"
        scripts = SRC_DIR / "alembic"
    else:
        raise RuntimeError(
            "Application migration assets are missing; reinstall the application wheel"
        )
    if (
        not ini.is_file()
        or not (scripts / "env.py").is_file()
        or not (scripts / "versions").is_dir()
    ):
        raise RuntimeError("Application migration assets are incomplete")
    return ini, scripts


ALEMBIC_INI, ALEMBIC_DIR = _migration_paths()
