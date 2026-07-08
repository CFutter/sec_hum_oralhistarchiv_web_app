"""Centralized structural paths for templates, static files, and project root."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR.parent
PROJECT_ROOT = BASE_DIR.parent.parent

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Source root (src/) — holds alembic.ini and the alembic/ migration dir.
ALEMBIC_INI = SRC_DIR / "alembic.ini"
ALEMBIC_DIR = SRC_DIR / "alembic"

GUNICORN_CONF = PROJECT_ROOT / "gunicorn.conf.py"