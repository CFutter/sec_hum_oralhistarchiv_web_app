#!/usr/bin/env bash
# Run from the repository root; downloads/runs the uv installer only if uv is absent.
# Creates .env from .env.example only when absent, replacing its DATABASE_URL
# with the devcontainer database URL; an existing .env is untouched.
# Installs locked dev/doc dependencies for Python 3.11; does not migrate or start services.
set -euo pipefail

echo "🚀 Starting DevContainer setup..."

if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="${UV_INSTALL_DIR:-$HOME/.local/bin}:$PATH"

if [[ ! -e .env ]]; then
    cp .env.example .env
    python3 - <<'PY'
import re
from pathlib import Path

env_file = Path(".env")
contents = env_file.read_text(encoding="utf-8")
replacement = 'DATABASE_URL="postgresql://postgres:postgres@db:5432/oralhistarchiv"'

updated, count = re.subn(
    r"^DATABASE_URL=.*$",
    replacement,
    contents,
    flags=re.MULTILINE,
)
if count != 1:
    raise RuntimeError(
        "Expected exactly one DATABASE_URL line in the newly created .env"
    )

env_file.write_text(updated, encoding="utf-8")
PY
fi

uv sync --locked --extra dev --extra doc --python 3.11

echo "✅ DevContainer setup finished successfully!"