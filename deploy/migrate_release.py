"""Apply schema and grants from one release while the unit holds its lock."""

import os
import subprocess  # nosec B404 - fixed migration commands, no shell
from pathlib import Path

from psycopg.conninfo import conninfo_to_dict

_DATABASE_NAME = "oralhistarchiv"

_DEPLOYED_ENV_STATES = frozenset({"staging", "production"})


def _migration_database_url() -> str:
    """Read the deployed migration URL and require database oralhistarchiv.

    Raises RuntimeError unless ENV_STATE is staging/production and
    MIGRATION_DATABASE_URL names that database; psycopg parse errors propagate.
    """
    if os.environ.get("ENV_STATE") not in _DEPLOYED_ENV_STATES:
        raise RuntimeError("migrate_release must run with ENV_STATE set to staging or production")

    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not migration_url:
        raise RuntimeError("MIGRATION_DATABASE_URL is required for release migration")

    connection = conninfo_to_dict(migration_url)
    if connection.get("dbname") != _DATABASE_NAME:
        raise RuntimeError(f"The shipped grant manifest supports only database {_DATABASE_NAME!r}")

    return migration_url


def main() -> None:
    """Run installed Alembic upgrade head, then psql runtime grants, each with a 900s timeout.

    The caller must hold the exclusive deployment lock with writers stopped and
    load migration.env. Changes PostgreSQL; the two commands are not one transaction.
    Validation, OS, CalledProcessError and TimeoutExpired errors propagate.
    """
    release = Path(__file__).resolve().parents[1]
    migration_url = _migration_database_url()

    subprocess.run(
        [str(release / ".venv/bin/python"), "-I", "-m", "app.migrate", "upgrade", "head"],
        cwd=release,
        check=True,
        timeout=900,
    )
    subprocess.run(
        [
            "/usr/bin/psql",
            "--no-password",
            "--no-psqlrc",
            f"--dbname={migration_url}",
            "--set=ON_ERROR_STOP=1",
            f"--file={release / 'deploy/database-runtime-grants.sql'}",
        ],
        cwd=release,
        check=True,
        timeout=900,
    )


if __name__ == "__main__":
    main()
