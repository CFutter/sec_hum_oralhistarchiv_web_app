"""Compose the shipped bootstrap, migrations, grants, and runtime logins."""

import secrets
import shutil
import subprocess

import psycopg
import pytest
from alembic.config import Config
from psycopg import sql
from psycopg_pool import AsyncConnectionPool
from sqlalchemy.engine import make_url

from alembic import command
from app.paths import ALEMBIC_DIR, ALEMBIC_INI, PROJECT_ROOT
from app.runtime_preflight import validate_runtime_schema
from app.services.seed_mock_data import seed_mock_data
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL

_ROLES = (
    "oralhistarchiv",
    "oralhistarchiv_web",
    "oralhistarchiv_scheduler",
    "oralhistarchiv_backup",
)


@pytest.fixture
def deployed_database(monkeypatch):
    psql = shutil.which("psql")
    if psql is None:
        pytest.fail("The composed deployment check requires psql")
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as admin:
        if admin.execute("SELECT 1 FROM pg_database WHERE datname = 'oralhistarchiv'").fetchone():
            pytest.skip(
                "Existing oralhistarchiv database must not be altered by a deployment probe"
            )
        if admin.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = ANY(%s)", (list(_ROLES),)
        ).fetchone():
            pytest.skip("Existing deployment roles must not be altered by a deployment probe")
        try:

            def run_sql_asset(name, *, database_url=TEST_DATABASE_URL):
                subprocess.run(
                    [
                        psql,
                        "-X",
                        "--dbname",
                        database_url,
                        "--file",
                        str(PROJECT_ROOT / "deploy" / name),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

            run_sql_asset("bootstrap-database-roles.sql")
            password = secrets.token_urlsafe(32)
            # CI uses TCP/SCRAM instead of the deployment's OS peer identities.
            # Test-only passwords allow real logins; role/database defaults,
            # including the shipped search_path, remain untouched.
            for role in _ROLES[:3]:
                admin.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
            urls = {
                role: make_url(TEST_DATABASE_URL)
                .set(username=role, password=password, database="oralhistarchiv")
                .render_as_string(hide_password=False)
                for role in _ROLES[:3]
            }
            monkeypatch.setenv("ENV_STATE", "staging")
            monkeypatch.setenv("MIGRATION_DATABASE_URL", urls["oralhistarchiv"])
            config = Config(str(ALEMBIC_INI))
            config.set_main_option("script_location", str(ALEMBIC_DIR))
            command.upgrade(config, "head")
            run_sql_asset(
                "database-runtime-grants.sql",
                database_url=make_url(TEST_DATABASE_URL)
                .set(database="oralhistarchiv")
                .render_as_string(hide_password=False),
            )
            monkeypatch.setattr(settings, "env_state", "staging")
            yield urls
        finally:
            admin.execute("DROP DATABASE IF EXISTS oralhistarchiv WITH (FORCE)")
            for role in reversed(_ROLES):
                admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


async def test_runtime_preflight_with_actual_deployed_role_login_defaults(deployed_database):
    for process in ("web", "scheduler"):
        role = f"oralhistarchiv_{process}"
        pool = AsyncConnectionPool(deployed_database[role], min_size=1, max_size=1, open=False)
        try:
            await pool.open(wait=True, timeout=5)
            async with pool.connection() as connection:
                row = await (
                    await connection.execute("SELECT current_schema(), current_user, session_user")
                ).fetchone()
                assert row == ("pg_catalog", role, role)
            await validate_runtime_schema(pool, process=process)
            if process == "scheduler":
                async with pool.connection() as connection:
                    # The cleanup query must work with only the narrow
                    # sessions UPDATE (flash_category) lock grant.
                    await connection.execute(
                        "SELECT id FROM public.sessions WHERE false FOR UPDATE SKIP LOCKED"
                    )
                assert await seed_mock_data(pool) > 0
                await validate_runtime_schema(pool, process=process)
        finally:
            await pool.close()
