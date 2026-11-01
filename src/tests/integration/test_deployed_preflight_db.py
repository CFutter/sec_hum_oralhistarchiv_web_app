"""Compose the shipped bootstrap, migrations, grants, and runtime logins."""

import asyncio
import os
import re
import secrets
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import create_autospec, patch
from uuid import uuid4

import psycopg
import pyotp
import pytest
from alembic.config import Config
from argon2 import PasswordHasher
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import tuple_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from sqlalchemy.engine import make_url

from alembic import command
from app.paths import ALEMBIC_DIR, ALEMBIC_INI, PROJECT_ROOT
from app.runtime_preflight import validate_runtime_schema
from app.services import (
    CatalogueStatsCache,
    DatasetAdminContext,
    build_catalogue_policy,
    change_dataset_admin_state,
    ensure_source_status_rows,
)
from app.services.account_deletion import delete_account_as_admin, delete_own_account
from app.services.database_privileges import validate_runtime_database_role
from app.services.datasets import (
    get_dataset_by_id,
    get_facets,
    get_recent_datasets,
    search_datasets,
)
from app.services.db import get_catalogue_cursor, get_db_cursor
from app.services.email_outbox import claim_due_emails, enqueue_email_cur, prepare_email_delivery
from app.services.federated_authentication import (
    FederatedLoginFailure,
    build_federated_principal,
    finalize_shibboleth_login,
)
from app.services.federated_session_policy import (
    REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
    reconcile_federated_session_policy,
)
from app.services.registration_setup import begin_local_registration
from app.services.scheduler import sync_and_invalidate
from app.services.session_ids import hash_session_id
from app.services.tokens import ActionEmailMetadata
from app.services.totp_crypto import encrypt_value
from app.services.users import reap_unverified_accounts
from app.sources import FixtureConfig, SourceDisplay, configure_sources
from config import settings
from tests.integration.conftest import TEST_DATABASE_URL
from tests.integration.sync_doubles import FETCH

_ROLES = (
    "oralhistarchiv",
    "oralhistarchiv_web",
    "oralhistarchiv_scheduler",
    "oralhistarchiv_backup",
)
_DEPLOYMENT_PROBE_LOCK = 8_212_027
_TIERS = ("public", "registered", "vetted")


def _ordered_discovery_ids(connection):
    """Exercise the actual restricted login's private ordering boundary."""
    viewer = connection.execute("SELECT current_setting('app.viewer_tier', true)").fetchone()[0]
    rank = _TIERS.index(viewer) if viewer in _TIERS else 0
    policy = build_catalogue_policy(_rls_source())
    context = Jsonb(
        {
            "mode": "empty",
            "term": "",
            "pattern": "%%",
            "keyword": "",
            "language": "",
            "access_level": "",
            "fingerprint": policy.fingerprint,
            "masks": dict(policy.page_masks[rank]),
        }
    )
    return [
        row[0]
        for row in connection.execute(
            "SELECT id FROM public.catalogue_page_ids("
            "NULL, public.catalogue_scan_ceiling(), false, 200, 0, %s) AS selected(id)",
            (context,),
        ).fetchall()
    ]


async def _assert_dataset_administration_web_grants(
    deployed_database,
):
    """The actual runtime login can administer state while catalogue DML stays denied."""
    raw_session = secrets.token_urlsafe(32)
    async with (
        AsyncConnectionPool(deployed_database["oralhistarchiv"], open=False) as owner,
        owner.connection() as conn,
    ):
        actor = await (
            await conn.execute(
                "INSERT INTO users (email, password_hash, totp_secret, email_verified, "
                "is_admin, totp_recovery_code_generation) VALUES (%s, %s, %s, true, true, 1) "
                "RETURNING id",
                (
                    "role-probe@example.org",
                    "unused-password-hash",
                    encrypt_value("JBSWY3DPEHPK3PXP"),
                ),
            )
        ).fetchone()
        assert actor is not None
        actor_id = actor[0]
        await conn.execute(
            "INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash) "
            "VALUES (%s, 1, 1, %s)",
            (actor_id, "unused-code-digest"),
        )
        await conn.execute(
            "INSERT INTO sessions (id, user_id, purpose, expires_at) "
            "VALUES (%s, %s, 'full', clock_timestamp() + INTERVAL '1 hour')",
            (hash_session_id(raw_session), actor_id),
        )
        target = await (
            await conn.execute(
                "INSERT INTO oral_history_datasets (source, uuid, visibility_tier) "
                "VALUES ('role_probe', 'controlled', 'public') RETURNING id"
            )
        ).fetchone()
        assert target is not None
        dataset_id = target[0]
    async with AsyncConnectionPool(deployed_database["oralhistarchiv_web"], open=False) as web:
        context = DatasetAdminContext(actor_id, raw_session)
        hidden = await change_dataset_admin_state(
            web, dataset_id, "hide", context=context, configured_sources=()
        )
        restored = await change_dataset_admin_state(
            web, dataset_id, "restore", context=context, configured_sources=()
        )
        assert hidden.changed and restored.changed
        assert restored.after.hidden_at is None
        async with web.connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT visibility_tier, has_table_privilege(current_user, "
                    "'public.oral_history_datasets', 'UPDATE') FROM public.oral_history_datasets "
                    "WHERE id = %s",
                    (dataset_id,),
                )
            ).fetchone()
            assert row == ("public", False)
    async with (
        AsyncConnectionPool(deployed_database["oralhistarchiv"], open=False) as owner,
        owner.connection() as conn,
    ):
        await conn.execute(
            "DELETE FROM dataset_admin_state WHERE source = 'role_probe' AND uuid = 'controlled'"
        )
        await conn.execute("DELETE FROM oral_history_datasets WHERE id = %s", (dataset_id,))
        await conn.execute("DELETE FROM users WHERE id = %s", (actor_id,))


@pytest.fixture
def deployed_database(monkeypatch):
    """Provision isolated deployment roles and database; yield role URLs and clean up afterward."""
    psql = shutil.which("psql")
    if psql is None:
        pytest.fail("The composed deployment check requires psql")
    # All xdist workers lock the same maintenance database before checking or
    # creating cluster-wide roles. A skip or failure closes this connection and
    # releases the lock without touching an existing installation.
    maintenance = (
        make_url(TEST_DATABASE_URL).set(database="postgres").render_as_string(hide_password=False)
    )
    with psycopg.connect(maintenance, autocommit=True) as admin:
        admin.execute("SELECT pg_advisory_lock(%s)", (_DEPLOYMENT_PROBE_LOCK,))
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
                """Run the named deployment SQL asset with psql, failing on a nonzero exit."""
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
            for role in _ROLES:
                admin.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(password)
                    )
                )
            urls = {
                role: make_url(TEST_DATABASE_URL)
                .set(username=role, password=password, database="oralhistarchiv")
                .render_as_string(hide_password=False)
                for role in _ROLES
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


@pytest.mark.parametrize("as_admin", [False, True])
async def test_account_deletion_with_actual_web_login(deployed_database, as_admin):
    """Both guarded deletion services and cascade cleanup work under the shipped grants."""
    password = "Copper lanterns 7! beside quiet rivers"
    secret = pyotp.random_base32()
    raw_session = secrets.token_urlsafe(32)
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        actor = owner.execute(
            "INSERT INTO users (email, password_hash, totp_secret, email_verified, "
            "is_admin, totp_recovery_code_generation) VALUES (%s, %s, %s, true, %s, 1) "
            "RETURNING id",
            (
                "deletion-actor@example.org",
                PasswordHasher().hash(password),
                encrypt_value(secret),
                as_admin,
            ),
        ).fetchone()
        assert actor is not None
        actor_id = actor[0]
        owner.execute(
            "INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash) "
            "VALUES (%s, 1, 1, 'unused-recovery-digest')",
            (actor_id,),
        )
        owner.execute(
            "INSERT INTO sessions (id, user_id, purpose, expires_at) "
            "VALUES (%s, %s, 'full', clock_timestamp() + INTERVAL '1 hour')",
            (hash_session_id(raw_session), actor_id),
        )
        target_id = actor_id
        if as_admin:
            target = owner.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
                ("deletion-target@example.org", "unused-password-hash"),
            ).fetchone()
            assert target is not None
            target_id = target[0]
        owner.execute(
            "INSERT INTO sessions (id, user_id, purpose, expires_at) "
            "VALUES (%s, %s, 'full', clock_timestamp() + INTERVAL '1 hour')",
            (hash_session_id(secrets.token_urlsafe(32)), target_id),
        )

    async with AsyncConnectionPool(deployed_database["oralhistarchiv_web"], open=False) as web:
        await validate_runtime_database_role(web, process="web")
        if as_admin:
            result = await delete_account_as_admin(
                web,
                actor_id=actor_id,
                actor_session_id=raw_session,
                target_user_id=target_id,
                password=password,
                totp_code=pyotp.TOTP(secret).now(),
            )
        else:
            result = await delete_own_account(
                web,
                user_id=actor_id,
                session_id=raw_session,
                password=password,
                totp_code=pyotp.TOTP(secret).now(),
            )
        assert result.target_user_id == target_id
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        assert owner.execute("SELECT 1 FROM users WHERE id = %s", (target_id,)).fetchone() is None
        assert (
            owner.execute("SELECT 1 FROM sessions WHERE user_id = %s", (target_id,)).fetchone()
            is None
        )
        if as_admin:
            assert owner.execute("SELECT 1 FROM users WHERE id = %s", (actor_id,)).fetchone() == (
                1,
            )


async def test_federated_reservation_claim_with_actual_web_login(deployed_database, monkeypatch):
    """The runtime login can replace a local reservation and revoke its queued capability."""
    issuer = "https://idp.example.org/idp/shibboleth"
    email = "reservation-owner@example.org"
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [issuer])
    async with AsyncConnectionPool(deployed_database["oralhistarchiv_web"], open=False) as web:
        await validate_runtime_database_role(web, process="web")
        await reconcile_federated_session_policy(web)
        await begin_local_registration(web, email=email)
        async with web.connection() as connection:
            reservation = await (
                await connection.execute("SELECT id FROM users WHERE email = %s", (email,))
            ).fetchone()
            assert reservation is not None
            original_id = reservation[0]
            queued = await (
                await connection.execute(
                    "SELECT count(*) FROM email_outbox WHERE user_id = %s", (original_id,)
                )
            ).fetchone()
            assert queued == (1,)
        result = await finalize_shibboleth_login(
            web,
            principal=build_federated_principal(
                issuer=issuer,
                subject_id="urn:subject:deployed-reservation",
                email=email,
                authn_context=REQUIRED_SHIBBOLETH_AUTHN_CONTEXT,
            ),
            ip_address="127.0.0.1",
        )
        assert isinstance(result, FederatedLoginFailure)
        assert result.reason == "inactive_account"
        assert result.user is not None and result.user.id != original_id
        assert result.user.auth_method == "shibboleth"
        assert result.user.federated_status == "pending"
        async with web.connection() as connection:
            assert (
                await (
                    await connection.execute("SELECT 1 FROM users WHERE id = %s", (original_id,))
                ).fetchone()
                is None
            )
            assert (
                await (
                    await connection.execute(
                        "SELECT 1 FROM email_outbox WHERE user_id = %s", (original_id,)
                    )
                ).fetchone()
                is None
            )


async def test_runtime_preflight_with_actual_deployed_role_login_defaults(deployed_database):
    """SB-VIS-009: actual CI logins prove runtime and read-only backup grants.

    TCP/SCRAM does not prove deployed OS peer identity, key custody or restoration.
    """
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
            async with pool.connection() as connection:
                rows = await (
                    await connection.execute("SELECT source FROM public.sync_status")
                ).fetchall()
                assert rows == []

            if process == "web":
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    await ensure_source_status_rows(pool, ("preflight_probe",))
                await _assert_dataset_administration_web_grants(deployed_database)
            if process == "scheduler":
                await ensure_source_status_rows(pool, ("preflight_probe",))
                async with pool.connection() as connection:
                    row = await (
                        await connection.execute(
                            """
                            SELECT source_cursor, source_fingerprint,
                                   incremental_harvest, incremental_started_at,
                                   incremental_position, incremental_affected
                            FROM public.sync_status WHERE source = %s
                            """,
                            ("preflight_probe",),
                        )
                    ).fetchone()
                    assert row == (None, None, None, None, 0, 0)

                    await connection.execute(
                        """
                        UPDATE public.sync_status
                        SET source_fingerprint = %s,
                            last_sync_error = 'retained-error',
                            incremental_harvest = %s,
                            incremental_started_at =
                                TIMESTAMPTZ '2020-01-04 00:00:00+00',
                            incremental_position = 1,
                            incremental_affected = 2
                        WHERE source = %s
                        """,
                        ("b" * 64, b"retained-staging", "preflight_probe"),
                    )
                    before = await (
                        await connection.execute(
                            "SELECT * FROM public.sync_status WHERE source = %s",
                            ("preflight_probe",),
                        )
                    ).fetchone()

                await ensure_source_status_rows(pool, ("preflight_probe", "other_probe"))
                async with pool.connection() as connection:
                    after = await (
                        await connection.execute(
                            "SELECT * FROM public.sync_status WHERE source = %s",
                            ("preflight_probe",),
                        )
                    ).fetchone()
                    assert after == before
                    row = await (
                        await connection.execute(
                            """
                            SELECT source_cursor, source_fingerprint,
                                   incremental_harvest, incremental_started_at,
                                   incremental_position, incremental_affected
                            FROM public.sync_status WHERE source = %s
                            """,
                            ("other_probe",),
                        )
                    ).fetchone()
                    assert row == (None, None, None, None, 0, 0)
                async with pool.connection() as connection:
                    # The cleanup query must work with only the narrow
                    # sessions UPDATE (flash_category) lock grant.
                    await connection.execute(
                        "SELECT id FROM public.sessions WHERE false FOR UPDATE SKIP LOCKED"
                    )
                source = configure_sources(
                    (
                        FixtureConfig(
                            name="preflight_fixture",
                            display=SourceDisplay(label="Preflight fixture"),
                            max_visibility="public",
                        ),
                    )
                )[0]
                await ensure_source_status_rows(pool, (source.name,))
                cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
                with patch(
                    FETCH,
                    autospec=True,
                    side_effect=AssertionError("Deployed fixture recovery used OAI"),
                ) as fetch:
                    outcome = await sync_and_invalidate(pool, cache, source)
                fetch.assert_not_called()
                assert (outcome.status, outcome.affected_count) == ("success", 3)
                cache.invalidate_cache.assert_called_once_with()
                async with pool.connection() as connection:
                    rows = await (
                        await connection.execute(
                            "SELECT uuid, visibility_tier FROM public.oral_history_datasets "
                            "WHERE source = %s ORDER BY uuid",
                            (source.name,),
                        )
                    ).fetchall()
                    assert rows == [
                        ("fixture:public", "public"),
                        ("fixture:registered", "registered"),
                        ("fixture:vetted", "vetted"),
                    ]
                await validate_runtime_schema(pool, process=process)
        finally:
            await pool.close()
    await _assert_backup_role_grants(deployed_database)


@pytest.mark.parametrize("process", ["web", "scheduler"])
@pytest.mark.parametrize(
    "function",
    [
        "public.catalogue_scan_ceiling()",
        "public.catalogue_page_ids(integer, integer, boolean, integer, integer, jsonb)",
    ],
)
async def test_runtime_and_shipped_verifier_reject_catalogue_execute_drift(
    deployed_database, process, function
):
    """Verify runtime and shipped verifier reject catalogue execute drift."""
    role = f"oralhistarchiv_{process}"
    psql = shutil.which("psql")
    assert psql is not None

    def verify():
        """Complete local registration with the supplied token and fixed mailbox-owner profile."""
        return subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--no-password",
                "--file",
                str(PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"),
            ],
            env=_pg_tool_environment(deployed_database[role]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    grant = sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
        sql.SQL(function), sql.Identifier(role)
    )
    revoke = sql.SQL("REVOKE EXECUTE ON FUNCTION {} FROM {}").format(
        sql.SQL(function), sql.Identifier(role)
    )
    async with AsyncConnectionPool(
        deployed_database[role], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        await validate_runtime_database_role(pool, process=process)
        assert verify().returncode == 0
        with psycopg.connect(deployed_database["oralhistarchiv"], autocommit=True) as owner:
            owner.execute(revoke if process == "web" else grant)
            try:
                with pytest.raises(RuntimeError, match="application-function EXECUTE set"):
                    await validate_runtime_database_role(pool, process=process)
                rejected = verify()
                assert rejected.returncode != 0
                assert "unexpected application-function EXECUTE" in rejected.stderr
            finally:
                owner.execute(grant if process == "web" else revoke)
        await validate_runtime_database_role(pool, process=process)
        assert verify().returncode == 0


async def _assert_backup_role_grants(deployed_database):
    """Check backup-role permissions, isolation and connection limits against PostgreSQL."""
    role = "oralhistarchiv_backup"
    async with (
        AsyncConnectionPool(deployed_database[role], min_size=1, max_size=1, open=False) as pool,
        pool.connection() as conn,
    ):
        row = await (await conn.execute("SELECT current_user, session_user")).fetchone()
        assert row == (role, role)
        row = await (
            await conn.execute(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, "
                "rolreplication, rolbypassrls, rolconnlimit FROM pg_roles "
                "WHERE rolname = current_user"
            )
        ).fetchone()
        assert row == (True, False, False, False, False, False, True, 1)
        row = await (
            await conn.execute(
                "SELECT has_database_privilege(current_database(), 'CREATE,TEMP'), "
                "has_schema_privilege('public', 'CREATE'), "
                "EXISTS (SELECT 1 FROM pg_auth_members WHERE member = "
                "(SELECT oid FROM pg_roles WHERE rolname = current_user)), "
                "(SELECT pg_get_userbyid(datdba) = current_user FROM pg_database "
                "WHERE datname = current_database()), "
                "(SELECT pg_get_userbyid(nspowner) = current_user FROM pg_namespace "
                "WHERE nspname = 'public')"
            )
        ).fetchone()
        assert row == (False, False, False, False, False)
        row = await (
            await conn.execute(
                "SELECT has_function_privilege('public.catalogue_scan_ceiling()', 'EXECUTE'), "
                "has_function_privilege('public.catalogue_page_ids(integer, integer, boolean, "
                "integer, integer, jsonb)', 'EXECUTE')"
            )
        ).fetchone()
        assert row == (False, False)
        rows = await (
            await conn.execute(
                "SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner) = current_user, "
                "CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'SELECT') "
                "ELSE has_table_privilege(c.oid, 'SELECT') END, "
                "CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'USAGE,UPDATE') "
                "ELSE has_table_privilege(c.oid, "
                "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') "
                "OR has_any_column_privilege(c.oid, 'INSERT,UPDATE,REFERENCES') END "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S')"
            )
        ).fetchall()
        assert {name for name, kind, *_ in rows if kind != "S"} == {
            "alembic_version",
            "catalogue_search_policy",
            "catalogue_search_public",
            "catalogue_search_registered",
            "catalogue_search_vetted",
            "ingestion_quarantine",
            "source_security_state",
            "source_binding_acknowledgements",
            "security_audit_events",
            "security_audit_receipts",
            "anonymous_mail_issuance",
            "oral_history_datasets",
            "dataset_admin_state",
            "sync_status",
            "ingestion_failures",
            "users",
            "totp_recovery_codes",
            "admin_promotion_requests",
            "federation_policy_state",
            "email_outbox",
            "sessions",
            "pending_totp_rotations",
        }
        assert {name for name, kind, *_ in rows if kind == "S"} == {
            "oral_history_datasets_id_seq",
            "users_id_seq",
            "email_outbox_id_seq",
        }
        for name, kind, owns, can_read, can_write in rows:
            assert (owns, can_read, can_write) == (False, True, False), name
            relation = sql.Identifier("public", name)
            # Read every column without exposing account, quarantine or staged bytes.
            await conn.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(relation))
            if kind != "S":
                count = await (
                    await conn.execute(sql.SQL("SELECT count(*) FROM {}").format(relation))
                ).fetchone()
                assert count is not None and count[0] >= 0


def _seed_rls_catalogue(deployed_database):
    """Commit synthetic rows through the migration owner, including durable restrictions."""
    cases = (
        ("public", "rls_archive", "public", "public", None, False),
        ("registered", "rls_archive", "registered", "registered", None, False),
        ("vetted", "rls_archive", "vetted", "vetted", None, False),
        ("floor_registered", "rls_archive", "floor_registered", "public", "registered", False),
        ("floor_vetted", "rls_archive", "floor_vetted", "registered", "vetted", False),
        ("hidden", "rls_archive", "shared-hidden-identity", "public", None, True),
        ("foreign", "rls_other", "shared-hidden-identity", "public", None, False),
    )
    records = {}
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        policy = build_catalogue_policy(_rls_source())
        owner.execute(
            "SELECT public.catalogue_initialize_search_policy(%s, %s)",
            (
                policy.fingerprint,
                Jsonb({str(rank): dict(masks) for rank, masks in policy.page_masks.items()}),
            ),
        )
        for name, source, uuid, stored, floor, hidden in cases:
            title = f"RLS-PUBLIC-TITLE-{name}"
            description = f"RLS-PRIVATE-DESCRIPTION-{name}"
            row = owner.execute(
                "INSERT INTO public.oral_history_datasets "
                "(source, uuid, title, description, visibility_tier, access_level, "
                "version, keywords, languages, data) "
                "VALUES (%s, %s, %s, %s, %s, 'public', 'rls-version', %s, %s, %s) RETURNING id",
                (
                    source,
                    uuid,
                    title,
                    description,
                    stored,
                    [f"keyword-{name}"] * 2,
                    [f"language-{name}"],
                    Jsonb({"visibility_tier": stored, "private": f"raw-private-{name}"}),
                ),
            ).fetchone()
            assert row is not None
            if floor is not None or hidden:
                owner.execute(
                    "INSERT INTO public.dataset_admin_state "
                    "(source, uuid, visibility_tier, hidden_at) "
                    "VALUES (%s, %s, %s, CASE WHEN %s THEN clock_timestamp() ELSE NULL END)",
                    (source, uuid, floor, hidden),
                )
            records[name] = {
                "id": row[0],
                "source": source,
                "uuid": uuid,
                "stored_tier": stored,
                "effective_tier": max((stored, floor or "public"), key=_TIERS.index),
                "hidden": hidden,
                "title": title,
                "description": description,
            }
    return records


def _permitted_rls_ids(records, viewer):
    """Return sorted IDs whose effective tier and hidden state permit this viewer."""
    return sorted(
        item["id"]
        for item in records.values()
        if not item["hidden"] and _TIERS.index(item["effective_tier"]) <= _TIERS.index(viewer)
    )


def _rls_source():
    """Build the two public-floor sources used by the RLS proof."""
    return configure_sources(
        (
            FixtureConfig(
                name="rls_archive",
                display=SourceDisplay(label="RLS archive"),
                max_visibility="public",
            ),
            FixtureConfig(
                name="rls_other",
                display=SourceDisplay(label="Other RLS archive"),
                max_visibility="public",
            ),
        )
    )


@pytest.mark.parametrize(
    "viewer_setting", (None, "", "public", "not-a-tier", "registered", "vetted")
)
def test_web_role_raw_reads_apply_the_current_tier_and_durable_restrictions(
    deployed_database, viewer_setting
):
    """Verify web role raw reads apply the current tier and durable restrictions."""
    records = _seed_rls_catalogue(deployed_database)
    viewer = viewer_setting if viewer_setting in _TIERS else "public"
    with psycopg.connect(deployed_database["oralhistarchiv_web"]) as web:
        assert web.execute("SELECT current_user, session_user").fetchone() == (
            "oralhistarchiv_web",
            "oralhistarchiv_web",
        )
        if viewer_setting is not None:
            web.execute("SELECT set_config('app.viewer_tier', %s, true)", (viewer_setting,))
        rows = web.execute("SELECT id FROM public.oral_history_datasets ORDER BY id").fetchall()
        assert [row[0] for row in rows] == _permitted_rls_ids(records, viewer)
        assert records["hidden"]["id"] not in [row[0] for row in rows]
        assert records["foreign"]["id"] in [row[0] for row in rows]
        assert web.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone() == (False, False)
        assert web.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = 'public.oral_history_datasets'::regclass"
        ).fetchone() == (True, False)
        policies = web.execute(
            "SELECT polname, polcmd, polroles FROM pg_policy "
            "WHERE polrelid = 'public.oral_history_datasets'::regclass ORDER BY polname"
        ).fetchall()
        assert policies == [
            ("catalogue_scheduler_all", "*", [0]),
            ("catalogue_web_select", "r", [0]),
        ]
        with pytest.raises(psycopg.errors.InsufficientPrivilege), web.transaction():
            web.execute("SET LOCAL row_security = off")
            web.execute("SELECT id FROM public.oral_history_datasets").fetchall()


async def test_owner_views_have_exact_safe_projections_and_unknown_roles_cannot_bypass_rls(
    deployed_database,
):
    """Verify owner views have exact safe projections and unknown roles cannot bypass RLS."""
    records = _seed_rls_catalogue(deployed_database)
    visible = {item["id"]: item for item in records.values() if not item["hidden"]}
    with psycopg.connect(deployed_database["oralhistarchiv_web"]) as web:
        discovery = web.execute("SELECT * FROM public.catalogue_discovery ORDER BY id DESC")
        assert [item.name for item in discovery.description] == [
            "id",
            "uuid",
            "title",
            "access_level",
            "version",
            "source",
            "visibility_tier",
        ]
        rows = discovery.fetchall()
        assert {row[0] for row in rows} == set(visible)
        assert [row[0] for row in rows] == sorted(visible, reverse=True)
        assert _ordered_discovery_ids(web) == sorted(visible, reverse=True)
        for row in rows:
            expected = visible[row[0]]
            assert row[1:7] == (
                expected["uuid"],
                expected["title"],
                "public",
                "rls-version",
                expected["source"],
                expected["effective_tier"],
            )
        administration = web.execute("SELECT * FROM public.dataset_admin_catalogue ORDER BY id")
        assert [item.name for item in administration.description] == [
            "id",
            "source",
            "uuid",
            "stored_tier",
            "record_tier",
        ]
        assert administration.fetchall() == [
            (item["id"], item["source"], item["uuid"], item["stored_tier"], item["stored_tier"])
            for item in sorted(records.values(), key=lambda item: item["id"])
        ]
        for view in ("catalogue_discovery", "dataset_admin_catalogue"):
            options = web.execute(
                "SELECT reloptions, pg_get_userbyid(relowner) FROM pg_class WHERE oid = %s::regclass",
                (f"public.{view}",),
            ).fetchone()
            assert options is not None and options[1] == "oralhistarchiv"
            assert set(options[0]) == {"security_barrier=true", "security_invoker=false"}
            assert web.execute(
                "SELECT has_table_privilege(current_user, %s, 'INSERT,UPDATE,DELETE')",
                (f"public.{view}",),
            ).fetchone() == (False,)
        for raw in (
            {},
            {"visibility_tier": None},
            {"visibility_tier": ["vetted"]},
            {"visibility_tier": "VETTED"},
        ):
            with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
                owner.execute(
                    "UPDATE public.oral_history_datasets SET data = %s WHERE id = %s",
                    (Jsonb(raw), records["public"]["id"]),
                )
            assert web.execute(
                "SELECT record_tier, pg_typeof(record_tier)::text FROM public.dataset_admin_catalogue WHERE id = %s",
                (records["public"]["id"],),
            ).fetchone() == (None, "text")

    role = f"oha_unknown_role_{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(32)
    admin_url = (
        make_url(TEST_DATABASE_URL)
        .set(database="oralhistarchiv")
        .render_as_string(hide_password=False)
    )
    psql = shutil.which("psql")
    assert psql is not None

    def verify_runtime_access():
        """Run the runtime-role SQL verifier and capture its exit status and output."""
        return subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--no-password",
                "--file",
                str(PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"),
            ],
            env=_pg_tool_environment(deployed_database["oralhistarchiv_web"]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as web_pool:
        await web_pool.wait(timeout=5)
        await validate_runtime_database_role(web_pool, process="web")
        assert verify_runtime_access().returncode == 0
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(
                "GRANT UPDATE (title) ON public.catalogue_discovery TO oralhistarchiv_web"
            )
            try:
                with pytest.raises(RuntimeError, match="Unsafe PostgreSQL role for web"):
                    await validate_runtime_database_role(web_pool, process="web")
                rejected = verify_runtime_access()
                assert rejected.returncode != 0
                assert "unexpected catalogue view contract: catalogue_discovery" in rejected.stderr
            finally:
                admin.execute(
                    "REVOKE UPDATE (title) ON public.catalogue_discovery FROM oralhistarchiv_web"
                )
        await validate_runtime_database_role(web_pool, process="web")
        assert verify_runtime_access().returncode == 0

    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOINHERIT").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
        try:
            admin.execute(
                sql.SQL("GRANT CONNECT ON DATABASE oralhistarchiv TO {}").format(
                    sql.Identifier(role)
                )
            )
            admin.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
            )
            # The policy must reject the identity even when ordinary SELECT
            # permissions exist on every relation mentioned by its predicate.
            admin.execute(
                sql.SQL(
                    "GRANT SELECT ON public.oral_history_datasets, public.dataset_admin_state, "
                    "public.ingestion_quarantine TO {}"
                ).format(sql.Identifier(role))
            )
            url = (
                make_url(admin_url)
                .set(username=role, password=password)
                .render_as_string(hide_password=False)
            )
            with psycopg.connect(url) as unknown:
                unknown.execute("SELECT set_config('app.viewer_tier', 'vetted', true)")
                assert (
                    unknown.execute("SELECT id FROM public.oral_history_datasets").fetchall() == []
                )
        finally:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


async def test_web_pool_restores_tier_across_reads_fallback_counts_and_nested_scopes(
    deployed_database,
):
    """Verify web pool restores tier across reads fallback counts and nested scopes."""
    records = _seed_rls_catalogue(deployed_database)
    sources = _rls_source()
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as pool:
        await pool.wait(timeout=5)
        for viewer in ("vetted", "public", "registered", "public"):
            detail = await get_dataset_by_id(
                pool, records["vetted"]["id"], viewer, configured_sources=sources
            )
            assert detail is not None and detail.title == records["vetted"]["title"]
            assert detail.description == (
                records["vetted"]["description"] if viewer == "vetted" else None
            )
            rows, count = await search_datasets(
                pool, viewer, search_text="RLS-PRIVATE", configured_sources=sources
            )
            assert sorted(row.id for row in rows) == _permitted_rls_ids(records, viewer)
            assert count == len(rows)
            assert await search_datasets(
                pool,
                viewer,
                search_text="RLS-PRIVATE",
                page=2,
                page_size=100,
                configured_sources=sources,
            ) == ([], len(rows))
            public_rows, total = await search_datasets(
                pool, viewer, search_text="RLS-PUBLIC-TITLE", configured_sources=sources
            )
            assert total == len(public_rows) == len(records) - 1
            assert (
                len(await get_recent_datasets(pool, viewer, limit=10, configured_sources=sources))
                == len(records) - 1
            )
            facets = await get_facets(pool, viewer, configured_sources=sources)
            assert len(facets["keywords"]) == len(facets["languages"]) == len(rows)

        async with pool.connection() as conn:
            before = await (await conn.execute("SELECT pg_backend_pid()")).fetchone()
            async with get_catalogue_cursor(conn, "vetted", row_factory=tuple_row) as outer:
                await outer.execute("SELECT current_setting('app.viewer_tier')")
                assert await outer.fetchone() == ("vetted",)
                async with get_catalogue_cursor(conn, "public", row_factory=tuple_row) as inner:
                    await inner.execute("SELECT id FROM public.oral_history_datasets ORDER BY id")
                    assert [row[0] for row in await inner.fetchall()] == _permitted_rls_ids(
                        records, "public"
                    )
                await outer.execute("SELECT current_setting('app.viewer_tier')")
                assert await outer.fetchone() == ("vetted",)
                with pytest.raises(psycopg.errors.DivisionByZero):
                    async with get_catalogue_cursor(conn, "registered") as inner:
                        await inner.execute("SELECT 1 / 0")
                await outer.execute("SELECT current_setting('app.viewer_tier')")
                assert await outer.fetchone() == ("vetted",)
            assert await (await conn.execute("SELECT pg_backend_pid()")).fetchone() == before
            assert (
                await (
                    await conn.execute("SELECT current_setting('app.viewer_tier', true)")
                ).fetchone()
            )[0] in (None, "")
            assert [
                row[0]
                for row in await (
                    await conn.execute("SELECT id FROM public.oral_history_datasets ORDER BY id")
                ).fetchall()
            ] == _permitted_rls_ids(records, "public")


@pytest.mark.parametrize("viewer", _TIERS)
async def test_actual_web_administration_works_without_raw_metadata_elevation(
    deployed_database, viewer
):
    """Verify actual web administration works without raw metadata elevation."""
    records = _seed_rls_catalogue(deployed_database)
    raw_session = secrets.token_urlsafe(32)
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        actor = owner.execute(
            "INSERT INTO users (email, password_hash, totp_secret, email_verified, access_tier, "
            "is_admin, totp_recovery_code_generation) VALUES (%s, %s, %s, true, 'public', true, 1) RETURNING id",
            (
                "e3-role-admin@example.org",
                "unused-password-hash",
                encrypt_value("JBSWY3DPEHPK3PXP"),
            ),
        ).fetchone()
        assert actor is not None
        owner.execute(
            "INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash) VALUES (%s, 1, 1, 'unused-digest')",
            (actor[0],),
        )
        owner.execute(
            "INSERT INTO sessions (id, user_id, purpose, expires_at) VALUES (%s, %s, 'full', clock_timestamp() + INTERVAL '1 hour')",
            (hash_session_id(raw_session), actor[0]),
        )
    target = records["public"]["id"]
    sources = _rls_source()
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_web"], min_size=1, max_size=1, open=False
    ) as web:
        await web.wait(timeout=5)
        async with web.connection() as conn:
            await conn.execute("SELECT set_config('app.viewer_tier', %s, false)", (viewer,))
        context = DatasetAdminContext(actor[0], raw_session)
        raised = await change_dataset_admin_state(
            web,
            target,
            "raise_tier",
            context=context,
            new_tier="registered",
            configured_sources=sources,
        )
        assert raised.changed and raised.after.effective_tier == "registered"
        hidden = await change_dataset_admin_state(
            web, target, "hide", context=context, configured_sources=sources
        )
        assert hidden.changed
        assert await get_dataset_by_id(web, target, "vetted", configured_sources=sources) is None
        restored = await change_dataset_admin_state(
            web, target, "restore", context=context, configured_sources=sources
        )
        assert restored.changed and restored.after.hidden_at is None
        public = await get_dataset_by_id(web, target, "public", configured_sources=sources)
        assert public is not None and public.title == records["public"]["title"]
        assert public.description is None and public.visibility_tier == "registered"
        async with web.connection() as conn:
            await conn.execute("SELECT set_config('app.viewer_tier', 'public', true)")
            assert (
                await (
                    await conn.execute(
                        "SELECT id FROM public.oral_history_datasets WHERE id = %s", (target,)
                    )
                ).fetchall()
                == []
            )
            assert await (
                await conn.execute(
                    "SELECT stored_tier, record_tier FROM public.dataset_admin_catalogue WHERE id = %s",
                    (target,),
                )
            ).fetchone() == ("public", "public")
            assert await (
                await conn.execute(
                    "SELECT access_tier FROM public.users WHERE id = %s", (actor[0],)
                )
            ).fetchone() == ("public",)


def _pg_tool_environment(url):
    """Keep disposable-role credentials in the child environment, never argv."""
    names = {
        "host": "PGHOST",
        "hostaddr": "PGHOSTADDR",
        "port": "PGPORT",
        "user": "PGUSER",
        "password": "PGPASSWORD",
        "dbname": "PGDATABASE",
        "sslmode": "PGSSLMODE",
    }
    parameters = conninfo_to_dict(url)
    assert not parameters.keys() - names.keys()
    environment = {name: value for name, value in os.environ.items() if not name.startswith("PG")}
    environment.update({names[name]: value for name, value in parameters.items()})
    environment.update(
        PGPASSFILE="/dev/null", PGCONNECT_TIMEOUT="5", PGAPPNAME="oha-e3-role-restore"
    )
    return environment


def _backup_snapshot(url):
    """Read catalogue rows, admin state and migration revision as the backup role."""
    with psycopg.connect(url) as backup:
        backup.execute("SET TIME ZONE 'UTC'")
        backup.execute("SELECT set_config('app.viewer_tier', 'public', true)")
        return {
            "catalogue": backup.execute(
                "SELECT jsonb_agg(to_jsonb(row) ORDER BY row.id) FROM public.oral_history_datasets AS row"
            ).fetchone()[0],
            "administration": backup.execute(
                "SELECT jsonb_agg(to_jsonb(row) ORDER BY row.source, row.uuid) FROM public.dataset_admin_state AS row"
            ).fetchone()[0],
            "revision": backup.execute("SELECT version_num FROM public.alembic_version").fetchone()[
                0
            ],
        }


def test_scheduler_hidden_dml_and_actual_backup_role_dump_restore_preserve_all_rows(
    deployed_database, tmp_path
):
    """Verify scheduler hidden dml and actual backup role dump restore preserve all rows."""
    records = _seed_rls_catalogue(deployed_database)
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        owner.execute(
            "INSERT INTO public.dataset_admin_state (source, uuid, hidden_at) VALUES ('rls_archive', 'scheduler-hidden-probe', clock_timestamp())"
        )
    with psycopg.connect(deployed_database["oralhistarchiv_scheduler"]) as scheduler:
        assert scheduler.execute(
            "SELECT count(*) FROM public.oral_history_datasets"
        ).fetchone() == (len(records),)
        probe = scheduler.execute(
            "INSERT INTO public.oral_history_datasets (source, uuid, title, visibility_tier) VALUES ('rls_archive', 'scheduler-hidden-probe', 'Scheduler hidden probe', 'vetted') RETURNING id"
        ).fetchone()
        assert probe is not None
        scheduler.execute(
            "UPDATE public.oral_history_datasets SET description = 'Updated while hidden' WHERE id = %s",
            (probe[0],),
        )
        assert scheduler.execute(
            "SELECT description FROM public.oral_history_datasets WHERE id = %s", (probe[0],)
        ).fetchone() == ("Updated while hidden",)
        assert (
            scheduler.execute(
                "DELETE FROM public.oral_history_datasets WHERE id = %s RETURNING id", (probe[0],)
            ).fetchone()
            == probe
        )
    backup_url = deployed_database["oralhistarchiv_backup"]
    before = _backup_snapshot(backup_url)
    assert before["revision"] == "4f73ae3ff827" and len(before["catalogue"]) == len(records)
    assert {row["visibility_tier"] for row in before["catalogue"]} == set(_TIERS)
    assert any(row["hidden_at"] is not None for row in before["administration"])
    with psycopg.connect(backup_url) as backup:
        assert backup.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone() == (False, True)
        assert backup.execute(
            "SELECT has_table_privilege(current_user, 'public.oral_history_datasets', 'INSERT,UPDATE,DELETE,TRUNCATE'), has_database_privilege(current_database(), 'CREATE,TEMP')"
        ).fetchone() == (False, False)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), backup.transaction():
            backup.execute("UPDATE public.oral_history_datasets SET title = title WHERE false")

    dump, restore = shutil.which("pg_dump"), shutil.which("pg_restore")
    assert dump is not None and restore is not None, (
        "Real-role recovery acceptance requires pg_dump and pg_restore"
    )
    archive = tmp_path / "e3-role-backup.dump"
    subprocess.run(
        [dump, "--format=custom", "--no-password", "--file", str(archive)],
        env=_pg_tool_environment(backup_url),
        check=True,
        capture_output=True,
        timeout=60,
    )
    target = f"oha_role_restore_{secrets.token_hex(8)}_test"
    maintenance = (
        make_url(TEST_DATABASE_URL).set(database="postgres").render_as_string(hide_password=False)
    )
    owner_url = (
        make_url(deployed_database["oralhistarchiv"])
        .set(database=target)
        .render_as_string(hide_password=False)
    )
    restored_backup_url = (
        make_url(backup_url).set(database=target).render_as_string(hide_password=False)
    )
    created = False
    with psycopg.connect(maintenance, autocommit=True) as control:
        try:
            control.execute(
                sql.SQL("CREATE DATABASE {} OWNER oralhistarchiv TEMPLATE template0").format(
                    sql.Identifier(target)
                )
            )
            created = True
            control.execute(
                sql.SQL("REVOKE CREATE, TEMP ON DATABASE {} FROM PUBLIC").format(
                    sql.Identifier(target)
                )
            )
            control.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO oralhistarchiv_backup").format(
                    sql.Identifier(target)
                )
            )
            subprocess.run(
                [
                    restore,
                    "--exit-on-error",
                    "--single-transaction",
                    "--no-owner",
                    "--no-password",
                    "--dbname",
                    target,
                    str(archive),
                ],
                env=_pg_tool_environment(owner_url),
                check=True,
                capture_output=True,
                timeout=60,
            )
            assert _backup_snapshot(restored_backup_url) == before
            with psycopg.connect(restored_backup_url) as backup:
                assert backup.execute(
                    "SELECT has_table_privilege(current_user, 'public.oral_history_datasets', 'INSERT,UPDATE,DELETE,TRUNCATE'), has_database_privilege(current_database(), 'CREATE,TEMP'), has_schema_privilege('public', 'CREATE')"
                ).fetchone() == (False, False, False)
                assert backup.execute(
                    "SELECT relrowsecurity FROM pg_class WHERE oid = 'public.oral_history_datasets'::regclass"
                ).fetchone() == (True,)
        finally:
            if created:
                control.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(target))
                )


def test_shipped_backup_sql_preflight_refuses_bypass_or_privilege_drift(deployed_database):
    """Execute the literal shipped SQL under the actual read-only backup login."""
    content = (PROJECT_ROOT / "deploy/oralhistarchiv-backup.sh").read_text()
    anchor = 'schema_ready="$(\n'
    assert content.count(anchor) == 1
    prefix, separator, remainder = content.split(anchor, 1)[1].partition("<<'SQL'\n")
    assert separator and "--set=expected_user" in prefix
    statement, terminator, _ = remainder.partition("\nSQL\n")
    assert terminator
    psql = shutil.which("psql")
    assert psql is not None
    backup_url = deployed_database["oralhistarchiv_backup"]

    def readiness():
        """Run the backup-role readiness SQL and return its stripped output."""
        result = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "--no-password",
                "--tuples-only",
                "--no-align",
                "--set=ON_ERROR_STOP=1",
                "--set=expected_database=oralhistarchiv",
                "--set=expected_user=oralhistarchiv_backup",
                "--set=expected_revision=4f73ae3ff827",
                "--file=-",
            ],
            input=statement,
            env=_pg_tool_environment(backup_url),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout.strip()

    assert readiness() == "ready"
    admin_url = (
        make_url(TEST_DATABASE_URL)
        .set(database="oralhistarchiv")
        .render_as_string(hide_password=False)
    )
    with psycopg.connect(admin_url, autocommit=True) as admin:
        for change, restore in (
            (
                "ALTER ROLE oralhistarchiv_backup NOBYPASSRLS",
                "ALTER ROLE oralhistarchiv_backup BYPASSRLS",
            ),
            (
                "GRANT UPDATE ON public.oral_history_datasets TO oralhistarchiv_backup",
                "REVOKE UPDATE ON public.oral_history_datasets FROM oralhistarchiv_backup",
            ),
            (
                "GRANT UPDATE (title) ON public.oral_history_datasets TO oralhistarchiv_backup",
                "REVOKE UPDATE (title) ON public.oral_history_datasets FROM oralhistarchiv_backup",
            ),
            (
                "REVOKE SELECT ON public.users FROM oralhistarchiv_backup",
                "GRANT SELECT ON public.users TO oralhistarchiv_backup",
            ),
        ):
            try:
                admin.execute(change)
                assert readiness() == "not-ready"
            finally:
                admin.execute(restore)
            assert readiness() == "ready"


def _role_recovery_tools(server_version):
    """Require matching PostgreSQL clients plus age tools and return their executable paths."""
    tools = {name: shutil.which(name) for name in ("pg_dump", "pg_restore", "age", "age-keygen")}
    assert all(tools.values()), "Encrypted role recovery requires PostgreSQL clients and age tools"
    for name in ("pg_dump", "pg_restore"):
        result = subprocess.run(
            [tools[name], "--version"], capture_output=True, text=True, check=True, timeout=10
        )
        match = re.search(r"PostgreSQL\) (\d+)\.", result.stdout)
        assert match is not None and int(match[1]) == server_version // 10000, (
            "Encrypted role recovery requires PostgreSQL clients matching the server major version"
        )
    return tools


def _role_recovery_stream(first, second, first_environment, second_environment, output):
    """Keep decrypted archive bytes in a pipe; bound and check both real children."""
    processes = []
    try:
        producer = subprocess.Popen(
            first, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=first_environment
        )
        processes.append(producer)
        assert producer.stdout is not None
        consumer = subprocess.Popen(
            second,
            stdin=producer.stdout,
            stdout=output,
            stderr=subprocess.DEVNULL,
            env=second_environment,
        )
        processes.append(consumer)
        producer.stdout.close()
        deadline = time.monotonic() + 60
        statuses = [
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            for process in reversed(processes)
        ]
        assert statuses == [0, 0], f"Encrypted role recovery pipeline failed: {statuses}"
    finally:
        if processes and processes[0].stdout is not None:
            processes[0].stdout.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


async def _assert_role_recovery_boundaries(restored, records, before):
    """Check the recovered schema and real restricted-role data boundaries."""
    for process in ("web", "scheduler"):
        async with AsyncConnectionPool(
            restored[f"oralhistarchiv_{process}"], min_size=1, max_size=1, open=False
        ) as pool:
            await pool.wait(timeout=5)
            await validate_runtime_schema(pool, process=process)

    visible = {item["id"]: item for item in records.values() if not item["hidden"]}
    for setting in (None, "invalid", *_TIERS):
        viewer = setting if setting in _TIERS else "public"
        with psycopg.connect(restored["oralhistarchiv_web"]) as web:
            if setting is not None:
                web.execute("SELECT set_config('app.viewer_tier', %s, true)", (setting,))
            assert web.execute(
                "SELECT id FROM public.oral_history_datasets ORDER BY id"
            ).fetchall() == [(value,) for value in _permitted_rls_ids(records, viewer)]
            if setting is None:
                with pytest.raises(psycopg.errors.InsufficientPrivilege), web.transaction():
                    web.execute("UPDATE public.oral_history_datasets SET title = title WHERE false")
            projection = web.execute("SELECT * FROM public.catalogue_discovery ORDER BY id DESC")
            assert [column.name for column in projection.description] == [
                "id",
                "uuid",
                "title",
                "access_level",
                "version",
                "source",
                "visibility_tier",
            ]
            rows = projection.fetchall()
            assert {row[0] for row in rows} == set(visible)
            assert _ordered_discovery_ids(web) == sorted(visible, reverse=True)
            for row in rows:
                record = visible[row[0]]
                assert row[1:7] == (
                    record["uuid"],
                    record["title"],
                    "public",
                    "rls-version",
                    record["source"],
                    record["effective_tier"],
                )
    with psycopg.connect(restored["oralhistarchiv_scheduler"]) as scheduler:
        assert scheduler.execute(
            "SELECT count(*) FROM public.oral_history_datasets"
        ).fetchone() == (len(records),)
        canary = scheduler.execute(
            "INSERT INTO public.oral_history_datasets (source, uuid, visibility_tier) "
            "VALUES ('rls_archive', 'e4-scheduler-canary', 'vetted') RETURNING id"
        ).fetchone()
        assert canary is not None
        assert scheduler.execute(
            "UPDATE public.oral_history_datasets SET description = 'E4 hidden write' "
            "WHERE id = %s RETURNING id",
            (records["hidden"]["id"],),
        ).fetchone() == (records["hidden"]["id"],)
        assert (
            scheduler.execute(
                "DELETE FROM public.oral_history_datasets WHERE id = %s RETURNING id",
                canary,
            ).fetchone()
            == canary
        )
        scheduler.rollback()
    assert _backup_snapshot(restored["oralhistarchiv_backup"]) == before
    with psycopg.connect(restored["oralhistarchiv_backup"]) as backup:
        assert backup.execute(
            "SELECT rolsuper, rolbypassrls, "
            "has_database_privilege(current_user, current_database(), 'CREATE,TEMP'), "
            "has_schema_privilege(current_user, 'public', 'CREATE'), "
            "has_table_privilege(current_user, 'public.oral_history_datasets', 'INSERT,UPDATE,DELETE,TRUNCATE') "
            "FROM pg_roles WHERE rolname = current_user"
        ).fetchone() == (False, True, False, False, False)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), backup.transaction():
            backup.execute("UPDATE public.oral_history_datasets SET title = title WHERE false")


def test_actual_backup_role_encrypted_restore_reestablishes_catalogue_boundaries(
    deployed_database, tmp_path
):
    """E4: check encrypted recovery under disposable roles; deployed peer/custody checks remain
    separate.
    """
    records = _seed_rls_catalogue(deployed_database)
    backup_url = deployed_database["oralhistarchiv_backup"]
    before = _backup_snapshot(backup_url)
    assert len(before["catalogue"]) == len(records)
    assert {row["visibility_tier"] for row in before["catalogue"]} == set(_TIERS)
    assert any(row["hidden_at"] is not None for row in before["administration"])
    with psycopg.connect(backup_url) as backup:
        assert backup.execute("SELECT current_user, session_user").fetchone() == (
            "oralhistarchiv_backup",
            "oralhistarchiv_backup",
        )
        assert backup.execute(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone() == (False, True)
        tools = _role_recovery_tools(backup.info.server_version)

    target = f"oha_encrypted_restore_{secrets.token_hex(8)}_test"
    maintenance = (
        make_url(TEST_DATABASE_URL).set(database="postgres").render_as_string(hide_password=False)
    )
    restored = {
        role: make_url(url).set(database=target).render_as_string(hide_password=False)
        for role, url in deployed_database.items()
    }
    tmp_path.chmod(0o700)
    identity = tmp_path / "e4-recovery.agekey"
    archive = tmp_path / "e4-role-backup.dump.age"
    clean_environment = {
        name: value for name, value in os.environ.items() if not name.startswith("PG")
    }
    created = False
    try:
        subprocess.run(
            [tools["age-keygen"], "--output", str(identity)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=clean_environment,
            check=True,
            timeout=10,
        )
        identity.chmod(0o600)
        recipient = subprocess.run(
            [tools["age-keygen"], "-y", str(identity)],
            capture_output=True,
            text=True,
            env=clean_environment,
            check=True,
            timeout=10,
        ).stdout.strip()
        assert recipient.startswith("age1")
        with archive.open("xb") as ciphertext:
            archive.chmod(0o600)
            _role_recovery_stream(
                [
                    tools["pg_dump"],
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    "--no-password",
                ],
                [tools["age"], "--encrypt", "--recipient", recipient],
                _pg_tool_environment(backup_url),
                clean_environment,
                ciphertext,
            )
        assert archive.stat().st_size > 0 and archive.stat().st_mode & 0o777 == 0o600
        assert identity.stat().st_mode & 0o777 == 0o600
        assert {path.name for path in tmp_path.iterdir()} == {archive.name, identity.name}

        with psycopg.connect(maintenance, autocommit=True) as control:
            try:
                control.execute(
                    sql.SQL("CREATE DATABASE {} OWNER oralhistarchiv TEMPLATE template0").format(
                        sql.Identifier(target)
                    )
                )
                created = True
                _role_recovery_stream(
                    [tools["age"], "--decrypt", "--identity", str(identity), str(archive)],
                    [
                        tools["pg_restore"],
                        "--exit-on-error",
                        "--single-transaction",
                        "--no-owner",
                        "--no-privileges",
                        "--no-password",
                        "--dbname",
                        target,
                    ],
                    clean_environment,
                    _pg_tool_environment(restored["oralhistarchiv"]),
                    subprocess.DEVNULL,
                )
                # Production archives omit ACLs. Prove a recovered backup login
                # has no implicit table read grant before reapplying the manifest.
                with psycopg.connect(restored["oralhistarchiv_backup"]) as backup:
                    assert backup.execute(
                        "SELECT has_table_privilege(current_user, 'public.oral_history_datasets', 'SELECT'), "
                        "has_table_privilege('oralhistarchiv_web', 'public.catalogue_discovery', 'SELECT'), "
                        "has_table_privilege('oralhistarchiv_scheduler', 'public.oral_history_datasets', 'SELECT')"
                    ).fetchone() == (False, False, False)
                grants = (PROJECT_ROOT / "deploy/database-runtime-grants.sql").read_text()
                quoted_target = sql.Identifier(target).as_string(control)
                grants, changed = re.subn(
                    r"\bON DATABASE oralhistarchiv\b",
                    lambda _: f"ON DATABASE {quoted_target}",
                    grants,
                )
                assert changed == 4, "Unexpected database grant-manifest target inventory"
                psql = shutil.which("psql")
                assert psql is not None
                subprocess.run(
                    [psql, "--no-psqlrc", "--no-password", "--set=ON_ERROR_STOP=1", "--file=-"],
                    input=grants,
                    env=_pg_tool_environment(restored["oralhistarchiv"]),
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                for role in ("oralhistarchiv_web", "oralhistarchiv_scheduler"):
                    control.execute(
                        sql.SQL(
                            "ALTER ROLE {} IN DATABASE {} SET search_path = pg_catalog, public"
                        ).format(sql.Identifier(role), sql.Identifier(target))
                    )
                asyncio.run(_assert_role_recovery_boundaries(restored, records, before))
            finally:
                if created:
                    control.execute(
                        sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(target))
                    )
    finally:
        identity.unlink(missing_ok=True)


async def test_scheduler_reads_only_delivery_and_cleanup_columns(deployed_database):
    """The real scheduler login rejects credential reads while both jobs remain usable."""
    async with (
        AsyncConnectionPool(deployed_database["oralhistarchiv"], open=False) as owner,
        get_db_cursor(owner) as cur,
    ):
        await cur.execute(
            "INSERT INTO users (email, is_active, email_verification_token_hash, "
            "email_verification_created_at) "
            "VALUES ('delivery-grant-probe@example.org', false, 'live-capability-hash', "
            "clock_timestamp()) RETURNING id"
        )
        delivery_user = (await cur.fetchone())["id"]
        await enqueue_email_cur(
            cur,
            user_id=delivery_user,
            message_type="email_verification",
            recipient="delivery-grant-probe@example.org",
            subject="Grant contract",
            body="Synthetic message",
            action=ActionEmailMetadata(
                "live-capability-hash", datetime.now(UTC) + timedelta(hours=1)
            ),
        )
        await cur.execute(
            "INSERT INTO users (email, is_active, created_at) "
            "VALUES ('cleanup-grant-probe@example.org', false, "
            "clock_timestamp() - INTERVAL '40 days') RETURNING id"
        )
        cleanup_user = (await cur.fetchone())["id"]

    with psycopg.connect(deployed_database["oralhistarchiv_scheduler"]) as connection:
        assert connection.execute(
            "SELECT has_table_privilege(current_user, 'public.users', 'SELECT')"
        ).fetchone() == (False,)
        for column in (
            "password_hash",
            "totp_secret",
            "pending_totp_secret",
            "pending_totp_session_hash",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), connection.transaction():
                connection.execute(
                    sql.SQL("SELECT {} FROM public.users LIMIT 0").format(sql.Identifier(column))
                )
        with pytest.raises(psycopg.errors.InsufficientPrivilege), connection.transaction():
            connection.execute("SELECT * FROM public.users LIMIT 0")

    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_scheduler"], open=False
    ) as scheduler:
        await validate_runtime_database_role(scheduler, process="scheduler")
        claims = await claim_due_emails(scheduler, limit=1, lease_timeout=timedelta(minutes=5))
        assert len(claims) == 1
        assert await prepare_email_delivery(
            scheduler,
            claims[0],
            lease_timeout=timedelta(minutes=5),
            min_remaining_lifetime=timedelta(seconds=10),
        )
        assert await reap_unverified_accounts(scheduler, max_age_days=30) == 1
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        assert (
            owner.execute("SELECT id FROM users WHERE id = %s", (cleanup_user,)).fetchone() is None
        )
        assert owner.execute("SELECT id FROM users WHERE id = %s", (delivery_user,)).fetchone() == (
            delivery_user,
        )


async def test_scheduler_verifiers_reject_restored_credential_access(deployed_database):
    """Effective grants, including table-wide overrides, are checked by both validators."""
    psql = shutil.which("psql")
    assert psql is not None
    async with AsyncConnectionPool(
        deployed_database["oralhistarchiv_scheduler"], open=False
    ) as scheduler:
        await validate_runtime_database_role(scheduler, process="scheduler")
        for grant, revoke in (
            (
                "GRANT SELECT (password_hash) ON users TO oralhistarchiv_scheduler",
                "REVOKE SELECT (password_hash) ON users FROM oralhistarchiv_scheduler",
            ),
            (
                "GRANT SELECT ON users TO oralhistarchiv_scheduler",
                "REVOKE SELECT ON users FROM oralhistarchiv_scheduler",
            ),
        ):
            with psycopg.connect(deployed_database["oralhistarchiv"], autocommit=True) as owner:
                original_columns = [
                    row[0]
                    for row in owner.execute(
                        "SELECT attname FROM pg_attribute "
                        "WHERE attrelid = 'public.users'::regclass "
                        "AND attnum > 0 AND NOT attisdropped "
                        "AND has_column_privilege('oralhistarchiv_scheduler', "
                        "attrelid, attname, 'SELECT') ORDER BY attname"
                    ).fetchall()
                ]
                owner.execute(grant)
                try:
                    with pytest.raises(RuntimeError, match=r"users\.(password_hash|SELECT)"):
                        await validate_runtime_database_role(scheduler, process="scheduler")
                    checked = await asyncio.to_thread(
                        subprocess.run,
                        [
                            psql,
                            "-X",
                            "--no-password",
                            "--file",
                            str(PROJECT_ROOT / "deploy/verify-runtime-database-access.sql"),
                        ],
                        env=_pg_tool_environment(deployed_database["oralhistarchiv_scheduler"]),
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    assert checked.returncode != 0
                    assert "unexpected users SELECT columns" in checked.stderr
                finally:
                    owner.execute(revoke)
                    # Restoring a table-level SELECT revocation also requires
                    # reinstalling the original per-column read permissions.
                    owner.execute(
                        sql.SQL("GRANT SELECT ({}) ON users TO oralhistarchiv_scheduler").format(
                            sql.SQL(", ").join(map(sql.Identifier, original_columns))
                        )
                    )
            await validate_runtime_database_role(scheduler, process="scheduler")


def test_runtime_producers_cannot_read_or_rewrite_security_evidence(deployed_database):
    """Actual producer logins append evidence without acquiring its readership or custody."""
    identifiers = []
    for role in ("oralhistarchiv_web", "oralhistarchiv_scheduler"):
        event_id = uuid4()
        identifiers.append(event_id)
        with psycopg.connect(deployed_database[role], autocommit=True) as producer:
            producer.execute(
                "INSERT INTO security_audit_events (event_id, event_type, payload) "
                "VALUES (%s, 'restriction_changed', %s)",
                (event_id, Jsonb({"dataset_id": 1})),
            )
            for statement in (
                "SELECT * FROM security_audit_events",
                "UPDATE security_audit_events SET payload = '{}'::jsonb",
                "DELETE FROM security_audit_events",
                "TRUNCATE security_audit_events CASCADE",
                "SELECT * FROM security_audit_receipts",
                "SELECT * FROM source_security_state",
                "DELETE FROM source_security_state",
                "DELETE FROM source_binding_acknowledgements",
                "SELECT public.catalogue_preserve_source_security_state()",
                "SELECT public.catalogue_audit_restriction_state()",
            ):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    producer.execute(statement)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                producer.execute(
                    "INSERT INTO security_audit_receipts (event_id) VALUES (%s)", (event_id,)
                )
            if role == "oralhistarchiv_scheduler":
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    producer.execute("SELECT * FROM anonymous_mail_issuance")
    with psycopg.connect(deployed_database["oralhistarchiv"]) as owner:
        rows = owner.execute(
            "SELECT event_id, payload FROM security_audit_events WHERE event_id = ANY(%s)",
            (identifiers,),
        ).fetchall()
        assert {identifier for identifier, _ in rows} == set(identifiers)
        assert all(payload == {"dataset_id": 1} for _, payload in rows)


def test_future_owner_function_is_private_before_any_explicit_function_grants(deployed_database):
    """Default ACLs protect a new routine without another manifest-repair pass."""
    with psycopg.connect(deployed_database["oralhistarchiv"], autocommit=True) as owner:
        owner.execute(
            "CREATE FUNCTION public.default_acl_probe() RETURNS integer "
            "LANGUAGE sql IMMUTABLE AS 'SELECT 1'"
        )
        try:
            for role in ("oralhistarchiv_web", "oralhistarchiv_scheduler"):
                with psycopg.connect(deployed_database[role]) as connection:
                    assert connection.execute(
                        "SELECT has_function_privilege(current_user, 'public.default_acl_probe()', 'EXECUTE')"
                    ).fetchone() == (False,)
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        connection.execute("SELECT public.default_acl_probe()")
            owner.execute(
                "GRANT EXECUTE ON FUNCTION public.default_acl_probe() TO oralhistarchiv_scheduler"
            )
            with psycopg.connect(deployed_database["oralhistarchiv_scheduler"]) as scheduler:
                assert scheduler.execute("SELECT public.default_acl_probe()").fetchone() == (1,)
        finally:
            owner.execute("DROP FUNCTION public.default_acl_probe()")
