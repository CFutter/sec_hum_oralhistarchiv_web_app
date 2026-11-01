"""Fresh schema installation and drift checks use only newly created, fixture-owned databases."""

import re
import secrets
from collections.abc import Iterator

import psycopg
import pytest
from alembic.config import Config
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from sqlalchemy.engine import make_url

from alembic import command
from app.paths import ALEMBIC_DIR, ALEMBIC_INI
from app.services import build_catalogue_policy
from app.services.db_drift import validate_schema_against_db
from config import settings

_REVISION = "4f73ae3ff827"
_TEST_DATABASE = re.compile(r".*_test(?:_gw\d+)?")
_EMPTY_POLICY = build_catalogue_policy(())
_EMPTY_PAGE_QUERY = Jsonb(
    {
        "mode": "empty",
        "term": "",
        "pattern": "%%",
        "keyword": "",
        "language": "",
        "access_level": "",
        "masks": {"*": 0},
        "fingerprint": _EMPTY_POLICY.fingerprint,
    }
)


@pytest.fixture(scope="session")
def _ensure_schema() -> Iterator[None]:
    """Override the shared database migration; this module migrates its own targets."""
    yield


@pytest.fixture
def clean_db() -> Iterator[None]:
    """Override shared-table truncation because no test here uses that database."""
    yield


@pytest.fixture
def isolated_fresh_database(monkeypatch):
    """Create a nonce database, and drop it only after this fixture created it."""
    base = settings.database_url.get_secret_value()
    selected = conninfo_to_dict(base).get("dbname", "")
    assert isinstance(selected, str) and _TEST_DATABASE.fullmatch(selected), (
        "Isolated migration checks require the configured disposable test database"
    )
    target = f"rls_upgrade_{secrets.token_hex(8)}_test"
    target_url = make_url(base).set(database=target).render_as_string(hide_password=False)
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    monkeypatch.setenv("ENV_STATE", "staging")
    monkeypatch.setenv("MIGRATION_DATABASE_URL", target_url)
    created = False
    with psycopg.connect(make_conninfo(base, dbname="postgres"), autocommit=True) as control:
        assert (
            control.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target,)).fetchone()
            is None
        )
        try:
            control.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(target))
            )
            created = True
            yield target_url, config
        finally:
            if created:
                control.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(target))
                )


def _seed_catalogue_state(connection):
    """Seed tiers, admin overrides, quarantine and source state for migration checks."""
    connection.execute(
        "SELECT public.catalogue_initialize_search_policy(%s, %s)",
        (
            _EMPTY_POLICY.fingerprint,
            Jsonb({str(rank): dict(masks) for rank, masks in _EMPTY_POLICY.page_masks.items()}),
        ),
    )
    for source, uuid, tier, date in (
        ("migration_archive", "public-row", "public", "2026-01-03T00:00:00Z"),
        ("migration_archive", "registered-row", "registered", "2026-01-04T00:00:00Z"),
        ("migration_archive", "vetted-row", "vetted", "2026-01-05T00:00:00Z"),
        ("migration_archive", "hidden-row", "public", "2026-01-06T00:00:00Z"),
        ("migration_archive", "admin-floor", "public", "2026-01-02T00:00:00Z"),
        ("independent_archive", "public-row", "public", "2026-01-01T00:00:00Z"),
    ):
        record_tier = (
            {"invalid": "classification is not descriptive metadata"}
            if uuid == "admin-floor"
            else tier
        )
        connection.execute(
            """INSERT INTO oral_history_datasets
               (source, uuid, title, visibility_tier, description, authors, keywords,
                languages, resource_proxies, data, upstream_modified_at, synced_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                source,
                uuid,
                f"Public discovery {uuid}",
                tier,
                f"Preserve descriptive metadata for {source}/{uuid}",
                ["Synthetic Author"],
                ["preserved", "keyword"],
                ["de", "fr"],
                Jsonb([{"type": "Resource", "ref": f"https://archive.example.org/{uuid}"}]),
                Jsonb({"visibility_tier": record_tier, "nested": {"value": [1, None, True]}}),
                date,
                "2026-01-07T00:00:00Z",
            ),
        )
    connection.execute(
        """INSERT INTO dataset_admin_state (source, uuid, visibility_tier, hidden_at)
           VALUES ('migration_archive', 'hidden-row', NULL, '2026-01-08T00:00:00Z'),
                  ('migration_archive', 'admin-floor', 'vetted', NULL),
                  ('migration_archive', 'orphaned-identity', 'registered', '2026-01-08T00:00:00Z')"""
    )
    connection.execute(
        """INSERT INTO sync_status
           (source, source_cursor, source_fingerprint, incremental_harvest,
            incremental_started_at, incremental_position, incremental_affected,
            last_harvest_date, last_full_rebuild_date, last_sync_error, last_sync_error_at)
           VALUES ('migration_archive', '2026-01-07T00:00:00Z', %s, %s,
                   '2026-01-08T00:00:00Z', 1, 1, '2026-01-07T00:00:00Z',
                   '2026-01-06T00:00:00Z', 'Preserved synthetic staging diagnostic',
                   '2026-01-08T00:00:00Z')""",
        ("a" * 64, b'{"records":[{"uuid":"staged-row"}],"opaque":"\x00\xff"}'),
    )
    connection.execute(
        """INSERT INTO ingestion_failures (source, uuid, message, updated_at)
           VALUES ('migration_archive', 'rejected-row', %s, '2026-01-08T00:00:00Z')""",
        ('{"reason":"preserved synthetic rejection"}',),
    )


def _snapshot(connection):
    """Capture all application row values, constraints and sequence state."""
    connection.execute("SET TIME ZONE 'UTC'")
    tables = connection.execute(
        """SELECT table_name FROM information_schema.tables
           WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
             AND table_name <> 'alembic_version' ORDER BY table_name"""
    ).fetchall()
    rows = {}
    for (name,) in tables:
        rows[name] = connection.execute(
            sql.SQL(
                "SELECT to_jsonb(stored) FROM public.{} AS stored ORDER BY to_jsonb(stored)::text"
            ).format(sql.Identifier(name))
        ).fetchall()
    constraints = connection.execute(
        """SELECT relation.relname, constraint_record.conname,
                  pg_get_constraintdef(constraint_record.oid, false),
                  constraint_record.condeferrable, constraint_record.condeferred,
                  constraint_record.convalidated, constraint_record.connoinherit
           FROM pg_constraint AS constraint_record
           JOIN pg_class AS relation ON relation.oid = constraint_record.conrelid
           JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = 'public'
           ORDER BY relation.relname, constraint_record.conname"""
    ).fetchall()
    sequences = connection.execute(
        """SELECT sequencename, start_value, min_value, max_value, increment_by,
                  cycle, cache_size, last_value
           FROM pg_sequences WHERE schemaname = 'public' ORDER BY sequencename"""
    ).fetchall()
    return rows, constraints, sequences


def _reseeded_snapshot(snapshot):
    """Compare generated event meaning while retaining exact ordinary row values."""
    rows, constraints, sequences = snapshot
    normalized = dict(rows)
    normalized["security_audit_events"] = sorted(
        [
            ({key: value for key, value in event.items() if key not in {"event_id", "created_at"}},)
            for (event,) in rows["security_audit_events"]
        ],
        key=lambda row: (row[0]["event_type"], repr(row[0]["payload"])),
    )
    return normalized, constraints, sequences


async def _validate(target_url):
    """Run the live schema validator through a one-connection pool."""
    async with AsyncConnectionPool(target_url, min_size=1, max_size=1, open=False) as pool:
        await validate_schema_against_db(pool)


async def test_fresh_schema_installation_teardown_and_reinstallation_restore_catalogue_security(
    isolated_fresh_database,
):
    """Verify fresh schema installation teardown and reinstallation restore catalogue security."""
    target_url, config = isolated_fresh_database
    with psycopg.connect(target_url) as connection:
        assert connection.execute(
            "SELECT count(*) FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public'"
        ).fetchone() == (0,)
    command.upgrade(config, _REVISION)
    await _validate(target_url)
    with psycopg.connect(target_url) as connection:
        empty_schema = _snapshot(connection)
        assert all(not rows for rows in empty_schema[0].values())
        _seed_catalogue_state(connection)
        populated_schema = _snapshot(connection)
        assert len(populated_schema[0]["oral_history_datasets"]) == 6
        assert len(populated_schema[0]["dataset_admin_state"]) == 3
        assert populated_schema[0]["sync_status"] and populated_schema[0]["ingestion_failures"]
        assert connection.execute(
            "SELECT discovery.source, discovery.uuid, discovery.visibility_tier "
            "FROM public.catalogue_page_ids(NULL, public.catalogue_scan_ceiling(), "
            "false, 200, 0, %s) WITH ORDINALITY AS selected(id, position) "
            "JOIN public.catalogue_discovery AS discovery ON discovery.id = selected.id "
            "ORDER BY selected.position",
            (_EMPTY_PAGE_QUERY,),
        ).fetchall() == [
            ("migration_archive", "vetted-row", "vetted"),
            ("migration_archive", "registered-row", "registered"),
            ("migration_archive", "public-row", "public"),
            ("migration_archive", "admin-floor", "vetted"),
            ("independent_archive", "public-row", "public"),
        ]
        assert connection.execute(
            "SELECT record_tier FROM dataset_admin_catalogue WHERE uuid = 'admin-floor'"
        ).fetchone() == (None,)
        assert connection.execute("SELECT count(*) FROM dataset_admin_catalogue").fetchone() == (6,)
    # A fresh-schema downgrade intentionally removes application tables and data.
    command.downgrade(config, "base")
    with psycopg.connect(target_url) as connection:
        assert connection.execute(
            "SELECT relation.relname FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'v', 'S') "
            "ORDER BY relation.relname"
        ).fetchall() == [("alembic_version",)]
        assert connection.execute("SELECT count(*) FROM alembic_version").fetchone() == (0,)
        assert (
            connection.execute("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'").fetchone()
            is None
        )
    command.upgrade(config, _REVISION)
    await _validate(target_url)
    with psycopg.connect(target_url) as connection:
        assert _snapshot(connection) == empty_schema
        _seed_catalogue_state(connection)
        reinstalled = _snapshot(connection)
        assert _reseeded_snapshot(reinstalled) == _reseeded_snapshot(populated_schema)
        assert {row[0]["event_id"] for row in reinstalled[0]["security_audit_events"]}.isdisjoint(
            row[0]["event_id"] for row in populated_schema[0]["security_audit_events"]
        )
    command.upgrade(config, _REVISION)
    with psycopg.connect(target_url) as connection:
        assert _snapshot(connection) == reinstalled


async def test_fresh_baseline_credential_budget_and_notice_constraints_survive_reinstallation(
    isolated_fresh_database,
):
    """Fresh installs enforce reset budgets and permit durable password-change notices."""
    target_url, config = isolated_fresh_database
    for installation in range(2):
        command.upgrade(config, "head")
        await _validate(target_url)
        with psycopg.connect(target_url) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                _REVISION,
            )
            assert connection.execute("SELECT count(*) FROM users").fetchone() == (0,)
            owner, count, started_at = connection.execute(
                """INSERT INTO users (email, password_hash, password_reset_token_hash,
                                      password_reset_created_at)
                   VALUES ('migration-owner@example.org', 'retained-password-hash',
                           'retained-reset-hash', clock_timestamp())
                   RETURNING id, password_reset_attempt_count,
                             password_reset_attempt_window_started_at"""
            ).fetchone()
            assert (count, started_at) == (0, None)
            assert connection.execute(
                """UPDATE users SET password_reset_attempt_count = 5,
                          password_reset_attempt_window_started_at = clock_timestamp()
                   WHERE id = %s
                   RETURNING password_reset_attempt_count,
                             password_reset_attempt_window_started_at IS NOT NULL""",
                (owner,),
            ).fetchone() == (5, True)
            for count, window, constraint in (
                (-1, "2026-01-01T00:00:00Z", "users_password_reset_attempt_count_check"),
                (6, "2026-01-01T00:00:00Z", "users_password_reset_attempt_count_check"),
                (0, "2026-01-01T00:00:00Z", "users_password_reset_attempt_window_check"),
                (1, None, "users_password_reset_attempt_window_check"),
            ):
                with (
                    pytest.raises(psycopg.errors.CheckViolation, match=constraint),
                    connection.transaction(),
                ):
                    connection.execute(
                        """UPDATE users SET password_reset_attempt_count = %s,
                                  password_reset_attempt_window_started_at = %s WHERE id = %s""",
                        (count, window, owner),
                    )
            notice = connection.execute(
                """INSERT INTO email_outbox
                       (user_id, message_type, recipient, subject, body_ciphertext)
                   VALUES (%s, 'password_changed_notice', 'migration-owner@example.org',
                           'Password changed', 'synthetic-encrypted-body')
                   RETURNING message_type, action_token_hash, expires_at, status""",
                (owner,),
            ).fetchone()
            assert notice == ("password_changed_notice", None, None, "pending")
            for kind, action_hash, expires_at in (
                ("password_changed_notice", "synthetic-action-hash", "2026-01-01T00:00:00Z"),
                ("password_reset", None, None),
                ("unknown_notice", None, None),
            ):
                with (
                    pytest.raises(
                        psycopg.errors.CheckViolation, match="email_outbox_action_metadata_check"
                    ),
                    connection.transaction(),
                ):
                    connection.execute(
                        """INSERT INTO email_outbox
                               (user_id, message_type, recipient, subject, body_ciphertext,
                                action_token_hash, expires_at)
                           VALUES (%s, %s, 'migration-owner@example.org', 'Invalid metadata',
                                   'synthetic-encrypted-body', %s, %s)""",
                        (owner, kind, action_hash, expires_at),
                    )
        if installation == 0:
            # The explicit fresh-schema reset removes fixture-owned application data.
            command.downgrade(config, "base")
            with psycopg.connect(target_url) as connection:
                assert connection.execute(
                    "SELECT to_regclass('public.users'), to_regclass('public.email_outbox')"
                ).fetchone() == (None, None)
                assert connection.execute("SELECT count(*) FROM alembic_version").fetchone() == (0,)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            "ALTER TABLE public.oral_history_datasets DISABLE ROW LEVEL SECURITY",
            "Row-security drift",
        ),
        ("ALTER TABLE public.oral_history_datasets FORCE ROW LEVEL SECURITY", "Row-security drift"),
        (
            "CREATE POLICY unexpected_permissive ON public.oral_history_datasets FOR SELECT USING (true)",
            "Row-security drift",
        ),
        (
            "ALTER POLICY catalogue_web_select ON public.oral_history_datasets USING (true)",
            "Row-security drift",
        ),
        (
            "ALTER POLICY catalogue_web_select ON public.oral_history_datasets TO CURRENT_USER",
            "Row-security drift",
        ),
        (
            "ALTER VIEW public.catalogue_discovery SET (security_invoker = true)",
            "Schema drift on view",
        ),
        (
            """CREATE OR REPLACE VIEW public.catalogue_discovery AS
               SELECT id, uuid, title, access_level, version, source, visibility_tier,
                      data
               FROM public.oral_history_datasets""",
            "Schema drift on view",
        ),
        (
            "ALTER FUNCTION public.catalogue_scan_ceiling() VOLATILE",
            "Schema drift in managed PostgreSQL functions",
        ),
        (
            "ALTER FUNCTION public.catalogue_page_ids(integer, integer, boolean, integer, integer, jsonb) "
            "SECURITY INVOKER",
            "Schema drift in managed PostgreSQL functions",
        ),
        (
            "ALTER FUNCTION public.catalogue_page_ids(integer, integer, boolean, integer, integer, jsonb) "
            "RESET ALL",
            "Schema drift in managed PostgreSQL functions",
        ),
    ),
    ids=(
        "disabled",
        "forced",
        "extra-policy",
        "predicate",
        "roles",
        "invoker",
        "raw-column",
        "function-volatility",
        "function-invoker",
        "function-path",
    ),
)
async def test_runtime_schema_validation_rejects_real_rls_or_discovery_drift(
    isolated_fresh_database, mutation, message
):
    """Verify runtime schema validation rejects real RLS or discovery drift."""
    target_url, config = isolated_fresh_database
    command.upgrade(config, _REVISION)
    await _validate(target_url)
    with psycopg.connect(target_url) as connection:
        connection.execute(mutation)
    with pytest.raises(RuntimeError, match=message):
        await _validate(target_url)


async def test_fresh_baseline_quarantine_progress_defaults_and_reinstallation(
    isolated_fresh_database,
):
    """Fresh installs expose independent clean/consumed state without a backfill."""
    target_url, config = isolated_fresh_database
    for installation in range(2):
        command.upgrade(config, _REVISION)
        await _validate(target_url)
        with psycopg.connect(target_url) as connection:
            assert connection.execute("SELECT count(*) FROM sync_status").fetchone() == (0,)
            assert connection.execute(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = 'public' "
                "AND table_name = 'sync_status' AND column_name LIKE 'source_fetch_%' "
                "ORDER BY column_name"
            ).fetchall() == [
                ("source_fetch_cursor", "timestamp with time zone", "YES", None),
                ("source_fetch_fingerprint", "text", "YES", None),
            ]
            assert (
                connection.execute(
                    "INSERT INTO sync_status (source) VALUES ('fresh_source') "
                    "RETURNING source_cursor, source_fingerprint, source_fetch_cursor, "
                    "source_fetch_fingerprint, last_harvest_date, last_full_rebuild_date"
                ).fetchone()
                == (None,) * 6
            )
            connection.execute(
                """INSERT INTO sync_status
                   (source, source_cursor, source_fingerprint, source_fetch_cursor,
                    source_fetch_fingerprint, last_sync_error)
                   VALUES ('quarantined', '2030-01-01T00:00:00Z', %s,
                           '2030-02-01T00:00:00Z', %s, 'Unresolved record')""",
                ("a" * 64, "b" * 64),
            )
            connection.execute(
                "INSERT INTO ingestion_failures (source, uuid, message) "
                "VALUES ('quarantined', 'new-record', 'invalid metadata')"
            )
        # A second connection proves both states and the quarantine survive restart.
        with psycopg.connect(target_url) as connection:
            assert connection.execute(
                "SELECT source_cursor = '2030-01-01T00:00:00Z', "
                "source_fetch_cursor = '2030-02-01T00:00:00Z', "
                "source_fingerprint, source_fetch_fingerprint, last_sync_error "
                "FROM sync_status WHERE source = 'quarantined'"
            ).fetchone() == (True, True, "a" * 64, "b" * 64, "Unresolved record")
            assert connection.execute(
                "SELECT uuid, message FROM ingestion_failures WHERE source = 'quarantined'"
            ).fetchall() == [("new-record", "invalid metadata")]
        if installation == 0:
            command.downgrade(config, "base")
            with psycopg.connect(target_url) as connection:
                assert connection.execute(
                    "SELECT to_regclass('public.sync_status'), "
                    "to_regclass('public.ingestion_failures')"
                ).fetchone() == (None, None)
                assert connection.execute("SELECT count(*) FROM alembic_version").fetchone() == (0,)


async def test_earlier_baseline_body_requires_operator_recreation(isolated_fresh_database):
    """The same revision label cannot retrofit missing consumed-progress columns."""
    target_url, config = isolated_fresh_database
    command.upgrade(config, _REVISION)
    with psycopg.connect(target_url) as connection:
        connection.execute(
            "ALTER TABLE sync_status DROP COLUMN source_fetch_cursor, "
            "DROP COLUMN source_fetch_fingerprint"
        )
    command.upgrade(config, "head")
    with psycopg.connect(target_url) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            _REVISION,
        )
    with pytest.raises(RuntimeError, match="Schema drift on 'sync_status': missing columns"):
        await _validate(target_url)
