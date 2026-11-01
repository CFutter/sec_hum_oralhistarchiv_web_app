"""PostgreSQL integration fixtures using the application migrations.

DATABASE_URL defaults to the disposable database in docker-compose.yml. Tests
truncate and commit shared tables before each test; use a *_test or *_test_gwN
database, or explicitly set ALLOW_DESTRUCTIVE_DB=1. Unreachable PostgreSQL skips
the tier unless REQUIRE_DB=1, which raises instead. xdist workers use separate
databases; concurrent serial runs must use separate databases too.
"""

import os
import re
import secrets
import subprocess
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import create_autospec, patch

import psycopg
import pyotp
import pytest
from alembic.config import Config
from argon2 import PasswordHasher
from fastapi import status
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.types.json import Jsonb

import app.main as _app_main
from alembic import command
from app.main import app
from app.paths import ALEMBIC_DIR, ALEMBIC_INI
from app.services import build_catalogue_policy, ensure_source_status_rows
from app.services.db import create_pool
from app.services.session_ids import hash_session_id
from app.services.tokens import hash_token
from app.services.totp_crypto import encrypt_value
from tests.fixtures import replace_test_catalogue_sources
from tests.source_fixtures import TEST_SOURCE_NAME, legacy_source

from .server_processes import free_port, start_private_redis, terminate_process

# The real lifespan collaborators the end-to-end client stubs, captured once
# at import so every stub is signature-checked against the production
# callable (a lifespan that drifts to a new argument shape fails here instead
# of running against a permissive mock).
_REAL_LIFESPAN_TARGETS = {
    name: getattr(_app_main, name)
    for name in (
        "validate_security_settings",
        "validate_runtime_schema",
        "reconcile_federated_session_policy",
        "setup_logging",
    )
}

# The documented contract: env var with a docker-compose-matching default.
TEST_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://test:test@localhost:5432/oralhistarchiv_test",
)

# TRUNCATE guard: clean_db wipes whatever DATABASE_URL points at, so refuse
# to run destructive fixtures against anything that doesn't look like a test
# database: a '*_test' name, or that name plus an xdist worker suffix
# ('*_test_gw3'). ALLOW_DESTRUCTIVE_DB=1 is the explicit, auditable override.
_DB_NAME = TEST_DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
_TEST_DATABASE_NAME = re.compile(r".*_test(_gw\d+)?")
_DESTRUCTIVE_OK = (
    _TEST_DATABASE_NAME.fullmatch(_DB_NAME) is not None
    or os.environ.get("ALLOW_DESTRUCTIVE_DB") == "1"
)


def _assert_test_database() -> None:
    """Refuse destructive fixtures unless the database name or explicit override permits them."""
    assert _DESTRUCTIVE_OK, (
        f"refusing to TRUNCATE non-test database {_DB_NAME!r} "
        f"(URL from DATABASE_URL); name a '*_test' database or set "
        f"ALLOW_DESTRUCTIVE_DB=1 to override"
    )


# Serialises CREATE DATABASE across xdist workers (an arbitrary constant key
# on the instance's maintenance database).
_WORKER_DATABASE_CREATION_LOCK = 8_212_026


def _ensure_worker_database() -> None:
    """Create a missing xdist database under a maintenance-database advisory lock.

    Use DATABASE_URL credentials against the same instance's postgres database.
    Do nothing outside a worker; suppress setup errors so the later connectivity
    probe determines whether the tier skips or errors under REQUIRE_DB=1.
    """
    if not os.environ.get("PYTEST_XDIST_WORKER"):
        return
    head, _, tail = TEST_DATABASE_URL.rpartition("/")
    query = tail[len(_DB_NAME) :]
    maintenance_url = f"{head}/postgres{query}"
    try:
        with psycopg.connect(maintenance_url, autocommit=True, connect_timeout=3) as conn:
            conn.execute("SELECT pg_advisory_lock(%s)", (_WORKER_DATABASE_CREATION_LOCK,))
            try:
                exists = conn.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s", (_DB_NAME,)
                ).fetchone()
                if exists is None:
                    conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(_DB_NAME)))
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (_WORKER_DATABASE_CREATION_LOCK,))
    except Exception:
        return


# Precomputed hash so user_factory doesn't pay Argon2 cost per insert.
DEFAULT_PASSWORD = "Sup3rSecret!pw-for-tests"
_PH = PasswordHasher()
_DEFAULT_PW_HASH = _PH.hash(DEFAULT_PASSWORD)


def _db_reachable() -> bool:
    """Probe PostgreSQL with a three-second connect timeout; return False on any exception."""
    try:
        with psycopg.connect(TEST_DATABASE_URL, connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


_ensure_worker_database()
_DB_AVAILABLE = _db_reachable()


@pytest.fixture(scope="session", autouse=True)
def _ensure_schema():
    """Migrate the disposable database to head once per session.

    An unreachable database skips the tier, or raises RuntimeError with REQUIRE_DB=1.
    The destructive-database guard runs before migrations.
    """
    if not _DB_AVAILABLE:
        if os.environ.get("REQUIRE_DB") == "1":
            raise RuntimeError(
                f"REQUIRE_DB=1 but integration database unreachable at {TEST_DATABASE_URL}"
            )
        pytest.skip(f"integration database not reachable at {TEST_DATABASE_URL}")

    _assert_test_database()

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def clean_db(_ensure_schema):
    """Truncate test tables, reset identities and seed a bound source before each test.

    Commits the reset; tests share this database and must not run concurrently in it.
    Use unbound_catalogue when the test needs a fresh source without a binding.
    """
    _assert_test_database()
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute(
            """
            TRUNCATE
                anonymous_mail_issuance,
                security_audit_receipts,
                security_audit_events,
                source_security_state,
                source_binding_acknowledgements,
                catalogue_search_policy,
                federation_policy_state,
                email_outbox,
                sessions,
                users,
                oral_history_datasets,
                dataset_admin_state,
                ingestion_failures,
                ingestion_quarantine
            RESTART IDENTITY CASCADE
            """
        )
        conn.execute("DELETE FROM sync_status")
        conn.execute(
            "INSERT INTO sync_status (source, last_harvest_date, source_fingerprint) "
            "VALUES (%s, %s, %s)",
            (
                TEST_SOURCE_NAME,
                datetime(2026, 1, 1, tzinfo=UTC),
                legacy_source().adapter.config_fingerprint(),
            ),
        )
        conn.commit()
    yield


@pytest.fixture
def private_redis(tmp_path: Path) -> Iterator[tuple[int, subprocess.Popen[bytes]]]:
    """A private, disposable redis-server with no persistence, owned by one test."""
    port = free_port()
    proc = start_private_redis(tmp_path, port, "--appendonly", "no")
    try:
        yield port, proc
    finally:
        terminate_process(proc)


@pytest.fixture
def unbound_catalogue():
    """Clear and commit the test source binding so incremental sync requires a rebuild."""
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute(
            "UPDATE sync_status SET source_fingerprint = NULL WHERE source = %s",
            (TEST_SOURCE_NAME,),
        )
        conn.commit()
    yield


@pytest.fixture
def sync_conn():
    """A plain synchronous psycopg connection for test-side setup/asserts."""
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        yield conn


@pytest.fixture
def bind_catalogue_policy(clean_db):
    """Explicit owner setup for the policy a test intends to serve.

    This is never installed in a query path. Repeated setup calls deliberately
    perform an owner compare-and-swap transition when the test changes policy,
    including rebuilding the physical projections through the real SQL API.
    """
    del clean_db  # Fixture dependency orders binding after the destructive reset.

    def bind(sources, *, database_url=TEST_DATABASE_URL):
        """Initialize or replace durable search policy and return the constructed policy."""
        policy = build_catalogue_policy(sources)
        masks = Jsonb({str(rank): dict(values) for rank, values in policy.page_masks.items()})
        with psycopg.connect(database_url) as owner:
            previous = owner.execute(
                "SELECT fingerprint FROM public.catalogue_search_policy WHERE singleton"
            ).fetchone()
            if previous is None:
                owner.execute(
                    "SELECT public.catalogue_initialize_search_policy(%s, %s)",
                    (policy.fingerprint, masks),
                )
            else:
                owner.execute(
                    "SELECT public.catalogue_replace_search_policy(%s, %s, %s)",
                    (previous[0], policy.fingerprint, masks),
                )
        return policy

    return bind


@pytest.fixture
def replace_bound_catalogue_sources(bind_catalogue_policy):
    """Explicit integration setup updates the durable binding and web snapshot."""

    def replace(monkeypatch, app, sources):
        """Bind the new catalogue policy and publish its test application snapshot."""
        bind_catalogue_policy(sources)
        return replace_test_catalogue_sources(monkeypatch, app, sources)

    return replace


@pytest.fixture
async def db_pool():
    """Open an application pool named oha-tests and close it after the test."""
    pool = create_pool(application_name="oha-tests")
    await pool.open()
    try:
        yield pool
    finally:
        await pool.close()


@pytest.fixture
def approve_source_rebinding(sync_conn):
    """Approve the exact transition as the owner before testing later recovery work."""

    def approve(source):
        """Approve the test identity against its expected issuer, subject and review revision."""
        previous = sync_conn.execute(
            "SELECT COALESCE(source_fetch_fingerprint, source_fingerprint) "
            "FROM sync_status WHERE source = %s",
            (source.name,),
        ).fetchone()[0]
        sync_conn.execute(
            "INSERT INTO source_binding_acknowledgements "
            "(source, previous_fingerprint, source_fingerprint) VALUES (%s, %s, %s) "
            "ON CONFLICT (source) DO UPDATE SET "
            "previous_fingerprint = EXCLUDED.previous_fingerprint, "
            "source_fingerprint = EXCLUDED.source_fingerprint",
            (source.name, previous, source.adapter.config_fingerprint()),
        )
        sync_conn.commit()

    return approve


@pytest.fixture(params=("archive_alpha", "archive_beta"))
async def sync_source(request, db_pool, sync_conn):
    """Provide a bound source under either explicit test identity."""
    source = legacy_source(name=request.param)

    await ensure_source_status_rows(db_pool, (source.name,))
    sync_conn.execute(
        """UPDATE sync_status
           SET last_harvest_date = %s,
               source_fingerprint = %s
           WHERE source = %s""",
        (
            datetime(2026, 1, 1, tzinfo=UTC),
            source.adapter.config_fingerprint(),
            source.name,
        ),
    )
    sync_conn.commit()
    return source


# Factories (synchronous — independent of the async loop under test)


class UserHandle:
    """Inserted user identity and plaintext test password."""

    def __init__(self, id: int, email: str, password: str):
        """Store the inserted user ID, email and plaintext test password."""
        self.id = id
        self.email = email
        self.password = password


def install_active_recovery_codes(
    conn: psycopg.Connection,
    user_id: int,
    *,
    generation: int = 1,
    count: int = 2,
) -> None:
    """Commit an active recovery-code generation containing count unused hashed codes.

    Codes are random and not returned; this helper grants availability for guard
    checks, not a redeemable plaintext fixture. Existing rows are not replaced.
    """
    conn.execute(
        "UPDATE users SET totp_recovery_code_generation = %s WHERE id = %s",
        (generation, user_id),
    )
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO totp_recovery_codes (user_id, generation, position, code_hash)
            VALUES (%s, %s, %s, %s)
            """,
            [
                (user_id, generation, position, hash_token(secrets.token_hex(16)))
                for position in range(1, count + 1)
            ],
        )
    conn.commit()


@pytest.fixture
def user_factory():
    """Return a factory that inserts and commits users, returning UserHandle.

    Keyword overrides are database columns, except password (plaintext to hash) and
    admin_recovery_ready (True by default). Defaults are a unique email, active and
    verified local public-tier account, DEFAULT_PASSWORD and no TOTP. Local admins
    get a factor and unused recovery codes unless admin_recovery_ready=False.
    Nonlocal accounts default to no password hash. Shibboleth fixtures force
    unverified email and normalize pending/approved/disabled authority fields.
    """
    counter = [0]

    def make(**overrides):
        """Insert and commit an overridden user; return its ID, email and plaintext password
        handle.
        """
        counter[0] += 1
        email = overrides.pop("email", f"user{counter[0]}@example.org")
        password = overrides.pop("password", None)
        admin_recovery_ready = overrides.pop("admin_recovery_ready", True)
        if password is not None:
            password_hash = _PH.hash(password)
        else:
            password = DEFAULT_PASSWORD
            password_hash = _DEFAULT_PW_HASH

        cols = {
            "email": email,
            "display_name": "Test User",
            "password_hash": password_hash,
            "auth_method": "local",
            "access_tier": "public",
            "is_admin": False,
            "is_active": True,
            "email_verified": True,
        }
        cols.update(overrides)
        if cols["auth_method"] != "local" and "password_hash" not in overrides:
            cols["password_hash"] = None
        provision_admin_recovery = (
            admin_recovery_ready and cols["is_admin"] and cols["auth_method"] == "local"
        )
        if provision_admin_recovery and cols.get("totp_secret") is None:
            cols["totp_secret"] = encrypt_value(pyotp.random_base32())
        if cols["auth_method"] == "shibboleth":
            cols["email_verified"] = False
            if "shibboleth_issuer" not in overrides:
                cols["shibboleth_issuer"] = "https://idp.test.example/idp/shibboleth"
            if "shibboleth_subject_id" not in overrides:
                cols["shibboleth_subject_id"] = f"urn:test:subject:{counter[0]}"

            if "federated_status" not in overrides:
                cols["federated_status"] = "approved" if cols["is_active"] else "pending"

            federated_status = cols["federated_status"]
            if federated_status == "pending":
                cols["access_tier"] = "public"
                cols["is_active"] = False
                cols["is_admin"] = False
            elif federated_status in {"approved", "disabled"}:
                cols["is_active"] = federated_status == "approved"
                if "federated_approved_at" not in overrides:
                    cols["federated_approved_at"] = datetime(2026, 1, 1, tzinfo=UTC)
                if "federated_approved_by" not in overrides:
                    cols["federated_approved_by"] = 9001

        names = ", ".join(cols)
        placeholders = ", ".join(["%s"] * len(cols))
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            row = conn.execute(
                f"INSERT INTO users ({names}) VALUES ({placeholders}) RETURNING id",
                list(cols.values()),
            ).fetchone()
            conn.commit()
            if provision_admin_recovery:
                install_active_recovery_codes(conn, row[0])
        return UserHandle(row[0], email, password)

    return make


@pytest.fixture
def session_factory():
    """Return a factory that commits hashed sessions and returns their raw IDs.

    The inner factory accepts user ID, purpose, lifetime in seconds and an optional
    (message, category) flash pair; negative lifetimes create expired sessions.
    """

    def make(user_id, purpose="full", expires_in_seconds=28800, flash=None):
        """Insert and commit a hashed session; return its raw ID; flash is a message/category pair."""
        raw = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        flash_message, flash_category = flash if flash else (None, None)
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO sessions
                       (id, user_id, purpose, expires_at, ip_address,
                        flash_message, flash_category)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    hash_session_id(raw),
                    user_id,
                    purpose,
                    expires_at,
                    "127.0.0.1",
                    flash_message,
                    flash_category,
                ),
            )
            conn.commit()
        return raw

    return make


@pytest.fixture
def dataset_factory():
    """Return a factory that commits dataset column overrides and returns the row ID.

    Defaults provide a unique test UUID/title and public metadata. resource_proxies
    is adapted to JSONB; derived URL columns are not populated by this helper.
    """

    counter = [0]

    def make(**overrides):
        """Insert and commit overridden dataset columns; adapt resource proxies to JSONB and return
        the ID.
        """
        counter[0] += 1
        cols = {
            "uuid": overrides.pop("uuid", f"oai:test:uuid-{counter[0]:04d}"),
            "title": overrides.pop("title", f"Dataset {counter[0]}"),
            "source": TEST_SOURCE_NAME,
            "access_level": "public",
            "visibility_tier": "public",
            "description": "Full description text.",
            "authors": [],
            "keywords": [],
            "languages": [],
            "institutions": [],
            "main_disciplines": [],
        }
        cols.update(overrides)
        if "resource_proxies" in cols:
            cols["resource_proxies"] = Jsonb(cols["resource_proxies"])
        names = ", ".join(cols)
        placeholders = ", ".join(["%s"] * len(cols))
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            row = conn.execute(
                f"INSERT INTO oral_history_datasets ({names}) VALUES ({placeholders}) RETURNING id",
                list(cols.values()),
            ).fetchone()
            conn.commit()
        return row[0]

    return make


# End-to-end client (real pool, real CatalogueStatsCache, real middleware)


@contextmanager
def _live_client(peer_address=None, *, unix_peer=False):
    """TestClient over the real app, optionally from a chosen peer address.

    Only the lifespan's external side effects are stubbed (migrations — the
    session fixture already ran them — logging reconfig, SMTP probe, security
    validation, seeding). The facet cache being real is deliberate: the page
    tests pin that routes `await get_cached_facets(...)` correctly.

    ``peer_address`` is the connecting address the ASGI scope reports, which
    is where the application takes client attribution from. The default,
    "testclient", is not a parseable IP address, so every client built without
    one shares a single limiter bucket.
    """
    with (
        patch(
            "app.main.validate_security_settings",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["validate_security_settings"]),
        ),
        patch(
            "app.main.validate_runtime_schema",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["validate_runtime_schema"]),
        ),
        patch(
            "app.main.reconcile_federated_session_policy",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["reconcile_federated_session_policy"]),
        ),
        patch(
            "app.main.setup_logging", new=create_autospec(_REAL_LIFESPAN_TARGETS["setup_logging"])
        ),
        TestClient(
            app,
            base_url="http://localhost",
            raise_server_exceptions=False,
            client=(
                None
                if unix_peer
                else (peer_address, 50000)
                if peer_address is not None
                else ("testclient", 50000)
            ),
        ) as client,
    ):
        yield client


@pytest.fixture
def e2e_client():
    """TestClient over the real app: real pool, REAL CatalogueStatsCache, real
    session/CSRF/TOTP middleware, real routes → services → SQL."""
    with _live_client() as client:
        yield client


@pytest.fixture
def e2e_client_from_address():
    """Factory for end-to-end clients connecting from chosen peer addresses.

    Every client it builds is closed when the test ends, however many were
    created.
    """
    with ExitStack() as stack:

        def _build(peer_address):
            """Enter a live client and register teardown with the fixture stack."""
            return stack.enter_context(_live_client(peer_address))

        yield _build


def do_login(client, email, password, totp_code=""):
    """Drive the real login form: GET /login (mints CSRF), then POST.

    Returns the POST response (303 on success). The client's cookie jar
    carries the session cookie afterwards.
    """
    client.get("/login")
    csrf = client.cookies.get("csrf_token")
    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
            "totp_code": totp_code,
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )


def login_with_totp(client, user_factory, **user_overrides):
    """Create a user with a working TOTP secret and log them in for real.

    Returns the UserHandle. The client's cookie jar carries the full-purpose
    session cookie afterwards (login asserted 303). Pass access_tier=... to
    mint an actor at a specific tier (e.g. the otherwise-untested middle
    'registered' tier)."""
    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret), **user_overrides)
    resp = do_login(client, user.email, user.password, pyotp.TOTP(secret).now())
    assert resp.status_code == 303, resp.text
    return user


def login_admin(client, user_factory):
    """Create a TOTP-enabled administrator and log them in for a FULL session.

    Returns (admin_handle, csrf_token) where csrf_token is the session-bound
    token minted by the subsequent GET /admin, the valid token for every admin
    POST in the test. Shared by the administrator-flow and login-flow modules.
    """
    secret = pyotp.random_base32()
    admin = user_factory(is_admin=True, totp_secret=encrypt_value(secret))
    resp = do_login(client, admin.email, DEFAULT_PASSWORD, pyotp.TOTP(secret).now())
    assert resp.status_code == status.HTTP_303_SEE_OTHER, resp.text

    page = client.get("/admin")
    assert page.status_code == status.HTTP_200_OK, page.text
    return admin, client.cookies.get("csrf_token")


@pytest.fixture
def e2e_unix_client():
    """Real application client with a synthetic ASGI Unix-peer shape.

    ``client=None`` exercises the callback's required no-TCP-peer boundary.
    It does not prove an installed Unix socket's ownership, ACLs, nginx or SP.
    The same ordinary lifespan stubs as e2e_client remain in force.
    """
    with _live_client(unix_peer=True) as client:
        yield client
