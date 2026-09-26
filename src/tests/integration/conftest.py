"""Integration-tier fixtures — real PostgreSQL, schema from the app's own migrations.

DATABASE SELECTION (launcher-agnostic): the URL comes from the DATABASE_URL
environment variable with a local default matching docker-compose.yml, so the
SAME suite runs against `docker compose up -d db` and the CI service container
with no code difference. The root conftest also feeds DATABASE_URL to
Settings, so the app under test connects to the same database.

CLEAN STATE: TRUNCATE-between-tests, not transaction-rollback-per-test. The
code under test manages its own transactions (per-record commits in the sync
loop, SAVEPOINTs in the full rebuild, FOR UPDATE in consume_flash) — a
wrapping rollback strategy would fight it.

SCHEMA: ensured once per session by running the app's own Alembic migrations
(idempotent no-op when CI already ran `alembic upgrade head`). If the database
is unreachable, every test here SKIPS — the unit tier must never depend on it.

PARALLEL WORKERS: under pytest-xdist the root conftest has already suffixed
the database name with the worker id (oralhistarchiv_test_gw0, ...). This
file creates that database on the same instance when it is missing, so every
worker migrates and truncates a database of its own.
"""

import os
import re
import secrets
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
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
from app.services.crypto import encrypt_value
from app.services.db import create_pool
from app.services.session_ids import hash_session_id
from app.services.sync import _source_a_fingerprint
from app.services.tokens import hash_token

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
        "seed_admin_user",
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
    assert _DESTRUCTIVE_OK, (
        f"refusing to TRUNCATE non-test database {_DB_NAME!r} "
        f"(URL from DATABASE_URL); name a '*_test' database or set "
        f"ALLOW_DESTRUCTIVE_DB=1 to override"
    )


# Serialises CREATE DATABASE across xdist workers (an arbitrary constant key
# on the instance's maintenance database).
_WORKER_DATABASE_CREATION_LOCK = 8_212_026


def _ensure_worker_database() -> None:
    """Create this xdist worker's private database when it does not exist yet.

    Runs only in a worker process (PYTEST_XDIST_WORKER set), where the root
    conftest has already put the worker-suffixed name into DATABASE_URL. The
    maintenance connection goes to the instance's ``postgres`` database with
    the same credentials; creation is serialised with an advisory lock so two
    workers never run CREATE DATABASE against the same template at once. Any
    failure is left to ``_db_reachable`` below, which then reports the tier
    as unavailable with the usual skip or REQUIRE_DB error.
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
    """Skip the whole tier without a DB; otherwise migrate to head once.

    Uses the app's OWN migrations (never a hand-maintained schema copy), so
    the test schema cannot drift from production. Idempotent when CI has
    already migrated.

    REQUIRE_DB=1 (set on the CI integration job) turns the silent skip into a
    hard error: pytest exits 0 on an all-skipped tier, so without this a dead
    service container would ship a green run that executed none of the
    auth/session/access-control assurance.
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
    """Give every integration test clean tables and a bound sync_status singleton.

    ``source_fingerprint`` is seeded with the value production computes for
    the current settings (``_source_a_fingerprint()``, sync.py:206-211) so
    the catalogue starts bound to its configured source, matching every
    catalogue that has completed a full rebuild. ``_sync_source_a``
    (sync.py:557-578) raises ``_FullReharvestRequired`` when this column is
    NULL — tests proving that unbound gate use the ``unbound_catalogue``
    fixture to null it back out.

    ``ingestion_failures`` is truncated explicitly: it has only a primary
    key (source, uuid in db_schema_contract.py's
    INGESTION_FAILURE_CONSTRAINT_CONTRACT), no foreign key to ``users`` or
    ``oral_history_datasets``, so it is not reached by this TRUNCATE's
    CASCADE and rows from one test would otherwise survive into the next.
    ``totp_recovery_codes``, ``admin_promotion_requests`` and
    ``pending_totp_rotations`` all carry a foreign key to ``users.id`` (see
    the same contract file), so truncating ``users`` with CASCADE already
    clears them and they need no explicit listing here.
    """
    _assert_test_database()
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute(
            """
            TRUNCATE
                federation_policy_state,
                email_outbox,
                sessions,
                users,
                oral_history_datasets,
                ingestion_failures
            RESTART IDENTITY CASCADE
            """
        )
        conn.execute("DELETE FROM sync_status")
        conn.execute(
            "INSERT INTO sync_status (id, last_harvest_date, source_fingerprint) "
            "VALUES (1, %s, %s)",
            (datetime(2026, 1, 1, tzinfo=UTC), _source_a_fingerprint()),
        )
        conn.commit()
    yield


@pytest.fixture
def unbound_catalogue():
    """Null out sync_status.source_fingerprint for the unbound-gate positive control.

    Use in a test that must prove a fresh/unbound catalogue rejects an
    incremental sync (``_FullReharvestRequired`` with "no source
    configuration binding", sync.py:568-572) instead of the
    ``clean_db``-seeded bound state every other test relies on.
    """
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute("UPDATE sync_status SET source_fingerprint = NULL WHERE id = 1")
        conn.commit()
    yield


@pytest.fixture
def sync_conn():
    """A plain synchronous psycopg connection for test-side setup/asserts."""
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        yield conn


@pytest.fixture
async def db_pool():
    """The application's own AsyncConnectionPool against the test database.

    Built via create_pool() so connection config (autocommit, statement
    timeout, application_name) matches production exactly.
    """
    pool = create_pool(application_name="oha-tests")
    await pool.open()
    try:
        yield pool
    finally:
        await pool.close()


# ---------------------------------------------------------------------------
# Factories (synchronous — independent of the async loop under test)
# ---------------------------------------------------------------------------


class UserHandle:
    def __init__(self, id: int, email: str, password: str):
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
    """Give a user an active TOTP recovery-code generation with unused codes.

    Mirrors the row shape ``guard_current_admin_session_cur`` and
    ``require_admin`` require of a local administrator (users.py:150-193): a
    positive ``totp_recovery_code_generation`` plus at least one unused,
    under-budget ``totp_recovery_codes`` row for that generation. The codes
    themselves are opaque here (only their hashes are stored) since this
    helper only needs to satisfy the recovery-availability check, not to
    redeem a code.

    ``psycopg.Connection`` has no ``executemany`` (only ``Cursor`` does), so
    the batch insert runs through an explicit cursor.
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
    """Insert a user row; returns UserHandle(id, email, password).

    Defaults: local auth, verified, active, public tier, no TOTP, password
    DEFAULT_PASSWORD. Override any column via kwargs (e.g. is_admin=True,
    email_verified=False, totp_secret=<encrypted>, auth_method='shibboleth').
    Shibboleth users get password_hash=None automatically unless overridden.

    A local administrator (``is_admin=True``, default ``auth_method``) is
    also given a healthy recovery state by default — an encrypted TOTP
    secret (unless one was passed in) plus an active recovery-code
    generation with unused codes — because
    ``guard_current_admin_session_cur`` (users.py:141-193) and
    ``require_admin`` (middleware/session.py:278-296) reject every local
    administrator write and route without one. Pass
    ``admin_recovery_ready=False`` for the explicit "incomplete recovery
    configuration" double that those rejection tests need.
    """
    counter = [0]

    def make(**overrides):
        counter[0] += 1
        email = overrides.pop("email", f"user{counter[0]}@uzh.ch")
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
            if federated_status in {"pending", "legacy_quarantined"}:
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
    """Insert a session row via the app's own hashing; returns the RAW id.

    Uses hash_session_id from the app so the stored value matches what
    get_session_user computes from the cookie.
    """

    def make(user_id, purpose="full", expires_in_seconds=28800, flash=None):
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
    """Insert a dataset row; returns its id. Array columns default to non-NULL
    empties, mirroring what the real upsert writes.

    resource_proxies (JSONB) takes a plain list of {"type", "ref"} dicts —
    e.g. [{"type": "Resource", "ref": "https://example.org/dl"}] to give the
    dataset a resource_access_url, [{"type": "LandingPage", "ref": ...}] for a
    landing page — and is adapted to JSONB here."""

    counter = [0]

    def make(**overrides):
        counter[0] += 1
        cols = {
            "uuid": overrides.pop("uuid", f"oai:test:uuid-{counter[0]:04d}"),
            "title": overrides.pop("title", f"Dataset {counter[0]}"),
            "source": "swissubase",
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


# ---------------------------------------------------------------------------
# End-to-end client (real pool, real CatalogueStatsCache, real middleware)
# ---------------------------------------------------------------------------


@contextmanager
def _live_client(peer_address=None):
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
        patch(
            "app.main.seed_admin_user",
            new=create_autospec(_REAL_LIFESPAN_TARGETS["seed_admin_user"]),
        ),
        TestClient(
            app,
            base_url="http://localhost",
            raise_server_exceptions=False,
            client=(peer_address, 50000) if peer_address is not None else ("testclient", 50000),
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
