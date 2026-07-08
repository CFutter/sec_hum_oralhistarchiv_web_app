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
"""
import os
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from argon2 import PasswordHasher

# The documented contract: env var with a docker-compose-matching default.
TEST_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://test:test@localhost:5432/oralhistarchiv_test",
)

# TRUNCATE guard: clean_db wipes whatever DATABASE_URL points at, so refuse
# to run destructive fixtures against anything that doesn't look like a test
# database. ALLOW_DESTRUCTIVE_DB=1 is the explicit, auditable override.
_DB_NAME = TEST_DATABASE_URL.rsplit("/", 1)[-1].split("?")[0]
_DESTRUCTIVE_OK = (
    _DB_NAME.endswith("_test")
    or os.environ.get("ALLOW_DESTRUCTIVE_DB") == "1"
)


def _assert_test_database() -> None:
    assert _DESTRUCTIVE_OK, (
        f"refusing to TRUNCATE non-test database {_DB_NAME!r} "
        f"(URL from DATABASE_URL); name a '*_test' database or set "
        f"ALLOW_DESTRUCTIVE_DB=1 to override"
    )

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
                f"REQUIRE_DB=1 but integration database unreachable at "
                f"{TEST_DATABASE_URL}"
            )
        pytest.skip(f"integration database not reachable at {TEST_DATABASE_URL}")

    _assert_test_database()

    from alembic import command
    from alembic.config import Config
    from app.paths import ALEMBIC_INI, ALEMBIC_DIR

    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def clean_db(_ensure_schema):
    """Give every integration test clean tables and the sync_status singleton."""
    _assert_test_database()
    with psycopg.connect(TEST_DATABASE_URL) as conn:
        conn.execute(
            "TRUNCATE users, sessions, oral_history_datasets RESTART IDENTITY CASCADE"
        )
        conn.execute("DELETE FROM sync_status")
        conn.execute(
            "INSERT INTO sync_status (id, last_harvest_date) VALUES (1, %s)",
            (datetime(2026, 1, 1, tzinfo=timezone.utc),),
        )
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
    from app.services.db import create_pool

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


@pytest.fixture
def user_factory():
    """Insert a user row; returns UserHandle(id, email, password).

    Defaults: local auth, verified, active, public tier, no TOTP, password
    DEFAULT_PASSWORD. Override any column via kwargs (e.g. is_admin=True,
    email_verified=False, totp_secret=<encrypted>, auth_method='shibboleth').
    Shibboleth users get password_hash=None automatically unless overridden.
    """
    counter = [0]

    def make(**overrides):
        counter[0] += 1
        email = overrides.pop("email", f"user{counter[0]}@uzh.ch")
        password = overrides.pop("password", None)
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

        names = ", ".join(cols)
        placeholders = ", ".join(["%s"] * len(cols))
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            row = conn.execute(
                f"INSERT INTO users ({names}) VALUES ({placeholders}) RETURNING id",
                list(cols.values()),
            ).fetchone()
            conn.commit()
        return UserHandle(row[0], email, password)

    return make


@pytest.fixture
def session_factory():
    """Insert a session row via the app's own hashing; returns the RAW id.

    Uses _hash_session_id from the app so the stored value matches what
    get_session_user computes from the cookie.
    """
    from app.services.sessions import _hash_session_id
    import secrets

    def make(user_id, purpose="full", expires_in_seconds=28800, flash=None):
        raw = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        flash_message, flash_category = flash if flash else (None, None)
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            conn.execute(
                """INSERT INTO sessions
                       (id, user_id, purpose, expires_at, ip_address,
                        flash_message, flash_category)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (_hash_session_id(raw), user_id, purpose, expires_at,
                 "127.0.0.1", flash_message, flash_category),
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
    dataset a download_url, [{"type": "LandingPage", "ref": ...}] for a
    landing page — and is adapted to JSONB here."""
    from psycopg.types.json import Jsonb

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
                f"INSERT INTO oral_history_datasets ({names}) "
                f"VALUES ({placeholders}) RETURNING id",
                list(cols.values()),
            ).fetchone()
            conn.commit()
        return row[0]

    return make


# ---------------------------------------------------------------------------
# End-to-end client (real pool, real FacetCache, real middleware)
# ---------------------------------------------------------------------------

@pytest.fixture
def e2e_client():
    """TestClient over the real app: real pool, REAL FacetCache, real
    session/CSRF/TOTP middleware, real routes → services → SQL.

    Only the lifespan's external side effects are stubbed (migrations — the
    session fixture already ran them — logging reconfig, SMTP probe, security
    validation, seeding). The facet cache being real is deliberate: §4.3 pins
    that routes `await get_cached_facets(...)` correctly.
    """
    from unittest.mock import patch
    from fastapi.testclient import TestClient

    with patch("app.main.Config"), \
         patch("app.main.command"), \
         patch("app.main.validate_security_settings"), \
         patch("app.main.verify_smtp_tls"), \
         patch("app.main.setup_logging"), \
         patch("app.main.seed_admin_user"):
        from app.main import app
        with TestClient(
            app, base_url="http://localhost", raise_server_exceptions=False
        ) as client:
            yield client


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
    import pyotp

    from app.services.crypto import encrypt_value

    secret = pyotp.random_base32()
    user = user_factory(totp_secret=encrypt_value(secret), **user_overrides)
    resp = do_login(client, user.email, user.password, pyotp.TOTP(secret).now())
    assert resp.status_code == 303, resp.text
    return user
