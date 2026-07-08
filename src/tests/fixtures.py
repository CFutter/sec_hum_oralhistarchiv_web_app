"""Shared test helpers — sample data, mock plumbing, and the client builder.

THE HARNESS FIX (backlog §0)
----------------------------
The old `_build_client` entered a patch that returned the pre-migration
2-tuple for `get_session_user` and left the corrected 3-tuple patch as a dead,
never-entered `patch(...)` expression. Every authenticated request then died
unpacking `user, purpose, flash_present = await get_session_user(...)` and,
with raise_server_exceptions=False, surfaced as a blanket 500 — so auth tests
were green-for-the-wrong-reason.

Here there is exactly ONE entered patch, and it returns a real
`SessionLookup` (the NamedTuple `get_session_user` now returns). Constructing
the NamedTuple is the structural guard: when the next field is added to
SessionLookup, this file fails at construction time instead of silently
returning a stale shape.

CSRF note: tokens are HMAC(session_secret-derived key, identifier), where the
identifier is the session id (authenticated) or the pre-session id (guest).
csrf_token_for() computes the *real* token so POSTs pass verification exactly
as production would.
"""
import datetime
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from fastapi.testclient import TestClient

from config import settings
from app.services.sessions import SessionLookup
from app.services.users import User
from app.middleware.cookies import SESSION_SIGNER, PRE_SESSION_COOKIE_NAME
from app.middleware.csrf import _compute_csrf_token, CSRF_COOKIE_NAME

# The REAL originals every patch specs against, captured once at import.
# create_autospec(original) instead of autospec=True: autospec=True specs
# whatever is installed at patch time, so building a second client while the
# first is alive would try to spec the first client's mock (InvalidSpecError).
# Speccing the captured original keeps signature enforcement AND clean nesting.
import app.main as _app_main  # noqa: E402  (env is set by conftest first)
from app.services.sessions import (  # noqa: E402
    get_session_user as _REAL_GET_SESSION_USER,
    consume_flash as _REAL_CONSUME_FLASH,
)

_REAL_LIFESPAN_TARGETS = {
    name: getattr(_app_main, name)
    for name in (
        "create_pool",
        "FacetCache",
        "Config",
        "command",
        "validate_security_settings",
        "verify_smtp_tls",
        "setup_logging",
        "seed_admin_user",
        "validate_schema_against_db",
    )
}

# Stable identifiers reused across tests.
RAW_SESSION_ID = "test-session-id"
GUEST_PRE_SESSION_ID = "test-pre-session-id"

MOCK_FACETS = {
    "keywords": ["data", "research", "test"],
    "languages": ["English", "German"],
    "access_levels": ["public", "restricted"],
}


# ---------------------------------------------------------------------------
# Cookie / CSRF helpers
# ---------------------------------------------------------------------------

def csrf_token_for(identifier: str) -> str:
    """The valid CSRF token bound to a session/pre-session identifier."""
    return _compute_csrf_token(identifier)


def sign_session_id(session_id: str) -> str:
    """Sign a raw session id exactly as the app does for the cookie value."""
    return SESSION_SIGNER.dumps(session_id)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

def make_sample_user(**overrides) -> User:
    """A User dataclass with sensible defaults (verified, active, TOTP on)."""
    defaults = dict(
        id=1,
        email="alice@uzh.ch",
        display_name="Alice Müller",
        affiliation="University of Zurich",
        country="Switzerland",
        auth_method="local",
        access_tier="registered",
        is_active=True,
        created_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        last_login=datetime.datetime(2026, 3, 20, tzinfo=datetime.timezone.utc),
        totp_configured=True,
        is_admin=False,
        email_verified=True,
        last_totp_step=None,
    )
    defaults.update(overrides)
    return User(**defaults)


def make_sample_user_row(**overrides) -> dict:
    """A user DB row dict as returned by psycopg dict_row."""
    row = {
        "id": 1,
        "email": "alice@uzh.ch",
        "display_name": "Alice Müller",
        "affiliation": "University of Zurich",
        "country": "Switzerland",
        "auth_method": "local",
        "access_tier": "registered",
        "is_active": True,
        "created_at": datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        "last_login": datetime.datetime(2026, 3, 20, tzinfo=datetime.timezone.utc),
        "totp_configured": True,
        "is_admin": False,
        "email_verified": True,
        "last_totp_step": None,
    }
    row.update(overrides)
    return row


# ---------------------------------------------------------------------------
# Async mock plumbing
# ---------------------------------------------------------------------------

def make_async_cursor(fetchone=None, fetchall=None, rowcount=0):
    """A mock async cursor: awaitable execute/fetchone/fetchall, sync rowcount.

    `fetchone` may be a single value or a list of values consumed in order
    (side_effect), matching code that calls fetchone repeatedly.
    """
    cur = MagicMock(name="mock_cursor")
    cur.execute = AsyncMock()
    if isinstance(fetchone, list):
        cur.fetchone = AsyncMock(side_effect=fetchone)
    else:
        cur.fetchone = AsyncMock(return_value=fetchone)
    cur.fetchall = AsyncMock(return_value=fetchall or [])
    cur.rowcount = rowcount
    return cur


class FakeCursorCtx:
    """Async context manager yielding a mock cursor — stands in for
    get_db_cursor(pool). Use: patch("...get_db_cursor", return_value=FakeCursorCtx(cur))."""

    def __init__(self, cursor):
        self.cursor = cursor

    async def __aenter__(self):
        return self.cursor

    async def __aexit__(self, *exc):
        return False


def make_mock_pool() -> MagicMock:
    """A pool mock that survives the lifespan (`await pool.open()/close()`).

    Any actual query through it fails loudly — unit-tier tests must patch the
    service layer, never talk to this pool. `pool.connection()` (the only way
    real code reaches the DB, via get_db_cursor) raises AssertionError so a
    route that slips past the service-layer patches cannot silently succeed.
    """
    pool = MagicMock(name="mock_db_pool")
    pool.open = AsyncMock()
    pool.close = AsyncMock()
    pool.connection = MagicMock(
        side_effect=AssertionError(
            "unit-tier test reached the mock DB pool — patch the service "
            "layer (app.routes.*/app.services.*) instead of querying"
        )
    )
    return pool


def make_mock_facet_cache() -> MagicMock:
    """FacetCache stand-in whose async get_cached_facets returns fixed facets."""
    cache = MagicMock(name="mock_facet_cache")
    cache.get_cached_facets = AsyncMock(return_value=MOCK_FACETS)
    cache.stop = MagicMock()
    return cache


# ---------------------------------------------------------------------------
# TestClient builder — the fixed harness
# ---------------------------------------------------------------------------

def _lifespan_patches(mock_pool, mock_facet_cache):
    """Neutralise the lifespan's external side effects (no DB, no migrations,
    no logging reconfiguration, no SMTP probe, no seeding). The pure
    schema-sync validators still run for real.

    Every stand-in is create_autospec(REAL original): a call-site
    arity/keyword drift in the lifespan (e.g. create_pool gaining a required
    arg) fails here instead of being swallowed by an accept-anything
    MagicMock."""
    real = _REAL_LIFESPAN_TARGETS

    def specced(name, **config):
        return patch(f"app.main.{name}", new=create_autospec(real[name], **config))

    return [
        specced("create_pool", return_value=mock_pool),
        specced("FacetCache", return_value=mock_facet_cache),
        specced("Config"),
        specced("command"),
        specced("validate_security_settings"),
        specced("verify_smtp_tls"),
        specced("setup_logging"),
        specced("seed_admin_user"),
        specced("validate_schema_against_db"),
    ]


def build_client(
    session_user=None,
    session_purpose="full",
    flash=None,
) -> TestClient:
    """Construct a TestClient with the given authentication state.

    One raw session id (RAW_SESSION_ID) is signed with the real signer;
    get_session_user is patched — ONE entered patch — to resolve it to a real
    SessionLookup 3-tuple. CSRF cookies carry the real HMAC token bound to the
    active identifier so POSTs pass verification.

    Args:
        session_user: User attached to the session, or None for a guest.
        session_purpose: "full" or "totp_setup" (ignored for guests).
        flash: optional (message, category) pending on the session — delivered
            through the real middleware path (flash_present → consume_flash).
    """
    mock_pool = make_mock_pool()
    mock_cache = make_mock_facet_cache()

    stack = ExitStack()
    for p in _lifespan_patches(mock_pool, mock_cache):
        stack.enter_context(p)

    # The Phase-1 fix: a single entered patch returning the real 3-shape.
    # SessionLookup construction is the loud-failure guard against the next
    # signature change (see module docstring). create_autospec(REAL fn) makes
    # the mocks signature-checked: a middleware call that drops the pool
    # argument (the documented drift class) raises here instead of passing
    # green. (Speccing the captured original, not autospec=True, so nested
    # multi-client builds don't try to spec another client's mock.)
    lookup = SessionLookup(
        user=session_user,
        purpose=session_purpose if session_user else None,
        flash_present=flash is not None,
    )
    session_spy = stack.enter_context(
        patch(
            "app.middleware.session.get_session_user",
            new=create_autospec(_REAL_GET_SESSION_USER, return_value=lookup),
        )
    )
    consume_spy = stack.enter_context(
        patch(
            "app.middleware.session.consume_flash",
            new=create_autospec(_REAL_CONSUME_FLASH, return_value=flash),
        )
    )

    from app.main import app

    # base_url host must be in settings.allowed_hosts or TrustedHostMiddleware
    # rejects every request with 400 "Invalid host header".
    client = TestClient(app, base_url="http://localhost", raise_server_exceptions=False)
    client.__enter__()

    if session_user is not None:
        identifier = RAW_SESSION_ID
        client.cookies.set(settings.session_cookie_name, sign_session_id(RAW_SESSION_ID))
    else:
        identifier = GUEST_PRE_SESSION_ID
        client.cookies.set(PRE_SESSION_COOKIE_NAME, GUEST_PRE_SESSION_ID)
    client.cookies.set(CSRF_COOKIE_NAME, csrf_token_for(identifier))

    # Conveniences for test bodies.
    client.csrf_identifier = identifier
    client.csrf_token = csrf_token_for(identifier)
    client.mock_pool = mock_pool
    client.facet_cache = mock_cache
    client.session_spy = session_spy
    client.consume_flash_spy = consume_spy
    client._patch_stack = stack
    return client


def teardown_client(client: TestClient) -> None:
    try:
        client.__exit__(None, None, None)
    finally:
        client._patch_stack.close()
