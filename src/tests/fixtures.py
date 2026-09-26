"""Shared test helpers — sample data, mock plumbing, and the client builder.

THE SESSION-LOOKUP PATCH
------------------------
`get_session_user` returns a `SessionLookup` NamedTuple and every
authenticated request unpacks it. A harness that patched it with any other
shape (a shorter tuple, or a patch expression that is never entered) would
make every authenticated request fail at the unpack and, with
raise_server_exceptions=False, surface as a blanket 500 — auth tests would
then pass for the wrong reason.

Here there is exactly ONE entered patch, and it returns a real
`SessionLookup`. Constructing the NamedTuple is the structural guard: when
the next field is added to SessionLookup, this file fails at construction
time instead of silently returning a stale shape.

CSRF note: tokens are HMAC(session_secret-derived key, identifier), where the
identifier is the session id (authenticated) or the pre-session id (guest).
csrf_token_for() computes the *real* token so POSTs pass verification exactly
as production would.
"""

import datetime
from contextlib import ExitStack
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from fastapi.testclient import TestClient

# The REAL originals every patch specs against, captured once at import.
# create_autospec(original) instead of autospec=True: autospec=True specs
# whatever is installed at patch time, so building a second client while the
# first is alive would try to spec the first client's mock (InvalidSpecError).
# Speccing the captured original keeps signature enforcement AND clean nesting.
import app.main as _app_main
from app.main import app as fastapi_app
from app.middleware.cookies import PRE_SESSION_COOKIE_NAME, SESSION_SIGNER
from app.middleware.csrf import CSRF_COOKIE_NAME, _compute_csrf_token
from app.routes.auth.account import (
    get_admin_promotion as _real_get_admin_promotion,
)
from app.runtime_preflight import (
    validate_runtime_schema as _real_validate_runtime_schema,
)
from app.services.cache import CatalogueStatsCache, GlobalStats
from app.services.federated_session_policy import (
    reconcile_federated_session_policy as _real_reconcile_federated_session_policy,
)
from app.services.seed_mock_data import seed_mock_data as _real_seed_mock_data
from app.services.sessions import (
    SessionLookup,
)
from app.services.sessions import (
    consume_flash as _real_consume_flash,
)
from app.services.sessions import (
    get_session_user as _real_get_session_user,
)
from app.services.users import User
from config import settings

_REAL_LIFESPAN_TARGETS = {
    name: getattr(_app_main, name)
    for name in (
        "Config",
        "CatalogueStatsCache",
        "command",
        "create_pool",
        "reconcile_federated_session_policy",
        "seed_admin_user",
        "setup_logging",
        "validate_runtime_schema",
        "validate_rate_limit_backend",
        "validate_security_settings",
        "warm_password_blocklist",
        "warn_unconsumed_env_keys",
    )
}
_REAL_LIFESPAN_TARGETS["validate_runtime_schema"] = _real_validate_runtime_schema
_REAL_LIFESPAN_TARGETS["reconcile_federated_session_policy"] = (
    _real_reconcile_federated_session_policy
)

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
    defaults = {
        "id": 1,
        "email": "alice@uzh.ch",
        "display_name": "Alice Müller",
        "affiliation": "University of Zurich",
        "country": "Switzerland",
        "auth_method": "local",
        "access_tier": "registered",
        "is_active": True,
        "created_at": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        "last_login": datetime.datetime(2026, 3, 20, tzinfo=datetime.UTC),
        "totp_configured": True,
        "is_admin": False,
        "email_verified": True,
        "last_totp_step": None,
        "shibboleth_issuer": None,
        "shibboleth_subject_id": None,
        "federated_status": None,
        "federated_approved_at": None,
        "federated_approved_by": None,
    }
    defaults.update(overrides)
    if defaults["is_admin"] and defaults["auth_method"] == "local":
        # require_admin (app/middleware/session.py) 403s a local administrator
        # whose active recovery-code generation is absent or empty. Default a
        # sample administrator to the healthy state so admin_client and other
        # admin doubles are admitted; pass these fields explicitly to build the
        # rejected case.
        if "totp_recovery_code_generation" not in overrides:
            defaults["totp_recovery_code_generation"] = 1
        if "totp_recovery_codes_available" not in overrides:
            defaults["totp_recovery_codes_available"] = True
        if "totp_recovery_required" not in overrides:
            defaults["totp_recovery_required"] = False
    if defaults["auth_method"] == "shibboleth":
        defaults["email_verified"] = False
        if "shibboleth_issuer" not in overrides:
            defaults["shibboleth_issuer"] = "https://idp.test.example/idp/shibboleth"
        if "shibboleth_subject_id" not in overrides:
            defaults["shibboleth_subject_id"] = f"urn:test:subject:{defaults['id']}"
        if "federated_status" not in overrides:
            defaults["federated_status"] = "approved" if defaults["is_active"] else "pending"
        if defaults["federated_status"] in {"pending", "legacy_quarantined"}:
            defaults["access_tier"] = "public"
            defaults["is_active"] = False
            defaults["is_admin"] = False
        elif defaults["federated_status"] in {"approved", "disabled"}:
            defaults["is_active"] = defaults["federated_status"] == "approved"
            if "federated_approved_at" not in overrides:
                defaults["federated_approved_at"] = datetime.datetime(
                    2026, 1, 1, tzinfo=datetime.UTC
                )
            if "federated_approved_by" not in overrides:
                defaults["federated_approved_by"] = 9001
    return User(**cast("Any", defaults))


def make_sample_user_row(**overrides) -> dict[str, Any]:
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
        "created_at": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        "last_login": datetime.datetime(2026, 3, 20, tzinfo=datetime.UTC),
        "totp_configured": True,
        "is_admin": False,
        "email_verified": True,
        "last_totp_step": None,
        "totp_recovery_code_generation": 0,
        "totp_recovery_codes_available": False,
        "totp_recovery_required": False,
        "shibboleth_issuer": None,
        "shibboleth_subject_id": None,
        "federated_status": None,
        "federated_approved_at": None,
        "federated_approved_by": None,
    }
    row.update(overrides)
    if row["auth_method"] == "shibboleth":
        row["email_verified"] = False
        if "shibboleth_issuer" not in overrides:
            row["shibboleth_issuer"] = "https://idp.test.example/idp/shibboleth"
        if "shibboleth_subject_id" not in overrides:
            row["shibboleth_subject_id"] = f"urn:test:subject:{row['id']}"
        if "federated_status" not in overrides:
            row["federated_status"] = "approved" if row["is_active"] else "pending"
        if row["federated_status"] in {"pending", "legacy_quarantined"}:
            row["access_tier"] = "public"
            row["is_active"] = False
            row["is_admin"] = False
        elif row["federated_status"] in {"approved", "disabled"}:
            row["is_active"] = row["federated_status"] == "approved"
            if "federated_approved_at" not in overrides:
                row["federated_approved_at"] = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
            if "federated_approved_by" not in overrides:
                row["federated_approved_by"] = 9001
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
    """Async context manager yielding a mock cursor — stands in for get_db_cursor(pool).
    Use: patch("...get_db_cursor", return_value=FakeCursorCtx(cur))."""

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


def make_mock_catalogue_stats_cache() -> MagicMock:
    """An autospecced CatalogueStatsCache double.

    `pages.home` awaits `get_global_stats()` (a single call returning both
    figures together); autospeccing against the real class means a route that
    fetches the two figures through separate get_total_datasets() and
    get_last_full_rebuild() calls, or that calls a method the class does not
    have, fails here instead of returning a silently-wrong MagicMock.
    """
    cache = create_autospec(CatalogueStatsCache, instance=True, spec_set=True)
    cache.get_global_stats.return_value = GlobalStats(total_datasets=0, last_full_rebuild=None)
    cache.get_total_datasets.return_value = 0
    cache.get_last_full_rebuild.return_value = None
    return cache


# ---------------------------------------------------------------------------
# TestClient builder — the fixed harness
# ---------------------------------------------------------------------------


def _lifespan_patches(mock_pool, mock_catalogue_stats_cache):
    """Neutralise lifecycle dependencies requiring external resources.

    The shared runtime preflight is mocked because the unit-client pool
    deliberately rejects database access. Its individual invariants and
    live-database behavior are covered by focused unit/integration tests.
    """
    real = _REAL_LIFESPAN_TARGETS

    def specced(name, **config):
        return patch(f"app.main.{name}", new=create_autospec(real[name], **config))

    return [
        ("create_pool", specced("create_pool", return_value=mock_pool)),
        (
            "CatalogueStatsCache",
            specced("CatalogueStatsCache", return_value=mock_catalogue_stats_cache),
        ),
        ("Config", specced("Config")),
        ("command", specced("command")),
        ("validate_security_settings", specced("validate_security_settings")),
        ("validate_rate_limit_backend", specced("validate_rate_limit_backend")),
        ("setup_logging", specced("setup_logging")),
        ("seed_admin_user", specced("seed_admin_user")),
        ("validate_runtime_schema", specced("validate_runtime_schema")),
        (
            "reconcile_federated_session_policy",
            specced("reconcile_federated_session_policy"),
        ),
        (
            "seed_mock_data",
            patch(
                "app.services.seed_mock_data.seed_mock_data",
                new=create_autospec(_real_seed_mock_data),
            ),
        ),
    ]


def build_client(
    session_user=None,
    session_purpose="full",
    flash=None,
    peer_address=None,
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
        peer_address: the connecting address the ASGI scope reports, for tests
            about per-client attribution. The default, "testclient", is not a
            parseable IP address, which is what most tests want: every client
            then shares one limiter bucket.
    """
    mock_pool = make_mock_pool()
    mock_cache = make_mock_catalogue_stats_cache()

    stack = ExitStack()
    lifespan_mocks = {}
    for name, p in _lifespan_patches(mock_pool, mock_cache):
        lifespan_mocks[name] = stack.enter_context(p)

    # One entered patch, returning the real SessionLookup shape.
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
            new=create_autospec(_real_get_session_user, return_value=lookup),
        )
    )
    consume_spy = stack.enter_context(
        patch(
            "app.middleware.session.consume_flash",
            new=create_autospec(_real_consume_flash, return_value=flash),
        )
    )

    # GET /account (routes/auth/account.py) awaits get_admin_promotion(pool,
    # user_id=..., session_id=...) for every local-auth full session; the
    # unit-tier pool raises by design (make_mock_pool), so every /account
    # test needs this patched. Autospecced against the real callable and
    # defaulting to "no promotion pending" (None) so /account renders 200;
    # a test asserting promotion-banner content overrides the return value.
    admin_promotion_spy = stack.enter_context(
        patch(
            "app.routes.auth.account.get_admin_promotion",
            new=create_autospec(_real_get_admin_promotion, return_value=None),
        )
    )

    # base_url host must be in settings.allowed_hosts or TrustedHostMiddleware
    # rejects every request with 400 "Invalid host header".
    client = TestClient(
        fastapi_app,
        base_url="http://localhost",
        raise_server_exceptions=False,
        client=(peer_address, 50000) if peer_address is not None else ("testclient", 50000),
    )
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
    client.catalogue_stats_cache = mock_cache
    client.session_spy = session_spy
    client.consume_flash_spy = consume_spy
    client.admin_promotion_spy = admin_promotion_spy
    client.lifespan_mocks = lifespan_mocks
    client._patch_stack = stack
    return client


def teardown_client(client: TestClient) -> None:
    try:
        client.__exit__(None, None, None)
    finally:
        client._patch_stack.close()
