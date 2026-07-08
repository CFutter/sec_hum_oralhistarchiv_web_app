"""Pure-unit tests for the User model layer (src/app/services/users.py).

Covers backlog §2.17 (pure part: the shared normalize_display_name validator
both registration and rename call — route-level symmetry is pinned in
test_register_routes.py) plus the model plumbing that everything else builds
on: parse_user row mapping, the USER_COLUMNS/User schema-sync validator, the
SELECT builder user_columns_sql, and the UserAlreadyExistsError contract.

No database, no TestClient — everything here is import-and-call.
"""

import datetime
from dataclasses import fields as dataclass_fields

import pytest

from app.services import users
from app.services.users import (
    DISPLAY_NAME_MAX_LENGTH,
    User,
    UserAlreadyExistsError,
    normalize_display_name,
    parse_user,
    user_columns_sql,
    validate_user_schema,
)
from tests.fixtures import make_sample_user_row


# ---------------------------------------------------------------------------
# normalize_display_name (§2.17 — shared validator for registration + rename)
# ---------------------------------------------------------------------------

def test_normalize_display_name_strips_whitespace_and_returns_stripped_value():
    """§2.17: the validator strips leading/trailing whitespace and RETURNS the
    stripped value — regression guard against the validator validating but
    passing the raw (padded) input through to the DB."""
    assert normalize_display_name("  Alice  ") == "Alice"


def test_normalize_display_name_rejects_c0_control_char():
    """§2.17: C0 control characters (here BEL \\x07) are banned. Regression:
    a bad name at registration used to escape validation and 500."""
    with pytest.raises(ValueError, match="control characters"):
        normalize_display_name("Alice\x07")


def test_normalize_display_name_rejects_del_char():
    """§2.17: DEL (\\x7f) is banned too — the ban is 'ord < 0x20 or == 0x7f',
    not just ord < 0x20. DEL is not whitespace, so strip() cannot save it."""
    with pytest.raises(ValueError, match="control characters"):
        normalize_display_name("\x7f")


@pytest.mark.parametrize("raw", ["", "   "], ids=["empty", "whitespace-only"])
def test_normalize_display_name_rejects_empty_and_whitespace_only(raw):
    """§2.17: empty input and whitespace-only input (empty AFTER strip) are
    both rejected with the empty-name error."""
    with pytest.raises(ValueError, match="cannot be empty"):
        normalize_display_name(raw)


def test_normalize_display_name_rejects_over_max_length():
    """§2.17: 201 characters exceeds DISPLAY_NAME_MAX_LENGTH=200 and raises."""
    assert DISPLAY_NAME_MAX_LENGTH == 200
    with pytest.raises(ValueError, match="at most 200 characters"):
        normalize_display_name("a" * 201)


def test_normalize_display_name_accepts_exactly_max_length():
    """§2.17: the boundary is inclusive — exactly 200 chars passes. Padding
    is stripped BEFORE the length check, so a padded 200-char name also
    passes (strip-then-validate ordering)."""
    name = "a" * 200
    assert normalize_display_name(name) == name
    assert normalize_display_name("  " + name + "  ") == name


def test_normalize_display_name_accepts_unicode():
    """§2.17: the control-char ban must not reject legitimate non-ASCII names
    (umlauts, accents) — only C0 + DEL are banned, not 'not ASCII'."""
    assert normalize_display_name("Müller-Àé") == "Müller-Àé"


# ---------------------------------------------------------------------------
# parse_user — row dict -> User dataclass mapping
# ---------------------------------------------------------------------------

def test_parse_user_full_row_maps_every_field():
    """A full DB row (fixtures.make_sample_user_row) maps 1:1 onto the User
    dataclass — guards against a field being silently dropped or renamed in
    parse_user when columns change."""
    row = make_sample_user_row()
    user = parse_user(row)

    assert isinstance(user, User)
    # Every dataclass field must equal the row value of the same name; this
    # loop is the drift guard — a new field missing from parse_user fails here.
    for f in dataclass_fields(User):
        assert getattr(user, f.name) == row[f.name], f"field {f.name} not mapped"


def test_parse_user_minimal_row_defaults_optionals():
    """A minimal row carrying only the required keys still parses; every
    optional field falls back to its documented default (display_name None,
    totp_configured False, is_admin False, email_verified False,
    last_totp_step None). Guards the row.get(...) defaults in parse_user."""
    created = datetime.datetime(2026, 5, 1, tzinfo=datetime.timezone.utc)
    row = {
        "id": 7,
        "email": "min@uzh.ch",
        "auth_method": "local",
        "access_tier": "public",
        "is_active": True,
        "created_at": created,
    }
    user = parse_user(row)

    assert user.id == 7
    assert user.email == "min@uzh.ch"
    assert user.auth_method == "local"
    assert user.access_tier == "public"
    assert user.is_active is True
    assert user.created_at == created
    # Optional fields default:
    assert user.display_name is None
    assert user.affiliation is None
    assert user.country is None
    assert user.last_login is None
    assert user.totp_configured is False
    assert user.is_admin is False
    assert user.email_verified is False
    assert user.last_totp_step is None


# ---------------------------------------------------------------------------
# validate_user_schema — USER_COLUMNS <-> User dataclass sync guard
# ---------------------------------------------------------------------------

def test_validate_user_schema_passes_on_real_lists():
    """The shipped USER_COLUMNS and User dataclass are in sync — the startup
    validator must not raise on the real module state."""
    validate_user_schema()  # must not raise


def test_validate_user_schema_flags_extra_sql_column(monkeypatch):
    """A column present in USER_COLUMNS but missing on the dataclass raises
    AssertionError naming the offending column — guards the
    'missing_from_dataclass' direction of the drift check."""
    monkeypatch.setattr(users, "USER_COLUMNS", users.USER_COLUMNS + ["bogus_col"])
    with pytest.raises(AssertionError, match="bogus_col") as excinfo:
        validate_user_schema()
    assert "not on User" in str(excinfo.value)


def test_validate_user_schema_flags_missing_sql_column(monkeypatch):
    """A dataclass field absent from USER_COLUMNS raises AssertionError the
    other direction ('Fields on User but not in USER_COLUMNS') — dropping
    'email' from the SELECT list must be caught at startup."""
    monkeypatch.setattr(
        users, "USER_COLUMNS", [c for c in users.USER_COLUMNS if c != "email"]
    )
    with pytest.raises(AssertionError, match="email") as excinfo:
        validate_user_schema()
    assert "not in USER_COLUMNS" in str(excinfo.value)


# ---------------------------------------------------------------------------
# user_columns_sql — SELECT list rendering (psycopg3 as_string(None))
# ---------------------------------------------------------------------------

def test_user_columns_sql_unaliased_rendering():
    """Unaliased build: every USER_COLUMNS column renders as a quoted
    identifier ('\"id\"', ...) and the computed totp flag renders as
    '(totp_secret IS NOT NULL) AS totp_configured' (totp_secret itself is
    raw SQL, not a quoted Identifier — see deviation note vs. the backlog
    sketch). Guards the never-fetch-the-secret contract."""
    rendered = user_columns_sql().as_string(None)

    assert '"id"' in rendered
    for col in users.USER_COLUMNS:
        assert f'"{col}"' in rendered, f"column {col} missing from SELECT list"
    assert "(totp_secret IS NOT NULL) AS totp_configured" in rendered
    # The encrypted secret is never selected as a column of its own.
    assert '"totp_secret"' not in rendered


def test_user_columns_sql_aliased_rendering():
    """Alias 'u': every column is table-qualified ('\"u\".\"id\"') and the
    computed totp flag reads from the aliased table
    ('(\"u\".totp_secret IS NOT NULL) AS totp_configured') — guards joined
    queries picking columns from the right table."""
    rendered = user_columns_sql("u").as_string(None)

    assert '"u"."id"' in rendered
    for col in users.USER_COLUMNS:
        assert f'"u"."{col}"' in rendered, f"column {col} not alias-qualified"
    assert '("u".totp_secret IS NOT NULL) AS totp_configured' in rendered


def test_user_columns_sql_cached_constant_matches_fresh_build():
    """The module-level cached USER_COLUMNS_SQL is exactly the unaliased
    build — guards against the cache and the builder drifting apart."""
    assert users.USER_COLUMNS_SQL.as_string(None) == user_columns_sql().as_string(None)


# ---------------------------------------------------------------------------
# UserAlreadyExistsError — except-ordering contract for the register route
# ---------------------------------------------------------------------------

def test_user_already_exists_error_is_value_error_carrying_email():
    """UserAlreadyExistsError subclasses ValueError and carries .email.
    §2.17: the register route relies on `except UserAlreadyExistsError`
    staying ordered BEFORE `except ValueError` — which only works because of
    this subclass relationship; a plain `except ValueError` catches it too."""
    err = UserAlreadyExistsError("dup@uzh.ch")

    assert isinstance(err, ValueError)
    assert err.email == "dup@uzh.ch"
    assert "dup@uzh.ch" in str(err)

    # The ordering contract in practice: a general ValueError handler would
    # swallow it, so the specific handler must come first in the route.
    with pytest.raises(ValueError):
        raise UserAlreadyExistsError("dup@uzh.ch")
