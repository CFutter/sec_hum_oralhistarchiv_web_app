"""Fail-closed pins for the Settings validators (TESTING_BACKLOG §6.3 + config hygiene).

Every test constructs ``Settings(_env_file=None, **kwargs)`` so no ``.env`` file
leaks in. Real OS environment variables still apply to *unset* fields, so the
kwargs helpers below pass an explicit value for every field a test asserts on.

These are boundary-enforcement guards (backlog "Note on scope"): each validator
moved an invariant from caller discipline to the config boundary, so a bad
deployment fails loudly at construction instead of silently at runtime. The
tests therefore assert the boundary REJECTS the bad input, not just that the
happy path constructs.
"""

import pytest
from pydantic import SecretStr, ValidationError

from config.settings import Settings


# ---------------------------------------------------------------------------
# kwargs helpers — one per environment tier
# ---------------------------------------------------------------------------

def base_kwargs(**overrides):
    """All mandatory fields with strong dev-safe values.

    Every toggle a validator inspects is pinned explicitly so ambient env vars
    (the conftest bootstrap block or a developer's shell) cannot change what a
    test constructs.
    """
    kw = dict(
        env_state="dev",
        database_url="postgresql://oha:db-secret-pw@localhost:5432/oha_test",
        public_base_url="http://localhost:8000",
        secret_key="unit-test-secret-key-0123456789abcdefghijklmnopqrstuv",
        session_secret="unit-test-session-secret-0123456789abcdefghijklmnopq",
        totp_encryption_keys=["unit-test-totp-key-0123456789abcdefghijklmnopqrstu"],
        allowed_hosts=["example.org"],
        oai_institution_filter="Universität Kassel",
        cookies_secure=True,
        fastapi_debug=False,
        smtp_enabled=False,
        smtp_user="",
        smtp_password=None,
        redis_enabled=False,
        shibboleth_enabled=False,
        cors_enabled=False,
    )
    kw.update(overrides)
    return kw


def staging_kwargs(**overrides):
    """base_kwargs adjusted to satisfy the is_hardened (staging) validators."""
    kw = base_kwargs(
        env_state="staging",
        public_base_url="https://staging.archive.example.org",
        cookies_secure=True,
    )
    kw.update(overrides)
    return kw


def prod_kwargs(**overrides):
    """base_kwargs adjusted to satisfy every production-only validator.

    Redis is enabled with a non-empty URL so construction emits no
    'Redis is disabled in production' RuntimeWarning (keeps warns-based
    assertions elsewhere clean without relying on the filterwarnings config).
    """
    kw = base_kwargs(
        env_state="production",
        public_base_url="https://archive.example.org",
        cookies_secure=True,
        health_detail_token="prod-health-token-0123456789abcdefghij",
        smtp_enabled=True,
        smtp_host="mail.example.org",
        smtp_port=587,
        smtp_from_address="archive@example.org",
        smtp_use_tls=True,
        redis_enabled=True,
        redis_url="redis://redis.internal.example.org:6379/0",
    )
    kw.update(overrides)
    return kw


_KWARGS_FOR_ENV = {
    "dev": base_kwargs,
    "staging": staging_kwargs,
    "production": prod_kwargs,
}


def make_settings(**kwargs) -> Settings:
    """Construct Settings without reading any .env file."""
    return Settings(_env_file=None, **kwargs)


# ---------------------------------------------------------------------------
# §6.3 — SMTP user/password must be set together (symmetric XOR)
# ---------------------------------------------------------------------------

def test_smtp_user_without_password_raises():
    """§6.3: smtp_user set with smtp_password=None fails at construction.

    Guards the smtp_user-without-smtp_password AttributeError that was
    swallowed into a silent False on every email send.
    """
    with pytest.raises(ValidationError, match="must be set together"):
        make_settings(**base_kwargs(smtp_user="x", smtp_password=None))


def test_smtp_password_without_user_raises():
    """§6.3: the symmetric case — password set with empty user also fails,
    so the XOR gate cannot be half-satisfied from either side."""
    with pytest.raises(ValidationError, match="must be set together"):
        make_settings(**base_kwargs(smtp_user="", smtp_password=SecretStr("x")))


def test_smtp_auth_pair_both_set_constructs():
    """§6.3: both credentials set is a valid (authenticated-relay) config."""
    s = make_settings(**base_kwargs(smtp_user="mailer", smtp_password=SecretStr("pw")))
    assert s.smtp_user == "mailer"
    assert s.smtp_password is not None
    assert s.smtp_password.get_secret_value() == "pw"


def test_smtp_auth_pair_both_unset_constructs():
    """§6.3: both credentials unset is a valid (unauthenticated-relay) config."""
    s = make_settings(**base_kwargs(smtp_user="", smtp_password=None))
    assert s.smtp_user == ""
    assert s.smtp_password is None


# ---------------------------------------------------------------------------
# fastapi_debug — dev only
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("env", ["staging", "production"])
def test_fastapi_debug_rejected_outside_dev(env):
    """FASTAPI_DEBUG=true must fail construction in any hardened environment
    (staging AND production) — debug tracebacks leak internals."""
    kwargs = _KWARGS_FOR_ENV[env](fastapi_debug=True)
    with pytest.raises(ValidationError, match="only permitted when ENV_STATE=dev"):
        make_settings(**kwargs)


# ---------------------------------------------------------------------------
# public_base_url
# ---------------------------------------------------------------------------

def test_public_base_url_http_scheme_rejected_in_production():
    """A plaintext http:// public base URL must fail in production — it would
    put session cookies and reset tokens on the wire unencrypted."""
    with pytest.raises(ValidationError, match="non-localhost https:// URL"):
        make_settings(**prod_kwargs(public_base_url="http://archive.example.org"))


def test_public_base_url_localhost_rejected_in_production():
    """https://localhost in production is a mis-deploy (links in emails would
    point at the operator's loopback), so it must fail construction."""
    with pytest.raises(ValidationError, match="non-localhost https:// URL"):
        make_settings(**prod_kwargs(public_base_url="https://localhost:8443"))


def test_public_base_url_trailing_slash_stripped():
    """The normalizer strips the trailing slash so URL joins elsewhere never
    produce a double slash (https://x//path)."""
    s = make_settings(**base_kwargs(public_base_url="http://localhost:8000/"))
    assert s.public_base_url == "http://localhost:8000"


def test_public_base_url_missing_scheme_rejected():
    """A bare hostname (no http/https scheme) must fail — every consumer
    assumes an absolute URL."""
    with pytest.raises(ValidationError, match="must start with http:// or https://"):
        make_settings(**base_kwargs(public_base_url="archive.example.org"))


# ---------------------------------------------------------------------------
# cookies_secure
# ---------------------------------------------------------------------------

def test_cookies_secure_false_rejected_in_staging():
    """COOKIES_SECURE=false must fail in staging (is_hardened covers every
    deployed environment, not just production)."""
    with pytest.raises(ValidationError, match="COOKIES_SECURE must be True"):
        make_settings(**staging_kwargs(cookies_secure=False))


def test_cookies_secure_false_allowed_in_dev():
    """Dev keeps the plaintext-HTTP escape hatch: cookies_secure=False
    constructs fine when env_state=dev."""
    s = make_settings(**base_kwargs(cookies_secure=False))
    assert s.cookies_secure is False


# ---------------------------------------------------------------------------
# allowed_hosts
# ---------------------------------------------------------------------------

def test_allowed_hosts_wildcard_rejected_in_staging():
    """'*' disables TrustedHostMiddleware's Host check entirely — must block
    startup in staging/production."""
    with pytest.raises(ValidationError, match="disables TrustedHostMiddleware"):
        make_settings(**staging_kwargs(allowed_hosts=["*"]))


def test_allowed_hosts_empty_rejected_in_staging():
    """An empty ALLOWED_HOSTS rejects every request (fail-closed but a broken
    deploy) — must block startup in staging/production."""
    with pytest.raises(ValidationError, match="every request would be rejected"):
        make_settings(**staging_kwargs(allowed_hosts=[]))


@pytest.mark.parametrize("hosts", [["*"], []], ids=["wildcard", "empty"])
def test_allowed_hosts_misconfig_warns_in_dev(hosts):
    """In dev the same misconfigurations only warn (RuntimeWarning) so local
    setups are not blocked, but the operator is still told."""
    with pytest.warns(RuntimeWarning, match="ALLOWED_HOSTS WARNING"):
        s = make_settings(**base_kwargs(allowed_hosts=hosts))
    assert s.allowed_hosts == hosts


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def test_cors_wildcard_with_credentials_rejected_in_staging():
    """CORS enabled with '*' origins (here with allow_credentials=True, the
    worst combination) must block startup in staging/production.

    NOTE: the validator rejects wildcard origins regardless of
    cors_allow_credentials — see 'deviations' in the run report.
    """
    kwargs = staging_kwargs(
        cors_enabled=True,
        cors_allow_credentials=True,
        cors_origins=["*"],
    )
    with pytest.raises(ValidationError, match="disables the same-origin policy"):
        make_settings(**kwargs)


def test_cors_localhost_origin_rejected_in_staging():
    """A localhost CORS origin outside dev is a leftover dev config — must
    block startup in staging/production."""
    kwargs = staging_kwargs(
        cors_enabled=True,
        cors_origins=["http://localhost:3000"],
    )
    with pytest.raises(ValidationError, match="localhost origins outside dev"):
        make_settings(**kwargs)


def test_cors_misconfig_warns_in_dev():
    """In dev the wildcard-origin misconfiguration only warns (RuntimeWarning)
    for awareness, mirroring the allowed_hosts policy."""
    kwargs = base_kwargs(
        cors_enabled=True,
        cors_allow_credentials=True,
        cors_origins=["*"],
    )
    with pytest.warns(RuntimeWarning, match="CORS WARNING"):
        s = make_settings(**kwargs)
    assert s.cors_origins == ["*"]


# ---------------------------------------------------------------------------
# database_url
# ---------------------------------------------------------------------------

def test_database_url_rejects_non_postgres_scheme():
    """A non-PostgreSQL URL must fail construction, and the error must name
    the offending scheme so the operator sees what was actually configured."""
    with pytest.raises(ValidationError, match="Got scheme: 'mysql'"):
        make_settings(**base_kwargs(database_url="mysql://x/y"))


def test_database_url_rejects_empty_connection_path():
    """'postgresql://' with nothing after the scheme (no host/db) must fail —
    it would otherwise surface as a confusing driver error at first query."""
    with pytest.raises(ValidationError, match="must contain a database name"):
        make_settings(**base_kwargs(database_url="postgresql://"))


# ---------------------------------------------------------------------------
# db_statement_timeout
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["5s", "500ms", "2min", "0"])
def test_db_statement_timeout_accepts_interval_formats(value):
    """The whitelist accepts '0' (disabled) and <digits><ms|s|min> — the only
    shapes the app ever needs to interpolate into SET statement_timeout."""
    s = make_settings(**base_kwargs(db_statement_timeout=value))
    assert s.db_statement_timeout == value


@pytest.mark.parametrize(
    "value",
    ["5; DROP TABLE users", "5 seconds"],
    ids=["sql-injection", "spelled-out-unit"],
)
def test_db_statement_timeout_rejects_non_interval_values(value):
    """Anything outside the strict interval regex must fail — the value is
    interpolated into SQL, so this validator is the injection guard."""
    with pytest.raises(ValidationError, match="db_statement_timeout must be '0'"):
        make_settings(**base_kwargs(db_statement_timeout=value))


# ---------------------------------------------------------------------------
# redis
# ---------------------------------------------------------------------------

def test_redis_enabled_requires_redis_url():
    """redis_enabled=True with an empty REDIS_URL must fail at construction
    instead of failing at first rate-limit/cache-invalidation call."""
    kwargs = base_kwargs(redis_enabled=True, redis_url=SecretStr(""))
    with pytest.raises(ValidationError, match="REDIS_URL must be set"):
        make_settings(**kwargs)


# ---------------------------------------------------------------------------
# shibboleth
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("env", ["dev", "staging", "production"])
def test_shibboleth_enabled_requires_internal_secret(env):
    """SHIBBOLETH_ENABLED=true without the internal callback secret must fail
    in EVERY environment — without it the callback has only the single
    IP-based trust check."""
    kwargs = _KWARGS_FOR_ENV[env](
        shibboleth_enabled=True,
        shibboleth_internal_secret=None,
    )
    with pytest.raises(
        ValidationError, match="SHIBBOLETH_INTERNAL_SECRET must be set"
    ):
        make_settings(**kwargs)


# ---------------------------------------------------------------------------
# SMTP placeholders / TLS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("smtp_host", "smtp.example.com", "smtp_host is still the placeholder"),
        (
            "smtp_from_address",
            "noreply@example.com",
            "smtp_from_address is still the placeholder",
        ),
    ],
    ids=["host", "from_address"],
)
def test_smtp_placeholders_rejected_in_production(field, value, match):
    """Enabling SMTP in production while a field still holds its shipped
    placeholder value must fail — the operator enabled SMTP without
    configuring it."""
    with pytest.raises(ValidationError, match=match):
        make_settings(**prod_kwargs(**{field: value}))


def test_smtp_use_tls_false_rejected_in_staging():
    """SMTP_USE_TLS=false with SMTP enabled must fail in hardened envs —
    plaintext SMTP would expose password-reset tokens and relay credentials.

    (The error text says 'in production' but the validator gates on
    is_hardened, so staging is covered too — the code is the pin.)
    """
    kwargs = staging_kwargs(
        smtp_enabled=True,
        smtp_host="mail.example.org",
        smtp_port=587,
        smtp_from_address="archive@example.org",
        smtp_use_tls=False,
    )
    with pytest.raises(ValidationError, match="SMTP_USE_TLS must be True"):
        make_settings(**kwargs)


# ---------------------------------------------------------------------------
# oai_institution_filter
# ---------------------------------------------------------------------------

def test_oai_institution_filter_blank_rejected():
    """A whitespace-only institution filter must fail — it scopes which
    datasets are ingested; empty would silently ingest nothing (or wrong)."""
    with pytest.raises(ValidationError, match="OAI_INSTITUTION_FILTER must not be empty"):
        make_settings(**base_kwargs(oai_institution_filter="  "))


def test_oai_institution_filter_whitespace_normalized():
    """Surrounding whitespace is stripped so ' X ' matches records tagged 'X'
    — guards against an invisible .env formatting mismatch."""
    s = make_settings(**base_kwargs(oai_institution_filter=" X "))
    assert s.oai_institution_filter == "X"


# ---------------------------------------------------------------------------
# __repr__ redaction
# ---------------------------------------------------------------------------

def test_repr_hides_database_password():
    """repr()/str() of Settings must never contain the database password —
    the custom __repr__ replaces the DSN with '***' so tracebacks and log
    lines cannot leak credentials."""
    password = "db-secret-pw"
    s = make_settings(
        **base_kwargs(
            database_url=f"postgresql://oha:{password}@localhost:5432/oha_test"
        )
    )
    assert password not in repr(s)
    assert password not in str(s)
    assert "database_url=***" in repr(s)
