"""Fail-closed pins for the Settings validators that guard network exposure.

Every test constructs ``Settings(_env_file=None, **kwargs)`` so no ``.env``
file leaks in. Real OS environment variables still apply to *unset* fields,
so the kwargs helpers below pass an explicit value for every field a test
asserts on.

Each validator here moved an invariant from caller discipline to the config
boundary, so a bad deployment fails loudly at construction instead of
silently at runtime. The tests therefore assert the boundary REJECTS the bad
input, not just that the happy path constructs.
"""

import pytest
from pydantic import SecretStr, ValidationError

from tests.unit.settings_builders import (
    KWARGS_FOR_ENV,
    base_kwargs,
    make_settings,
    prod_kwargs,
    staging_kwargs,
)


class TestFastapiDebugGate:
    """FASTAPI_DEBUG must never be true outside dev."""

    @pytest.mark.parametrize("env", ["staging", "production"])
    def test_fastapi_debug_rejected_outside_dev(self, env):
        """FASTAPI_DEBUG=true must fail construction in any hardened environment
        (staging AND production) — debug tracebacks leak internals."""
        kwargs = KWARGS_FOR_ENV[env](fastapi_debug=True)
        with pytest.raises(ValidationError, match="only permitted when ENV_STATE=dev"):
            make_settings(**kwargs)


class TestPublicBaseUrl:
    """PUBLIC_BASE_URL must be a bare http(s) origin, normalized consistently."""

    @pytest.mark.parametrize(
        "public_base_url",
        [
            "https://",
            "https://?x",
            "https://#fragment",
            "https://archive.example.org/app",
            "https://archive.example.org?tenant=one",
            "https://archive.example.org#section",
            "https://user:password@archive.example.org",
        ],
    )
    def test_public_base_url_rejects_non_origin_values(self, public_base_url):
        with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
            make_settings(**base_kwargs(public_base_url=public_base_url))

    def test_public_base_url_allows_valid_port(self):
        configured = make_settings(
            **base_kwargs(public_base_url="https://archive.example.org:8443/")
        )

        assert configured.public_base_url == "https://archive.example.org:8443"

    def test_public_base_url_http_scheme_rejected_in_production(self):
        """A plaintext http:// public base URL must fail in production — it would
        put session cookies and reset tokens on the wire unencrypted."""
        with pytest.raises(ValidationError, match="non-localhost https:// URL"):
            make_settings(**prod_kwargs(public_base_url="http://archive.example.org"))

    def test_public_base_url_localhost_rejected_in_production(self):
        """https://localhost in production is a mis-deploy (links in emails would
        point at the operator's loopback), so it must fail construction."""
        with pytest.raises(ValidationError, match="non-localhost https:// URL"):
            make_settings(**prod_kwargs(public_base_url="https://localhost:8443"))

    def test_public_base_url_trailing_slash_stripped(self):
        """The normalizer strips the trailing slash so URL joins elsewhere never
        produce a double slash (https://x//path)."""
        s = make_settings(**base_kwargs(public_base_url="http://localhost:8000/"))
        assert s.public_base_url == "http://localhost:8000"

    def test_public_base_url_missing_scheme_rejected(self):
        """A bare hostname (no http/https scheme) must fail — every consumer
        assumes an absolute URL."""
        with pytest.raises(ValidationError, match="must be an absolute http:// or https:// URL"):
            make_settings(**base_kwargs(public_base_url="archive.example.org"))


class TestCookiesSecure:
    """COOKIES_SECURE may only relax outside a network-reachable deployment."""

    def test_cookies_secure_false_rejected_in_staging(self):
        """COOKIES_SECURE=false must fail in staging (is_hardened covers every
        deployed environment, not just production)."""
        with pytest.raises(ValidationError, match="COOKIES_SECURE must be True"):
            make_settings(**staging_kwargs(cookies_secure=False))

    def test_cookies_secure_false_allowed_in_dev(self):
        """Dev keeps the plaintext-HTTP escape hatch: cookies_secure=False
        constructs fine when env_state=dev."""
        s = make_settings(**base_kwargs(cookies_secure=False))
        assert s.cookies_secure is False


class TestAllowedHosts:
    """ALLOWED_HOSTS must actually constrain the Host header outside dev."""

    def test_allowed_hosts_wildcard_rejected_in_staging(self):
        """'*' disables TrustedHostMiddleware's Host check entirely — must block
        startup in staging/production."""
        with pytest.raises(ValidationError, match="disables TrustedHostMiddleware"):
            make_settings(**staging_kwargs(allowed_hosts=["*"]))

    def test_allowed_hosts_empty_rejected_in_staging(self):
        """An empty ALLOWED_HOSTS rejects every request (fail-closed but a broken
        deploy) — must block startup in staging/production."""
        with pytest.raises(ValidationError, match="every request would be rejected"):
            make_settings(**staging_kwargs(allowed_hosts=[]))

    @pytest.mark.parametrize("hosts", [["*"]], ids=["wildcard"])
    def test_allowed_hosts_misconfig_warns_in_dev(self, hosts):
        """In dev the same misconfigurations only warn (RuntimeWarning) so local
        setups are not blocked, but the operator is still told."""
        with pytest.warns(RuntimeWarning, match="ALLOWED_HOSTS WARNING"):
            s = make_settings(**base_kwargs(allowed_hosts=hosts))
        assert s.allowed_hosts == hosts

    def test_empty_hosts_rejects_public_origin_even_in_dev(self):
        with pytest.warns(RuntimeWarning), pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
            make_settings(**base_kwargs(allowed_hosts=[]))

    @pytest.mark.parametrize(
        "hosts",
        [
            ["unrelated.example.org"],
            ["https://localhost"],
            ["bad*host"],
            ["localhost:8000"],
        ],
        ids=[
            "syntactically-valid-host-does-not-match-public-base-url",
            "scheme-prefix-is-not-a-bare-host",
            "wildcard-not-in-leading-dot-position",
            "port-suffix-is-not-a-bare-host",
        ],
    )
    def test_allowed_hosts_syntax_and_public_base_url_membership_are_one_contract(self, hosts):
        """ALLOWED_HOSTS entries must both be syntactically valid bare hosts
        AND include PUBLIC_BASE_URL's own hostname — construction fails
        whichever half of that single contract a given input violates."""
        with pytest.raises(ValidationError):
            make_settings(**base_kwargs(allowed_hosts=hosts))


class TestCors:
    """CORS must not disable the same-origin policy outside dev."""

    def test_cors_wildcard_with_credentials_rejected_in_staging(self):
        """CORS enabled with '*' origins (here with allow_credentials=True, the
        worst combination) must block startup in staging/production.

        The validator rejects wildcard origins regardless of
        cors_allow_credentials.
        """
        kwargs = staging_kwargs(
            cors_enabled=True,
            cors_allow_credentials=True,
            cors_origins=["*"],
        )
        with pytest.raises(ValidationError, match="disables the same-origin policy"):
            make_settings(**kwargs)

    def test_cors_localhost_origin_rejected_in_staging(self):
        """A localhost CORS origin outside dev is a leftover dev config — must
        block startup in staging/production."""
        kwargs = staging_kwargs(
            cors_enabled=True,
            cors_origins=["http://localhost:3000"],
        )
        with pytest.raises(ValidationError, match="localhost origins outside dev"):
            make_settings(**kwargs)

    def test_cors_misconfig_warns_in_dev(self):
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


class TestDatabaseUrl:
    """DATABASE_URL must be a well-formed, canonical PostgreSQL DSN."""

    def test_database_url_rejects_non_postgres_scheme(self):
        """A non-PostgreSQL URL must fail construction, and the error must name
        the offending scheme so the operator sees what was actually configured."""
        with pytest.raises(ValidationError, match="Got scheme: 'mysql'"):
            make_settings(**base_kwargs(database_url="mysql://x/y"))

    def test_database_url_rejects_empty_connection_path(self):
        """'postgresql://' with nothing after the scheme (no host/db) must fail —
        it would otherwise surface as a confusing driver error at first query."""
        with pytest.raises(ValidationError, match="must contain a database name"):
            make_settings(**base_kwargs(database_url="postgresql://"))

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("postgres://u:p@h/db", "postgresql://u:p@h/db"),
            ("postgresql://u:p@h/db", "postgresql://u:p@h/db"),
            ("postgres:///dbname", "postgresql:///dbname"),
        ],
        ids=["legacy-scheme", "canonical-scheme", "legacy-socket-path"],
    )
    def test_database_url_scheme_normalized_to_postgresql(self, url, expected):
        """Validator-accepts-what-a-consumer-rejects. SQLAlchemy (the
        dialect registry Alembic's env.py resolves against) refuses the legacy
        'postgres://' scheme, so the boundary must NORMALIZE it to 'postgresql://'
        rather than pass it through — a revert to pass-through boots green and
        then crashes the first migration. The socket form 'postgres:///dbname'
        (no host) must survive the same rewrite."""
        s = make_settings(**base_kwargs(database_url=url))
        value = s.database_url.get_secret_value()
        assert value.startswith("postgresql://")
        assert value == expected

    def test_database_url_accepts_an_already_wrapped_secretstr(self):
        """The 'before' validator runs on the RAW input, ahead of Pydantic's
        own SecretStr wrapping, so it must explicitly unwrap a caller-supplied
        SecretStr (not just a plain str) before parsing the scheme — and the
        unwrapped value round-trips unchanged through get_secret_value()."""
        value = "postgresql://user:password@localhost/test"
        s = make_settings(**base_kwargs(database_url=SecretStr(value)))
        assert s.database_url.get_secret_value() == value


class TestStatementTimeoutFormat:
    """db_statement_timeout is interpolated into SQL, so its shape is pinned tightly."""

    @pytest.mark.parametrize(
        "value",
        ["5s", "500ms", "2min", "0"],
        ids=["seconds-unit", "milliseconds-unit", "minutes-unit", "zero-disables-the-timeout"],
    )
    def test_db_statement_timeout_accepts_interval_formats(self, value):
        """The whitelist accepts '0' (disabled) and <digits><ms|s|min> — the only
        shapes the app ever needs to interpolate into SET statement_timeout."""
        s = make_settings(**base_kwargs(db_statement_timeout=value))
        assert s.db_statement_timeout == value

    @pytest.mark.parametrize(
        "value",
        ["5; DROP TABLE users", "5 seconds"],
        ids=["sql-injection", "spelled-out-unit"],
    )
    def test_db_statement_timeout_rejects_non_interval_values(self, value):
        """Anything outside the strict interval regex must fail — the value is
        interpolated into SQL, so this validator is the injection guard."""
        with pytest.raises(ValidationError, match="db_statement_timeout must be '0'"):
            make_settings(**base_kwargs(db_statement_timeout=value))


class TestOaiInstitutionFilter:
    """OAI_INSTITUTION_FILTER scopes which upstream records are ingested."""

    def test_oai_institution_filter_blank_rejected(self):
        """A whitespace-only institution filter must fail — it scopes which
        datasets are ingested; empty would silently ingest nothing (or wrong)."""
        with pytest.raises(ValidationError, match="OAI_INSTITUTION_FILTER must not be empty"):
            make_settings(**base_kwargs(oai_institution_filter="  "))

    def test_oai_institution_filter_whitespace_normalized(self):
        """Surrounding whitespace is stripped so ' X ' matches records tagged 'X'
        — guards against an invisible .env formatting mismatch."""
        s = make_settings(**base_kwargs(oai_institution_filter=" X "))
        assert s.oai_institution_filter == "X"


class TestSessionCookieName:
    """SESSION_COOKIE_NAME must be a distinct, syntactically valid cookie
    token so it can never be confused with the CSRF/pre-session cookies and
    the browser can always store and echo it back."""

    @pytest.mark.parametrize(
        "session_cookie_name",
        [
            "",
            "csrf_token",
            "pre_session_id",
            "bad name",
            "a;b",
            "a=b",
            "é",
            "path",
            "__Secure-session",
            "__Host-session",
        ],
        ids=[
            "empty_string",
            "collides_with_csrf_cookie_name",
            "collides_with_pre_session_cookie_name",
            "contains_space",
            "contains_semicolon",
            "contains_equals",
            "non_ascii_character",
            "reserved_cookie_attribute_name",
            "secure_prefix_unsupported",
            "host_prefix_unsupported",
        ],
    )
    def test_invalid_session_cookie_name_fails_construction(self, session_cookie_name):
        """Empty, colliding with a reserved cookie name (CSRF or pre-session),
        containing characters SimpleCookie cannot encode, or carrying an
        unsupported __Secure-/__Host- prefix must all fail construction."""
        with pytest.raises(ValidationError, match="SESSION_COOKIE_NAME"):
            make_settings(**base_kwargs(session_cookie_name=session_cookie_name))

    def test_valid_session_cookie_name_constructs(self):
        """Positive control: a distinct, syntactically valid cookie name
        without a __Secure-/__Host- prefix constructs without error."""
        s = make_settings(**base_kwargs(session_cookie_name="oha_session"))
        assert s.session_cookie_name == "oha_session"
