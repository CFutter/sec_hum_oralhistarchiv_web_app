"""Fail-closed pins for the Settings validators that guard network exposure."""

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
        """Check public base URL rejects non origin values (ValidationError)."""
        with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
            make_settings(**base_kwargs(public_base_url=public_base_url))

    def test_public_base_url_allows_valid_port(self):
        """Check public base URL allows valid port."""
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

    def test_empty_hosts_rejects_even_in_dev_without_a_warning(self, recwarn):
        """Check empty hosts rejects even in dev without a warning (ValidationError)."""
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS is empty"):
            make_settings(**base_kwargs(allowed_hosts=[]))
        assert not recwarn.list

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
        """Check allowed hosts syntax and public base URL membership are one contract
        (ValidationError).
        """
        with pytest.raises(ValidationError):
            make_settings(**base_kwargs(allowed_hosts=hosts))


class TestCors:
    """CORS must not disable the same-origin policy outside dev."""

    def test_cors_wildcard_with_credentials_rejected_in_staging(self):
        """CORS enabled with '*' origins (here with allow_credentials=True, the worst combination) must
        block startup in staging/production.
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
        """A non-PostgreSQL URL fails without echoing any submitted input."""
        with pytest.raises(ValidationError, match="must start with 'postgresql://'"):
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
        """Validator-accepts-what-a-consumer-rejects."""
        s = make_settings(**base_kwargs(database_url=url))
        value = s.database_url.get_secret_value()
        assert value.startswith("postgresql://")
        assert value == expected

    def test_database_url_accepts_an_already_wrapped_secretstr(self):
        """Check database URL accepts an already wrapped secretstr."""
        value = "postgresql://user:password@localhost/test"
        s = make_settings(**base_kwargs(database_url=SecretStr(value)))
        assert s.database_url.get_secret_value() == value


class TestStatementTimeoutFormat:
    """Reject configuration mistakes before a pool tries to configure connections."""

    @pytest.mark.parametrize(
        "value",
        ["5s", "500ms", "2min", "0"],
        ids=["seconds-unit", "milliseconds-unit", "minutes-unit", "zero-disables-the-timeout"],
    )
    def test_db_statement_timeout_accepts_interval_formats(self, value):
        """Accept bare '0' and ordinary positive ms/s/min durations."""
        s = make_settings(**base_kwargs(db_statement_timeout=value))
        assert s.db_statement_timeout == value

    @pytest.mark.parametrize(
        "value",
        ["5; DROP TABLE users", "5 seconds"],
        ids=["sql-injection", "spelled-out-unit"],
    )
    def test_db_statement_timeout_rejects_non_interval_values(self, value):
        """Invalid duration syntax fails early; sql.Literal handles SQL quoting."""
        with pytest.raises(ValidationError, match="db_statement_timeout must be '0'"):
            make_settings(**base_kwargs(db_statement_timeout=value))


class TestSessionCookieName:
    """Cover session cookie name."""

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
        ],
    )
    def test_invalid_session_cookie_name_fails_construction(self, session_cookie_name):
        """Check invalid session cookie name fails construction (ValidationError)."""
        with pytest.raises(ValidationError, match="SESSION_COOKIE_NAME"):
            make_settings(**base_kwargs(session_cookie_name=session_cookie_name))

    def test_valid_session_cookie_name_constructs(self):
        """Check valid session cookie name constructs."""
        s = make_settings(**base_kwargs(session_cookie_name="oha_session"))
        assert s.session_cookie_name == "oha_session"
