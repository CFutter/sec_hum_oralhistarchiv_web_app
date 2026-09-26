"""Fail-closed pins for Settings branches that the other settings modules do
not reach: type-coercion guards, environment-state smuggling, and validator
arms that need a permitted-but-unusual value (a public IPv4 literal, an
absent health token, a smuggled ``.env`` state) to exercise.

Every test constructs ``Settings(_env_file=None, **kwargs)`` via the shared
``make_settings`` helper so no real ``.env`` leaks in, except the
``TestEnvStateCannotBeSmuggledViaDotenv`` class, which patches the module's
``_ENV_FILE`` constant directly because that guard inspects the OS
environment and a real filesystem path *before* Settings is constructed.

``config/__init__.py`` does ``from .settings import settings`` — because the
submodule and the singleton share the name ``settings``, the package
attribute ``config.settings`` is shadowed by the *instance*, and even
``pytest.monkeypatch.setattr("config.settings._ENV_FILE", ...)`` resolves to
that instance and fails. The module-constant tests below therefore import
the real submodule with ``importlib.import_module`` and patch attributes on
that object directly.
"""

import importlib
import logging

import pytest
from pydantic import ValidationError

from config import settings as settings_singleton
from config.settings import (
    Settings,
    _public_https_origin_error,
    warn_unconsumed_env_keys,
)
from tests.unit.settings_builders import base_kwargs, make_settings, prod_kwargs, staging_kwargs

_settings_module = importlib.import_module("config.settings")

SHIBBOLETH_TEST_SECRET = "uB8k4Pq7Nw2Yx6Ds9Fm3Ha5Jv1Rc8Tz4Lg7Ke2Qp9Ws6Bn3Xf5Mh8Cy1Vr4Zd7Aa"
TRUSTED_SHIBBOLETH_ISSUER = "https://idp.example.org/idp/shibboleth"


class TestAllowedHostsRejectsUnparseableHostSyntax:
    """ALLOWED_HOSTS entries must be hosts Starlette can compare unambiguously.

    ``_is_syntactically_valid_http_host`` returns False (never raises) for a
    host containing "%" or one whose IDNA encoding fails, and the field
    validator turns that into the same construction failure as any other
    syntactically invalid host.
    """

    @pytest.mark.parametrize(
        "host",
        ["archive%2eexample.org", "exa%mple.com"],
        ids=["percent-in-place-of-a-dot", "percent-mid-label"],
    )
    def test_allowed_hosts_rejects_a_host_containing_a_percent_character(self, host):
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS must contain"):
            make_settings(**base_kwargs(allowed_hosts=[host]))

    def test_allowed_hosts_rejects_a_host_with_an_empty_dns_label(self):
        """ "example..com" has an empty label between the dots: idna encoding
        raises UnicodeError, which the validator must catch and turn into the
        same rejection, not let it propagate as an unhandled exception."""
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS must contain"):
            make_settings(**base_kwargs(allowed_hosts=["example..com"]))

    def test_allowed_hosts_accepts_a_syntactically_valid_host(self):
        """Positive control: an ordinary DNS host with no '%' and no empty
        label constructs without error. "localhost" stays in the list so it
        still matches the default PUBLIC_BASE_URL's own hostname."""
        s = make_settings(**base_kwargs(allowed_hosts=["archive.example.org", "localhost"]))
        assert s.allowed_hosts == ["archive.example.org", "localhost"]


class TestAllowedHostsRejectsNonAsciiNames:
    def test_allowed_hosts_rejects_a_non_ascii_host(self):
        """A raw Unicode host must be rejected — operators must supply the
        punycode form so string comparison against the Host header is exact."""
        with pytest.raises(ValidationError, match="ASCII/punycode DNS names"):
            make_settings(**base_kwargs(allowed_hosts=["archïve.example.org"]))

    def test_allowed_hosts_accepts_the_punycode_form_of_the_same_host(self):
        """Positive control: the punycode encoding of the same host constructs
        fine, proving the rejection above targets the raw Unicode, not the
        host itself."""
        s = make_settings(**base_kwargs(allowed_hosts=["xn--archve-lwa.example.org", "localhost"]))
        assert s.allowed_hosts == ["xn--archve-lwa.example.org", "localhost"]


class TestTrustedProxyIpNormalization:
    """TRUSTED_PROXY_IPS entries are compared verbatim against the resolved
    peer address, so every entry must be normalizable to a literal IP."""

    def test_blank_entries_are_dropped_silently(self):
        """A blank line/entry (e.g. a trailing comma in a hand-edited list)
        is simply skipped, not treated as an invalid address."""
        s = make_settings(**base_kwargs(trusted_proxy_ips=["127.0.0.1", "   ", "::1"]))
        assert s.trusted_proxy_ips == ["127.0.0.1", "::1"]

    def test_unparseable_entries_are_rejected_and_named(self):
        """A hostname or a CIDR range is not a literal IP address — the
        validator must fail construction and name every offending entry so
        the operator can find the typo."""
        with pytest.raises(ValidationError) as excinfo:
            make_settings(**base_kwargs(trusted_proxy_ips=["proxy.example.org", "10.0.0.0/24"]))
        message = str(excinfo.value)
        assert "TRUSTED_PROXY_IPS entries are not valid IP addresses" in message
        assert "proxy.example.org" in message
        assert "10.0.0.0/24" in message


class TestDatabaseUrlRejectsNonStringValues:
    """The 'before' validator must reject a non-string, non-SecretStr raw
    value instead of letting a downstream .startswith() call raise a raw
    AttributeError."""

    def test_database_url_rejects_an_integer(self):
        with pytest.raises(
            ValidationError, match="DATABASE_URL must be a PostgreSQL connection string"
        ):
            make_settings(**base_kwargs(database_url=12345))

    def test_database_url_accepts_a_well_formed_string(self):
        """Positive control: the ordinary string case still constructs."""
        s = make_settings(**base_kwargs(database_url="postgresql://oha:pw@localhost:5432/oha_test"))
        assert s.database_url.get_secret_value() == "postgresql://oha:pw@localhost:5432/oha_test"


class TestAdminSeedCredentialPairing:
    """ADMIN_SEED_EMAIL and ADMIN_SEED_PASSWORD are an atomic pair: setting
    only one would seed nothing while looking configured."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"admin_seed_email": "admin@example.org", "admin_seed_password": None},
            {"admin_seed_email": None, "admin_seed_password": "AdminSeedPassw0rd!"},
        ],
        ids=["email-without-password", "password-without-email"],
    )
    def test_setting_only_one_half_of_the_pair_is_rejected(self, overrides):
        with pytest.raises(ValidationError, match="must be set together"):
            make_settings(**base_kwargs(**overrides))

    def test_setting_both_halves_constructs_and_normalizes_the_email(self):
        """Positive control: both set together constructs, and the email is
        normalized (lowercased) by validate_seed_credentials."""
        s = make_settings(
            **base_kwargs(
                admin_seed_email="Admin@Example.ORG",
                admin_seed_password="AdminSeedPassw0rd!",
            )
        )
        assert s.admin_seed_email == "admin@example.org"


class TestSmtpFromAddressValidation:
    def test_smtp_from_address_rejects_an_unparseable_address(self):
        with pytest.raises(ValidationError, match="SMTP_FROM_ADDRESS must be a supported"):
            make_settings(**base_kwargs(smtp_from_address="not-an-email-address"))

    def test_smtp_from_address_accepts_and_normalizes_a_real_address(self):
        """Positive control: a valid address constructs, normalized to
        lowercase, matching normalize_email's contract."""
        s = make_settings(**base_kwargs(smtp_from_address="Archive@Example.ORG"))
        assert s.smtp_from_address == "archive@example.org"


class TestSmtpFromNameValidation:
    @pytest.mark.parametrize(
        "value",
        ["", "bad\x00name"],
        ids=["empty_string", "contains_a_control_character"],
    )
    def test_smtp_from_name_rejects_unprintable_or_empty_values(self, value):
        with pytest.raises(ValidationError, match="SMTP_FROM_NAME must contain printable"):
            make_settings(**base_kwargs(smtp_from_name=value))

    def test_smtp_from_name_accepts_a_printable_display_name(self):
        """Positive control: an ordinary printable display name constructs."""
        s = make_settings(**base_kwargs(smtp_from_name="Oral History Archive"))
        assert s.smtp_from_name == "Oral History Archive"


class TestSmtpHostRequiredWhenSmtpEnabled:
    def test_smtp_enabled_with_blank_host_is_rejected(self):
        with pytest.raises(ValidationError, match="smtp_enabled=True requires smtp_host"):
            make_settings(
                **base_kwargs(
                    smtp_enabled=True,
                    smtp_host="",
                    smtp_from_address="archive@example.org",
                )
            )

    def test_smtp_enabled_with_a_real_host_constructs(self):
        """Positive control: SMTP fully configured constructs without error."""
        s = make_settings(
            **base_kwargs(
                smtp_enabled=True,
                smtp_host="mail.example.org",
                smtp_from_address="archive@example.org",
            )
        )
        assert s.smtp_host == "mail.example.org"


class TestHealthDetailTokenRequiredWhenHardened:
    """Without HEALTH_DETAIL_TOKEN, /health/detail 404s in every non-debug
    environment — staging and production must refuse to start without one."""

    def test_hardened_environment_without_a_health_token_is_rejected(self):
        with pytest.raises(ValidationError, match="HEALTH_DETAIL_TOKEN must be set"):
            make_settings(**staging_kwargs(health_detail_token=None))

    def test_hardened_environment_with_a_health_token_constructs(self):
        """Positive control: a real token in the same (staging) tier
        constructs fine."""
        s = make_settings(
            **staging_kwargs(health_detail_token="staging-health-token-0123456789abcdef")
        )
        assert s.health_detail_token is not None
        assert s.health_detail_token.get_secret_value() == "staging-health-token-0123456789abcdef"


class TestRedisDisabledInProductionWarns:
    """Production without Redis still boots (single-worker mode), but the
    operator must be told at startup, not discover it at the second worker."""

    def test_production_without_redis_warns(self):
        with pytest.warns(RuntimeWarning, match="Redis is disabled in production"):
            s = make_settings(**prod_kwargs(redis_enabled=False))
        assert s.redis_enabled is False

    def test_production_with_redis_enabled_does_not_warn(self, recwarn):
        """Positive control: the documented multi-worker configuration
        constructs with no RuntimeWarning about a missing Redis."""
        make_settings(**prod_kwargs(redis_enabled=True))
        assert not any("Redis is disabled in production" in str(w.message) for w in recwarn.list)


class TestCorsRequiresOriginsWhenEnabled:
    """CORS enabled with an empty origin list would allow the preflight to
    succeed while every real browser request is still cross-origin-blocked
    — a silently broken configuration the validator must flag."""

    def test_cors_enabled_with_no_origins_warns_in_dev(self):
        with pytest.warns(RuntimeWarning, match="no origins are configured"):
            s = make_settings(**base_kwargs(cors_enabled=True, cors_origins=[]))
        assert s.cors_origins == []

    def test_cors_enabled_with_no_origins_blocks_startup_in_staging(self):
        with pytest.raises(ValidationError, match="no origins are configured"):
            make_settings(**staging_kwargs(cors_enabled=True, cors_origins=[]))

    def test_cors_enabled_with_real_origins_constructs_with_no_warning(self, recwarn):
        """Positive control: CORS enabled with a concrete, non-wildcard,
        non-localhost origin constructs with no CORS RuntimeWarning at all —
        proving the two rejections above are not just rejecting every
        CORS-enabled configuration."""
        s = make_settings(
            **base_kwargs(cors_enabled=True, cors_origins=["https://good.example.org"])
        )
        assert s.cors_origins == ["https://good.example.org"]
        assert not any("CORS WARNING" in str(w.message) for w in recwarn.list)


class TestPublicHttpsOriginErrorHelper:
    """``_public_https_origin_error`` backs the Shibboleth transport gate.

    By the time Settings calls it, PUBLIC_BASE_URL has already been
    normalized by the ``public_base_url`` field validator to a bare
    ``scheme://netloc`` (no path, query, or fragment; ASCII-or-Unicode host
    unchanged) — so its own path/query/fragment check and its own IDNA
    UnicodeError recovery can only be exercised by calling the pure function
    directly with a value Settings itself would never produce.
    """

    def test_rejects_a_value_with_a_path_query_or_fragment(self):
        assert (
            _public_https_origin_error("https://archive.example.org/reports")
            == "SHIBBOLETH_ENABLED=true requires a non-localhost HTTPS PUBLIC_BASE_URL "
            "in every environment"
        )

    def test_rejects_a_host_whose_idna_encoding_fails(self):
        """A host with an empty label (double dot) cannot be IDNA-encoded;
        the UnicodeError must be caught and turned into the same rejection
        message, not propagate as an unhandled exception."""
        assert (
            _public_https_origin_error("https://example..com")
            == "SHIBBOLETH_ENABLED=true requires a non-localhost HTTPS PUBLIC_BASE_URL "
            "in every environment"
        )

    def test_accepts_a_bare_public_https_origin(self):
        """Positive control: a bare, non-localhost https origin with no
        path/query/fragment and an IDNA-encodable host returns None (no
        blocker) — proving the two rejections above are specific to the
        path/query/fragment and IDNA-failure cases, not to every input."""
        assert _public_https_origin_error("https://archive.example.org") is None


class TestShibbolethAcceptsAPublicIpv4LiteralOrigin:
    """A public (non-loopback) IPv4-literal PUBLIC_BASE_URL, alongside a
    mixed IPv4/DNS ALLOWED_HOSTS list, is a permitted Shibboleth transport —
    covers the branch where address parsing succeeds and the address is
    genuinely public, and the allowed-hosts loop continuing past one valid
    IPv4 entry to check the next one."""

    def test_ipv4_literal_public_base_url_with_mixed_allowed_hosts_constructs(self):
        s = make_settings(
            **base_kwargs(
                shibboleth_enabled=True,
                shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
                shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
                public_base_url="https://203.0.113.5",
                allowed_hosts=["203.0.113.5", "archive.example.org"],
                cookies_secure=True,
            )
        )
        assert s.public_base_url == "https://203.0.113.5"
        assert s.allowed_hosts == ["203.0.113.5", "archive.example.org"]


class TestPublicBaseUrlHostnameMustBeAsciiAndListedInAllowedHosts:
    """``validate_shibboleth_settings`` also pins PUBLIC_BASE_URL's own
    hostname unconditionally (not only when SHIBBOLETH_ENABLED=true): it
    must be ASCII/punycode and present in ALLOWED_HOSTS (exactly, or via a
    leading ``*.`` entry). The general ``public_base_url`` field validator
    permits raw Unicode; this later, always-on model validator is what
    actually forbids it reaching a running app, since Host-header matching
    downstream needs an exact, punycode comparison.
    """

    def test_a_raw_unicode_hostname_is_rejected(self):
        """ALLOWED_HOSTS is left at its default (ASCII, unrelated) value: the
        ASCII check on PUBLIC_BASE_URL's own hostname runs, and raises,
        before the ALLOWED_HOSTS membership check is ever reached."""
        with pytest.raises(ValidationError, match="ASCII/punycode hostname"):
            make_settings(**base_kwargs(public_base_url="https://müller.example.org"))

    def test_an_ascii_hostname_listed_in_allowed_hosts_constructs(self):
        """Positive control: an ordinary ASCII hostname that is also listed
        in ALLOWED_HOSTS constructs fine."""
        s = make_settings(
            **base_kwargs(
                public_base_url="https://archive.example.org",
                allowed_hosts=["archive.example.org"],
            )
        )
        assert s.public_base_url == "https://archive.example.org"


class TestShibbolethDoesNotRequireAHealthDetailToken:
    """HEALTH_DETAIL_TOKEN is only folded into the other-secrets reuse check
    when it is set; Shibboleth activation must not require one."""

    def test_shibboleth_enabled_with_no_health_token_constructs(self):
        s = make_settings(
            **base_kwargs(
                shibboleth_enabled=True,
                shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
                shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
                public_base_url="https://archive.example.org",
                allowed_hosts=["archive.example.org"],
                cookies_secure=True,
                health_detail_token=None,
            )
        )
        assert s.health_detail_token is None

    def test_shibboleth_enabled_with_a_distinct_health_token_constructs(self):
        """Positive control: a health token that is set (and not reused
        elsewhere) also constructs fine — the None case above is not merely
        an accident of every construction succeeding."""
        s = make_settings(
            **base_kwargs(
                shibboleth_enabled=True,
                shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
                shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
                public_base_url="https://archive.example.org",
                allowed_hosts=["archive.example.org"],
                cookies_secure=True,
                health_detail_token="distinct-health-token-0123456789abcdef",
            )
        )
        assert s.health_detail_token is not None
        assert s.health_detail_token.get_secret_value() == "distinct-health-token-0123456789abcdef"


class TestEnvStateCannotBeSmuggledViaDotenv:
    """``require_os_level_env_state_outside_dev`` reads ``ENV_STATE`` from
    the OS environment (not from the parsed value) so a non-dev value that
    only ever existed in the repo-root ``.env`` cannot exempt itself from a
    check that inspects the file the value came from.
    """

    def test_non_dev_state_from_a_dotenv_with_no_os_level_variable_is_rejected(
        self, tmp_path, monkeypatch
    ):
        env_file = tmp_path / ".env"
        env_file.write_text("ENV_STATE=production\n")
        monkeypatch.setattr(_settings_module, "_ENV_FILE", env_file)
        monkeypatch.delenv("ENV_STATE", raising=False)

        with pytest.raises(ValidationError, match="must be set as a real OS environment"):
            make_settings(**prod_kwargs())

    def test_non_dev_state_with_a_real_os_level_variable_constructs(self, tmp_path, monkeypatch):
        """Positive control: the same stray ``.env`` on disk is harmless once
        ENV_STATE is genuinely set at the OS level — the guard is about
        where the value came from, not whether a ``.env`` happens to exist."""
        env_file = tmp_path / ".env"
        env_file.write_text("ENV_STATE=production\n")
        monkeypatch.setattr(_settings_module, "_ENV_FILE", env_file)
        monkeypatch.setenv("ENV_STATE", "production")

        s = make_settings(**prod_kwargs())
        assert s.env_state == "production"


class TestWarnUnconsumedEnvKeysEnvironmentGate:
    """``warn_unconsumed_env_keys`` is a dev-only convenience: outside dev
    there is no ``.env`` (systemd loads real OS env files), so the function
    must return immediately without touching the filesystem.
    """

    def test_returns_immediately_when_not_in_dev(self, tmp_path, monkeypatch, caplog):
        env_file = tmp_path / ".env"
        env_file.write_text("SOME_UNKNOWN_KEY=1\n")
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
        monkeypatch.setattr(settings_singleton, "env_state", "production")

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        assert [r for r in caplog.records if r.name == "config.settings"] == []

    def test_processes_the_env_file_when_in_dev(self, tmp_path, monkeypatch, caplog):
        """Positive control: with env_state == 'dev' (the module's default in
        this suite), the same unknown key IS flagged — proving the early
        return above is what suppressed it, not a broken parser."""
        env_file = tmp_path / ".env"
        env_file.write_text("SOME_UNKNOWN_KEY=1\n")
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
        monkeypatch.setattr(settings_singleton, "env_state", "dev")

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        warned_keys = {r.args[0] for r in caplog.records if r.name == "config.settings"}
        assert warned_keys == {"SOME_UNKNOWN_KEY"}

    def test_a_list_valued_env_file_config_uses_its_first_entry(self, tmp_path, monkeypatch):
        """pydantic-settings accepts a sequence of candidate env files; the
        function must take the first entry rather than crash on the list."""
        env_file = tmp_path / ".env"
        env_file.write_text("SOME_UNKNOWN_KEY=1\n")
        monkeypatch.setitem(Settings.model_config, "env_file", [str(env_file)])
        monkeypatch.setattr(settings_singleton, "env_state", "dev")

        warn_unconsumed_env_keys()  # must not raise

    def test_returns_immediately_when_the_env_file_does_not_exist(
        self, tmp_path, monkeypatch, caplog
    ):
        missing = tmp_path / "does-not-exist.env"
        monkeypatch.setitem(Settings.model_config, "env_file", str(missing))
        monkeypatch.setattr(settings_singleton, "env_state", "dev")

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        assert [r for r in caplog.records if r.name == "config.settings"] == []

    def test_a_field_alias_is_accepted_as_a_known_key(self, tmp_path, monkeypatch, caplog):
        """A field declaring an explicit alias must be looked up by that
        alias too, not just by its Python attribute name uppercased."""
        env_file = tmp_path / ".env"
        env_file.write_text("LOG_LEVEL_ALIAS_PROBE=INFO\n")
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
        monkeypatch.setattr(settings_singleton, "env_state", "dev")
        monkeypatch.setattr(Settings.model_fields["log_level"], "alias", "LOG_LEVEL_ALIAS_PROBE")

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        assert [r for r in caplog.records if r.name == "config.settings"] == []
