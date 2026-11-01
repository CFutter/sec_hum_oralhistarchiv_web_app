"""Contract tests for settings boundary conditions."""

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
    """ALLOWED_HOSTS entries must be hosts Starlette can compare unambiguously."""

    @pytest.mark.parametrize(
        "host",
        ["archive%2eexample.org", "exa%mple.com"],
        ids=["percent-in-place-of-a-dot", "percent-mid-label"],
    )
    def test_allowed_hosts_rejects_a_host_containing_a_percent_character(self, host):
        """Check allowed hosts rejects a host containing a percent character (ValidationError)."""
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS must contain"):
            make_settings(**base_kwargs(allowed_hosts=[host]))

    def test_allowed_hosts_rejects_a_host_with_an_empty_dns_label(self):
        """Check allowed hosts rejects a host with an empty dns label (ValidationError)."""
        with pytest.raises(ValidationError, match="ALLOWED_HOSTS must contain"):
            make_settings(**base_kwargs(allowed_hosts=["example..com"]))

    def test_allowed_hosts_accepts_a_syntactically_valid_host(self):
        """Check allowed hosts accepts a syntactically valid host."""
        s = make_settings(**base_kwargs(allowed_hosts=["archive.example.org", "localhost"]))
        assert s.allowed_hosts == ["archive.example.org", "localhost"]


class TestAllowedHostsRejectsNonAsciiNames:
    """Cover allowed hosts rejects non ascii names."""

    def test_allowed_hosts_rejects_a_non_ascii_host(self):
        """A raw Unicode host must be rejected — operators must supply the
        punycode form so string comparison against the Host header is exact."""
        with pytest.raises(ValidationError, match="ASCII/punycode DNS names"):
            make_settings(**base_kwargs(allowed_hosts=["archïve.example.org"]))

    def test_allowed_hosts_accepts_the_punycode_form_of_the_same_host(self):
        """Check allowed hosts accepts the punycode form of the same host."""
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
        """Check database URL rejects an integer (ValidationError)."""
        with pytest.raises(
            ValidationError, match="DATABASE_URL must be a PostgreSQL connection string"
        ):
            make_settings(**base_kwargs(database_url=12345))

    def test_database_url_accepts_a_well_formed_string(self):
        """Check database URL accepts a well formed string."""
        s = make_settings(**base_kwargs(database_url="postgresql://oha:pw@localhost:5432/oha_test"))
        assert s.database_url.get_secret_value() == "postgresql://oha:pw@localhost:5432/oha_test"


class TestLegacyBootstrapSettings:
    """Cover legacy bootstrap settings."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"admin_seed_email": "admin@example.org"},
            {"admin_seed_password": "AdminSeedPassw0rd!"},
            {"admin_seed_email": "admin@example.org", "admin_seed_password": "AdminSeedPassw0rd!"},
        ],
    )
    def test_runtime_rejects_bootstrap_material(self, overrides):
        """Check runtime rejects bootstrap material (ValidationError)."""
        with pytest.raises(ValidationError, match="no longer service settings"):
            make_settings(**base_kwargs(**overrides))


class TestSmtpFromAddressValidation:
    """Cover SMTP from address validation."""

    def test_smtp_from_address_rejects_an_unparseable_address(self):
        """Check SMTP from address rejects an unparseable address (ValidationError)."""
        with pytest.raises(ValidationError, match="SMTP_FROM_ADDRESS must be a supported"):
            make_settings(**base_kwargs(smtp_from_address="not-an-email-address"))

    def test_smtp_from_address_accepts_and_normalizes_a_real_address(self):
        """Check SMTP from address accepts and normalizes a real address."""
        s = make_settings(**base_kwargs(smtp_from_address="Archive@Example.ORG"))
        assert s.smtp_from_address == "archive@example.org"


class TestSmtpFromNameValidation:
    """Cover SMTP from name validation."""

    @pytest.mark.parametrize(
        "value",
        ["", "bad\x00name"],
        ids=["empty_string", "contains_a_control_character"],
    )
    def test_smtp_from_name_rejects_unprintable_or_empty_values(self, value):
        """Check SMTP from name rejects unprintable or empty values (ValidationError)."""
        with pytest.raises(ValidationError, match="SMTP_FROM_NAME must contain printable"):
            make_settings(**base_kwargs(smtp_from_name=value))

    def test_smtp_from_name_accepts_a_printable_display_name(self):
        """Check SMTP from name accepts a printable display name."""
        s = make_settings(**base_kwargs(smtp_from_name="Oral History Archive"))
        assert s.smtp_from_name == "Oral History Archive"


class TestSmtpHostRequiredWhenSmtpEnabled:
    """Cover SMTP host required when SMTP enabled."""

    def test_smtp_enabled_with_blank_host_is_rejected(self):
        """Check SMTP enabled with blank host is rejected (ValidationError)."""
        with pytest.raises(ValidationError, match="smtp_enabled=True requires smtp_host"):
            make_settings(
                **base_kwargs(
                    smtp_enabled=True,
                    smtp_host="",
                    smtp_from_address="archive@example.org",
                )
            )

    def test_smtp_enabled_with_a_real_host_constructs(self):
        """Check SMTP enabled with a real host constructs."""
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
        """Check hardened environment without a health token is rejected (ValidationError)."""
        with pytest.raises(ValidationError, match="HEALTH_DETAIL_TOKEN must be set"):
            make_settings(**staging_kwargs(health_detail_token=None))

    def test_hardened_environment_with_a_health_token_constructs(self):
        """Check hardened environment with a health token constructs."""
        s = make_settings(
            **staging_kwargs(health_detail_token="staging-health-token-0123456789abcdef")
        )
        assert s.health_detail_token is not None
        assert s.health_detail_token.get_secret_value() == "staging-health-token-0123456789abcdef"


class TestRedisDisabledInProductionWarns:
    """Disabling general Redis warns about catalogue-statistics freshness.

    Dedicated rate-limit Redis is enforced separately by web startup.
    """

    def test_production_without_redis_warns(self):
        """Check production without Redis warns."""
        with pytest.warns(RuntimeWarning, match="General Redis is disabled in production"):
            s = make_settings(**prod_kwargs(redis_enabled=False))
        assert s.redis_enabled is False

    def test_production_with_redis_enabled_does_not_warn(self, recwarn):
        """Enabling general Redis suppresses the cache-invalidation warning."""
        make_settings(**prod_kwargs(redis_enabled=True))
        assert not any(
            "General Redis is disabled in production" in str(w.message) for w in recwarn.list
        )


class TestCorsRequiresOriginsWhenEnabled:
    """Cover cors requires origins when enabled."""

    def test_cors_enabled_with_no_origins_warns_in_dev(self):
        """Check cors enabled with no origins warns in dev."""
        with pytest.warns(RuntimeWarning, match="no origins are configured"):
            s = make_settings(**base_kwargs(cors_enabled=True, cors_origins=[]))
        assert s.cors_origins == []

    def test_cors_enabled_with_no_origins_blocks_startup_in_staging(self):
        """Check cors enabled with no origins blocks startup in staging (ValidationError)."""
        with pytest.raises(ValidationError, match="no origins are configured"):
            make_settings(**staging_kwargs(cors_enabled=True, cors_origins=[]))

    def test_cors_enabled_with_real_origins_constructs_with_no_warning(self, recwarn):
        """Check cors enabled with real origins constructs with no warning."""
        s = make_settings(
            **base_kwargs(cors_enabled=True, cors_origins=["https://good.example.org"])
        )
        assert s.cors_origins == ["https://good.example.org"]
        assert not any("CORS WARNING" in str(w.message) for w in recwarn.list)


class TestPublicHttpsOriginErrorHelper:
    """``_public_https_origin_error`` backs the Shibboleth transport gate."""

    def test_rejects_a_value_with_a_path_query_or_fragment(self):
        """Check rejects a value with a path query or fragment."""
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
        """Check accepts a bare public https origin."""
        assert _public_https_origin_error("https://archive.example.org") is None


class TestShibbolethAcceptsAPublicIpv4LiteralOrigin:
    """Cover Shibboleth accepts apublic ipv4 literal origin."""

    def test_ipv4_literal_public_base_url_with_mixed_allowed_hosts_constructs(self):
        """Check ipv4 literal public base URL with mixed allowed hosts constructs."""
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
    """Cover public base URL hostname must be ascii and listed in allowed hosts."""

    def test_a_raw_unicode_hostname_is_rejected(self):
        """Check a raw unicode hostname is rejected (ValidationError)."""
        with pytest.raises(ValidationError, match="ASCII/punycode hostname"):
            make_settings(**base_kwargs(public_base_url="https://müller.example.org"))

    def test_an_ascii_hostname_listed_in_allowed_hosts_constructs(self):
        """Check an ascii hostname listed in allowed hosts constructs."""
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
        """Check Shibboleth enabled with no health token constructs."""
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
        """Check Shibboleth enabled with a distinct health token constructs."""
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
    """Cover env state cannot be smuggled via dotenv."""

    def test_non_dev_state_from_a_dotenv_with_no_os_level_variable_is_rejected(
        self, tmp_path, monkeypatch
    ):
        """Check non dev state from a dotenv with no os level variable is rejected (ValueError)."""
        env_file = tmp_path / ".env"
        env_file.write_text("ENV_STATE=production\n")
        monkeypatch.setattr(_settings_module, "_ENV_FILE", env_file)
        monkeypatch.delenv("ENV_STATE", raising=False)

        with pytest.raises(ValueError, match="uppercase ENV_STATE"):
            make_settings(**prod_kwargs())

    def test_non_dev_state_with_a_real_os_level_variable_constructs(self, tmp_path, monkeypatch):
        """Check non dev state with a real os level variable constructs."""
        env_file = tmp_path / ".env"
        env_file.write_text("ENV_STATE=production\n")
        monkeypatch.setattr(_settings_module, "_ENV_FILE", env_file)
        monkeypatch.setenv("ENV_STATE", "production")

        s = make_settings(**prod_kwargs())
        assert s.env_state == "production"


class TestWarnUnconsumedEnvKeysEnvironmentGate:
    """Cover warn unconsumed env keys environment gate."""

    def test_returns_immediately_when_not_in_dev(self, tmp_path, monkeypatch, caplog):
        """Check returns immediately when not in dev."""
        env_file = tmp_path / ".env"
        env_file.write_text("SOME_UNKNOWN_KEY=1\n")
        monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))
        monkeypatch.setattr(settings_singleton, "env_state", "production")

        with caplog.at_level(logging.WARNING, logger="config.settings"):
            warn_unconsumed_env_keys()

        assert [r for r in caplog.records if r.name == "config.settings"] == []

    def test_processes_the_env_file_when_in_dev(self, tmp_path, monkeypatch, caplog):
        """Check processes the env file when in dev."""
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

        warn_unconsumed_env_keys()

    def test_returns_immediately_when_the_env_file_does_not_exist(
        self, tmp_path, monkeypatch, caplog
    ):
        """Check returns immediately when the env file does not exist."""
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
