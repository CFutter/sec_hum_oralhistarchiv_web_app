"""Fail-closed pins for the Settings validators that guard secret material.

Every test constructs ``Settings(_env_file=None, **kwargs)`` so no ``.env``
file leaks in. Real OS environment variables still apply to *unset* fields,
so the kwargs helpers below pass an explicit value for every field a test
asserts on.

Each validator here moved an invariant from caller discipline to the config
boundary, so a bad deployment fails loudly at construction instead of
silently at runtime. The tests therefore assert the boundary REJECTS the bad
input, not just that the happy path constructs.
"""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretStr, ValidationError

from tests.unit.settings_builders import (
    KWARGS_FOR_ENV,
    base_kwargs,
    make_settings,
    prod_kwargs,
    staging_kwargs,
)

SHIBBOLETH_TEST_SECRET = "uB8k4Pq7Nw2Yx6Ds9Fm3Ha5Jv1Rc8Tz4Lg7Ke2Qp9Ws6Bn3Xf5Mh8Cy1Vr4Zd7Aa"
TRUSTED_SHIBBOLETH_ISSUER = "https://idp.example.org/idp/shibboleth"


class TestCredentialAttemptBudgets:
    """session/TOTP-rotation step-up attempt budgets have bounded, sane defaults."""

    def test_credential_attempt_budget_defaults_are_bounded(self) -> None:
        """The credential-budget fields ship conservative, explicit defaults."""
        configured = make_settings(**base_kwargs())

        assert configured.session_step_up_attempt_limit == 5
        assert configured.totp_rotation_confirmation_attempt_limit == 5

    @pytest.mark.parametrize(
        ("field_name", "valid_value"),
        [
            ("session_step_up_attempt_limit", 1),
            ("session_step_up_attempt_limit", 100),
            ("totp_rotation_confirmation_attempt_limit", 1),
            ("totp_rotation_confirmation_attempt_limit", 100),
        ],
    )
    def test_credential_attempt_budget_accepts_documented_bounds(
        self,
        field_name: str,
        valid_value: int,
    ) -> None:
        configured = make_settings(**base_kwargs(**{field_name: valid_value}))

        assert getattr(configured, field_name) == valid_value

    @pytest.mark.parametrize(
        ("field_name", "invalid_value"),
        [
            ("session_step_up_attempt_limit", 0),
            ("session_step_up_attempt_limit", 101),
            ("totp_rotation_confirmation_attempt_limit", 0),
            ("totp_rotation_confirmation_attempt_limit", 101),
        ],
    )
    def test_credential_attempt_budget_rejects_out_of_range_values(
        self,
        field_name: str,
        invalid_value: int,
    ) -> None:
        """A typo cannot silently disable or overflow a credential budget."""
        with pytest.raises(ValidationError):
            make_settings(**base_kwargs(**{field_name: invalid_value}))


class TestSmtpAuthPairing:
    """SMTP user/password must be set together (symmetric XOR)."""

    def test_smtp_user_without_password_raises(self):
        """smtp_user set with smtp_password=None fails at construction.

        Guards the smtp_user-without-smtp_password AttributeError that was
        swallowed into a silent False on every email send.
        """
        with pytest.raises(ValidationError, match="must be set together"):
            make_settings(**base_kwargs(smtp_user="x", smtp_password=None))

    def test_smtp_password_without_user_raises(self):
        """The symmetric case — password set with empty user also fails, so
        the XOR gate cannot be half-satisfied from either side."""
        with pytest.raises(ValidationError, match="must be set together"):
            make_settings(**base_kwargs(smtp_user="", smtp_password=SecretStr("x")))

    def test_smtp_auth_pair_both_set_constructs(self):
        """Both credentials set is a valid (authenticated-relay) config."""
        s = make_settings(**base_kwargs(smtp_user="mailer", smtp_password=SecretStr("pw")))
        assert s.smtp_user == "mailer"
        assert s.smtp_password is not None
        assert s.smtp_password.get_secret_value() == "pw"

    def test_smtp_auth_pair_both_unset_constructs(self):
        """Both credentials unset is a valid (unauthenticated-relay) config."""
        s = make_settings(**base_kwargs(smtp_user="", smtp_password=None))
        assert s.smtp_user == ""
        assert s.smtp_password is None

    def test_smtp_required_in_staging(self):
        """Is_hardened (staging included) requires SMTP — send_email()
        fail-opens to True when disabled, so a staging deploy without SMTP would
        'send' every verification/reset/security notice while delivering nothing."""
        with pytest.raises(ValidationError, match="SMTP_ENABLED"):
            make_settings(**staging_kwargs(smtp_enabled=False))


class TestSmtpHardening:
    """SMTP must be genuinely configured, and encrypted, outside dev."""

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
    def test_smtp_placeholders_rejected_in_production(self, field, value, match):
        """Enabling SMTP in production while a field still holds its shipped
        placeholder value must fail — the operator enabled SMTP without
        configuring it."""
        with pytest.raises(ValidationError, match=match):
            make_settings(**prod_kwargs(**{field: value}))

    def test_smtp_real_values_accepted_in_production(self):
        """A production build with a real SMTP host and from-address must
        construct — without this, the placeholder rejections above could pass
        by rejecting production SMTP outright."""
        s = make_settings(**prod_kwargs())
        assert s.smtp_enabled is True
        assert s.smtp_host == "mail.example.org"
        assert s.smtp_from_address == "archive@example.org"

    def test_smtp_use_tls_false_rejected_in_staging(self):
        """SMTP_USE_TLS=false with SMTP enabled must fail in hardened envs —
        plaintext SMTP would expose password-reset tokens and relay
        credentials.

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


def _self_signed_ca_pem() -> bytes:
    """Minimal self-signed CA cert generated in-process (cryptography is a
    runtime dependency), so no binary fixture is checked in and the PEM is
    always parseable by the running OpenSSL build."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-test smtp ca")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestSmtpCaBundle:
    """SMTP_CA_BUNDLE must name a real, parseable PEM file, or be unset."""

    def test_smtp_ca_bundle_nonexistent_path_rejected(self, tmp_path):
        """Fail-open startup control — services/email.py loads this
        file unconditionally at import time, so a bad path must fail Settings
        construction on the friendly path, naming the env var and the path (not
        crash email.py's import with a raw traceback)."""
        missing = tmp_path / "does-not-exist.pem"
        with pytest.raises(ValidationError) as excinfo:
            make_settings(**base_kwargs(smtp_ca_bundle=str(missing)))
        message = str(excinfo.value)
        assert "SMTP_CA_BUNDLE" in message
        assert str(missing) in message

    def test_smtp_ca_bundle_unparseable_pem_rejected(self, tmp_path):
        """The validator must LOAD the file, not merely stat it — a
        present-but-garbage bundle passes any existence check and only detonates
        in email.py's import-time SSLContext, the exact deferred failure this
        boundary exists to prevent."""
        bundle = tmp_path / "garbage.pem"
        bundle.write_text("this is not a PEM certificate\n")
        with pytest.raises(ValidationError) as excinfo:
            make_settings(**base_kwargs(smtp_ca_bundle=str(bundle)))
        message = str(excinfo.value)
        assert "SMTP_CA_BUNDLE" in message
        assert str(bundle) in message

    def test_smtp_ca_bundle_empty_string_normalized_to_none(self):
        """Empty str '' normalizes to None so the config value's truthiness
        matches the consumer's `if settings.smtp_ca_bundle:` check — an
        un-normalized empty string would flip email.py onto the custom-bundle
        path with no bundle to load."""
        s = make_settings(**base_kwargs(smtp_ca_bundle=""))
        assert s.smtp_ca_bundle is None

    def test_smtp_ca_bundle_valid_pem_round_trips(self, tmp_path):
        """A real PEM CA bundle passes the boundary and round-trips unchanged,
        so the rejection tests above cannot pass by rejecting every bundle.

        (A permissions-based unreadable-file case is deliberately omitted:
        chmod 000 is a no-op when CI runs as root, so it is flaky by design.)
        """
        bundle = tmp_path / "ca.pem"
        bundle.write_bytes(_self_signed_ca_pem())
        s = make_settings(**base_kwargs(smtp_ca_bundle=str(bundle)))
        assert s.smtp_ca_bundle == str(bundle)


class TestRedisConfiguration:
    """Redis must be reachable whenever it is turned on."""

    def test_redis_enabled_requires_redis_url(self):
        """redis_enabled=True with an empty REDIS_URL must fail at construction
        instead of failing at first rate-limit/cache-invalidation call."""
        kwargs = base_kwargs(redis_enabled=True, redis_url=SecretStr(""))
        with pytest.raises(ValidationError, match="REDIS_URL must be set"):
            make_settings(**kwargs)


class TestShibbolethActivationBoundary:
    """Enabling the Shibboleth callback closes every relaxed default at once."""

    @pytest.mark.parametrize("env", ["dev", "staging", "production"])
    def test_shibboleth_enabled_requires_internal_secret(self, env):
        """SHIBBOLETH_ENABLED=true without the internal callback secret must fail
        in EVERY environment — without it the callback has only the single
        IP-based trust check."""
        kwargs = KWARGS_FOR_ENV[env](
            shibboleth_enabled=True,
            shibboleth_internal_secret=None,
            shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
        )
        with pytest.raises(ValidationError, match="SHIBBOLETH_INTERNAL_SECRET must be set"):
            make_settings(**kwargs)

    @pytest.mark.parametrize("empty_value", ["", SecretStr("")])
    def test_empty_shibboleth_secret_is_unset_when_federation_is_disabled(self, empty_value):
        """The documented empty value must not provision a credential."""
        configured = make_settings(
            **base_kwargs(shibboleth_internal_secret=empty_value),
        )

        assert configured.shibboleth_internal_secret is None

    @pytest.mark.parametrize("env", ["dev", "staging", "production"])
    @pytest.mark.parametrize(
        "weak_secret",
        [
            "INSECURE-SHIB-DEV-SECRET-CHANGE-IN-PRODUCTION",
            "too-short",
            "a" * 64,
            SHIBBOLETH_TEST_SECRET * 17,
            f"{SHIBBOLETH_TEST_SECRET}\n",
            f" {SHIBBOLETH_TEST_SECRET}",
            "ä" + SHIBBOLETH_TEST_SECRET,
        ],
        ids=[
            "shipped-default",
            "too-short",
            "low-diversity",
            "oversized",
            "control",
            "whitespace",
            "non-token-url-safe",
        ],
    )
    def test_enabled_shibboleth_rejects_weak_callback_secret_in_every_environment(
        self, env, weak_secret
    ):
        kwargs = KWARGS_FOR_ENV[env](
            shibboleth_enabled=True,
            shibboleth_internal_secret=weak_secret,
            shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
        )

        with pytest.raises(ValidationError, match="SHIBBOLETH_INTERNAL_SECRET"):
            make_settings(**kwargs)

    @pytest.mark.parametrize("env", ["dev", "staging", "production"])
    def test_enabled_shibboleth_requires_an_exact_issuer_allowlist(self, env):
        kwargs = KWARGS_FOR_ENV[env](
            shibboleth_enabled=True,
            shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
            shibboleth_trusted_issuers=[],
        )

        with pytest.raises(ValidationError, match="SHIBBOLETH_TRUSTED_ISSUERS"):
            make_settings(**kwargs)

    @pytest.mark.parametrize(
        "issuer",
        [
            "",
            "http://idp.example.org/idp/shibboleth",
            "idp.example.org",
            "https://user:password@idp.example.org/idp/shibboleth",
            " https://idp.example.org/idp/shibboleth ",
            "https://idp.example.org/idp/shibboleth\nforged",
            "https://local host/idp/shibboleth",
            "https://exa|mple.org/idp/shibboleth",
            "https://idp.example.org\\forged",
            "https://*/idp/shibboleth",
            "https://idp.example.org/*",
            "https://idp.example.org/idp,forged",
            "https://idp.example.org/" + ("x" * 2049),
        ],
        ids=[
            "blank",
            "http",
            "relative",
            "userinfo",
            "surrounding-whitespace",
            "control",
            "authority-whitespace",
            "invalid-authority-character",
            "backslash",
            "wildcard-host",
            "wildcard-path",
            "comma",
            "oversized",
        ],
    )
    def test_shibboleth_issuer_allowlist_rejects_unsafe_values(self, issuer):
        with pytest.raises(ValidationError, match="SHIBBOLETH_TRUSTED_ISSUERS"):
            make_settings(**base_kwargs(shibboleth_trusted_issuers=[issuer]))

    def test_shibboleth_issuer_allowlist_rejects_exact_duplicates(self):
        with pytest.raises(ValidationError, match="duplicate"):
            make_settings(
                **base_kwargs(
                    shibboleth_trusted_issuers=[
                        TRUSTED_SHIBBOLETH_ISSUER,
                        TRUSTED_SHIBBOLETH_ISSUER,
                    ]
                )
            )

    @pytest.mark.parametrize("env", ["dev", "staging", "production"])
    def test_enabled_shibboleth_accepts_strong_independent_secret_and_exact_issuer(self, env):
        transport = {"public_base_url": "https://archive.example.org"} if env == "dev" else {}
        configured = make_settings(
            **KWARGS_FOR_ENV[env](
                shibboleth_enabled=True,
                shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
                shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
                **transport,
            )
        )

        assert configured.shibboleth_internal_secret is not None
        assert configured.shibboleth_internal_secret.get_secret_value() == SHIBBOLETH_TEST_SECRET
        assert configured.shibboleth_trusted_issuers == [TRUSTED_SHIBBOLETH_ISSUER]

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"public_base_url": "http://archive.example.org"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://localhost:8443"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://LOCALHOST."}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://localhost.:8443"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://foo.localhost."}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://ⓛocalhost"}, "HTTPS PUBLIC_BASE_URL"),
            (
                {
                    "public_base_url": "https://\uff11\uff12\uff17\u3002\uff10\u3002\uff10\u3002\uff11"
                },
                "HTTPS PUBLIC_BASE_URL",
            ),
            ({"public_base_url": "https://2130706433"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://127.1"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://0177.0.0.1"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://0x7f000001"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://%31%32%37.0.0.1"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://%6cocalhost"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://127%2e0%2e0%2e1"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://localhost\x01"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://127.0.0.1\x01"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://localhost\x00"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://[::ffff:127.0.0.1]"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://[::ffff:7f00:1]"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://[0:0:0:0:0:0:0:1]"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://0.0.0.0"}, "HTTPS PUBLIC_BASE_URL"),
            ({"public_base_url": "https://[::]"}, "HTTPS PUBLIC_BASE_URL"),
            ({"cookies_secure": False}, "COOKIES_SECURE"),
            ({"allowed_hosts": ["*"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": ["*.example.org"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": [""]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": [" archive.example.org"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": ["["]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": ["[2001"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            (
                {"allowed_hosts": ["archive.example.org:443"]},
                "non-empty, non-wildcard ALLOWED_HOSTS",
            ),
            ({"allowed_hosts": ["Archive.example.org"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": ["localhost"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": ["127.0.0.1"]}, "non-empty, non-wildcard ALLOWED_HOSTS"),
            ({"allowed_hosts": []}, "non-empty, non-wildcard ALLOWED_HOSTS"),
        ],
        ids=[
            "plaintext",
            "loopback",
            "uppercase-trailing-dot-localhost",
            "trailing-dot-localhost",
            "localhost-subdomain",
            "idna-localhost",
            "idna-numeric-loopback",
            "integer-loopback",
            "short-loopback",
            "octal-loopback",
            "hex-loopback",
            "percent-encoded-loopback",
            "percent-encoded-localhost",
            "percent-encoded-dots",
            "localhost-with-c0-control",
            "loopback-with-c0-control",
            "localhost-with-nul",
            "mapped-ipv6-loopback",
            "mapped-ipv6-loopback-hex",
            "expanded-ipv6-loopback",
            "unspecified-ipv4",
            "unspecified-ipv6",
            "insecure-cookie",
            "universal-wildcard-host",
            "subdomain-wildcard-host",
            "blank-host",
            "whitespace-host",
            "open-bracket-host",
            "ipv6-prefix-host",
            "host-with-port",
            "mixed-case-host",
            "localhost-host",
            "loopback-ipv4-host",
            "empty-hosts",
        ],
    )
    @pytest.mark.filterwarnings("ignore:ALLOWED_HOSTS WARNING:RuntimeWarning")
    def test_enabled_shibboleth_requires_hardened_transport_even_in_dev(self, overrides, message):
        """Enabling federation closes the relaxed dev transport defaults.

        Staging and production are already pinned by their general hardened-host,
        HTTPS-origin, and secure-cookie validator tests; this test proves that the
        same boundary becomes mandatory in otherwise permissive development/demo
        settings as soon as the Shibboleth callback is enabled.
        """
        kwargs = base_kwargs(
            shibboleth_enabled=True,
            shibboleth_internal_secret=SHIBBOLETH_TEST_SECRET,
            shibboleth_trusted_issuers=[TRUSTED_SHIBBOLETH_ISSUER],
            public_base_url="https://archive.example.org",
            cookies_secure=True,
            allowed_hosts=["archive.example.org"],
        )
        kwargs.update(overrides)

        with pytest.raises(ValidationError, match=message):
            make_settings(**kwargs)

    @pytest.mark.parametrize(
        "reused_field",
        [
            "secret_key",
            "session_secret",
            "health_detail_token",
            "totp_encryption_keys",
            "outbox_encryption_keys",
        ],
    )
    def test_shibboleth_callback_secret_cannot_reuse_another_security_secret(self, reused_field):
        overrides = {
            "shibboleth_enabled": True,
            "shibboleth_internal_secret": SHIBBOLETH_TEST_SECRET,
            "shibboleth_trusted_issuers": [TRUSTED_SHIBBOLETH_ISSUER],
            reused_field: (
                [SHIBBOLETH_TEST_SECRET]
                if reused_field.endswith("_encryption_keys")
                else SHIBBOLETH_TEST_SECRET
            ),
        }

        with pytest.raises(ValidationError, match="must not reuse"):
            make_settings(**base_kwargs(**overrides))


_LIMITER_REUSE_PROBE = "SharedLimiterProbePassword-0123456789abcdef"


def _redis_url_with_password(password: str) -> str:
    return f"redis://:{password}@limiter.internal.example.org:6379/0"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"secret_key": _LIMITER_REUSE_PROBE}, id="secret_key"),
        pytest.param({"session_secret": _LIMITER_REUSE_PROBE}, id="session_secret"),
        pytest.param({"totp_encryption_keys": [_LIMITER_REUSE_PROBE]}, id="totp_encryption_key"),
        pytest.param(
            {"outbox_encryption_keys": [_LIMITER_REUSE_PROBE]}, id="outbox_encryption_key"
        ),
        pytest.param(
            {"database_url": f"postgresql://oha:{_LIMITER_REUSE_PROBE}@localhost:5432/oha_test"},
            id="database_password",
        ),
        pytest.param(
            {
                "redis_enabled": True,
                "redis_url": _redis_url_with_password(_LIMITER_REUSE_PROBE),
            },
            id="general_redis_password",
        ),
    ],
)
class TestRateLimitRedisUrlCredentialIsolation:
    """The dedicated rate-limit Redis credential is an independent secret:
    reusing another configured secret's value as its password would mean
    exposing the limiter store (a lower-value target) also exposes a
    signing, encryption, database, or general-cache credential."""

    def test_rejects_a_limiter_password_that_reuses_another_configured_secret(self, overrides):
        kwargs = base_kwargs(**overrides)
        kwargs["rate_limit_redis_url"] = _redis_url_with_password(_LIMITER_REUSE_PROBE)

        with pytest.raises(ValidationError, match="must not reuse"):
            make_settings(**kwargs)

    def test_a_distinct_limiter_password_constructs(self, overrides):
        distinct = _redis_url_with_password("Distinct-Limiter-Only-Password-42")
        kwargs = base_kwargs(**overrides)
        kwargs["rate_limit_redis_url"] = distinct

        configured = make_settings(**kwargs)

        assert configured.rate_limit_redis_url.get_secret_value() == distinct


class TestSeedMockData:
    """SEED_MOCK_DATA is a demo-environment toggle, never a production one."""

    def test_seed_mock_data_rejected_in_production(self):
        """Fail-open deploy toggle — mock rows in the production
        archive would surface fake datasets to real researchers, so the boundary
        must refuse to start rather than trust deploy discipline."""
        with pytest.raises(ValidationError, match="SEED_MOCK_DATA=true is not permitted"):
            make_settings(**prod_kwargs(seed_mock_data=True))

    @pytest.mark.parametrize("env", ["dev", "staging"])
    def test_seed_mock_data_allowed_outside_production(self, env):
        """Dev AND staging construct with the flag on. Staging-allowed is
        deliberate product behavior (demo/presentation environments seed on
        purpose): the validator gates on is_production, so a sweep that flips
        it to is_hardened must fail here."""
        s = make_settings(**KWARGS_FOR_ENV[env](seed_mock_data=True))
        assert s.seed_mock_data is True


class TestSettingsRepr:
    """repr()/str() of Settings must never leak the database credential."""

    def test_repr_hides_database_password(self):
        """The custom __repr__ replaces the DSN with '***' so tracebacks and
        log lines cannot leak credentials."""
        password = "db-secret-pw"
        s = make_settings(
            **base_kwargs(database_url=f"postgresql://oha:{password}@localhost:5432/oha_test")
        )
        assert password not in repr(s)
        assert password not in str(s)
        assert "database_url=***" in repr(s)


class TestOutboxEncryptionKeys:
    """OUTBOX_ENCRYPTION_KEYS is mandatory, non-empty key material."""

    def test_outbox_encryption_keys_are_required(self, monkeypatch):
        monkeypatch.delenv("OUTBOX_ENCRYPTION_KEYS", raising=False)
        monkeypatch.delenv("outbox_encryption_keys", raising=False)
        kwargs = base_kwargs()
        kwargs.pop("outbox_encryption_keys")

        with pytest.raises(ValidationError) as excinfo:
            make_settings(**kwargs)

        assert any(
            error["loc"] == ("outbox_encryption_keys",) and error["type"] == "missing"
            for error in excinfo.value.errors()
        )

    def test_outbox_encryption_keys_cannot_be_empty(self):
        with pytest.raises(ValidationError) as excinfo:
            make_settings(**base_kwargs(outbox_encryption_keys=[]))

        assert any(
            error["loc"] == ("outbox_encryption_keys",) and error["type"] == "too_short"
            for error in excinfo.value.errors()
        )
