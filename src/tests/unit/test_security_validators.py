"""Startup security validation is fail-closed (app.middleware.validators).

Pins the three layers of the boot-time security gate:

- ``_check_secret_strength`` — the necessary-conditions filter (length,
  blocklist, character diversity, Shannon entropy) that rejects values too
  weak to have come from ``secrets.token_urlsafe(64)``.
- ``validate_security_settings`` — the aggregator: raises ONCE with every
  blocker listed when ``is_hardened`` (staging/production), and downgrades
  blockers to "would block in production" warnings in dev so local work
  is not bricked.
- ``_check_cors_setting`` — credentialed CORS must use concrete https,
  non-localhost origins.

These guards are fail-closed startup checks: each must actually reject the
bad state, not merely appear to, and RATE_LIMIT_TRUST_PROXY is mandatory in
production. All settings mutation goes through ``monkeypatch.setattr`` on
the real settings object, which restores automatically after each test.

The key literals below are frozen ``secrets.token_urlsafe`` output (screened
against the blocklist) so the tests are deterministic.
"""

import logging
import secrets as _secrets

import pytest
from pydantic import SecretStr

from app.middleware.validators import (
    _check_cors_setting,
    validate_security_settings,
)
from app.paths import PROJECT_ROOT
from config import settings
from config.secret_strength import check_secret_strength as _check_secret_strength

# Frozen CSPRNG output (secrets.token_urlsafe, blocklist-screened).
RANDOM_20 = "lEwbW7ljfXh9XvjQs7Jk"
RANDOM_50 = "v9jVy0fjtsDwqZHTqpq4t57HR4Fkfsy9KByq7596_QJDn_1ruj"
RANDOM_90 = (
    "D4kVYBi7-oPIvePUg7bM3j7MXIPYGB0F6DbQRfZmWXKzMPpvakumLXHwze6HqaJAfL_BG1hsuQ-XGAv7y5vIlIpJn4"
)
# token_urlsafe(64) produces 86 chars — the documented "generate" hint output.
STRONG_86 = "MIJMMBoMnEmiptnTZeR9ZQN0MhwogmNZlsFzh4yrNmySYREs7SwrmSUgt2svef0jiFeW7J9ipcXCND1Cont6oL"
SHIB_STRONG = "uB8k4Pq7Nw2Yx6Ds9Fm3Ha5Jv1Rc8Tz4Lg7Ke2Qp9Ws6Bn3Xf5Mh8Cy1Vr4Zd7Aa"
SHIB_ISSUER = "https://idp.example.org/idp/shibboleth"


def _patch_strong_secrets(monkeypatch):
    """Give every checked secret a zero-blocker, zero-warning value.

    Used by tests that need exactly one specific blocker to fire so the raised
    message can be pinned to that blocker alone.
    """
    monkeypatch.setattr(settings, "secret_key", SecretStr(STRONG_86))
    monkeypatch.setattr(settings, "session_secret", SecretStr(RANDOM_90))
    monkeypatch.setattr(settings, "health_detail_token", SecretStr(STRONG_86))
    monkeypatch.setattr(settings, "shibboleth_internal_secret", None)
    monkeypatch.setattr(settings, "totp_encryption_keys", [SecretStr(RANDOM_90)])
    monkeypatch.setattr(settings, "outbox_encryption_keys", [SecretStr(STRONG_86)])


def _enable_valid_federation(monkeypatch):
    """Install a complete dev federation boundary before mutating one field."""
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr(SHIB_STRONG))
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [SHIB_ISSUER])
    monkeypatch.setattr(settings, "public_base_url", "https://archive.example.org")
    monkeypatch.setattr(settings, "cookies_secure", True)
    monkeypatch.setattr(settings, "allowed_hosts", ["archive.example.org"])


# ---------------------------------------------------------------------------
# _check_secret_strength — necessary conditions for a CSPRNG-grade secret
# ---------------------------------------------------------------------------


def test_secret_under_43_chars_is_a_blocker():
    """A 20-char value cannot hold 256 bits of randomness -> hard reject.

    Guards the _SECRET_MIN_CHARS floor: shortening a key below token_urlsafe(32)
    output must be a blocker, not a warning.
    """
    blockers, warns = _check_secret_strength(RANDOM_20)
    assert len(blockers) == 1
    assert "too short" in blockers[0]
    assert warns == []


def test_secret_of_50_random_chars_warns_but_does_not_block():
    """50 random chars: above the 43-char floor, below the 84-char
    recommendation -> exactly one warning, no blockers.

    Guards the two-tier length policy (acceptable-but-not-ideal must not brick
    startup).
    """
    blockers, warns = _check_secret_strength(RANDOM_50)
    assert blockers == []
    assert len(warns) == 1
    assert "recommended" in warns[0]


def test_secret_of_90_random_chars_is_clean():
    """90 random chars clear every check: no blockers, no warnings."""
    blockers, warns = _check_secret_strength(RANDOM_90)
    assert blockers == []
    assert warns == []


def test_secret_containing_blocklisted_word_is_a_blocker():
    """'password' embedded anywhere in an otherwise-strong key -> blocker.

    Guards the substring blocklist (`any(w in lowered ...)`) — a long random
    key with a human-chosen word spliced in must still be rejected.
    """
    key_with_word = RANDOM_90[:41] + "password" + RANDOM_90[49:]
    assert len(key_with_word) == 90  # length/entropy checks stay satisfied
    blockers, _warns = _check_secret_strength(key_with_word)
    assert len(blockers) == 1
    assert "blocklisted word" in blockers[0]


def test_repeated_pattern_blocked_for_unique_chars_and_entropy():
    """'ab'*22 (44 chars, so past the length floor) trips BOTH pattern checks:
    too few unique characters AND Shannon entropy below 3.5 bits/char.

    Guards against 'pad a short key by repeating it' passing the length check.
    """
    blockers, _warns = _check_secret_strength("ab" * 22)
    assert len(blockers) == 2
    assert any("unique characters" in b for b in blockers)
    assert any("low-diversity pattern" in b for b in blockers)


def test_token_urlsafe_64_style_secret_yields_no_blockers_and_no_warnings():
    """The documented generation recipe (token_urlsafe(64), 86 chars) yields
    zero blockers and zero warnings — the recommended path is fully quiet."""
    blockers, warns = _check_secret_strength(STRONG_86)
    assert blockers == []
    assert warns == []


# ---------------------------------------------------------------------------
# validate_security_settings — aggregate, then fail closed when hardened
# ---------------------------------------------------------------------------


def test_staging_weak_secret_key_raises_with_name_and_generate_hint(monkeypatch):
    """staging (is_hardened) + weak SECRET_KEY -> RuntimeError naming the
    offending setting and including the token_urlsafe(64) generation hint.

    The fail-closed assertion: a hardened environment must NOT boot on a weak
    core secret — the guard actually rejects the bad state.
    """
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "secret_key", SecretStr("short"))

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    msg = str(excinfo.value)
    assert "SECRET_KEY" in msg
    assert "secrets.token_urlsafe(64)" in msg


def test_dev_weak_secret_key_warns_instead_of_raising(monkeypatch, caplog):
    """dev + the same weak SECRET_KEY -> NO raise; each blocker is logged as a
    'would block in production' warning instead.

    Guards the dev downgrade path: local development stays bootable while the
    operator still sees exactly what production would reject.
    """
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "secret_key", SecretStr("short"))

    with caplog.at_level(logging.WARNING, logger="app.middleware.validators"):
        validate_security_settings()  # must not raise

    would_block = [r for r in caplog.records if "would block in production" in r.getMessage()]
    assert would_block, "expected the dev downgrade warning to be logged"
    assert any("SECRET_KEY" in r.getMessage() for r in would_block)


def test_unset_health_detail_token_is_not_flagged(monkeypatch):
    """health_detail_token=None (legitimately unset in dev) -> the name never
    appears in the failure list, even when other secrets force a raise.

    Guards the optional-secret contract: unset optional secrets are skipped,
    not treated as weak empty strings.
    """
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "health_detail_token", None)
    # A weak core secret forces the aggregate RuntimeError so we can inspect
    # the full blocker list.
    monkeypatch.setattr(settings, "secret_key", SecretStr("short"))

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    assert "HEALTH_DETAIL_TOKEN" not in str(excinfo.value)


def test_weak_health_detail_token_is_flagged_when_set(monkeypatch):
    """health_detail_token, once SET, must be as strong as the core secrets:
    a weak value is a named blocker in staging.

    Guards the 'included only when configured — but then fully checked'
    contract for optional secrets (it gates internal diagnostics).
    """
    _patch_strong_secrets(monkeypatch)  # only the health token is weak
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "health_detail_token", SecretStr("weak"))

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    assert "HEALTH_DETAIL_TOKEN" in str(excinfo.value)


def test_weak_totp_key_is_flagged_with_its_index(monkeypatch):
    """EVERY entry of totp_encryption_keys is checked: [strong, weak] raises in
    staging naming TOTP_ENCRYPTION_KEYS[1] (and not the strong [0]).

    Guards key rotation: a weak *old* decrypt key added for rotation must be
    rejected the same as the primary encrypt key.
    """
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(
        settings,
        "totp_encryption_keys",
        [SecretStr(STRONG_86), SecretStr("weak")],
    )

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    msg = str(excinfo.value)
    assert "TOTP_ENCRYPTION_KEYS[1]" in msg
    assert "TOTP_ENCRYPTION_KEYS[0]" not in msg


def test_http_swissubase_url_blocks_startup_in_staging(monkeypatch):
    """A plaintext-HTTP OAI-PMH URL is a blocker wherever the app is hardened:
    staging startup raises naming SWISSUBASE_OAI_PMH_URL.

    Guards against metadata sync over an interceptable/tamperable channel.
    """
    _patch_strong_secrets(monkeypatch)  # isolate the URL blocker
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "swissubase_oai_pmh_url", "http://demo.swissubase.ch/oai")

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    assert "SWISSUBASE_OAI_PMH_URL" in str(excinfo.value)


def test_http_swissubase_url_is_warning_only_in_dev(monkeypatch, caplog):
    """The same http:// URL in dev -> no raise; logged as a SECURITY
    RECOMMENDATION warning instead (the msg goes to all_warnings, not
    all_blockers, when not hardened)."""
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "swissubase_oai_pmh_url", "http://demo.swissubase.ch/oai")

    with caplog.at_level(logging.WARNING, logger="app.middleware.validators"):
        validate_security_settings()  # must not raise

    assert any(
        "SECURITY RECOMMENDATION" in r.getMessage() and "SWISSUBASE_OAI_PMH_URL" in r.getMessage()
        for r in caplog.records
    )


def test_production_rate_limiting_without_proxy_trust_raises(monkeypatch):
    """production + rate_limit_enabled + rate_limit_trust_proxy=False ->
    RuntimeError naming RATE_LIMIT_TRUST_PROXY: the setting is mandatory in
    production because without it per-IP limiting is a no-op behind nginx —
    every request would share the proxy's IP.

    All secrets are patched strong so this is provably the ONLY blocker.
    """
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "production")
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", False)

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    msg = str(excinfo.value)
    assert "RATE_LIMIT_TRUST_PROXY" in msg
    # Exactly one blocker fired — proving the strong secrets, default https
    # URL, and credential-less CORS contributed nothing.
    assert "1 issue(s)" in msg


# ---------------------------------------------------------------------------
# _check_cors_setting — credentialed CORS requires concrete https origins
# ---------------------------------------------------------------------------


def test_cors_without_credentials_is_never_a_blocker(monkeypatch):
    """credentials off -> [] even with a wildcard origin list (browsers refuse
    credentialed '*' anyway; without credentials there is nothing to steal).

    Guards the early return: the check only polices the credentialed mode.
    """
    monkeypatch.setattr(settings, "cors_allow_credentials", False)
    monkeypatch.setattr(settings, "cors_origins", ["*"])
    assert _check_cors_setting() == []


def test_cors_credentials_with_wildcard_origin_is_blocked(monkeypatch):
    """credentials + '*' -> blocker (Starlette reflects the request Origin, so
    ANY site could make credentialed reads)."""
    monkeypatch.setattr(settings, "cors_allow_credentials", True)
    monkeypatch.setattr(settings, "cors_origins", ["*"])
    blockers = _check_cors_setting()
    assert any("'*'" in b for b in blockers)


def test_cors_credentials_with_http_origin_is_blocked(monkeypatch):
    """credentials + a plain-http origin -> blocker listing the unsafe entry
    (credentialed responses must never be readable from an http origin)."""
    monkeypatch.setattr(settings, "cors_allow_credentials", True)
    monkeypatch.setattr(settings, "cors_origins", ["http://x.org"])
    blockers = _check_cors_setting()
    assert len(blockers) == 1
    assert "http://x.org" in blockers[0]


def test_cors_credentials_with_https_localhost_is_blocked(monkeypatch):
    """credentials + https://localhost:3000 -> blocker: localhost origins are
    developer machines, not a concrete production origin, even over https."""
    monkeypatch.setattr(settings, "cors_allow_credentials", True)
    monkeypatch.setattr(settings, "cors_origins", ["https://localhost:3000"])
    blockers = _check_cors_setting()
    assert len(blockers) == 1
    assert "https://localhost:3000" in blockers[0]


def test_cors_credentials_with_concrete_https_origin_is_clean(monkeypatch):
    """credentials + a concrete https origin -> [] (the compliant config)."""
    monkeypatch.setattr(settings, "cors_allow_credentials", True)
    monkeypatch.setattr(settings, "cors_origins", ["https://app.example.org"])
    assert _check_cors_setting() == []


# ---------------------------------------------------------------------------
# The SHIPPED .env.example literals must block startup
# ---------------------------------------------------------------------------


def _env_example_value(key: str) -> str | None:
    """Read a literal out of the committed .env.example, parsed the same way
    warn_unconsumed_env_keys / test_env_bijection parse it."""
    for line_raw in (PROJECT_ROOT / ".env.example").read_text().splitlines():
        line = line_raw.strip().removeprefix("export ").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip().upper() == key:
            return v.strip().strip('"').strip("'")
    return None


@pytest.mark.parametrize("key", ["SECRET_KEY", "SESSION_SECRET"])
def test_shipped_env_example_secret_blocks_startup_in_staging(monkeypatch, key):
    """The EXACT literal in the committed .env.example must be a
    startup blocker. Every other weak-secret test uses a synthetic value, so
    this coupling to the real file is unpinned — edit the template
    placeholder and the blocker silently stops matching, letting a deploy
    boot with a publicly known SECRET_KEY (the HKDF root for the TOTP
    encryption keys and the audit-email-hash key)."""
    template_value = _env_example_value(key)
    assert template_value, f"{key} not found in .env.example — update this test"

    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, key.lower(), SecretStr(template_value))

    with pytest.raises(RuntimeError, match=key):
        validate_security_settings()


def test_a_strong_unique_secret_does_not_block(monkeypatch):
    """POSITIVE CONTROL: the blocker must reject the TEMPLATE value
    specifically, not every secret — otherwise no real deploy could boot."""
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "secret_key", SecretStr(_secrets.token_urlsafe(64)))
    monkeypatch.setattr(settings, "session_secret", SecretStr(_secrets.token_urlsafe(64)))
    # Neutralise the optional secrets this test doesn't set: a repo-root .env
    # (read directly by Settings in dev — env_file, so os.environ tricks in
    # conftest can't reach it) may carry the template SHIBBOLETH_INTERNAL_SECRET,
    # which would trip the blocklist/template blockers and mask the thing under
    # test. None is the "not configured" state _get_secrets_to_validate skips.
    monkeypatch.setattr(settings, "shibboleth_internal_secret", None)
    # Staging would otherwise trip the unrelated RATE_LIMIT_TRUST_PROXY blocker
    # (rate limiting is on in the test env and trust_proxy defaults to False).
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    validate_security_settings()  # must not raise


def test_enabled_shibboleth_runtime_gate_requires_secret_and_issuer(monkeypatch):
    """The final startup gate repeats the model's fail-closed federation pins."""
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", None)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    message = str(excinfo.value)
    assert "SHIBBOLETH_INTERNAL_SECRET" in message
    assert "SHIBBOLETH_TRUSTED_ISSUERS" in message


def test_weak_shibboleth_secret_blocks_hardened_startup(monkeypatch):
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr("weak"))
    monkeypatch.setattr(
        settings,
        "shibboleth_trusted_issuers",
        ["https://idp.example.org/idp/shibboleth"],
    )

    with pytest.raises(RuntimeError, match="SHIBBOLETH_INTERNAL_SECRET"):
        validate_security_settings()


def test_enabled_shibboleth_runtime_gate_is_fatal_in_dev(monkeypatch):
    """A public demo labelled dev must not turn on an incomplete auth boundary."""
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "shibboleth_enabled", True)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", None)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])

    with pytest.raises(RuntimeError, match="SHIBBOLETH SECURITY FAILURE") as excinfo:
        validate_security_settings()

    message = str(excinfo.value)
    assert "SHIBBOLETH_INTERNAL_SECRET" in message
    assert "SHIBBOLETH_TRUSTED_ISSUERS" in message


def test_enabled_shibboleth_runtime_gate_accepts_complete_boundary(monkeypatch):
    """Positive control for the shared construction/startup policy."""
    _enable_valid_federation(monkeypatch)

    validate_security_settings()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("public_base_url", "http://archive.example.org", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://2130706433", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://127.1", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://[::ffff:127.0.0.1]", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://ⓛocalhost", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://%31%32%37.0.0.1", "PUBLIC_BASE_URL"),
        ("public_base_url", "https://localhost\x01", "PUBLIC_BASE_URL"),
        ("cookies_secure", False, "COOKIES_SECURE"),
        ("allowed_hosts", ["*"], "ALLOWED_HOSTS"),
        ("allowed_hosts", ["*.example.org"], "ALLOWED_HOSTS"),
        ("allowed_hosts", [""], "ALLOWED_HOSTS"),
        ("allowed_hosts", ["archive.example.org", "*.example.org"], "ALLOWED_HOSTS"),
        ("allowed_hosts", ["["], "ALLOWED_HOSTS"),
        (
            "shibboleth_trusted_issuers",
            ["http://idp.example.org/idp/shibboleth"],
            "SHIBBOLETH_TRUSTED_ISSUERS",
        ),
        (
            "shibboleth_trusted_issuers",
            ["https://exa|mple.org/idp/shibboleth"],
            "SHIBBOLETH_TRUSTED_ISSUERS",
        ),
        (
            "shibboleth_trusted_issuers",
            ["https://idp.example.org/idp/*"],
            "SHIBBOLETH_TRUSTED_ISSUERS",
        ),
        (
            "shibboleth_trusted_issuers",
            ["https://idp.example.org/idp,forged"],
            "SHIBBOLETH_TRUSTED_ISSUERS",
        ),
        (
            "shibboleth_trusted_issuers",
            [SHIB_ISSUER, SHIB_ISSUER],
            "duplicate",
        ),
    ],
    ids=[
        "plaintext-origin",
        "numeric-loopback-origin",
        "short-loopback-origin",
        "mapped-ipv6-loopback-origin",
        "idna-localhost-origin",
        "percent-encoded-loopback-origin",
        "c0-control-loopback-origin",
        "insecure-cookie",
        "universal-wildcard-host",
        "subdomain-wildcard-host",
        "blank-host",
        "mixed-wildcard-host",
        "ambiguous-ipv6-host-pattern",
        "invalid-issuer",
        "malformed-issuer-authority",
        "wildcard-issuer",
        "comma-issuer",
        "duplicate-issuer",
    ],
)
def test_enabled_shibboleth_runtime_gate_rechecks_prestartup_mutation(
    monkeypatch, field, value, message
):
    """The final pre-bind gate catches mutation after construction."""
    _enable_valid_federation(monkeypatch)
    monkeypatch.setattr(settings, field, value)

    with pytest.raises(RuntimeError, match=message):
        validate_security_settings()


def test_enabled_shibboleth_runtime_gate_rejects_reused_secret(monkeypatch):
    """Runtime revalidation repeats secret independence, not only strength."""
    _enable_valid_federation(monkeypatch)
    monkeypatch.setattr(
        settings,
        "shibboleth_internal_secret",
        SecretStr(settings.secret_key.get_secret_value()),
    )

    with pytest.raises(RuntimeError, match="must not reuse"):
        validate_security_settings()


def test_enabled_shibboleth_runtime_gate_reports_each_boundary_once(monkeypatch):
    """The shared gate aggregates defects without duplicate secret ownership."""
    _enable_valid_federation(monkeypatch)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", None)
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])
    monkeypatch.setattr(settings, "public_base_url", "http://localhost")
    monkeypatch.setattr(settings, "cookies_secure", False)
    monkeypatch.setattr(settings, "allowed_hosts", ["*"])

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    message = str(excinfo.value)
    for setting_name in (
        "SHIBBOLETH_INTERNAL_SECRET",
        "SHIBBOLETH_TRUSTED_ISSUERS",
        "PUBLIC_BASE_URL",
        "COOKIES_SECURE",
        "ALLOWED_HOSTS",
    ):
        assert message.count(setting_name) == 1


def test_disabled_shibboleth_weak_optional_secret_remains_a_dev_warning(monkeypatch):
    """The all-environment fatal rule starts only when federation is enabled."""
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "dev")
    monkeypatch.setattr(settings, "shibboleth_enabled", False)
    monkeypatch.setattr(settings, "shibboleth_internal_secret", SecretStr("weak"))
    monkeypatch.setattr(settings, "shibboleth_trusted_issuers", [])

    validate_security_settings()


@pytest.mark.parametrize("weak_index", [0, 1], ids=["first-key-weak", "second-key-weak"])
def test_weak_outbox_key_is_flagged_with_its_index(monkeypatch, weak_index):
    _patch_strong_secrets(monkeypatch)
    monkeypatch.setattr(settings, "env_state", "staging")
    monkeypatch.setattr(settings, "rate_limit_trust_proxy", True)

    keys = [SecretStr(STRONG_86), SecretStr(RANDOM_90)]
    keys[weak_index] = SecretStr("weak")
    monkeypatch.setattr(settings, "outbox_encryption_keys", keys)

    with pytest.raises(RuntimeError) as excinfo:
        validate_security_settings()

    message = str(excinfo.value)
    assert f"OUTBOX_ENCRYPTION_KEYS[{weak_index}]" in message
    assert f"OUTBOX_ENCRYPTION_KEYS[{1 - weak_index}]" not in message
