# Configuration Module

The `config` package owns two things: the Pydantic Settings class that loads and validates all environment variables, and the structured logging setup with sensitive-value redaction.

For the operator-facing reference of every individual setting, see [Configuration → Settings Reference](../configuration/settings.md). For the operator-facing logging documentation, see [Configuration → Logging & Audit](../configuration/logging.md). The pages here document the underlying Python implementation.

## `config.settings`

The `Settings` class is a Pydantic `BaseSettings` subclass. It loads values from `.env` in `dev` only — in `staging` and `production`, only real OS environment variables are read. Validation runs at instance construction time, before any other application code touches the settings; failures raise `ValidationError` and the process exits.

Two pieces of behaviour to know about:

- **`SecretStr` for credentials.** Every secret-like field is typed as `SecretStr`, which prevents accidental exposure in tracebacks, debugger output, and `repr()` calls. The `__repr__` and `__str__` of `Settings` itself are also overridden to mask `database_url`.
- **Cross-field validators.** Several `model_validator(mode="after")` checks enforce safe combinations. Most of them distinguish `dev` from the two *hardened* environments (`staging` **and** `production` — not production alone): `validate_cors_settings` and `validate_allowed_hosts` block hardened startup on unsafe CORS/host lists (`*`, empty lists, localhost origins); `_require_https_in_prod` requires a non-localhost `https://` `PUBLIC_BASE_URL` outside dev; `validate_cookies_secure` and `validate_debug_only_in_dev` enforce `COOKIES_SECURE=true` and `FASTAPI_DEBUG=false` outside dev; `require_smtp_in_prod`, `validate_smtp_settings`, `validate_smtp_tls_in_prod`, and `validate_smtp_auth_pair` require working, TLS-enabled, non-placeholder SMTP in production (user/password must be set together everywhere); `require_health_token_in_prod` requires `HEALTH_DETAIL_TOKEN` in production; `validate_redis_url_required` requires a Redis URL whenever Redis is enabled, and `validate_redis_in_production` warns (single-worker mode) when it is not. `validate_shibboleth_settings` requires the internal secret **whenever Shibboleth is enabled, in every environment**. Field validators additionally enforce the `postgresql://` / `postgres://` scheme on `database_url` and an interval-literal format on `db_statement_timeout`.

::: config.settings

## `config.logging`

`setup_logging` configures the root logger, the `audit` logger, a `StreamHandler` per stream writing to stdout, the JSON (or text) formatter, and the redaction filters that strip sensitive `Settings` values from every record before it is emitted.

All logs go to stdout — systemd-journald captures them in production, and the dev terminal shows them directly. This is multi-process safe, unlike the earlier `TimedRotatingFileHandler` setup which could corrupt logs when Gunicorn workers rotated concurrently.

Redaction works by walking `Settings.model_fields` and collecting any field that is a `SecretStr` or marked `json_schema_extra={"sensitive": True}`. For each such field a regex is compiled from the actual current value and applied to the message and to every non-standard extra attribute of every log record, replacing matches with a `[REDACTED:<field_name>]` marker. This means a developer can `logger.info("Object: %s", obj)` without remembering whether `obj` happens to contain a secret — if it does, the secret is replaced before reaching any handler. A static pattern also strips `Bearer <token>` values. The pattern set is built **lazily on first use** (a cached property), so the filter can be installed before settings are fully loaded. Two filter instances exist — one per handler: the application-log instance additionally auto-redacts anything matching an email-address pattern; the audit instance does not, because audit code never logs raw addresses (it uses the keyed `audit_email_hash` instead).

Two known limitations are worth flagging when reading the source:

- Values shorter than 8 characters cannot be reliably redacted; the filter emits a warning for any such sensitive field and skips it.
- Redaction is value-based, not field-based. Two settings sharing the same value will be redacted in both places, which is the intended behaviour.

::: config.logging
