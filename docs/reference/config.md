# Configuration Module

Generated configuration and logging APIs. Operator references: [Settings](../configuration/settings.md) and [Logging & Audit](../configuration/logging.md).

## `config.settings`

`Settings` loads the environment at construction. The OS-level `ENV_STATE` selects whether the repository `.env` is read: unset/`dev` enables it; staging/production require real environment configuration. Invalid settings raise Pydantic validation errors. Cross-field checks cover hardened URLs, cookies, SMTP/TLS, health credentials, host/CORS policy, independent Redis credentials, and federation activation. Secret fields use `SecretStr`; masking is not permission to log credentials.

::: config.settings

## `config.logging`

`setup_logging` writes application and audit streams to stdout; audit formatting is always JSON. Filters redact configured secret values, recognized runtime secret/token shapes, and nested extras. Application email addresses are redacted; audit addresses are automatically replaced by keyed hashes, or redacted until the hasher is registered. Exception diagnostics omit arbitrary messages, source lines, and locals.

Patterns are initialized lazily and retain the settings values seen at first use. Configured secrets shorter than eight characters are skipped with a warning. Pattern matching cannot guarantee removal of arbitrary encodings or unrecognized sensitive content; callers must avoid logging it.

::: config.logging

## Package exports

::: config
