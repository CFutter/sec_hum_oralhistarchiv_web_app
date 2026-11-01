# Configuration Module

Generated configuration and logging APIs. Operator references: [Settings](../configuration/settings.md) and [Logging & Audit](../configuration/logging.md).

## `config.settings`

`Settings` requires the exact uppercase OS key `ENV_STATE` with value `dev`, `staging` or `production`. Only `dev` loads the repository `.env`; OS values take precedence. Missing, conflicting or invalid mode selections fail before settings load. Other invalid settings raise Pydantic validation errors. Secret fields use `SecretStr`; callers must still avoid logging credentials.

::: config.settings

## `config.logging`

`setup_logging` writes application and audit streams to stdout; audit formatting is always JSON. Filters redact configured secret values, recognized runtime secret/token shapes, and nested extras. Application email addresses are redacted; audit addresses are automatically replaced by keyed hashes, or redacted until the hasher is registered. Exception diagnostics omit arbitrary messages, source lines, and locals.

Patterns are initialized lazily and retain the settings values seen at first use. Configured secrets shorter than eight characters are skipped with a warning. Pattern matching cannot guarantee removal of arbitrary encodings or unrecognized sensitive content; callers must avoid logging it.

::: config.logging

## Package exports

::: config
