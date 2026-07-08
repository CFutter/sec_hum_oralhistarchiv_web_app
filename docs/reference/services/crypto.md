# Crypto & Passwords

The cryptographic primitives, password hashing helpers, and password strength validation.

`crypto` provides Fernet-based encryption used to protect TOTP secrets at rest. The key material comes from **`TOTP_ENCRYPTION_KEYS`** — a list of secrets, each stretched to a Fernet key via HKDF-SHA256 with a fixed `info` string for domain separation, and combined into a `MultiFernet`: the **first** key encrypts, **all** keys decrypt. That is what makes rotation possible without locking every user out of their authenticator: prepend a new key, re-encrypt the stored secrets, then retire the old key — the exact procedure (including the re-encryption script) is in the [Key-Rotation Runbook](../../runbooks/key-rotation.md). Removing or replacing the encrypting key *before* re-encrypting makes the affected TOTP secrets unrecoverable (decryption returns `None` and those users must re-enroll), so treat that runbook as mandatory reading. `SECRET_KEY` plays **no part** in TOTP encryption — within this module it only derives (again via HKDF, under a different `info` string) the HMAC key for `audit_email_hash()`, the keyed, truncated hash that lets audit-log entries be correlated by email without ever storing the address.

`password_validation` runs user-supplied passwords through the SecLists 10k common-password blocklist plus contextual checks against the user's email local part and display name. It also enforces the **12-character minimum length itself** (`_MIN_PASSWORD_LENGTH = 12`). The form layer only bounds the maximum length; the minimum, the blocklist, and the contextual checks all live in `validate_password_strength()`. That 12-character floor alone catches all but a handful of the 10k blocklist entries, but the explicit blocklist check is kept as defense in depth and to give clearer error messages.

Password hashing and re-hashing are not a separate module. Argon2id hashing lives in `users.create_local_user`, and the rehash-on-login path (when Argon2 parameters are out of date) is in `authentication.verify_password`. The reset finaliser — verify the single-use token, reject weak/reused passwords, hash, clear the token, and invalidate all sessions — is `password_reset.update_password_with_token`.

`password_reset` owns the reset token: signed generation via `itsdangerous`, SHA-256 hashing for storage (the user row stores the hash, never the live token), and constant-time validation. See [Architecture → Authentication & Sessions](../../architecture/auth.md) for the full reset flow including the no-enumeration response strategy.

## `app.services.crypto`

::: app.services.crypto

## `app.services.password_validation`

::: app.services.password_validation

## `app.services.password_reset`

::: app.services.password_reset
