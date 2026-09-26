# Crypto & Passwords

Encryption, password policy, reset tokens, and bounded password work. See [Key Rotation](../../runbooks/key-rotation.md) for operator procedures.

`TOTP_ENCRYPTION_KEYS` and `OUTBOX_ENCRYPTION_KEYS` are independent HKDF/Fernet rings: the first key encrypts and all configured keys decrypt. Keep old keys while retained ciphertext depends on them; restart processes after changing key configuration. Invalid ciphertext returns `None`, and TOTP callers fail closed.

Within `crypto`, `SECRET_KEY` derives the audit-email HMAC key; signed action tokens use it separately. Rotating it does not re-encrypt TOTP/outbox data, but invalidates existing signed links and changes audit-email correlation.

Password policy enforces a 12-character minimum, a common-password blocklist, and contextual exclusions. Shared Argon2 operations run through `password_work` to bound per-event-loop concurrency.

## `app.services.crypto`

::: app.services.crypto

## `app.services.password_validation`

::: app.services.password_validation

## `app.services.password_reset`

::: app.services.password_reset

## `app.services.password_work`

::: app.services.password_work
