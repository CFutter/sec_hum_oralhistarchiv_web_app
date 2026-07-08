# Users Service

User accounts, password verification, TOTP secret management, access tier checks — this page covers the four modules that together implement the user side of authentication. The `User` dataclass is the canonical in-memory representation of an authenticated principal; routes obtain it via the session middleware and read it from `request.state.user`.

The TOTP secret is encrypted at rest with Fernet via the [`crypto` module](crypto.md), so a database compromise alone does not let an attacker generate valid TOTP codes.

For the conceptual model see [Architecture → Authentication & Sessions](../../architecture/auth.md).

## `app.services.users`

User CRUD, the `User` dataclass, the user-schema invariant, and the unverified-account reaper.

::: app.services.users

## `app.services.authentication`

Password verification with rehash-on-login, timing equalisation for nonexistent/locked/inactive accounts, and the failed-login/lockout counters.

::: app.services.authentication

## `app.services.totp`

TOTP enrolment (pending-secret lifecycle), verification with a one-step clock-skew window, and atomic time-step consumption for replay protection.

::: app.services.totp

## `app.services.access_tiers`

The tier ranking (`can_access`, `tier_rank`) and the ingest-side `SourcePolicy` / `resolve_tier` ceiling — see [Architecture → Access Control & Visibility](../../architecture/access-control.md) for the model.

::: app.services.access_tiers
