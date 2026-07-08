# Sessions Service

Server-side session storage. The cookie carries only the session ID (signed with `itsdangerous`); the actual session row — user ID, IP, purpose, expiry, optional flash message — lives in PostgreSQL.

The `purpose` column is what gates `totp_setup` sessions: a session created at **login** before TOTP enrolment (registration itself creates no session) is restricted to `/setup-totp`, `/logout`, and `/verify-email` until enrolment is completed and the session is upgraded to `purpose='full'`. The enforcement lives in `TotpGateMiddleware`; see [Architecture → Authentication & Sessions](../../architecture/auth.md) for the full lifecycle and the rationale.

This module also owns the small flash-message helper used to carry one-shot status messages (e.g. "Password updated") across redirects without query strings or in-memory state.

::: app.services.sessions
