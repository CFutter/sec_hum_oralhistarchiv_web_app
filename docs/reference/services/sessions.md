# Sessions Service

The signed cookie carries a raw random token; PostgreSQL stores its hash with user, expiry, IP, purpose, and flash state.

`full`, `totp_setup`, and `totp_recovery` are distinct authorities. Exact route policies limit setup sessions. Recovery sessions have an additional middleware restriction to enrollment/logout. Initial enrollment upgrades its exact setup session to full; recovery enrollment deletes sessions and requires a new login.

Federated lookup requires an active approved identity under the live flag and exact issuer allowlist; rejected presented sessions are deleted. Flash helpers consume messages once and preserve them across redirects.

::: app.services.sessions

## Federated-session policy

`federated_session_policy` computes the deterministic whole-policy fingerprint
and reconciles it against the singleton database row at web startup. First
startup or a change to the flag, sorted issuer set, exact MFA context, policy
version, or callback secret revokes all Shibboleth sessions transactionally;
local sessions remain. The finalizer and federated-approval service take a
shared lock on the singleton and refuse a missing or mismatched fingerprint
before writing, so an old process cannot mint or approve past a newer policy.

::: app.services.federated_session_policy

## Session tokens and revocation

::: app.services.session_ids

::: app.services.session_revocation
