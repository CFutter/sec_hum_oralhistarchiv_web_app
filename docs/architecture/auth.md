# Authentication & Sessions

Local accounts use verified email, password, and TOTP; federated accounts use a trusted institutional assertion. Both use PostgreSQL sessions. Deployment and recovery procedures are in [Deployment](../../Deployment.md).

## Security boundaries

- Cookies contain signed random session tokens; PostgreSQL stores their SHA-256 hashes and authority state.
- Local registration and authentication do not grant a higher metadata tier. Administrators assign registered/vetted access.
- TOTP secrets and queued email bodies use separate encryption key rings. Keep keys outside database backups.
- Login failures, session step-up submissions, and recovery-code password attempts have distinct durable budgets.
- `SecureAPIRouter` installs exact-route access policies and mutation protections; startup validates the contract.
- Mail-request success responses conceal account eligibility, but server work and latency can differ.

See the sections below for each enforcement path.

## Local sign-in and registration policy

`LOCAL_REGISTRATION_ENABLED` controls new local registration, not existing login. Local users start at public tier. The bootstrap administrator is local; federated approval requires an existing administrator, and promotion accepts only local targets. Disabling registration therefore does not disable local administration.

## Sessions

### What's in the cookie

`SESSION_COOKIE_NAME` defaults to `oha_session`. Its value is a URL-safe token generated from 32 random bytes, signed/timestamped with `SESSION_SECRET` using the `session-cookie-v1` salt. Cookie validation enforces `SESSION_MAX_AGE_SECONDS` (default 28,800 seconds); database expiry may be earlier.

Cookies use `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure=COOKIES_SECURE` (default true; hardened environments require it). Cross-site navigation can omit the session cookie. CSRF protection also verifies an identifier-bound HMAC.

### What's in the database

`sessions` stores the hashed token ID, user ID, creation/expiry timestamps, IP address, purpose, step-up attempt count, and optional flash message/category. User deletion cascades to sessions; session deletion cascades to its rotation challenge. Purposes are `full`, `totp_setup`, and `totp_recovery`.

Flash consumption atomically clears one stored message. Concurrent readers cannot consume the same stored value; this is not a guarantee that the browser receives it.

### Lifecycle

Login commits a fresh session before setting its cookie. Revoking a token supplied with the login request is best-effort; if that deletion fails, the previous session remains valid until expiry or later revocation. Session middleware resolves the token against its database row and current account; hourly cleanup deletes expired rows in bounded batches.

Local sessions require an active account and matching recovery state. Federated sessions additionally require `full` purpose, enabled federation, approved/active status, and an exact trusted issuer. Disallowed federated or mismatched recovery rows are deleted to prevent revival after later state changes.

At startup, `reconcile_federated_session_policy()` locks the singleton policy row. A missing/changed fingerprint atomically deletes every federated session and records the new digest; local sessions remain. The fingerprint covers enabled state, sorted issuers, the fixed MFA context, policy version, and internal callback secret. Federated login/approval hold a shared policy lock and reject a mismatched fingerprint, preventing stale workers from recreating authority after reconciliation.

Logout deletes the presented application session and clears cookies. Whenever federation is enabled, it also redirects through the fixed local SP logout handler, including for local or already-expired sessions. No request parameter chooses that destination. The institutional-login link requests `forceAuthn=true`; actual SP/IdP logout and fresh authentication require deployment acceptance tests. On shared browsers, users must also sign out at the IdP and close the browser.

## Local-account login

After form-content and CSRF checks, `POST /login`:

1. Reads the local password hash and `auth_revision`, then verifies Argon2 without holding a database connection. Unusable/missing hashes receive dummy work. Successful rehash writes compare both old hash and revision.
2. Records counted failures against that revision. `LOGIN_FAILURE_THRESHOLD` defaults to 10 and `LOGIN_LOCKOUT_MINUTES` to 15. Active locks neither increment nor extend; the first failure after expiry starts a new streak at one and clears the notice marker. A threshold transition and its once-per-streak outbox notice share a transaction.
3. On a matching password, locks the user and rechecks local/active/verified state, revision, recovery requirement, and lockout. Configured TOTP must match within one adjacent 30-second step and be newer than the last consumed step. Failed TOTP commits failure/notice state; successful login resets it, updates `last_login`, and commits a fresh `full` or `totp_setup` session.
4. Sets the cookie after commit and redirects to setup or a validated same-origin `next` path.

Ordinary credential failures use a generic 401 response. A verified password for an unverified account returns verification instructions; required authenticator recovery redirects to `/recover-totp`. Undecryptable TOTP produces support guidance. Dummy work reduces hash-timing differences but does not make complete requests constant-time.

## Registration and email verification

`POST /register` validates credentials and atomically inserts a public-tier unverified local user, verification-token hash, and encrypted outbox message. It creates no session. Duplicate registration uses the same success page and queues a notice to the existing address.

Verification tokens are signed with `SECRET_KEY`, nonce-bearing, and valid for 24 hours. `GET /verify-email/{token}` renders confirmation without consuming the token; `POST /verify-email` checks the signature, matching stored hash, age, and current email before atomically verifying and clearing the hash. The POST is CSRF-exempt because the signed token is its capability; form-content checks remain. `/send_verification` replaces a pending token/mail and returns a generic success response irrespective of account eligibility.

After verification, password login creates a `totp_setup` session. `GET /setup-totp` is an authenticated state-changing GET: it reuses a decryptable pending seed younger than ten minutes or replaces it, and always replaces pending recovery codes. Refreshing therefore invalidates previously displayed recovery codes. `POST /setup-totp` requires both a current TOTP code and one staged recovery code. It activates both, advances `auth_revision`, clears pending capabilities, and upgrades the supplied session to `full`.

The hourly reaper deletes local unverified nonadmin accounts older than `UNVERIFIED_REAP_AFTER_DAYS` (default seven), at most 1,000 per run. Neither verification nor enrollment changes the metadata tier.

## Route authorization

`SecureAPIRouter` installs one `RouteAccess` policy after exact route selection. Full local sessions require active status, verified email, and configured TOTP. Public catalogue routes permit guests but reject a presented partial session. Setup/recovery sessions receive only their exact allowlisted routes; path prefixes grant no authority. Capability routes use their signed link, health credential, or authenticated proxy assertion.

`validate_route_security_contract()` runs after registration and at startup. It rejects undeclared routes, unexpected public/exception keys, missing access/mutation dependencies, duplicate route keys, unsupported mounts/Starlette routes, and WebSockets. Extend the central policy/allowlist alongside any new endpoint.

## Changing the authenticator

`GET /account/reset-totp` only renders a form. Its protected POST spends a session step-up attempt, verifies the password off-connection, then locks/rechecks user, credentials/revision, exact full session, lockout, and fresh current TOTP. It consumes that step and replaces the session-bound encrypted five-minute challenge; only this response contains the replacement seed/QR.

`POST /account/reset-totp/confirm` rechecks user/session/revision/expiry and spends the challenge's `TOTP_ROTATION_CONFIRMATION_ATTEMPT_LIMIT` budget (default five). Invalid final attempts delete the challenge, leaving the active factor unchanged. Success changes TOTP, advances `auth_revision`, clears pending capabilities, and deletes every user session atomically. Active recovery codes remain; all devices must log in again.

## Credential attempt budgets

`SESSION_STEP_UP_ATTEMPT_LIMIT` (default five) is shared by rotation start, self-service email changes, promotion preparation/acceptance, and admin recovery authorization. Each raw full-session reservation commits before proof work; successes and later failures spend it. The first excess request expires only that session and clears its flash. Expiration avoids additional cascading locks; cleanup deletes it later. Existing login locks block reservations, but step-up failures never increment or extend account lockout.

Rotation confirmation instead uses its own challenge counter. Public recovery uses three password attempts per matching retained code, requires current admin authorization, and bypasses ordinary login locks. Unknown codes receive dummy work without changing account/code state. Successful redemption clears login lockout. Storage errors propagate; a later failure cannot refund a previously committed reservation. Per-IP limits supplement these budgets.

## Password reset and email changes

`POST /forgot-password` queues a nonce-bearing, 30-minute signed link only for an active local account. Hash replacement, prior-mail cancellation, and encrypted outbox insertion commit together. Every valid-email request returns the same success status/body; work and latency may differ, and queue failures are logged. Raw links are present in encrypted outbox bodies, not plaintext database columns.

`GET /reset-password/{token}` checks signature and stored capability without consumption. `POST /reset-password` submits the token as a form field. It validates password strength and nonreuse from a snapshot, then atomically rechecks the active local account, case-insensitive email, hash, and age. Success changes the password, advances `auth_revision`, clears failure/lockout state, and revokes sessions and pending capabilities.

Self-service email changes spend a session step-up attempt and verify a password snapshot off-connection. Under user/session locks, staging rechecks password hash/revision and current eligibility, then commits a one-hour signed revision-bound token, confirmation to the new address, and notice to the old address. It does not reveal destination membership; delivery and confirmation check availability. Administrator staging uses the current-admin/session guard and can reject an occupied address.

Email-change GETs do not consume the capability. The confirmation POST validates the signature then atomically matches active/local state, exact pending address/hash/revision, age, and uniqueness. Success verifies the new email, advances revision, and revokes sessions/pending capabilities. Reset, email confirmation, deactivation, and revoke-all retain current recovery codes and the recovery-required flag.

Administrator activation/unlock also advances revision, preventing older password checks from re-locking the account. It preserves existing sessions but clears staged email changes; request those links again.

## Password storage and validation

Local email validation accepts internationalized domains with ASCII local parts; SMTP converts domains to IDNA. Legacy Unicode local parts require SMTPUTF8 at the relay.

`argon2-cffi.PasswordHasher()` supplies Argon2id defaults. Login rehashes stale parameters using a compare-and-update. Hash/verify/dummy work uses `run_password_work`, limited by `PASSWORD_WORK_CONCURRENCY` per event loop; cancellation waits for the worker thread. See [Deployment](../../Deployment.md) before changing worker counts.

Passwords must contain 12–200 characters, avoid case-insensitive membership in the bundled common-password list, and omit the email local part or display-name words of at least four characters. Registration/reset apply supplied profile context; seeding checks email context. The list is cached, warmed at startup, and a read failure is fatal in hardened environments (empty-list fallback in development).

## CSRF and mutation defaults

CSRF tokens are HMAC-SHA256 of the raw session/pre-session identifier using a domain-separated key derived from `SESSION_SECRET`. Forms receive the middleware's outgoing token; verification uses incoming cookies. Cookie flags follow `COOKIES_SECURE`, `HttpOnly`, `SameSite=Strict`, and `Path=/`. Middleware can prepare cookies for GET and resolved POST responses, including failed form renders; explicit session-cookie transitions own their response cookies.

Every method except GET/HEAD/OPTIONS receives form-content validation then CSRF verification. Verification requires matching cookie/form values and the expected identifier-bound HMAC; failure returns 403. Exact `POST /verify-email` and `POST /account/confirm-email` omit CSRF because they consume signed email-bound capabilities, but retain content-type checks. Exception keys are centralized and validated at startup.

## Admin actions

`routes/auth/admin.py` uses `RouteAccess.ADMIN`. Its dependency enforces a full session/admin flag and, for local admins, a usable active recovery-code generation; missing/nonadmin principals receive 404. Each mutation also rechecks current authority and the exact full session under the shared admin-action advisory lock. Role changes do not grant metadata tiers.

Administrators can review federated identities, change tiers/active status, demote users, invite local promotions, authorize local recovery, and stage email changes. Self-demotion/deactivation and removal of the last active admin are rejected. Activation clears lockout and pending email changes; deactivation revokes sessions/pending capabilities. Pending/legacy federated identities require the dedicated approval path. Successful actions emit structured audit events; form mutations receive CSRF/content-type checks.

Promotion invitations last seven days. The target proves password/fresh TOTP in a full session and receives a new recovery-code set. Within fifteen minutes and invitation expiry, confirming one code activates the set and admin role, advances revision, removes the invitation/pending capabilities, and revokes target sessions. The confirming code remains unused. Cancellation/decline removes staged codes, preserving the active set.

Recovery requires a different eligible local administrator, fresh admin TOTP, and an unused, unexhausted target recovery code. A 30-minute authorization removes the old factor and sessions but exposes no target credential. The owner presents password plus a saved code; each matching code allows three committed password attempts. Redemption atomically consumes code/authorization, clears lockout, and issues one 15-minute `totp_recovery` session. Replacement setup confirms a fresh seed/code set, clears recovery state, and revokes all sessions; the owner then logs in again.

## Federated (Shibboleth) login

Federation defaults off. The shipped Phase 1 nginx callback returns 404; enabling `SHIBBOLETH_ENABLED` alone does not install an SP. Complete [Deployment](../../Deployment.md)'s SP, identity, MFA, header, socket, and logout acceptance steps before enabling it.

The callback requires a Unix-socket peer, the configured `SHIBBOLETH_INTERNAL_SECRET`, an exact HTTPS issuer from `SHIBBOLETH_TRUSTED_ISSUERS`, and `https://refeds.org/profile/mfa`. Fixed private headers are `X-OHA-Shib-Subject`, `Issuer`, `Mail`, `Display-Name`, `Affiliation`, `Country`, and `Authn-Context` (each with the `X-OHA-Shib-` prefix), plus `X-OHA-Internal-Auth`. The SP-authorized proxy must replace them; ordinary proxy locations clear private and legacy assertion headers. The secret alone does not prove SAML/MFA.

Identity is the exact `(issuer, subject)` pair. Operators must establish a stable, non-reassigned subject contract with each IdP. Email never links accounts; a collision rejects login. First assertion creates a public, inactive, unverified, nonadmin `pending` user without a session. Dedicated admin approval rechecks the reviewed identity, current policy/admin session, and pending state, then assigns tier, activates, records approver/time, advances revision, and deletes old sessions. A later trusted assertion can issue `full` access without local TOTP.

Only active approved identities refresh mutable profile fields; absent optional attributes preserve old values. An email change clears mailbox verification and pending email/reset tokens. Disabled identities remain unchanged until admin reactivation. Legacy sentinel identities require authoritative issuer/subject reconciliation back to public/inactive/nonadmin/unverified pending state before dedicated approval; never activate them through generic controls.

Federation-policy reconciliation and live session checks are described under [Lifecycle](#lifecycle). Browser/SP/IdP behavior remains an operational verification requirement.

## Limitations

There is no password-age reminder, self-authorized lost-admin-factor recovery, per-field visibility, or database row-level security. Lost-factor recovery needs another eligible administrator and a retained code; otherwise use the controlled operator procedure in [Deployment](../../Deployment.md). SP installation, federation registration, and real-browser MFA/logout checks are deployment work, not application guarantees.