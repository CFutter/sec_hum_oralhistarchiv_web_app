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

`SESSION_COOKIE_NAME` defaults to `oha_session` in development and `__Host-oha_session` in staging/production. Its value is a URL-safe token generated from 32 random bytes, signed/timestamped with `SESSION_SECRET` using the `session-cookie-v1` salt. Cookie validation enforces `SESSION_MAX_AGE_SECONDS` (default 28,800 seconds); database expiry may be earlier. Hardened full sessions cannot exceed eight hours, including explicit service overrides. Setup and recovery capabilities have a separate maximum lifetime of ten minutes.

Cookies use `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, and `Secure=COOKIES_SECURE` (default true; hardened environments require it). Hardened security-cookie names use `__Host-`, including CSRF and anonymous pre-session cookies; setting and deletion retain their secure attributes. Duplicate active security-cookie names are rejected before account lookup. Cross-site navigation can omit the session cookie. CSRF protection also verifies an identifier-bound HMAC and the canonical browser origin.

### What's in the database

`sessions` stores the hashed token ID, user ID, creation/expiry and last-activity timestamps, IP address, purpose, step-up attempt count, and optional flash message/category. User deletion cascades to sessions; session deletion cascades to its rotation challenge. Purposes are `full`, `totp_setup`, and `totp_recovery`.

Flash consumption atomically clears one stored message. Concurrent readers cannot consume the same stored value; this is not a guarantee that the browser receives it.

### Lifecycle

Login commits a fresh session before setting its cookie. Revoking a token supplied with the login request is best-effort; if that deletion fails, the previous session remains valid until expiry or later revocation. Session middleware resolves the token against its database row and current account. An idle session expires after `SESSION_IDLE_TIMEOUT_SECONDS` (default 1,800 seconds), independently of its absolute deadline. Eligible application requests touch activity at most once per `SESSION_ACTIVITY_UPDATE_INTERVAL_SECONDS` (default 60 seconds); health and static requests do not refresh it. A touch cannot revive idle or absolute expiry. Cleanup deletes expired rows in bounded batches.

Local sessions require an active account and matching recovery state. Federated sessions additionally require `full` purpose, enabled federation, approved/active status, and an exact trusted issuer. Disallowed federated or mismatched recovery rows are deleted to prevent revival after later state changes.

At startup, `reconcile_federated_session_policy()` locks the singleton policy row. A missing/changed fingerprint atomically deletes every federated session and records the new digest; local sessions remain. The fingerprint covers enabled state, sorted issuers, the fixed MFA context, policy version, and internal callback secret. Federated login/approval hold a shared policy lock and reject a mismatched fingerprint, preventing stale workers from recreating authority after reconciliation.

Logout with valid CSRF proof deletes the presented application session and clears cookies. Whenever federation is enabled, it also redirects through the fixed local SP logout handler, including for local or already-expired sessions. No request parameter chooses that destination. An invalid-token retry after logout redirects locally without cookie changes or SP handoff only when session resolution completed anonymously and no session cookie is present; see [CSRF](security.md#csrf). The institutional-login link requests `forceAuthn=true`; actual SP/IdP logout and fresh authentication require deployment acceptance tests. On shared browsers, users must also sign out at the IdP and close the browser.

## Local-account login

After form-content and CSRF checks, `POST /login`:

1. Reads the local password hash and `auth_revision`, then verifies Argon2 without holding a database connection. Unusable/missing hashes receive dummy work. Successful rehash writes compare both old hash and revision.
2. Records counted failures against that revision. `LOGIN_FAILURE_THRESHOLD` defaults to 10 and `LOGIN_LOCKOUT_MINUTES` to 15. Active locks neither increment nor extend; the first failure after expiry starts a new streak at one and clears the notice marker. A threshold transition and its once-per-streak outbox notice share a transaction.
3. On a matching password, locks the user and rechecks local/active/verified state, revision, recovery requirement, and lockout. Configured TOTP must match within one adjacent 30-second step and be newer than the last consumed step. Failed TOTP commits failure/notice state; successful login resets it, updates `last_login`, and commits a fresh `full` or `totp_setup` session.
4. Sets the cookie after commit and redirects to setup or a validated same-origin `next` path.

Ordinary credential failures use a generic 401 response. A verified password for an unverified account returns verification instructions; required authenticator recovery redirects to `/recover-totp`. Undecryptable TOTP produces support guidance. Dummy work reduces hash-timing differences but does not make complete requests constant-time.

## Registration and email verification

`POST /register` accepts only an email address. It atomically inserts an
inactive, unverified, public local account without a password or profile and
queues a signed setup capability when shared mail admission allows it. Existing
addresses are no-ops: no notice or credential/capability change. Admitted, duplicate
and limited requests render the same generic pending page without Argon2 or a
session; elapsed times may differ.

The nonce-bearing capability lasts 24 hours. `GET /verify-email/{public_id}`
checks only the public identifier's syntax and renders a generic setup form;
it does not look up an account, validate a capability, expose email/profile
state or consume a token. The email provides a public link and a separate
security code, which the user copies into the form. `POST /verify-email` requires both
`public_id` and `token`, the identifier-bound CSRF pair and form content type.
The token must derive the posted public ID before signature or account
processing. The service checks the live capability before password feedback;
completion repeats capability, expiry and revision checks after hashing and
user-row lock waits. It atomically sets
the owner's chosen password/profile, verifies and activates, revokes pending
state/sessions and redirects to login without creating a session. Stale, used,
cancelled and expired links fail closed.

`/send_verification` preserves an eligible pending account's live capability
and expiry. Within issuance budgets, it requeues retained sent/delivery-failed
mail; existing pending/sending copies prevent duplicates. Only expired state is
replaced. A cleared capability cannot be recreated. Responses remain generic.
Closing registration leaves pending setup/resend available. Completion does not
switch an existing browser session; sign out before using the new account.

## Route authorization

`SecureAPIRouter` installs one `RouteAccess` policy after exact route selection. Full local sessions require active status, verified email, and configured TOTP. Public catalogue routes permit guests but reject a presented partial session. Setup/recovery sessions receive only their exact allowlisted routes; path prefixes grant no authority. Capability routes use their signed link, health credential, or authenticated proxy assertion.

`validate_route_security_contract()` runs after registration and at startup. It rejects undeclared routes, unexpected public/exception keys, missing access/mutation dependencies, duplicate route keys, unsupported mounts/Starlette routes, and WebSockets. Extend the central policy/allowlist alongside any new endpoint.

## Changing the authenticator

`GET /account/reset-totp` only renders a form. Its protected POST spends a session step-up attempt, verifies the password off-connection, then locks/rechecks user, credentials/revision, exact full session and fresh current TOTP. It consumes that step and replaces the session-bound encrypted five-minute challenge; only this response contains the replacement seed/QR.

`POST /account/reset-totp/confirm` rechecks user/session/revision/expiry and spends the challenge's `TOTP_ROTATION_CONFIRMATION_ATTEMPT_LIMIT` budget (default five). Invalid final attempts delete the challenge, leaving the active factor unchanged. Success changes TOTP, advances `auth_revision`, clears pending capabilities, and deletes every user session atomically. Active recovery codes remain; all devices must log in again.

## Credential attempt budgets

`SESSION_STEP_UP_ATTEMPT_LIMIT` (default five) is shared by rotation start, password changes, self-service email changes, promotion preparation/acceptance, admin recovery authorization, and account deletion. Each raw full-session reservation commits before proof work; successes and later failures spend it. The first excess request expires only that session and clears its flash. Expiration avoids additional cascading locks; cleanup deletes it later. Login lockout does not block an already authenticated full session from its separately budgeted proof workflow. Step-up failures never increment or extend account lockout.

Rotation confirmation instead uses its own challenge counter. Public recovery uses three password attempts per matching retained code, requires current admin authorization, and bypasses ordinary login locks. Unknown codes receive dummy work without changing account/code state. Successful redemption clears login lockout. Storage errors propagate; a later failure cannot refund a previously committed reservation. Per-IP limits supplement these budgets.

## Password changes, reset and email changes

Local **Change Password** uses `RouteAccess.LOCAL_FULL_SESSION`, CSRF and the
shared durable session step-up budget. It requires the current password and a
fresh, single-use TOTP code. Password verification and new-hash work release the
database connection; the final transaction rechecks local/active/verified state,
lockout, password hash, `auth_revision` and the exact unexpired full session after
lock waits. It consumes TOTP, replaces the password, advances the revision,
revokes every session and pending authentication capability, and queues a
`password_changed_notice` together. Active TOTP and current recovery codes stay
configured. The response clears the cookie and redirects to login; audit follows
commit. Institutional passwords remain managed by the institution.

`POST /forgot-password` admits anonymous issuance before account lookup. Only
active, verified local accounts with TOTP and no recovery requirement qualify.
A live 30-minute capability keeps its hash and expiry; eligible resends copy
retained encrypted mail without extending it, and pending/sending copies prevent
duplicates. Only absent/expired state mints a replacement. Token state, prior-mail
cancellation and enqueue commit together. Responses conceal eligibility; timing
may differ. The email carries a public link and a separate security code.

`GET /reset-password/{public_id}` renders a generic form after public-ID syntax
validation, without looking up the account or validating the capability.
Completion requires the public ID, email security code, new password and a fresh
TOTP code. Only a valid live capability for an eligible enrolled local account
can reserve a proof attempt. The account permits five such submissions in a
30-minute window, anchored to the first reservation using database wall time.
Reservations commit before password work; rejection/admission failure cannot
refund them. Replacement emails and successful resets do not replenish this
window. Exhaustion blocks reset proofs, not ordinary login. Unknown or stale
capabilities never spend an account's budget.

Completion repeats capability expiry, token hash, current email, password hash,
revision, account eligibility and password-profile policy under the final user
lock. Fresh TOTP consumption, hash replacement, revision advancement, lockout
clearing, session/pending-capability revocation and the password notification
commit together. Configured TOTP and current recovery codes remain. Accounts
awaiting first enrollment or requiring authenticator recovery cannot complete
this strict reset. Combined password/authenticator loss requires separately
approved operator recovery; the online authenticator-recovery flow still needs
the current password and a retained recovery code. See the
[recovery policy](../runbooks/credential-recovery.md).

Self-service email changes spend a session step-up attempt and verify a password
snapshot off-connection. Under user/session locks, staging rechecks credentials,
revision and current eligibility, then consumes a fresh TOTP and commits a
one-hour revision-bound capability, confirmation to the new address and notice
to the old address. It does not reveal destination membership. Administrator
staging can reject occupied addresses and remains available for other users;
an administrator must use protected self-service for their own email change.

`GET /account/confirm-email/{public_id}` remains generic and non-consuming.
Confirmation uses the emailed capability for cross-device completion and checks
active/local state, pending address/hash/revision, age and uniqueness atomically.
Success verifies the address, advances revision and revokes sessions/pending
capabilities. Administrator activation/unlock also advances revision and clears
staged email changes while preserving sessions. Already-issued email-change
capabilities keep their normal lifetime; operators requiring an immediate
cutover must cancel staged changes and reissue them under the new proof policy.

The same capability plus fresh TOTP can instead sign in through a temporary
login lock without changing the password. This spends a reset proof attempt,
consumes the capability, clears lockout, advances the revision and replaces
previous sessions with one full session. See [mail recovery](../runbooks/mail-recovery.md).

## Email-action URL and form boundary

`SignedActionToken(salt, max_age)` centralizes issuance, signature/age validation
and signed issue-time metadata for all three flows. Salts remain
`password-reset`, `email-verification` and `email-change`; lifetimes remain
30 minutes, 24 hours and one hour respectively. Fresh random nonces distinguish
issuances, and only token hashes and timestamps enter account state. This
action-link format itself adds no database columns. The approved initial-schema
reset includes the reset-proof budget columns and password notification outbox
type directly in revision `4f73ae3ff827`.

The public path identifier is a 43-character, unpadded base64url encoding of a
SHA-256 digest derived from the token. It is not a credential, database locator
or mechanism for retrieving the secret. Valid-shaped IDs, including unknown
ones, open the same generic form. Legacy signed-token path segments contain
dots and return 404. Query parameters never supply action authority.

Generated email links use `/<flow>/<public_id>` with no token, query or
fragment. The same email prints a separate security code. The user opens the
public link, copies the code into the visible form field and explicitly submits
it. The flow uses ordinary HTML forms without JavaScript, automatic requests or
persistent browser storage. POST validation errors may rerender a valid
submitted token in a form; GET never reconstructs it from the public ID.

The security code remains a credential; the public URL does not grant an
action. Mail systems, browser extensions, copied codes and historical records
remain outside HTTP request-target protection. `Cache-Control: no-store` and
`Referrer-Policy: strict-origin` apply to action pages and responses. Existing
path/query log redaction remains defense in depth, including for obsolete
requests. See the [action-link procedure](../runbooks/action-links.md) for
cutover, reissue and logging acceptance.

The referrer contains at most the source origin, never the action path or
query. Unlike `no-referrer`, this policy preserves the real `Origin` header on
an ordinary same-origin form POST, allowing the independent CSRF origin check
to succeed. Null and foreign origins remain rejected even with a valid token.

## Account deletion

Local self-service deletion requires a current full session, an explicit
confirmation, password proof and a fresh, single-use TOTP code. Administrator
removal requires a current eligible local administrator, the administrator's
password/fresh TOTP and explicit confirmation of the target. Federated accounts,
including pending and disabled identities, can only be removed by an
administrator. The administrator path rejects its own actor as the target;
local administrators use self-service for their own account.

Deletion spends the shared session step-up budget before credential work.
Password verification runs off-connection. The final transaction rechecks the
credential snapshot/revision, active local actor, current exact full session
and TOTP under locks. The shared administration advisory lock serializes
last-active-admin checks with membership changes and other deletions. No
deletion may remove the final active administrator.

The committed user deletion cascades through sessions, rotation challenges,
recovery codes, promotion requests where the user is target or requester, and
user-linked outbox rows. Pending capabilities stored on the user disappear;
valid signatures alone cannot redeem outstanding links. An already-resolved
in-flight request may finish, but the next request with a copied session
cookie resolves no deleted account. The response clears the deleting user's
cookies. There is no grace period or undo flow.

After commit, the route emits one successful `account_deleted` or
`admin_account_deleted` audit event with an `audit_email_hash`-derived address
marker in `email_hash` and actor/target identifiers, without plaintext address or assertion
payload. Existing log-delivery durability remains an operational concern.
Historical audit records, backups and already-delivered messages are outside
the live account cascade. See the
[account-deletion procedure](../runbooks/account-deletion.md) and
[retention/DSAR template](../runbooks/retention-dsar-template.md).

## Password storage and validation

Local email validation accepts internationalized domains with ASCII local parts; SMTP converts domains to IDNA. Legacy Unicode local parts require SMTPUTF8 at the relay.

`services/password_verification.py` owns Argon2 failure classification,
verification logging, and the process-local dummy-hash cache. Callers supply a
required operation label and receive `PasswordVerified` or a typed rejection
that retains the original exception. Admission, cancellation and storage errors
propagate; they never become credential failures. Login and reset keep their
own rehash/reuse decisions.

Administrator promotion and authenticator rotation also share the module's
two-column snapshot reader. It closes the snapshot cursor before password or
dummy work and returns `VerifiedPasswordSnapshot` on success. This result is
only a proof of the observed hash: workflows still reserve their own durable
attempts, apply account eligibility, and compare hash plus revision under their
final user/session locks. Deletion and email change keep their richer snapshot
queries and eligibility checks while sharing hash verification.

Existing dummy-work policies remain explicit: login, promotion, rotation and
recovery use dummy work for unusable hashes; deletion, email change and the
reset reuse check do not add it. The legacy authentication-module dummy/warm-up
imports remain aliases of the shared implementation.

`argon2-cffi.PasswordHasher()` supplies Argon2id defaults. Login rehashes stale
parameters using a compare-and-update. Hash/verify/dummy work uses
`run_password_work`, limited by `PASSWORD_WORK_CONCURRENCY` per event loop.
Each operation waits at most `PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS` (default
1 second, finite range 0.01–5). A wait timeout starts no password work and reaches
the shared HTTP boundary as a 503 with `Retry-After: 5`; ordinary password errors
keep their existing outcomes. Cancellation while queued is immediate. Once
admitted, cancellation waits for the worker thread before releasing its slot.
The budget limits queue residence, not hash execution time or instantaneous
queue length. A request that verifies then rehashes can wait once per operation.
Durable step-up/recovery attempts reserved before admission remain consumed
when admission times out; retries are new submissions, and reservations are not
refunded. Startup password warm-up failures stop startup. Bootstrap failures stop only the one-shot operator command.
See [Deployment](../../Deployment.md) before changing worker counts.

Passwords must contain 12–200 characters, avoid case-insensitive membership in the bundled common-password list, and omit the email local part or display-name words of at least four characters. Registration/reset apply supplied profile context; seeding checks email context. The list is cached, warmed at startup, and a read failure is fatal in hardened environments (empty-list fallback in development).

## CSRF and mutation defaults

CSRF tokens are HMAC-SHA256 of the raw session/pre-session identifier using a domain-separated key derived from `SESSION_SECRET`. Forms receive the middleware's outgoing token; verification uses incoming cookies. Hardened CSRF/pre-session names are `__Host-oha_csrf` and `__Host-oha_pre_session`; development keeps `csrf_token` and `pre_session_id`. Cookie flags follow `COOKIES_SECURE`, `HttpOnly`, `SameSite=Strict`, root `Path=/` and no Domain. Middleware can prepare cookies for GET and resolved POST responses, including failed form renders; explicit session-cookie transitions own their response cookies.

Every method except GET/HEAD/OPTIONS receives form-content validation then CSRF verification. Verification requires matching cookie/form values and the expected identifier-bound HMAC; failure normally returns 403. The anonymous logout retry described above returns an inert 303 without exempting the route from verification. Staging/production also require an `Origin` matching `PUBLIC_BASE_URL`, or a same-origin `Referer` when Origin is absent. Missing both headers, repeated ambiguous headers and sibling origins are rejected. Development permits absent origin headers, but rejects an explicitly foreign origin. Only exact `POST /account/confirm-email` omits CSRF because it consumes a signed email-bound capability, but retains content-type checks. Public IDs do not add a CSRF exemption for registration or password reset. Exception keys are centralized and validated at startup.

## Admin actions

`routes/auth/admin.py` uses `RouteAccess.ADMIN`. Its dependency enforces a full session/admin flag and, for local admins, a usable active recovery-code generation; missing/nonadmin principals receive 404. Each mutation also rechecks current authority and the exact full session under the shared admin-action advisory lock. Role changes do not grant metadata tiers.

Administrators can review federated identities, change tiers/active status, demote users, invite local promotions, authorize local recovery, stage email changes, and remove accounts through the confirmed credential-proof flow. Self-demotion/deactivation and removal of the last active admin are rejected. Activation clears lockout and pending email changes; deactivation revokes sessions/pending capabilities. Pending federated identities require dedicated approval under the enabled, currently trusted policy. Successful actions emit structured audit events; form mutations receive CSRF/content-type checks.

Promotion invitations last seven days. The target proves password/fresh TOTP in a full session and receives a new recovery-code set. Within fifteen minutes and invitation expiry, confirming one code activates the set and admin role, advances revision, removes the invitation/pending capabilities, and revokes target sessions. The confirming code remains unused. Cancellation/decline removes staged codes, preserving the active set.

Recovery requires a different eligible local administrator, fresh admin TOTP, and an unused, unexhausted target recovery code. A 30-minute authorization removes the old factor and sessions but exposes no target credential. The owner presents password plus a saved code; each matching code allows three committed password attempts. Redemption atomically consumes code/authorization, clears lockout, and issues one ten-minute `totp_recovery` session. Replacement setup confirms a fresh seed/code set, clears recovery state, and revokes all sessions; the owner then logs in again.

## Federated (Shibboleth) login

Federation defaults off. The shipped Phase 1 nginx callback returns 404; enabling `SHIBBOLETH_ENABLED` alone does not install an SP. Complete [Deployment](../../Deployment.md)'s SP, identity, MFA, header, socket, and logout acceptance steps before enabling it.

The callback requires a Unix-socket peer, the configured `SHIBBOLETH_INTERNAL_SECRET`, an exact HTTPS issuer from `SHIBBOLETH_TRUSTED_ISSUERS`, and `https://refeds.org/profile/mfa`. Fixed private headers are `X-OHA-Shib-Subject`, `Issuer`, `Mail`, `Display-Name`, `Affiliation`, `Entitlement`, `Country`, and `Authn-Context` (each with the `X-OHA-Shib-` prefix), plus `X-OHA-Internal-Auth`. The SP-authorized proxy must replace them; ordinary proxy locations clear private and legacy assertion headers. The secret alone does not prove SAML/MFA.

Identity is the exact `(issuer, subject)` pair. Operators must establish a
stable, non-reassigned subject contract with each IdP. Email never links or
merges accounts. For a new exact identity only, the trusted login finalizer
may replace a nonadmin, unverified local email reservation: it locks and
rechecks that row, deletes it, and inserts a new public, inactive, unverified,
nonadmin `pending` federated user in the same transaction. The new row receives
no local credentials, profile, authority, sessions or pending capabilities.
Deletion cascades user-linked state, and a failed insert or concurrency
conflict rolls the deletion back. A verified local row, an administrator or
another federated identity still causes collision refusal. An existing exact
federated identity never removes a local reservation, including while refreshing
an approved identity's email.

Local setup completion and reservation replacement serialize on the local
user row. If verification commits first, the waiting assertion rechecks the
verified row and refuses replacement; if replacement commits first, the old
setup capability cannot recreate or verify the deleted account. Only committed
replacement produces `federated_email_reservation_claimed`, with the old/new
user IDs and a pseudonymous email hash, without the plaintext email, assertion
or capability. See the
[reservation procedure and acceptance record](../runbooks/federated-reservations.md).

First assertion issues no session. Dedicated admin approval rechecks the
reviewed identity and review revision, current policy/admin session, and
pending state, then assigns the explicitly selected tier, activates, records
approver/time, advances revision, and deletes old sessions. A later trusted
assertion can issue `full` access without local TOTP.

Only active approved identities refresh mutable profile fields; absent optional
attributes preserve old values. An email change clears mailbox verification
and pending email/reset tokens. Pending and disabled identities keep their
profile and authority unchanged; a later trusted assertion can refresh only
the separate proposal-review metadata until approval or reactivation. The fresh-install baseline does not convert older
identity formats. Any retained prototype accounts require a separately
reviewed migration or isolated import: establish authoritative issuer/subject
pairs, reset imported federated authority to public/inactive/non-admin/unverified
pending state, and revoke prior sessions. Unresolved identities remain outside
the serving account set. Dedicated approval under the enabled trusted policy
is required before a later assertion can establish a session; generic controls
cannot substitute for that transition.

`FEDERATED_TIER_RULES` is a strict ordered advisory rule list. After the callback
validates the trusted principal and current federation policy, login stores the
latest proposal, matched rule and normalized issuer, affiliation and entitlement
serialization in the identity transaction. The administrator page shows these
values as escaped text. No match is displayed separately from a proposal of
`public`. Approval defaults to a chosen tier of `public` and binds the reviewed
identity and revision; changed review attributes make an older form stale.
Successful approval audits the proposed tier/rule and chosen tier, with the
existing actor/time metadata, without raw assertion attributes.

Approval retains the reviewed proposal as a separate baseline. Later assertions
flag a changed proposal against that baseline; an administrator may deliberately
choose a different tier, so mismatch is not a comparison with `access_tier`.
No rule approves an account, changes assigned authority or revokes sessions.
See [Federated tier proposals](federated-tier-rules.md) and the
[WP F acceptance record](../runbooks/federated-tier-acceptance.md) for integrated
callback/review/approval evidence and the separate open Gate F requirements.

Federation-policy reconciliation and live session checks are described under [Lifecycle](#lifecycle). Browser/SP/IdP behavior remains an operational verification requirement.

## Limitations

There is no password-age reminder or self-authorized lost-admin-factor recovery. Per-field metadata visibility and row-level security are described in the [field-policy contract](field-visibility.md). Lost-factor recovery needs another eligible administrator and a retained code; otherwise use the controlled operator procedure in [Deployment](../../Deployment.md). SP installation, federation registration, and real-browser MFA/logout checks are deployment work, not application guarantees.

## Session-owned authenticator enrollment

A pending enrollment or recovery seed belongs to the session that created it.
Only that live session may display or confirm it or replace its staged recovery
codes. A separate browser session receives no factor material. If the creator
session expires or is removed, another eligible setup must generate a fresh
seed and recovery-code set; it never inherits the abandoned factor. Pending
material also expires after ten minutes.

Successful initial enrollment activates the factor and staged recovery codes,
advances the account revision and revokes every existing session in one
transaction. The response clears authentication cookies and returns to login.
A copied setup token cannot acquire full authority when the owner finishes.
Recovery completion follows the same fresh-login requirement.

## Owner security-change notifications

Authenticator enrollment and rotation, recovery authorization/redemption/
completion, and acceptance of administrator privileges queue a fixed owner
notice in the same transaction as their successful state change. Rejected or
rolled-back transitions queue no notice. Reissuing an already active recovery
authorization does not repeat its notice. The encrypted outbox retries delivery;
SMTP acknowledgement does not provide exactly-once delivery.

Notices use the account's stored address and contain no passwords, authenticator
seeds, recovery codes or bearer capabilities. An outbox insert failure rolls
back the associated authority change. Owners should contact the configured
support address immediately if a notice describes an unexpected change.
