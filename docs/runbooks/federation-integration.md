# Integrating a Shibboleth SP with the fixed header contract

Keep federation closed until the gates below pass on the intended host. Record
SP/module versions, registration, attribute release, MFA and rollback results
in a protected change record; repository tests do not certify a live deployment.

The application consumes trusted HTTP facts; it does not validate SAML. The SP
must verify signatures, metadata trust, audience, destinations, time bounds and
session assurance before its authorizer exports any identity. nginx then copies
only reviewed SP output through the fixed private header contract. There is no
email-domain, client-IP or ordinary request-header shortcut into that boundary.

## Decisions before installation

Complete these placeholders in the restricted deployment record, not in public
source. Example domains below are illustrations, not approved production values.

| Decision | Operator value and required evidence |
|---|---|
| Public application origin and SP entity ID | `<archive-origin>` and `<sp-entity-id>`; validated HTTPS origin, matching TLS and registered metadata |
| IdP and federation registration | `<exact-idp-entity-id>`, `<registration-process>`, `<metadata-trust-source>`; authoritative metadata and approval |
| Supported edge build | `<sp-version>`, `<nginx-version>`, `<module-version>`, `<package-provenance>`; compatibility and configuration verification |
| Stable subject | `<persistent-subject-contract>`; non-reassignment guarantee, release and alias mapping |
| Required attributes and MFA | `<release-evidence>` and `<mfa-evidence>`; observed release and exact authentication context |
| Service identities and sockets | `<effective-nginx-worker>`, `<authorizer-identity>`, `<responder-identity>`, `<unrelated-test-uid>`; positive and negative filesystem admission |
| Private configuration custody | `<secret-custodian>` and `<reviewed-change-record>`; restricted files and independent recovery |
| Activation and rollback | `<operators>`, `<approved-window>`, `<canary-account>`, `<rollback-evidence>`; second review and recorded outcomes |

Use the [deployment policy](../configuration/deployment.md),
[tier-proposal contract](../architecture/federated-tier-rules.md),
[application acceptance record](federated-tier-acceptance.md),
[email-reservation contract](federated-reservations.md) and
[key-rotation procedure](key-rotation.md) alongside this runbook.

## Identity and authority contract

Identity is the exact `(issuer, subject)` pair. Require an absolute HTTPS issuer
that exactly matches `SHIBBOLETH_TRUSTED_ISSUERS`, a persistent non-reassigned
subject and exactly `https://refeds.org/profile/mfa`. Do not substitute email or
a mutable/recyclable login name for the subject. The shipped alias is
`eduPersonUniqueId`; verify its semantics and actual release with the operator.
The issuer is the authenticated SP session's issuer, never a guessed email
domain, discovery choice, affiliation or Host header.

A first eligible assertion creates a fresh pending, public, inactive, nonadmin,
unverified federated row, with no session and no approval actor/time. A dedicated
administrator approval must re-match the exact pair and current review revision,
choose the tier independently of the advisory proposal, activate the account,
record actor/time, advance `auth_revision` and purge target sessions atomically.
Only a subsequent matching assertion may issue a full session. Generic tier,
administrator and reactivation actions cannot approve pending identities.

An unverified nonadmin local reservation may be replaced only under the guarded
email-reservation contract, with a fresh federated account and no transferred
credentials. Other account/email conflicts fail closed. Never merge a verified
local account, administrator, different federated pair or retained historical
identity merely because its email matches. Federated authentication does not
establish local mailbox verification. Proposal rules never grant authority;
later proposal changes flag review without changing assigned tiers or sessions.

Retained historical identities need a separate reviewed conversion/import plan,
executed only through the static/manual migration unit while federation remains
closed. Every converted row must enter pending/public/inactive/nonadmin/unverified
state with both approval fields null. Advance `auth_revision` and revoke all
target sessions atomically in the same authority transition. Ambiguous or
unresolved pairs stay outside the serving account set. Verify those postconditions
and preserve the working local administrator before activation. Startup policy
reconciliation does not establish or approve identities, and a trusted pair alone
does not permit preserving imported authority. This runbook supplies no automatic
conversion, schema reset or retained-database migration.

## Fixed header map

The header names are fixed in code and are not configurable. Limits count decoded
characters, not UTF-8 bytes. Required claims must occur exactly once and be
nonempty; an optional claim may be absent or empty. Supplied fields must satisfy
duplicate, strict UTF-8, printability and size checks. Identity/security scalars
also reject ambiguous comma coalescing and surrounding whitespace. Optional
entitlement is a bounded escaped serialization, not an arbitrary comma-split
list; use the proposal contract's decoding rules.

<!-- FEDERATION_HEADER_MAP_START -->
| Header | Required | SP/nginx source | Decoded character limit |
|---|---|---|---|
| `X-OHA-Internal-Auth` | yes | Root-only include; same independent `SHIBBOLETH_INTERNAL_SECRET` | 1024 |
| `X-OHA-Shib-Issuer` | yes | `$oha_shib_issuer` from `$upstream_http_variable_shib_identity_provider` | 2048 |
| `X-OHA-Shib-Subject` | yes | `$oha_shib_subject` from `$upstream_http_variable_edupersonuniqueid` | 512 |
| `X-OHA-Shib-Mail` | yes | `$oha_shib_mail` from `$upstream_http_variable_mail` | 320 |
| `X-OHA-Shib-Authn-Context` | yes | `$oha_shib_authn_context` from `$upstream_http_variable_shib_authncontext_class` | 1024 |
| `X-OHA-Shib-Display-Name` | no | `$oha_shib_display_name` from `$upstream_http_variable_displayname` | 200 |
| `X-OHA-Shib-Affiliation` | no | `$oha_shib_affiliation` from `$upstream_http_variable_affiliation` | 512 |
| `X-OHA-Shib-Entitlement` | no | `$oha_shib_entitlement` from `$upstream_http_variable_entitlement` | 4096 |
| `X-OHA-Shib-Country` | no | `$oha_shib_country` from `$upstream_http_variable_schachomeorganizationcountry` | 128 |
<!-- FEDERATION_HEADER_MAP_END -->

Require every ordinary application proxy, including `/health` and any enabled
`/health/detail` location, to load the ordinary clearing include. It clears all
nine private headers and the legacy/raw names, including `eduPersonEntitlement`
and `entitlement`. Never consume raw legacy attributes in application code.

The sole exact `/auth/shibboleth/callback` location must use `satisfy all`,
`shib_request /shibauthorizer`, `shib_request_use_headers off` and
`proxy_pass_request_headers off`. Explicit assignments overwrite every private
claim from SP variables. The Cookie header is the sole retained client header;
Host and forwarded address/scheme are explicitly assigned by nginx. The internal
credential is supplied by the root-only include. Do not enable ambient module
header copying or forward client identity headers to this location.

Use the tracked `deploy/nginx-ordinary-proxy-headers.conf.example`,
`deploy/nginx-shibboleth-phase2.conf.example` and
`deploy/nginx-shibboleth-secret.conf.example` as the reviewed source. Compare the
actual installed fragments against the tested release, including all explicit
assignments. Do not reconstruct the callback from a shortened example. The
responder uses `/run/shibboleth/shibresponder.sock`; the internal-only
`/shibauthorizer` uses `/run/shibboleth/shibauthorizer.sock`. If paths change,
review and verify both ends and the effective configuration.

## Bound work before the SP

Both public Phase-2 locations apply dedicated admission limits before expensive
SP processing. `/Shibboleth.sso/` calls the responder directly; the callback calls
an internal authorizer before it reaches FastAPI. Application limits cannot
protect that earlier work. Keep `/shibauthorizer` internal, and place admission
on the public parent requests rather than relying on limits on a subrequest.

The zones in `deploy/nginx.conf.example` and directives in the complete Phase-2
fragment establish these initial budgets:

| Budget | Initial value | Scope |
|---|---|---|
| Request rate | 2 requests/s, burst 10 | One client address, shared across both public SSO locations |
| Aggregate request rate | 10 requests/s, burst 20 | The configured virtual host, shared across both locations |
| Concurrent requests | 8 | One client address |
| Aggregate concurrent requests | 16 | Both public SSO locations combined |
| Request body | 64 KiB | Both public locations; responder buffers the request before FastCGI |
| Client headers | 10 seconds; 1 KiB initial buffer and four 8 KiB large buffers | HTTPS server |
| Client body and response inactivity | 10 seconds | Both public locations |
| FastCGI connection | 1 second | Responder and internal authorizer |
| FastCGI send/read inactivity | 5 seconds | Responder and internal authorizer; upstream retries disabled |

These are deployment starting points, not measured SP throughput. The aggregate
key uses nginx's configured `$server_name`, not an attacker-supplied Host or
forwarding header. The zones share counts across workers of one nginx instance.
Multiple edge instances require a shared upstream admission budget or a partition
of the deployment-wide capacity across instances. Do not multiply the allowance
by adding another edge without reviewing the combined bound.

FastCGI send/read timeouts bound idle intervals, not total execution time. Set
and verify the SP services' worker/concurrency and queue limits, process memory
limits, and supported operation deadlines. Include slow-client and client-abort
cases: closing nginx's upstream socket does not itself prove SP execution stops.
Choose the aggregate concurrency and request rate below measured sustainable SP
capacity with room for administrative and recovery work. Request buffering and
body bounds keep incomplete or oversized bodies away from the responder, while
header/body timeouts also bound clients not yet counted by `limit_conn`.

Before activation, retain a sanitized acceptance record proving all of these:

- `nginx -t` succeeds with the actual Shibboleth module, and a root-only review of
  `nginx -T` confirms both public locations use both request zones and both
  connection zones, the authorizer is internal, and all timeouts/body budgets
  remain effective. Do not retain secret-bearing configuration output.
- A legitimate login/logout flow and expected university-NAT bursts pass,
  including the largest approved SAML message. Raise a budget only after
  repeating the capacity measurements; do not disable admission to pass a test.
- Excess requests and excess simultaneous requests receive 429 before either
  SP socket is contacted. Check backend invocation counters, not just HTTP
  status. Exercise each location separately and both together, from one address
  and rotating addresses, and verify the shared aggregate ceiling.
- Oversized bodies return 413 before responder work. Slow bodies, stalled SP
  responses and client disconnects release bounded resources; another client
  recovers after the in-flight requests finish or their deadlines expire.
- Direct `/shibauthorizer` access remains 404. Neither a denial nor an SP outage
  grants an application session or bypasses the existing header/secret checks.

The repository's nginx tests execute the shipped admission directives against
counted FastCGI test backends. Where the Shibboleth module is unavailable, a
separately identified `auth_request` access-phase stand-in tests ordering; that
result does not certify a live SP/module installation. The retained host test
with its installed module and real SP remains an activation requirement.

Using the repository's disposable test Redis configuration, run the real-module
variant with the installed dynamic-module path (`builtin` for a statically
compiled module). `REQUIRE_NGINX_SHIBBOLETH=1` makes a missing module fail:

```bash
REQUIRE_NGINX=1 REQUIRE_NGINX_SHIBBOLETH=1 \
NGINX_SHIBBOLETH_MODULE=/usr/lib/nginx/modules/ngx_http_shibboleth_module.so \
uv run pytest -q src/tests/unit/test_nginx_contract.py \
  src/tests/unit/test_nginx_federation_admission.py
```

## Configure the SP

Keep `SHIBBOLETH_ENABLED=false` and the original exact nginx callback's direct
`return 404` during initial setup. Install the supported SP, `shibd`, FastCGI
authorizer/responder services and compatible nginx module from approved sources.
The `shib_request*` directives require the separately supplied
nginx-http-shibboleth module; a stock nginx syntax check does not validate that
integration. Package names, service units and socket ownership depend on the
reviewed platform. The FastCGI applications need managed services; installing a
package alone does not prove they are running safely.

The following is a complete example `ApplicationDefaults` element, not a
replacement for the installation's complete `shibboleth2.xml`. Resolve the
metadata, certificate/key, request-map and access-control configuration against
the installed SP version. Preserve required metadata validation and trust.
Replace the two example entity IDs with the approved values from the record.

```xml
<ApplicationDefaults entityID="https://archive.example.org/shibboleth"
                     REMOTE_USER="eduPersonUniqueId"
                     signing="true"
                     encryption="true">
    <Sessions lifetime="28800" timeout="3600"
              checkAddress="false"
              handlerSSL="true"
              redirectLimit="exact"
              relayState="ss:mem"
              cookieProps="https">
        <SSO entityID="https://idp.example.org/idp/shibboleth">SAML2</SSO>
        <Logout>SAML2 Local</Logout>
        <Handler type="MetadataGenerator" Location="/Metadata" signing="true"/>
    </Sessions>
    <AttributeExtractor type="XML" validate="true" path="attribute-map.xml"/>
</ApplicationDefaults>
```

Protect the callback in the SP request map using both `authType="shibboleth"`
and `requireSession="true"`; the FastCGI authorizer can otherwise ignore an
unprotected path. Request
`authnContextClassRef="https://refeds.org/profile/mfa"` with exact comparison,
and enforce the same context with the installed SP's access-control policy.
Verify its precise XML syntax for that version. A login-button parameter or a
registration checkbox does not enforce assurance on direct SP handler requests.
Password-only assertions must not authorize the callback.

`redirectLimit="exact"` restricts handler redirects to the exact request origin;
verify that this is the intended validated public HTTPS scheme, host and port
behind the actual proxy topology. `relayState="ss:mem"` keeps return targets in
server-side storage. Send off-origin `target` and `return` values to
`/Shibboleth.sso/Login` and `/Shibboleth.sso/Logout` in staging; neither
request-supplied value may select an unapproved off-origin return or redirect
destination. Approved SP-to-IdP protocol redirects are distinct from untrusted
return targets. Direct handler requests require the same policy as the UI.

With valid CSRF proof, `POST /logout` first deletes the presented application session; a deletion
failure propagates before cookie clearing. With `SHIBBOLETH_ENABLED=true`, every
caller, including local and anonymous callers, receives the fixed
`/Shibboleth.sso/Logout` redirect with its return URL derived only from validated
`PUBLIC_BASE_URL`. That fixes the application's handoff, not the eventual
IdP/global-logout result or final browser destination. With the flag false, the return is `/`. Query parameters never
choose this target. The login UI requests `forceAuthn=true` as defense in depth,
but a query parameter in HTML is not an authentication boundary.

Verify SP local-session termination and the IdP's actual logout/fresh-user-gesture
behavior, including direct login-handler requests omitting `forceAuthn`. If
reliable global logout is unavailable, shared-browser use must be prohibited
and user guidance must require IdP logout plus browser closure. Application
cookie deletion and SP local logout alone do not prove upstream SSO ended.
The MFA context alone also does not prove fresh interaction; an existing MFA
session can be reused unless the effective authentication policy prevents it.

## Registration and attribute release

1. Register the approved SP entity ID and metadata using `<registration-process>`.
   Verify the metadata trust source, signatures, rollover and renewal ownership.
2. Request the persistent subject and required `mail` attribute, plus optional
   `displayName`, `affiliation`, `schacHomeOrganizationCountry` and only the
   entitlement values needed for reviewed proposal rules. Configure
   `eduPersonEntitlement` with the SP attribute-map alias `entitlement` used by
   the shipped nginx fragment. Missing entitlement is valid but cannot satisfy
   a rule that requires it.
3. Verify each actual attribute alias and `$upstream_http_variable_*` export on
   the exact installed module/SP build. A request for release is not proof of
   release. The mandatory mail field remains required even though it is not an
   identity key or local mailbox-verification proof.
4. Establish the authoritative exact HTTPS issuer and non-reassignment contract.
   Require the exact REFEDS MFA result and test failure of weaker assurance.
5. Retain minimized pass/fail evidence and version/configuration identifiers in
   the restricted record. Do not publish raw assertions or an attribute dump.

## Socket and credential boundary

Gunicorn must listen only at `/run/oralhistarchiv/gunicorn.sock`. Its parent and
socket must be `0750` and `0660`, owned under the reviewed web/proxy identities.
Inventory the effective nginx worker UID, supplementary groups, ACLs and every
other process using that UID or proxy group. A scheduler or unrelated process
must not share the proxy authority. If the worker account runs unrelated jobs,
use an isolated worker identity/instance before granting membership. The
callback rejects TCP peers, but that topology tripwire does not replace socket
permissions, the authorizer, header replacement or secret custody.

Inspect `systemctl cat/show`, `namei -l`, `stat`, `getfacl`, `ss -ltnp` and the
relevant `/proc` process/group state. First prove that the intended worker can
fetch `/health` over the Unix socket as `<effective-nginx-worker>`, using
`sudo -u` and `curl --unix-socket` with the configured Host. Then prove the scheduler and
`<unrelated-test-uid>` cannot connect to the same known-working socket. A failed
request without a positive control is not an ACL test. Never grant them access
or enable a Gunicorn TCP listener to make acceptance convenient.

Generate an independent high-entropy internal value equivalent to
`secrets.token_urlsafe(64)` through the approved secret workflow. Place the same
value only in the root-owned mode-`0600` nginx secret include and web-only
`/etc/oralhistarchiv/shibboleth.env`. Treat it as an arbitrary federated
impersonation credential. Do not print it, pass it on a command line, put it in
Git or expose it through `nginx -T` evidence. The tracked secret example is only
a placeholder. The web overlay, loaded after the common environment, contains:

```dotenv
SHIBBOLETH_ENABLED=false
SHIBBOLETH_INTERNAL_SECRET=<independent-value-matching-the-nginx-include>
SHIBBOLETH_TRUSTED_ISSUERS='["https://idp.example.org/idp/shibboleth"]'
FEDERATED_TIER_RULES='[]'
```

The common environment retains the disabled default and no callback secret.
The scheduler neither loads the overlay nor receives the credential. systemd's
root manager reads the restricted environment before dropping privilege; do not
make the file readable by service accounts. Check environment-file references
and secret presence/absence without printing matching values. The optional
advisory rule list belongs in the reviewed web environment; changes require web
restart and subsequent assertions to refresh stored observations.

## Ordered pre-flip checklist

All ten gates must pass before the production application flag changes. Record
actual results and an independent review, preserving a working local
administrator with TOTP and recovery codes throughout.

1. **Closed starting state.** `SHIBBOLETH_ENABLED=false`; the public callback is
   the exact nginx `return 404`; the common environment has no internal secret.
2. **Release and retained identities.** Verify the matching release, schema and
   runtime grants. Retained prototype identities need a reviewed migration/import,
   authoritative pairs and session revocation; never infer or merge by email.
   Start current code with federation disabled and confirm fingerprint
   reconciliation and federated-session revocation.
3. **SP services.** Verify SP/module provenance, configuration syntax, service
   accounts, sockets, metadata trust and authorizer failure behavior. The SP
   authorizer must not become optional if it stops or denies the request.
4. **Identity, MFA and handlers.** Verify persistent subject, exact issuer,
   actual release, exact MFA, weaker-context rejection, redirect confinement and
   logout/fresh-gesture behavior using an operator-only diagnostic or equivalent
   isolated staging. Prohibit shared browsers when the required guarantee fails.
5. **Header replacement.** Inspect every ordinary proxy and the sole callback
   against the fixed header map, including optional entitlement. Require
   `satisfy all`, ambient copying off and general request headers off. Client
   private/raw/duplicate identity headers must not influence SP-derived claims.
6. **Unix boundary.** Verify `0750`/`0660`, effective groups and ACLs; require the
   intended proxy's positive control, scheduler/unrelated-UID refusal and no
   Gunicorn TCP listener. Document every principal with equivalent socket access.
7. **Independent credential.** Provision only the two restricted locations,
   prove scheduler absence, restart web with the flag false and callback still
   closed, and verify successful fingerprint reconciliation. Do not log its value
   or export the policy digest.
8. **Executable regressions and staging.** Run the repository's header, nginx,
   authentication, review, reservation, session-policy and logout tests plus the
   negative matrix below against the real SP boundary. Include pending enrollment,
   exact-pair approval, stale review and both stale-policy reconciliation races.
   Synthetic callback headers are application evidence only.
9. **Edge integration while disabled.** Install the complete reviewed fragments;
   replace the original callback with one Phase-2 include in the HTTPS server.
   Never supplement it with a second exact callback. Run `nginx -t`, reload and
   review effective `nginx -T` under controlled root access without retaining
   secret-bearing output. Confirm authorizer enforcement, ordinary clearing and
   exactly one callback. Verify the still-disabled app issues no session. These
   callback/handler locations must carry the fragment's explicit per-client
   and aggregate SSO budgets; sibling `location /` controls do not apply.
   Complete the pre-SP capacity, NAT-burst and rejection-before-backend checks
   above before opening the locations to public traffic.
10. **Independent release approval.** A second operator reviews exact issuer,
    assurance, mappings, modes, services, identity reconciliation, tests and
    rollback readiness. Approve the application flag change as its own final
    operational change. Unfilled evidence blocks activation.

Only after those gates pass, edit the web overlay to
`SHIBBOLETH_ENABLED=true` and restart web under the approved change. Do not
restart or add credentials to the scheduler for this purpose. Enabled startup
requires the independent credential, nonempty exact issuer allowlist, hardened
HTTPS public origin, secure cookies and allowed hosts in every environment.
The changed policy fingerprint revokes federated sessions atomically; local
sessions are unaffected. Review revisions still protect individual approvals.

## Negative tests and controlled canary

Run destructive identity/approval/race variants only in disposable staging, with
synthetic accounts and no real user attributes in captured output. Public probes
contain deliberately false values, never the actual credential. The closed edge
returns `404`; an enabled SP may redirect unauthenticated callers to login, so
the public negative invariant is **no application session or authority** rather
than one universal status. Application-level header rejections redirect to login;
the service layer rejects account conflicts without granting authority.

<!-- FEDERATION_NEGATIVE_MAP_START -->
| Case | Expected result | Evidence |
|---|---|---|
| `disabled` | Closed edge gives 404; disabled application never issues a federated session | Edge request and callback unit/client tests |
| `tcp-peer` | A direct TCP callback cannot authenticate even with shaped claims | Callback peer test; no Gunicorn TCP listener on the actual host |
| `client-header-spoof` | Private and raw identity/entitlement input cannot replace SP output on ordinary proxies or callback | Fragment pins plus public staging probes with false headers |
| `missing-required` | Each missing/blank required header refuses before identity writes | Parametrized callback tests; required-attribute release negative |
| `duplicate-header` | Duplicate security and optional claims fail closed; coalesced identity scalars are rejected | Raw callback header tests and installed edge interpretation |
| `malformed-header` | Invalid UTF-8, nonprintable or oversized claims cannot authenticate | Callback bounds tests and header-map drift checks |
| `wrong-secret` | Missing/wrong internal credential never reaches the identity service | Callback unit/client tests; no real credential in a public probe |
| `untrusted-issuer` | A different, lookalike or unapproved issuer is rejected | Exact issuer tests and authoritative SP session observation |
| `non-mfa` | Password-only or different assurance cannot authorize the callback | Application tests plus real SP/IdP weaker-context test |
| `optional-entitlement` | Missing/empty optional entitlement is valid; raw aliases cannot inject a proposal and malformed supplied input fails | Entitlement/header tests and reviewed rule no-match control |
| `email-collision` | Only the guarded nonadmin unverified reservation can be replaced; other email collisions refuse without merging or credential transfer | Reservation and exact-identity integration tests |
| `stale-review` | Changed observation invalidates an old approval; generic mutations cannot approve pending accounts | Review/approval integration tests |
| `stale-policy` | Reconciliation deletes a prior worker's committed session; an old worker ordered afterward cannot write identity or issue a session | Both policy race integration cases |
| `off-origin-redirect` | External target/return values on either SP handler cannot select an external origin | Real staging Login/Logout handler probes |
| `logout` | Presented session deletion and cookie clearing precede the fixed SP handoff whenever enabled; disabled return is / | Auth-route tests plus real SP local/IdP logout and fresh-gesture checks |
<!-- FEDERATION_NEGATIVE_MAP_END -->

Immediately after the approved flip, use the controlled canary identity:

1. Confirm a new exact pair reaches pending/public/inactive/nonadmin/unverified
   state, stores the trusted review/proposal and emits no full session.
2. Use only the dedicated administrator approval for that exact pair and current
   review revision. Choose the tier explicitly; retain minimized actor/time and
   proposed-versus-chosen audit evidence. Confirm revision advance and purge of
   target sessions. This approval requires enabled, currently trusted federation.
3. Repeat the same pair's assertion and confirm a full session at only the
   assigned tier. In staging, prove proposal drift flags review without changing
   authority, approval metadata or existing sessions. A changed review must
   reject an older form even if the resulting proposal is unchanged.
4. Complete logout and fresh-gesture tests. On any unexpected result, close the
   edge, disable the flag under current code and follow the rollback boundary.
   A failed canary does not justify weakening identity, assurance or approval.

## Federation rollback boundary

Revision `4f73ae3ff827` is the initial schema; its downgrade drops application
tables. No earlier compatible release is supplied. Keep federation closed while
using a separately reviewed restore or forward-repair plan:

1. Replace the Phase-2 callback/include with the original exact `return 404`
   location. Run `nginx -t`, reload and verify public callback 404. Confirm no
   other effective location proxies an assertion into the application.
2. Set `SHIBBOLETH_ENABLED=false` while current code is still installed and
   restart web. Require successful committed policy reconciliation, then verify
   zero sessions owned by Shibboleth users. Preserve local administrator access.
3. Remove `/etc/oralhistarchiv/shibboleth.env` and the nginx secret include only
   after the effective unit/configuration no longer references them. Verify the
   disabled common policy, test/reload nginx as needed and restart web so no
   stale environment remains. Do not print the credential in the change record.
4. Enter maintenance, stop web and scheduler, and execute the release's reviewed
   repair/restore plan; do not run an ad-hoc Alembic downgrade. Reapply the
   matching runtime grants and deploy code compatible with the resulting schema.
5. Verify local-only operation and callback 404. Federation must never be
   re-enabled until the complete acceptance gates pass again on the recovered
   release. Restore data only under the reviewed isolated recovery procedure.

Use a read-only authorized diagnostic connection for the revocation check:

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT count(*) AS federated_sessions
FROM sessions
JOIN users ON users.id = sessions.user_id
WHERE users.auth_method = 'shibboleth';
COMMIT;
```

Expect zero only after successful disabled-policy reconciliation. A query is not
a substitute for the transition. If web cannot start/reconcile, keep it stopped
and use the reviewed revocation/repair procedure; do not reopen or downgrade.

**Suspected credential disclosure is a separate emergency:** follow the
[key-rotation incident procedure](key-rotation.md) that stops web and verifies
socket closure before edge or configuration changes. Closing the public callback
alone cannot contain a credential holder that can reach the application socket.

## Evidence record

| Item | Restricted evidence reference |
|---|---|
| Reviewed source and complete CI checks | `<source-commit>` and `<required-check-references>` |
| SP/module build, metadata trust and registration | `<version-and-registration-evidence>` |
| Exact issuer, persistent subject, aliases and actual release | `<minimized-release-evidence>` |
| MFA, negative matrix, handler confinement and logout | `<staging-results>` |
| Effective nginx config review, socket permissions and credential custody | `<host-boundary-results>`; no secret-bearing config output |
| Final independent approval and canary | `<activation-approval>` and `<canary-results>` |
| Rollback rehearsal and recovery compatibility | `<rollback-results>` |

Unfilled entries block activation. Retain actual host evidence separately from
`scripts/check-no-site-refs.sh`, page-neutrality tests and the opaque-reference
scan. Complete the [release qualification and publication gate](before-staging-handoff.md#qualify-the-artifact-using-the-existing-release-path);
repository checks do not establish live SP behavior.

## Primary configuration references

- [SP session and redirect configuration](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334342/Sessions)
- [SP attribute access and export](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335257/AttributeAccess)
- [SP request-map content settings](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334723/ContentSettings)
- [SP asserted-context access-control rule](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335141/Rule)
- [SP logout configuration](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334353/Logout)
- [nginx module configuration and FastCGI integration](https://github.com/nginx-shib/nginx-http-shibboleth)
- [REFEDS MFA profile](https://refeds.org/profile/mfa)

Use the documentation matching the installed supported versions. These references
describe configuration; only the recorded host tests demonstrate its effective
behavior on a deployment.
