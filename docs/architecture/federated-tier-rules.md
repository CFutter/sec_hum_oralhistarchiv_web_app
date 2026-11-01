# Federated tier proposals

**Status: F1–F3 application acceptance complete; final source/check references open; Gate F open.**
Validated ordered rules produce advisory proposals from trusted assertions.
F2 stores the latest proposal and review attributes, presents them to an
administrator, binds explicit approval to the current review revision and
flags later proposal changes. No rule grants a tier or approves an identity.
F3 joins the real HTTP callback, administrator view, manual approval and audit
against PostgreSQL. The [acceptance record](../runbooks/federated-tier-acceptance.md)
separates that application evidence from final source/CI references and the
still-open operational Gate F.

## Configuration and matching

`FEDERATED_TIER_RULES` is a JSON list loaded into an immutable ordered tuple.
It defaults to `[]`. A rule has exactly `match` and `tier`; the match object
contains at least one of `issuer`, `affiliation` and `entitlement`:

```json
[
  {
    "match": {
      "issuer": "https://idp.example.org/idp/shibboleth",
      "entitlement": "urn:example:archive:vetted"
    },
    "tier": "vetted"
  },
  {
    "match": {
      "issuer": "https://idp.example.org/idp/shibboleth",
      "affiliation": "member",
      "entitlement": {"prefix": "urn:example:archive:"}
    },
    "tier": "registered"
  }
]
```

Rules are evaluated in list order. Every supplied predicate in one rule must
match; the first matching rule wins. No matching rule produces no proposal,
which is distinct from a matched rule proposing `public`. The only tiers are
the canonical `public`, `registered` and `vetted` values.

Issuer and affiliation predicates use case-sensitive exact equality. The issuer
must be an absolute HTTPS entity ID; a rule does not add an issuer to the
callback's trusted allowlist. Affiliation uses the current normalized scalar
profile value, without splitting it into values. Entitlement is either an exact
string or an object containing only a nonempty `prefix`. Prefix matching applies
to one complete decoded entitlement value with `startswith`; it does not cross
value boundaries. There is no inferred wildcard, regex, substring or case-folded
matching. An asterisk in an exact string is a literal character.

Unknown keys, empty match objects, explicit null/blank predicates, malformed
structures, noncanonical tiers and coercions such as booleans are refused.
Match strings must be printable, without surrounding whitespace or commas.
Issuer, affiliation and entitlement limits are 2048, 512 and 4096 characters
respectively. Environment and dotenv input must be a JSON array: null or empty
text, duplicate object keys and nonfinite numeric constants are refused.
Malformed rules fail settings construction even while federation is disabled.
Use a reviewed rule list; there is no rule-count tuning setting.

## Trusted entitlement input

The callback accepts optional `X-OHA-Shib-Entitlement` through the same fixed
header reader as other optional claims. It rejects duplicate headers, invalid
UTF-8, nonprintable text and raw values above 4096 decoded characters before
constructing a principal. The principal retains the full escaped serialization
after stripping outer whitespace; whitespace-only input becomes absent. After
all trust and current-policy checks, the login transaction stores this bounded
normalized serialization in the separate administrator review observation.

The supplied nginx fragment reads the SP attribute-map alias `entitlement` as
`$upstream_http_variable_entitlement` and overwrites the private header. Ordinary
proxy locations clear that private header and the raw `eduPersonEntitlement`
and `entitlement` names. Confirm the actual installed attribute release and
mapping during Gate F. A client header, issuer-shaped string or rule match does
not authenticate a principal; the proxy credential, exact trusted issuer and
fixed MFA assurance remain mandatory.

The matcher interprets the SP's serialized entitlement values as follows:

- An unescaped semicolon separates values. `\;` represents a literal semicolon;
  `\\` represents a literal backslash.
- Values retain their case and order. No trimming or case folding creates a
  match. Exact and prefix predicates are checked against individual decoded values.
- Missing or empty input yields no entitlement values and cannot satisfy an
  entitlement predicate. A rule that does not require entitlement may still match.
- Empty elements, unknown or trailing escapes, surrounding whitespace overall
  or within a decoded element, commas, controls and oversized input make the
  serialization malformed. Malformed serialization yields no proposal globally.

The separator convention follows the SP3
[attribute export contract](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335257/AttributeAccess).
The application explicitly supports only the two escapes above; verify the
configured SP output rather than relying on ambiguous export formatting.

## Public foundation API

`app.federated_tier_rules` owns the strict immutable rule models and these pure
interfaces:

- `parse_federated_entitlements(value)` returns the ordered decoded tuple, an
  empty tuple when absent, or `None` for malformed serialization.
- `propose_federated_tier(rules, *, issuer, affiliation=None, entitlement=None)`
  returns `None` or a `FederatedTierProposal` containing `tier`, a one-based
  `rule_index` and the immutable matched rule.
- `proposal.rule_snapshot` returns a fresh JSON-compatible object with `index`,
  `match` and `tier`. Mutating that object cannot change configured rules.

The matcher has no database, session or audit side effects. Its caller supplies
trusted assertion inputs only after the existing authentication checks.
Configuration changes require restarting the web process to load the new
immutable rules; the advisory rules are excluded from the federation-session
authority fingerprint and do not revoke sessions. Stored observations refresh
on a later trusted assertion, not when a configuration file changes.

## Stored observation and explicit review

`finalize_shibboleth_login()` rechecks the principal and persisted federation
policy, provisions or locks the exact identity, and records its latest proposal
in the same transaction. An untrusted assertion or policy mismatch cannot write
a review. Email conflicts and transaction failures cannot leave a partial
observation behind. New identities remain public, inactive, nonadmin,
unverified and sessionless. Pending and disabled identities may refresh only
the separate review observation; their existing profile and authority stay
unchanged. Active approved identities keep the ordinary profile refresh and
session-creation behavior.

The `users` table stores three review fields:

| Field | Meaning |
|---|---|
| `federated_review` | Latest trusted normalized issuer, affiliation, escaped entitlement serialization, and proposal snapshot; SQL NULL means no observed assertion. |
| `federated_review_revision` | Zero before an observation; advances when the observation changes. An identical observation retains the revision. |
| `federated_approved_proposal` | The proposal reviewed at dedicated approval, wrapped as `{"proposal": ...}`. A null proposal explicitly records no matching rule; SQL NULL means no stored approval baseline. |

The separate `app.services.federated_review` administrator projection keeps
these attributes out of session `User` snapshots. The administrator page shows
the latest accepted values as autoescaped text, the proposed tier and complete
matched rule including its one-based index. No match is labelled explicitly;
it is distinct from a rule proposing `public`. This is the current observation,
not a history of every assertion. The catalogue-only classification matrix does
not classify these account attributes; account retention and access controls
continue to apply.

An eligible administrator must verify enrollment and submit the dedicated
approval form. The chosen tier defaults to `public`, independently of any
proposal. Approval locks and rechecks the current policy, administrator session,
exact issuer/subject, pending state and the submitted review revision. A changed
observation, including changed attributes with the same proposal, invalidates
an older form. A row with no observed trusted assertion cannot be approved.
Approval retains the reviewed proposal, assigns only the explicitly chosen
tier, records approver/time, advances `auth_revision` and deletes prior target
sessions atomically. Only a later trusted assertion can establish a session.

The approval result carries the proposed tier/rule from the locked committed
review. The route audits that result alongside the chosen tier and existing
actor/time metadata; raw assertion attributes and the subject identifier do not
enter the approval audit event.

## Later proposal changes

A mismatch compares the latest proposal snapshot with the proposal retained at
approval. It does not compare the proposed tier with `access_tier`: an
administrator may deliberately choose a different tier. The comparison includes
the matched rule and its index, so a changed matching rule can be flagged even
when it proposes the same tier. No-match to matched `public`, and the reverse,
are changes. A legacy approved identity without a stored baseline is not
silently assigned one by a later login.

The administrator page flags a mismatch for approved or disabled identities.
It does not automatically change tier, admin status, approval actor/time or
session eligibility, and it does not revoke existing sessions. There is no
background re-evaluation; the latest trusted assertion supplies the observation.
An administrator investigates the change and uses the existing explicit
authority controls as appropriate.

## Schema and acceptance record

The three columns and their state constraints are part of fresh-install initial
revision `4f73ae3ff827`. `upgrade head` does not rerun a revision already recorded
in an older database; stamping cannot install changed columns. Rebuild disposable
test databases and each parallel worker database from the current baseline.
Retained development or historical data requires a separately reviewed conversion
or isolated import plan. Neither the application nor the tests/docs updater
recreates databases. See [Data model](data-model.md).

F1–F3 are accepted application checkpoints. The
[WP F evidence record](../runbooks/federated-tier-acceptance.md) retains integrated
callback-to-review acceptance and the outstanding final commit/check references.
Complete the formal record without another implementation batch. Deployment-side
Gate F remains open until its operator evidence and activation dependencies pass.

Automatic approval is not planned for 1.0.0. A possible later opt-in extension
remains outside WP F's accepted proposal-only design. Broader federation
activation still requires the installed SP, approved registration and attribute
release, missing/duplicate/spoofed/wrong-issuer/non-MFA checks, manual approval,
controlled real MFA login and rollback evidence. Keep the callback disabled
until its complete deployment acceptance procedure passes.

See [Authentication](auth.md), the [settings reference](../configuration/settings.md)
and the [deployment checklist](../configuration/deployment.md) for the current
trust boundary. Synthetic rule and
header tests do not certify a live IdP's release or production Gate F.
