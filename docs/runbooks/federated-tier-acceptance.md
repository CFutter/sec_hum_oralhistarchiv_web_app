# Federated tier acceptance

**Status: F1–F3 application acceptance complete; final source/check references open; Gate F open.**
The application implements WP F's proposal-only rules, trusted entitlement
input, stored review, dedicated manual approval and later mismatch display.
F3 joins those boundaries through real HTTP routes, middleware and PostgreSQL.
Retain the exact final source and required-check references below to close the
application record. This page does not certify a deployed SP, released
attributes, a real MFA login or operational Gate F.

## Accepted checkpoints and scope

| Scope | State | Evidence boundary |
|---|---|---|
| F1 rules, settings and entitlement header | Application acceptance complete | Ordered exact/prefix matching, strict startup validation and fixed header/nginx contracts |
| F2 persistence, approval and mismatch | Application acceptance complete | Trusted transactional observation, revision-bound manual approval, explicit no-match baseline, authority/session preservation |
| F3 integrated acceptance | Application acceptance complete | HTTP callback, rendered administrator review, real guarded approval, structured audit and subsequent assertions against PostgreSQL |
| Final source and required checks | References open | Exact tested main commit and complete CI matrix for the final F3 state |
| Operational Gate F | Open | Installed SP/IdP, attribute release, host identity boundary, activation and rollback evidence |

Automatic approval is not planned for 1.0.0. A possible later opt-in extension
remains outside the accepted scope.

## Application acceptance map

The [proposal contract](../architecture/federated-tier-rules.md) describes the
rule schema, bounded normalized inputs, snapshots and review revisions. The
[authentication contract](../architecture/auth.md#federated-shibboleth-login)
describes the surrounding identity/session policy.

| WP F criterion | Executable evidence |
|---|---|
| First matching rule wins; exact versus explicit prefix entitlement values; absent/unknown values give no proposal; malformed rules refuse startup | `src/tests/unit/test_federated_tier_rules.py::test_rule_predicates_are_conjoined_and_first_match_wins`; `src/tests/unit/test_federated_tier_rules.py::test_entitlement_exact_and_explicit_prefix_match_one_decoded_value`; `src/tests/unit/test_federated_tier_rules.py::test_unknown_or_missing_predicate_values_produce_no_proposal`; `src/tests/unit/test_federated_tier_rules.py::test_invalid_json_rule_environment_fails_even_when_federation_is_disabled` |
| Trusted optional entitlement is bounded; missing/duplicate/spoofed/wrong-issuer/non-MFA assertions fail closed; ordinary proxies clear and callback overwrites the header | `src/tests/unit/test_shibboleth_callback.py::test_every_required_assertion_header_fails_closed`; `src/tests/unit/test_shibboleth_callback.py::test_duplicate_security_or_attribute_header_is_rejected`; `src/tests/unit/test_shibboleth_callback.py::test_unapproved_issuer_or_password_only_context_never_reaches_db`; `src/tests/unit/test_shibboleth_callback.py::test_control_or_oversized_assertion_value_is_rejected`; `src/tests/unit/test_shibboleth_callback.py::test_raw_entitlement_names_cannot_populate_the_private_claim`; `src/tests/unit/test_nginx_contract.py::test_ordinary_proxy_include_is_an_exact_fail_closed_header_contract`; `src/tests/unit/test_nginx_contract.py::test_phase_two_callback_forwards_only_an_explicit_header_allowlist`; `src/tests/unit/test_nginx_contract.py::test_phase_two_maps_required_identity_and_assurance_from_authorizer_output` |
| First trusted assertion is pending, public, inactive, unverified, nonadmin and sessionless, with the latest proposal and rule | `src/tests/integration/test_federated_review_db.py::test_first_assertion_persists_first_ordered_proposal_without_granting_authority`, plus the F3 HTTP flow below |
| Dedicated approval chooses a tier independently of the proposal and records the locked proposed/chosen result with actor/time | `src/tests/integration/test_federated_review_db.py::test_manual_choice_is_independent_of_proposal_and_preserves_its_approval_baseline`, plus the F3 HTTP audit assertions |
| A later changed proposal is flagged without changing assigned authority, approval history or existing sessions | `src/tests/integration/test_federated_review_db.py::test_changed_proposal_flags_mismatch_without_changing_authority_or_existing_session`, plus the F3 rendered mismatch assertions |
| Changed attributes invalidate the reviewed form, even when the matching proposal stays the same | `src/tests/integration/test_federated_authentication_db.py::test_changed_assertion_committing_first_rejects_waiting_stale_review_approval`, plus the F3 HTTP stale-form case |
| Stored review state rejects malformed combinations; no-match differs from never reviewed | `src/tests/integration/test_federated_review_schema_db.py::test_malformed_observation_is_rejected_fail_closed`; `src/tests/integration/test_federated_review_schema_db.py::test_malformed_rule_snapshot_is_rejected`; `src/tests/integration/test_federated_review_schema_db.py::test_approved_no_match_remains_distinct_from_no_review` |

F3's module is
`src/tests/integration/test_federated_tier_acceptance_db.py`:

| Test | Integrated acceptance |
|---|---|
| `src/tests/integration/test_federated_tier_acceptance_db.py::test_http_assertion_review_approval_and_changed_proposal_keep_authority_manual` | The `matched-proposal` and `reviewed-no-match` parameters drive the same route/SQL chain: pending sessionless identity, escaped administrator view, explicitly chosen tier independent of the proposal, committed approval audit, later login and rendered mismatch without assigned-authority changes. The no-match case retains an explicit null approval baseline. |
| `src/tests/integration/test_federated_tier_acceptance_db.py::test_http_changed_attributes_with_the_same_proposal_reject_a_stale_approval_form` | A changed observation advances the review revision; the older real form cannot activate the identity or emit a successful approval audit |

These tests use the application's real callback, administrator routes, CSRF,
session handling, proposal/approval services and SQL. The test client supplies
the callback's Unix-peer ASGI representation and synthetic trusted headers;
it does not run a Shibboleth SP or prove Unix-socket ownership, SAML signatures,
IdP MFA, attribute release or production nginx behavior. The fixture's ordinary
external lifespan substitutions remain in place. Preserve the separate unit,
race, header and native-nginx evidence rather than replacing it with the three
integrated cases.

The integrated assertions cover stored approval actor/time and the structured
approval event's proposed tier/rule, explicitly chosen tier, actor and target.
Retain that event with its existing logging timestamp in the acceptance evidence.
The event omits the observed assertion
payload and subject identifier. Its rule snapshot intentionally contains the
reviewed configuration predicates. Other authentication events keep their
existing audit fields; F3 makes no claim that every authentication audit omits
issuer or assurance data.

## Reproduce application acceptance

Use Python 3.11, PostgreSQL 18, disposable Redis and nginx for the existing
native contract tests. The example below selects the default local test
instance explicitly; use the corresponding disposable endpoint for your
environment. `DATABASE_URL` is the integration harness input. An environment
variable named `TEST_DATABASE_URL` does not select the database for this suite.
Keep the base name unsuffixed; pytest adds `_gwN` for each worker.

```bash
tests=(
  src/tests/unit/test_federated_*.py
  src/tests/unit/test_shibboleth_callback.py
  src/tests/unit/test_nginx_contract.py
  src/tests/client/test_admin_membership_routes.py
  src/tests/client/test_federated_tier_review_routes.py
  src/tests/integration/test_federated_*.py
)
ENV_STATE=dev \
DATABASE_URL='postgresql://test:test@localhost:5432/oralhistarchiv_test' \
REQUIRE_DB=1 REQUIRE_REDIS=1 REQUIRE_NGINX=1 uv run pytest \
  -n 0 -p no:randomly -q -rs -rx --no-cov "${tests[@]}"
ENV_STATE=dev \
DATABASE_URL='postgresql://test:test@localhost:5432/oralhistarchiv_test' \
REQUIRE_DB=1 REQUIRE_REDIS=1 REQUIRE_NGINX=1 uv run pytest \
  -n 3 --randomly-seed=61023 -q -rs -rx --no-cov "${tests[@]}"
```

Retain the complete existing CI matrix as well as these focused results,
including both full-suite orders, the current collection floor and the 92.5%
overall/90% security-module branch-coverage gates. Focused `--no-cov` runs do
not establish aggregate coverage. The capability-token nginx error-log expected
failure recorded during F3 preparation was resolved by later WP I work. The
current native nginx regression asserts that throttled capability secrets stay
out of both access and error logs; it is not marked as an expected failure.
Retain that WP I evidence separately from the F3 results and deployed Gate F
checks.

## Test schema and worker handoff

F3 adds tests and documentation only; a database already verified against F2
needs no further recreation for this batch. The initial revision remains
`4f73ae3ff827`, with the three F2 review columns
and `users_federated_review_state_check` in its body. The revision label alone
cannot distinguish an older body. `upgrade head` and stamping do not install
the changed body into an already stamped database.

Before troubleshooting a fresh baseline, inspect the migration actually used:

```bash
PYTHONPATH=src uv run python - <<'PY'
from app.paths import ALEMBIC_DIR

path = ALEMBIC_DIR / "versions/4f73ae3ff827_initial_schema.py"
text = path.read_text()
print("Loaded migration:", path)
for marker in (
    "federated_review JSONB",
    "federated_review_revision BIGINT",
    "federated_approved_proposal JSONB",
    "users_federated_review_state_check",
):
    print(marker, marker in text)
PY
```

All four markers must be present. `app.paths` prefers bundled migration assets
when available, so editing a different source file does not establish which
body Alembic executed. In development test commands, `ENV_STATE=dev` keeps
migration routing on the same `DATABASE_URL`; staging/production migration
mode instead selects `MIGRATION_DATABASE_URL`.

The serial test database and every worker database are independent. The
fixture creates a missing worker database and migrates it; it reuses an
existing worker. Recreating the serial database does not refresh existing
workers. The accepted local repair recreated disposable test databases from
empty `template0`, then ran the updated migration through the fixtures.
That operator action is not an application/updater feature. Keep development
`oralhistarchiv` data intact. Retained data needs an operator-reviewed migration
or isolated import plan; this record supplies no reset or live-data conversion
procedure.

## Final application evidence

Record references for the exact final state. A maintainer's all-green report is
accepted checkpoint evidence; it is not an invented commit or CI-run identity.
Store redacted results and references, not callback credentials, session/CSRF
tokens, raw assertions, real identities or a secret-bearing `nginx -T` dump.

| Required reference | Value |
|---|---|
| Exact final tested main commit | `<main-commit-sha>` |
| Required CI jobs, serial/randomized orders and coverage results | `<ci-run-url-and-check-references>` |
| F3 integrated test commands, results and collection count | `<f3-test-result-reference>` |
| Strict docs build and repository reference/site scan | `<docs-and-reference-scan-evidence>` |
| Synthetic administrator review/approval/mismatch interface evidence, using the integrated DOM assertions or a synthetic capture | `<synthetic-interface-evidence-reference>` |
| Application acceptance owner and UTC time | `<owner-and-utc-time>` |

Retain these references in the application acceptance record. Keep the deployment
gate open until the host evidence below passes; application acceptance does not
authorize a flag change.

## Operational Gate F remains open

The [generic federation integration runbook](federation-integration.md) is the operational procedure for
installation, the ordered mandatory pre-flip checks, final flag change,
immediate real-login canary and rollback. The
[deployment overview](../configuration/deployment.md#nginx-in-front-with-the-shibboleth-sp-at-the-edge)
explains the topology. This evidence template adds no alternative activation
commands or shorter acceptance path.

Before federation opens while public registration is enabled, WP J's handling
of unverified local email reservations must be accepted and deployed as well.
The [reservation acceptance record](federated-reservations.md) describes the
transactional replacement and its independent validation state. Verified local
accounts, administrator rows and other federated identities still collide;
proposal rules cannot merge accounts or grant replacement authority. Keep
`SHIBBOLETH_ENABLED=false` while preparing the edge. Production-equivalent
staging supplies the pre-flip application/assertion evidence; the production
flag is the last approved change after the ordered prerequisites. The real
production MFA canary follows that flip immediately and requires rollback on
an unexpected result.

| Host evidence still required | Restricted reference |
|---|---|
| Candidate release/schema and runtime identities, socket/ACL isolation, effective nginx header replacement and web-only secret custody | `<candidate-and-host-boundary-evidence>` |
| SP installation, signed metadata trust, accepted federation registration and actual release/mapping including entitlement | `<sp-registration-and-release-evidence>` |
| Exact trusted issuer, persistent non-reassigned subject, enforced REFEDS MFA, redirect and shared-browser/logout checks | `<identity-mfa-and-logout-evidence>` |
| Missing/duplicate/client-spoofed/wrong-issuer/non-MFA refusals through the deployed edge, plus production-equivalent staging proposal/approval/mismatch evidence | `<pre-flip-check-evidence>` |
| WP J deployed when registration and federation are open together | `<reservation-dependency-evidence>` |
| Independent review and final flag-change authorization, owner and UTC time | `<flag-change-approval-reference>` |
| Immediate controlled real MFA canary: pending sessionless identity, reviewed proposal, dedicated approval with actor/time/proposed/chosen tier, then approved login | `<restricted-canary-audit-reference>` |
| Rehearsed rollback to callback 404 and flag false, with session reconciliation and reviewed code/schema boundary | `<rollback-evidence-reference>` |

Record operator ownership, UTC times and pass/fail outcomes in the deployment
change record. A synthetic assertion, an empty environment or a passing source
contract test cannot fill an unexecuted host evidence row. Gate F closes only
after the applicable prerequisites, real canary and rollback rehearsal have
recorded successful results.
