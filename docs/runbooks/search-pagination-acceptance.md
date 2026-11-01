# Resource classification, search and pagination acceptance

**Status: WP K1–K3 application acceptance reported complete; final evidence references and deployment acceptance remain open.**

WP K is divided into three application batches. K1 replaces the OAI/CMDI
resource-access heuristic with an explicit mapping and binds that interpretation
to source state. K2 covers field-aware full-text search and its substring
fallback. K3 covers keyset pagination and concurrent/stale-cursor behavior.
The [K2 search contract](search-fulltext.md) and [K3 continuation contract](search-pagination.md)
record the matching and pagination behavior supplied after K1. Source-owner
approval, retained-staging upgrade acceptance and production performance remain
separate from the application checkpoint.


## K1 mapping contract

The `oai_pmh_cmdi` source policy uses an immutable exact mapping:

| Input | Stored/displayed `access_level` |
|---|---|
| `Public access` | `public` |
| `License CC BY` | `public` |
| `CC BY 4.0` | `public` |
| `Restricted access` | `restricted` |
| Missing (`None`), empty string or any other string | `restricted` |
| Nontext value other than `None` | `TypeError`, without echoing the raw value |

No case folding, whitespace trimming, Unicode normalization or prefix matching
is applied. A label such as `Public access extra`, `public access` or
` Public access` is therefore restricted. An unknown label cannot become public
merely because it resembles a familiar license or an access description.

`License CC BY` and `CC BY 4.0` are retained from existing application-test
inputs: the record-pipeline fixture and incremental-ingestion fixture. These
test inputs establish compatibility expectations only. They are not provider
or governance evidence and do not define additional supported license spellings.

The other three adapter classifiers are unchanged. Fixture and static JSON map
only exact `Public access` to public and other labels/missing values to
restricted. The JSON feed accepts only exact `Public access` and
`Restricted access`, rejecting unknown strings and missing/nontext input.
The [all-adapter table](../sources/index.md#resource-access-classification)
records the complete distinction.

`access_level` remains a public discovery label/filter. It grants no metadata
tier or download permission. Field-level SQL/redaction, RLS, administrator
hiding, audited resource-link checks and upstream authorization remain in force.

## Interpretation and deployment

The OAI/CMDI configuration fingerprint now binds the exact access-label map
and restricted fallback in addition to the former five interpretation fields.
The earlier binding cannot match the new interpretation. Normal scheduler
recovery therefore requires an authoritative source rebuild before incremental
ingestion can continue for an existing OAI source. Existing records retain
stored labels until normal successful rebuild writes replace them.

Do not edit durable fingerprints, discard staged state or reset a database to
bypass that recovery requirement. Applying the tests/docs updater performs no
harvest, rebuild or application-data operation. The production guide describes
the reviewed source change; operator deployment and normal scheduler work
remain separate from running the updater.

K1 adds no schema columns, indexes or migration and requires no database reset.
Keep the current initial-schema baseline. Use only explicitly disposable test
databases for validation. This batch neither performs nor authorizes any action
on an existing development or production catalogue.

## K1 application evidence

| Criterion | Required evidence |
|---|---|
| Exact public/restricted labels and conservative fallback | Public classifier tests for all mapped labels, `None`, empty/unknown strings, prefix lookalikes, case and whitespace variants |
| Wrong-type refusal without data echo | Public classifier tests for nontext inputs and fixed error text |
| Immutable mapping | Mutation refusal and mapping/classifier agreement tests |
| Interpretation binding | New fingerprint differs from the old five-field binding; exact mapping and fallback affect the binding; operational-only changes preserve it |
| Source recovery | Existing source interpretation mismatch requests normal authoritative rebuild without rewriting durable bindings or metadata outside that path |
| Other adapters preserved | Fixture, static-JSON and strict JSON-feed public-interface regression tests |
| Existing ingestion/access behavior | Source/record parsing, conformance, fingerprint/recovery and access-control regression selection |

| Required reference | Record from the reviewed candidate |
|---|---|
| Source and artifact | Exact commit, artifact identity and independent provenance |
| Automated checks | Complete serial/randomized CI, measured collection/coverage, lint, typing, security audit, strict docs and repository scans |
| Focused behavior | Exact commands, runtime versions, results and unavailable checks |
| Deployment acceptance | Applicable source, identity, recovery and host evidence |

The executable K1 evidence is:

- `src/tests/unit/test_oai_access_mapping.py`: exact labels, missing/unknown/type handling, immutable mapping, binding and other-adapter preservation (30 cases).
- `src/tests/unit/test_access_tiers.py`: updated four-case classifier contract.
- `src/tests/unit/test_source_adapters.py::test_fingerprint_binds_access_mapping_and_injected_policy`: updated deterministic binding and operational-setting invariance.
- `src/tests/integration/test_oai_access_mapping_db.py::test_exact_mapping_changes_no_metadata_or_administrator_authority`: incremental and authoritative paths preserve source isolation, hidden state, stored/admin minima and field-level search gates.
- `src/tests/integration/test_oai_access_mapping_db.py::test_old_access_binding_requires_rebuild_before_cursor_or_staged_reuse`: old committed binding with and without a staged payload is fenced; a successful authoritative rebuild reclassifies labels, retains the stricter tier and clears obsolete staged state.

A focused pass is not full-suite coverage or a production rebuild rehearsal.
Retain exact commands, test-node references and unavailable checks with the
results; do not infer a successful database or deployment check from collection.

## Related K2 and K3 acceptance

K2 preserves field/tier gates for every matching channel, the approved
public discovery envelope, substring behavior and facet/count behavior while
adding full-text search. Retain its actual-role plan JSON before making a
specific index-use claim; representative workload measurements remain separate
from the accepted synthetic plan probes and do not follow from green CI alone.

K3 supplies bounded continuation and stale-cursor behavior under its documented
current-state and concurrency limits. Its implementation and tests are accepted
at the reported current checkpoint; the K1 classification change alone did not
supply them. Retain the K2/K3 test and deployment evidence separately from the
historical K1 preparation figures.
