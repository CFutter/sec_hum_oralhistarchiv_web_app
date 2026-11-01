# OAI ingestion resource limits

The OAI adapter treats transport, XML structure and record metadata as separate
budgets. Complying with the byte limit alone does not establish an acceptable
XML tree or record.

Each response page has the existing 4 MiB wire limit. XML parser callbacks stop
before forwarding a node or text fragment that exceeds any of these page limits:

| Budget | Maximum |
| --- | ---: |
| Elements | 100,000 |
| Nested element depth | 64 |
| Text characters, including attribute names/values | 3,145,728 |
| Attributes | 200,000 |

The bounded page parser rejects document type declarations. Entity resolution,
DTD loading and network loading remain disabled. Comments and processing
instructions are not retained. No partial page is classified or published after
a parser-budget rejection.

Shared record validation applies on parser output and again when decoding staged
harvests or writing accepted records. Collections contain at most 512 entries;
CMDI dataset/project titles and ordinary labels contain at most 4,096 characters;
descriptions and citations
at most 262,144 characters; and URLs at most 4,096 characters. Existing UUID/DOI
bounds and the 256-character keyword/language label bound remain. JSON feeds
use a configurable project-title cap within the shared codec's 16,384-character
ceiling; that ceiling does not widen the CMDI profile. Older staged record-contract
versions are conservatively refetched rather than replayed as current input.

The separate parser service supplies a further process-tree memory ceiling of
512 MiB, a task limit, an overall deadline and forced cleanup. These OS controls
apply to the parser job rather than sharing the scheduler/mail service's cgroup.
Provision host memory for the configured maximum of two parser jobs and the
remaining services; a per-job ceiling is not a reservation of physical RAM.

## Verify on a disposable deployment host

Run the explicit parser-host proofs described in `Deployment.md`. In addition to
identity, filesystem, local-network and actual entrypoint checks, the proof file
exhausts a disposable copy of the shipped parser cgroup. It requires the effective
systemd result `oom-kill` and demonstrates that an independent coordinator can
continue spawning real SMTP delivery children before and after the failure.
The delivery canary uses a local synthetic SMTP server and no production
recipient or credentials. It verifies the resource boundary; it is not a
production-catalogue load measurement.

Run representative valid upstream pages as well as element/depth/text/collection
boundary tests before adjusting these limits. A legitimate oversized response
needs an upstream page-size or metadata-contract correction, not a silent
fallback to unbounded parsing.
