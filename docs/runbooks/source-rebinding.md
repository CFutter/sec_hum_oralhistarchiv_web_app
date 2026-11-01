# Review a source configuration change

A source name is a persistent catalogue identity. Changing its upstream endpoint,
institution filter, interpretation contract or source restriction can change which
records belong to that identity. Incremental replay and full rebuilds therefore
stop before fetching when the configured fingerprint differs from its committed
binding. A scheduler restart does not acknowledge the change.

Review the actual configuration and upstream repository before approving a
rebinding. A `source_binding_review_required` event contains the previous and
target SHA-256 fingerprints; those hashes contain no fetch credentials. They
identify the proposed change and are not themselves evidence that it is safe.

Use the installed release's owner maintenance command after review:

```sh
sudo -u oralhistarchiv-migrate /usr/bin/env -i \
  ENV_STATE=production \
  DATABASE_URL='postgresql://oralhistarchiv@/oralhistarchiv?host=/var/run/postgresql' \
  /opt/oralhistarchiv/.venv/bin/python \
  /opt/oralhistarchiv/scripts/acknowledge_source_binding.py \
  --source reviewed_source \
  --expected-fingerprint PREVIOUS_64_CHARACTER_FINGERPRINT \
  --new-fingerprint TARGET_64_CHARACTER_FINGERPRINT
```

The command needs only the canonical environment selection and owner database
connection. It loads neither application Settings nor web/scheduler environment
files or upstream fetch secrets. The database owner compares the previous binding
under a row lock and commits approval for that exact previous/target pair. A stale
comparison fails without changing the approval. Runtime roles cannot write it.
The approval and a metadata-free security event commit in the same transaction.

Run a full rebuild after acknowledgement, or let the next incremental scheduler
tick request that rebuild. Review its result before declaring the change
complete. Approval does not bypass record validation, privacy restrictions,
contraction guards, or failed-ingestion quarantine. An initial empty database
needs no rebinding approval. An intentional rollback to a previous configuration
requires a new review and acknowledgement against the current binding.

## Filter exclusions and upstream withdrawals

An authoritative upstream tombstone deletes its metadata even if an unrelated
rebuild fails later. A locally inferred institution-filter mismatch instead
withholds a previously stored record from every access tier. Its old metadata
is retained for correction but does not remain in discovery, search or resource
links. Unknown mismatching identities do not create quarantine or diagnostic
rows. A valid fresh matching correction can restore a withheld record; deleting
diagnostics or restoring an administrator-hidden record cannot do so.

A withheld predecessor retains its DOI ownership. A proposed successor using the
same DOI remains rejected until the upstream supplies an authoritative tombstone
or corrects the ownership conflict; filter exclusion alone cannot discard the
predecessor's retained identity state.

Filter exclusions count against full-rebuild contraction limits alongside
inferred absences. Exceeding a guard leaves exclusions withheld, retains other
unmentioned metadata and reports a failed rebuild. A zero-match rebuild also
reports failure and preserves ambiguous absences.

Stored visibility restrictions are recorded separately in
`source_security_state`. This table contains the last accepted source/UUID/tier
without descriptive metadata, has no catalogue foreign key, and survives
withdrawal and reintroduction. An explicit valid upstream assertion replaces its
tier automatically, including a lower tier. Without an assertion, the returning
record retains its prior restriction. Administrator restrictions remain in their
separate state table and continue to apply to every corrected record. Runtime
ingestion cannot clear either security-state table. Include both security
state tables and `source_binding_acknowledgements` in consistent backups.

Do not disable triggers or modify these tables directly during ordinary
ingestion. Upstream assertions and their source tier commit with the matching
catalogue/projection changes and a value-free lowering event. Changes to the
source configuration itself still use the fingerprint acknowledgement procedure
above. Administrator floors are changed through dataset administration.
