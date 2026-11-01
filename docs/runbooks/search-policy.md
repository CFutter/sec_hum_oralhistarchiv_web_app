# Search policy and audience projections

Search text, keyword filters and language filters use three separate physical
tables and index sets: `catalogue_search_public`, `catalogue_search_registered`
and `catalogue_search_vetted`. The selected audience table contains only text and
filter values that audience may search. Raw catalogue search indexes are not
used by the page, exact-count or compatibility candidate query paths.

Each projection applies the current source field minima and source visibility
floor, the stored record tier, administrator restrictions, hiding and ingestion
quarantine. Nonhidden above-tier records retain their intentionally public
discovery text. Negative search terms are evaluated against the same permitted
document as positive terms. Public discovery does not make descriptions,
keywords or languages public.

Database triggers update projections in the same transaction as record,
administrator-state and quarantine changes. A common catalogue write lock also
serializes those mutations with policy replacement. No request rebuilds a
projection or falls back to unrestricted indexes when its policy is unavailable.

## First startup and normal restarts

On a fresh database, web startup installs its compiled policy and builds the
projections before publishing the catalogue snapshot. Subsequent workers verify
the existing binding. A different fingerprint stops startup; an old worker
cannot overwrite a newer policy merely by restarting. Requests carry their
compiled policy fingerprint, and a mismatch fails closed.

Page, count, facet, recent-record, detail and resource-metadata reads verify that
binding before reading fields. They hold a shared catalogue transaction lock
through the protected database work. A concurrent mutation/rebuild or stale
worker produces a generic temporary-unavailability response instead of waiting
on the ordinary connection pool or rendering under an obsolete policy. Cached
statistics are also bound to the worker's published policy.

The `catalogue_search_policy` binding and projection tables are private to the
database owner. The web role can initialize an empty binding and verify an
identical binding through a narrow function. It cannot call the replacement
function or read/write projection tables directly. Include all four tables in
backups and restore them with their source tables and triggers.

## Deliberate configuration changes

Changing configured sources, source field visibility, source visibility floors
or the code field matrix can change the fingerprint. Treat this as an explicit
policy deployment:

1. Review the new configuration, including any permissions it relaxes. Drain or
   stop the old web workers for the policy cutover.
2. Read and record the previous fingerprint using the database owner:

   ```sql
   SELECT fingerprint FROM public.catalogue_search_policy WHERE singleton;
   ```

3. Run the installed command under the database-owner operating-system identity
   with a standalone environment. It reads only `DATABASE_URL`,
   `SOURCES_CONFIG_FILE` and `ENV_STATE`; it does not load application Settings,
   authentication keys, web/scheduler environment files or source fetch
   credentials. The new source file must pass the same protected-file checks
   as web startup. For the reference peer-authenticated deployment:

   ```sh
   sudo -u oralhistarchiv-migrate /usr/bin/env -i \
     DATABASE_URL='postgresql://oralhistarchiv@/oralhistarchiv?host=/var/run/postgresql' \
     SOURCES_CONFIG_FILE=/etc/oralhistarchiv-sources/sources.toml \
     ENV_STATE=production \
     /opt/oralhistarchiv/.venv/bin/python /opt/oralhistarchiv/scripts/rebuild_search_policy.py \
     --expected-fingerprint PREVIOUS_64_CHARACTER_FINGERPRINT
   ```

   Use the installed release interpreter so no `PYTHONPATH` is necessary. The
   owner identity needs read/search access to the source file and its parent
   directories. For a separately managed PostgreSQL endpoint, supply its owner
   connection through the institution's protected credential mechanism; do not
   put a password in shell history or the process argument list. Keep the normal
   web database identity unchanged.

4. Start the new workers and check readiness and representative searches at
   every access tier.

The command compares the expected previous fingerprint while holding the
catalogue write lock, then replaces the binding and all projections atomically.
A stale expected fingerprint, invalid policy, database error or cancellation
rolls back the operation. The maintenance command has a ten-minute statement
budget; this is separate from request search deadlines. Size the maintenance
window for the real catalogue and investigate timeouts before retrying.

Running the ordinary startup path against a different policy is deliberately
insufficient. An intentional rollback also requires a reviewed owner command
with the currently installed fingerprint. Direct SQL that disables triggers or
truncates catalogue/admin/quarantine tables is outside the runtime write
contract; restore the matching projection state before serving traffic.

## Verification

Run the PostgreSQL integration tests with `REQUIRE_DB=1`. Inspect the actual SQL
plans generated inside the owner query functions under the web role: only the
selected audience's projection and indexes should carry search predicates.
Exercise administrator floors, source configuration tightening, quarantine,
rollback, concurrent mutations and stale worker fingerprints.

Compare repeated, randomized query timings while changing only forbidden text
and filter values. Include public and registered audiences, cold and warm
caches, different corpus sizes and representative production conditions.
Statistical timing checks complement the physical index boundary; a noisy test
result is not proof of universal constant-time execution. The existing search
rate, concurrency and execution budgets remain necessary for availability.
