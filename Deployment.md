# Deployment Guide

**Oral History Archive — Example University**

This guide covers deploying the application on a single Ubuntu VM behind nginx
with TLS, PostgreSQL, and Redis. Phase 1 uses local accounts; Shibboleth is a
separate, fail-closed Phase-2 activation.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [VM Setup & Hardening](#2-vm-setup--hardening)
3. [PostgreSQL](#3-postgresql)
4. [Redis](#4-redis)
5. [Application Installation](#5-application-installation)
6. [Environment Configuration](#6-environment-configuration)
7. [Gunicorn, Scheduler & Systemd](#7-gunicorn-scheduler--systemd)
8. [Nginx & SSL](#8-nginx--ssl)
9. [Shibboleth SP](#9-shibboleth-sp)
10. [Firewall](#10-firewall)
11. [Backups](#11-backups)
12. [Log Management](#12-log-management)
13. [Monitoring](#13-monitoring)
14. [Memory Tuning](#14-memory-tuning)
15. [CI/CD](#15-cicd)
16. [Post-Deployment Checklist](#16-post-deployment-checklist)
17. [Maintenance](#17-maintenance)

---

## 1. Prerequisites

- Ubuntu 22.04 or 24.04 LTS
- Root or sudo access
- Domain name pointing to the VM's IP (e.g., `archive.example.org`)
- A dedicated PostgreSQL 18 cluster (same VM; the HBA policy in §3 ends with
  a local catch-all reject and must not be pasted into a shared cluster)
- A dedicated Redis 7+ limiter endpoint. The reference deployment runs its
  own local instance; an approved external service is also supported. A
  physically separate general instance is optional for cache invalidation
- Python 3.11 (the reviewed release artifact is built for this series)
- SSL certificate (institutional or Let's Encrypt)

The package commands below assume an institutionally approved APT source that
provides these exact major versions. Ubuntu releases do not all ship Python
3.11, PostgreSQL 18, and Redis 7 in their default repositories. Configure and
record the approved source before installation; do not silently substitute an
unreviewed PPA or a different major version.

---

## 2. VM Setup & Hardening

### System updates

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Install ssh server (check)

```bash
sudo apt install openssh-server
```

### Create isolated service identities and the proxy group

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
    oralhistarchiv
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
    oralhistarchiv-scheduler
sudo groupadd --system oralhistarchiv-proxy
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin \
    oralhistarchiv_backup
sudo groupadd --system oralhistarchiv-migrate
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
    --gid oralhistarchiv-migrate oralhistarchiv-migrate
# Reference host-local limiter only; omit this identity for an external service.
sudo useradd --system --user-group --no-create-home \
    --home-dir /var/lib/oralhistarchiv-rate-limit-redis \
    --shell /usr/sbin/nologin oralhistarchiv-rate-limit-redis

getent group oralhistarchiv oralhistarchiv-scheduler \
    oralhistarchiv-proxy oralhistarchiv_backup oralhistarchiv-migrate
id oralhistarchiv
id oralhistarchiv-scheduler
id oralhistarchiv_backup
id oralhistarchiv-migrate
# Reference host-local limiter only:
getent group oralhistarchiv-rate-limit-redis
id oralhistarchiv-rate-limit-redis
```

The web and scheduler deliberately have different UIDs. The web unit runs with
primary group `oralhistarchiv-proxy`. After nginx is installed in §8, the
effective worker account is derived fail-closed from `nginx -T` and added as
the only supplementary member so it can connect to the group-owned Gunicorn
socket. If that worker UID also runs PHP-FPM, another site, or any other
service, every such process receives the same socket authority; give this site
a dedicated nginx worker UID/instance before continuing. The scheduler is not
a proxy-group member and its unit makes the runtime directory inaccessible.
`oralhistarchiv_backup` remains a third identity with only the documented
read-only backup authority. Do not add the scheduler, backup user, an
interactive account, or any unrelated daemon to `oralhistarchiv-proxy`.

`oralhistarchiv-migrate` exists only to authenticate the static/manual
migration unit as the PostgreSQL owner. It is not a runtime, login, deployment,
or interactive-maintenance identity.

For the reference host-local deployment, `oralhistarchiv-rate-limit-redis`
owns only the dedicated limiter's runtime and AOF state. It is not the
distribution's general `redis` user and is not a member of any application,
proxy, scheduler, backup, or migration group. An external-limiter deployment
omits this otherwise-unused local identity.

### SSH hardening

Edit `/etc/ssh/sshd_config`:

```
PermitRootLogin no
PasswordAuthentication no
AllowUsers your_admin_user
MaxAuthTries 3
```

```bash
sudo systemctl restart sshd
```

### Install fail2ban

```bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
```

Create `/etc/fail2ban/jail.local`:

```ini
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600
```

```bash
sudo systemctl restart fail2ban
```

---

## 3. PostgreSQL

### Install PostgreSQL

Install PostgreSQL 18 from the institutionally approved
[PostgreSQL APT repository](https://www.postgresql.org/download/linux/ubuntu/).
Ubuntu 22.04/24.04 default packages do not supply this major version. Configure
its signed package source, then verify the running server before creating roles:

```bash
sudo apt install -y postgresql-common ca-certificates
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt install -y postgresql-18 postgresql-client-18
sudo systemctl enable --now postgresql
sudo -u postgres psql -XAt --dbname=postgres --command='SHOW server_version'
sudo -u postgres psql -XAt --dbname=postgres --command="SELECT current_setting('server_version_num')::integer / 10000" \
  | grep -qx '18'
```

### Create separated database identities

The tracked bootstrap and grant scripts become available in the reviewed
release installed in §5. After installing the first release, return to this
subsection and create the database roles while both application services are
stopped:

```bash
sudo -u postgres psql --dbname=postgres --set=ON_ERROR_STOP=1 \
  --file=/opt/oralhistarchiv/deploy/bootstrap-database-roles.sql
```

The owner role `oralhistarchiv` is usable only by the
`oralhistarchiv-migrate` OS identity. Web, scheduler, and backup have separate
login roles with `PASSWORD NULL`; web and scheduler are non-owner,
`NOBYPASSRLS`, and have no role memberships. The backup role remains
read-only, `BYPASSRLS`, and limited to one connection so a recovery archive can
contain all rows.

### Configure exact local peer authentication

Add this map to `/etc/postgresql/18/main/pg_ident.conf`:

```text
oralhistarchiv_app oralhistarchiv           oralhistarchiv_web
oralhistarchiv_app oralhistarchiv-scheduler oralhistarchiv_scheduler
oralhistarchiv_app oralhistarchiv-migrate   oralhistarchiv
```

Replace the generic local-authentication block in
`/etc/postgresql/18/main/pg_hba.conf` with this complete, ordered block:

```text
local all             postgres                  peer

local oralhistarchiv oralhistarchiv_backup      peer
local all             oralhistarchiv_backup      reject

local oralhistarchiv oralhistarchiv_web          peer map=oralhistarchiv_app
local all             oralhistarchiv_web          reject

local oralhistarchiv oralhistarchiv_scheduler    peer map=oralhistarchiv_app
local all             oralhistarchiv_scheduler    reject

local oralhistarchiv oralhistarchiv              peer map=oralhistarchiv_app
local all             oralhistarchiv              reject

local all             all                        reject
```

The per-identity rejects and final catch-all are load-bearing. They prevent an
application, backup, or migration OS identity from requesting another database
role or falling through to a broader peer rule. Keep administrative TCP rules,
if any, in a separately reviewed host policy; do not add another local rule
after the catch-all.

```bash
sudo -u postgres psql --dbname=postgres --set=ON_ERROR_STOP=1 -c \
  "SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL"
sudo systemctl reload postgresql
sudo -u oralhistarchiv-migrate \
  psql --no-password --dbname=oralhistarchiv --username=oralhistarchiv \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv \
  psql --no-password --dbname=oralhistarchiv --username=oralhistarchiv_web \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv-scheduler \
  psql --no-password --dbname=oralhistarchiv \
  --username=oralhistarchiv_scheduler \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv_backup \
  psql --no-password --dbname=oralhistarchiv \
  --username=oralhistarchiv_backup \
  --command='SELECT current_user, session_user'
```

Every command must report the requested identity twice. Also test that each OS
identity is rejected when it requests an unapproved database role or database:

```bash
if sudo -u oralhistarchiv psql --no-password --dbname=oralhistarchiv \
    --username=oralhistarchiv --command='SELECT 1'; then exit 1; fi
if sudo -u oralhistarchiv-migrate psql --no-password \
    --dbname=oralhistarchiv --username=oralhistarchiv_web \
    --command='SELECT 1'; then exit 1; fi
if sudo -u oralhistarchiv-scheduler psql --no-password --dbname=postgres \
    --username=oralhistarchiv_scheduler --command='SELECT 1'; then exit 1; fi
if sudo -u oralhistarchiv_backup psql --no-password --dbname=postgres \
    --username=oralhistarchiv_backup --command='SELECT 1'; then exit 1; fi
```

Do not configure a password or TCP authentication for any application role.
The owner mapping is exclusive to `oralhistarchiv-migrate`; ordinary
maintenance commands use a runtime or backup identity with the least required
privileges.

---

## 4. Redis

Redis has two deliberately separate roles:

1. **Required security limiter (port 6380):** a dedicated process, memory
   ceiling, AOF, ACL and credential used only by the web process through
   `RATE_LIMIT_REDIS_URL`. It makes counters global across Gunicorn workers and
   durable across ordinary worker/service restarts.
2. **Optional general Redis (normally port 6379):** best-effort catalogue-cache
   pub/sub used through `REDIS_URL` when `REDIS_ENABLED=true`. It has no
   security role and its credential must never be substituted for the limiter.

The synchronization mutex is PostgreSQL advisory locking, not Redis. The
scheduler has no reason to receive the limiter credential or depend on the
limiter service.

Staging/production web startup aborts if the dedicated limiter's namespace or
functional probes fail. Later backend failures reject affected requests with a
retryable, non-cacheable `503` before endpoint execution. Use a separate Redis
process: logical databases share memory pressure, eviction and restarts.

The local config, unit, ACL generation, restart-persistence probe and systemd
checks below form the **reference host-local path**. An external-limiter
deployment skips those local-only steps and follows the external contract in
§7; it must still meet the same physical isolation, ACL, `noeviction`,
persistence, functional-probe and monitoring requirements.

### Install Redis binaries (reference host-local path)

Ubuntu 22.04's stock Redis 6 package is not sufficient: the reviewed AOF and
ACL syntax requires Redis 7 or newer. Configure the institutionally approved
Redis 7+ package source before running `apt`; never use an unreviewed PPA,
bypass the executable gate, or remove newer directives to make an old binary
start.

Require the scripted-counter restart probe below on each host and after every
Redis upgrade; a version number alone is not persistence evidence. If using a
non-distribution binary, set the dedicated unit's ExecStart to its approved
absolute path and keep its state and ACL separate from general Redis.

```bash
# The approved package source must already be configured here.
sudo apt install -y redis-server

redis_server_major="$({ redis-server --version || true; } \
  | sed -nE 's/.*v=([0-9]+)\..*/\1/p')"
if [[ ! "$redis_server_major" =~ ^[0-9]+$ ]] \
    || (( redis_server_major < 7 )); then
  echo 'Redis server 7 or newer is required' >&2
  exit 1
fi

# The distribution's port-6379 service is optional. Keep it stopped unless the
# separately documented cache/pub-sub feature is intentionally enabled.
sudo systemctl disable --now redis-server
```

### Install the dedicated limiter service

The tracked files become available in the reviewed release installed in §5.
After installing that release, return here and complete this subsection before
creating runtime environment files or starting the web service.

Review `deploy/redis-security.conf.example`, select a `maxmemory` value from
load testing, and install it as its own configuration. Do not merge it into
the general `/etc/redis/redis.conf`. Redis metadata, clients and AOF rewrite
buffers require headroom above `maxmemory` and the unit's `MemoryMax`.

```bash
sudo install -d -o root -g oralhistarchiv-rate-limit-redis -m 0750 \
  /etc/oralhistarchiv-rate-limit-redis
sudo install -o root -g oralhistarchiv-rate-limit-redis -m 0640 \
  /opt/oralhistarchiv/deploy/redis-security.conf.example \
  /etc/oralhistarchiv-rate-limit-redis/redis.conf
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/deploy/oralhistarchiv-rate-limit-redis.service \
  /etc/systemd/system/oralhistarchiv-rate-limit-redis.service
sudoedit /etc/oralhistarchiv-rate-limit-redis/redis.conf
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/oralhistarchiv-rate-limit-redis.service
```

Do not start it yet: §6 generates the unique ACL and places its matching URL
only in root-owned `web.env`. The configuration establishes these load-bearing
properties:

- a separate loopback-only port (`6380`), OS identity and state directory;
- an ACL file that disables the default user and constrains the web credential
  to `LIMITS:*` plus the commands exercised by the bounded fixed-window backend;
- an explicit memory ceiling with `maxmemory-policy noeviction`;
- AOF enabled with `appendfsync everysec`; and
- fail-closed AOF loading if the file is truncated or corrupt.

`allkeys-lru`, `volatile-lru`, and every other eviction policy are forbidden:
evicting a live counter silently replenishes an attacker's quota. With
`noeviction`, physical capacity exhaustion becomes an explicit Redis write error,
which the web application maps to `503` instead of executing the protected
endpoint. The application also refuses new counter allocation at its logical
capacity before client diversity can grow counter state without a bound.
The operational cost is availability during a Redis incident; the independent
nginx limits still constrain traffic while operators restore the backend.

`appendfsync everysec` preserves live quotas across orderly restarts while
limiting disk cost. A host crash can lose roughly one second of acknowledged
counter writes. `appendfsync always` reduces that window at materially higher
latency; use it only after representative load testing. The AOF contains
short-lived HMAC-pseudonymous client limiter keys, not raw IP addresses. A
`SECRET_KEY` rotation leaves the old pseudonym namespace until its natural TTL
while new counters are created, temporarily increasing memory and AOF
cardinality. Prove headroom for that overlap before rotating. The example pins
an automatic rewrite threshold; the site must approve it from measured
write/rotation load and preserve temporary disk/RSS headroom for rewrite.
That size-triggered threshold is not a time bound at low traffic: historical
pseudonyms can remain until a successful rewrite. Record privacy-owner
acceptance of that residual, or add a separately reviewed scheduled rewrite
control if institutional policy mandates a hard maximum retention interval.
Superseded AOF generations are not retained as backups. Keep the state
directory owned by `oralhistarchiv-rate-limit-redis`, exclude it from
log/backup collection, and never use it as an audit record or flush it during
key rotation.

Alert before `used_memory` approaches the tested ceiling, and immediately on
any nonzero increase in `evicted_keys`, rejected connection, AOF write/rewrite
failure, application `rate_limit_backend_unavailable` event, or sustained
limiter `503`. `evicted_keys` should remain unchanged under `noeviction`; an
increase means the effective configuration is wrong or was previously unsafe.
Credential-safe startup, durability and monitoring commands follow in §§6–7
after the ACL and `web.env` exist.

### Limiter capacity and existing counters

`LIMITER_COUNTER_CAPACITY=20000` bounds registered fixed-window counters across
all web workers sharing the dedicated Redis database. It is capped at 20,000;
choose one value for every worker before initializing the namespace. The full
Redis counter key is limited to 512 UTF-8 bytes and its TTL to 86,400 seconds.
`LIMITER_CLEANUP_BATCH_SIZE=128` bounds expired registry work per admission.
An atomic script owns each counter allocation and its expiry-registry entry.
At capacity, existing registered quotas keep their values and original expiry;
a new counter is refused with a non-cacheable, retryable 503. No live counter
is evicted, reset or moved into process-local memory to make room.

Four fixed control keys use
`LIMITS:oralhistarchiv-security-v1:bounded:{meta,counters,search-start,readiness}`.
The `counters` sorted set records expiry deadlines; shared search admission uses
one fixed hash, so rotating client addresses cannot create search-gate keys.
The dedicated database must have no other `LIMITS:*` writers. Startup rejects
unregistered counter keys, incompatible capacity metadata, persistent counters
without TTLs and other unsupported retained state. The shared search hash also
pins its rate/burst policy; workers with different values refuse startup. A
capacity or search-policy change requires a coordinated, reviewed state
migration; this release supplies no automatic migration. Do not edit/delete
registry, metadata or search-gate keys to force incompatible workers to start.

The example sets `maxmemory 128mb`; the capacity test permits less than 64 MiB
of additional `used_memory` for 20,000 maximum-length counters and their registry.
This excludes baseline RSS and persistence costs. Before production, fill a
disposable dedicated instance to the selected cap using maximum-length keys
and representative route/window distributions.
Measure `used_memory`, peak RSS, AOF growth and rewrite peaks, including old/new
HMAC namespaces during a signing-key rotation. Refusing the next new key must
leave existing values/TTLs intact and `evicted_keys` unchanged. Let short-lived
entries expire and verify new admission recovers through bounded cleanup.
Record the server/allocator version, selected cap and measured headroom; the
logical cap does not bound client buffers or Redis/AOF allocator overhead.
Do not increase the cap or enable eviction to conceal a capacity incident.

An upgrade from the earlier unregistered counter layout requires a maintenance
window. This release does not automatically adopt that layout. Preserve its
counters and AOF, stop **every** old web writer, and allow their actual remaining
TTLs to expire before starting the new release. Ordinary maximum retention is
24 hours, but inspect the effective store instead of assuming the timer has
already elapsed. Keep Redis running and the edge limits in place. Never run
`FLUSHDB`, `FLUSHALL`, a counter reset, or a prefix delete as an upgrade step.
Do not run old and new web workers concurrently against the store.

```bash
# Stop the web service on every application host sharing this limiter.
sudo systemctl stop oralhistarchiv.service

# Read-only TTL inventory; no credential or counter key is printed.
sudo /opt/oralhistarchiv/.venv/bin/python -I - <<'PY'
import math
import shlex
from pathlib import Path
from redis import Redis

lines = Path("/etc/oralhistarchiv/web.env").read_text(encoding="utf-8").splitlines()
values = [shlex.split(line.partition("=")[2].strip())[0]
          for line in lines
          if line.partition("=")[0].strip() == "RATE_LIMIT_REDIS_URL"]
if len(values) != 1:
    raise SystemExit("Expected exactly one limiter URL")
controls = {("LIMITS:oralhistarchiv-security-v1:bounded:" + suffix).encode()
            for suffix in ("meta", "counters", "search-start", "readiness")}
client = Redis.from_url(values[0], socket_connect_timeout=0.5, socket_timeout=0.5)
count = longest_ms = 0
try:
    for key in client.scan_iter(match="LIMITS:*", count=128):
        if key in controls:
            continue
        ttl = client.pttl(key)
        if ttl == -1:
            raise SystemExit("A retained counter has no expiry; preserve state and investigate")
        if ttl >= 0:
            count += 1
            longest_ms = max(longest_ms, ttl)
finally:
    client.close()
print(f"Live counters: {count}; wait at least {math.ceil(longest_ms / 1000)} seconds")
PY
```

Install the updated ACL command allowlist before this inventory if the old ACL
lacks `SCAN`/`PTTL`; preserve its passwords and key scope. After the reported wait,
repeat the inventory and require zero live legacy counters, then start the new
release and require its namespace/readiness checks. Counters that had no expiry
need an explicit reviewed recovery decision; silently resetting them is not a
safe default. Ordinary upgrades between compatible bounded namespaces retain
live quotas and do not require this legacy drain. Backout to old writers can
create unregistered state again and requires the same reviewed transition.

### Optional general Redis

If cross-worker catalogue-cache invalidation is desired, separately harden the
distribution service on port 6379 (loopback binding, protected mode, service
memory/disk monitoring), then enable it and set `REDIS_ENABLED=true` plus
`REDIS_URL` in `common.env`. This service is best-effort: a subscriber outage
falls back to the cache TTL. It may use a site-approved persistence/eviction
policy because no authentication quota is stored there. Do not point
`RATE_LIMIT_REDIS_URL` at it.

```bash
sudoedit /etc/redis/redis.conf
sudo systemctl enable --now redis-server
redis-cli -p 6379 PING
```

### Verify it's not exposed

```bash
# From another machine (should fail or time out)
redis-cli -h YOUR_VM_IP -p 6380 PING
redis-cli -h YOUR_VM_IP -p 6379 PING  # if optional general Redis is enabled
```

---

## 5. Application Installation

### Install system dependencies

```bash
sudo apt install -y python3.11 python3.11-venv acl age jq unzip
```

`jq` is used for filtering structured JSON logs from journald, and `getfacl`
from `acl` verifies backup-directory ACLs. `age` provides recipient public-key
encryption for database backups; the corresponding
private identity must not be generated or stored on this host.

### Produce the release in CI

Production is installed only from the `reviewed production release` artifact
created by a manual **CI** workflow run on `main`. The release job cannot run
until lint, type checking, dependency audit, release-builder smoke, and the
PostgreSQL/Redis test job have all passed for the same commit. It records both
the full source commit and GitHub's SHA-256 digest of the uploaded artifact in
the workflow summary.

Before upload, the release job checks all deployment assets listed in
`required_release_paths` below. These include the migration runner, tmpfiles
configuration, Redis configuration and dedicated Redis service unit, isolated
parser launcher and units, and the search-policy rebuild command. The release
contract tests keep the CI and runbook inventories aligned and verify that the
installer requires every listed asset.

From the repository's **Actions → CI → Run workflow** page, select `main` and
run the workflow. Review the green jobs and source commit, download the single
artifact whose name is `oralhistarchiv-release-` followed by that 40-character
commit, and copy its
workflow-summary `GitHub artifact SHA-256` value into the approved deployment
change record. Treat every rerun as a new artifact and record its emitted
digest; it requires a new approval even when the source commit is unchanged.

### Verify and install the artifact on the host

Transfer the downloaded artifact ZIP to an otherwise empty working directory
on the host through the approved administrative channel. Run these commands
from that directory as the deployment administrator:

```bash
set -euo pipefail

mapfile -t artifact_zips < <(
    find . -maxdepth 1 -type f -name 'oralhistarchiv-release-*.zip' -print
)
test "${#artifact_zips[@]}" -eq 1

read -r -p 'Approved GitHub artifact SHA-256: ' expected_artifact_digest
[[ "$expected_artifact_digest" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$expected_artifact_digest" "${artifact_zips[0]}" \
    | sha256sum --check --strict -

artifact_directory=$(mktemp -d)
unzip -q "${artifact_zips[0]}" -d "$artifact_directory"

mapfile -t release_archives < <(
    find "$artifact_directory" -maxdepth 1 -type f \
        -name 'oralhistarchiv-release-*.tar.gz' -print
)
test "${#release_archives[@]}" -eq 1
test -f "$artifact_directory/install_release.py"
test -f "$artifact_directory/ARTIFACT.txt"
(
    cd "$artifact_directory"
    sha256sum --check --strict ARTIFACT.txt
)

release_root="$(tar -tzf "${release_archives[0]}" | sed -n '1{s#/.*##;p}')"
test -n "$release_root"
required_release_paths=(
    oralhistarchiv.service
    oralhistarchiv-scheduler.service
    oralhistarchiv-migrate.service
    oralhistarchiv-parser.socket
    oralhistarchiv-parser@.service
    run_parser.py
    scripts/rebuild_search_policy.py
    scripts/bootstrap_admin.py
    scripts/acknowledge_source_binding.py
    scripts/export_security_audit.py
    deploy/migrate_release.py
    deploy/oralhistarchiv-tmpfiles.conf
    deploy/bootstrap-database-roles.sql
    deploy/database-runtime-grants.sql
    deploy/verify-runtime-database-access.sql
    deploy/invalidate-action-email-capabilities.sql
    deploy/nginx.conf.example
    deploy/nginx-ordinary-proxy-headers.conf.example
    deploy/nginx-shibboleth-phase2.conf.example
    deploy/nginx-shibboleth-secret.conf.example
    deploy/redis-security.conf.example
    deploy/oralhistarchiv-rate-limit-redis.service
)
for relative_path in "${required_release_paths[@]}"; do
    tar -tzf "${release_archives[0]}" \
        "${release_root}/${relative_path}" >/dev/null
done

# The installer refuses to switch code while either process is running.
sudo systemctl stop oralhistarchiv-scheduler.service oralhistarchiv.service 2>/dev/null || true

# One-time conversion of the old source-checkout layout. The old tree is kept
# for forensic comparison and is never executed again.
if [[ -e /opt/oralhistarchiv && ! -L /opt/oralhistarchiv ]]; then
    retired=/opt/oralhistarchiv-source-retired-$(date -u +%Y%m%dT%H%M%SZ)
    sudo mv -- /opt/oralhistarchiv "$retired"
    sudo chown --no-dereference root:root "$retired"
    sudo chmod 0700 "$retired"
    printf 'Retired old source tree at %s\n' "$retired"
fi

# Provision the shared stable lock inode BEFORE the first installer run.
sudo groupadd --system --force oralhistarchiv-deploy-lock
for account in oralhistarchiv oralhistarchiv-scheduler oralhistarchiv-migrate; do
    sudo usermod --append --groups oralhistarchiv-deploy-lock "$account"
done
if id oralhistarchiv_backup >/dev/null 2>&1; then
    sudo usermod --append --groups oralhistarchiv-deploy-lock oralhistarchiv_backup
fi
tar -xzf "${release_archives[0]}" -C "$artifact_directory" \
    "${release_root}/deploy/oralhistarchiv-tmpfiles.conf"
sudo install -o root -g root -m 0644 \
    "$artifact_directory/${release_root}/deploy/oralhistarchiv-tmpfiles.conf" \
    /etc/tmpfiles.d/oralhistarchiv.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/oralhistarchiv.conf

sudo python3.11 -I "$artifact_directory/install_release.py" "${release_archives[0]}"

release_path=$(readlink -e /opt/oralhistarchiv)
test -n "$release_path"
sudo test "$(stat -c '%U:%G %a' "$release_path")" = 'root:root 755'
sudo jq -e '.schema_version == 1 and (.source_commit | test("^[0-9a-f]{40}$"))' \
    /opt/oralhistarchiv/release-manifest.json
```

`install_release.py` rejects traversal entries, links, devices, duplicate
members, oversized archives, missing/extra/changed payload files, a non-3.11
runtime, active application services, and a commit/manifest mismatch. It
creates a new root-owned release directory, installs every runtime dependency
from the CI-generated `uv.lock` export with `--require-hashes`, `--no-deps`,
and `--only-binary=:all:`, installs the manifested application wheel with
`--no-index --no-deps`, runs `pip check`, and then atomically changes the
root-managed `/opt/oralhistarchiv` symlink. It never installs development
extras and never resolves an application source checkout. Inherited pip target,
prefix, user and root overrides are discarded; an isolated import probe verifies
that both application packages resolve from this exact release's virtualenv.

The installer holds the exclusive `/run/lock/oralhistarchiv-deploy.lock` for the
entire operation. Both runtime units hold shared locks for their process
lifetimes, while migration and documented maintenance commands hold exclusive
locks. Never delete or replace that lock inode while a process is running.
An unqueryable service state fails closed; a confirmed not-found/inactive unit
is allowed for first installation. Stop all three application units before retry.

Interrupted, unactivated releases are retryable: an incomplete directory without
`.installation-complete` is preserved under `.incomplete-*` before rebuilding.
An interrupted current attempt is cleaned up; the old current-release symlink
is unchanged until final verification succeeds. Completed inactive releases
must pass manifest and installed-import checks before reuse. The active release
is never overwritten. Inspect quarantined content before manually retiring it.

### Security configuration and first administrator

Use the [initial administrator and browser configuration runbook](docs/runbooks/bootstrap-admin.md)
for one-shot terminal bootstrap, host-prefixed security cookies, canonical
request origins and explicit registration opt-in. Long-running services reject
legacy seed credentials. Keep public access closed until initial authenticator
enrollment and a fresh MFA login have succeeded.

The [deployment boundary runbook](docs/runbooks/deployment-boundaries.md)
explains the dedicated lock group, restricted scheduler account reads and clean
installer-owned virtual environments. New archive payloads cannot contain a
`.venv` directory at any depth.

Configure independently acknowledged security-event delivery using the
[security event delivery runbook](docs/runbooks/security-event-delivery.md).
Monitor pending event count/age; stdout collection alone is not a durable sink.
Mailbox capability preservation, issuance budgets and protected account unlock
are documented in the [mail and recovery runbook](docs/runbooks/mail-recovery.md).
Deliberate source rebinding requires the
[source acknowledgement procedure](docs/runbooks/source-rebinding.md).

CI retains dated advisory results for runtime, development/documentation and the
actual build environment. The same checks run weekly; see the
[dependency advisory runbook](docs/runbooks/dependency-advisories.md).

### Runtime state

Immutable releases live under `/opt/oralhistarchiv-releases/`; each directory
name is `oralhistarchiv-release-` plus its source commit, and the directories
are owned by `root:root`; `/opt/oralhistarchiv` is only the current-release
symlink. The service identities need read/execute access but must not own or
write either path. Persistent configuration remains in root-controlled
`/etc/oralhistarchiv`, logs go to journald, and the catalogue-statistics cache
is in memory (with optional general-Redis pub/sub invalidation). Catalogue
writer coordination uses PostgreSQL advisory locks, not Redis. systemd alone
creates the writable `/run/oralhistarchiv` socket directory; the scheduler
cannot access it.

---

## 6. Environment Configuration

Production does not read the repository `.env` or `/opt/oralhistarchiv/.env`.
systemd loads root-controlled files under `/etc`; the service users do not need
filesystem read permission on them.

Create the directory and files before installing or starting any unit:

```bash
sudo install -d -o root -g root -m 0700 /etc/oralhistarchiv
sudo install -o root -g root -m 0600 /dev/null \
  /etc/oralhistarchiv/common.env
sudo install -o root -g root -m 0600 /dev/null \
  /etc/oralhistarchiv/web.env
sudo install -o root -g root -m 0600 /dev/null \
  /etc/oralhistarchiv/scheduler.env
sudo install -o root -g root -m 0600 /dev/null \
  /etc/oralhistarchiv/migration.env
```

Populate `common.env` at `/etc/oralhistarchiv/common.env` with the shared
runtime settings below, replacing every site value and every `GENERATE_*`
value. Generate each secret independently; never reuse a value between keys or
environments.

```bash
ENV_STATE=production
PUBLIC_BASE_URL="https://archive.example.org"
ALLOWED_HOSTS='["archive.example.org"]'
CONTACT_EMAIL="archive@example.org"
PAGINATION_SIZE=20

DATABASE_POOL_SIZE=5
DATABASE_POOL_MAX_WAITING=32
DB_STATEMENT_TIMEOUT="5s"
SCHEDULER_STATEMENT_TIMEOUT="5min"

# Optional best-effort catalogue-cache pub/sub only. This is not the limiter.
REDIS_ENABLED=false
REDIS_URL="redis://127.0.0.1:6379/0"

FASTAPI_DEBUG=false
COOKIES_SECURE=true

SECRET_KEY="GENERATE_INDEPENDENT_TOKEN_URLSAFE_64"
SESSION_SECRET="GENERATE_INDEPENDENT_TOKEN_URLSAFE_64"
OUTBOX_ENCRYPTION_KEYS='["GENERATE_INDEPENDENT_TOKEN_URLSAFE_64"]'
HEALTH_DETAIL_TOKEN="GENERATE_INDEPENDENT_TOKEN_URLSAFE_64"

SESSION_MAX_AGE_SECONDS=28800
SESSION_COOKIE_NAME="__Host-oha_session"
# Registration only: existing local accounts, including administrators,
# retain /login access when new sign-ups are disabled.
LOCAL_REGISTRATION_ENABLED=false
# Site identity: single-line plain text; HTML is escaped in templates.
SITE_NAME="Oral History Archive"
INSTITUTION_NAME="Your institution"
ABOUT_SUMMARY="Search and explore interview metadata from oral history research collections."
FEDERATED_LOGIN_LABEL="Institutional login"
# Blank uses SITE_NAME for newly provisioned authenticator entries.
TOTP_ISSUER_NAME=""
LOGIN_FAILURE_THRESHOLD=10
LOGIN_LOCKOUT_MINUTES=15
UNVERIFIED_REAP_AFTER_DAYS=7

# Phase 1 is local-auth only. Do not define SHIBBOLETH_INTERNAL_SECRET here.
SHIBBOLETH_ENABLED=false
SHIBBOLETH_TRUSTED_ISSUERS='[]'

LOG_LEVEL="INFO"
LOG_FORMAT="json"

LIMITER_COUNTER_CAPACITY=20000
LIMITER_CLEANUP_BATCH_SIZE=128
SEARCH_STATEMENT_TIMEOUT_MS=500
SEARCH_OPERATION_TIMEOUT_SECONDS=1
SEARCH_POOL_TIMEOUT_SECONDS=0.1
SEARCH_GLOBAL_RATE_PER_SECOND=0.5
SEARCH_GLOBAL_BURST=1
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000
RATE_LIMIT_PER_DAY=10000
RATE_LIMIT_TRUST_PROXY=true
TRUSTED_PROXY_IPS='["127.0.0.1","::1"]'

# This is a server-rendered same-origin application; cross-origin access is off.
CORS_ENABLED=false
CORS_ORIGINS='[]'
CORS_ALLOW_METHODS='["GET","POST"]'
CORS_ALLOW_HEADERS='["Authorization","Content-Type"]'
CORS_ALLOW_CREDENTIALS=false

# Required by both runtime processes. Install the reviewed source file
# using the source-file selection procedure before starting services.
SOURCES_CONFIG_FILE="/etc/oralhistarchiv-sources/sources.toml"
ALLOW_FIXTURE_SOURCE=false

# Endpoints, source floors, schedules and harvest budgets are defined in the
# selected source TOML. Do not repeat retired per-source environment settings.

OUTBOX_SENT_RETENTION_DAYS=7
OUTBOX_DEAD_RETENTION_DAYS=30
OUTBOX_RETENTION_BATCH_SIZE=1000
OUTBOX_STALE_AFTER_SECONDS=600

SMTP_ENABLED=true
SMTP_HOST="smtp.example.org"
SMTP_PORT=587
SMTP_USER="REPLACE_WITH_SMTP_USER"
SMTP_PASSWORD="REPLACE_WITH_SMTP_PASSWORD"
SMTP_FROM_ADDRESS="noreply@example.org"
SMTP_FROM_NAME="Oral History Archive"
SMTP_USE_TLS=true
SMTP_CA_BUNDLE=""

# Initial administrator creation uses the one-shot terminal command.
# Never put bootstrap credentials in web or scheduler environment files.
```

Generate secret values from a trusted administrative session, for example:

```bash
python3.11 -c 'import secrets; print(secrets.token_urlsafe(64))'
```

Populate `/etc/oralhistarchiv/web.env` with the web database URL and exactly
one quoted-empty limiter placeholder. The credential-generation step
immediately below replaces that placeholder; it rejects a missing, duplicate,
or already populated entry:

```dotenv
APP_PROCESS_ROLE=web
TOTP_ENCRYPTION_KEYS='["GENERATE_INDEPENDENT_TOKEN_URLSAFE_64"]'
DATABASE_URL="postgresql:///oralhistarchiv?host=%2Fvar%2Frun%2Fpostgresql&user=oralhistarchiv_web"
RATE_LIMIT_REDIS_URL=""
```

For an external limiter, do **not** run the local generator below. Provision
the reviewed non-default ACL user and independent monitoring user at the
provider, then use the approved secret channel to replace this one placeholder
with the authenticated `rediss://` DB-0 URL. Store the monitor credential only
in the monitoring platform's protected store. The application environment and
negative custody checks below still apply; omit only the explicitly labelled
host-local files and checks.

For the reference host-local deployment, generate independent limiter and
read-only monitoring passwords without printing either or placing either in a
command argument. This writes the ACL as
`root:oralhistarchiv-rate-limit-redis 0640`, disables the Redis default user,
atomically replaces the empty limiter placeholder in root-only `web.env`, and
writes the monitor URL to a separate root-only file that no service loads.
Each file replacement is atomic; the three files are not one filesystem
transaction, so an interrupted run requires a custody check before retrying.
The command allowlist matches the bounded fixed-window registry, shared search
gate and functional startup probe. A backend/strategy change must review this
ACL. Existing installations must add the new commands without rotating their
passwords or deleting counters; the generator below is for first installation.

```bash
sudo python3 - <<'PY'
import grp
import os
import secrets
import shlex
import tempfile
from pathlib import Path
from urllib.parse import quote

acl_path = Path("/etc/oralhistarchiv-rate-limit-redis/users.acl")
web_env_path = Path("/etc/oralhistarchiv/web.env")
monitor_env_path = Path("/etc/oralhistarchiv/rate-limit-monitor.env")

web_env = web_env_path.read_text(encoding="utf-8")
retained_lines: list[str] = []
rate_limit_placeholders = 0
for line in web_env.splitlines():
    if line.partition("=")[0].strip() != "RATE_LIMIT_REDIS_URL":
        retained_lines.append(line)
        continue
    rate_limit_placeholders += 1
    existing = shlex.split(line.partition("=")[2].strip())
    if existing != [""]:
        raise SystemExit(
            "RATE_LIMIT_REDIS_URL must be the one empty quoted placeholder; "
            "use reviewed rotation for a configured value"
        )
if rate_limit_placeholders != 1:
    raise SystemExit("web.env must contain exactly one empty RATE_LIMIT_REDIS_URL placeholder")

limiter_password = secrets.token_urlsafe(64)
monitor_password = secrets.token_urlsafe(64)
acl = (
    "user default reset off\n"
    f"user limiter reset on >{limiter_password} ~LIMITS:* resetchannels "
    "+ping +get +ttl +del +evalsha +script|load +time +exists +incrby "
    "+pexpireat +pttl +zrangebyscore +zscore +zcard +zadd +zrem +zrange "
    "+hget +hset +hsetnx +scan +set\n"
    f"user monitor reset on >{monitor_password} resetkeys resetchannels "
    "+ping +info\n"
)
limiter_url = (
    "redis://limiter:"
    + quote(limiter_password, safe="")
    + "@127.0.0.1:6380/0"
)
monitor_url = (
    "redis://monitor:"
    + quote(monitor_password, safe="")
    + "@127.0.0.1:6380/0"
)

def atomic_write(path: Path, data: str, *, mode: int, uid: int, gid: int) -> None:
    """Replace a file with fsynced text and explicit ownership/mode in its existing parent."""
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)

limiter_gid = grp.getgrnam("oralhistarchiv-rate-limit-redis").gr_gid
atomic_write(acl_path, acl, mode=0o640, uid=0, gid=limiter_gid)
atomic_write(
    web_env_path,
    "\n".join(retained_lines).rstrip("\n")
    + f'\nRATE_LIMIT_REDIS_URL="{limiter_url}"\n',
    mode=0o600,
    uid=0,
    gid=0,
)
atomic_write(
    monitor_env_path,
    f'RATE_LIMIT_MONITOR_REDIS_URL="{monitor_url}"\n',
    mode=0o600,
    uid=0,
    gid=0,
)
print("Limiter and monitor ACL credentials installed; no secret was printed")
PY
```

Never put `RATE_LIMIT_REDIS_URL` in `common.env`, `scheduler.env`, shell
profiles, monitoring command arguments, or the general Redis configuration.
For the local reference path, no service may load `rate-limit-monitor.env`;
only an approved root-run monitoring adapter may read it. Rerunning the block
is intentionally refused:
rotate the limiter credential only in a maintenance window by staging matching
ACL and `web.env` changes, restarting the limiter, then restarting the web
process. Rotate the monitor credential independently in the ACL and its
root-only file. The scheduler must remain unaware of every limiter credential.

Populate `/etc/oralhistarchiv/scheduler.env` with the following settings.
Selected JSON-feed bearer/signing environment variables also belong only here,
never in `common.env` or `web.env`; the web process rejects those names even
when their values are empty. The shared TOML source description is nonsecret.
`TOTP_ENCRYPTION_KEYS` belongs only in `web.env` (or an explicitly authorized
TOTP-maintenance process), never in the scheduler environment. Scheduler mail
uses its independent outbox key ring and does not import TOTP encryption.

```dotenv
APP_PROCESS_ROLE=scheduler
PARSER_EXECUTION_MODE=service
ORALHISTARCHIV_PARSER_SOCKET=/run/oralhistarchiv-parser.sock
DATABASE_URL="postgresql:///oralhistarchiv?host=%2Fvar%2Frun%2Fpostgresql&user=oralhistarchiv_scheduler"
```

Populate `/etc/oralhistarchiv/migration.env` with exactly:

```dotenv
ENV_STATE=production
MIGRATION_DATABASE_URL="postgresql:///oralhistarchiv?host=%2Fvar%2Frun%2Fpostgresql&user=oralhistarchiv"
PGHOST=/var/run/postgresql
PGUSER=oralhistarchiv
```

Keep `DATABASE_URL` out of `common.env` and `MIGRATION_DATABASE_URL` out of all
runtime files. The checked-in `deploy/environment/*.env.example` files are
provisioning templates; systemd reads only the separately provisioned `/etc`
files. Never commit live secrets. Setting semantics and defaults are in the
[settings reference](docs/configuration/settings.md).

Edit the files with `sudoedit`, then verify custody and key separation without
printing any values:

```bash
sudoedit /etc/oralhistarchiv/common.env
sudoedit /etc/oralhistarchiv/web.env
sudoedit /etc/oralhistarchiv/scheduler.env
sudoedit /etc/oralhistarchiv/migration.env

sudo stat -c '%U:%G %a %n' \
  /etc/oralhistarchiv \
  /etc/oralhistarchiv/common.env \
  /etc/oralhistarchiv/web.env \
  /etc/oralhistarchiv/scheduler.env \
  /etc/oralhistarchiv/migration.env
# Expected: environment directory root:root 700; environment files root:root
# 600.

# Reference host-local limiter only:
sudo stat -c '%U:%G %a %n' \
  /etc/oralhistarchiv/rate-limit-monitor.env \
  /etc/oralhistarchiv-rate-limit-redis \
  /etc/oralhistarchiv-rate-limit-redis/redis.conf \
  /etc/oralhistarchiv-rate-limit-redis/users.acl
# Expected: monitor file root:root 600; limiter directory
# root:oralhistarchiv-rate-limit-redis 750; its config/ACL
# root:oralhistarchiv-rate-limit-redis 640.

! sudo grep -Eq '^(DATABASE_URL|MIGRATION_DATABASE_URL)=' \
  /etc/oralhistarchiv/common.env
! sudo grep -Eq '^MIGRATION_DATABASE_URL=' \
  /etc/oralhistarchiv/web.env /etc/oralhistarchiv/scheduler.env
! sudo grep -Eq '^SHIBBOLETH_INTERNAL_SECRET=' \
  /etc/oralhistarchiv/common.env /etc/oralhistarchiv/scheduler.env
! sudo grep -Eq '^RATE_LIMIT_REDIS_URL=' \
  /etc/oralhistarchiv/common.env /etc/oralhistarchiv/scheduler.env \
  /etc/oralhistarchiv/migration.env
test "$(sudo grep -Ec '^RATE_LIMIT_REDIS_URL=' \
  /etc/oralhistarchiv/web.env)" -eq 1
# Reference host-local limiter only:
! sudo grep -Eq '^RATE_LIMIT_REDIS_URL=' \
  /etc/oralhistarchiv/rate-limit-monitor.env
test "$(sudo grep -Ec '^RATE_LIMIT_MONITOR_REDIS_URL=' \
  /etc/oralhistarchiv/rate-limit-monitor.env)" -eq 1
! sudo grep -Eq '^RATE_LIMIT_MONITOR_REDIS_URL=' \
  /etc/oralhistarchiv/common.env /etc/oralhistarchiv/web.env \
  /etc/oralhistarchiv/scheduler.env /etc/oralhistarchiv/migration.env
```

Before rotating any signing or encryption key, follow
`docs/runbooks/key-rotation.md`. TOTP and outbox keys are key rings with
re-encryption/retention sequencing; deleting an old key prematurely can make
stored authenticators or queued mail permanently undecryptable.

---

## 7. Gunicorn, Scheduler & Systemd

The application has two long-running runtime units and one static/manual
migration unit:

- **oralhistarchiv.service** — gunicorn web workers, handles HTTP requests
- **oralhistarchiv-scheduler.service** — configured-source harvests, mail
  delivery and maintenance jobs through APScheduler
- **oralhistarchiv-migrate.service** — reviewed Alembic upgrade plus exact
  runtime-grant reapplication; never enabled at boot

Run one scheduler per deployment; web workers do not create a scheduler.
PostgreSQL advisory locks serialize competing ingestion jobs.

### Existing databases

This pre-deployment release uses fresh initialization; current databases are
disposable. Provision an empty PostgreSQL 18 database and run the manual migration
unit plus runtime grants before starting either runtime. Revision `4f73ae3ff827`
creates schema with zero users and catalogue records; sources and registration
populate them, with an explicit bootstrap command for the initial administrator.

Recreate any disposable database made from an earlier body of that baseline:
`upgrade head` does not rerun a recorded revision, and stamping does not install
missing objects. Database recreation remains an explicit operator action;
application/updater tools do not drop databases. Verify the schema and runtime
grants before serving traffic. Once an installation retains data, use the
[inventory and recovery procedure](docs/runbooks/retained-staging-inventory.md)
and a new migration for later schema changes.

### Install the runtime, migration and parser units

```bash
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/oralhistarchiv.service \
  /etc/systemd/system/oralhistarchiv.service
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/oralhistarchiv-scheduler.service \
  /etc/systemd/system/oralhistarchiv-scheduler.service
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/oralhistarchiv-migrate.service \
  /etc/systemd/system/oralhistarchiv-migrate.service
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/oralhistarchiv-parser.socket \
  /opt/oralhistarchiv/oralhistarchiv-parser@.service \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oralhistarchiv-parser.socket
sudo systemctl enable oralhistarchiv.service oralhistarchiv-scheduler.service
# Reference host-local limiter only; omit for an external endpoint.
sudo systemctl enable oralhistarchiv-rate-limit-redis.service
test "$(sudo systemctl is-enabled oralhistarchiv-migrate.service)" = 'static'
if sudo systemctl is-active --quiet oralhistarchiv-migrate.service; then
  echo 'Migration unit must not remain active' >&2
  exit 1
fi

sudo systemd-analyze verify \
  /etc/systemd/system/oralhistarchiv.service \
  /etc/systemd/system/oralhistarchiv-scheduler.service \
  /etc/systemd/system/oralhistarchiv-migrate.service \
  /etc/systemd/system/oralhistarchiv-parser.socket \
  /etc/systemd/system/oralhistarchiv-parser@.service
```

### Parser privilege boundary

The scheduler authenticates a socket-activated parser through Linux
`SCM_CREDENTIALS` before transmitting job inputs. Each accepted connection has
its own dynamic nonroot UID, receives exactly one bounded job, and exits. The
parser starts without any application environment file. The unit executes
`env -i` before Python, retaining only fixed `LANG`, `PATH` and `HOME` values;
this also keeps inherited secrets out of Python's original process environment.
`run_parser.py` repeats the environment reset before importing application modules. OAI uses no service
secrets. A JSON job receives only that selected feed's bearer and signing key,
which its combined fetching/parsing operation requires. No database URL,
session/signing key, TOTP/outbox key, SMTP credential or other source's keys are
included. The catalogue web workers retain nonsecret source policies only.

Install the supplied socket and template unchanged. The socket is root-owned,
mode `0660`, group `oralhistarchiv-scheduler`; its root-owned `/run` parent cannot
be replaced by either runtime. Do not add web users to the scheduler group or
create a database peer mapping for dynamic parser users. The worker unit denies
new Unix sockets and loopback network access, hides other users' processes and
service-secret paths, uses a read-only filesystem, and drops capabilities.
Do not weaken these settings to make a source work. Outbound upstream HTTPS is
allowed. The optional read-only resolver bind uses systemd-resolved's upstream
DNS configuration; other hosts must provide a nonloopback resolver. A localhost
DNS exception would also weaken the database network boundary and is not an
acceptable workaround. Remote databases must require authentication; do not
configure network `trust` rules for parser traffic.

The socket admits at most two active jobs. Each has a 512 MiB memory cap, 16
process/thread tasks, a 250-second service lifetime and whole-cgroup cleanup
within two seconds after termination. Reserve up to 1 GiB for these parser
cgroups **in addition to** the scheduler and web budgets. The existing OAI and
JSON deadlines, bounded result protocol, child termination and cancellation
remain in effect. Disconnecting the scheduler cancels and reaps its worker;
systemd bounds the complete service even if its supervisor is compromised.

`PARSER_EXECUTION_MODE=service` is the default. Staging/production refuse local
mode, missing sockets, unsafe socket ownership and same-UID/root worker replies;
there is no fallback to scheduler-owned parsing. Scheduler startup probes this
boundary before opening PostgreSQL. `PARSER_EXECUTION_MODE=local` is an explicit
`ENV_STATE=dev` convenience for development/tests, not a production sandbox.
Before release, execute the host isolation proof in
`src/tests/host_proofs/parser_sandbox.py` on the reference systemd host,
including real denied process/file/database access. Use a checkout of the exact
release commit on a disposable qualification host, with development test
dependencies in a separate test environment and a disposable Redis instance.
Install that release's wheel/runtime under `/opt` for the worker proof; the
production environment itself does not need pytest or development dependencies.
From the qualification checkout:

```bash
sudo env RUN_PARSER_SANDBOX_TESTS=1 REDIS_URL=redis://127.0.0.1:6379/0 \
  PARSER_PROOF_PYTHON=/opt/oralhistarchiv/.venv/bin/python \
  /path/to/test-environment/bin/python -m pytest --no-cov -q \
  src/tests/host_proofs/parser_sandbox.py
```

The proof interpreter and its installed runtime dependencies must be outside
`/home` and `/root`, which the sandbox hides. The second proof runs the actual
entrypoint, identity handshake and a spawned worker. The test suite resets its
selected Redis database. Pure unit tests cannot
establish kernel/systemd enforcement. Before accepting each job, the service
also verifies its different UID, minimal environment, denied parent-process and
service-file access, forbidden Unix sockets, enforced loopback denial against
its own live test listeners, no new privileges and empty capability set.
Unsupported or ineffective sandboxing fails before the worker's identity hello;
the scheduler therefore sends no job credentials to that service.

The base web unit waits for `network-online.target` and therefore supports an
institutionally managed external limiter. For the reference host-local
dedicated limiter, add this dependency to the **web unit only**. The scheduler
must not receive the limiter URL or a dependency on this service.

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/oralhistarchiv.service.d
sudo install -o root -g root -m 0644 /dev/null \
  /etc/systemd/system/oralhistarchiv.service.d/rate-limit-redis-local.conf
sudo tee \
  /etc/systemd/system/oralhistarchiv.service.d/rate-limit-redis-local.conf \
  >/dev/null <<'EOF'
[Unit]
Requires=oralhistarchiv-rate-limit-redis.service
After=oralhistarchiv-rate-limit-redis.service
EOF
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/oralhistarchiv.service \
  /etc/systemd/system/oralhistarchiv-scheduler.service \
  /etc/systemd/system/oralhistarchiv-rate-limit-redis.service
```

When `RATE_LIMIT_REDIS_URL` names an external endpoint, omit this drop-in; the
functional startup probe remains the authority. With the local drop-in,
stopping the dedicated service also stops the web tier. Runtime limiter
failures are still handled inside the web process because a capacity, command,
or network failure does not necessarily deactivate the systemd service.

Start the dedicated store and prove the bounded counter operations plus
ordinary-restart durability without putting its URL/password in argv, stdout,
or the shell environment. This must succeed before the web service starts:

The durability probe needs one free counter slot. If the registry is full,
wait for natural expiry; do not clear a live quota. Normal application readiness
uses a reserved control key and can succeed with a full valid counter registry.

```bash
sudo systemctl start oralhistarchiv-rate-limit-redis.service
sudo /opt/oralhistarchiv/.venv/bin/python -I - <<'PY'
import os
import shlex
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from redis import Redis
from redis.backoff import NoBackoff
from redis.exceptions import AuthenticationError, NoPermissionError
from redis.retry import Retry

def load_url(path: str, key: str) -> str:
    """Read one shell-quoted assignment; exit on a missing, duplicate or malformed value."""
    content = Path(path).read_text(encoding="utf-8")
    matches = [
        line.partition("=")[2].strip()
        for line in content.splitlines()
        if line.partition("=")[0].strip() == key
    ]
    if len(matches) != 1:
        raise SystemExit(f"{path} must contain exactly one {key}")
    parts = shlex.split(matches[0])
    if len(parts) != 1:
        raise SystemExit(f"{key} is malformed")
    return parts[0]

url = load_url("/etc/oralhistarchiv/web.env", "RATE_LIMIT_REDIS_URL")
monitor_url = load_url(
    "/etc/oralhistarchiv/rate-limit-monitor.env",
    "RATE_LIMIT_MONITOR_REDIS_URL",
)
for candidate, expected_user in ((url, "limiter"), (monitor_url, "monitor")):
    parsed = urlsplit(candidate)
    if (parsed.scheme, parsed.username, parsed.hostname, parsed.port, parsed.path) != (
        "redis",
        expected_user,
        "127.0.0.1",
        6380,
        "/0",
    ):
        raise SystemExit(f"{expected_user} URL does not select its local ACL user")

# Load the web unit's configuration in the same order before the public
# middleware facade initializes settings. The Shibboleth file is optional;
# the examples use one NAME=value assignment per line.
for env_path, optional in (
    ("/etc/oralhistarchiv/common.env", False),
    ("/etc/oralhistarchiv/web.env", False),
    ("/etc/oralhistarchiv/shibboleth.env", True),
):
    path = Path(env_path)
    if optional and not path.exists():
        continue
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, value = stripped.partition("=")
        parts = shlex.split(value, comments=True)
        if not separator or len(parts) != 1:
            raise SystemExit("Unsupported application environment-file assignment")
        os.environ[name.strip()] = parts[0]

from app.middleware import BoundedRedisStorage
from config import settings

def storage() -> BoundedRedisStorage:
    """Build limiter storage with configured capacity, half-second I/O limits and no retries."""
    return BoundedRedisStorage(
        url,
        counter_capacity=settings.limiter_counter_capacity,
        cleanup_batch_size=settings.limiter_cleanup_batch_size,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
        retry_on_timeout=False,
        retry=Retry(NoBackoff(), retries=0),
        wrap_exceptions=True,
    )

probe = f"deployment-aof-probe-{time.time_ns()}"
before = storage()
if not before.probe() or before.incr(probe, 300) != 1:
    raise SystemExit("limiter functional probe failed")
remaining_before_restart = before.get_expiry(probe) - time.time()
if before.get(probe) != 1 or not 0 < remaining_before_restart <= 300:
    raise SystemExit("limiter read/TTL probe failed")
before.get_connection().close()

subprocess.run(
    ["systemctl", "restart", "oralhistarchiv-rate-limit-redis.service"],
    check=True,
)
after = storage()
if not after.probe():
    raise SystemExit("limiter did not recover after ordinary restart")
remaining_after_restart = after.get_expiry(probe) - time.time()
if (
    after.get(probe) != 1
    or not 0 < remaining_after_restart <= 300
):
    raise SystemExit("live limiter quota did not survive ordinary restart")
monitor = Redis.from_url(
    monitor_url,
    socket_connect_timeout=0.5,
    socket_timeout=0.5,
    retry_on_timeout=False,
)
if not monitor.ping():
    raise SystemExit("limiter monitoring ACL cannot ping")
unauthenticated = Redis(
    host="127.0.0.1",
    port=6380,
    socket_connect_timeout=0.5,
    socket_timeout=0.5,
    retry_on_timeout=False,
)
try:
    unauthenticated.ping()
except AuthenticationError:
    pass
else:
    raise SystemExit("limiter Redis default user is not disabled")
finally:
    unauthenticated.close()

try:
    monitor.get("LIMITS:deployment-monitor-acl-probe")
except NoPermissionError:
    pass
else:
    raise SystemExit("limiter monitoring ACL unexpectedly has key-read authority")

try:
    after.get_connection().info()
except NoPermissionError:
    pass
else:
    raise SystemExit("web limiter ACL unexpectedly has INFO authority")

server = monitor.info("server")
memory = monitor.info("memory")
stats = monitor.info("stats")
persistence = monitor.info("persistence")
redis_version = str(server.get("redis_version", ""))
try:
    redis_major = int(redis_version.partition(".")[0])
except ValueError as exc:
    raise SystemExit("limiter Redis did not report a valid version") from exc
if redis_major < 7:
    raise SystemExit("limiter Redis 7 or newer is required")
if memory.get("maxmemory_policy") != "noeviction":
    raise SystemExit("limiter Redis is not using noeviction")
if persistence.get("aof_enabled") != 1:
    raise SystemExit("limiter AOF is not enabled")
if persistence.get("aof_last_write_status") != "ok":
    raise SystemExit("limiter AOF write status is not healthy")
if persistence.get("aof_last_bgrewrite_status") != "ok":
    raise SystemExit("limiter AOF rewrite status is not healthy")
if stats.get("evicted_keys") != 0:
    raise SystemExit("limiter reports evicted keys")
after.clear(probe)
after.get_connection().close()
monitor.close()
print("Dedicated limiter command, policy and restart checks passed")
PY
```

The subsequent web startup validates retained counter registration and capacity,
probes reserved control-key write/read/expiry/delete operations, and checks the
shared search start gate before opening PostgreSQL. That
probe is the final ACL/command compatibility gate; `systemctl is-active` alone
is not readiness.

For an external dedicated limiter, omit the local OS identity, config, ACL
generator, unit, drop-in, and local restart command. Provision equivalent
Redis 7+ service/version evidence, physical capacity, `noeviction`, restart
persistence and ACL isolation at the provider. Use `rediss://` with
certificate verification, a non-default
username, independently generated `secrets.token_urlsafe(64)` password,
database 0 (an empty path or `/0`), and no URL query parameters. Plain
`redis://` is permitted only for the loopback endpoint; query parameters are
forbidden because redis-py can use them to override connection options. URL
fragments are also rejected. Settings and startup enforce the URL policy, then
inspect the effective connection pool for bounded timeouts, disabled retries,
required certificate verification and hostname checks. Replace the one empty
`RATE_LIMIT_REDIS_URL` placeholder in root-only
`web.env` through the approved secret-provisioning channel; never put it in
`common.env` or `scheduler.env`.

Provision an independent external monitoring ACL user with no key/channel
access and only PING/INFO authority. Its credential belongs in the monitoring
platform's protected secret store, never an application environment file.
Record provider evidence for capacity, policy, persistence, ACLs and restart
survival, then require the web startup's functional probe before admitting
traffic.

Per-client admission is mandatory for staging and production web processes.
When Redis is unavailable, retain the fail-closed refusals or stop public web
traffic while repairing it. Do not set `RATE_LIMIT_ENABLED=false`, flush live
counters, or substitute process-local memory. Restore the backend, repeat the
functional readiness probe, and restart with admission enabled before reopening
traffic. Use a separately restricted administrative channel for maintenance.

All three unit files ship at the repository root. The runtime units must load
`common.env` plus their own database overlay; only the web unit may also load
the optional Phase-2 `shibboleth.env`. The migration unit loads only
`migration.env`.

```bash
sudo systemctl cat oralhistarchiv.service \
  oralhistarchiv-scheduler.service oralhistarchiv-migrate.service
sudo systemctl show oralhistarchiv.service \
  -p User -p Group -p UMask -p RuntimeDirectoryMode -p EnvironmentFiles \
  -p UnsetEnvironment -p RestrictAddressFamilies -p SyslogIdentifier
sudo systemctl show oralhistarchiv-scheduler.service \
  -p User -p Group -p UMask -p InaccessiblePaths -p EnvironmentFiles \
  -p UnsetEnvironment -p RestrictAddressFamilies -p SyslogIdentifier
sudo systemctl show oralhistarchiv-migrate.service \
  -p User -p Group -p UMask -p EnvironmentFiles -p UnsetEnvironment \
  -p RestrictAddressFamilies -p SyslogIdentifier
```

Expected environment-file order:

- web: `common.env`, `web.env`, optional `shibboleth.env`;
- scheduler: `common.env`, `scheduler.env`;
- migration: `migration.env` only.

The effective unit files must contain these exact environment directives:

```ini
# oralhistarchiv.service
EnvironmentFile=/etc/oralhistarchiv/common.env
EnvironmentFile=/etc/oralhistarchiv/web.env
EnvironmentFile=-/etc/oralhistarchiv/shibboleth.env
UnsetEnvironment=PYTHONPATH PYTHONHOME VIRTUAL_ENV RATE_LIMIT_MONITOR_REDIS_URL

# oralhistarchiv-scheduler.service
EnvironmentFile=/etc/oralhistarchiv/common.env
EnvironmentFile=/etc/oralhistarchiv/scheduler.env
Environment=APP_PROCESS_ROLE=scheduler PARSER_EXECUTION_MODE=service
UnsetEnvironment=PYTHONPATH PYTHONHOME VIRTUAL_ENV RATE_LIMIT_REDIS_URL RATE_LIMIT_MONITOR_REDIS_URL TOTP_ENCRYPTION_KEYS

# oralhistarchiv-migrate.service
EnvironmentFile=/etc/oralhistarchiv/migration.env
UnsetEnvironment=PYTHONPATH PYTHONHOME VIRTUAL_ENV RATE_LIMIT_REDIS_URL RATE_LIMIT_MONITOR_REDIS_URL
```

The socket boundary additionally depends on all of these exact settings:

```ini
# oralhistarchiv.service
User=oralhistarchiv
Group=oralhistarchiv-proxy
UMask=0077
RuntimeDirectory=oralhistarchiv
RuntimeDirectoryMode=0750
```

and on Gunicorn applying `umask = 0o117` while creating the socket. Together
they must yield `/run/oralhistarchiv` as
`oralhistarchiv:oralhistarchiv-proxy 0750` and `gunicorn.sock` as
`oralhistarchiv:oralhistarchiv-proxy 0660`. The only non-web identity allowed
in `oralhistarchiv-proxy` is the dedicated nginx worker account verified in
§8. A different owner, group, mode, Gunicorn mask, or group membership blocks
deployment.

Any Alembic `ExecStartPre` in a runtime unit blocks deployment. All three units
must use `WorkingDirectory=/opt/oralhistarchiv` and unset Python import
overrides. The web unit additionally strips the monitoring credential; the
scheduler and migration units strip both limiter credentials even if an
operator accidentally injects them through the systemd manager environment or
an environment file. The scheduler and migration commands must invoke the
installed environment with Python isolated mode (`-I`); production must never
import application code from a source-tree `PYTHONPATH`.

### Apply the reviewed schema and runtime grants

For a fresh installation, keep both runtimes stopped and start the manual unit
against the operator-prepared empty database. For any later schema-changing
release, retain the maintenance/backup procedure and its reviewed migration
plan; this changed baseline is not an in-place upgrade for an initialized
database:

```bash
sudo systemctl stop oralhistarchiv.service oralhistarchiv-scheduler.service \
  2>/dev/null || true
sudo systemctl start oralhistarchiv-migrate.service
sudo systemctl is-failed --quiet oralhistarchiv-migrate.service && exit 1
sudo journalctl -u oralhistarchiv-migrate.service --since=-10m --no-pager

sudo -u oralhistarchiv \
  psql -X --no-password --dbname=oralhistarchiv \
  --username=oralhistarchiv_web --set=ON_ERROR_STOP=1 \
  --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
sudo -u oralhistarchiv-scheduler \
  psql -X --no-password --dbname=oralhistarchiv \
  --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1 \
  --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
```

Do not enable the migration unit or invoke Alembic from a runtime or interactive
shell. The unit runs installed Python with `-I` and loads only
`MIGRATION_DATABASE_URL` from `migration.env` (Unix socket `/var/run/postgresql`).
Its single `deploy/migrate_release.py` command pins the resolved release and
performs the upgrade followed by `deploy/database-runtime-grants.sql` under one
exclusive deployment lock. There is no separate `ExecStartPost` lock gap.
Both inventory checks above must succeed before a runtime starts.

The web role has `DELETE` on `users` for guarded account deletion and trusted
federation replacement of an unverified local reservation. Application services
validate current authority and credentials before deleting; account-owned rows
cascade in the same transaction. Keep this grant and the exact runtime privilege
contract together when applying a release. It does not grant catalogue deletion
to the web role.

The initial revision `4f73ae3ff827` creates an empty catalogue and empty
`sync_status`; source rows provisioned later start with NULL clean and consumed
cursors/fingerprints. It enables base-table RLS and creates `catalogue_discovery` and
`dataset_admin_catalogue` for a fresh installation. It requires the matching
grants/access-inventory checks above. It performs no DOI backfill,
historical-account conversion or retrofit of a database already marked with
that revision. See “Existing databases” before using an initialized database.

Catalogue RLS is a record-tier boundary for the exact web role. Unset, empty or
invalid viewer context defaults to public; query services set trusted context
transaction-locally. The public discovery view deliberately uses the owner to
preserve only approved discovery and opaque ordering, and the separate control
view exposes only identity/classification. Scheduler ingestion and read-only
`BYPASSRLS` backups retain their separate authority. The shared web role can set
its viewer setting; authenticated application code and E2 field redaction remain
part of the boundary. See `docs/architecture/field-visibility.md` for scope.

### Required source-file selection

Both runtime processes require an explicit nonempty `SOURCES_CONFIG_FILE`.
Select the same reviewed TOML for web and scheduler. Missing or empty selection,
file errors, invalid configuration and startup-policy failures abort startup
without fallback. Settings may omit the selector for imports and migration
tools; that does not permit either runtime process to start.

Keep `/etc/oralhistarchiv` root:root `0700` and its environment files `0600`.
The application opens source TOML itself, so install it in a separate readable
directory. Store no secrets or credential-bearing URLs in this file.

Prepare a reviewed TOML using `deploy/environment/sources.example.toml` as a
schema example. Replace its placeholders and review the fixture entry. When
preserving an existing catalogue, retain its source name and exact interpretation
inputs, including endpoint, institution filter and visibility policy.

While both runtime services are stopped:

```bash
sudo install -d -o root -g root -m 0755 /etc/oralhistarchiv-sources
sudo install -o root -g root -m 0644 /path/to/reviewed-sources.toml \
  /etc/oralhistarchiv-sources/sources.toml
sudo namei -l /etc/oralhistarchiv-sources/sources.toml
```

Every ancestor must be a direct root-owned directory without group/other write
permission. Both runtime identities need directory read/search access and file
read access. The existing `ProtectSystem=strict` permits these reads.

Set these values in shared `common.env`, with no conflicting process overlays:

```dotenv
SOURCES_CONFIG_FILE="/etc/oralhistarchiv-sources/sources.toml"
ALLOW_FIXTURE_SOURCE=false
```

Remove retired source settings and the mock-seeding key from every active
environment file and inherited environment; false or empty values are still
rejected. The [settings reference](docs/configuration/settings.md) lists their
source-TOML replacements. Normal production keeps `ALLOW_FIXTURE_SOURCE=false`.
Both bundled synthetic adapters, `fixture` and `static_json`, require explicit
permission when selected in production. Permission does not select an adapter
or bypass source-file validation.

Validate as both runtime identities before starting services:

```bash
for runtime_user in oralhistarchiv oralhistarchiv-scheduler; do
  sudo -u "$runtime_user" /opt/oralhistarchiv/.venv/bin/python -I -c \
    'from app.sources import load_sources_for_startup; sources = load_sources_for_startup("/etc/oralhistarchiv-sources/sources.toml", environment="production"); print(tuple(source.name for source in sources))'
done
```

Both checks must print the same reviewed ordered selection. They construct and
validate without fetching or touching PostgreSQL. Actual service startup still
applies shared-security and database preflights.

Keep both services stopped during file replacement, then restart both. Each
process retains its startup snapshot. Actual ownership, access under deployed
identities and service namespaces, endpoints and resource limits remain VM
acceptance checks.

### Start and verify

```bash
sudo systemctl start oralhistarchiv.service oralhistarchiv-scheduler.service
# Reference host-local limiter only. For an external endpoint, verify its
# provider health plus the successful web functional probe instead.
sudo systemctl is-active --quiet oralhistarchiv-rate-limit-redis.service
sudo systemctl is-active --quiet oralhistarchiv.service
sudo systemctl is-active --quiet oralhistarchiv-scheduler.service
sudo systemctl status oralhistarchiv.service \
  oralhistarchiv-scheduler.service \
  --no-pager --full
sudo systemctl status oralhistarchiv-rate-limit-redis.service \
  --no-pager --full  # reference host-local limiter only

sudo namei -l /run/oralhistarchiv/gunicorn.sock
sudo stat -Lc 'type=%F owner=%U group=%G mode=%a path=%n' \
  /run/oralhistarchiv /run/oralhistarchiv/gunicorn.sock
# Expected directory: oralhistarchiv:oralhistarchiv-proxy 750
# Expected socket:    oralhistarchiv:oralhistarchiv-proxy 660

sudo -u oralhistarchiv curl --fail --silent --show-error \
  --unix-socket /run/oralhistarchiv/gunicorn.sock \
  -H 'Host: archive.example.org' \
  http://localhost/health | jq -e '.status == "alive"'

sudo journalctl -u oralhistarchiv.service --since=-10m --no-pager
sudo journalctl -u oralhistarchiv-scheduler.service --since=-10m --no-pager
```

The scheduler should log `"Scheduler started"` and then an initial sync
attempt within a few seconds. `/health` is liveness only; it is not a database,
Redis, or scheduler readiness check.

### Verify the Unix-socket boundary before nginx

At this stage nginx need not be installed, so only unrelated-UID negative
controls are meaningful:

```bash
OHA_SOCKET_CONNECT='import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect("/run/oralhistarchiv/gunicorn.sock"); s.close()'

! sudo -u oralhistarchiv-scheduler python3 -c "$OHA_SOCKET_CONNECT" \
  >/dev/null 2>&1
! sudo -u nobody python3 -c "$OHA_SOCKET_CONNECT" >/dev/null 2>&1

# Gunicorn must not expose a TCP listener. Investigate any matching row.
! sudo ss -H -ltnp | grep -E 'gunicorn|oralhistarchiv'
```

Both socket commands must fail before an application response. Success or a
Gunicorn TCP listener blocks deployment. A firewall is not a substitute for
the directory and socket inode permissions. The positive nginx-worker test is
performed immediately after nginx is authorized in §8.

`MemoryMax=1G` covers the scheduler and its SMTP children. In production,
harvests run in separate parser cgroups: reserve their combined capacity of up
to 1 GiB in addition to scheduler/web memory. OAI limits are 4 MiB per response
page, 32 MiB aggregate response bytes, 20,000 records, 1 MiB per record and
16 MiB serialized results. Its 240-second deadline excludes bounded cleanup
and result decoding. These byte budgets do not bound Python RSS.

Before activation or budget changes, qualify near-limit harvests alongside mail
delivery and measure both scheduler and parser cgroup peaks. An OOM kill may
leave no `sync_status` diagnostic; alert on kernel/service OOM evidence too.

### Verify the scheduler isn't running in web workers

```bash
# The web journal should NOT contain "Scheduler started" or OAI-PMH sync messages
sudo journalctl -u oralhistarchiv | grep -i "scheduler\|oai-pmh"
# Should produce no output
```

### Verify per-process database identity

After both services are running, check pg_stat_activity to confirm the
web and scheduler processes identify themselves correctly:

```bash
sudo -u postgres psql -d oralhistarchiv -c \
    "SELECT pid, usename, application_name, state FROM pg_stat_activity WHERE datname = 'oralhistarchiv'"
```

Should show entries with `application_name` set to `oralhistarchiv-web`
and `oralhistarchiv-scheduler`. If you see `psycopg` instead, the
scheduler's pool isn't being created with the right identifier.

---

## 8. Nginx & SSL

### Install nginx and authorize its effective worker identity

```bash
sudo apt install -y nginx

# Resolve exactly one effective worker user from the configuration nginx
# itself accepts. Never guess a distro default or continue on an absent,
# duplicate, root, unsafe, or nonexistent account.
set -o pipefail
OHA_NGINX_WORKER_USER="$(
  sudo nginx -T 2>&1 | awk '
    /^[[:space:]]*user[[:space:]]+/ {
      value = $2
      sub(/;.*/, "", value)
      users[++count] = value
    }
    END {
      if (count != 1 || users[1] == "") exit 1
      print users[1]
    }
  '
)" || {
  echo "Could not resolve exactly one nginx worker user from nginx -T" >&2
  exit 1
}
case "$OHA_NGINX_WORKER_USER" in
  root|*[!A-Za-z0-9_.-]*)
    echo "Unsafe nginx worker user: $OHA_NGINX_WORKER_USER" >&2
    exit 1
    ;;
esac
getent passwd "$OHA_NGINX_WORKER_USER" >/dev/null || {
  echo "nginx worker account does not exist: $OHA_NGINX_WORKER_USER" >&2
  exit 1
}
if [ "$(id -u "$OHA_NGINX_WORKER_USER")" -eq 0 ]; then
  echo "nginx workers must not run with uid 0" >&2
  exit 1
fi

getent group oralhistarchiv-proxy >/dev/null \
  || sudo groupadd --system oralhistarchiv-proxy
sudo usermod --append --groups oralhistarchiv-proxy \
  "$OHA_NGINX_WORKER_USER"

# A running worker does not acquire a newly added supplementary group.
sudo nginx -t
sudo systemctl restart nginx

# Inventory every member and every process running under the authorized UID.
# Only the web process and this dedicated nginx worker identity may hold the
# proxy group; interactive users and unrelated daemons are forbidden.
getent group oralhistarchiv-proxy
id "$OHA_NGINX_WORKER_USER"
ps -eo pid,user,group,comm,args
mapfile -t OHA_NGINX_WORKER_PIDS \
  < <(pgrep -u "$OHA_NGINX_WORKER_USER")
if ((${#OHA_NGINX_WORKER_PIDS[@]} == 0)); then
  echo "No live nginx-worker-UID process found" >&2
  exit 1
fi
for pid in "${OHA_NGINX_WORKER_PIDS[@]}"; do
  sudo sed -n '/^Name:/p;/^Uid:/p;/^Gid:/p;/^Groups:/p' "/proc/$pid/status"
done

# Raw AF_UNIX connect isolates filesystem admission from TrustedHost/HTTP.
OHA_SOCKET_CONNECT='import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect("/run/oralhistarchiv/gunicorn.sock"); s.close()'
sudo -u "$OHA_NGINX_WORKER_USER" python3 -c "$OHA_SOCKET_CONNECT"
! sudo -u oralhistarchiv-scheduler python3 -c "$OHA_SOCKET_CONNECT" \
  >/dev/null 2>&1
! sudo -u nobody python3 -c "$OHA_SOCKET_CONNECT" >/dev/null 2>&1
```

The positive command must connect and both negative commands must fail. Review
every process listed for `$OHA_NGINX_WORKER_USER`: if the UID also runs PHP-FPM
or another service, give this nginx instance a dedicated worker UID/instance;
otherwise that other service inherits Gunicorn socket authority. Repeat this
entire block after every nginx `user` directive, group, unit, or socket change.

### SSL certificate

**Option A — Let's Encrypt** (if the VM is publicly accessible):

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d archive.example.org
```

**Option B — Institutional certificate:**

```bash
sudo cp your-cert.crt /etc/ssl/certs/oralhistarchiv.crt
sudo cp your-cert.key /etc/ssl/private/oralhistarchiv.key
sudo chmod 600 /etc/ssl/private/oralhistarchiv.key
```

### Install nginx config

```bash
sudo install -o root -g root -m 0644 \
    /opt/oralhistarchiv/deploy/nginx-ordinary-proxy-headers.conf.example \
    /etc/nginx/snippets/oralhistarchiv-ordinary-proxy-headers.conf
sudo install -o root -g root -m 0644 \
    /opt/oralhistarchiv/deploy/nginx.conf.example \
    /etc/nginx/sites-available/oralhistarchiv

sudoedit /etc/nginx/sites-available/oralhistarchiv
```

**Required edits in the config:**

- `server_name` — your domain
- `ssl_certificate` and `ssl_certificate_key` paths
- Static file alias path if your deployment path differs
- The initial edge-zone rates/bursts only after a production-equivalent load
  test that includes the largest expected university NAT and monitoring source

The example's Shibboleth callback returns 404 in Phase 1. Replace that entire
location with the complete SP-authorized proxy block in §9 only after the SP,
attribute mappings, and internal secret are verified. Do not add a second
callback location: duplicate exact-match locations make `nginx -t` fail.

**Critical security notes on the nginx config:**

1. The Phase-1 `location = /auth/shibboleth/callback` block must continue to
   return 404. In Phase 2 it is replaced, not supplemented, by the complete
   SP-authorized callback block in §9. Correctness does not depend on file
   order because the exact-match `=` location has priority.

2. Every location that proxies an ordinary client request to Gunicorn must
   include `/etc/nginx/snippets/oralhistarchiv-ordinary-proxy-headers.conf`
   exactly once. It sets the canonical Host/client-address/scheme metadata and
   clears `X-OHA-Internal-Auth`, every fixed `X-OHA-Shib-*` header, and the
   legacy/raw Shibboleth names. This includes `/health` and every future
   special proxy location; sibling locations do not inherit
   `proxy_set_header` directives from `location /`. `/health/detail` has no
   separate exact location and therefore receives this contract through
   `location /`.

   The SP-authorized Phase-2 callback is the sole exception. It must use
   `proxy_pass_request_headers off` and its own explicit SP-derived header
   allowlist; never include the ordinary clearing fragment in that callback.

3. The application-facing federation header contract is fixed in code:
   `X-OHA-Internal-Auth`, `X-OHA-Shib-Issuer`, `X-OHA-Shib-Subject`,
   `X-OHA-Shib-Mail`, `X-OHA-Shib-Authn-Context`,
   `X-OHA-Shib-Display-Name`, `X-OHA-Shib-Affiliation`,
   `X-OHA-Shib-Entitlement`, and `X-OHA-Shib-Country`. Ordinary locations clear
   all of them, plus the raw `eduPersonEntitlement` and `entitlement` names. Only the
   SP-authorized callback may populate them, from explicitly mapped SP output.
   Legacy/raw Shibboleth names are also cleared and must never be consumed by
   application code.

4. location / uses oralhistarchiv_req (20 requests/s, burst 40) and
   oralhistarchiv_conn (20 connections per client address). /health uses
   separate 2 requests/s, burst 10 and 5-connection limits. The optional exact
   health-detail block still needs explicit limits before activation. The
   Phase-2 fragment explicitly applies separate SSO limits to both public
   locations: 2 requests/s with burst 10 and 8 concurrent requests per client;
   a shared virtual-host budget of 10 requests/s with burst 20 and 16 concurrent
   requests across both locations. Those nginx preaccess checks run before the
   access-phase authorizer and before responder FastCGI work. Shared-memory
   zones cover all workers on one nginx instance, not independent edge hosts.
   Keep the Phase-1 callback closed until the SP capacity and the largest
   expected university NAT pass the federation runbook's acceptance checks.
   If another proxy is added, review trusted real-IP
   handling; never key limits from arbitrary request paths or forwarding headers.

5. `/static/` repeats the server's HSTS policy because its `Cache-Control`
   directive replaces inherited `add_header` directives. Keep both HSTS values
   identical when changing the policy; `always` also covers missing assets.

6. Use oralhistarchiv_safe for access logs and remove inherited duplicate
   access logs. This format omits paths, queries and Referer. Generated email
   actions carry only a non-secret public ID in the HTTP request target; their
   separately emailed security code is entered explicitly in a POST body.
   nginx error logs can still retain arbitrary targets, including obsolete token URLs sent by a
   client. Review error-log custody and the action-link cutover before opening
   traffic; see docs/runbooks/action-links.md.

### Enable the site

```bash
sudo ln -s /etc/nginx/sites-available/oralhistarchiv \
    /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

### Verify

```bash
set -euo pipefail

archive_host="$(
  sudo awk '
    $1 == "server_name" && $2 != "_" {
      host = $2
      sub(/;$/, "", host)
      if (host !~ /[<>]/) {
        print host
        exit
      }
    }
  ' /etc/nginx/sites-enabled/oralhistarchiv
)"
test -n "$archive_host"

sudo nginx -t
sudo systemctl reload nginx

curl --fail --silent --show-error \
  --resolve "${archive_host}:443:127.0.0.1" \
  "https://${archive_host}/health" |
  jq -e 'type == "object" and keys == ["status"] and .status == "alive"'

# Exercise only the small, independent health edge bucket. The output must
# contain both 200 and 429; this must not consume the dynamic application quota.
for attempt in $(seq 1 20); do
  curl --silent --output /dev/null --write-out '%{http_code}\n' \
    --resolve "${archive_host}:443:127.0.0.1" \
    "https://${archive_host}/health"
done | sort | uniq -c

# Inspect a 429 while the bucket is exhausted. The example supplies neither
# Retry-After nor Cache-Control: no-store on edge rejections.
curl --silent --dump-header - --output /dev/null \
  --resolve "${archive_host}:443:127.0.0.1" \
  "https://${archive_host}/health"

for config_file in \
  /etc/nginx/sites-enabled/oralhistarchiv \
  /etc/nginx/snippets/oralhistarchiv-ordinary-proxy-headers.conf
do
  test "$(sudo stat -Lc '%U:%G %a' "$config_file")" = 'root:root 644'
done
```

### Verify client IP propagation

After nginx is in place, verify that audit logs show real client IPs
rather than nginx's loopback IP:

```bash
# Hit the app from an external machine, then check the audit log entry
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.event_type == "request") | .client_ip' | tail -5
```

Should show the external client IP. If you see `127.0.0.1` for requests
from external hosts, the three-way IP trust contract is broken — verify
nginx sets `X-Real-IP`, gunicorn has `forwarded_allow_ips = ""`, and the
app's `RATE_LIMIT_TRUST_PROXY=true` with the right `TRUSTED_PROXY_IPS`.

---

## 9. Shibboleth SP

Use [Integrating a Shibboleth SP with the fixed header contract](docs/runbooks/federation-integration.md)
for the generic SP configuration, attribute mapping, ordered pre-flip checklist,
negative spoofing tests, controlled canary and federation rollback boundary.
The reviewed deployment record holds the actual federation registration,
issuer, attribute release and host acceptance evidence outside this repository.

Keep `SHIBBOLETH_ENABLED=false` and the exact callback at nginx's direct
`return 404` until the runbook's staged edge preparation permits replacement.
Do not set the application flag until every pre-flip gate has passed. Repository
tests and a completed documentation template do not establish real Gate F.

The generic runbook describes the current application behavior, including
`POST /logout`: whenever federation is enabled, all callers pass through the
fixed same-origin SP logout handler after application-session deletion; when
disabled, logout returns to `/`. No request parameter chooses the return URL.

For a suspected internal-credential disclosure, follow the stopped-web-first
[key-rotation incident procedure](docs/runbooks/key-rotation.md) before
configuration changes. Routine federation rollback has a different boundary.

---

## 10. Firewall

```bash
sudo apt install -y ufw

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

sudo ufw enable
sudo ufw status verbose
```

**Verify Gunicorn and Redis are not directly accessible:**

```bash
# These should all time out or be refused. A Redis NOAUTH response still proves
# that the port is exposed and therefore fails this check.
curl http://YOUR_VM_IP:5000
redis-cli -h YOUR_VM_IP -p 6380 PING
# Run only when optional general cache/pub-sub Redis was intentionally enabled:
redis-cli -h YOUR_VM_IP -p 6379 PING
```

---

## 11. Backups

Back up all selected and retained source data, accounts, credentials, sessions,
outbox state and administrative state. PostgreSQL custom format
(`pg_dump --format=custom`) is not encryption.

The shipped backup path therefore has five mandatory boundaries:

1. a read-only OS/PostgreSQL identity distinct from the application;
2. a `0700` directory and `0600` encrypted temporary/final file modes;
3. no filesystem plaintext: `pg_dump` streams directly into `age`;
4. atomic publication only after database/schema preflight and successful dump
   and encryption processes; and
5. an `age` private identity held off-host under separate recovery custody.

### Generate the backup encryption identity off-host

On a trusted recovery workstation—not on the application/database VM—generate
an `age` identity:

```bash
umask 077
age-keygen -o oralhistarchiv-backup.agekey
age-keygen -y oralhistarchiv-backup.agekey
```

The second command prints the public `age1...` recipient. Provision only that
public value on the VM. Escrow the private identity in the institutional secret
store under access control separate from the archive store and application
environment files. Do not put it in Git, `/etc/oralhistarchiv`, a VM snapshot,
or the directory containing the archives.

### Install the tracked backup unit

Install the script outside the immutable release. Root ownership of the
executable and units remains load-bearing: application service identities can
read the root-owned `/opt/oralhistarchiv` release but cannot change it.

```bash
sudo install -D -o root -g root -m 0755 \
    /opt/oralhistarchiv/deploy/oralhistarchiv-backup.sh \
    /usr/local/libexec/oralhistarchiv-backup

sudo install -o root -g root -m 0644 \
    /opt/oralhistarchiv/deploy/oralhistarchiv-backup.service \
    /etc/systemd/system/oralhistarchiv-backup.service
sudo install -o root -g root -m 0644 \
    /opt/oralhistarchiv/deploy/oralhistarchiv-backup.timer \
    /etc/systemd/system/oralhistarchiv-backup.timer

sudo install -o root -g root -m 0600 \
    /opt/oralhistarchiv/deploy/oralhistarchiv-backup.conf.example \
    /etc/oralhistarchiv-backup.conf
sudoedit /etc/oralhistarchiv-backup.conf
```

Replace `BACKUP_AGE_RECIPIENT` with the public recipient generated above. The
configuration must remain `root:root` mode `0600`. Although the recipient is
public, root-owned configuration prevents an attacker from redirecting future
backups to an attacker-controlled key or changing the database/path. systemd
reads `EnvironmentFile=` before dropping to `oralhistarchiv_backup`; the script
does not source this file.

After migrations have created the tables, confirm that the backup role can read
but not write them:

```bash
sudo -u oralhistarchiv_backup psql -XAt --no-password -d oralhistarchiv -c \
    "SELECT has_table_privilege('oralhistarchiv_backup', 'users', 'SELECT'),
            has_table_privilege('oralhistarchiv_backup', 'users', 'INSERT');"
```

Expected output is `t|f`. This smoke check does not replace the complete backup
preflight: the backup role must remain read-only `BYPASSRLS`, have no memberships
and hold SELECT on every managed table. If `SELECT` is false, keep the runtimes stopped and
reapply the reviewed grant manifest through the manual migration unit; never
solve it by giving the backup role ownership or write permission.

The unit creates `/var/lib/oralhistarchiv-backup` as
`oralhistarchiv_backup:oralhistarchiv_backup` mode `0700`, sets `UMask=0077`,
allows only the PostgreSQL Unix-socket address family, and makes
`/etc/oralhistarchiv` protected by root-only filesystem permissions. The script 
refuses a missing, symlinked, wrongly owned, or non-`0700` directory. Before dumping, 
it confirms the configured database and role, its `BYPASSRLS`/membership contract,
the exact Alembic revision shipped with the backup script, and SELECT coverage
for all managed tables. `pg_dump` retains its default `row_security=off`; it
must fail rather than silently produce an RLS-filtered archive. It then streams
the custom-format dump directly through `age` into a hidden `0600` ciphertext file: no plaintext dump
is written to any filesystem. `set -o pipefail` makes a `pg_dump` or `age` failure 
abort publication; a completed ciphertext is synced, renamed atomically to `*.dump.age`, 
and its directory is synced. Retention runs only after successful publication and always 
keeps the new archive plus the immediately preceding local archive. That previous copy 
is not automatically "known good"—only an isolated restore can establish that.

`EXPECTED_ALEMBIC_REVISION` deliberately binds the installed backup script to
the release schema. A changed Alembic head requires the matching constant (the
unit contract compares it with the head); deployment must install the matching script.
A mismatched release fails the backup visibly instead of silently archiving an
unexpected revision. This release pins the single baseline head `4f73ae3ff827`.
The baseline label alone cannot distinguish its older bodies; the complete
schema/view/policy and runtime inventories must also
pass. Pause/drain the old backup before replacing its executable, complete the
operator-prepared schema and grant checks, then restart the timer only after
the current baseline schema and both runtime access inventories pass (§17).

The supplied config enables `BACKUP_STATUS_DIR`. Provision its separate
backup-owned `0755` directory before the first run, or set that variable empty
to disable the marker:

```bash
sudo install -o root -g root -m 0644 \
  /opt/oralhistarchiv/deploy/oralhistarchiv-backup-tmpfiles.conf \
  /etc/tmpfiles.d/oralhistarchiv-backup.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/oralhistarchiv-backup.conf
```

To report its age through authenticated health detail, set
`BACKUP_STATUS_FILE="/var/lib/oralhistarchiv-backup-status/last-success"` in
`web.env` before restarting web. The marker proves local publication only;
continue monitoring the backup unit result, off-host copies and restore drills.

Enable the timer and force one initial run:

```bash
sudo systemd-analyze verify \
    /etc/systemd/system/oralhistarchiv-backup.service \
    /etc/systemd/system/oralhistarchiv-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now oralhistarchiv-backup.timer
sudo systemctl start oralhistarchiv-backup.service

sudo systemctl status oralhistarchiv-backup.service --no-pager
sudo systemctl list-timers oralhistarchiv-backup.timer
sudo journalctl -u oralhistarchiv-backup.service --since "1 hour ago"
```

Do not add the old user crontab. A pipeline ending in `logger` can hide the
backup command's exit status; the oneshot unit preserves it for monitoring.
Configure host monitoring to alert when the service fails or when no new
`*.dump.age` appears within the expected interval. An active timer does not
prove that the last backup succeeded.

### Verify custody and failure behaviour

After the initial run, inspect the effective unit and filesystem boundary:

```bash
sudo systemctl show oralhistarchiv-backup.service \
    --property=User --property=Group --property=UMask \
    --property=ProtectSystem --property=ProtectHome \
    --property=StateDirectory --property=StateDirectoryMode \
    --property=EnvironmentFiles --property=InaccessiblePaths \
    --property=ReadWritePaths --property=RestrictAddressFamilies \
    --property=SystemCallFilter
sudo systemctl cat oralhistarchiv-backup.service oralhistarchiv-backup.timer

sudo namei -l /var/lib/oralhistarchiv-backup
sudo stat -c '%U:%G %a %n' /var/lib/oralhistarchiv-backup
sudo find /var/lib/oralhistarchiv-backup -maxdepth 1 -type f \
    -name '*.dump.age' -exec stat -c '%U:%G %a %n' {} \;
sudo getfacl -p /var/lib/oralhistarchiv-backup

sudo namei -l /etc/oralhistarchiv-backup.conf \
    /usr/local/libexec/oralhistarchiv-backup
sudo stat -c '%U:%G %a %n' /etc/oralhistarchiv-backup.conf \
    /usr/local/libexec/oralhistarchiv-backup
sudo getfacl -p /etc/oralhistarchiv-backup.conf \
    /usr/local/libexec/oralhistarchiv-backup

sudo -u oralhistarchiv test ! -r /var/lib/oralhistarchiv-backup
sudo -u oralhistarchiv test ! -x /var/lib/oralhistarchiv-backup
sudo -u nobody test ! -r /var/lib/oralhistarchiv-backup
sudo -u nobody test ! -x /var/lib/oralhistarchiv-backup
```

Expected: the directory is `0700`, final archives are `0600`, and neither the
web identity nor an unrelated UID can traverse it. There must be no durable
plaintext `*.dump` or hidden plaintext temporary file. Hidden interrupted files
may only match `.oralhistarchiv-encrypted.*`; a subsequent run removes them
before starting. The installed configuration is `root:root 0600`; the installed
script is `root:root 0755`; neither has an ACL granting unexpected access.

On a disposable staging host, also perform a failure drill: save the root-only
configuration, temporarily select a nonexistent `PGDATABASE`, run the service,
then restore the configuration. The unit must fail, publish no new final
archive, preserve older archives, and trigger the configured alert. Never
perform that drill by editing the root-owned installed script or unit.

### Off-host copy and verification

Copy only `*.dump.age` artifacts to authenticated, access-controlled off-host
storage. Prefer versioning or immutability appropriate to the retention policy.
Storage-side encryption is defense in depth, not a replacement for `age`: the
archive must already be encrypted before a storage reader receives it.
`age` provides confidentiality and detects ciphertext modification during
decryption; it does **not** authenticate the producer because anyone who knows
the public recipient can create a decryptable ciphertext. Backup provenance
therefore depends on the authenticated transfer identity and immutable or
versioned storage record. If storage writers are not fully trusted, require a
separately controlled detached signature or storage-native signed provenance;
a checksum alone is not producer authentication.

The off-host retention policy must keep the last archive whose isolated restore
was recorded as successful until a successor has also passed that restore test,
subject to the approved maximum data-retention period. Local filename/age and a
successful timer run are not evidence that an archive is restore-verified.

Install `deploy/oralhistarchiv-backup-verify.sh` on the trusted recovery host,
not as a scheduled service on the application VM. Install `age` and a
`pg_restore` version at least as new as the producing PostgreSQL client. With a
local archive and the private identity:

```bash
install -D -m 0755 deploy/oralhistarchiv-backup-verify.sh \
    "$HOME/.local/bin/oralhistarchiv-backup-verify"

"$HOME/.local/bin/oralhistarchiv-backup-verify" \
    oralhistarchiv_YYYYMMDDTHHMMSSZ.dump.age \
    /secure/escrow/oralhistarchiv-backup.agekey
```

The verification script rejects a group/other-readable private identity,
streams the decrypted archive through `pg_restore --list`, and fully drains the
authenticated stream. It writes no plaintext file. This checks decryption and
the archive table of contents; it is **not** a data-completeness or restore test.

At least once per release and after any key/custody change, use an
isolated, disposable PostgreSQL cluster that cannot reach production. Create a new empty
database, restore into it as its owner/recovery identity, and require the
following commands to succeed (set the `PGHOST`, `PGPORT`, and `PGUSER` values
for that disposable cluster only). The backup identity does not receive DDL or
DML to perform restoration. Provision reviewed runtime/backup role attributes
in the isolated cluster separately; production role membership or peer mapping
is not inherited by a logical restore.

```bash
set -Eeuo pipefail
export PGHOST=/run/postgresql-restore-test
export PGPORT=5432
export PGUSER=restore_operator
restore_db="oralhistarchiv_restore_$(date -u +%Y%m%dT%H%M%SZ)"

createdb --maintenance-db=postgres --template=template0 "$restore_db"
trap 'dropdb --if-exists --maintenance-db=postgres "$restore_db"' EXIT

age --decrypt --identity /secure/escrow/oralhistarchiv-backup.agekey \
    oralhistarchiv_YYYYMMDDTHHMMSSZ.dump.age \
    | pg_restore --exit-on-error --single-transaction \
        --no-owner --no-privileges --dbname="$restore_db"

psql -XAt --no-password --dbname="$restore_db" --set=ON_ERROR_STOP=1 <<'SQL'
SELECT count(*) = 1 AND bool_and(btrim(version_num) <> '')
FROM alembic_version;
SELECT to_regclass('public.oral_history_datasets') IS NOT NULL
   AND to_regclass('public.sync_status') IS NOT NULL
   AND to_regclass('public.users') IS NOT NULL
   AND to_regclass('public.email_outbox') IS NOT NULL
   AND to_regclass('public.sessions') IS NOT NULL;
SELECT 'oral_history_datasets', count(*) FROM oral_history_datasets
UNION ALL SELECT 'users', count(*) FROM users
UNION ALL SELECT 'email_outbox', count(*) FROM email_outbox
UNION ALL SELECT 'sessions', count(*) FROM sessions;
SQL
```

Both Boolean queries must return `t`. Review the counts for obvious truncation
and compare them with an independently approved backup-time metric if one is
collected; the backup job deliberately does not place sensitive catalogue or
account counts in its logs. Reapply the reviewed grant inventory to this
explicitly isolated target, then repeat the complete catalogue/source-state
comparison as the read-only `oralhistarchiv_backup` identity. Its `BYPASSRLS`
attribute and all-table SELECT must reveal public, registered, vetted and hidden
rows, matching the owner result. Check the restored view definitions, RLS flags,
policies, web default-public reads and scheduler operations under their actual
restricted identities. Do not give backup ownership, CREATE, INSERT, UPDATE or
DELETE to make these checks pass. The tracked grant manifest names the production
database explicitly; review its database target before using it in a drill.

Then exercise login/TOTP and outbox decryption using
the application key-ring versions applicable to that archive. Preserve the
dated result without secrets or row contents, drop the database, and destroy the
disposable recovery environment.

E3's automated checks use disposable roles/databases and do not close E4's
deployment-host role, custody or representative encrypted-restore acceptance.

For a production restore, enter the maintenance procedure in §17 and stream
directly to `pg_restore` under `set -o pipefail`, as in the isolated drill. Add
`--clean --if-exists --no-owner --no-privileges` for the approved production
target and require `--exit-on-error --single-transaction`; do not create a
plaintext archive file. Do not copy the backup private identity into the
application environment files for this step, and remove it from the recovery environment
after the restore is verified.

Keep the private identity for an old backup recipient until every archive made
for it has expired or been re-encrypted and a restore with the successor has
succeeded. Historical archives may also require old `TOTP_ENCRYPTION_KEYS` and
`OUTBOX_ENCRYPTION_KEYS`; backup encryption does not replace application key
escrow. See `docs/runbooks/key-rotation.md`.

**Redis is deliberately excluded from the PostgreSQL backup set.** The
dedicated limiter's AOF is local operational persistence for short-lived
rate-limit counters, not an archive or audit source. AOF is required so an
ordinary service restart does not reset still-valid quotas; it is not copied
into long-term backups because restoring stale counters after a disaster is
not useful. Optional general cache/pub-sub Redis is also not backed up. After
loss of the limiter host/state, keep nginx admission in place, provision a new
empty dedicated instance and ACL, verify the hardened configuration, and
restart the web tier. Treat the quota reset as a security event and monitor
closely until the longest configured limit window has passed.

---

## 12. Log Management

### Initial setup

Install the journald retention configuration:

```bash
sudo install -D -o root -g root -m 0644 \
  /opt/oralhistarchiv/deploy/journald-oralhistarchiv.conf \
  /etc/systemd/journald.conf.d/oralhistarchiv.conf

sudo systemctl restart systemd-journald
```

This caps journal disk usage and sets retention policy.

### Application logs via systemd-journald

Application/audit logging uses stdout; systemd-journald also captures stderr
and manages host-wide rotation and retention for all workers.

### Retention configuration

The journald config file (`/etc/systemd/journald.conf.d/oralhistarchiv.conf`)
contains:

```ini
[Journal]
# Cap total journal disk usage. Adjust based on /var/log volume size.
SystemMaxUse=2G

# Per-file cap. journald's default is one eighth of SystemMaxUse (256M here);
# 128M halves that, so rotation runs more often and expired space frees sooner.
SystemMaxFileSize=128M

# Time-based retention.
MaxRetentionSec=30day
```

These host-wide settings cap age at 30 days and total journal usage at 2 GiB;
space pressure can remove records sooner. Approve both limits against required
retention, or provide sufficient off-host retention. Do not create an
unencrypted local log export.

### Off-host audit log shipping (optional)

Use host-level rsyslog over RELP+TLS to forward the journal. The collector must
separately provide approved retention, access control and tamper evidence:

```bash
sudo apt install -y rsyslog-relp   # omrelp is not in the base rsyslog package
sudo install -o root -g root -m 0640 \
  /opt/oralhistarchiv/deploy/rsyslog-oralhistarchiv.conf.example \
  /etc/rsyslog.d/30-oralhistarchiv.conf
sudoedit /etc/rsyslog.d/30-oralhistarchiv.conf
# Install the collector CA and client certificate/key under a root-controlled
# directory using the modes required by the rsyslog service account.
sudo rsyslogd -N1
sudo systemctl restart rsyslog
```

Collector endpoint, transport (RELP vs RFC 5425 TLS-syslog), CA, and client
certificate enrollment are provided by your infrastructure team — confirm these in the
onboarding consultation.

**PRE-FLIGHT — remote shipping is not an active control until every item passes:**

- [ ] `systemctl cat oralhistarchiv.service` contains
      `SyslogIdentifier=oralhistarchiv`.
- [ ] `systemctl cat oralhistarchiv-scheduler.service` contains
      `SyslogIdentifier=oralhistarchiv-scheduler`.
- [ ] `systemctl cat oralhistarchiv-backup.service` contains
      `SyslogIdentifier=oralhistarchiv-backup`.
- [ ] `systemctl cat oralhistarchiv-migrate.service` contains
      `SyslogIdentifier=oralhistarchiv-migrate`.
- [ ] The effective rsyslog rule selects `_SYSTEMD_UNIT` for exactly those
      four units and does not select them by `$programname` or `$syslogtag`.
- [ ] Audit email logging uses the keyed HMAC hash, not raw addresses, and the
      audit-hash key is not present in the shipped stream.
- [ ] `queue.maxDiskSpace` is bounded, `action.resumeRetryCount` is `-1`, and
      suspension plus continuation reporting are enabled for the named action
      `oralhistarchiv_remote_audit`.
- [ ] `sudo rsyslogd -N1` exits successfully before rsyslog is restarted.
- [ ] A genuine web request event, a genuine scheduler lifecycle/job event,
      and a genuine backup event are visible both in their unit journals and
      at the collector. On every release that applies a migration, the
      successful `oralhistarchiv-migrate.service` event is also present at the
      collector. A `logger -t` canary is not acceptable because it does not
      prove that the real unit stream matches the filter.
- [ ] Monitoring alerts on rsyslog action suspension, queue-disk growth, and
      absence of each expected unit stream. Remote retention and access
      control have been approved for FADP/GDPR audit data.

Use these local checks after installing the units and rsyslog rule:

```bash
sudo systemctl daemon-reload
sudo systemctl restart oralhistarchiv.service oralhistarchiv-scheduler.service
sudo systemctl start oralhistarchiv-backup.service

sudo journalctl -u oralhistarchiv.service -n 100 -o json | \
  jq -se 'map(select(.SYSLOG_IDENTIFIER == "oralhistarchiv")) | length > 0 and all(._SYSTEMD_UNIT == "oralhistarchiv.service")'
sudo journalctl -u oralhistarchiv-scheduler.service -n 100 -o json | \
  jq -se 'map(select(.SYSLOG_IDENTIFIER == "oralhistarchiv-scheduler")) | length > 0 and all(._SYSTEMD_UNIT == "oralhistarchiv-scheduler.service")'
sudo journalctl -u oralhistarchiv-backup.service -n 100 -o json | \
  jq -se 'map(select(.SYSLOG_IDENTIFIER == "oralhistarchiv-backup")) | length > 0 and all(._SYSTEMD_UNIT == "oralhistarchiv-backup.service")'
sudo journalctl -u oralhistarchiv-migrate.service -n 100 -o json | \
  jq -se 'map(select(.SYSLOG_IDENTIFIER == "oralhistarchiv-migrate")) | length > 0 and all(._SYSTEMD_UNIT == "oralhistarchiv-migrate.service")'

sudo rsyslogd -N1
sudo systemctl restart rsyslog.service
sudo journalctl -u rsyslog.service --since "10 minutes ago" --no-pager | \
  grep -E 'oralhistarchiv_remote_audit|action suspended|action resumed'
sudo du -sh /var/spool/rsyslog/relp_oralhistarchiv_fwd* 2>/dev/null || true
```

The final collector-side confirmation is deployment acceptance evidence and
must identify the web, scheduler, and backup streams, plus the migration stream
for every release that ran it. Keep `remote audit shipping` marked
inactive in the control register until that evidence exists.

### Sensitive data scrubbing

Audit logs:

- use matched route templates rather than concrete parameter values;
- scrub action-token paths when no matched route is available;
- retain only bounded query structure/presence, not submitted values or
  unknown parameter names; and
- redact configured secrets and known credential formats.

See `request_utils.py` for request-target sanitization and
`config/logging.py` for formatter-level defense in depth. When adding a new
token-bearing route, extend the fallback formatter patterns and the route
inventory regression tests in the same change.

### Nginx logs

The `oralhistarchiv_safe` access-log format is a load-bearing security
control. It must be selected by every server capable of handling archive
traffic, including default-reject and HTTP-redirect servers. Static locations
must inherit that format, and no second inherited combined log may receive
the same traffic. The active format must not contain `$request`,
`$request_uri`, `$uri`, `$args`, or `$http_referer`.

Inspect the effective configuration, not only the site file:

```bash
sudo nginx -T 2>&1 | \
  grep -nE 'log_format|access_log|\$request|\$request_uri|\$uri|\$args|\$http_referer'
```

`nginx -T` prints the complete effective configuration and, in Phase 2, may
include the literal `X-OHA-Internal-Auth` secret from the root-only include. Do
not paste or retain its complete output
in tickets, CI logs, or shared terminals. Confirm manually that every active
`access_log` for this site selects `oralhistarchiv_safe`; the presence of a
safe format definition alone is not sufficient.

Use a synthetic public-ID action link and a separate canary security code.
Confirm the code is absent from all nginx access/error logs, the application
journal, and forwarded copies after GET, 403, 415, 422, 429, and same-origin
static-asset requests. The generated URL has no query, fragment or secret. For
the 429 case, verify the non-secret public ID is present in the error log so the check
proves rejection logging was exercised. Keep the shipped error-log settings;
do not suppress the log to obtain a pass. Never use a live action token or
record POST bodies. Raw legacy targets can still be logged before the app
rejects them. Follow docs/runbooks/action-links.md for queued-message cutover,
reissue and complete-link custody.

Standard nginx logrotate remains configured at `/etc/logrotate.d/nginx`.

### Systemd journal

Both gunicorn and scheduler services log to the journal:

```bash
# Web service
sudo journalctl -u oralhistarchiv --since "1 hour ago"
sudo journalctl -u oralhistarchiv -f

# Scheduler
sudo journalctl -u oralhistarchiv-scheduler --since "1 hour ago"
sudo journalctl -u oralhistarchiv-scheduler -f

# Encrypted backup oneshot service
sudo journalctl -u oralhistarchiv-backup.service --since "1 week ago"
```

### Querying audit events

The app emits structured JSON logs. Filter with `jq`:

```bash
# All audit events
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.event_type)'

# Specific event type
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.event_type == "login_success")'

# Trace a specific request by request_id
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.request_id == "abc12345")'

# Failed login attempts
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.path == "/login" and .status_code == 401)'

# All restricted dataset accesses by a specific user
sudo journalctl -u oralhistarchiv -o cat | jq -R 'fromjson? | select(.event_type == "dataset_access" and .user_id == 42)'
```

Audit classification follows the field projection, not merely the row's
`visibility_tier`. Rendering only the policy-defined catalogue fields (`id`,
`uuid`, `title`, `access_level`, `version`, `source`, and `visibility_tier`)
is an intentional public disclosure and does not require a restricted-object
event. If home/search/recent renders any other field from a non-public record
to an authorized tier, it is a restricted-content disclosure and must emit the
bounded object-level event defined by the application audit contract.

---

## 13. Monitoring

### Health check script

Create the host-owned check outside the immutable release at
`/usr/local/libexec/oralhistarchiv-health-check`:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 /dev/null \
  /usr/local/libexec/oralhistarchiv-health-check
sudoedit /usr/local/libexec/oralhistarchiv-health-check
```

Paste this complete script and set the production URL and approved alert
recipient. The host must have a configured `mail` command; otherwise connect
the same HTTPS check to the institutional monitoring service instead of cron.

```bash
#!/bin/bash
set -euo pipefail

HEALTH_URL="https://archive.example.org/health"
ALERT_EMAIL="admin@example.org"

HTTP_CODE="$(
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --max-time 10 "$HEALTH_URL" || printf '000'
)"

if [ "$HTTP_CODE" != "200" ]; then
  printf 'ALERT: Oral History Archive health check failed (HTTP %s)\n' \
    "$HTTP_CODE" | mail -s "OHA Health Check FAILED" "$ALERT_EMAIL"
  exit 1
fi
```

```bash
sudo chown root:root /usr/local/libexec/oralhistarchiv-health-check
sudo chmod 0755 /usr/local/libexec/oralhistarchiv-health-check
```

Schedule:

```bash
sudo crontab -e
```

```
*/5 * * * * /usr/local/libexec/oralhistarchiv-health-check
```

### Detailed health check (internal)

```bash
curl -H "Authorization: Bearer YOUR_HEALTH_DETAIL_TOKEN" \
    https://archive.example.org/health/detail
```

`/health` is process liveness, not Redis readiness. Monitor the limiter backend
and edge admission separately:

```bash
# Reference host-local limiter. For an external endpoint, collect equivalent
# provider availability, memory, persistence/rewrite and restart metrics.
systemctl is-active oralhistarchiv-rate-limit-redis.service
systemctl show oralhistarchiv-rate-limit-redis.service \
  --property=MemoryCurrent --property=MemoryMax --property=NRestarts
sudo journalctl -u oralhistarchiv-rate-limit-redis.service --since=-1h \
  --no-pager

sudo journalctl -u oralhistarchiv -o cat | \
  jq -R 'fromjson? | select(.event_type == "rate_limit_backend_unavailable") |
    {timestamp, backend_failure_category, request_id, path, exception_type}'
sudo awk '$0 ~ /"status":429|"status":503/' \
  /var/log/nginx/oralhistarchiv_access.log | tail -50
```

Collect Redis `INFO memory`, `INFO stats`, and `INFO persistence` through a
separate monitoring ACL limited to `+ping +info` and no key access. Give its
independent credential only to the approved monitoring agent through its
protected credential mechanism; never pass either monitoring or web limiter
password through `redis-cli -a`, a process argument, or a log. The one-off
credential-safe §7 verification shows the fields and invariants to monitor.

Alert on limiter unavailability/restarts, rejected connections, AOF failures,
unexpected `evicted_keys` growth, sustained limiter `503`, sustained nginx
`429`, and memory/AOF disk without tested headroom. Slice the application alert
by the bounded `backend_failure_category`: `capacity`, `authentication`,
`authorization`, `timeout`, `connection`, `command`, `concurrency`,
`configuration`, `storage`, or `unexpected`.
Authentication/authorization/configuration normally indicate credential or
deployment drift; capacity/storage indicate resource pressure or a generic
known storage failure; connection/timeout indicate reachability; concurrency
indicates backend contention; command indicates a rejected/mismatched Redis
operation; and unexpected means an unclassified dependency or adapter defect
that requires code/dependency investigation. Public responses deliberately
remain the same generic 503. Do not alert on a single edge `429`; ordinary
client bursts can legitimately consume a burst allowance.

The logical counter cap can produce `capacity` refusals while Redis still has
physical memory headroom. Treat this as controlled admission pressure; do not
flush counters, delete registry entries or enable eviction. Monitor the
`search_start_budget_exhausted` and `search_unavailable` events separately from
ordinary pool failures, and correlate their rates with mixed-traffic latency
and PostgreSQL activity. A search refusal alone does not mean that the ordinary
account pool is exhausted.

The detailed health route intentionally does not make limiter failure look
like database failure. Optional general Redis health is a separate cache
performance signal, not limiter readiness.

### Scheduler liveness

The scheduler service has no HTTP health endpoint. Monitor it via:

```bash
# Is it running?
systemctl is-active oralhistarchiv-scheduler

# When was the last sync?
sudo -u oralhistarchiv-scheduler psql -X --no-password \
  --dbname=oralhistarchiv --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1 --command="SELECT source, last_harvest_date, last_sync_error, last_sync_error_at, last_rebuild_error, last_rebuild_error_at FROM sync_status ORDER BY source"
```

`last_harvest_date` records the start time of a successfully finalized harvest;
it is not a process heartbeat. For each selected source, alert when it is
missing or older than twice that source's `incremental_interval_seconds` in the
selected TOML. Check `last_full_rebuild_date` against that source's
`rebuild_interval_seconds` as well. Inspect both error channels, scheduler logs
and service state to distinguish failed, stalled or long-running work from a
stopped scheduler. Historical rows for unselected sources are not scheduled
sources' liveness signals.

---

## 14. Memory Tuning

Both systemd units set `MemoryMax` as a safety net. Initial values:

- **oralhistarchiv.service** — 1024M (up to 4 gunicorn workers)
- **oralhistarchiv-scheduler.service** — 1G (scheduler and SMTP children;
  parser cgroups are additional)

The scheduler value is a conservative starting ceiling, not reserved memory or
a proven bound for every source. Confirm host capacity alongside web workers,
PostgreSQL and Redis, and qualify the aggregate scheduler `MemoryPeak` before
activation. Reducing the ceiling requires repeating that qualification.

All password hashing, checking, rehashing and dummy work share a dedicated
per-worker limiter. `PASSWORD_WORK_CONCURRENCY=1` is the default: four workers
times one 64 MiB Argon2 operation reserve roughly 256 MiB, leaving 768 MiB of
the web limit for interpreter, libraries, requests and other process memory.
The setting is capped at two; four workers at two operations consume about 512 MiB before other memory. Password
parameters are unchanged. Existing hashes can encode different memory costs:
measure representative retained hashes and the aggregate cgroup peak before
raising concurrency or worker count. General-purpose thread-pool capacity is
not the password memory budget.

`PASSWORD_WORK_ADMISSION_TIMEOUT_SECONDS` bounds each operation's wait for a
slot: default 1 second, finite range 0.01–5 seconds. Exhausted admission starts no
password work and returns HTTP 503 with `Retry-After: 5`. Tune against measured
hash durations and expected arrivals. The budget does not interrupt running
hashes or impose an absolute queue-size limit; waiting requests still consume
request memory. Keep the existing request/rate limits and monitor
`MemoryCurrent` under load. Requests that verify and then rehash may wait twice.
Step-up and recovery reservations made before waiting remain consumed on a
capacity timeout, so repeated retries still spend the existing attempt budget.

Tune these after observing real usage. To check current memory:

```bash
systemctl show oralhistarchiv --property=MemoryCurrent
systemctl show oralhistarchiv-scheduler --property=MemoryCurrent
```

**Signs you need to raise the limit:**

- `journalctl -u oralhistarchiv | grep -i "oom\|killed"`
- Scheduler `oom-kill`/signal-9 entries during OAI-PMH full rebuilds
- Scheduler service restarting unexpectedly

**Signs you can lower the limit:**

- `MemoryCurrent` stays well below the cap for weeks under load
- VM is memory-constrained overall

To adjust:

```bash
sudo systemctl edit oralhistarchiv.service
# In the editor, add (using the reviewed measured value):
# [Service]
# MemoryMax=1536M
sudo systemctl daemon-reload
sudo systemctl restart oralhistarchiv
sudo systemctl show oralhistarchiv --property=MemoryMax
```

Search reserves one additional PostgreSQL connection per web worker in its
dedicated pool. Include it in the database connection budget; it never borrows
the ordinary pool. Defaults admit one shared search start every two seconds,
with burst one, a 500 ms SQL timeout, a one-second operation deadline and a
100 ms acquisition timeout. A nonblocking PostgreSQL transaction advisory lock
allows one active search across workers sharing the database. The operation
deadline is followed by rollback/connection cleanup before the local permit is
released. Rollback has a separate one-second deadline; a failed rollback closes
the connection, and connection close/pool return can extend the cleanup period.
Empty browsing, filters, literal/full-text terms, numbered pages,
cursor continuation and page restarts all use this boundary.

Staging/production requires `SEARCH_GLOBAL_BURST=1` and
`SEARCH_GLOBAL_RATE_PER_SECOND * SEARCH_OPERATION_TIMEOUT_SECONDS <= 0.5`.
The SQL and acquisition timeouts must each be shorter than the operation
deadline. Search gates remain active when ordinary per-client limiting is
disabled. A refusal or timeout returns retryable, non-cacheable 503 without
using the ordinary pool or retrying through another query mode. Validate
simultaneous search/login/detail traffic using the
[capacity acceptance procedure](docs/runbooks/search-fulltext.md#capacity-and-load-acceptance).
Connection separation does not reserve PostgreSQL CPU, memory or I/O; retain
representative latency measurements before changing the budgets.

Gunicorn uses one worker when `RATE_LIMIT_REDIS_URL` is absent and up to four
when the dedicated limiter is configured. General `REDIS_ENABLED` does not
control worker count. Staging/production web startup rejects a missing or
unusable limiter URL, and storage errors never switch to local counters. If
measured web RSS is too high, lower the worker cap only after load testing.
Worker recycling remains enabled and is safe because security quotas live in
the dedicated process and ordinary limiter restarts reload its AOF.

Redis `maxmemory` is not a complete process-memory cap: allocator overhead,
client buffers, and AOF rewrite buffers can sit outside it. Size the host or a
separate Redis systemd cgroup from measured rewrite peaks rather than setting
its service limit equal to `maxmemory`; doing so can make an otherwise healthy
rewrite trigger an OOM kill and fail closed all dynamic requests.

---

## 15. CI/CD

CI is committed at `.github/workflows/ci.yml` and runs on every push and pull
request: `ruff`, `mypy`, `bandit`, and `pip-audit` (against the locked
dependency set), plus `pytest` against a PostgreSQL service **and** a Redis
service with `REQUIRE_DB=1` and `REQUIRE_REDIS=1` (so a dead service container
fails the run instead of silently skipping its tier). CI also installs nginx
and sets `REQUIRE_NGINX=1`, making effective nginx-template parsing a blocking
test, and enforces the branch-coverage threshold. The workflow token has only
`contents: read`; every third-party action is pinned to a reviewed full commit
SHA and checkout does not persist its token. Do not hand-create a second
workflow—edit the committed one and keep Dependabot's reviewed action updates.

Deployment is a manual, two-person release operation using §5 and §17. CI is
the only release builder. A production artifact is emitted only by a manual
workflow run on `main`, after every blocking job passes for the same full Git
commit. The host verifies GitHub's artifact digest, the inner archive digest,
and the release manifest before installing a hash-locked runtime graph and the
exact tested wheel. Production never checks out source, runs a package build,
or installs development dependencies. Migrations never run during web or
scheduler startup; a reviewed operator invokes the static/manual migration
unit while both runtimes are stopped, then verifies the exact runtime grants.

Repository rules must require `lint`, `typecheck`, `security`, `wheel-smoke`,
and `tests` before `main` can be merged. The workflow file cannot prove that
GitHub-side rules are enabled; verify them in repository settings before the
first release.

---

## 16. Post-Deployment Checklist

```
Configuration
[ ] common.env has independent SECRET_KEY, SESSION_SECRET,
    OUTBOX_ENCRYPTION_KEYS and HEALTH_DETAIL_TOKEN values; independent
    TOTP_ENCRYPTION_KEYS belong only in web.env; no live key is a placeholder
    or reused across purposes/environments
[ ] PUBLIC_BASE_URL is the public https:// URL; ALLOWED_HOSTS lists the
    public hostname
[ ] FASTAPI_DEBUG=false
[ ] Both runtime processes use the same reviewed source selection;
    ALLOW_FIXTURE_SOURCE=false for the normal production catalogue
[ ] RATE_LIMIT_ENABLED=true
[ ] web.env alone contains the generated dedicated RATE_LIMIT_REDIS_URL;
    common.env, scheduler.env, migration.env, logs and command lines do not
[ ] systemd UnsetEnvironment strips RATE_LIMIT_MONITOR_REDIS_URL from web and
    strips both RATE_LIMIT_REDIS_URL and RATE_LIMIT_MONITOR_REDIS_URL from
    scheduler and migration
[ ] If optional general cache/pub-sub Redis is used, REDIS_ENABLED=true and
    REDIS_URL select a different process/credential from the limiter
[ ] RATE_LIMIT_TRUST_PROXY=true
[ ] DATABASE_POOL_MAX_WAITING has a positive, load-tested bound (initially 32)
[ ] PostgreSQL connection sizing includes one additional search connection per
    web worker; search never uses the ordinary pool as fallback
[ ] Search budgets retain burst one and rate × operation deadline ≤0.5; all
    modes meet the representative mixed search/login load acceptance
[ ] journald retention config installed at
    /etc/systemd/journald.conf.d/oralhistarchiv.conf
[ ] `/etc/oralhistarchiv` is root:root 0700; `common.env`, `web.env`,
    `scheduler.env`, and `migration.env` are root:root 0600
[ ] `common.env` contains no `DATABASE_URL`, `MIGRATION_DATABASE_URL`,
    `TOTP_ENCRYPTION_KEYS`, feed credentials or `SHIBBOLETH_INTERNAL_SECRET`;
    runtime overlays contain no migration URL
[ ] TOTP keys are web/maintenance-only; selected feed credentials are scheduler-only
[ ] The separate parser socket/service is installed; its real denial proof passes
    and scheduler startup authenticates a distinct, sandboxed worker identity
[ ] web, scheduler, migration-owner, and backup peer mappings pass; requesting
    any other role/database as those OS identities is rejected
[ ] `oralhistarchiv-migrate.service` is installed, static, and inactive
[ ] web reports `current_user=oralhistarchiv_web`; scheduler reports
    `current_user=oralhistarchiv_scheduler`; both exact privilege preflights pass
[ ] the owner role is not used by web, scheduler, backup, an interactive shell,
    or an application maintenance command

Services
[ ] /opt/oralhistarchiv is a symlink to a root:root 0755 directory under
    /opt/oralhistarchiv-releases
[ ] release-manifest.json source_commit equals the approved CI run commit
[ ] the downloaded ZIP matched that run's GitHub artifact SHA-256
[ ] the release contains the three application units, dedicated limiter unit
    and config, plus the bootstrap, grant, access-verification, nginx, backup,
    and migration assets checked in §5
[ ] .venv contains no editable Oral-History-Archive install and no dev extras
[ ] postgresql.service is running
[ ] The dedicated limiter is healthy: the reference local deployment has
    oralhistarchiv-rate-limit-redis.service running; an external deployment
    records equivalent provider health evidence and has no local limiter unit
[ ] redis-server.service is disabled unless the distinct, optional
    best-effort cache/pub-sub process was intentionally enabled
[ ] Effective limiter Redis config is physically isolated, uses `noeviction`
    and restart persistence, and disables the default user. The reference local
    config is loopback port 6380, AOF `everysec`, and fail-closed on truncated
    AOF; an external provider has equivalent reviewed controls
[ ] Bounded counter capacity and cleanup settings match across all workers;
    the old unregistered layout was drained with writers stopped, without reset
[ ] Maximum-length counter load at the chosen cap leaves measured Redis/AOF
    headroom; next-new-key refusal preserves live values/TTLs and later recovers
[ ] A live TTL probe survives an ordinary Redis restart; AOF write/rewrite
    status is `ok`, and memory has measured headroom below `maxmemory`
[ ] Limiter memory and AOF disk sizing includes the temporary old/new
    pseudonym-key overlap caused by SECRET_KEY rotation plus rewrite headroom;
    superseded AOF generations are not archived
[ ] For a local limiter, only the web unit has effective `Requires`/`After` on
    oralhistarchiv-rate-limit-redis.service; the scheduler has neither that
    dependency nor RATE_LIMIT_REDIS_URL
[ ] oralhistarchiv.service is running
[ ] oralhistarchiv-scheduler.service is running
[ ] Scheduler log shows "Scheduler started" and at least one sync
[ ] Web service log does NOT contain scheduler messages
[ ] The dedicated limiter accepts connections only from the approved web
    network (loopback port 6380 for the reference local deployment); optional
    general Redis port 6379 accepts connections only from loopback
[ ] pg_stat_activity shows oralhistarchiv-web and oralhistarchiv-scheduler
    (sudo -u postgres psql -d oralhistarchiv -c
     "SELECT pid, usename, application_name FROM pg_stat_activity")

Endpoints
[ ] SSL certificate is valid and HTTPS works
[ ] HTTP → HTTPS redirect works
[ ] /health returns {"status": "alive"}
[ ] Verify /health edge limiting with a controlled burst; the supplied template
    returns 429 without Retry-After or Cache-Control: no-store. Resolve that
    response-policy gap before claiming the original admission gate passes.
[ ] /health/detail returns 404 without token
[ ] /health/detail returns data with correct Bearer token
[ ] /docs and /redoc return 404 (disabled in production)
[ ] Static files load from nginx (not gunicorn)

Authentication flows
[ ] Admin user can log in
[ ] Admin is email_verified by default (no verification email required)
[ ] Keep LOCAL_REGISTRATION_ENABLED=false for untrusted users until the registration-safety gate in roadmap.md is resolved; exercise registration only with controlled test accounts
[ ] Opening the verification link shows a confirmation form; submitting it verifies the user
[ ] Unverified users cannot reach /setup-totp (see "check your email" page)
[ ] TOTP enrollment works after verification
[ ] Password reset email sends via SMTP
[ ] Password reset link can only be used once
[ ] CSRF protection works (form submissions succeed, forged ones rejected)
[ ] Rate limiting active and global across workers (test with curl
    from different simulated IPs)
[ ] An exhausted quota remains exhausted after Gunicorn worker recycling and
    an ordinary Redis restart
[ ] Redis unavailable/full causes a prompt non-cacheable 503 and does not run
    the protected endpoint or create per-worker fallback quotas
[ ] Search overload/timeout returns non-cacheable retryable 503 without
    ordinary-pool or query-mode fallback, including RATE_LIMIT_ENABLED=false
[ ] Random 404 paths and 405 method probes share a bounded fallback quota and
    over-budget requests perform no session-database lookup

Shibboleth (if enabled)
[ ] Every ordered pre-flip gate in §9 has recorded evidence and second review
[ ] Missing, duplicate, client-spoofed, wrong-issuer, and non-MFA assertions fail
[ ] A new identity receives no session and is pending, public, inactive,
    non-admin, unverified, and without approval metadata
[ ] Dedicated exact-pair approval records actor/time, assigns only the reviewed
    tier, bumps auth_revision, and deletes target sessions
[ ] A later exact issuer+subject assertion logs in only at the approved tier

Security
[ ] Anonymous `/`, `/search`, `/health`, and bearer-authorized
    `/health/detail` responses return `Cache-Control: no-store`.
[ ] `/reset-password/{public_id}`, `/verify-email/{public_id}`, and
    `/account/confirm-email/{public_id}` return generic forms with both
    `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; GET reveals
    no secret or account state, and legacy token-bearing paths return 404.
[ ] A public path/query alone cannot redeem an action; POST requires its bound
    secret, plus CSRF for reset/registration. Open the public link and copy the
    separate email code into the form; verify this flow without JavaScript.
[ ] Pending old-format action messages were cancelled under the cutover plan;
    required requests were reissued through the deployed application.
[ ] `/static/` responses do not receive application `no-store` and nginx
    applies only the reviewed static-asset cache policy.
[ ] Security headers present (curl -I https://...)
[ ] Firewall blocks direct gunicorn access (curl to port 5000 fails)
[ ] Firewall blocks direct Redis access on port 6380 and, if enabled, port 6379
    (a timeout/refusal is required; a Redis NOAUTH reply still means exposed)
[ ] the single non-root nginx worker UID resolved from `nginx -T` can make a
    raw AF_UNIX connection; oralhistarchiv-scheduler and nobody cannot
[ ] Audit logs show real external client IPs (not 127.0.0.1)
    when accessing via nginx (sudo journalctl -u oralhistarchiv -o cat |
    jq -R 'fromjson? | select(.event_type == "request") | .client_ip')
[ ] Every nginx server uses the `oralhistarchiv_safe` log format
[ ] Effective nginx config contains the dynamic and independent health
    request/connection zones; both public Phase-2 Shibboleth locations carry
    their per-client and shared aggregate SSO controls when installed
[ ] No active nginx access log records URI, query arguments, or Referer;
    error-log custody accounts for arbitrary request targets.
[ ] A synthetic new-format action secret is absent from nginx, journald, and
    forwarded logs after GET, 403, 415, 422, 429, and static requests; the 429
    error-log record includes its non-secret public ID as a positive control.

Operations
[ ] oralhistarchiv-backup.timer is enabled and the forced initial oneshot
    completed successfully
[ ] Backup directory is oralhistarchiv_backup-owned 0700; encrypted archives
    are 0600; the web and an unrelated identity cannot read them
[ ] Only *.dump.age final artifacts remain; no plaintext dump or hidden
    plaintext temporary file survives
[ ] Host monitoring alerts on a failed backup service and a stale latest archive
[ ] At least one encrypted archive is in separately controlled off-host storage
[ ] Off-host age identity custody and historical application key-ring escrow are
    documented, and an isolated restore drill succeeded
[ ] Health check cron is running
[ ] Both long-running runtime units restart on failure; migration remains static
[ ] Bootstrap the initial administrator with the one-shot terminal command
    and verify fresh MFA login before opening public access
```

---

## 17. Maintenance

### Updating the application and database

1. Put the HTTPS nginx server into maintenance mode with
   a server-level `return 503;` in the HTTPS application server, covering exact locations too. Save the existing configuration and run `sudo nginx -t` before reloading.
2. Pause automatic backups, drain any active backup without terminating its
   dump, then stop both runtime units. Do not replace the backup executable
   until the active service has finished:

   ```bash
   sudo systemctl stop oralhistarchiv-backup.timer
   while true; do
     backup_state=$(sudo systemctl show -p ActiveState --value oralhistarchiv-backup.service)
     case "$backup_state" in inactive|failed) break ;; esac
     sleep 5
   done
   ```

   Backups also hold the stable deployment inode shared from before preflight
   through publication (manual invocations included). They wait at most 60
   seconds for the lock and fail with a diagnostic if maintenance holds it.
   Migration waits at most 60 seconds for the exclusive lock; the installer fails immediately if it is held.
   Keep the stable lock inode mode `0640`, owned by `root:oralhistarchiv-deploy-lock`;
   backup and the other approved participants require group read access only.

   Stop both runtime units:

   ```bash
   sudo systemctl stop oralhistarchiv.service oralhistarchiv-scheduler.service
   ```

3. Take a fresh encrypted backup, run the off-host verifier, and retain the
   most recent archive that has passed an isolated restore.
4. Review the application diff, every Alembic migration, and
   `deploy/database-runtime-grants.sql` together. Build, approve,
   digest-verify, and install the immutable release exactly as described in §5.
5. Install the new release's three application unit files and the schema-bound
   backup executable/unit before reloading systemd. For the reference local
   limiter, review the new Redis example and unit against the installed files.
   Record whether an effective limiter asset change is required. Merge each
   applicable config change manually; never overwrite the live config blindly
   because its capacity is host-specific. Never overwrite or regenerate
   `users.acl` blindly: a changed command contract requires its own reviewed,
   least-privilege ACL update or coordinated credential rotation. An external
   deployment reviews its provider configuration/API diff and skips the
   **entire** host-local limiter block below.

   ```bash
   sudo install -o root -g root -m 0644 \
     /opt/oralhistarchiv/oralhistarchiv.service \
     /etc/systemd/system/oralhistarchiv.service
   sudo install -o root -g root -m 0644 \
     /opt/oralhistarchiv/oralhistarchiv-scheduler.service \
     /etc/systemd/system/oralhistarchiv-scheduler.service
   sudo install -o root -g root -m 0644 \
     /opt/oralhistarchiv/oralhistarchiv-migrate.service \
     /etc/systemd/system/oralhistarchiv-migrate.service
   sudo install -D -o root -g root -m 0755 \
     /opt/oralhistarchiv/deploy/oralhistarchiv-backup.sh \
     /usr/local/libexec/oralhistarchiv-backup
   sudo install -o root -g root -m 0644 \
     /opt/oralhistarchiv/deploy/oralhistarchiv-backup.service \
     /etc/systemd/system/oralhistarchiv-backup.service

   # Reference host-local limiter review only. Exit 1 from diff means
   # "differences shown"; any other nonzero status is an error.
   sudo diff -u /etc/oralhistarchiv-rate-limit-redis/redis.conf \
     /opt/oralhistarchiv/deploy/redis-security.conf.example || test "$?" -eq 1
   sudo diff -u \
     /etc/systemd/system/oralhistarchiv-rate-limit-redis.service \
     /opt/oralhistarchiv/deploy/oralhistarchiv-rate-limit-redis.service \
     || test "$?" -eq 1

   # Run these next two commands only when the review found an effective
   # config/unit change; otherwise leave both installed files and the running
   # limiter untouched so still-live quotas are not reset gratuitously.
   sudoedit /etc/oralhistarchiv-rate-limit-redis/redis.conf
   sudo install -o root -g root -m 0644 \
     /opt/oralhistarchiv/deploy/oralhistarchiv-rate-limit-redis.service \
     /etc/systemd/system/oralhistarchiv-rate-limit-redis.service
   sudo stat -c '%U:%G %a %n' \
     /etc/oralhistarchiv-rate-limit-redis \
     /etc/oralhistarchiv-rate-limit-redis/redis.conf \
     /etc/oralhistarchiv-rate-limit-redis/users.acl

   sudo systemctl daemon-reload
   sudo systemd-analyze verify \
     /etc/systemd/system/oralhistarchiv.service \
     /etc/systemd/system/oralhistarchiv-scheduler.service \
     /etc/systemd/system/oralhistarchiv-migrate.service
   # Reference host-local limiter only; external deployments omit this.
   sudo systemd-analyze verify \
     /etc/systemd/system/oralhistarchiv-rate-limit-redis.service
   test "$(sudo systemctl is-enabled oralhistarchiv-migrate.service)" = 'static'
   if sudo systemctl is-active --quiet oralhistarchiv-migrate.service; then
     echo 'Migration unit must not remain active' >&2
     exit 1
   fi
   ```

6. Apply the reviewed migration and deny-first grants only through the manual
   unit:

   ```bash
   sudo systemctl start oralhistarchiv-migrate.service
   sudo systemctl is-failed --quiet oralhistarchiv-migrate.service && exit 1
   sudo journalctl -u oralhistarchiv-migrate.service --since=-10m --no-pager
   ```

7. Run the complete access inventory as each runtime role. Both must exit zero:

   ```bash
   sudo -u oralhistarchiv psql -X --no-password \
     --dbname=oralhistarchiv --username=oralhistarchiv_web \
     --set=ON_ERROR_STOP=1 \
     --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
   sudo -u oralhistarchiv-scheduler psql -X --no-password \
     --dbname=oralhistarchiv --username=oralhistarchiv_scheduler \
     --set=ON_ERROR_STOP=1 \
     --file=/opt/oralhistarchiv/deploy/verify-runtime-database-access.sql
   ```

8. Restore the backup timer only after migration and grant checks pass:

   ```bash
   sudo systemctl start oralhistarchiv-backup.timer
   ```

   If maintenance fails, keep the timer paused until the installed backup
   script's expected revision matches the restored/migrated database. Record
   this in the maintenance incident and restore the timer after recovery.

   If step 5 changed the reference local limiter config, unit, ACL, or pinned
   command contract, restart it now and rerun the complete credential-safe
   command/policy/TTL/AOF-survival check in §7. Both the restart and full probe
   are blocking: otherwise the reviewed config may not be effective. If the
   review recorded **no** effective limiter change, deliberately leave the
   process running so deployment does not gratuitously reset or perturb live
   quotas; check only that it remains active. An external deployment skips all
   local-unit commands and records equivalent provider policy, persistence and
   health evidence. Web startup still performs its authoritative functional
   command probe.

   Start scheduler and web, then require both startup schema/role preflights and
   authenticated smoke checks to pass:

   ```bash
   # Reference host-local limiter, changed-assets branch only: execute the
   # complete §7 Python heredoc now and require exit 0. Its internal systemctl
   # restart is the one planned restart and proves value + bounded TTL survive;
   # do not pre-restart it or replace the probe with PING alone. After it exits:
   sudo systemctl is-active --quiet oralhistarchiv-rate-limit-redis.service

   # Reference host-local limiter, unchanged-assets branch: do not restart.
   sudo systemctl is-active --quiet oralhistarchiv-rate-limit-redis.service

   sudo systemctl start oralhistarchiv-scheduler.service oralhistarchiv.service
   sudo systemctl is-active --quiet oralhistarchiv-scheduler.service
   sudo systemctl is-active --quiet oralhistarchiv.service
   current_release=$(readlink -e /opt/oralhistarchiv)
   sudo test "$(stat -c '%U:%G %a' "$current_release")" = 'root:root 755'
   /opt/oralhistarchiv/.venv/bin/python -I -m pip check
   ```

9. Remove the nginx maintenance location only after the smoke checks pass;
   require `sudo nginx -t` before reloading.

Never enable `oralhistarchiv-migrate.service`. It hard-codes `upgrade head` and
is not a generic downgrade tool. Every schema-changing release must include a
reviewed forward-repair or encrypted-restore plan. Execute that plan through an
equivalently sandboxed owner-only one-shot while both runtimes remain stopped,
then reapply the matching grants and pass both runtime preflights before
reopening traffic. The federation rollback ordering in §9 takes precedence.

### Viewing logs

Use the journal/nginx commands in [Log Management](#12-log-management).
Check the backup schedule with
`sudo systemctl list-timers oralhistarchiv-backup.timer`.

### Memory check

Use the cgroup measurements and qualification steps in
[Memory Tuning](#14-memory-tuning).

### Rotating secrets

Follow [key rotation](docs/runbooks/key-rotation.md) for each signing/encryption
key. It specifies maintenance, token-message cancellation, non-overlapping
restarts, limiter-namespace changes and verification. Keep historical TOTP and
outbox keys until both live data and retained backups no longer need them.

### Rotating SHIBBOLETH_INTERNAL_SECRET

Treat this value as an arbitrary federated-impersonation credential. Rotate it
inside a maintenance window with the callback closed:

1. Replace the active Phase-2 callback include with the Phase-1 exact
   `location = /auth/shibboleth/callback { return 404; }`; run `nginx -t`,
   reload nginx, and verify the public callback returns 404.
2. Set `SHIBBOLETH_ENABLED=false` in
   `/etc/oralhistarchiv/shibboleth.env` and restart the web service. Startup
   must report that the changed federation-policy fingerprint revoked the
   Shibboleth session population; local sessions remain valid.
3. Generate an independent `secrets.token_urlsafe(64)` value. Update both the
   root-only nginx secret include and root-only web overlay without placing the
   value on a command line or in retained output. Keep their modes `0600`.
4. Restart the web service while the flag remains false. Restore the verified
   Phase-2 callback include, run `nginx -t`, and reload nginx.
5. Re-run the §9 issuer, stable-subject, REFEDS-MFA, header-spoofing, socket,
   and effective-nginx checks, plus the automated pending-enrollment contract
   tests, while the production application flag remains false.
6. Set `SHIBBOLETH_ENABLED=true` and restart only the web service as the final
   step. Complete a controlled real MFA login and restore the flag to false
   plus the callback to 404 immediately on failure.

#### Suspected disclosure

Do not use the planned sequence above for a suspected disclosure. Immediately
run `sudo systemctl stop oralhistarchiv` and verify that the web process is
inactive and its Unix socket is absent or unconnectable **before** changing
nginx or configuration. A holder of the secret who can reach the socket does
not traverse nginx, so `return 404` alone is not containment.

With the web process stopped, close the public callback, set
`SHIBBOLETH_ENABLED=false`, replace the secret, and execute the runbook's manual
transaction to bump every federated user's `auth_revision` and delete every
federated session. Preserve evidence and investigate newly provisioned or
changed identities against IdP/SP and audit evidence. Restart the current code
only with federation disabled; confirm startup reconciliation and a zero
federated-session count. Keep the callback at 404 through incident response and
the complete pre-flip acceptance procedure. The authoritative ordered commands
and verification query are in `docs/runbooks/key-rotation.md`.

### Emergency procedures

**Application won't start:**

```bash
sudo journalctl -u oralhistarchiv -n 50 --no-pager
sudo journalctl -u oralhistarchiv-scheduler -n 50 --no-pager
```

**Scheduler stopped syncing:**

```bash
# Check if the process is running
sudo systemctl status oralhistarchiv-scheduler

# Check last sync status in the DB
sudo -u oralhistarchiv-scheduler psql -X --no-password \
  --dbname=oralhistarchiv --username=oralhistarchiv_scheduler --set=ON_ERROR_STOP=1 --command="SELECT source, last_harvest_date, last_sync_error, last_sync_error_at, last_rebuild_error, last_rebuild_error_at FROM sync_status ORDER BY source"

# Restart it
sudo systemctl restart oralhistarchiv-scheduler
```

**Database connection failed:**

```bash
sudo systemctl status postgresql
sudo -u oralhistarchiv \
  psql --no-password --dbname=oralhistarchiv --username=oralhistarchiv_web \
  --command='SELECT current_user, session_user'
sudo -u oralhistarchiv-scheduler \
  psql --no-password --dbname=oralhistarchiv \
  --username=oralhistarchiv_scheduler \
  --command='SELECT current_user, session_user'
```

**Database pool exhausted:**

The database helper logs pool-admission rejections at `WARNING`. With
`LOG_FORMAT=json` and `LOG_LEVEL` set to `WARNING`, `INFO` or `DEBUG`, inspect
the real warning message:

```bash
sudo journalctl -u oralhistarchiv.service --since=-1h --no-pager -o cat | \
  jq -R 'fromjson? | objects |
    select(.logger == "app.services.db" and
      ((.message // "") | startswith("Database pool admission rejected "))) |
    {timestamp, level, message}'

# Check active connections in PostgreSQL.
sudo -u postgres psql -d oralhistarchiv -c \
    "SELECT pid, usename, application_name, state, query_start, state_change FROM pg_stat_activity WHERE datname = 'oralhistarchiv'"
```

These warnings have no dedicated `event_type` or request ID. A request audit
record with `status_code=503` alone does not establish pool exhaustion:
rate-limit admission and other failures can produce the same status. Review
the warning timestamps, application logs and PostgreSQL activity before
changing `DATABASE_POOL_SIZE` or `DATABASE_POOL_MAX_WAITING`.

Search uses an additional, separately bounded one-connection pool per web worker.
Its local permit, global PostgreSQL try-lock, start budget and operation deadline
can return 503 without exhausting the ordinary pool. Check the search-specific
capacity/timeout diagnostics and `application_name` alongside ordinary pool
warnings; do not route failed search work into the ordinary pool.

The bounded waiter queue deliberately returns retryable, non-cacheable `503`
instead of allowing request objects to accumulate without limit. Do not raise
it as a substitute for fixing slow queries or upstream admission; a larger
queue consumes more memory and increases tail latency during an outage.


**Redis connection failed:**

The commands below are for the reference host-local limiter. For an external
endpoint, use provider health/configuration evidence and the same categorized
application event without exposing either credential.

```bash
sudo systemctl status oralhistarchiv-rate-limit-redis.service --no-pager --full
sudo journalctl -u oralhistarchiv-rate-limit-redis.service --since=-1h \
  --no-pager
sudo grep -E \
  '^(bind|port|maxmemory|maxmemory-policy|appendonly|appendfsync|aof-load-truncated|auto-aof-rewrite|aclfile) ' \
  /etc/oralhistarchiv-rate-limit-redis/redis.conf
sudo journalctl -u oralhistarchiv -o cat | \
  jq -R 'fromjson? | select(.event_type == "rate_limit_backend_unavailable") |
    {timestamp, backend_failure_category, request_id, path, exception_type}'
```

This is a security-backend outage, not a transparent cache degradation.
Hardened startup stops if the limiter cannot reach Redis; a later failure or
`noeviction` capacity error returns `503` without executing affected endpoints.
Do not enable memory fallback, an eviction policy, or disable AOF to restore
traffic. Correct service/network/disk/capacity health, rerun the credential-safe
functional/durability check from §7, then restart the web unit if startup
exhausted its systemd retry limit. Never paste the URL into `redis-cli -u` or
put its password in `-a`; both expose it through process arguments. The
catalogue cache's separate TTL degradation does not weaken this limiter
contract.

**Restore from backup:**

Use the encrypted restore procedure in §11 and the maintenance boundary in
§17. Do not pass a `*.dump.age` file directly to `pg_restore`, persist a
decrypted archive under `/opt`, or place the `age` private identity in any
application environment file.

**Restart the complete local stack after reviewed maintenance:**

```bash
sudo systemctl restart postgresql
# Reference host-local security limiter. For an external endpoint, complete
# the provider's reviewed maintenance/recovery procedure and rerun §7's probe.
sudo systemctl restart oralhistarchiv-rate-limit-redis.service
# Optional general cache/pub-sub Redis only; do not start it implicitly.
if sudo systemctl is-enabled --quiet redis-server.service; then
  sudo systemctl restart redis-server.service
fi
sudo systemctl restart oralhistarchiv oralhistarchiv-scheduler
sudo systemctl restart nginx
```
