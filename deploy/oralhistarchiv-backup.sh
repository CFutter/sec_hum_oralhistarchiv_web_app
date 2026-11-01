#!/bin/bash
# shellcheck shell=bash
# Stream a custom-format PostgreSQL dump through age; publish ciphertext atomically.
# No positional arguments; usage errors exit 64. Read BACKUP_* and
# PGHOST/PGDATABASE/PGUSER (defaults below);
# BACKUP_AGE_RECIPIENT is required. Run as the owner of an existing 0700 backup
# directory, with peer-authenticated read access and the shared deploy lock file.
# Hold a shared deployment lock (60-second wait) and nonblocking directory lock.
# Refuse wrong identity/revision or missing critical tables. Retention follows
# successful publication; failures exit nonzero and attempt partial-output cleanup.
# Optional BACKUP_STATUS_DIR publishes a nonsecret local-publication timestamp
# outside the private archive directory. It is not off-host/restore/PITR proof.

set -Eeuo pipefail
umask 077

if (($# != 0)); then
    printf 'Usage: %s (no arguments)\n' "${0##*/}" >&2
    exit 64
fi

readonly DEFAULT_BACKUP_DIR="/var/lib/oralhistarchiv-backup"
readonly DEFAULT_RETENTION_DAYS="30"
readonly DEFAULT_DATABASE="oralhistarchiv"
readonly DEFAULT_DATABASE_USER="oralhistarchiv_backup"
readonly DEFAULT_DATABASE_HOST="/var/run/postgresql"
readonly EXPECTED_ALEMBIC_REVISION="4f73ae3ff827"

backup_dir="${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}"
retention_days="${BACKUP_RETENTION_DAYS:-$DEFAULT_RETENTION_DAYS}"
database="${PGDATABASE:-$DEFAULT_DATABASE}"
database_user="${PGUSER:-$DEFAULT_DATABASE_USER}"
database_host="${PGHOST:-$DEFAULT_DATABASE_HOST}"
age_recipient="${BACKUP_AGE_RECIPIENT:-}"
status_dir="${BACKUP_STATUS_DIR:-}"

encrypted_tmp=""
status_tmp=""

# Print the supplied diagnostic to stderr and terminate with status 1.
fail() {
    printf 'Encrypted PostgreSQL backup failed: %s\n' "$*" >&2
    exit 1
}

# Accept a missing marker; otherwise require a backup-owned, single-link regular
# file with mode 0644 and no symlink. Invalid objects exit through fail().
validate_status_marker() {
    if [[ -e "$status_dir/last-success" || -L "$status_dir/last-success" ]]; then
        [[ -f "$status_dir/last-success" && ! -L "$status_dir/last-success" ]] \
            || fail "backup status marker must be a nonsymlink regular file"
        local marker_owner marker_mode marker_links
        read -r marker_owner marker_mode marker_links <<<"$(
            /usr/bin/stat -c '%u %a %h' -- "$status_dir/last-success"
        )"
        [[ "$marker_owner" == "$current_uid" && "$marker_mode" == "644" && "$marker_links" == "1" ]] \
            || fail "backup status marker must be backup-owned, mode 0644 and single-linked"
    fi
}

# Attempt both temporary removals and report cleanup errors separately. Preserve
# an incoming nonzero exit status; cleanup-only failure exits 1.
cleanup() {
    local status=$?
    local path cleanup_failed=0
    trap - EXIT

    for path in "$encrypted_tmp" "$status_tmp"; do
        if [[ -n "$path" ]] && ! /usr/bin/rm -f -- "$path"; then
            printf 'Encrypted PostgreSQL backup cleanup failed: cannot remove %s\n' "$path" >&2 || :
            cleanup_failed=1
        fi
    done

    if ((status == 0 && cleanup_failed != 0)); then
        status=1
    fi

    if ((status != 0)); then
        printf 'Encrypted PostgreSQL backup failed with exit status %d\n' "$status" >&2 || :
    fi
    exit "$status"
}
trap cleanup EXIT

for required_command in \
    /usr/bin/age \
    /usr/bin/chmod \
    /usr/bin/date \
    /usr/bin/find \
    /usr/bin/flock \
    /usr/bin/id \
    /usr/bin/mktemp \
    /usr/bin/mv \
    /usr/bin/pg_dump \
    /usr/bin/psql \
    /usr/bin/rm \
    /usr/bin/stat \
    /usr/bin/sync; do
    [[ -x "$required_command" ]] \
        || fail "required command is unavailable: $required_command"
done

[[ -n "$age_recipient" ]] \
    || fail "BACKUP_AGE_RECIPIENT is required; provision only the public recipient here"
[[ "$backup_dir" == /* && "$backup_dir" != "/" ]] \
    || fail "BACKUP_DIR must be an absolute, non-root path"
[[ "$database_host" == /* ]] \
    || fail "PGHOST must be a Unix-socket directory, not a TCP host"
[[ "$retention_days" =~ ^[1-9][0-9]{0,3}$ ]] \
    || fail "BACKUP_RETENTION_DAYS must be a positive decimal integer without leading zeros"
((retention_days <= 3650)) \
    || fail "BACKUP_RETENTION_DAYS must be between 1 and 3650"

[[ -d "$backup_dir" && ! -L "$backup_dir" ]] \
    || fail "backup directory must already exist and must not be a symbolic link: $backup_dir"
directory_mode="$(/usr/bin/stat -c '%a' -- "$backup_dir")"
directory_owner="$(/usr/bin/stat -c '%u' -- "$backup_dir")"
current_uid="$(/usr/bin/id -u)"
[[ "$directory_mode" == "700" ]] \
    || fail "backup directory must have mode 0700 (found $directory_mode): $backup_dir"
[[ "$directory_owner" == "$current_uid" ]] \
    || fail "backup directory must be owned by the executing backup identity"

if [[ -n "$status_dir" ]]; then
    [[ "$status_dir" == /* && "$status_dir" != "/" && "$status_dir" != */ \
        && "$status_dir" != *"//"* && "$status_dir" != *$'\n'* \
        && "$status_dir" != *$'\r'* ]] \
        || fail "BACKUP_STATUS_DIR must be an absolute, non-root directory without trailing slash"
    status_path=""
    IFS='/' read -r -a status_parts <<<"${status_dir#/}"
    for status_part in "${status_parts[@]}"; do
        [[ -n "$status_part" && "$status_part" != "." && "$status_part" != ".." ]] \
            || fail "BACKUP_STATUS_DIR must not contain empty, dot or parent components"
        status_path="$status_path/$status_part"
        [[ -d "$status_path" && ! -L "$status_path" ]] \
            || fail "backup status directory and its ancestors must be nonsymlink directories"
    done
    [[ "$status_dir" != "$backup_dir" ]] \
        || fail "backup status directory must be separate from the archive directory"
    [[ "$(/usr/bin/stat -c '%a' -- "$status_dir")" == "755" \
        && "$(/usr/bin/stat -c '%u' -- "$status_dir")" == "$current_uid" ]] \
        || fail "backup status directory must be backup-owned with mode 0755"
fi

# Coordinate with schema/release changes before locking the backup directory.
exec 8</run/lock/oralhistarchiv-deploy.lock
/usr/bin/flock --shared --timeout 60 8 || fail "deployment lock unavailable after 60 seconds"

# Lock the directory inode to avoid a replaceable lock-file path.
exec 9<"$backup_dir"
/usr/bin/flock -n 9 || fail "another backup process already holds the backup-directory lock"

if [[ -n "$status_dir" ]]; then
    # Serialize a shared marker even if separately configured archive paths exist.
    exec 7<"$status_dir"
    /usr/bin/flock -n 7 || fail "another backup process already holds the status-directory lock"
    validate_status_marker
fi

# An interrupted process can leave only partial ciphertext. It is never a
# published archive and is deleted before a new attempt.
/usr/bin/find "$backup_dir" -maxdepth 1 -type f \
    -name '.oralhistarchiv-encrypted.*' -delete

timestamp="$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)"
final_archive="$backup_dir/oralhistarchiv_${timestamp}.dump.age"
[[ ! -e "$final_archive" && ! -L "$final_archive" ]] \
    || fail "refusing to replace an existing backup archive: $final_archive"

encrypted_tmp="$(/usr/bin/mktemp --tmpdir="$backup_dir" '.oralhistarchiv-encrypted.XXXXXX')"
/usr/bin/chmod 0600 "$encrypted_tmp"

# Force the documented local peer-authentication path. No password file or
# service definition may silently change this backup identity's connection.
unset PGPASSWORD PGSERVICE PGSERVICEFILE PGOPTIONS
export PGAPPNAME="oralhistarchiv-backup"
export PGCONNECT_TIMEOUT="10"
export PGPASSFILE="/dev/null"

# Refuse a typoed, empty, or wrong-schema database before producing an archive.
# The expected database value is passed as a psql variable and quoted by psql;
# it is never interpolated into SQL by the shell.
schema_ready="$(
    /usr/bin/psql \
        --host="$database_host" \
        --username="$database_user" \
        --dbname="$database" \
        --no-password \
        --no-psqlrc \
        --tuples-only \
        --no-align \
        --set=ON_ERROR_STOP=1 \
        --set=expected_database="$database" \
        --set=expected_user="$database_user" \
        --set=expected_revision="$EXPECTED_ALEMBIC_REVISION" \
        --file=- <<'SQL'
            SELECT CASE WHEN
                current_database() = :'expected_database'
                AND current_user = :'expected_user'
                AND session_user = :'expected_user'
                AND EXISTS (
                    SELECT 1 FROM pg_roles AS role
                    WHERE role.rolname = current_user
                      AND role.rolcanlogin AND role.rolbypassrls
                      AND NOT role.rolsuper AND NOT role.rolcreatedb
                      AND NOT role.rolcreaterole AND NOT role.rolreplication
                      AND NOT role.rolinherit
                      AND NOT EXISTS (
                          SELECT 1 FROM pg_auth_members AS membership
                          WHERE membership.member = role.oid
                      )
                )
                AND NOT has_database_privilege(current_user, current_database(), 'CREATE,TEMP')
                AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
                AND NOT EXISTS (
                    SELECT 1 FROM pg_class AS relation
                    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                    WHERE namespace.nspname = 'public'
                      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                      AND NOT EXISTS (
                          SELECT 1 FROM pg_depend AS dependency
                          WHERE dependency.classid = 'pg_class'::regclass
                            AND dependency.objid = relation.oid AND dependency.deptype = 'e'
                      )
                      AND CASE WHEN relation.relkind = 'S' THEN
                          NOT has_sequence_privilege(current_user, relation.oid, 'SELECT')
                          OR has_sequence_privilege(current_user, relation.oid, 'USAGE,UPDATE')
                      ELSE
                          NOT has_table_privilege(current_user, relation.oid, 'SELECT')
                          OR has_table_privilege(current_user, relation.oid,
                              'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                          OR has_any_column_privilege(current_user, relation.oid,
                              'INSERT,UPDATE,REFERENCES')
                      END
                )
                AND to_regclass('public.alembic_version') IS NOT NULL
                AND to_regclass('public.oral_history_datasets') IS NOT NULL
                AND to_regclass('public.dataset_admin_state') IS NOT NULL
                AND to_regclass('public.sync_status') IS NOT NULL
                AND to_regclass('public.ingestion_failures') IS NOT NULL
                AND to_regclass('public.ingestion_quarantine') IS NOT NULL
                AND to_regclass('public.source_security_state') IS NOT NULL
                AND to_regclass('public.source_binding_acknowledgements') IS NOT NULL
                AND to_regclass('public.security_audit_events') IS NOT NULL
                AND to_regclass('public.security_audit_receipts') IS NOT NULL
                AND to_regclass('public.anonymous_mail_issuance') IS NOT NULL
                AND to_regclass('public.catalogue_search_policy') IS NOT NULL
                AND to_regclass('public.catalogue_search_public') IS NOT NULL
                AND to_regclass('public.catalogue_search_registered') IS NOT NULL
                AND to_regclass('public.catalogue_search_vetted') IS NOT NULL
                AND to_regclass('public.users') IS NOT NULL
                AND to_regclass('public.totp_recovery_codes') IS NOT NULL
                AND to_regclass('public.admin_promotion_requests') IS NOT NULL
                AND to_regclass('public.federation_policy_state') IS NOT NULL
                AND to_regclass('public.email_outbox') IS NOT NULL
                AND to_regclass('public.sessions') IS NOT NULL
                AND to_regclass('public.pending_totp_rotations') IS NOT NULL
                AND (SELECT count(*) FROM public.alembic_version) = 1
                AND (SELECT version_num FROM public.alembic_version)
                    = :'expected_revision'
            THEN 'ready' ELSE 'not-ready' END;
SQL
)"
[[ "$schema_ready" == "ready" ]] \
    || fail "database identity/schema preflight failed; refusing to publish a backup"

# Stream the custom archive directly into age. With pipefail, either producer
# or encryptor failure aborts publication and removes the partial ciphertext.
# No plaintext dump is ever written to a filesystem.
/usr/bin/pg_dump \
    --host="$database_host" \
    --username="$database_user" \
    --dbname="$database" \
    --format=custom \
    --no-owner \
    --no-privileges \
    --no-password \
    | /usr/bin/age --encrypt --recipient "$age_recipient" >"$encrypted_tmp"

[[ -s "$encrypted_tmp" ]] || fail "age produced an empty encrypted archive"
/usr/bin/chmod 0600 "$encrypted_tmp"
/usr/bin/sync -f "$encrypted_tmp"

# Rename within one filesystem, publishing the final name only after dump,
# schema preflight, and encryption have all succeeded.
/usr/bin/mv -T -- "$encrypted_tmp" "$final_archive"
encrypted_tmp=""
/usr/bin/sync -f "$backup_dir"

# Prune only after publication. find -mtime +N removes files at least N+1
# whole days old, except the new archive and newest prior archive by mtime.
# Off-host retention must separately protect a restore-verified copy.
shopt -s nullglob
previous_archives=("$backup_dir"/oralhistarchiv_*.dump.age)
shopt -u nullglob
previous_archive=""
for candidate in "${previous_archives[@]}"; do
    if [[ "$candidate" != "$final_archive" && -f "$candidate" && ! -L "$candidate" ]]; then
        if [[ -z "$previous_archive" || "$candidate" -nt "$previous_archive" ]]; then
            previous_archive="$candidate"
        fi
    fi
done

if [[ -n "$previous_archive" ]]; then
    /usr/bin/find "$backup_dir" -maxdepth 1 -type f \
        -name 'oralhistarchiv_*.dump.age' \
        -mtime "+$retention_days" \
        ! -path "$final_archive" \
        ! -path "$previous_archive" \
        -delete
else
    /usr/bin/find "$backup_dir" -maxdepth 1 -type f \
        -name 'oralhistarchiv_*.dump.age' \
        -mtime "+$retention_days" \
        ! -path "$final_archive" \
        -delete
fi
/usr/bin/sync -f "$backup_dir"

if [[ -n "$status_dir" ]]; then
    # The local archive and retention checkpoint are durable before its marker.
    # Earlier failures preserve the old timestamp. A failure/crash after marker
    # rename can still leave a new marker with a failed/unknown service result;
    # monitor the unit result independently, as well as off-host restore proof.
    status_epoch="$(/usr/bin/date -u +%s)"
    [[ "$status_epoch" =~ ^[1-9][0-9]{0,11}$ ]] \
        || fail "backup status timestamp is not a canonical positive Unix epoch"
    status_tmp="$(/usr/bin/mktemp --tmpdir="$status_dir" '.oralhistarchiv-backup-status.XXXXXX')"
    printf 'OHA_BACKUP_SUCCESS_V1 %s\n' "$status_epoch" >"$status_tmp"
    /usr/bin/chmod 0644 "$status_tmp"
    /usr/bin/sync -f "$status_tmp"
    validate_status_marker
    /usr/bin/mv -T -- "$status_tmp" "$status_dir/last-success"
    status_tmp=""
    /usr/bin/sync -f "$status_dir"
fi

printf 'Encrypted PostgreSQL backup completed: %s\n' "${final_archive##*/}"
