#!/bin/bash
# shellcheck shell=bash
# Stream a custom-format PostgreSQL dump through age; publish ciphertext atomically.
# No arguments. Read BACKUP_* and PGHOST/PGDATABASE/PGUSER (defaults below);
# BACKUP_AGE_RECIPIENT is required. Run as the owner of an existing 0700 backup
# directory, with peer-authenticated read access and the shared deploy lock file.
# Hold a shared deployment lock (60-second wait) and nonblocking directory lock.
# Refuse wrong identity/revision or missing critical tables. Retention follows
# successful publication; failures exit nonzero and clean partial ciphertext.

set -Eeuo pipefail
umask 077

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

encrypted_tmp=""

# Print the supplied diagnostic to stderr and terminate with status 1.
fail() {
    printf 'Encrypted PostgreSQL backup failed: %s\n' "$*" >&2
    exit 1
}

# Preserve exit status, remove tracked partial ciphertext, report failure, and exit.
cleanup() {
    local status=$?
    trap - EXIT

    if [[ -n "$encrypted_tmp" ]]; then
        /usr/bin/rm -f -- "$encrypted_tmp"
    fi

    if ((status != 0)); then
        printf 'Encrypted PostgreSQL backup failed with exit status %d\n' "$status" >&2
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
[[ "$retention_days" =~ ^[0-9]+$ ]] \
    || fail "BACKUP_RETENTION_DAYS must be an integer"
((retention_days >= 1 && retention_days <= 3650)) \
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

# Coordinate with schema/release changes before locking the backup directory.
exec 8</run/lock/oralhistarchiv-deploy.lock
/usr/bin/flock --shared --timeout 60 8 || fail "deployment lock unavailable after 60 seconds"

# Lock the directory inode to avoid a replaceable lock-file path.
exec 9<"$backup_dir"
/usr/bin/flock -n 9 || fail "another backup process already holds the backup-directory lock"

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
                AND to_regclass('public.alembic_version') IS NOT NULL
                AND to_regclass('public.oral_history_datasets') IS NOT NULL
                AND to_regclass('public.sync_status') IS NOT NULL
                AND to_regclass('public.users') IS NOT NULL
                AND to_regclass('public.email_outbox') IS NOT NULL
                AND to_regclass('public.sessions') IS NOT NULL
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

printf 'Encrypted PostgreSQL backup completed: %s\n' "${final_archive##*/}"
