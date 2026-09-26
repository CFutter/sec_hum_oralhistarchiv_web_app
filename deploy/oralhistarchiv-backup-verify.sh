#!/bin/bash
# Decrypt an age archive completely and validate its pg_restore table of contents.
# Usage: oralhistarchiv-backup-verify.sh ARCHIVE IDENTITY_FILE. Run on a trusted
# recovery host; keep the private identity off the application/database host.
# Inputs must be nonsymlink regular files; the identity must deny group/other
# permission bits. Ownership, ancestor paths, and archive permissions are not checked.
# Exit 64 for usage errors, otherwise nonzero on failure. No plaintext file is
# written; this does not restore data or prove row completeness/application recovery.
# shellcheck shell=bash

set -Eeuo pipefail
umask 077


usage() {
    printf 'Usage: %s <archive.dump.age> <age-identity-file>\n' "${0##*/}" >&2
    exit 64
}

# Print the supplied diagnostic to stderr and exit 1.
fail() {
    printf 'Encrypted backup verification failed: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || usage
archive=$1
identity_file=$2

for required_command in \
    /usr/bin/age \
    /usr/bin/cat \
    /usr/bin/pg_restore \
    /usr/bin/stat; do
    [[ -x "$required_command" ]] \
        || fail "required command is unavailable: $required_command"
done

[[ -f "$archive" && ! -L "$archive" ]] \
    || fail "archive must be a regular file and not a symbolic link: $archive"
[[ -f "$identity_file" && ! -L "$identity_file" ]] \
    || fail "identity must be a regular file and not a symbolic link: $identity_file"

identity_mode="$(/usr/bin/stat -c '%a' -- "$identity_file")"
((8#$identity_mode & 077)) \
    && fail "age identity must not be accessible by group or other users"

# pg_restore accepts a custom-format archive on standard input. Streaming keeps
# the decrypted archive out of the recovery host's filesystem as well. It can
# finish after reading only the archive TOC, so cat must drain the remaining
# authenticated stream; otherwise age can receive SIGPIPE for a valid archive.
/usr/bin/age --decrypt --identity "$identity_file" -- "$archive" \
    | (
        set +e
        /usr/bin/pg_restore --list >/dev/null
        restore_status=$?
        /usr/bin/cat >/dev/null
        drain_status=$?
        if ((restore_status != 0)); then
            exit "$restore_status"
        fi
        exit "$drain_status"
    )
printf 'Encrypted PostgreSQL backup verified: %s\n' "${archive##*/}"
