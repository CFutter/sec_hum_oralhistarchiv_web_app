#!/bin/bash
# Bash 4.3+; from the repository root, run uv run bash dev.sh with ENV_STATE=dev.
# Migrates the configured database, then starts scheduler and web; exits with
# the first child's status, terminating and reaping both children. INT/TERM exit
# 130/143. Migration runs before the web launcher checks the environment.
set -euo pipefail

python3 -m alembic -c src/alembic.ini upgrade head

python3 run_scheduler.py &
scheduler_pid=$!
python3 run.py &
web_pid=$!

# shellcheck disable=SC2329 # Invoked by the EXIT trap below.
# Ignore further INT/TERM while terminating and waiting for both children.
cleanup() {
    trap - EXIT
    trap '' INT TERM
    kill "$web_pid" "$scheduler_pid" 2>/dev/null || true
    wait "$web_pid" 2>/dev/null || true
    wait "$scheduler_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set +e
wait -n "$web_pid" "$scheduler_pid"
child_status=$?
set -e
exit "$child_status"
