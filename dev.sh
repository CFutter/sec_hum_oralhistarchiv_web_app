#!/bin/bash
set -euo pipefail
python3 run_scheduler.py &
SCHEDULER_PID=$!
trap 'kill "$SCHEDULER_PID" 2>/dev/null || true' EXIT
python3 run.py