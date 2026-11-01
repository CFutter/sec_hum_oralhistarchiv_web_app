#!/usr/bin/env bash
# Repository publication policy; content findings and read/policy errors fail.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/check_site_refs.py" "$@"
