#!/usr/bin/env bash
# Scan src/tests, docs, .github, and pyproject.toml from the repository root.
# Exit 1 for matching ticket-style IDs or section signs; planning vocabulary
# emits GitHub warnings only. Root Markdown files are outside this scope.
# Exit 2 if root setup or either scan fails.
# Requires Bash and GNU-compatible grep.
set -uo pipefail

script_dir=$(dirname -- "${BASH_SOURCE[0]}") || {
  printf 'Cannot resolve script directory; opaque-reference scan incomplete.\n' >&2
  exit 2
}
cd -- "$script_dir/.." || {
  printf 'Cannot enter repository root; opaque-reference scan incomplete.\n' >&2
  exit 2
}

SCOPE=(src/tests docs .github pyproject.toml)
BLOCKING='\b(CQ|SEC|BUG|ISSUE|TASK|TICKET|TEST)[-_ ]?[0-9]{2,}\b|\b[sS][eE][cC][-_]?[0-9]{3}\b|\b[cC][qQ][-_]?[0-9]{3}\b|\b[AI]-[0-9]{1,3}\b|§'
ADVISORY='\b[Bb]acklogs?\b|\b[Ff]indings?\b|\b[Cc]losure\b|\b[Rr]emediation\b|\bP[01]\b'

status=0
if grep -rInE -- "$BLOCKING" "${SCOPE[@]}"; then
  printf 'Opaque reference found. Replace it with the behaviour it names.\n' >&2
  status=1
else
  scan_status=$?
  if ((scan_status != 1)); then
    printf 'Blocking opaque-reference scan failed (grep exit %s).\n' "$scan_status" >&2
    exit 2
  fi
fi

if advisory_matches=$(grep -rInE -- "$ADVISORY" "${SCOPE[@]}"); then
  while IFS=: read -r file line text; do
    text=${text//%/%25}
    printf '::warning file=%s,line=%s::Planning vocabulary, review: %s\n' "$file" "$line" "$text"
  done <<< "$advisory_matches"
else
  scan_status=$?
  if ((scan_status != 1)); then
    printf 'Advisory opaque-reference scan failed (grep exit %s).\n' "$scan_status" >&2
    exit 2
  fi
fi

exit "$status"