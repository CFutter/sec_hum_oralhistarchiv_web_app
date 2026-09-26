#!/usr/bin/env bash
# Scan src/tests, docs, .github, and pyproject.toml from the repository root.
# Exit 1 for matching ticket-style IDs or section signs; planning vocabulary
# emits GitHub warnings only. Root Markdown files are outside this scope.
# Requires Bash and GNU-compatible grep; search/read errors do not fail the gate.
set -uo pipefail
cd "$(dirname "$0")/.."

SCOPE=(src/tests docs .github pyproject.toml)
BLOCKING='\b(CQ|SEC|BUG|ISSUE|TASK|TICKET|TEST)[-_ ]?[0-9]{2,}\b|\b[sS][eE][cC][-_]?[0-9]{3}\b|\b[cC][qQ][-_]?[0-9]{3}\b|\b[AI]-[0-9]{1,3}\b|§'
ADVISORY='\b[Bb]acklogs?\b|\b[Ff]indings?\b|\b[Cc]losure\b|\b[Rr]emediation\b|\bP[01]\b'

status=0
if grep -rInE "$BLOCKING" "${SCOPE[@]}"; then
  echo "Opaque reference found. Replace it with the behaviour it names." >&2
  status=1
fi

while IFS=: read -r file line text; do
  text=${text//%/%25}
  printf '::warning file=%s,line=%s::Planning vocabulary, review: %s\n' "$file" "$line" "$text"
done < <(grep -rInE "$ADVISORY" "${SCOPE[@]}" || true)

exit "$status"