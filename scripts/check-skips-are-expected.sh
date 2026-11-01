#!/usr/bin/env bash
# Check a pytest short-summary log (argument 1, otherwise stdin) against
# EXPECTED_SKIPS_FILE (default scripts/expected-skips.txt); require Bash, GNU
# text tools, a completed count line, and unfolded node/reason entries for skips.
# CI is active unless unset/empty or case-insensitively 0, false, or no; active
# CI permits no skips. Locally, only listed skips are allowed; absent entries
# are fine. Exit 1 for malformed summaries or unexpected skips, otherwise 0.
# This checks skips only: failed tests, xfails, and xpasses need separate gates.
# Usage: uv run pytest -rs --no-fold-skipped 2>&1 | tee pytest.log
#        bash scripts/check-skips-are-expected.sh pytest.log
set -uo pipefail
cd "$(dirname "$0")/.."

expected_list="${EXPECTED_SKIPS_FILE:-scripts/expected-skips.txt}"
input="${1:-/dev/stdin}"

ci="$(printf '%s' "${CI:-}" | tr '[:upper:]' '[:lower:]')"
case "$ci" in
  ""|0|false|no) under_ci=0 ;;
  *) under_ci=1 ;;
esac

log="$(sed -E $'s/\x1b\\[[0-9;]*m//g' "$input")" || exit 1

count_line="$(printf '%s\n' "$log" | grep -v '^[[:space:]]*$' | tail -1 | sed -E 's/^=+ ?//; s/ ?=+$//')"
if ! printf '%s\n' "$count_line" | grep -qE '^[0-9]+ (passed|failed|error|errors|skipped|xfailed|xpassed|deselected)\b.* in [0-9.]+s'; then
  echo "Not a completed pytest run: the log does not end with pytest's count line." >&2
  echo "  last line: ${count_line}" >&2
  exit 1
fi

if printf '%s\n' "$log" | grep -qE '^SKIPPED \[[0-9]+\] '; then
  echo "The run folded its skips. Run pytest with -rs --no-fold-skipped so every skip carries its node id." >&2
  exit 1
fi

# pytest prints the reason as "Skipped: <reason>"; the list carries the reason alone.
actual="$(printf '%s\n' "$log" | sed -nE '/^SKIPPED /{s/^SKIPPED //; s/ - Skipped: / - /; p;}' | sort -u)" || exit 1

if printf '%s\n' "$count_line" | grep -qE '\b[1-9][0-9]* skipped\b' && [ -z "$actual" ]; then
  echo "The run reports skipped tests but lists none. Run pytest with -rs --no-fold-skipped." >&2
  exit 1
fi

if [ "$under_ci" -eq 1 ]; then
  expected=""
else
  expected="$(sed -E '/^[[:space:]]*(#|$)/d' "$expected_list" | sort -u)" || exit 1
fi

# Materialize the sorted inputs: comparison errors must fail the gate,
# including on hosts where /dev/fd process substitution is unavailable.
comparison_dir="$(mktemp -d)" || exit 1
trap 'rm -rf -- "$comparison_dir"' EXIT
printf '%s\n' "$actual" | sed '/^$/d' > "$comparison_dir/actual" || exit 1
printf '%s\n' "$expected" | sed '/^$/d' > "$comparison_dir/expected" || exit 1
unexpected="$(comm -23 "$comparison_dir/actual" "$comparison_dir/expected")" || exit 1
seen="$(comm -12 "$comparison_dir/actual" "$comparison_dir/expected")" || exit 1

if [ -n "$seen" ]; then
  echo "Expected skips (listed in ${expected_list}):"
  printf '%s\n' "$seen" | sed 's/^/  /'
fi
if [ -n "$unexpected" ]; then
  if [ "$under_ci" -eq 1 ]; then
    echo "Skipped under CI, where every test must run:" >&2
  else
    echo "Skipped but not listed in ${expected_list}:" >&2
  fi
  printf '%s\n' "$unexpected" | sed 's/^/  /' >&2
  echo "A test that cannot run is a failure, not a skip. Make it run, or list it with its reason." >&2
  exit 1
fi
echo "No unexpected skips."
exit 0
