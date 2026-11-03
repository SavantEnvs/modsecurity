#!/usr/bin/env bash
#
# mayhem/test.sh — RUN ModSecurity's own unit + regression suites (built by mayhem/build.sh with the
# project's normal flags in mayhem/build-tests). exit 0 = pass.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TESTS="$SRC/mayhem/build-tests/test"
for r in regression_tests unit_tests; do
  [ -x "$TESTS/$r" ] || { echo "missing $TESTS/$r — mayhem/build.sh did not build it" >&2; emit_ctrf "modsecurity" 0 1 0; exit 1; }
done

# Upstream's authoritative list is TESTS+= in test/test-suite.in (run from test/, as test-suite.sh does).
# Pass/fail comes from the runners' own summary lines, never from exit status alone: a runner that
# exits 0 without printing a summary (a neutered binary) counts as a failed file.
passed=0; failed=0; skipped=0
cd "$SRC/test"
while read -r f; do
  [ -f "../$f" ] || { echo "FAIL (missing test file): $f"; failed=$((failed+1)); continue; }
  rel="${f#test/}"
  case "$f" in
    */regression/*) runner=regression_tests ;;
    *)              runner=unit_tests ;;
  esac
  out="$(timeout 600 "$TESTS/$runner" "$rel" 2>&1; echo "RC=$?")"
  rc="$(printf '%s\n' "$out" | sed -nE '$s/^RC=([0-9]+)$/\1/p')"; rc="${rc:-1}"
  out="$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')"
  if [ "$runner" = regression_tests ]; then
    line="$(printf '%s\n' "$out" | grep -E '^Ran a total of: [0-9]+ regression tests' | tail -1)"
    n="$(printf '%s' "$line" | sed -E 's/^Ran a total of: ([0-9]+) .*/\1/')"
    nf="$(printf '%s' "$line" | sed -nE 's/.* ([0-9]+) failed\..*/\1/p')"
    ns="$(printf '%s' "$line" | sed -nE 's/.* ([0-9]+) skipped test.*/\1/p')"
  else
    line="$(printf '%s\n' "$out" | grep -E '^Ran a total of: [0-9]+ unit tests' | tail -1)"
    n="$(printf '%s\n' "$out" | sed -nE 's/^Total >> ([0-9]+)$/\1/p' | tail -1)"
    nf="$(printf '%s' "$line" | sed -nE 's/.* ([0-9]+) failed\..*/\1/p')"
    ns=0
  fi
  nf="${nf:-0}"; ns="${ns:-0}"
  if [ -z "$line" ] || { [ "${n:-0}" -eq 0 ] && [ "$ns" -eq 0 ]; }; then
    echo "FAIL (no tests reported, rc=$rc): $f"; failed=$((failed+1)); continue
  fi
  if [ "$rc" -ne 0 ] && [ "$nf" -eq 0 ]; then nf=1; fi
  # Cases that fetch a remote rule/list (SecRemoteRules, @ipMatchFromFile https://...) cannot pass
  # without network (the grader runs offline). Re-run such a file case by case; a failing case counts
  # as skipped only if its own rules reference a remote URL, every other case must still pass.
  if [ "$runner" = regression_tests ] && [ "$nf" -gt 0 ] && grep -qE '(SecRemoteRules|FromFile)[^"]* https?://' "../$f"; then
    remote="$(python3 - "../$f" <<'PY'
import json, re, sys
for i, t in enumerate(json.load(open(sys.argv[1])), 1):
    if any(re.search(r"(SecRemoteRules|FromFile)\S*\s.*https?://", r) for r in t.get("rules", [])):
        print(i)
PY
)"
    total="$("$TESTS/regression_tests" countall "$rel" 2>/dev/null | tail -1)"
    nf=0; ns=0
    for i in $(seq 1 "${total:-0}"); do
      cout="$(timeout 600 "$TESTS/regression_tests" "$rel:$i" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
      printf '%s\n' "$cout" | grep -qE 'regression tests - All tests passed' && continue
      if printf '%s\n' "$remote" | grep -qx "$i"; then ns=$((ns+1))
      else nf=$((nf+1)); echo "FAIL: $f:$i"; printf '%s\n' "$cout" | tail -15; fi
    done
    n=$(( ${total:-0} - ns ))
  fi
  [ "$nf" -eq 0 ] || { echo "FAIL ($nf failed): $f"; printf '%s\n' "$out" | tail -25; }
  failed=$((failed+nf)); skipped=$((skipped+ns))
  ok=$(( ${n:-0} - nf )); [ "$ok" -ge 0 ] || ok=0
  passed=$((passed+ok))
done < <(sed -nE 's/^TESTS\+=//p' "$SRC/test/test-suite.in")

emit_ctrf "modsecurity-unit+regression" "$passed" "$failed" "$skipped"
