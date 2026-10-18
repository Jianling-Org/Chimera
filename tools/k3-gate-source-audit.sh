#!/usr/bin/env bash
# Independent implicit-vectorization source audit of both xgcc builds.
#
# Audits build-stack/gcc/xgcc and build-gate2/gcc/xgcc against the gate-2
# decision file used as the COMPARISON list, then emits the cross-build
# comparison.  Comparing both builds against one target list is deliberate:
# build-stack only enables the stack-object plugin and build-gate2 is the one
# that consumes the gate list, so the baseline is expressed as "the same
# function set, before the gate".  What each build actually consumed is a
# separate, recorded fact (see decisions.txt) and never affects matching.
#
# The audit is an independent re-check: it does not change check-elf, the
# safety-point classification, the pass criteria or the check credentials, and
# it never writes back into the gate decision.  Everything it produces lands
# under a fresh directory inside "$RUN/reports"; the decision files, the GCC
# binaries and any existing report are only ever read, and their hashes are
# re-checked after the run.
#
# The code that executes must be the code that was reviewed: the installed
# module is hashed and compared against the source tree before the first
# audit, and the run stops if they differ (see step 1b).
#
# Exit code: 0 means the AUDIT completed.  It does not mean the application is
# safe.  Insufficient evidence is reported inside the audit documents; invalid
# input, an identity mismatch or an execution failure exits non-zero.
set -euo pipefail

RUN=${RUN:-/root/yangzheng/gcc-rebuild/chimera-staged-20260919-132951}
CHIMERA=${CHIMERA:-/root/yangzheng/chimera_release/chimera}
VENV=${VENV:-/root/yangzheng/chimera_release/chimera_release}

# Inputs, never guessed.  GATE_DECISION is the *comparison* list the audit
# checks both builds against - it is the gate-2 target list, and the baseline
# build does not consume it (build-stack only enables the stack-object plugin).
# STACK_DECISION optionally names what build-stack itself consumed; it is
# recorded, never used for matching, because the two roles are different facts.
# GATE_CENSUS (repeatable via GATE_CENSUS_EXTRA) is the per-TU census stream,
# and EVIDENCE_MANIFEST is the manifest that binds those census files to build
# identity - including the artifact hash, without which a record from another
# build of the same stage would attach to the wrong product.
: "${GATE_DECISION:?set GATE_DECISION to the gate-2 decision file used as the comparison list}"
STACK_DECISION=${STACK_DECISION:-}
GATE_CENSUS=${GATE_CENSUS:-}
GATE_CENSUS_EXTRA=${GATE_CENSUS_EXTRA:-}
EVIDENCE_MANIFEST=${EVIDENCE_MANIFEST:-}

MIN_VLEN_BITS=${MIN_VLEN_BITS:-256}
EXPECTED_GATE_COUNT=${EXPECTED_GATE_COUNT:-1642}
#: The two build stages the audit distinguishes.  A census file binds only to
#: the stage it was captured under, which is why both are named here.
STAGE_STACK=build-stack
STAGE_GATE2=build-gate2
XGCC_STACK="$RUN/build-stack/gcc/xgcc"
XGCC_GATE2="$RUN/build-gate2/gcc/xgcc"

PY="$VENV/bin/python"
unset PYTHONPATH PYTHONHOME
export PATH="$VENV/bin:$PATH"

test -n "$RUN"
test -d "$RUN"
test -x "$PY"
test -f "$GATE_DECISION"
test -x "$XGCC_STACK"
test -x "$XGCC_GATE2"
command -v objdump >/dev/null
command -v sha256sum >/dev/null
test -x /usr/bin/time

mkdir -p "$RUN/reports"
OUT=$(mktemp -d "$RUN/reports/gate-source-audit-$(date +%Y%m%d-%H%M%S)-XXXXXX")
printf '%s\n' "$OUT" > "$RUN/last-gate-source-audit-reports.txt"
echo "Results: $OUT"
trap 'rc=$?; echo "Script exit=$rc; results=$OUT"' EXIT

# --- 1. identity of everything this run depends on -------------------------
{
  echo "stage=gate-source-audit"
  echo "run=$RUN"
  echo "chimera=$CHIMERA"
  echo "venv=$VENV"
  echo "comparison_list=$GATE_DECISION"
  echo "stack_consumed_decision=${STACK_DECISION:-<not supplied>}"
  echo "gate2_consumed_decision=$GATE_DECISION"
  echo "min_vlen_bits=$MIN_VLEN_BITS"
  echo "expected_gate_count=$EXPECTED_GATE_COUNT"
} > "$OUT/inputs.txt"

sha256sum "$XGCC_STACK" "$XGCC_GATE2" "$GATE_DECISION" > "$OUT/inputs.sha256"
if test -n "$STACK_DECISION"; then
  test -f "$STACK_DECISION" || {
    echo "STOP: STACK_DECISION does not exist: $STACK_DECISION" >&2; exit 2;
  }
  sha256sum "$STACK_DECISION" >> "$OUT/inputs.sha256"
fi
# The revision of the *source tree* - deliberately named so it cannot be
# mistaken for the revision that will actually execute (see step 1b).
git -C "$CHIMERA" rev-parse HEAD > "$OUT/source-tree-revision.txt" 2>&1 || true
"$PY" -I -c 'import sys; print(sys.version)' > "$OUT/python.version.txt" 2>&1
objdump --version 2>&1 | head -n 2 > "$OUT/objdump.version.txt"
cp -- "$GATE_DECISION" "$OUT/decision.snapshot" 2>/dev/null || true

# --- 1b. the code that runs must be the reviewed code ----------------------
# The audit is executed with the venv's `python -I -m`, i.e. the *installed*
# module, while the repository HEAD may already have moved on.  Recording the
# source revision alone would therefore describe the wrong code, so every
# deciding module is hashed and compared against its source-tree file before
# the first audit: an audit module at HEAD paired with a stale analyzer would
# otherwise pass a check that only ever looked at one file.
#
# The check is its own executable (tools/audit_module_identity.py) rather than
# an inline heredoc, so it can be run - and tested - on its own.  All inputs
# are passed as arguments; nothing is read from the ambient environment, which
# is what made the earlier inline version fail with KeyError on a shell that
# merely assigned OUT/VENV.  It writes the digest table itself; parsing a
# digest back out of a printed line is exactly the kind of step that silently
# yields an empty string and waves the check through.
IDENTITY_TOOL="$CHIMERA/tools/audit_module_identity.py"
test -f "$IDENTITY_TOOL" || {
  echo "STOP: module identity tool not found: $IDENTITY_TOOL" >&2; exit 2;
}
if ! "$PY" -I "$IDENTITY_TOOL" \
    --out-dir "$OUT" \
    --source-root "$CHIMERA" \
    --venv "$VENV" \
    > "$OUT/audit-module.log" 2>&1; then
  cat "$OUT/audit-module.log" >&2
  cat "$OUT/module-identity.txt" >&2 || true
  exit 2
fi
cat "$OUT/audit-module.log"
cat "$OUT/module-identity.txt"
grep -q '^all_modules_match_source=True$' "$OUT/audit-module.txt" || {
  echo "STOP: a deciding module does not match the source tree" >&2
  exit 2
}
grep -q '^all_modules_inside_venv=True$' "$OUT/audit-module.txt" || {
  echo "STOP: a deciding module was imported from outside the venv" >&2
  exit 2
}
echo "deciding modules verified ($(grep -c '^chimera' "$OUT/installed-modules.tsv" || true) modules)"

# --- 2. inventory of the logs and census the builds left behind ------------
# Missing evidence is written down as missing; it is never silently assumed.
{
  echo "# wrapper / build transcripts found under \$RUN"
  find "$RUN" -maxdepth 6 \
    \( -name '*wrapper*.log' -o -name '*-build.log' -o -name 'ninja.log' \) \
    -type f -print 2>/dev/null | LC_ALL=C sort
} > "$OUT/log-inventory.txt"

{
  echo "# implicit-vector-census files found under \$RUN"
  find "$RUN" -maxdepth 8 -name '*implicit_vector_census*.tsv' -type f -print \
    2>/dev/null | LC_ALL=C sort
} > "$OUT/census-inventory.txt"

{
  echo "# decision files found under \$RUN"
  find "$RUN" -maxdepth 8 -name '*decision*.json' -name '*.decision.json' -type f \
    -print 2>/dev/null | LC_ALL=C sort
} > "$OUT/decision-inventory.txt"

# The two roles, side by side.  Conflating them is how "the baseline was
# audited against a list it never used" turns into a false conclusion.
{
  echo "# comparison list (the gate-2 target list, applied to BOTH builds)"
  echo "comparison_list=$GATE_DECISION"
  echo
  echo "# decisions the builds actually consumed (declared, not derived)"
  echo "build-gate2=$GATE_DECISION"
  echo "build-stack=${STACK_DECISION:-<not supplied: build-stack enables only the stack-object plugin>}"
} > "$OUT/decisions.txt"

census_args=()
if test -n "$GATE_CENSUS"; then
  test -f "$GATE_CENSUS" || {
    echo "STOP: GATE_CENSUS does not exist: $GATE_CENSUS" >&2; exit 2;
  }
  census_args+=(--census "$GATE_CENSUS")
fi
if test -n "$GATE_CENSUS_EXTRA"; then
  IFS=':' read -r -a extra_census <<< "$GATE_CENSUS_EXTRA"
  for extra in "${extra_census[@]}"; do
    test -n "$extra" || continue
    test -f "$extra" || { echo "STOP: census does not exist: $extra" >&2; exit 2; }
    census_args+=(--census "$extra")
  done
fi

evidence_args=()
if test -n "$EVIDENCE_MANIFEST"; then
  test -f "$EVIDENCE_MANIFEST" || {
    echo "STOP: EVIDENCE_MANIFEST does not exist: $EVIDENCE_MANIFEST" >&2; exit 2;
  }
  evidence_args+=(--evidence "$EVIDENCE_MANIFEST")
fi

{
  if ((${#census_args[@]} == 0)); then
    echo "census: none supplied - per-function gate execution evidence is MISSING"
    echo "        (the census inventory above lists any file the builds left behind)"
  else
    echo "census: ${#census_args[@]} argument(s) supplied"
  fi
  if ((${#evidence_args[@]} == 0)); then
    echo "evidence manifest: none supplied - every census record is UNBOUND,"
    echo "                   so it can neither prove nor refute the gate"
  else
    echo "evidence manifest: $EVIDENCE_MANIFEST"
  fi
} > "$OUT/evidence-presence.txt"

# --- 3. audit each build, one after the other ------------------------------
audit_one() {
  local stage="$1" elf="$2" name="$3" consumed="$4"
  local json="$OUT/$name.audit.json"
  local timefile="$OUT/$name.time.txt"
  local logfile="$OUT/$name.audit.log"
  local consumed_args=()
  if test -n "$consumed"; then
    consumed_args+=(--consumed-decision "$consumed")
  fi
  local rc=0
  echo "Auditing $stage ($elf) against the comparison list; log: $logfile"
  if /usr/bin/time -v -o "$timefile" \
      "$PY" -I -m chimera.gate_source_audit audit \
      --input "$elf" \
      --gate-list "$GATE_DECISION" \
      --stage "$stage" \
      --expected-gate-count "$EXPECTED_GATE_COUNT" \
      --min-vlen-bits "$MIN_VLEN_BITS" \
      ${consumed_args[@]+"${consumed_args[@]}"} \
      ${census_args[@]+"${census_args[@]}"} \
      ${evidence_args[@]+"${evidence_args[@]}"} \
      --json "$json" \
      --candidates-csv "$OUT/$name.candidates.csv" \
      --gate-csv "$OUT/$name.gate-entries.csv" \
      --report "$OUT/$name.report.md" \
      > "$logfile" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$rc" > "$OUT/$name.exit.txt"
  test -s "$timefile" || { echo "STOP: $stage produced no timing artifact" >&2; return 2; }
  grep -E 'Elapsed|Maximum resident' "$timefile" || true
  if ((rc != 0)); then
    tail -n 20 "$logfile" >&2
    echo "STOP: audit of $stage failed ($rc)" >&2
    return "$rc"
  fi
  test -s "$json" || { echo "STOP: $stage produced no JSON" >&2; return 2; }
  test -s "$OUT/$name.report.md" || { echo "STOP: $stage produced no report" >&2; return 2; }
  echo "audited $stage: $json"
  return 0
}

stack_rc=0
gate2_rc=0
audit_one "$STAGE_STACK" "$XGCC_STACK" "build-stack" "$STACK_DECISION" || stack_rc=$?
audit_one "$STAGE_GATE2" "$XGCC_GATE2" "build-gate2" "$GATE_DECISION" || gate2_rc=$?

# --- 4. cross-build comparison (grouped by symbol and source kind) ---------
compare_rc=0
if ((stack_rc == 0 && gate2_rc == 0)); then
  if "$PY" -I -m chimera.gate_source_audit compare \
      --baseline "$OUT/build-stack.audit.json" \
      --audited "$OUT/build-gate2.audit.json" \
      --json "$OUT/compare.json" \
      --report "$OUT/compare.md" \
      > "$OUT/compare.log" 2>&1; then
    compare_rc=0
  else
    compare_rc=$?
    tail -n 20 "$OUT/compare.log" >&2
  fi
else
  compare_rc=3
  echo "compare skipped: an audit did not complete" >&2
fi

# --- 5. the inputs must be exactly as they were ----------------------------
# Read-only is a claim; it is checked rather than asserted.
sha256sum -c --status "$OUT/inputs.sha256" || {
  echo "STOP: an input changed during the audit" >&2
  exit 2
}

# --- 6. summary, with the disclaimer the exit code cannot carry ------------
{
  echo "run=$RUN"
  echo "out=$OUT"
  echo "deciding modules: see $OUT/installed-modules.tsv"
  echo "build-stack audit exit=$stack_rc"
  echo "build-gate2 audit exit=$gate2_rc"
  echo "compare exit=$compare_rc"
  echo
  echo "Exit 0 means the audit completed.  It does NOT mean the application is"
  echo "safe, that the gate fired, or that the gate list is complete: read"
  echo "$OUT/build-gate2.report.md, $OUT/build-stack.report.md and"
  echo "$OUT/compare.md.  Insufficient evidence is reported there, not here."
  echo
  echo "本脚本正常退出只表示审计执行完成，不代表安全检查通过。"
} | tee "$OUT/summary.txt"

if ((stack_rc != 0 || gate2_rc != 0 || compare_rc != 0)); then
  echo "STOP: audit did not complete cleanly" >&2
  exit 2
fi
echo "Audit completed.  This says nothing about whether the application is safe."
