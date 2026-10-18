#!/usr/bin/env bash
# Isolated gate4 builtin A/B; never relinks GCC or changes the formal decision.
set -euo pipefail
export LC_ALL=C LANG=C
: "${RUN:?set RUN to the staged GCC root}"
CHIMERA="${CHIMERA:-/root/yangzheng/chimera_release/chimera}"
VENV="${VENV:-/root/yangzheng/chimera_release/chimera_release}"
PY="$VENV/bin/python"
export CHIMERA_TOOLCHAIN_BUILD="${CHIMERA_TOOLCHAIN_BUILD:-/root/.chimera/toolchain_build}"
COLLECTION="${COLLECTION:-$RUN/reports/builtin-gate-inputs-20261001T064917Z-7Rt302/collection/collection.json}"
test -x "$PY" || { echo "STOP: missing venv Python" >&2; exit 2; }
test -f "$COLLECTION" || { echo "STOP: missing collection: $COLLECTION" >&2; exit 2; }
test -f "$CHIMERA/tools/builtin_gate_experiment.py" || { echo "STOP: synchronize experiment tools first" >&2; exit 2; }
mkdir -p "$RUN/reports"
OUT="$(mktemp -d "$RUN/reports/builtin-gate-experiment-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
printf 'Evidence directory: %s\n' "$OUT"
finish() {
  rc=$?
  trap - EXIT
  set +e
  printf '%s\n' "$rc" > "$OUT/workflow.exit.txt"
  tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
  pack_rc=$?
  if [ "$pack_rc" -eq 0 ]; then
    printf 'Evidence package: %s.tar.gz\n' "$OUT"
  else
    echo 'Evidence packaging failed' >&2
    if [ "$rc" -eq 0 ]; then rc=2; fi
  fi
  printf 'Workflow exit: %s\n' "$rc"
  exit "$rc"
}
trap finish EXIT
unset PYTHONPATH PYTHONHOME CHIMERA_GATE_LIST CHIMERA_GATE_STATS
unset DEPENDENCIES_OUTPUT SUNPRO_DEPENDENCIES LLVM_PROFILE_FILE GCOV_PREFIX
git -C "$CHIMERA" rev-parse HEAD > "$OUT/source-revision.txt"
git -C "$CHIMERA" status --short > "$OUT/source-working-tree.txt"
cp "$0" "$OUT/driver.snapshot.sh"
sha256sum "$COLLECTION" "$CHIMERA/tools/builtin_gate_experiment.py" \
  "$CHIMERA/tools/layout_codegen_forensics.py" "$CHIMERA/tools/builtin_gate_inputs.py" \
  "$CHIMERA/tools/audit_module_identity.py" > "$OUT/inputs-and-tools.sha256"

# Verify the installed analysis and wrapper actually match the checkout.
IDENTITY=("$PY" -I "$CHIMERA/tools/audit_module_identity.py"
  --out-dir "$OUT/module-identity" --source-root "$CHIMERA" --venv "$VENV")
for spec in \
  'chimera.llvm_wrapper=cli/chimera/llvm_wrapper.py' \
  'chimera.check_elf=cli/chimera/check_elf.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.analyzer=preprocessing/offline/analysis/safety/stack_liveness/analyzer.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.accesses=preprocessing/offline/analysis/safety/stack_liveness/accesses.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.frame_liveness=preprocessing/offline/analysis/safety/stack_liveness/frame_liveness.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.dependencies=preprocessing/offline/analysis/safety/stack_liveness/dependencies.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.liveness=preprocessing/offline/analysis/safety/stack_liveness/liveness.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.origins=preprocessing/offline/analysis/safety/stack_liveness/origins.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.expressions=preprocessing/offline/analysis/safety/stack_liveness/expressions.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.loops=preprocessing/offline/analysis/safety/stack_liveness/loops.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.model=preprocessing/offline/analysis/safety/stack_liveness/model.py' \
  'chimera.preprocess.offline.analysis.safety.stack_liveness.scope=preprocessing/offline/analysis/safety/stack_liveness/scope.py' \
  'chimera.preprocess.offline.analysis.arch.riscv.control_flow=preprocessing/offline/analysis/arch/riscv/control_flow.py' \
  'chimera.preprocess.offline.analysis.arch.riscv.scalar_semantics=preprocessing/offline/analysis/arch/riscv/scalar_semantics.py' \
  'chimera.preprocess.offline.analysis.arch.riscv.stack_semantics=preprocessing/offline/analysis/arch/riscv/stack_semantics.py' \
  'chimera.preprocess.offline.analysis.program_model.parser=preprocessing/offline/analysis/program_model/parser.py'; do
  IDENTITY+=(--module "$spec")
done
"${IDENTITY[@]}" > "$OUT/module-identity.stdout.txt" 2> "$OUT/module-identity.stderr.txt"
CMD=("$PY" -I "$CHIMERA/tools/builtin_gate_experiment.py"
  --collection "$COLLECTION" --out "$OUT/experiment"
  --policy assume-scalar-independent --objdump objdump --readelf readelf)
if [ -x /usr/bin/time ]; then
  CMD=(/usr/bin/time -v -o "$OUT/experiment.time.txt" "${CMD[@]}")
fi
printf '%q ' "${CMD[@]}" > "$OUT/experiment.command.txt"
printf '\n' >> "$OUT/experiment.command.txt"
if "${CMD[@]}" > "$OUT/experiment.stdout.txt" 2> "$OUT/experiment.stderr.txt"; then
  experiment_rc=0
else
  experiment_rc=$?
fi
printf '%s\n' "$experiment_rc" > "$OUT/experiment.exit.txt"
cat "$OUT/experiment.stdout.txt"
if [ "$experiment_rc" -ne 0 ]; then
  tail -n 40 "$OUT/experiment.stderr.txt" >&2
fi
printf 'Read experiment/report.md and experiment/result.json. This experiment is not a full GCC safety verdict.\n'
exit "$experiment_rc"
