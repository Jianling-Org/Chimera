#!/usr/bin/env bash
# Collect the gate4 builtin root's replay inputs. No compiler or wrapper runs.
set -euo pipefail
export LC_ALL=C LANG=C
: "${RUN:?set RUN to the staged GCC root}"
CHIMERA="${CHIMERA:-/root/yangzheng/chimera_release/chimera}"
VENV="${VENV:-/root/yangzheng/chimera_release/chimera_release}"
PY="${PY:-$VENV/bin/python}"
ORIGIN="${ORIGIN:-$RUN/reports/gate4-build-check-v20-20260930-163702-BKOpNC}"
COMPILER="${COMPILER:-/root/.chimera/toolchain_build/llvm/bin/clang++}"
STACK_PLUGIN="${STACK_PLUGIN:-/root/.chimera/toolchain_build/plugins/lib/chimera/llvm/ChimeraStackObject.so}"
GATE_PLUGIN="${GATE_PLUGIN:-/root/.chimera/toolchain_build/plugins/lib/chimera/llvm/ChimeraVectorGate.so}"
test -x "$PY" || { echo "STOP: missing Python $PY" >&2; exit 2; }
test -f "$CHIMERA/tools/builtin_gate_inputs.py" || { echo "STOP: missing collector; synchronize the new tools first" >&2; exit 2; }
mkdir -p "$RUN/reports"
OUT="$(mktemp -d "$RUN/reports/builtin-gate-inputs-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
printf 'Evidence directory: %s\n' "$OUT"
finish() {
  rc=$?
  trap - EXIT
  set +e
  printf '%s\n' "$rc" > "$OUT/workflow.exit.txt"
  tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
  pack_rc=$?
  if [ "$pack_rc" -ne 0 ]; then
    echo "Evidence packaging failed" >&2
    if [ "$rc" -eq 0 ]; then rc=2; fi
  else
    printf 'Evidence package: %s.tar.gz\n' "$OUT"
  fi
  printf 'Workflow exit: %s\n' "$rc"
  exit "$rc"
}
trap finish EXIT
unset PYTHONPATH PYTHONHOME
git -C "$CHIMERA" rev-parse HEAD > "$OUT/source-revision.txt"
git -C "$CHIMERA" status --short > "$OUT/source-working-tree.txt"
cp "$CHIMERA/tools/k3-collect-builtin-gate-inputs.sh" "$OUT/driver.snapshot.sh"
sha256sum "$CHIMERA/tools/builtin_gate_inputs.py" \
  "$CHIMERA/tools/k3_unknown_stack_scope_evidence.py" \
  "$CHIMERA/tools/k3-collect-builtin-gate-inputs.sh" > "$OUT/collector-source.sha256"
CMD=("$PY" -I "$CHIMERA/tools/builtin_gate_inputs.py"
  --run "$RUN" --origin "$ORIGIN" --out "$OUT/collection"
  --compiler "$COMPILER" --plugin "$STACK_PLUGIN" --plugin "$GATE_PLUGIN")
if [ -x /usr/bin/time ]; then
  CMD=(/usr/bin/time -v -o "$OUT/collect.time.txt" "${CMD[@]}")
fi
printf '%q ' "${CMD[@]}" > "$OUT/collector-command.txt"
printf '\n' >> "$OUT/collector-command.txt"
if "${CMD[@]}" > "$OUT/collect.stdout.txt" 2> "$OUT/collect.stderr.txt"; then
  collector_rc=0
else
  collector_rc=$?
fi
printf '%s\n' "$collector_rc" > "$OUT/collector.exit.txt"
cat "$OUT/collect.stdout.txt"
if [ "$collector_rc" -ne 0 ]; then
  tail -n 30 "$OUT/collect.stderr.txt" >&2
  exit "$collector_rc"
fi
printf 'Review collection/report.md and collection/collection.json; collection is not a gate or safety verdict.\n'
