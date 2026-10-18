#!/usr/bin/env bash
set -euo pipefail

STAGE="${1:-}"
case "$STAGE" in
  collect|resolve|replay|gate-experiment) ;;
  *) echo "usage: $0 collect|resolve|replay|gate-experiment" >&2; exit 2 ;;
esac

RUN="${RUN:?set RUN to the staged GCC root}"
CHIMERA="${CHIMERA:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
VENV="${VENV:-${VIRTUAL_ENV:?set VENV or activate a Python virtual environment}}"
PY="${PY:-$VENV/bin/python}"
EXPECTED_GATE2_SHA256="${EXPECTED_GATE2_SHA256:-3b022cb21ef1e5ce80768ac84a8862f14bbf568650b28c75210d884c46a65e1d}"
test -x "$PY" || { echo "STOP: missing Python $PY" >&2; exit 2; }
test -x "$RUN/build-stack/gcc/xgcc" || { echo "STOP: missing build-stack xgcc" >&2; exit 2; }
test -x "$RUN/build-gate2/gcc/xgcc" || { echo "STOP: missing build-gate2 xgcc" >&2; exit 2; }
command -v objdump >/dev/null
command -v readelf >/dev/null
command -v nm >/dev/null
command -v ar >/dev/null
command -v addr2line >/dev/null

mkdir -p "$RUN/reports"
OUT=$(mktemp -d "$RUN/reports/layout-codegen-${STAGE}-$(date +%Y%m%d-%H%M%S)-XXXXXX")
printf 'Results: %s\n' "$OUT"
finish() {
  rc=$?
  trap - EXIT
  printf "stage=%s exit=%s results=%s\\n" "$STAGE" "$rc" "$OUT" > "$OUT/driver-status.txt"
  if ! tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"; then
    echo "failed to archive evidence: $OUT.tar.gz" >&2
    rc=1
  else
    echo "Evidence bundle: $OUT.tar.gz"
  fi
  exit "$rc"
}
trap finish EXIT

COMMON=(--repo "$CHIMERA" --run "$RUN" --out "$OUT" --expected-gate2-sha256 "$EXPECTED_GATE2_SHA256"
  --wrapper "$VENV/bin/chimera-pkg")
TOOL=("$PY" -I "$CHIMERA/tools/layout_codegen_forensics.py")
LAYOUT_SYMBOL="${LAYOUT_SYMBOL:-_ZN12_GLOBAL__N_16layoutC2ERK30diagnostic_source_print_policyRK13rich_locationP29diagnostic_source_effect_info}"
case "$STAGE" in
  collect)
    ARGS=(collect "${COMMON[@]}" --layout-symbol "$LAYOUT_SYMBOL")
    if [[ -n "${GATE_DECISION:-}" ]]; then ARGS+=(--gate-list "$GATE_DECISION"); fi
    if [[ -n "${STACK_DECISION:-}" ]]; then ARGS+=(--stack-decision "$STACK_DECISION"); fi
    "${TOOL[@]}" "${ARGS[@]}"
    ;;
  resolve)
    : "${COLLECTION:?set COLLECTION to the existing collect result collection.json}"
    "${TOOL[@]}" resolve "${COMMON[@]}" --layout-symbol "$LAYOUT_SYMBOL" \
      --collection "$COLLECTION"
    ;;
  replay)
    : "${COLLECTION:?set COLLECTION to the collect result collection.json}"
    : "${BUILD_STAGE:?set BUILD_STAGE to stack or gate2}"
    ARGS=(replay "${COMMON[@]}" --layout-symbol "$LAYOUT_SYMBOL"
      --collection "$COLLECTION" --build-stage "$BUILD_STAGE")
    if [[ -n "${RESOLUTION:-}" ]]; then ARGS+=(--resolution "$RESOLUTION"); fi
    if [[ "$BUILD_STAGE" == gate2 ]]; then
      : "${GATE_DECISION:?set GATE_DECISION to the exact decision consumed by build-gate2}"
      ARGS+=(--gate-list "$GATE_DECISION")
    else
      : "${STACK_DECISION:?set STACK_DECISION to the exact stack-only decision consumed by build-stack}"
      ARGS+=(--stack-decision "$STACK_DECISION")
    fi
    if [[ -n "${COMPILE_DATABASE:-}" ]]; then
      : "${ENTRY_INDEX:?set ENTRY_INDEX to the uniquely matched entry index}"
      ARGS+=(--compile-database "$COMPILE_DATABASE" --entry-index "$ENTRY_INDEX")
    elif [[ -n "${COMPILE_ENTRY_JSON:-}" ]]; then
      : "${ORIGINAL_OBJECT:?set ORIGINAL_OBJECT to the uniquely verified collected object defining layout}"
      ARGS+=(--compile-entry-json "$COMPILE_ENTRY_JSON" --original-object "$ORIGINAL_OBJECT")
    else
      echo "STOP: provide COMPILE_DATABASE+ENTRY_INDEX or a reviewed COMPILE_ENTRY_JSON" >&2
      exit 2
    fi
    "${TOOL[@]}" "${ARGS[@]}"
    ;;
  gate-experiment)
    # A/B gate experiment for one exact symbol.  The Python stage runs A and B
    # sequentially and stops before B when A cannot reproduce the original
    # object; this driver only supplies inputs and packages the evidence.
    : "${COLLECTION:?set COLLECTION to the collect result collection.json}"
    : "${GATE_DECISION:?set GATE_DECISION to the exact decision consumed by build-gate2}"
    : "${TOOLCHAIN_MANIFEST:?set TOOLCHAIN_MANIFEST to the tool/plugin/source/object/decision hash manifest}"
    ARGS=(gate-experiment "${COMMON[@]}" --layout-symbol "$LAYOUT_SYMBOL"
      --collection "$COLLECTION" --gate-list "$GATE_DECISION"
      --toolchain-manifest "$TOOLCHAIN_MANIFEST")
    if [[ -n "${TARGET_SYMBOL:-}" ]]; then ARGS+=(--target-symbol "$TARGET_SYMBOL"); fi
    if [[ -n "${RESOLUTION:-}" ]]; then ARGS+=(--resolution "$RESOLUTION"); fi
    if [[ -n "${COMPILE_DATABASE:-}" ]]; then
      : "${ENTRY_INDEX:?set ENTRY_INDEX to the uniquely matched entry index}"
      ARGS+=(--compile-database "$COMPILE_DATABASE" --entry-index "$ENTRY_INDEX")
    elif [[ -n "${COMPILE_ENTRY_JSON:-}" ]]; then
      : "${ORIGINAL_OBJECT:?set ORIGINAL_OBJECT to the uniquely verified collected object defining layout}"
      ARGS+=(--compile-entry-json "$COMPILE_ENTRY_JSON" --original-object "$ORIGINAL_OBJECT")
    else
      echo "STOP: provide COMPILE_DATABASE+ENTRY_INDEX or a reviewed COMPILE_ENTRY_JSON" >&2
      exit 2
    fi
    "${TOOL[@]}" "${ARGS[@]}"
    ;;
esac
