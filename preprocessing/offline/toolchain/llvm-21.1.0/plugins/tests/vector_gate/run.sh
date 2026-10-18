#!/usr/bin/env bash
set -euo pipefail

# End-to-end checks for the patched compiler plus ChimeraVectorGate.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLANG="${CLANG:-${CHIMERA_TOOLCHAIN_BUILD:-$HOME/.chimera/toolchain_build}/llvm/bin/clang++}"
PLUGIN="${PLUGIN:-}"
if [[ -z "$PLUGIN" ]]; then
    for candidate in "$ROOT"/../build*/plugins/vector_gate/ChimeraVectorGate.so \
                     "$ROOT"/build/plugins/vector_gate/ChimeraVectorGate.so; do
        [[ -f "$candidate" ]] && { PLUGIN="$candidate"; break; }
    done
fi
PYTHON="${PYTHON:-python3}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "ERROR: $*" >&2; exit 1; }
[[ -x "$CLANG" ]] || fail "patched clang++ not found: $CLANG"
[[ -f "$PLUGIN" ]] || fail "plugin not found: $PLUGIN"

# LV: the same profitable loop must be blocked only in the listed function.
cat >"$TMP_DIR/lv.cc" <<'EOF'
extern "C" void gated(float *a, const float *b, int n) {
  for (int i = 0; i < n; ++i) a[i] = b[i] + 1.0f;
}
extern "C" void open(float *a, const float *b, int n) {
  for (int i = 0; i < n; ++i) a[i] = b[i] + 1.0f;
}
EOF
printf 'gated\n' >"$TMP_DIR/gate.txt"
: >"$TMP_DIR/census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/census.tsv" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S -emit-llvm "$TMP_DIR/lv.cc" -o "$TMP_DIR/lv.ll"

grep -F $'implicit-vector-census\tLV\tgated\tblocked' "$TMP_DIR/census.tsv" >/dev/null ||
  fail "missing gated LV blocked record"
grep -F $'implicit-vector-census\tLV\topen\tformed' "$TMP_DIR/census.tsv" >/dev/null ||
  fail "missing open LV formed record"

"$PYTHON" - "$TMP_DIR/lv.ll" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()

def body(name):
    match = re.search(r"define [^{]*@" + name + r"\([^)]*\)[^{]*\{", text)
    if not match:
        raise SystemExit("missing function " + name)
    return text[match.end():text.find("\n}\n", match.end())]

if re.search(r"<(?:vscale x )?\d+ x ", body("gated")):
    raise SystemExit("gated loop still contains implicit vector IR")
if not re.search(r"<(?:vscale x )?\d+ x ", body("open")):
    raise SystemExit("open control did not vectorize")
PY

# A global gate list may contain functions from other translation units.  Such
# names are intentionally silent here; final effectiveness is checked on the
# linked ELF by `chimera-pkg check-elf`, not by per-module warning counters.
printf 'not_defined_in_this_tu\n' >"$TMP_DIR/unmatched-gate.txt"
CHIMERA_GATE_LIST="$TMP_DIR/unmatched-gate.txt" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S -emit-llvm "$TMP_DIR/lv.cc" -o "$TMP_DIR/unmatched.ll" \
  2>"$TMP_DIR/unmatched.stderr"
if grep -E 'gate list matched no function|listed function\(s\) not found in this module' \
  "$TMP_DIR/unmatched.stderr" >/dev/null; then
  fail "VectorGate emitted a per-module unmatched-list warning"
fi

# SLP: straight-line independent operations exercise the list/store-tree
# commit paths without relying on loop vectorization.
cat >"$TMP_DIR/slp.cc" <<'EOF'
extern "C" void gated_slp(float *a, const float *b) {
  a[0] = b[0] + 1.0f; a[1] = b[1] + 1.0f;
  a[2] = b[2] + 1.0f; a[3] = b[3] + 1.0f;
}
extern "C" void open_slp(float *a, const float *b) {
  a[0] = b[0] + 1.0f; a[1] = b[1] + 1.0f;
  a[2] = b[2] + 1.0f; a[3] = b[3] + 1.0f;
}
EOF
printf 'gated_slp\n' >"$TMP_DIR/slp-gate.txt"
: >"$TMP_DIR/slp-census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/slp-gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/slp-census.tsv" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S -emit-llvm "$TMP_DIR/slp.cc" -o "$TMP_DIR/slp.ll"
grep -F $'implicit-vector-census\tSLP\tgated_slp\tblocked' \
  "$TMP_DIR/slp-census.tsv" >/dev/null || fail "missing SLP blocked record"
grep -F $'implicit-vector-census\tSLP\topen_slp\tformed' \
  "$TMP_DIR/slp-census.tsv" >/dev/null || fail "missing SLP formed record"

# C1/C2 and D1/D2 gate-list compatibility remains required.  The plugin no
# longer emits start/last JSON; inspect the stamped IR attribute directly.
cat >"$TMP_DIR/special.cc" <<'EOF'
struct item { item(); ~item(); int x; };
item::item() : x(1) {}
item::~item() { x = 0; }
EOF
"$CLANG" -O2 -march=rv64gcv -c "$TMP_DIR/special.cc" -o "$TMP_DIR/special.o"
CTOR="$(nm "$TMP_DIR/special.o" | awk '/itemC1/ {print $3; exit}')"
DTOR="$(nm "$TMP_DIR/special.o" | awk '/itemD1/ {print $3; exit}')"
[[ -n "$CTOR" && -n "$DTOR" ]] || fail "C1/D1 symbols not found"
printf '%s\n%s\n' "$CTOR" "$DTOR" >"$TMP_DIR/special-gate.txt"
CHIMERA_GATE_LIST="$TMP_DIR/special-gate.txt" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S -emit-llvm "$TMP_DIR/special.cc" -o "$TMP_DIR/special.ll"
"$PYTHON" - "$TMP_DIR/special.ll" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
for tag in ("C2", "D2"):
    match = re.search(r"define [^{]*@(_Z[^ (]*item" + tag + r"[^ (]*)[^\{]*#(\d+)[^{]*\{", text)
    if not match:
        raise SystemExit("missing " + tag + " definition")
    attrs = re.search(r"attributes #" + match.group(2) + r" = \{([^}]*)\}", text)
    if not attrs or '"chimera-no-vectorize"' not in attrs.group(1):
        raise SystemExit("gate attribute missing on " + tag)
    if re.search(r'"target-features"="[^"]*(?:^|,)-v(?:,|$)', attrs.group(1)):
        raise SystemExit("gate must not strip explicit RVV target features")
PY

# Backend census requires the late function id.  A constant memop is enough to
# exercise the RISC-V vector expansion decision; duplicate events are allowed
# here and are deduplicated by vector_census_report.py.
cat >"$TMP_DIR/memop.cc" <<'EOF'
extern "C" void gated_memop(void *d, const void *s) {
  __builtin_memcpy(d, s, 64);
}
extern "C" void open_memop(void *d, const void *s) {
  __builtin_memcpy(d, s, 64);
}
EOF
printf 'gated_memop\n' >"$TMP_DIR/memop-gate.txt"
: >"$TMP_DIR/memop-census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/memop-gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/memop-census.tsv" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S "$TMP_DIR/memop.cc" -o "$TMP_DIR/memop.s"
grep -F $'implicit-vector-census\tMEMOP\tgated_memop\tblocked' \
  "$TMP_DIR/memop-census.tsv" >/dev/null || fail "missing MEMOP blocked record"
grep -F $'implicit-vector-census\tMEMOP\topen_memop\tformed' \
  "$TMP_DIR/memop-census.tsv" >/dev/null || fail "missing MEMOP formed record"

# Store Merge: disable the IR vectorizers so adjacent scalar load/store pairs
# reach the SelectionDAG combine decision unchanged.
cat >"$TMP_DIR/merge.cc" <<'EOF'
extern "C" void gated_merge(long *d, const long *s) {
  d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
}
extern "C" void open_merge(long *d, const long *s) {
  d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
}
EOF
printf 'gated_merge\n' >"$TMP_DIR/merge-gate.txt"
: >"$TMP_DIR/merge-census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/merge-gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/merge-census.tsv" \
  "$CLANG" -O2 -fno-vectorize -fno-slp-vectorize -march=rv64gcv \
  -fpass-plugin="$PLUGIN" -S "$TMP_DIR/merge.cc" -o "$TMP_DIR/merge.s"
grep -F $'implicit-vector-census\tMERGE\tgated_merge\tblocked' \
  "$TMP_DIR/merge-census.tsv" >/dev/null || fail "missing MERGE blocked record"
grep -F $'implicit-vector-census\tMERGE\topen_merge\tformed' \
  "$TMP_DIR/merge-census.tsv" >/dev/null || fail "missing MERGE formed record"

# Explicit RVV does not remove a function from the implicit-decision census.
# The intrinsic operations must survive while the independent scalar loop is
# rejected at LV's positive commit point.
cat >"$TMP_DIR/mixed.cc" <<'EOF'
#include <stddef.h>
#include <riscv_vector.h>
extern "C" void mixed(float *explicit_dst, const float *explicit_src,
                      float *loop_dst, const float *loop_src, int n) {
  size_t vl = __riscv_vsetvl_e32m1((size_t)n);
  vfloat32m1_t value = __riscv_vle32_v_f32m1(explicit_src, vl);
  __riscv_vse32_v_f32m1(explicit_dst, value, vl);
  for (int i = 0; i < n; ++i)
    loop_dst[i] = loop_src[i] + 1.0f;
}
EOF
printf 'mixed\n' >"$TMP_DIR/mixed-gate.txt"
: >"$TMP_DIR/mixed-census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/mixed-gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/mixed-census.tsv" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S "$TMP_DIR/mixed.cc" -o "$TMP_DIR/mixed.s"
grep -F $'implicit-vector-census\tLV\tmixed\tblocked' \
  "$TMP_DIR/mixed-census.tsv" >/dev/null || fail "mixed function LV was not blocked"
grep -E '\bvle32\.v\b' "$TMP_DIR/mixed.s" >/dev/null ||
  fail "explicit RVV load disappeared from gated function"
grep -E '\bvse32\.v\b' "$TMP_DIR/mixed.s" >/dev/null ||
  fail "explicit RVV store disappeared from gated function"

# Inline topology regression: a gated caller must still inline an ungated
# helper.  The caller remains gated after inlining, so its positive LV
# decision is blocked; the helper must not reappear as an independent symbol.
cat >"$TMP_DIR/inline.cc" <<'EOF'
static __attribute__((always_inline)) void helper(float *dst, const float *src,
                                                  int n) {
  for (int i = 0; i < n; ++i)
    dst[i] = src[i] + 1.0f;
}
extern "C" void gated_caller(float *dst, const float *src, int n) {
  helper(dst, src, n);
}
extern "C" void open_caller(float *dst, const float *src, int n) {
  helper(dst, src, n);
}
EOF
printf 'gated_caller\n' >"$TMP_DIR/inline-gate.txt"
: >"$TMP_DIR/inline-census.tsv"
CHIMERA_GATE_LIST="$TMP_DIR/inline-gate.txt" \
CHIMERA_GATE_STATS="$TMP_DIR/inline-census.tsv" \
  "$CLANG" -O2 -march=rv64gcv -fpass-plugin="$PLUGIN" \
  -S -emit-llvm "$TMP_DIR/inline.cc" -o "$TMP_DIR/inline.ll"
grep -F $'implicit-vector-census\tLV\tgated_caller\tblocked' \
  "$TMP_DIR/inline-census.tsv" >/dev/null ||
  fail "gated caller did not record the blocked LV decision after inlining"
grep -F $'implicit-vector-census\tLV\topen_caller\tformed' \
  "$TMP_DIR/inline-census.tsv" >/dev/null ||
  fail "open caller did not record the formed LV decision after inlining"
if grep -F 'define internal' "$TMP_DIR/inline.ll" | grep -F 'helper' >/dev/null; then
  fail "ungated helper was outlined instead of inlined into the gated caller"
fi

echo "VectorGate single-face census tests passed."
