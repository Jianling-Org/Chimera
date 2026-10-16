#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

LLVM="${LLVM:-/root/yangzheng/svf/toolchains/build/llvm-21.1.0}"
OPT="${OPT:-$LLVM/bin/opt}"
LLC="${LLC:-$LLVM/bin/llc}"
LLD="${LLD:-$LLVM/bin/ld.lld}"
OBJDUMP="${OBJDUMP:-$LLVM/bin/llvm-objdump}"
PYTHON="${PYTHON:-python3}"
PLUGIN="${PLUGIN:-$ROOT/build/plugins/stackobject/ChimeraStackObject.so}"
CHECKER="$ROOT/tests/tools/check_stackobj_map.py"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

TESTED_FILES=()


fail() {
  echo "ERROR: $*" >&2
  exit 1
}


mark_tested() {
  TESTED_FILES+=("$(basename "$1")")
}


assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  grep -qF "$pattern" "$file" || fail "$message"
}


assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  if grep -qF "$pattern" "$file"; then
    fail "$message"
  fi
}


assert_count() {
  local file="$1"
  local pattern="$2"
  local expected="$3"
  local message="$4"
  local count

  count="$(grep -cF "$pattern" "$file" || true)"
  if [[ "$count" -ne "$expected" ]]; then
    echo "Expected count: $expected" >&2
    echo "Actual count:   $count" >&2
    fail "$message"
  fi
}


assert_regex_count() {
  local file="$1"
  local pattern="$2"
  local expected="$3"
  local message="$4"
  local count

  count="$(grep -cE "$pattern" "$file" || true)"
  if [[ "$count" -ne "$expected" ]]; then
    echo "Expected count: $expected" >&2
    echo "Actual count:   $count" >&2
    fail "$message"
  fi
}


run_pass_impl() {
  local debug="$1"
  local input="$2"
  local passes="$3"
  local output="$4"
  local stderr_file="$5"
  local debug_args=()

  mark_tested "$input"
  if [[ "$debug" == "debug" ]]; then
    debug_args=(-chimera-stackobject-debug)
  fi

  "$OPT" \
    -load-pass-plugin="$PLUGIN" \
    "${debug_args[@]}" \
    -passes="$passes" \
    -S \
    "$input" \
    -o "$output" \
    2>"$stderr_file"
}


run_pass() {
  run_pass_impl debug "$@"
}


run_pass_quiet() {
  run_pass_impl quiet "$@"
}


run_pass_expect_failure() {
  local input="$1"
  local stderr_file="$2"

  mark_tested "$input"
  if "$OPT" \
      -load-pass-plugin="$PLUGIN" \
      -passes='function(chimera-stack-object)' \
      -disable-output \
      "$input" \
      2>"$stderr_file"; then
    fail "$(basename "$input"): expected pass failure"
  fi
}


for tool in "$OPT" "$LLC" "$LLD" "$OBJDUMP"; do
  [[ -x "$tool" ]] || fail "required LLVM tool not found: $tool"
done
[[ -f "$PLUGIN" ]] || fail "plugin not found: $PLUGIN"
[[ -f "$CHECKER" ]] || fail "ELF checker not found: $CHECKER"
command -v "$PYTHON" >/dev/null || fail "Python not found: $PYTHON"

echo "LLVM:   $LLVM"
echo "Plugin: $PLUGIN"


# Running the pass opts the function into backend StackObject handling even
# when no supported intrinsic or inline-asm access exists in IR. Backend spills
# may be introduced after this pass.
run_pass_quiet \
  "$SCRIPT_DIR/attribute-only.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/attribute-only.ll" \
  "$TMP_DIR/attribute-only.err"
assert_contains \
  "$TMP_DIR/attribute-only.ll" \
  '"chimera-stack-object"' \
  'attribute-only.ll: pass must add the backend opt-in function attribute'
assert_not_contains \
  "$TMP_DIR/attribute-only.ll" \
  '.chimera.stackobj_map' \
  'attribute-only.ll: attribute alone must not create an IR map record'


# The pass sees only non-stack RVV accesses here, so it creates no IR record.
# Its function attribute must nevertheless opt in spills introduced by llc.
run_pass_quiet \
  "$SCRIPT_DIR/backend-spill.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/backend-spill.ll" \
  "$TMP_DIR/backend-spill.err"
assert_contains \
  "$TMP_DIR/backend-spill.ll" \
  '"chimera-stack-object"' \
  'backend-spill.ll: pass must preserve backend opt-in without an IR map'
assert_not_contains \
  "$TMP_DIR/backend-spill.ll" \
  '.chimera.stackobj_map' \
  'backend-spill.ll: non-stack IR accesses must not create IR map records'
"$LLC" \
  -mtriple=riscv64-unknown-linux-gnu \
  -mattr=+v \
  -filetype=asm \
  "$TMP_DIR/backend-spill.ll" \
  -o "$TMP_DIR/backend-spill.s"
assert_contains \
  "$TMP_DIR/backend-spill.s" \
  '.chimera.stackobj_map' \
  'backend-spill.ll: attributed backend spill must create the Chimera map'
assert_contains \
  "$TMP_DIR/backend-spill.s" \
  '.Lpcsection' \
  'backend-spill.ll: attributed backend spill must create PCSections labels'


# Successful analysis is silent unless the hidden debug option is explicit.
run_pass_quiet \
  "$SCRIPT_DIR/exact-stack.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/exact-quiet.ll" \
  "$TMP_DIR/exact-quiet.err"
assert_not_contains \
  "$TMP_DIR/exact-quiet.err" \
  '[Chimera StackObject]' \
  'exact-stack.ll: successful analysis must be silent by default'
assert_contains \
  "$TMP_DIR/exact-quiet.ll" \
  '.chimera.stackobj_map!A' \
  'exact-stack.ll: quiet mode must still emit metadata'


# ExactStack: offset 32, SOID 0, one absolute PCSections entry.
run_pass \
  "$SCRIPT_DIR/exact-stack.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/exact.ll" \
  "$TMP_DIR/exact.err"
assert_contains "$TMP_DIR/exact.err" 'offset: 32' \
  'exact-stack.ll: expected stack offset 32'
assert_contains "$TMP_DIR/exact.err" 'SOID: 0' \
  'exact-stack.ll: expected SOID 0'
assert_count "$TMP_DIR/exact.ll" '!".chimera.stackobj_map!A"' 1 \
  'exact-stack.ll: expected one Chimera PCSections entry'


# Same (alloca, offset) reuses its SOID; a different offset gets a new SOID.
run_pass \
  "$SCRIPT_DIR/same-object.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/same-object.ll" \
  "$TMP_DIR/same-object.err"
assert_count "$TMP_DIR/same-object.err" 'SOID: 0' 2 \
  'same-object.ll: expected SOID 0 twice'
assert_count "$TMP_DIR/same-object.err" 'SOID: 1' 1 \
  'same-object.ll: expected SOID 1 once'
assert_count "$TMP_DIR/same-object.err" 'offset: 32' 2 \
  'same-object.ll: expected offset 32 twice'
assert_count "$TMP_DIR/same-object.err" 'offset: 64' 1 \
  'same-object.ll: expected offset 64 once'
assert_count "$TMP_DIR/same-object.ll" \
  'distinct !{!".chimera.stackobj_map!A"' 3 \
  'same-object.ll: each instruction needs distinct top-level metadata'


# The other three StackAddrKind outcomes.
run_pass \
  "$SCRIPT_DIR/nonlocal.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/nonlocal.ll" \
  "$TMP_DIR/nonlocal.err"
assert_not_contains "$TMP_DIR/nonlocal.err" 'warning: [Chimera StackObject]' \
  'nonlocal.ll: proven non-local addresses must not warn'
assert_not_contains "$TMP_DIR/nonlocal.ll" '.chimera.stackobj_map' \
  'nonlocal.ll: proven non-local addresses must not receive metadata'

run_pass \
  "$SCRIPT_DIR/multiple-locations.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/multiple.ll" \
  "$TMP_DIR/multiple.err"
assert_not_contains "$TMP_DIR/multiple.err" 'warning: [Chimera StackObject]' \
  'multiple-locations.ll: multiple locations must be silently ignored'
assert_not_contains "$TMP_DIR/multiple.ll" '.chimera.stackobj_map' \
  'multiple-locations.ll: multiple locations must not receive metadata'

run_pass \
  "$SCRIPT_DIR/unknown-provenance.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/unknown.ll" \
  "$TMP_DIR/unknown.err"
assert_contains "$TMP_DIR/unknown.err" 'warning: [Chimera StackObject]' \
  'unknown-provenance.ll: warning must remain unconditional'
assert_contains "$TMP_DIR/unknown.err" \
  'cannot determine whether RVV address belongs' \
  'unknown-provenance.ll: expected provenance warning'
assert_not_contains "$TMP_DIR/unknown.ll" '.chimera.stackobj_map' \
  'unknown-provenance.ll: unresolved provenance must not receive metadata'


# Preserve the previously hand-verified optimized multiple-location case.
run_pass \
  "$SCRIPT_DIR/optimized-multiple.ll" \
  'default<O2>,function(chimera-stack-object)' \
  "$TMP_DIR/optimized.ll" \
  "$TMP_DIR/optimized.err"
assert_not_contains "$TMP_DIR/optimized.err" 'warning: [Chimera StackObject]' \
  'optimized-multiple.ll: multiple locations must not warn'
assert_not_contains "$TMP_DIR/optimized.ll" '.chimera.stackobj_map' \
  'optimized-multiple.ll: multiple locations must not receive metadata'
assert_regex_count "$TMP_DIR/optimized.ll" \
  'call .*@llvm\.riscv\.vle' 1 \
  'optimized-multiple.ll: O2 must leave one merged RVV load'


# Inline asm target locator index 0 and index >0.
run_pass \
  "$SCRIPT_DIR/inline-direct.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-direct.ll" \
  "$TMP_DIR/inline-direct.err"
assert_contains "$TMP_DIR/inline-direct.err" 'target-index: 0' \
  'inline-direct.ll: expected target locator 0'
assert_contains "$TMP_DIR/inline-direct.err" 'offset: 32' \
  'inline-direct.ll: expected offset 32'
assert_contains "$TMP_DIR/inline-direct.ll" '.chimera.stackobj_map!AL' \
  'inline-direct.ll: expected deferred inline PCSections metadata'
assert_contains "$TMP_DIR/inline-direct.ll" '!{i32 0, i32 0}' \
  'inline-direct.ll: expected locator 0 and SOID 0'

run_pass \
  "$SCRIPT_DIR/inline-address-calc.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-address.ll" \
  "$TMP_DIR/inline-address.err"
assert_contains "$TMP_DIR/inline-address.err" 'target-index: 2' \
  'inline-address-calc.ll: expected target locator 2'
assert_contains "$TMP_DIR/inline-address.err" 'offset: 32' \
  'inline-address-calc.ll: expected folded offset 32'
assert_contains "$TMP_DIR/inline-address.ll" '!{i32 2, i32 0}' \
  'inline-address-calc.ll: expected locator 2 and SOID 0'

run_pass \
  "$SCRIPT_DIR/inline-pcsections.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-pcsections.ll" \
  "$TMP_DIR/inline-pcsections.err"
assert_count "$TMP_DIR/inline-pcsections.ll" \
  '.chimera.stackobj_map!AL' 2 \
  'inline-pcsections.ll: expected two deferred entries'
assert_contains "$TMP_DIR/inline-pcsections.ll" '!{i32 0, i32 0}' \
  'inline-pcsections.ll: expected direct locator'
assert_contains "$TMP_DIR/inline-pcsections.ll" '!{i32 2, i32 0}' \
  'inline-pcsections.ll: expected calculated-address locator'


# Intrinsic and inline asm share the function-local (alloca, offset) registry.
run_pass \
  "$SCRIPT_DIR/inline-shared-object.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-shared.ll" \
  "$TMP_DIR/inline-shared.err"
assert_count "$TMP_DIR/inline-shared.err" 'SOID: 0' 2 \
  'inline-shared-object.ll: both paths must reuse SOID 0'
assert_count "$TMP_DIR/inline-shared.ll" '!".chimera.stackobj_map!A"' 1 \
  'inline-shared-object.ll: expected one intrinsic entry'
assert_count "$TMP_DIR/inline-shared.ll" '.chimera.stackobj_map!AL' 1 \
  'inline-shared-object.ll: expected one inline entry'


# Irrelevant asm is ignored; multiple targets and whole-block whitelist
# violations warn and receive no carrier metadata.
run_pass \
  "$SCRIPT_DIR/inline-no-target.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-no-target.ll" \
  "$TMP_DIR/inline-no-target.err"
assert_not_contains "$TMP_DIR/inline-no-target.err" \
  'warning: [Chimera StackObject]' \
  'inline-no-target.ll: irrelevant inline asm must not warn'
assert_not_contains "$TMP_DIR/inline-no-target.ll" '.chimera.stackobj_map' \
  'inline-no-target.ll: irrelevant inline asm must not receive metadata'

run_pass \
  "$SCRIPT_DIR/inline-multiple-target.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-multiple.ll" \
  "$TMP_DIR/inline-multiple.err"
assert_contains "$TMP_DIR/inline-multiple.err" \
  'inline asm contains multiple RVV memory instructions' \
  'inline-multiple-target.ll: expected multiple-target warning'
assert_not_contains "$TMP_DIR/inline-multiple.ll" '.chimera.stackobj_map' \
  'inline-multiple-target.ll: unsupported asm must not receive metadata'

run_pass \
  "$SCRIPT_DIR/inline-unsupported-after-target.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/inline-after-target.ll" \
  "$TMP_DIR/inline-after-target.err"
assert_contains "$TMP_DIR/inline-after-target.err" \
  'unsupported instruction in relevant inline asm: vadd.vv' \
  'inline-unsupported-after-target.ll: whole block must be checked'
assert_not_contains "$TMP_DIR/inline-after-target.ll" '.chimera.stackobj_map' \
  'inline-unsupported-after-target.ll: rejected asm must not receive metadata'


# Existing !pcsections data must be merged, not overwritten.
run_pass \
  "$SCRIPT_DIR/pcsections-merge.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/pcsections-merge.ll" \
  "$TMP_DIR/pcsections-merge.err"
assert_count "$TMP_DIR/pcsections-merge.ll" '.other_map' 1 \
  'pcsections-merge.ll: existing section must remain'
assert_count "$TMP_DIR/pcsections-merge.ll" '!".chimera.stackobj_map!A"' 1 \
  'pcsections-merge.ll: Chimera section must be appended once'
assert_contains "$TMP_DIR/pcsections-merge.ll" 'distinct !{!".other_map"' \
  'pcsections-merge.ll: merged top-level metadata must be distinct'


# Chimera-specific wire format is RV64-only.
run_pass_expect_failure \
  "$SCRIPT_DIR/rv32-unsupported.ll" \
  "$TMP_DIR/rv32.err"
assert_contains "$TMP_DIR/rv32.err" \
  'requires a riscv64 target with 64-bit pointers' \
  'rv32-unsupported.ll: expected explicit RV64 diagnostic'

run_pass_expect_failure \
  "$SCRIPT_DIR/riscv64-pointer32-unsupported.ll" \
  "$TMP_DIR/riscv64-pointer32.err"
assert_contains "$TMP_DIR/riscv64-pointer32.err" \
  'requires a riscv64 target with 64-bit pointers' \
  'riscv64-pointer32-unsupported.ll: expected pointer-width diagnostic'


# Final linked ELF: derive the expected instruction VAs outside the checker,
# then validate unordered 12-byte records and absence of map relocations.
run_pass \
  "$SCRIPT_DIR/elf-multi-record.ll" \
  'function(chimera-stack-object)' \
  "$TMP_DIR/elf-multi-record.ll" \
  "$TMP_DIR/elf-multi-record.err"
"$LLC" \
  -mtriple=riscv64-unknown-linux-gnu \
  -mattr=+v \
  -filetype=obj \
  "$TMP_DIR/elf-multi-record.ll" \
  -o "$TMP_DIR/elf-multi-record.o"
"$LLD" \
  --entry=test_a \
  -o "$TMP_DIR/elf-multi-record.elf" \
  "$TMP_DIR/elf-multi-record.o"
"$OBJDUMP" \
  -d \
  --no-show-raw-insn \
  "$TMP_DIR/elf-multi-record.elf" \
  >"$TMP_DIR/elf-multi-record.dis"
awk \
  '/[[:space:]]vle8\.v[[:space:]]/ { sub(/:$/, "", $1); print "0x" $1 ":0" }' \
  "$TMP_DIR/elf-multi-record.dis" \
  >"$TMP_DIR/expected-records"
assert_count "$TMP_DIR/expected-records" ':0' 3 \
  'elf-multi-record.ll: expected three final RVV instruction VAs'

CHECKER_ARGS=(
  "$CHECKER"
  "$TMP_DIR/elf-multi-record.elf"
  --require-no-relocations
)
while IFS= read -r record; do
  CHECKER_ARGS+=(--expect-record "$record")
done <"$TMP_DIR/expected-records"
"$PYTHON" "${CHECKER_ARGS[@]}"


# Regression for the shared-MDNode wire-format bug (LLVM patch 0008):
# three stores reference ONE distinct !pcsections node, and each store
# expands into an li/sw MI pair. Upstream emission would group the six
# PCs ahead of a single aux (6*8+4 = 52 bytes, not a multiple of 12);
# with 0008 every MI emits its own 12-byte record (72 bytes).
# shared-node.ll is hand-annotated and deliberately skips the plugin.
mark_tested "$SCRIPT_DIR/shared-node.ll"
"$LLC" \
  -mtriple=riscv64-unknown-linux-gnu \
  -filetype=obj \
  "$SCRIPT_DIR/shared-node.ll" \
  -o "$TMP_DIR/shared-node.o"
"$LLD" \
  --entry=shared_node \
  -o "$TMP_DIR/shared-node.elf" \
  "$TMP_DIR/shared-node.o"
"$PYTHON" \
  "$CHECKER" \
  "$TMP_DIR/shared-node.elf" \
  --require-no-relocations


# Inventory guard: no .ll file may sit in this directory without execution.
for test_file in "$SCRIPT_DIR"/*.ll; do
  test_name="$(basename "$test_file")"
  found=false
  for tested_name in "${TESTED_FILES[@]}"; do
    if [[ "$tested_name" == "$test_name" ]]; then
      found=true
      break
    fi
  done
  [[ "$found" == true ]] || fail "$test_name exists but is not executed"
done

echo 'StackObject tests passed.'
