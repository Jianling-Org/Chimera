#!/usr/bin/env bash
# ==============================================================================
# vlen-escape build script (self-contained; does NOT wipe the build dir).
#
#   ./build.sh            # incremental configure+build
#
# Toolchains (env overrides): LLVM21_DIR, Z3_DIR
#   LLVM21_DIR  LLVM 21 install root (default /home/jnkdog/hjt/llamatest/llvm-21.1.0.obj)
#   Z3_DIR      Z3 install root      (default /home/jnkdog/hjt/llamatest/z3.obj)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P)"
LLVM21="${LLVM21_DIR:-/home/jnkdog/hjt/llamatest/llvm-21.1.0.obj}"
Z3="${Z3_DIR:-/home/jnkdog/hjt/llamatest/z3.obj}"

if [ ! -f "$SCRIPT_DIR/build/CMakeCache.txt" ]; then
    cmake -S "$SCRIPT_DIR" -B "$SCRIPT_DIR/build" -DLLVM_DIR="$LLVM21" -DZ3_DIR="$Z3"
fi
cmake --build "$SCRIPT_DIR/build" -j"$(nproc)"

echo "built: $SCRIPT_DIR/build/bin/svf-vlenesc"
