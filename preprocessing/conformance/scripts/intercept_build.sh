#!/usr/bin/env bash
# ==============================================================================
# Intercept a project's build to collect LLVM bitcode for vlen-checker.
#
# Usage:
#   intercept_build.sh <project_dir> [--bc-dir <dir>] -- <build command...>
#
# Examples:
#   intercept_build.sh /path/proj -- make -j$(nproc) V=1
#   intercept_build.sh llamacpp -- cmake -B build-rvv -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \&\& cmake --build build-rvv --target ggml-cpu -j
#
# The build command runs with CC/CXX pointing at wrap_cc.sh/wrap_cxx.sh
# (cmake honors the CC/CXX env on first configure; make honors CC/CXX vars
# when passed -e or when the Makefile uses ?=/origin default — for stubborn
# Makefiles pass CC="$CC" explicitly inside the command).
#
# Output: <bc-dir>/<name>.<hash>.bc for every compiled TU + bc.list
# (tab-separated: bc path <TAB> absolute source path).
#
# Env overrides: RVV_LLVM_DIR, VLEN_TARGET_FLAGS
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P)"

PROJ=""; BC_DIR=""; CMD=()
while [ $# -gt 0 ]; do
    case "$1" in
        --bc-dir) BC_DIR="$2"; shift 2 ;;
        --) shift; CMD=("$@"); break ;;
        *) [ -z "$PROJ" ] && { PROJ="$1"; shift; } || { echo "unknown arg: $1" >&2; exit 2; } ;;
    esac
done
[ -n "$PROJ" ] && [ ${#CMD[@]} -gt 0 ] || { sed -n '2,20p' "$0"; exit 2; }
[ -d "$PROJ" ] || { echo "FAIL: no such project dir: $PROJ" >&2; exit 1; }
BC_DIR="${BC_DIR:-$PROJ/.vlen-bc}"
mkdir -p "$BC_DIR"
BC_DIR="$(cd "$BC_DIR" && pwd -P)"   # absolute: wrapper runs with cwd=$PROJ
: > "$BC_DIR/bc.list"

RVV_LLVM="${RVV_LLVM_DIR:-/home/jnkdog/hjt/rvregen/opt/llvm-rvv}"
export VLEN_BC_DIR="$BC_DIR"
export VLEN_CC="$RVV_LLVM/bin/clang"
export VLEN_CXX="$RVV_LLVM/bin/clang++"
export VLEN_TARGET_FLAGS="${VLEN_TARGET_FLAGS:---target=riscv64-linux-gnu --sysroot=/ --gcc-toolchain=/usr -march=rv64gcv1p0_zfh_zvfh_zvl256b -mabi=lp64d -D_GNU_SOURCE}"
export CC="$SCRIPT_DIR/wrap_cc.sh"
export CXX="$SCRIPT_DIR/wrap_cxx.sh"
# cmake builds often inject ccache as compiler launcher; hits would skip the
# wrapper entirely and silently starve bc collection — force passthrough.
export CCACHE_DISABLE=1

echo "== intercept build =="
echo "project: $PROJ"
echo "bc dir:  $BC_DIR"
echo "cmd:     ${CMD[*]}"
(cd "$PROJ" && "${CMD[@]}")
rc=$?

n=$(wc -l < "$BC_DIR/bc.list")
echo
echo "intercept rc=$rc, bitcode collected: $n TUs -> $BC_DIR/bc.list"
# build rc is propagated as-is: analysis works on whatever was collected
exit $rc
