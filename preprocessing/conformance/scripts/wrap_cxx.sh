#!/usr/bin/env bash
# ==============================================================================
# Compiler wrapper for vlen-checker build interception.
# Acts as CC/CXX: performs the real compile AND emits an LLVM bitcode copy.
#
# Env:
#   VLEN_CC / VLEN_CXX   real compiler to invoke (per language)
#   VLEN_TARGET_FLAGS    extra flags appended to every compile (target/march)
#   VLEN_BC_DIR          directory receiving <hash>.bc + bc.list (required)
# ==============================================================================
set -u

VLEN_BC_DIR="${VLEN_BC_DIR:?VLEN_BC_DIR not set}"
self="$(basename "$0")"
case "$self" in
    *cxx*|*c++*|*++) REAL="${VLEN_CXX:?VLEN_CXX not set}" ;;
    *)               REAL="${VLEN_CC:?VLEN_CC not set}" ;;
esac

# find "-c <src> ... -o <out>" shape; otherwise (link etc.) just pass through
src=""; out=""; is_compile=0
prev=""
for a in "$@"; do
    [ "$prev" = "-o" ] && out="$a"
    if [ "$prev" = "-c" ]; then
        case "$a" in *.c|*.cc|*.cpp|*.cxx|*.C) src="$a"; is_compile=1 ;; esac
    fi
    prev="$a"
done

if [ "$is_compile" = 1 ] && [ -n "$src" ]; then
    # bitcode copy for analysis FIRST (best effort; -emit-llvm does not run
    # the assembler, so it survives asm-syntax incompatibilities that break
    # the real object compile below). Reuses the project's own flags ("$@"),
    # only swapping -o to the bc path, so the bc matches the real build.
    abs="$(readlink -f "$src")"
    hash="$(printf '%s' "$abs" | md5sum | cut -c1-12)"
    base="$(basename "$src")"
    bc="$VLEN_BC_DIR/${base%.${src##*.}}.$hash.bc"
    bcargs=(); prev=""
    for a in "$@"; do
        if [ "$prev" = "-o" ]; then bcargs+=("$bc"); prev=""; continue; fi
        bcargs+=("$a"); prev="$a"
    done
    if "$REAL" $VLEN_TARGET_FLAGS -emit-llvm "${bcargs[@]}" -g 2>>"$VLEN_BC_DIR/wrap.log"; then
        flock "$VLEN_BC_DIR/bc.list" -c "printf '%s\t%s\n' '$bc' '$abs' >> '$VLEN_BC_DIR/bc.list'" 2>/dev/null \
            || printf '%s\t%s\n' "$bc" "$abs" >> "$VLEN_BC_DIR/bc.list"
    else
        echo "wrap_cc: bc emit failed for $src" >> "$VLEN_BC_DIR/wrap.log"
    fi
    # real object (project build result propagates truthfully)
    "$REAL" $VLEN_TARGET_FLAGS "$@"
    exit $?
fi

# link / preprocess / other: pass through unchanged
exec "$REAL" $VLEN_TARGET_FLAGS "$@"
