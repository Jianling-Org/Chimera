#!/usr/bin/env bash
# ==============================================================================
# vlen-escape stage 2: static escape analysis over collected bitcode.
#
# Usage:
#   analyze.sh <bc.list> [-o <out_dir>]
#
# Per bc: vscale cleanup -> svf-vlenesc (Andersen + taint). Escape criteria
# (conservative): RETURN (value returned) | HEAP (stored to heap) |
# GLOBAL (stored to data segment). Each escape site -> one JSONL record.
#
# Output: <out_dir>/escapes.jsonl + <out_dir>/vlen/<module>.vlen.json
#
# Env overrides: RVV_LLVM_DIR, LLVM21_DIR, Z3_DIR, SVF_VLENESC
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P)"
PROJ_ROOT="$(dirname "$SCRIPT_DIR")"

LIST=""; OUT="$PROJ_ROOT/out"
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT="$2"; shift 2 ;;
        *) [ -z "$LIST" ] && { LIST="$1"; shift; } || { echo "unknown arg: $1" >&2; exit 2; } ;;
    esac
done
[ -n "$LIST" ] && [ -f "$LIST" ] || { echo "usage: analyze.sh <bc.list> [-o out_dir]" >&2; exit 2; }
mkdir -p "$OUT/vlen" "$OUT/logs" "$OUT/bc"
OUT="$(cd "$OUT" && pwd -P)"
LIST="$(cd "$(dirname "$LIST")" && pwd -P)/$(basename "$LIST")"
rm -f "$OUT/vlen"/*.vlen.json "$OUT/bc"/*.clean.bc

RVV_LLVM="${RVV_LLVM_DIR:-/home/jnkdog/hjt/rvregen/opt/llvm-rvv}"
LLVM21="${LLVM21_DIR:-/home/jnkdog/hjt/llamatest/llvm-21.1.0.obj}"
Z3="${Z3_DIR:-/home/jnkdog/hjt/llamatest/z3.obj}"
# svf-vlenesc: built by this project itself (vlen-escape/build.sh); override via env
VLENESC="${SVF_VLENESC:-$PROJ_ROOT/build/bin/svf-vlenesc}"
export PATH="$LLVM21/bin:$Z3/bin:$PATH"
export LD_LIBRARY_PATH="$LLVM21/lib:$Z3/bin:${LD_LIBRARY_PATH:-}"
[ -x "$VLENESC" ] || { echo "FAIL: svf-vlenesc not found ($VLENESC); build svfanalysis first or set SVF_VLENESC" >&2; exit 1; }

SCRATCH="$(mktemp -d)"; trap 'rm -rf "$SCRATCH"' EXIT

n=0; fail=0
while IFS=$'\t' read -r bc src; do
    [ -f "$bc" ] || { echo "  skip (missing): $bc"; fail=$((fail+1)); continue; }
    id="$(basename "$bc" .bc)"
    ll="$SCRATCH/$id.ll"; clean="$OUT/bc/$id.clean.bc"
    if ! "$RVV_LLVM/bin/llvm-dis" "$bc" -o "$ll" 2>"$OUT/logs/$id.log" || \
       ! python3 "$SCRIPT_DIR/clean_rvv_ir.py" "$ll" >>"$OUT/logs/$id.log" 2>&1 || \
       ! "$RVV_LLVM/bin/llvm-as" "$ll" -o "$clean" 2>>"$OUT/logs/$id.log"; then
        echo "  clean FAIL: $id (see $OUT/logs/$id.log)"; fail=$((fail+1)); continue
    fi
    if (cd "$SCRATCH" && timeout 3600 "$VLENESC" -output-json="$OUT/vlen/$id.vlen.json" "$clean" \
            >>"$OUT/logs/$id.vlen.log" 2>&1); then
        n=$((n+1)); echo "  analyzed: $id"
    else
        echo "  analysis FAIL: $id (see $OUT/logs/$id.vlen.log)"; fail=$((fail+1))
    fi
done < "$LIST"

python3 - "$OUT" <<'PYEOF'
import json, glob, sys
out = sys.argv[1]
records = []
for p in sorted(glob.glob(f"{out}/vlen/*.vlen.json")):
    d = json.load(open(p))
    for f in d["functions"]:
        for e in f["escapes"]:
            if e["kind"] in ("RETURN", "HEAP", "GLOBAL"):
                records.append({
                    "module": d.get("module", p), "function": f["name"],
                    "file": e["file"], "line": e["line"], "column": e["column"],
                    "kind": e["kind"], "target": e["target"],
                    "derived": e["derived"], "confidence": e["confidence"],
                })
with open(f"{out}/escapes.jsonl", "w") as fp:
    for r in records:
        fp.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"escapes.jsonl: {len(records)} escape records")
PYEOF

echo
echo "modules analyzed: $n, failed: $fail"
[ $fail -gt 0 ] && exit 1
exit 0
