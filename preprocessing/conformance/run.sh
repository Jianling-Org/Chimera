#!/usr/bin/env bash
# ==============================================================================
# vlen-escape: one-click RVV vlen escape detection.
#
#   Detect whether a project built with the given options reads the RISC-V
#   vector length (vlenb/vsetvl) and lets the value escape a function:
#   returned (RETURN), stored to heap (HEAP), or stored to data-segment
#   globals (GLOBAL). One record per possible escape site.
#
# Usage:
#   run.sh <project_dir> [-o <out_dir>] [--skip-build] [--report-only] \
#          -- <build command...>
#
# Examples:
#   run.sh examples/hello_make -- make -B
#   run.sh /path/to/proj -- make -j$(nproc)
#   run.sh llamacpp -- bash -c 'cmake -B b -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
#          -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY ... && cmake --build b'
#
# Env overrides: RVV_LLVM_DIR, LLVM21_DIR, Z3_DIR, SVF_VLENESC
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P)"

PROJ=""; OUT="$SCRIPT_DIR/out"; SKIP_BUILD=0; REPORT_ONLY=0; CMD=()
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --report-only) REPORT_ONLY=1; SKIP_BUILD=1; shift ;;
        --) shift; CMD=("$@"); break ;;
        *) [ -z "$PROJ" ] && { PROJ="$1"; shift; } || { echo "unknown arg: $1" >&2; exit 2; } ;;
    esac
done
[ -n "$PROJ" ] || { sed -n '5,18p' "$0"; exit 2; }
PROJ="$(cd "$PROJ" && pwd -P)"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd -P)"

say() { echo; echo "=== $* ==="; }

if [ $REPORT_ONLY -eq 0 ]; then
    if [ $SKIP_BUILD -eq 0 ]; then
        [ ${#CMD[@]} -gt 0 ] || { echo "FAIL: need -- <build command> (or --skip-build)"; exit 2; }
        say "1/3 intercept build"
        bash "$SCRIPT_DIR/scripts/intercept_build.sh" "$PROJ" -- "${CMD[@]}"
        build_rc=$?
    else
        build_rc=0
        say "1/3 intercept build (skipped)"
    fi
    LIST="$PROJ/.vlen-bc/bc.list"
    [ -s "$LIST" ] || { echo "FAIL: no bitcode collected ($LIST)"; exit 1; }
    echo "bitcode TUs: $(wc -l < "$LIST") (build rc=$build_rc)"

    say "2/3 static escape analysis"
    bash "$SCRIPT_DIR/scripts/analyze.sh" "$LIST" -o "$OUT"
    analysis_rc=$?
    [ $analysis_rc -ne 0 ] && echo "WARNING: $analysis_rc 个模块分析失败（见 out/logs/），报告基于成功模块"
else
    build_rc=0
fi

say "3/3 report"
python3 - "$OUT" "$PROJ" "${build_rc:-0}" "${analysis_rc:-0}" <<'PYEOF'
import json, sys, datetime
out, proj, build_rc, analysis_rc = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
esc = [json.loads(l) for l in open(f"{out}/escapes.jsonl") if l.strip()]
lines = []
lines.append("# RVV vlen 逃逸检测报告\n")
lines.append(f"- 项目: `{proj}`")
lines.append(f"- 时间: {datetime.datetime.now().isoformat(timespec='seconds')}")
lines.append(f"- 构建返回码: {build_rc}（非 0 表示部分 TU 编译失败，分析覆盖已收集 bitcode）")
if analysis_rc != "0":
    lines.append(f"- **注意**: 分析返回码 {analysis_rc}（个别模块失败，结果基于成功模块；日志见 out/logs/）")
lines.append(f"- 逃逸候选（RETURN/HEAP/GLOBAL，保守口径）: {len(esc)} 条\n")
if not esc:
    lines.append("**未发现 vlen 逃逸。**\n")
else:
    lines.append("| # | 函数 | 位置 | 类别 | 目标 | derived | 置信度 |")
    lines.append("|---|---|---|---|---|---|---|")
    for i, r in enumerate(esc, 1):
        lines.append(f"| {i} | `{r['function']}` | {r['file']}:{r['line']} | {r['kind']} | "
                     f"`{r['target']}` | {r['derived']} | {r['confidence']} |")
    lines.append("")
with open(f"{out}/report.md", "w") as fp:
    fp.write("\n".join(lines))
print(f"report: {out}/report.md ({len(esc)} candidates)")
PYEOF

echo
echo "DONE. outputs in $OUT (escapes.jsonl / report.md)"
exit ${analysis_rc:-0}
