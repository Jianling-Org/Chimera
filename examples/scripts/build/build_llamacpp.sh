#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 统一构建脚本（按 ELF 原子化相位版）。
#
#   启动 bootstrap 会幂等补齐项目子模块、patched LLVM 与插件；
#   系统包和当前仓库的 Chimera CLI 仍须预先安装：
#     * vanilla 面使用 patched LLVM；它只用于发现和交付，不进入隐式向量
#       census 的统计分母。
#     * remediated 面使用 patched LLVM + StackObject/VectorGate 插件：
#         $CHIMERA_DEV toolchain build patched-llvm   （小时级，一次）
#         $CHIMERA_DEV toolchain build llvm-plugin    （改插件后重跑）
# ============================================================
#   相位0  预检：决策 shim、patched LLVM、StackObject/VectorGate 插件产物
#   相位1  vanilla 主交付：build → check-elf
#            CHECKED     → 直接 prepare
#            PROBLEMATIC → 按需 StackObject-only，再至多一次 Gate 修复/复检
#   相位2  prepare 三个迁移场景
#
# 设计要点：
#   - 修复重编紧跟在产生该决策的 check-elf 之后，天然取到正确决策。
#     vanilla 已 CHECKED 时不额外编译；否则交付面使用 StackObject 或 Gate
#     修复后的 ELF。prepare 统一放在最后，按三种迁移场景（1024-to-256 /
#     256-to-1024 / bidirectional）各用对应 profile 对一份改名副本执行，
#     run 脚本不再自行 prepare。
#   - 决策完全由 check-elf 的发现性质驱动：
#     不可规约循环发现 → StackObject；其余发现按规模路由到 Gate 或
#     FunctionPointer/SVF。主示例只支持 Gate 路线，FP/LTO 决策明确退出。
#   - Gate 是纯编译期门控，不带 LTO，正式 gate 只允许一轮；stats 脚本
#     独占 clean-first census 和阻止率报告。
#   - 决策指纹护栏：每个修复目录记录所用决策块的哈希，失配即清目录
#     重编。根因：CMake 增量构建不感知决策变化，陈旧产物会让复检
#     失真（2026-08-27 exit-3 事故：陈旧 build-remediated 复用旧门控
#     名单的目标文件，复检数字与早前错误运行逐字节一致）。
#   - 退出码：0 全绿 / 3 修复复检未清零。
#   - 小 ELF 若路由到 SVF/function_pointer 插件由 stats/专用工具链流程处理；
#     llama.cpp 主示例不承担 FP/LTO 路线。
#
# 工具链依赖（bootstrap 会在产物缺失时按需构建）：
#   $CHIMERA_DEV toolchain build patched-llvm
#   $CHIMERA_DEV toolchain build llvm-plugin
#     （安装 ~/.chimera/bin/{clang,clang++} 决策 shims 与两个插件：
#       ChimeraStackObject / ChimeraVectorGate）
#
# 内部实现：由发布脚本或人工构建调用；Workspace 交付由 chimera-pkg workspace pack 完成。
# 环境变量：
#   CHIMERA_LLAMA_JOBS        并行度（默认 2；-j 亦可）
#   CHIMERA_TOOLCHAIN_BUILD   工具链安装根（默认 ~/.chimera/toolchain_build）
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
    LLAMA="${CHIMERA_EXAMPLE_SOURCE_DIR:-$HOME/.chimera/example-source/llama.cpp}"
else
    LLAMA="$REPO_ROOT/examples/applications/llama-cpp/llama.cpp"
fi
# Discovery and remediation use a repository-owned workflow that declares the
# Safety preflight explicitly.  The application Profile is selected by the
# build script and is never inherited from an implicit system configuration.
SAFETY_PROFILE="${CHIMERA_SAFETY_PROFILE:-$REPO_ROOT/examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml}"

# ``make wheel`` enters this script in one of two release component modes.
# Those modes stop immediately after the relevant compile/check/remediation
# phase; the normal example invocation continues through prepare and runtime
# rebuilds below.
RELEASE_COMPONENT="${CHIMERA_RELEASE_COMPONENT:-}"
RELEASE_OUTPUT="${CHIMERA_RELEASE_OUTPUT:-}"
RELEASE_DIAGNOSTIC_DIR="${CHIMERA_RELEASE_DIAGNOSTIC_DIR:-}"
if [[ -n "$RELEASE_COMPONENT" && "$RELEASE_COMPONENT" != "system" &&
      "$RELEASE_COMPONENT" != "remediated" ]]; then
    echo "ERROR: unknown release component: $RELEASE_COMPONENT" >&2
    exit 2
fi
if [[ -n "$RELEASE_COMPONENT" && -z "$RELEASE_OUTPUT" ]]; then
    echo "ERROR: CHIMERA_RELEASE_OUTPUT is required for release builds" >&2
    exit 2
fi

# llama.cpp 源码 patch：编译前应用、脚本结束前还原（vanilla 4fc4ec554）。
# 顺序由 git index 链决定：q5-fix（c37488cae→c01140203）→ vlen 兼容改造
# （c01140203→9ab554bbd），后者依赖前者的结果，不可调换。
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
    LLAMA_PATCH_DIR="$REPO_ROOT/examples/applications/llama-cpp/patch"
else
    LLAMA_PATCH_DIR="$LLAMA/../patch"
fi
LLAMA_PATCHES=(
    "$LLAMA_PATCH_DIR/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch"
    "$LLAMA_PATCH_DIR/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch"
)

BUILD_VANILLA="$LLAMA/build-vanilla"
BUILD_REMEDIATED="$LLAMA/build-remediated"
ELF_VANILLA="$BUILD_VANILLA/bin/llama-perplexity"
ELF_REMEDIATED="$BUILD_REMEDIATED/bin/llama-perplexity"
DELIVERY_ELF=""

if [[ -n "$RELEASE_COMPONENT" ]]; then
    # Never reuse a developer example cache: stale CMake compiler/library
    # choices were the reason a prior release build emitted libllama.so even
    # though the script requested static libraries.  Keep release intermediates
    # in a dedicated, disposable tree and remove it only after the output is
    # copied successfully.
    RELEASE_BUILD_ROOT="${CHIMERA_RELEASE_BUILD_ROOT:-$HOME/.chimera/release-build}"
    BUILD_VANILLA="$RELEASE_BUILD_ROOT/system"
    BUILD_REMEDIATED="$RELEASE_BUILD_ROOT/remediated"
    ELF_VANILLA="$BUILD_VANILLA/bin/llama-perplexity"
    ELF_REMEDIATED="$BUILD_REMEDIATED/bin/llama-perplexity"
fi
# A release wheel's prebuilt input can pass all checks without cloning
# llama.cpp.  Keep its temporary CMake trees outside the would-be source
# checkout so a successful run never creates a fake non-Git source directory.
PACKAGED_INPUT_BUILD_ROOT=""
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" &&
      -n "${CHIMERA_EXAMPLE_INPUT:-}" && -z "$RELEASE_COMPONENT" ]]; then
    PACKAGED_INPUT_BUILD_ROOT="${CHIMERA_EXAMPLE_BUILD_ROOT:-$HOME/.chimera/example-build/llamacpp}"
    export CHIMERA_EXAMPLE_STATE_PATH="$PACKAGED_INPUT_BUILD_ROOT/.chimera-example-state.json"
    mkdir -p -- "$PACKAGED_INPUT_BUILD_ROOT"
    BUILD_VANILLA="$PACKAGED_INPUT_BUILD_ROOT/vanilla"
    BUILD_REMEDIATED="$PACKAGED_INPUT_BUILD_ROOT/remediated"
    ELF_VANILLA="$BUILD_VANILLA/bin/llama-perplexity"
    ELF_REMEDIATED="$BUILD_REMEDIATED/bin/llama-perplexity"
fi

SHIM_CC="$HOME/.chimera/bin/clang"
SHIM_CXX="$HOME/.chimera/bin/clang++"

TOOLCHAIN_ROOT="${CHIMERA_TOOLCHAIN_BUILD:-$HOME/.chimera/toolchain_build}"
PLUGIN_DIR="$TOOLCHAIN_ROOT/plugins/lib/chimera/llvm"

# 主示例只使用无 LTO 的 Gate 修复路线。
FLAGS_VANILLA="-march=rv64gcv"
SYSTEM_CC="${CHIMERA_SYSTEM_CC:-$(command -v clang || true)}"
SYSTEM_CXX="${CHIMERA_SYSTEM_CXX:-$(command -v clang++ || true)}"
_is_chimera_compiler() {
    local candidate="$1" resolved shim_cc shim_cxx patched_cc patched_cxx
    [[ -n "$candidate" ]] || return 1
    if [[ "$candidate" != */* ]]; then
        candidate="$(command -v "$candidate" 2>/dev/null || true)"
        [[ -n "$candidate" ]] || return 1
    fi
    resolved="$(readlink -e "$candidate" 2>/dev/null || true)"
    [[ -n "$resolved" ]] || resolved="$candidate"
    shim_cc="$(readlink -e "$SHIM_CC" 2>/dev/null || true)"; [[ -n "$shim_cc" ]] || shim_cc="$SHIM_CC"
    shim_cxx="$(readlink -e "$SHIM_CXX" 2>/dev/null || true)"; [[ -n "$shim_cxx" ]] || shim_cxx="$SHIM_CXX"
    patched_cc="$(readlink -e "$TOOLCHAIN_ROOT/llvm/bin/clang" 2>/dev/null || true)"; [[ -n "$patched_cc" ]] || patched_cc="$TOOLCHAIN_ROOT/llvm/bin/clang"
    patched_cxx="$(readlink -e "$TOOLCHAIN_ROOT/llvm/bin/clang++" 2>/dev/null || true)"; [[ -n "$patched_cxx" ]] || patched_cxx="$TOOLCHAIN_ROOT/llvm/bin/clang++"
    [[ "$resolved" == "$shim_cc" || "$resolved" == "$shim_cxx" ||
       "$resolved" == "$patched_cc" || "$resolved" == "$patched_cxx" ]]
}
if [[ -z "$SYSTEM_CC" || -z "$SYSTEM_CXX" ||
      "$SYSTEM_CC" == "$HOME/.chimera/bin/clang" ||
      "$SYSTEM_CXX" == "$HOME/.chimera/bin/clang++" ]] ||
   _is_chimera_compiler "$SYSTEM_CC" || _is_chimera_compiler "$SYSTEM_CXX"; then
    SYSTEM_CC=""
    SYSTEM_CXX=""
fi

CMAKE_COMMON=(
    -DBUILD_SHARED_LIBS=OFF
    -DLLAMA_BUILD_SHARED_LIBS=OFF
    -DGGML_STATIC=ON
    -DGGML_SHARED=OFF
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DLLAMA_NATIVE=OFF
    -DLLAMA_CURL=OFF
    -DLLAMA_OPENSSL=OFF
)

source "$SCRIPT_DIR/_common.sh"
ARTIFACT_DIR="$(chimera_example_artifact_root)/main"
RELEASE_PREBUILT_DIR="$(chimera_example_artifact_root)/prebuilt"
parse_llama_build_args "$@"
export CHIMERA_EXAMPLE_CLEAN_NAME=build_llamacpp
# Serialize source checkout mutation with cleanup and the stats build.
# The host-tool probe runs first so the lock helper can rely on flock; the
# descriptor is released by the EXIT trap (and by the kernel on SIGKILL).
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" || -n "$RELEASE_COMPONENT" ]]; then
    # Packaged inputs and the standalone release component build use the
    # deployed/picked clang explicitly; a distro cc/c++ pair is not required.
    export CHIMERA_SKIP_BASELINE_COMPILER=1
fi
ensure_chimera_host_tools || exit 1
chimera_example_operation_lock || exit 1
ensure_example_build_not_interrupted || exit 1
if [[ -n "${CHIMERA_EXAMPLE_INPUT:-}" || -n "$RELEASE_COMPONENT" ]]; then
    # A release wheel already supplies the toolchain and the input ELF.  Do
    # not initialize or download source checkouts until a real finding
    # proves that remediation is required.
    ensure_chimera_cli_current || exit 1
    ensure_chimera_profile || exit 1
    if [[ -n "$RELEASE_COMPONENT" ]]; then
        # Release component builds still compile from the pinned llama.cpp
        # checkout.  The component path intentionally skips the complete
        # example bootstrap, so enforce the same gitlink/clean-tree guard
        # explicitly before applying patches.  Packaged remediation uses the
        # user-owned fixed checkout instead.
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
            ensure_packaged_llama_source || exit 1
        else
            ensure_chimera_submodule \
                "examples/applications/llama-cpp/llama.cpp" \
                "CMakeLists.txt" || exit 1
        fi
    fi
    install_llamacpp_scalar || exit 1
else
    bootstrap_llamacpp_dependencies full
fi
detect_chimera_openmp

# ---------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------

# status 输出对 PROBLEMATIC/REMEDIATED 附带 hint/note 行，必须只取首个
# 状态关键字（awk '{print $2}' 会把 hint 的第二个词也吃进来）。
_status_of() { $CHIMERA_PKG status --input "$1" | grep -oE 'UNCHECKED|CHECKED|PROBLEMATIC|REMEDIATED' | head -1; }

# 从 <ELF>.check.json 读决策，单行输出：STRATEGY GATE FP STACK_OBJECT
_read_decision() {
    python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))["decision"]
print(d["strategy"],
      int(d["vector_gate"]["enabled"]),
      int(d["function_pointer_plugin"]),
      int(d["stack_object_plugin"]))
PY
}

# 决策块规范化 JSON 的 sha256，用作修复目录的指纹护栏。
_decision_fingerprint() {
    python3 - "$1" <<'PY' | sha256sum | awk '{print $1}'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))["decision"]
print(json.dumps(d, sort_keys=True, ensure_ascii=False))
PY
}

# 决策合并：新报告的 gate 名单与既有名单取并集、stack_object 取或，
# 写入修复目录之外的稳定文件，并把 latest.json 指针重定向到它。
# 稳定文件的目的只是让清理/重编期间的 shim 仍能读取同一份决策；
# 单轮 gate 失败时不会把复检显影的新名字自动并入下一轮。
# $1 新报告 check.json  $2 稳定决策文件（修复目录之外）  $3 修复产物 ELF
_merge_decision() {
    python3 - "$1" "$2" "$3" "${@:4}" <<'PY'
import json, pathlib, sys
new_path, stable_path, elf_path = sys.argv[1:4]
no_gate = "--no-gate" in sys.argv[4:]
new = (json.loads(pathlib.Path(new_path).read_text(encoding="utf-8"))
       .get("decision") or {})
stable = pathlib.Path(stable_path)
prev = {}
if stable.is_file():
    try:
        prev = json.loads(stable.read_text(encoding="utf-8")).get("decision") or {}
    except json.JSONDecodeError:
        prev = {}
merged = dict(new)
merged["gate"] = dict(new.get("gate") or {})
merged["gate"]["names"] = sorted(
    set((new.get("gate") or {}).get("names") or [])
    | set((prev.get("gate") or {}).get("names") or [])
)
if no_gate:
    # 精度阶段（stack-object 先行）：剥离 gate，只让分析进入 metadata
    # 精确模式。本阶段复检得到的 findings 才是真实的向量源集合，随后
    # 由唯一一次正式 gate 重编统一处理（自动向量化 / memop / 后端合并
    # 随盖章联动生效）。
    merged["vector_gate"] = {"enabled": False}
    merged["gate"] = {"enabled": False, "names": []}
merged["stack_object_plugin"] = bool(
    new.get("stack_object_plugin") or prev.get("stack_object_plugin")
)
stable.write_text(
    json.dumps({"decision": merged}, indent=2, ensure_ascii=False),
    encoding="utf-8",
)
# latest.json 只被 wrapper 消费（elf_path + decision_path）；重定向到
# 稳定文件，修复目录的清理不再使其悬空。
pointer = pathlib.Path.home() / ".chimera" / "check_elf" / "latest.json"
pointer.parent.mkdir(parents=True, exist_ok=True)
pointer.write_text(
    json.dumps({
        "elf_path": elf_path,
        "decision_path": str(stable.resolve()),
        "strategy": merged.get("strategy"),
        "stack_object": bool(merged.get("stack_object_plugin")),
        "exported_at": "script-merge",
        "counts": {},
    }, indent=2, ensure_ascii=False),
    encoding="utf-8",
)
PY
}

# 修复重编：指纹护栏 → shim 重编。
# $1 修复目录  $2 基线 flags（=修复 flags）  $3 决策来源（稳定决策文件）
# 复检由调用方负责（复检是权威判定，须对修复后的新 ELF 做）。
_remediate() {
    local build_dir="$1" flags="$2" decision_json="$3"
    local fp stamp="$build_dir/.chimera-decision.sha256"
    fp="$(_decision_fingerprint "$decision_json")"
    if [[ -f "$stamp" ]] && [[ "$(cat "$stamp")" == "$fp" ]]; then
        echo "决策指纹一致，增量重编：$build_dir"
    else
        if [[ -d "$build_dir" ]]; then
            echo "决策指纹失配（或首次构建），清理重编：$build_dir"
            # 注册表（链接态决策源）仍按原路径引用目录内的 check.json：
            # 先移出、清理、再放回，避免悬空引用。恢复段在 $rescue 下执行，
            # build_dir 必须先 canonical 成绝对路径。
            local rescue
            rescue="$(mktemp -d)"
            build_dir="$(cd "$build_dir" && pwd)"
            ( cd "$build_dir" && find . -name '*.check.json' -type f \
                -exec cp --parents {} "$rescue"/ \; )
            rm -rf "$build_dir"
            if [[ -n "$(ls -A "$rescue" 2>/dev/null)" ]]; then
                # cp --parents 要求目标目录已存在（rm -rf 后已消失）
                mkdir -p "$build_dir"
                ( cd "$rescue" && find . -type f \
                    -exec cp --parents {} "$build_dir"/ \; )
            fi
            rm -rf "$rescue"
        fi
    fi
    cmake -S "$LLAMA" -B "$build_dir" \
        -DCMAKE_C_COMPILER="$SHIM_CC" \
        -DCMAKE_CXX_COMPILER="$SHIM_CXX" \
        -DCMAKE_C_FLAGS="$flags" \
        -DCMAKE_CXX_FLAGS="$flags" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        "${CMAKE_COMMON[@]}" \
        "${CHIMERA_OPENMP_CMAKE_ARGS[@]}"
    verify_chimera_openmp_build "$build_dir"
    cmake --build "$build_dir" -j"$JOBS" "${BUILD_TARGETS[@]}"
    printf '%s\n' "$fp" > "$stamp"
}

# 修复闭环（StackObject → 单轮 Gate）：
#   种子报告含不可规约/保守降级时，先执行一次 --no-gate 的
#   StackObject 精度阶段；该阶段复检若 CHECKED 即直接交付。
#   否则使用新报告执行至多一次 Gate 修复和复检。Gate 复检若仍有
#   actionable finding，立即退出并保留报告，禁止自动开启第二轮。
# $1 修复目录  $2 基线 flags（不含 LTO）  $3 修复后 ELF  $4 相位标签  $5 种子决策 check.json
_report_has_function_pointer() {
    python3 - "$1" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1], encoding="utf-8")).get("decision") or {}
sys.exit(0 if decision.get("function_pointer_plugin") else 1)
PY
}

_report_has_gate() {
    python3 - "$1" <<'PY'
import json, sys
decision = json.load(open(sys.argv[1], encoding="utf-8")).get("decision") or {}
gate = decision.get("gate") or {}
sys.exit(0 if (decision.get("vector_gate") or {}).get("enabled") or gate.get("enabled") else 1)
PY
}

_reject_function_pointer_route() {
    local report="$1" phase="$2"
    if _report_has_function_pointer "$report"; then
        echo "ERROR: [$phase] decision 要求 FunctionPointer/SVF；主 llama.cpp 构建不支持 FP/LTO 路线。" >&2
        python3 - "$report" <<'PY' >&2
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
decision = document.get("decision") or {}
print(f"       decision={decision.get('strategy')} reason={document.get('strategy_reason', '')}")
print(f"       decision path: {sys.argv[1]}")
print("       请使用 build_llamacpp_stats 或手动准备 SVF/FunctionPointer 工具链。")
PY
        return 2
    fi
    return 0
}

_remediate_loop() {
    local build_dir="$1" base_flags="$2" elf="$3" phase="$4" seed_report="$5"
    local stable="$build_dir.decision.json"
    local report="$seed_report"

    _reject_function_pointer_route "$report" "$phase" || return $?

    # 精度阶段判定：种子报告存在不可规约/保守降级时，先走一次
    # StackObject（剥离 Gate），用精确分析重新产出门控目标。
    if python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
s = document.get("summary") or {}
d = document.get("decision") or {}
sys.exit(0 if (d.get("stack_object_plugin") or int(s.get("irreducible", 0)) or int(s.get("conservative", 0))) else 1)
' "$seed_report"; then
        echo "[$phase] 精度阶段：只应用 StackObject，随后生成单轮 Gate 清单"
        _merge_decision "$report" "$stable" "$elf" --no-gate
        _remediate "$build_dir" "$base_flags" "$stable"
            $CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$elf"
        local precision_status
        precision_status="$(_status_of "$elf")"
        if [[ "$precision_status" == "CHECKED" ]]; then
            echo "[$phase] StackObject 复检 -> CHECKED（无需 Gate）"
            DELIVERY_ELF="$elf"
            return 0
        fi
        if [[ "$precision_status" != "PROBLEMATIC" ]]; then
            echo "ERROR: [$phase] 精度阶段出现意外状态：$precision_status" >&2
            return 1
        fi
        report="$elf.check.json"
    fi

    _reject_function_pointer_route "$report" "$phase" || return $?
    if ! _report_has_gate "$report"; then
        echo "ERROR: [$phase] 修复决策仍有 actionable findings，但 decision 未提供 Gate 路线；报告保留于 $report" >&2
        return 3
    fi

    # 合并必须先于 _remediate：wrapper 编译态（含 CMake TryCompile）从
    # latest.json 取决策，而清理会删除目录内的新鲜 check.json。
    _merge_decision "$report" "$stable" "$elf"

    # 主示例只支持 Gate 路线；Gate 是编译期门控，不追加 LTO。
    local flags="$base_flags" fp gate_count
    fp="$(_decision_fingerprint "$stable")"
    gate_count="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["decision"]
print(len((d.get("gate") or {}).get("names") or []))' "$stable")"
    echo "[$phase] 单轮 Gate 修复（决策指纹 ${fp:0:12}…，累计门控 $gate_count 函数，flags='$flags'）"
    _remediate "$build_dir" "$flags" "$stable"

    $CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$elf"
    local status
    status="$(_status_of "$elf")"
    if [[ "$status" == "CHECKED" ]]; then
        echo "[$phase] Gate 复检 -> CHECKED"
        DELIVERY_ELF="$elf"
        return 0
    fi
    if [[ "$status" != "PROBLEMATIC" ]]; then
        echo "ERROR: [$phase] 单轮修复后出现意外状态：$status" >&2
        return 1
    fi

    python3 - "$stable" "$elf.check.json" <<'PY' >&2
import json, sys
applied = json.load(open(sys.argv[1], encoding="utf-8"))["decision"]
report = json.load(open(sys.argv[2], encoding="utf-8"))
applied_names = set((applied.get("gate") or {}).get("names") or [])
suggested_names = set(report.get("gate_names") or [])
summary = report.get("summary") or {}
actionable = int(summary.get("actionable", 0))
extra = sorted(suggested_names - applied_names)
print(f"ERROR: 单轮 gate 复检仍有 actionable findings: {actionable}")
print(f"       已应用 gate 函数: {len(applied_names)}")
if extra:
    print("       复检显影但未在原清单中的函数:")
    for name in extra:
        print(f"         {name}")
print(f"       报告保留于: {sys.argv[2]}")
PY
    return 3
}

# llama.cpp patch 应用/还原：拒绝覆盖用户 tracked/staged 修改；restore
# 由 EXIT trap 负责，第二个 patch 失败时也能恢复第一个 patch 的改动。
llama_patch_apply() {
    if ! git -C "$LLAMA" diff --quiet 2>/dev/null ||
       ! git -C "$LLAMA" diff --cached --quiet 2>/dev/null; then
        echo "ERROR: llama.cpp 子模块存在 tracked/staged 修改，拒绝应用 patch：$LLAMA" >&2
        git -C "$LLAMA" status --short >&2 || true
        return 1
    fi
    LLAMA_PATCH_APPLIED_COUNT=0
    local p
    for p in "${LLAMA_PATCHES[@]}"; do
        if ! git -C "$LLAMA" apply --check "$p" 2>/dev/null; then
            echo "ERROR: llama.cpp patch 无法应用（基线不符或已应用？）：$p" >&2
            return 1
        fi
        git -C "$LLAMA" apply "$p"
        LLAMA_PATCH_APPLIED_COUNT=$((LLAMA_PATCH_APPLIED_COUNT + 1))
        LLAMA_PATCH_ACTIVE=1
    done
    if git -C "$LLAMA" diff --quiet 2>/dev/null; then
        echo "ERROR: llama.cpp patch 未产生任何改动（子模块未初始化或基线不符）。" >&2
        return 1
    fi
    echo "llama.cpp 已打 ${#LLAMA_PATCHES[@]} 个 patch（q5-fix → vlen 兼容改造）"
}

llama_patch_restore() {
    [[ "${LLAMA_PATCH_ACTIVE:-0}" == "1" ]] || return 0
    local index
    while (( LLAMA_PATCH_APPLIED_COUNT > 0 )); do
        index=$((LLAMA_PATCH_APPLIED_COUNT - 1))
        if ! git -C "$LLAMA" apply -R "${LLAMA_PATCHES[$index]}"; then
            echo "WARN: 无法反向还原 llama.cpp patch（保留现场供手动处理）。" >&2
            return 1
        fi
        LLAMA_PATCH_APPLIED_COUNT=$index
    done
    LLAMA_PATCH_ACTIVE=0
    echo "llama.cpp 已还原为 vanilla 检出"
}

LATEST_POINTER="$HOME/.chimera/check_elf/latest.json"
LATEST_BACKUP=""
BUILD_COMPLETED=0
_on_exit() {
    local original_status=$?
    if [[ -n "$LATEST_BACKUP" ]]; then
        if ! cp "$LATEST_BACKUP" "$LATEST_POINTER"; then
            echo "WARN: 无法恢复 check-elf latest 指针：$LATEST_POINTER" >&2
            (( original_status == 0 )) && original_status=1
        fi
        rm -f "$LATEST_BACKUP" || {
            echo "WARN: 无法删除 check-elf latest 备份：$LATEST_BACKUP" >&2
            (( original_status == 0 )) && original_status=1
        }
    else
        if ! rm -f "$LATEST_POINTER"; then
            echo "WARN: 无法清理 check-elf latest 指针：$LATEST_POINTER" >&2
            (( original_status == 0 )) && original_status=1
        fi
    fi
    if ! llama_patch_restore; then
        (( original_status == 0 )) && original_status=1
        exit "$original_status"
    fi
    chimera_example_state_clear
    # Release the source lock before removing its state file; otherwise a
    # successful build would deadlock during cleanup.
    chimera_example_operation_unlock
    if [[ "$BUILD_COMPLETED" == "1" ]]; then
        local cleanup_status=0
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" != "1" ]]; then
            $CHIMERA_DEV toolchain clean patched-llvm --llvm-src "$REPO_ROOT/third_party/llvm" || cleanup_status=1
        fi
        rm -f -- "$(chimera_example_state_path 2>/dev/null || true)" || cleanup_status=1
        if [[ -n "$PACKAGED_INPUT_BUILD_ROOT" ]]; then
            rm -rf -- "$PACKAGED_INPUT_BUILD_ROOT" || cleanup_status=1
        fi
        if (( cleanup_status != 0 )); then
            echo "ERROR: 构建已完成，但自动清理失败；可重新运行上述两个 clean 命令。" >&2
            exit "$cleanup_status"
        fi
    fi
}


# ---------------------------------------------------------------
# 相位0：预检
# ---------------------------------------------------------------
echo "===== 相位0：预检 ====="
if [[ "$RELEASE_COMPONENT" == "system" ]]; then
    echo "release system 组件：跳过 Chimera census 预检，使用系统编译器"
else
    verify_chimera_implicit_vector_census_toolchain
    echo "预检通过。"
fi
# 每次运行都从当前发现面重新生成 gate 决策；不继承上次运行留下的
# 稳定决策或 census，避免旧函数污染本轮的分母。
rm -f "$BUILD_REMEDIATED.decision.json"
LLAMA_PATCH_ACTIVE=0
LLAMA_PATCH_APPLIED_COUNT=0
# A packaged prebuilt input does not need a llama.cpp checkout when its fresh
# check passes: prepare consumes the ELF and bundled translators directly.
# Defer the fixed-source clone until the PROBLEMATIC branch below proves that
# patching and remediation are actually required.  Source builds and release
# component builds enter ``bootstrap_llamacpp_dependencies``/their own source
# path before this point.
if [[ -f "$LATEST_POINTER" ]]; then
    LATEST_BACKUP="$(mktemp)"
    cp "$LATEST_POINTER" "$LATEST_BACKUP"
fi
trap _on_exit EXIT
chimera_example_state_begin
if [[ -z "${CHIMERA_EXAMPLE_INPUT:-}" ]]; then
    llama_patch_apply
fi

# ---------------------------------------------------------------
# 相位1：vanilla 主交付
# ---------------------------------------------------------------
echo "===== 相位1：vanilla 主交付 ====="
# vanilla 面只用于 check-elf 发现和交付，不参与阻止率统计。
if [[ -n "${CHIMERA_EXAMPLE_INPUT:-}" ]]; then
    [[ -f "$CHIMERA_EXAMPLE_INPUT" ]] || {
        echo "ERROR: release input ELF 不存在：$CHIMERA_EXAMPLE_INPUT" >&2
        exit 1
    }
    mkdir -p "$(dirname "$ELF_VANILLA")"
    cp "$CHIMERA_EXAMPLE_INPUT" "$ELF_VANILLA"
    # Wheel extractors commonly restore package files as 0644.  The copied
    # delivery ELF is user-owned, so restore its executable bit here without
    # mutating the read-only site-packages resource or an external input.
    chmod u+x "$ELF_VANILLA"
    echo "使用预编译输入 ELF：$CHIMERA_EXAMPLE_INPUT"
else
    [[ -n "$SYSTEM_CC" && -n "$SYSTEM_CXX" ]] || {
        echo "ERROR: 系统 LLVM clang/clang++ 不可用；设置 CHIMERA_SYSTEM_CC 和 CHIMERA_SYSTEM_CXX 后重试。" >&2
        exit 1
    }
    cmake -S "$LLAMA" -B "$BUILD_VANILLA" \
        -DCMAKE_C_COMPILER="$SYSTEM_CC" \
        -DCMAKE_CXX_COMPILER="$SYSTEM_CXX" \
        -DCMAKE_C_FLAGS="$FLAGS_VANILLA" \
        -DCMAKE_CXX_FLAGS="$FLAGS_VANILLA" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        "${CMAKE_COMMON[@]}" \
        "${CHIMERA_OPENMP_CMAKE_ARGS[@]}"
    verify_chimera_openmp_build "$BUILD_VANILLA"
    cmake --build "$BUILD_VANILLA" -j"$JOBS" "${BUILD_TARGETS[@]}"
fi

# The system release component needs no workflow admission or remediation.
if [[ "$RELEASE_COMPONENT" == "system" ]]; then
    mkdir -p "$(dirname "$RELEASE_OUTPUT")"
    cp "$ELF_VANILLA" "$RELEASE_OUTPUT"
    # The release payload is already copied to its final user cache path;
    # remove only this script's exact intermediate tree after a successful
    # component build.  Diagnostics are retained on every failure path.
    rm -rf -- "$BUILD_VANILLA"
    echo "release system ELF: $RELEASE_OUTPUT"
    exit 0
fi

# The profile is explicit below (the old command shape was:
# chimera-pkg check-elf --profile "$SAFETY_PROFILE" --input "$ELF_VANILLA".
$CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$ELF_VANILLA"
VANILLA_STATUS="$(_status_of "$ELF_VANILLA")"

if [[ "$VANILLA_STATUS" == "PROBLEMATIC" ]]; then
    if [[ -n "${CHIMERA_EXAMPLE_INPUT:-}" && "${LLAMA_PATCH_ACTIVE:-0}" != "1" ]]; then
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
            ensure_chimera_host_tools || exit 1
            ensure_chimera_cli_current || exit 1
            ensure_chimera_profile || exit 1
            ensure_packaged_llama_source || exit 1
        else
            bootstrap_llamacpp_dependencies full
        fi
        llama_patch_apply
    fi
    VANILLA_REPORT="$ELF_VANILLA.check.json"
    read -r VANILLA_STRATEGY VANILLA_GATE VANILLA_FP VANILLA_STACKOBJ \
        < <(_read_decision "$VANILLA_REPORT")
    echo "相位1：PROBLEMATIC（strategy=$VANILLA_STRATEGY gate=$VANILLA_GATE fp=$VANILLA_FP stack_object=$VANILLA_STACKOBJ），进入修复闭环"
    _remediate_loop "$BUILD_REMEDIATED" "$FLAGS_VANILLA" "$ELF_REMEDIATED" "相位1" "$VANILLA_REPORT"
    [[ -n "$DELIVERY_ELF" ]] || {
        echo "ERROR: 修复闭环未产生交付 ELF" >&2
        exit 1
    }
elif [[ "$VANILLA_STATUS" == "CHECKED" ]]; then
    echo "相位1：CHECKED，无需修复"
    DELIVERY_ELF="$ELF_VANILLA"
else
    echo "ERROR: 相位1 出现意外状态：$VANILLA_STATUS" >&2
    exit 1
fi

# Release builds intentionally end here.  In particular, do not enter the
# migration loop below: it creates Workspaces and executes prepare/runtime
# rebuilds, which are user execution artifacts rather than wheel payloads.
if [[ "$RELEASE_COMPONENT" == "remediated" ]]; then
    [[ -n "$DELIVERY_ELF" && -f "$DELIVERY_ELF" ]] || {
        echo "ERROR: remediated release build did not produce an ELF" >&2
        exit 1
    }
    mkdir -p "$(dirname "$RELEASE_OUTPUT")"
    cp "$DELIVERY_ELF" "$RELEASE_OUTPUT"
    # The remediation loop already checked its result.  Packaging does not
    # repeat workflow checks for the migration scene copies.
    rm -f "$RELEASE_OUTPUT.check.json"
    rm -rf -- "$BUILD_VANILLA" "$BUILD_REMEDIATED"
    echo "release remediated ELF: $RELEASE_OUTPUT"
    exit 0
fi

# ---------------------------------------------------------------
# 迁移场景 workspace：只对最终交付面生成，三种迁移场景各自用
# 自己的 profile，并使用显式 Workspace ID。把最终交付 ELF 拷成三份名字
# 不同的副本即可互不冲突：
#   llama-perplexity-1024-to-256   <- linux-riscv64-rvv-1024-to-256.toml
#   llama-perplexity-256-to-1024   <- linux-riscv64-rvv-256-to-1024.toml
#   llama-perplexity-bidirectional <- linux-riscv64-rvv-1024-256-bidirectional.toml
# 副本与最终交付内容一致时直接 prepare（CLI 按内容摘要复用，秒回）；
# 交付 ELF 重建后副本内容变化时，prepare 会根据显式 ID 重新生成该
# Workspace；Workspace 的内容摘要和重定位元数据会在这一过程中刷新。
# ---------------------------------------------------------------
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$RELEASE_PREBUILT_DIR/system" "$RELEASE_PREBUILT_DIR/remediated"
cp "$ELF_VANILLA" "$RELEASE_PREBUILT_DIR/system/llama-perplexity"
if [[ -f "$ELF_REMEDIATED" ]]; then
    cp "$ELF_REMEDIATED" "$RELEASE_PREBUILT_DIR/remediated/llama-perplexity"
else
    cp "$ELF_VANILLA" "$RELEASE_PREBUILT_DIR/remediated/llama-perplexity"
fi
cp "$DELIVERY_ELF" "$ARTIFACT_DIR/llama-perplexity"
DELIVERY_ELF="$ARTIFACT_DIR/llama-perplexity"
BIN_REMEDIATED="$ARTIFACT_DIR"
mkdir -p "$BIN_REMEDIATED"
for scenario in 1024-to-256 256-to-1024 bidirectional; do
    case "$scenario" in
        1024-to-256)   profile_name="linux-riscv64-rvv-1024-to-256.toml" ;;
        256-to-1024)   profile_name="linux-riscv64-rvv-256-to-1024.toml" ;;
        bidirectional) profile_name="linux-riscv64-rvv-1024-256-bidirectional.toml" ;;
    esac
    profile="$REPO_ROOT/examples/platforms/k3/$profile_name"
    workspace_id="llama-perplexity-$scenario"
    copy="$BIN_REMEDIATED/llama-perplexity-$scenario"
    if [[ -f "$copy" ]] && cmp -s "$DELIVERY_ELF" "$copy"; then
        : # 副本未变，交给 prepare 的内容摘要复用
    else
        if [[ -f "$copy" ]]; then
            rm -f -- "$copy.check.json" 2>/dev/null || true
            rm -f "$copy"
        fi
        cp "$DELIVERY_ELF" "$copy"
        # ELF 状态按文件记录、不随 cp 传递：新副本对 registry 而言是
        # UNCHECKED，需自行过检取得当前 profile 的检查凭据。
    fi
    # 即使副本内容未变化，也必须按场景 profile 复核当前检查范围；这
    # 确保新增 Safety 或参数变更不会被 inode/内容复用绕过。
    $CHIMERA_PKG check-elf --profile "$profile" --input "$copy"
    echo "prepare [$scenario]: $copy"
    $CHIMERA_PKG prepare --profile "$profile" --input "$copy" --workspace "$workspace_id"
    # prepare 默认非 --debug，workspace 里的 runtime 是 CHIMERA_DEBUG=OFF
    # 编的，迁移演示没有诊断打印。这里对每个场景 workspace 重编
    # build-runtime（CHIMERA_DEBUG=ON + si_ptr 诊断链路）；只需 runtime
    # 重编、不重跑 dump/translate。
    echo "rebuild [$scenario]: build-runtime（CHIMERA_DEBUG=ON）"
    $CHIMERA_DEV --debug rebuild --profile "$profile" --steps build-runtime --input "$copy" --workspace "$workspace_id"
done

echo "===== 构建完成 ====="
echo "delivery ELF : $DELIVERY_ELF"
echo "scenarios    : $BIN_REMEDIATED"
BUILD_COMPLETED=1
