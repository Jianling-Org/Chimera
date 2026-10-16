#!/usr/bin/env bash
set -euo pipefail

# llama.cpp 单面隐式向量生成阻止率统计（内部实现：通过
# 由开发者手动调用；Workspace 交付由 chimera-pkg workspace pack 完成。
#
# 1. 无 gate 的发现构建只供 check-elf 生成 gate 清单，不参与统计。
# 2. 使用最终清单做一次 clean-first 的 gate census 全量构建。
# 3. vector_census_report.py 只输出函数级主表；四类机制和总计均按集合
#    去重，分母为 formed ∪ blocked，分子为 blocked。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
    LLAMA="${CHIMERA_EXAMPLE_SOURCE_DIR:-$HOME/.chimera/example-source/llama.cpp}"
else
    LLAMA="$REPO_ROOT/examples/applications/llama-cpp/llama.cpp"
fi
# Stats discovery/census must use a repository-owned application Profile with
# Safety enabled; no implicit system Profile is consulted.
SAFETY_PROFILE="$REPO_ROOT/examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml"

if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
    LLAMA_PATCH_DIR="$REPO_ROOT/examples/applications/llama-cpp/patch"
else
    LLAMA_PATCH_DIR="$LLAMA/../patch"
fi
LLAMA_PATCHES=(
    "$LLAMA_PATCH_DIR/llama-cpp-rvv-vlen1024-q5-fix-4fc4ec554.patch"
    "$LLAMA_PATCH_DIR/0001-llama.cpp-rvv-vlen1024-compatible-with-vlen256.patch"
)

BUILD_DISCOVERY="$LLAMA/build-stats-discovery"
BUILD_GATE="$LLAMA/build-stats-gate"
ELF_DISCOVERY="$BUILD_DISCOVERY/bin/llama-perplexity"
ELF_GATE="$BUILD_GATE/bin/llama-perplexity"

MOCK_SEED="$LLAMA/build-stats.mock-seed.json"
STABLE_DECISION="$LLAMA/build-stats.decision.json"
GATE_NAMES="$LLAMA/build-stats.decision.gate_names.txt"
GATE_CENSUS="$LLAMA/build-stats.decision.gate_names.implicit_vector_census.tsv"

SHIM_CC="$HOME/.chimera/bin/clang"
SHIM_CXX="$HOME/.chimera/bin/clang++"
BASELINE_CC="${CHIMERA_BASELINE_CC:-cc}"
BASELINE_CXX="${CHIMERA_BASELINE_CXX:-c++}"
TOOLCHAIN_ROOT="${CHIMERA_TOOLCHAIN_BUILD:-$HOME/.chimera/toolchain_build}"
PLUGIN_DIR="$TOOLCHAIN_ROOT/plugins/lib/chimera/llvm"
FLAGS_STATS="-march=rv64gcv"

CMAKE_COMMON=(
    -DBUILD_SHARED_LIBS=OFF
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DLLAMA_NATIVE=OFF
    -DLLAMA_CURL=OFF
    -DLLAMA_OPENSSL=OFF
)

source "$SCRIPT_DIR/_common.sh"
ARTIFACT_DIR="$(chimera_example_artifact_root)/stats"
parse_llama_build_args "$@"
export CHIMERA_EXAMPLE_CLEAN_NAME=build_llamacpp_stats
if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
    # Stats always compiles through the deployed Chimera compiler in a wheel;
    # requiring an unrelated distro cc/c++ would reject valid installations.
    export CHIMERA_SKIP_BASELINE_COMPILER=1
fi
ensure_chimera_host_tools || exit 1
chimera_example_operation_lock || exit 1
ensure_example_build_not_interrupted || exit 1
ensure_packaged_llama_source
bootstrap_llamacpp_dependencies stats
detect_chimera_openmp

_status_of() {
    $CHIMERA_PKG status --input "$1" |
        grep -oE 'UNCHECKED|CHECKED|PROBLEMATIC|REMEDIATED' | head -1
}

# 合并决策并重定向 wrapper 的 latest.json。--no-gate 用于发现面；
# --force-gate 用于 census 面，即使清单为空也加载 VectorGate 的晚期 ID pass。
_merge_decision() {
    python3 - "$1" "$2" "$3" "${@:4}" <<'PY'
import json, pathlib, sys

new_path, stable_path, elf_path = sys.argv[1:4]
options = set(sys.argv[4:])
new = json.loads(pathlib.Path(new_path).read_text(encoding="utf-8")).get("decision") or {}
stable = pathlib.Path(stable_path)
previous = {}
if stable.is_file():
    try:
        previous = json.loads(stable.read_text(encoding="utf-8")).get("decision") or {}
    except json.JSONDecodeError:
        pass

merged = dict(new)
merged["gate"] = dict(new.get("gate") or {})
merged["gate"]["names"] = sorted(
    set((new.get("gate") or {}).get("names") or [])
    | set((previous.get("gate") or {}).get("names") or [])
)
merged["stack_object_plugin"] = bool(
    new.get("stack_object_plugin") or previous.get("stack_object_plugin")
)
if "--no-gate" in options:
    merged["vector_gate"] = {"enabled": False}
    merged["gate"] = {"enabled": False, "names": []}
elif "--force-gate" in options:
    merged["vector_gate"] = {"enabled": True}
    merged["gate"]["enabled"] = True

stable.write_text(
    json.dumps({"decision": merged}, indent=2, ensure_ascii=False),
    encoding="utf-8",
)
pointer = pathlib.Path.home() / ".chimera" / "check_elf" / "latest.json"
pointer.parent.mkdir(parents=True, exist_ok=True)
pointer.write_text(
    json.dumps({
        "elf_path": elf_path,
        "decision_path": str(stable.resolve()),
        "strategy": merged.get("strategy"),
        "stack_object": bool(merged.get("stack_object_plugin")),
        "exported_at": "single-face-census",
        "counts": {},
    }, indent=2, ensure_ascii=False),
    encoding="utf-8",
)
PY
}

_clean_shim_build() {
    local build_dir="$1" flags="$2"
    cmake -S "$LLAMA" -B "$build_dir" \
        -DCMAKE_C_COMPILER="$SHIM_CC" \
        -DCMAKE_CXX_COMPILER="$SHIM_CXX" \
        -DCMAKE_C_FLAGS="$flags" \
        -DCMAKE_CXX_FLAGS="$flags" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        "${CMAKE_COMMON[@]}" \
        "${CHIMERA_OPENMP_CMAKE_ARGS[@]}"
    verify_chimera_openmp_build "$build_dir"
    # census 必须来自一次全量重编；CMake/Ninja 的增量状态不得混入。
    cmake --build "$build_dir" --clean-first -j"$JOBS" "${BUILD_TARGETS[@]}"
}

_write_mock_seed() {
    python3 - "$1" <<'PY'
import json, sys
seed = {
    "decision": {
        "strategy": "none",
        "strategy_reason": "mock: force stack-object discovery",
        "vector_gate": {"enabled": False},
        "function_pointer_plugin": False,
        "stack_object_plugin": True,
        "gate": {"enabled": False, "names": []},
    }
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(seed, stream, indent=2, ensure_ascii=False)
PY
}

llama_patch_apply() {
    if ! git -C "$LLAMA" diff --quiet 2>/dev/null ||
       ! git -C "$LLAMA" diff --cached --quiet 2>/dev/null; then
        echo "ERROR: llama.cpp 子模块存在 tracked/staged 修改，拒绝应用 patch：$LLAMA" >&2
        git -C "$LLAMA" status --short >&2 || true
        return 1
    fi
    LLAMA_PATCH_APPLIED_COUNT=0
    local patch
    for patch in "${LLAMA_PATCHES[@]}"; do
        git -C "$LLAMA" apply --check "$patch"
        git -C "$LLAMA" apply "$patch"
        LLAMA_PATCH_APPLIED_COUNT=$((LLAMA_PATCH_APPLIED_COUNT + 1))
        LLAMA_PATCH_ACTIVE=1
    done
    if git -C "$LLAMA" diff --quiet 2>/dev/null; then
        echo "ERROR: llama.cpp patch 未产生改动。" >&2
        return 1
    fi
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
}

LATEST_POINTER="$HOME/.chimera/check_elf/latest.json"
LATEST_BACKUP=""
BUILD_COMPLETED=0
LLAMA_PATCH_ACTIVE=0
LLAMA_PATCH_APPLIED_COUNT=0
_on_exit() {
    local original_status=$?
    if [[ -n "$LATEST_BACKUP" ]]; then
        cp "$LATEST_BACKUP" "$LATEST_POINTER"
        rm -f "$LATEST_BACKUP"
    else
        rm -f "$LATEST_POINTER"
    fi
    if ! llama_patch_restore; then
        (( original_status == 0 )) && original_status=1
        exit "$original_status"
    fi
    chimera_example_state_clear
    # State-file cleanup uses the shared source lock; release the build lock first.
    chimera_example_operation_unlock
    if [[ "$BUILD_COMPLETED" == "1" ]]; then
        local cleanup_status=0
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" != "1" ]]; then
            $CHIMERA_DEV toolchain clean patched-llvm --llvm-src "$REPO_ROOT/third_party/llvm" || cleanup_status=1
        fi
        rm -f -- "$(chimera_example_state_path 2>/dev/null || true)" || cleanup_status=1
        if (( cleanup_status != 0 )); then
            echo "ERROR: stats 构建已完成，但自动清理失败；可重新运行上述两个 clean 命令。" >&2
            exit "$cleanup_status"
        fi
    fi
}

echo "===== 相位S0：预检 ====="
verify_chimera_implicit_vector_census_toolchain

rm -f "$GATE_CENSUS" "$STABLE_DECISION" "$GATE_NAMES" "$MOCK_SEED"
if [[ -f "$LATEST_POINTER" ]]; then
    LATEST_BACKUP="$(mktemp)"
    cp "$LATEST_POINTER" "$LATEST_BACKUP"
fi
trap _on_exit EXIT
chimera_example_state_begin
llama_patch_apply

echo "===== 相位S1：生成 gate 清单（不统计） ====="
SEED_REPORT="${CHIMERA_STATS_SEED_DECISION:-}"
if [[ -z "$SEED_REPORT" ]]; then
    SEED_REPORT="$MOCK_SEED"
    _write_mock_seed "$SEED_REPORT"
elif [[ ! -f "$SEED_REPORT" ]]; then
    echo "ERROR: CHIMERA_STATS_SEED_DECISION 不存在：$SEED_REPORT" >&2
    exit 1
fi

_merge_decision "$SEED_REPORT" "$STABLE_DECISION" "$ELF_DISCOVERY" --no-gate
_clean_shim_build "$BUILD_DISCOVERY" "$FLAGS_STATS"
$CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$ELF_DISCOVERY"
DISCOVERY_STATUS="$(_status_of "$ELF_DISCOVERY")"
if [[ "$DISCOVERY_STATUS" != "CHECKED" && "$DISCOVERY_STATUS" != "PROBLEMATIC" ]]; then
    echo "ERROR: 发现面状态异常：$DISCOVERY_STATUS" >&2
    exit 1
fi
DISCOVERY_REPORT="$ELF_DISCOVERY.check.json"

echo "===== 相位S2：单面 gate census 全量构建 ====="
_merge_decision "$DISCOVERY_REPORT" "$STABLE_DECISION" "$ELF_GATE" --force-gate
: > "$GATE_CENSUS"

ensure_stats_decision_dependencies "$STABLE_DECISION"
# FunctionPointer/SVF is deliberately not part of the stats bootstrap; the
# helper above emits the complete opt-in build commands when a decision asks
# for that route.

GATE_FLAGS="$FLAGS_STATS"
if python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))["decision"]
sys.exit(0 if d.get("function_pointer_plugin") else 1)
' "$STABLE_DECISION"; then
    check_chimera_lto_capacity
    GATE_FLAGS="$GATE_FLAGS -flto"
fi
_clean_shim_build "$BUILD_GATE" "$GATE_FLAGS"

$CHIMERA_PKG check-elf --profile "$SAFETY_PROFILE" --input "$ELF_GATE"
GATE_STATUS="$(_status_of "$ELF_GATE")"
if [[ "$GATE_STATUS" != "CHECKED" ]]; then
    echo "ERROR: 最终门控 ELF 复检必须为 CHECKED，实际为 $GATE_STATUS" >&2
    exit 3
fi

[[ -f "$GATE_NAMES" ]] || { echo "ERROR: 未生成 gate 清单：$GATE_NAMES" >&2; exit 1; }
[[ -f "$GATE_CENSUS" ]] || { echo "ERROR: 未生成 census：$GATE_CENSUS" >&2; exit 1; }

echo "===== 相位S3：隐式向量生成阻止率 ====="
python3 "$SCRIPT_DIR/vector_census_report.py" \
    --census "$GATE_CENSUS" \
    --gate-list "$GATE_NAMES"

mkdir -p "$ARTIFACT_DIR"
cp "$ELF_DISCOVERY" "$ARTIFACT_DIR/llama-perplexity-discovery"
cp "$ELF_GATE" "$ARTIFACT_DIR/llama-perplexity-gate"
[[ -f "$ELF_DISCOVERY.check.json" ]] && cp "$ELF_DISCOVERY.check.json" "$ARTIFACT_DIR/discovery.check.json"
[[ -f "$ELF_GATE.check.json" ]] && cp "$ELF_GATE.check.json" "$ARTIFACT_DIR/gate.check.json"
[[ -f "$STABLE_DECISION" ]] && cp "$STABLE_DECISION" "$ARTIFACT_DIR/"
[[ -f "$GATE_NAMES" ]] && cp "$GATE_NAMES" "$ARTIFACT_DIR/"
[[ -f "$GATE_CENSUS" ]] && cp "$GATE_CENSUS" "$ARTIFACT_DIR/"
echo "stats artifacts: $ARTIFACT_DIR"
BUILD_COMPLETED=1
