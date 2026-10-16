#!/usr/bin/env bash
set -euo pipefail
CHIMERA_PKG="${CHIMERA_PKG:-chimera-pkg}"
CHIMERA_USER="${CHIMERA_USER:-chimera-user}"

# ============================================================
# 运行 llama-perplexity：vlen1024 -> vlen256 迁移
#
# 内部实现：直接运行已准备的 Workspace。
#   输入 ELF 为 build_llamacpp.sh prepare 的场景副本
#   ~/.chimera/examples/<仓库ID>/llamacpp/main/llama-perplexity-1024-to-256（workspace 已就绪）。
#
# 生命周期（workspace 已由 examples/scripts/build/build_llamacpp.sh 统一
# prepare，本脚本不再 prepare）：
#   1. echo $$ > /proc/set_ai_thread   （pin 到 1024 核，后续程序启动在 1024 核心）
#   2. $CHIMERA_USER register
#   3. $CHIMERA_USER run（后台；从 --debug 输出抓 parent_thread_id）
#   4. 等待 llama.cpp 工作线程全部启动（默认 16 线程）——过早 migrate
#      时线程尚未创建，迁移覆盖不到它们
#   5. $CHIMERA_USER migrate --direction 1024-to-256
#
# Chimera 入口已通过 make install 或 make develop 安装到 PATH。
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"   # chimera/
source "$SCRIPT_DIR/_common.sh"

LLAMA="$REPO_ROOT/examples/applications/llama-cpp/llama.cpp"

# ---- 输入 ELF：build_llamacpp.sh 为本场景准备的副本（workspace 已就绪）----
BINARY="$(chimera_example_artifact_root)/main/llama-perplexity-1024-to-256"
WORKSPACE="$(chimera_workspace_for_elf "$BINARY")" || exit 1

# Profile（与 examples/platforms/k3/ 下的 TOML 对应）
PROFILE="$REPO_ROOT/examples/platforms/k3/linux-riscv64-rvv-1024-to-256.toml"

# 模型与提示词（目录内具体文件，可用环境变量覆盖；llama.cpp 用 -f 指定 prompt 文件）
MODEL="$(chimera_resolve_model)" || exit 1
PROMPT_FILE="${PROMPT_FILE:-$REPO_ROOT/examples/applications/llama-cpp/prompt/file.txt}"

# 迁移参数
MIGRATION_COUNT="${MIGRATION_COUNT:-8}"
DIRECTION="1024-to-256"
# llama.cpp 默认 n_threads=16；migrate 前必须等工作线程全部启动
MIN_THREADS="${MIN_THREADS:-16}"
THREAD_WAIT_TIMEOUT="${THREAD_WAIT_TIMEOUT:-120}"   # 秒

# ---- 前置检查 ----
for f in "$BINARY" "$PROFILE" "$MODEL" "$PROMPT_FILE"; do
    [[ -e "$f" ]] || { echo "ERROR: 不存在: $f（先在部署机 prepare 并交付 .workspace 包）" >&2; exit 1; }
done
command -v chimera-pkg >/dev/null 2>&1 || { echo "ERROR: chimera-pkg 不在 PATH（需先 pip install 或 make develop）" >&2; exit 1; }
command -v chimera-user >/dev/null 2>&1 || { echo "ERROR: chimera-user 不在 PATH（需先 make install 或 make develop）" >&2; exit 1; }
[[ -e /proc/set_ai_thread && -w /proc/set_ai_thread ]] || {
    echo "ERROR: /proc/set_ai_thread 不存在或不可写" >&2
    exit 1
}

# ---- 1. pin 到 1024 核 ----
echo "========== [1/5] Pin to 1024 cores =========="
echo $$ > /proc/set_ai_thread

# ---- 2. register ----
echo "========== [2/5] $CHIMERA_USER register =========="
$CHIMERA_USER register --verify --workspace "$WORKSPACE"

# ---- 3. run（后台，抓取 parent_thread_id）----
echo "========== [3/5] $CHIMERA_USER run (background) =========="
RUN_LOG="$(mktemp)"
run_install_cleanup_traps
$CHIMERA_USER --debug run --workspace "$WORKSPACE" -- \
    -m "$MODEL" -f "$PROMPT_FILE" \
    > >(tee "$RUN_LOG") 2>&1 &
RUN_PID=$!

TID=""
for _ in $(seq 1 100); do
    if [[ -r "$RUN_LOG" ]] && grep -q 'parent_thread_id=' "$RUN_LOG"; then
        TID="$(grep -m1 'parent_thread_id=' "$RUN_LOG" | sed 's/.*=//')"
        break
    fi
    kill -0 "$RUN_PID" 2>/dev/null || break
    sleep 0.1
done

if [[ -z "$TID" ]]; then
    echo "ERROR: 未能从 chimera-user --debug run 输出捕获 parent_thread_id" >&2
    kill "$RUN_PID" 2>/dev/null || true
    exit 1
fi
echo "parent_thread_id = $TID"

# ---- 4. 等待工作线程全部启动 ----
run_wait_for_threads "$TID" "$MIN_THREADS" "$THREAD_WAIT_TIMEOUT"

# 迁移时机：等待 llama 打出 "calculating perplexity"（计算热区开始）后，
# 小停顿再执行唯一一轮迁移。OpenMP 持久线程池会让 worker 保持在迁移后的
# 核组，不需要再次调用 migrate。
MIGRATE_DELAY="${MIGRATE_DELAY:-5}"
echo "等待计算热区（calculating perplexity）..."
run_wait_for_marker "$RUN_LOG" "calculating perplexity" "$THREAD_WAIT_TIMEOUT"
if [[ "$MIGRATE_DELAY" -gt 0 ]]; then
    echo "延后 ${MIGRATE_DELAY}s（确保计算线程已进入热区）..."
    sleep "$MIGRATE_DELAY"
fi

# ---- 5. migrate（单次）----
echo "========== [5/5] $CHIMERA_USER migrate --direction $DIRECTION =========="
if ! kill -0 "$RUN_PID" 2>/dev/null; then
    echo "ERROR: llama 进程在单次迁移前已退出" >&2
    if wait "$RUN_PID"; then
        exit 1
    else
        exit $?
    fi
fi
$CHIMERA_USER migrate --workspace "$WORKSPACE" --parent-thread "$TID" --migration-count "$MIGRATION_COUNT" --direction "$DIRECTION"

wait "$RUN_PID"
