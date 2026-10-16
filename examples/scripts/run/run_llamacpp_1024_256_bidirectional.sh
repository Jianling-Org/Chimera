#!/usr/bin/env bash
set -euo pipefail
CHIMERA_PKG="${CHIMERA_PKG:-chimera-pkg}"
CHIMERA_USER="${CHIMERA_USER:-chimera-user}"

# ============================================================
# 运行 llama-perplexity：vlen1024 <-> vlen256 双向迁移
#
# 内部实现：直接运行已准备的 Workspace。
#   输入 ELF 为 build_llamacpp.sh prepare 的场景副本
#   ~/.chimera/examples/<仓库ID>/llamacpp/main/llama-perplexity-bidirectional（workspace 已就绪）。
#
# 生命周期与单向版相同（workspace 已由 build_llamacpp.sh 统一 prepare，
# 本脚本不再 prepare），但 migrate 分两次：
#   先 256-to-1024，再 1024-to-256。
#   两次之间必须等待（SETTLE_SECONDS，默认 10s）：不能迁移正处于翻译
#   状态的线程，需等上一波翻译全部退出后再发起下一次迁移。
#
# Chimera 入口已通过 make install 或 make develop 安装到 PATH。
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"   # chimera/
source "$SCRIPT_DIR/_common.sh"

LLAMA="$REPO_ROOT/examples/applications/llama-cpp/llama.cpp"

# ---- 输入 ELF：build_llamacpp.sh 为本场景准备的副本（workspace 已就绪）----
BINARY="$(chimera_example_artifact_root)/main/llama-perplexity-bidirectional"
WORKSPACE="$(chimera_workspace_for_elf "$BINARY")" || exit 1

# Profile（双向）
PROFILE="$REPO_ROOT/examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml"

# 模型与提示词（目录内具体文件，可用环境变量覆盖；llama.cpp 用 -f 指定 prompt 文件）
MODEL="$(chimera_resolve_model)" || exit 1
PROMPT_FILE="${PROMPT_FILE:-$REPO_ROOT/examples/applications/llama-cpp/prompt/file.txt}"

# 迁移参数
MIGRATION_COUNT="${MIGRATION_COUNT:-8}"
# llama.cpp 默认 n_threads=16；migrate 前必须等工作线程全部启动
MIN_THREADS="${MIN_THREADS:-16}"
THREAD_WAIT_TIMEOUT="${THREAD_WAIT_TIMEOUT:-120}"   # 秒
# 两次迁移之间的间隔：等上一波翻译状态全部退出
SETTLE_SECONDS="${SETTLE_SECONDS:-10}"
# 迁移时机：等计算热区开始，确保工作线程已经进入稳定计算阶段。
MIGRATE_DELAY="${MIGRATE_DELAY:-5}"

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

# ---- 1. register ----
echo "========== [1/5] $CHIMERA_USER register =========="
$CHIMERA_USER register --verify --workspace "$WORKSPACE"

# ---- 2. run（后台，抓取 parent_thread_id）----
echo "========== [2/5] $CHIMERA_USER run (background) =========="
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

# ---- 3. 等待工作线程全部启动 ----
run_wait_for_threads "$TID" "$MIN_THREADS" "$THREAD_WAIT_TIMEOUT"

# 迁移时机：等计算热区开始（llama 打出 "calculating perplexity"），
# 再执行一次去程和一次回程迁移。
echo "等待计算热区（calculating perplexity）..."
run_wait_for_marker "$RUN_LOG" "calculating perplexity" "$THREAD_WAIT_TIMEOUT"
if [[ "$MIGRATE_DELAY" -gt 0 ]]; then
    echo "延后 ${MIGRATE_DELAY}s（确保计算线程已进入热区）..."
    sleep "$MIGRATE_DELAY"
fi

# ---- 4. migrate 256-to-1024 ----
echo "========== [4/5] $CHIMERA_USER migrate --direction 256-to-1024 =========="
$CHIMERA_USER migrate --workspace "$WORKSPACE" --parent-thread "$TID" --migration-count "$MIGRATION_COUNT" --direction 256-to-1024

# 等上一波翻译状态全部退出：不能迁移正处于翻译状态的线程
echo "等待 ${SETTLE_SECONDS}s 让翻译状态退出 ..."
sleep "$SETTLE_SECONDS"

# ---- 5. migrate 1024-to-256 ----
echo "========== [5/5] $CHIMERA_USER migrate --direction 1024-to-256 =========="
$CHIMERA_USER migrate --workspace "$WORKSPACE" --parent-thread "$TID" --migration-count "$MIGRATION_COUNT" --direction 1024-to-256

wait "$RUN_PID"
