#!/usr/bin/env bash
set -euo pipefail
CHIMERA_PKG="${CHIMERA_PKG:-chimera-pkg}"
CHIMERA_USER="${CHIMERA_USER:-chimera-user}"

# ============================================================
# 运行 llama-perplexity：256 核基线（不经调度器迁移）
#
# 内部实现：直接运行已准备的 Workspace。
#   输入 ELF 为 build_llamacpp.sh prepare 的场景副本
#   ~/.chimera/examples/<仓库ID>/llamacpp/main/llama-perplexity-bidirectional（workspace 已就绪）。
#
# 用途：进程默认启动在 256 核上，只 register + run，不发起任何迁移——
# 作为 PPL/性能对照基准（与三个迁移场景的输出对比，验证翻译不改结果）。
# workspace 里的翻译变体在此场景下不会被触发，仅提供 preload 与本地副本。
#
# Chimera 入口已通过 make install 或 make develop 安装到 PATH。
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"   # chimera/
source "$SCRIPT_DIR/_common.sh"

LLAMA="$REPO_ROOT/examples/applications/llama-cpp/llama.cpp"

# ---- 输入 ELF：任一场景副本均可（本场景不触发翻译，取双向副本）----
BINARY="$(chimera_example_artifact_root)/main/llama-perplexity-bidirectional"
WORKSPACE="$(chimera_workspace_for_elf "$BINARY")" || exit 1

# Profile（双向 workspace 内容最全；不迁移时翻译变体不参与）
PROFILE="$REPO_ROOT/examples/platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml"

# 模型与提示词（目录内具体文件，可用环境变量覆盖；llama.cpp 用 -f 指定 prompt 文件）
MODEL="$(chimera_resolve_model)" || exit 1
PROMPT_FILE="${PROMPT_FILE:-$REPO_ROOT/examples/applications/llama-cpp/prompt/file.txt}"

# ---- 前置检查 ----
for f in "$BINARY" "$PROFILE" "$MODEL" "$PROMPT_FILE"; do
    [[ -e "$f" ]] || { echo "ERROR: 不存在: $f（先在部署机 prepare 并交付 .workspace 包）" >&2; exit 1; }
done
command -v chimera-pkg >/dev/null 2>&1 || { echo "ERROR: chimera-pkg 不在 PATH（需先 pip install 或 make develop）" >&2; exit 1; }
command -v chimera-user >/dev/null 2>&1 || { echo "ERROR: chimera-user 不在 PATH（需先 make install 或 make develop）" >&2; exit 1; }

# ---- 1. register ----
echo "========== [1/2] $CHIMERA_USER register =========="
$CHIMERA_USER verify --workspace "$WORKSPACE" --input "$BINARY"
$CHIMERA_USER register --workspace "$WORKSPACE" --input "$BINARY"

# ---- 2. run（前台；不迁移，进程默认 affinity 即 256 组）----
echo "========== [2/2] $CHIMERA_USER run (foreground, no migrate) =========="
$CHIMERA_USER --debug run --workspace "$WORKSPACE" --input "$BINARY" -- \
    -m "$MODEL" -f "$PROMPT_FILE"
