#!/usr/bin/env bash

# The release wheel deliberately omits this roughly 500 MB file.  A caller
# supplies MODEL or places a verified copy in this content-addressed cache;
# source checkouts may still use their repository copy.
CHIMERA_MODEL_FILENAME="tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf"
CHIMERA_MODEL_SHA256="6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca"
CHIMERA_MODEL_SIZE=500315520

chimera_cached_model_valid() {
    local path="$1" size digest
    [[ -f "$path" && -r "$path" && ! -L "$path" ]] || return 1
    if size="$(stat -c '%s' -- "$path" 2>/dev/null)"; then
        [[ "$size" == "$CHIMERA_MODEL_SIZE" ]] || return 1
    else
        size="$(wc -c < "$path")" || return 1
        [[ "${size//[[:space:]]/}" == "$CHIMERA_MODEL_SIZE" ]] || return 1
    fi
    command -v sha256sum >/dev/null 2>&1 || return 1
    digest="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
    [[ "$digest" == "$CHIMERA_MODEL_SHA256" ]]
}

chimera_resolve_model() {
    if [[ -n "${MODEL:-}" ]]; then
        if [[ -f "$MODEL" && -r "$MODEL" ]]; then
            printf '%s\n' "$MODEL"
            return 0
        fi
        echo "ERROR: MODEL 指定的文件不存在或不可读：$MODEL" >&2
        return 1
    fi
    local cached="$HOME/.chimera/models/$CHIMERA_MODEL_SHA256/$CHIMERA_MODEL_FILENAME"
    if chimera_cached_model_valid "$cached"; then
        printf '%s\n' "$cached"
        return 0
    fi
    # A source checkout keeps the historical repository model location.  A
    # packaged release has no model under site-packages and must tell the user
    # how to obtain it instead of downloading from a run script.
    if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" != "1" ]]; then
        local source_model="${REPO_ROOT:?}/examples/applications/llama-cpp/model/$CHIMERA_MODEL_FILENAME"
        if [[ -f "$source_model" && -r "$source_model" ]]; then
            printf '%s\n' "$source_model"
            return 0
        fi
    fi
    echo "ERROR: 样例模型不存在；请设置 MODEL=/path/to/$CHIMERA_MODEL_FILENAME" >&2
    return 1
}

run_cleanup() {
    local pid="${RUN_PID:-}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    if [[ -n "${RUN_LOG:-}" ]]; then
        rm -f -- "$RUN_LOG"
    fi
}

chimera_example_artifact_root() {
    local id
    id="$(printf '%s' "${REPO_ROOT:?}" | sha256sum | awk '{print $1}')"
    printf '%s\n' "${CHIMERA_EXAMPLE_ARTIFACT_ROOT:-$HOME/.chimera/examples/$id/llamacpp}"
}

# Resolve the published Workspace from an input ELF for the source example
# layout. Runtime commands still receive the resulting Workspace path; they
# never use ELF inode lookup themselves. Set CHIMERA_EXAMPLE_WORKSPACE to
# bypass this helper when running a `.workspace` installed on another machine.
chimera_workspace_for_elf() {
    local elf="$1" root="${CHIMERA_WORKSPACE_ROOT:-$HOME/.chimera/workspaces}"
    if [[ -n "${CHIMERA_EXAMPLE_WORKSPACE:-}" ]]; then
        printf '%s\n' "$CHIMERA_EXAMPLE_WORKSPACE"
        return 0
    fi
    python3 - "$elf" "$root" <<'PY'
import pathlib, sys
# A Workspace is addressed by the identity digest of the application it was
# prepared for, so the digest *is* the lookup key -- no scan, no inode.
from chimera.preprocess.offline.analysis.core.workspace import workspace_name

elf = pathlib.Path(sys.argv[1]).expanduser().resolve()
root = pathlib.Path(sys.argv[2]).expanduser().resolve()
try:
    workspace = root / workspace_name(elf)
except (OSError, ValueError) as error:
    print(f"ERROR: cannot identify {elf}: {error}", file=sys.stderr)
    raise SystemExit(1)
if not (workspace / "workspace.json").is_file():
    print(
        f"ERROR: no Workspace matches {elf}; run chimera-pkg prepare "
        "--profile PROFILE first",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(workspace)
PY
}

run_install_cleanup_traps() {
    trap 'run_cleanup' EXIT
    trap 'run_cleanup; exit 130' INT
    trap 'run_cleanup; exit 143' TERM
}

run_thread_count() {
    local task_dir="/proc/$1/task"
    if [[ ! -d "$task_dir" ]]; then
        return 1
    fi
    local had_nullglob=0
    shopt -q nullglob && had_nullglob=1
    shopt -s nullglob
    local entries=("$task_dir"/*) path name count=0
    if (( had_nullglob == 0 )); then
        shopt -u nullglob
    fi
    for path in "${entries[@]}"; do
        [[ -d "$path" ]] || continue
        name="${path##*/}"
        [[ "$name" =~ ^[0-9]+$ ]] || continue
        count=$((count + 1))
    done
    echo "$count"
}

run_wait_for_threads() {
    local tgid="$1" minimum="$2" timeout="$3"
    local waited=0 limit=$((timeout * 10)) count
    echo "========== 等待线程数 >= $minimum（超时 ${timeout}s）=========="
    while true; do
        if ! count="$(run_thread_count "$tgid")"; then
            echo "ERROR: /proc/$tgid/task 在等待期间消失；工作进程可能已退出" >&2
            return 1
        fi
        if [[ "$count" -ge "$minimum" ]]; then
            echo "threads = $count，可以 migrate"
            return 0
        fi
        if ! kill -0 "${RUN_PID:-0}" 2>/dev/null; then
            echo "ERROR: 进程已退出，线程数仅 $count（< $minimum）" >&2
            return 1
        fi
        if [[ "$waited" -ge "$limit" ]]; then
            echo "ERROR: 等待线程超时，当前线程数 $count（< $minimum）" >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
}

run_wait_for_marker() {
    local log_path="$1" marker="$2" timeout="$3"
    echo "等待计算热区（$marker）..."
    local waited=0
    while [[ "$waited" -lt "$timeout" ]]; do
        if grep -Fq "$marker" "$log_path" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "${RUN_PID:-0}" 2>/dev/null; then
            echo "ERROR: llama 进程在出现计算热区标记前退出" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "ERROR: 等待计算热区标记超时（${timeout}s）：$marker" >&2
    return 1
}
