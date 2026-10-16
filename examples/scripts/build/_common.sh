CHIMERA_PKG="${CHIMERA_PKG:-chimera-pkg}"
CHIMERA_USER="${CHIMERA_USER:-chimera-user}"
CHIMERA_DEV="${CHIMERA_DEV:-chimera-dev}"
# 供 build_llamacpp*.sh source 的内部公共函数；示例 Workspace 由部署者显式打包。
#
# 构建参数约定（用户决定）：
#   - 默认只编 llama-perplexity；--target/-t 可重复指定要编的目标；
#   - 并行度默认 2；CHIMERA_LLAMA_JOBS 环境变量或 -j N / -jN / --jobs N 覆盖。
#
# Function-pointer/LTO 路线只检查可用内存和 swap，不替用户创建 swap。
#
# 用法：
#   source "$SCRIPT_DIR/_common.sh"
#   parse_llama_build_args "$@"
#   cmake --build "$BUILD" -j"$JOBS" "${BUILD_TARGETS[@]}"

chimera_example_artifact_root() {
    local id
    id="$(printf '%s' "${REPO_ROOT:?}" | sha256sum | awk '{print $1}')"
    printf '%s\n' "${CHIMERA_EXAMPLE_ARTIFACT_ROOT:-$HOME/.chimera/examples/$id/llamacpp}"
}

chimera_example_state_path() {
    local state
    if [[ -n "${CHIMERA_EXAMPLE_STATE_PATH:-}" ]]; then
        printf '%s\n' "${CHIMERA_EXAMPLE_STATE_PATH}"
        return 0
    fi
    state="$(git -C "$LLAMA" rev-parse --path-format=absolute --git-path chimera-example-state.json 2>/dev/null || true)"
    if [[ -z "$state" ]]; then
        state="$(git -C "$LLAMA" rev-parse --git-path chimera-example-state.json 2>/dev/null || true)"
        if [[ -z "$state" ]]; then
            # Release remediation checkouts are ordinary writable directories,
            # not submodules with a Git administrative directory.
            state="$LLAMA/.chimera-example-state.json"
        elif [[ "$state" != /* ]]; then
            state="$LLAMA/$state"
        fi
    fi
    printf '%s\n' "$state"
}

ensure_example_build_not_interrupted() {
    local state
    state="$(chimera_example_state_path 2>/dev/null || true)"
    if [[ -n "$state" && -f "$state" ]]; then
        echo "ERROR: 检测到未完成的样例构建状态，拒绝继续：$LLAMA" >&2
        echo "       请删除上述样例构建状态文件后重试：$state" >&2
        return 1
    fi
}

chimera_example_state_begin() {
    local state temporary
    state="$(chimera_example_state_path)"
    temporary="$state.tmp.$$"
    printf '{"schema_version":1,"example":"%s"}\n' "${CHIMERA_EXAMPLE_CLEAN_NAME:?}" >"$temporary"
    mv -f -- "$temporary" "$state"
}

chimera_example_state_clear() {
    local state
    state="$(chimera_example_state_path 2>/dev/null || true)"
    [[ -z "$state" ]] || rm -f -- "$state"
}

# Build and cleanup commands share one advisory lock for the llama.cpp source
# checkout.  The descriptor is released by the kernel if a process is killed,
# so an interrupted build cannot leave a stale lock file that blocks recovery.
CHIMERA_EXAMPLE_LOCK_FD=""
CHIMERA_EXAMPLE_LOCK_HELD=0
chimera_example_operation_lock() {
    local lock_path="${CHIMERA_EXAMPLE_LOCK_PATH:-$HOME/.chimera/.llamacpp-source.lock}"
    mkdir -p "$(dirname "$lock_path")"
    exec {CHIMERA_EXAMPLE_LOCK_FD}>"$lock_path"
    if ! flock -n "$CHIMERA_EXAMPLE_LOCK_FD"; then
        echo "ERROR: another Chimera llama.cpp operation is using the source; wait and retry" >&2
        eval "exec ${CHIMERA_EXAMPLE_LOCK_FD}>&-"
        CHIMERA_EXAMPLE_LOCK_FD=""
        return 1
    fi
    CHIMERA_EXAMPLE_LOCK_HELD=1
}

chimera_example_operation_unlock() {
    if [[ "$CHIMERA_EXAMPLE_LOCK_HELD" == "1" ]]; then
        flock -u "$CHIMERA_EXAMPLE_LOCK_FD" || true
        eval "exec ${CHIMERA_EXAMPLE_LOCK_FD}>&-"
        CHIMERA_EXAMPLE_LOCK_FD=""
        CHIMERA_EXAMPLE_LOCK_HELD=0
    fi
}

# Release wheels do not carry the llama.cpp checkout.  Keep that checkout in
# the user's writable Chimera area and pin it to the commit recorded by the
# package.  This helper is intentionally opt-in; source checkouts continue to
# use their superproject gitlink and existing cleanup path.
ensure_packaged_llama_source() {
    [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]] || return 0
    local parent commit repository current
    parent="$(dirname "$LLAMA")"
    commit="${CHIMERA_LLAMA_COMMIT:-4fc4ec554}"
    repository="${CHIMERA_LLAMA_REPOSITORY:-https://github.com/ggml-org/llama.cpp.git}"
    mkdir -p "$parent"
    if [[ ! -d "$LLAMA/.git" ]]; then
        [[ ! -e "$LLAMA" ]] || {
            echo "ERROR: release llama.cpp source path is not a Git checkout: $LLAMA" >&2
            return 1
        }
        git clone "$repository" "$LLAMA"
    fi
    if ! git -C "$LLAMA" diff --quiet 2>/dev/null ||
       ! git -C "$LLAMA" diff --cached --quiet 2>/dev/null; then
        echo "ERROR: release llama.cpp checkout has tracked/staged modifications: $LLAMA" >&2
        git -C "$LLAMA" status --short >&2 || true
        return 1
    fi
    current="$(git -C "$LLAMA" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$current" != "$commit" && "$current" != "$(git -C "$LLAMA" rev-parse "$commit" 2>/dev/null || true)" ]]; then
        git -C "$LLAMA" checkout --detach "$commit"
    fi
}

# Discover the system LLVM OpenMP development files for the patched Clang
# builds.  Do not add the distro Clang resource directory to the include
# search path: duplicate resource headers such as stdatomic.h share include
# guards, so Clang's include_next fallback can silently lose all definitions.
# Instead expose only omp.h through a dedicated include directory.
detect_chimera_openmp() {
    local package="${CHIMERA_OPENMP_DEV_PACKAGE:-libomp-21-dev}"
    local runtime_package="${CHIMERA_OPENMP_RUNTIME_PACKAGE:-libomp5}"
    local header="${CHIMERA_OPENMP_HEADER:-}"
    local library="${CHIMERA_OPENMP_LIBRARY:-}"
    local include_dir="${CHIMERA_OPENMP_INCLUDE_DIR:-${TOOLCHAIN_ROOT:-$HOME/.chimera/toolchain_build}/system-openmp/include}"
    local candidate

    # Complete explicit overrides are intentionally independent of Debian.
    # This also makes cross/sysroot builds possible when dpkg-query is absent.
    if [[ -z "$header" || -z "$library" ]]; then
        command -v dpkg-query >/dev/null 2>&1 || {
            echo "ERROR: dpkg-query is required when CHIMERA_OPENMP_HEADER and" >&2
            echo "       CHIMERA_OPENMP_LIBRARY are not both provided" >&2
            return 1
        }
        dpkg-query -W -f='${Status}\n' "$package" 2>/dev/null |
            grep -q 'install ok installed' || {
            echo "ERROR: $package is not installed; install the LLVM OpenMP dev package" >&2
            echo "       fix (run as administrator): apt-get install $package $runtime_package" >&2
            return 1
        }

        if [[ -z "$header" ]]; then
            header="$(dpkg-query -L "$package" 2>/dev/null |
                awk '/\/omp\.h$/ {print; exit}')"
        fi
        if [[ -z "$library" ]]; then
            candidate="$(dpkg-query -L "$package" 2>/dev/null |
                awk '/\/libomp\.so$/ {print; exit}')"
            [[ -e "$candidate" ]] && library="$candidate"
        fi
        if [[ -z "$library" ]]; then
            while IFS= read -r candidate; do
                if [[ -e "$candidate" ]]; then
                    library="$candidate"
                    break
                fi
            done < <(dpkg-query -L "$runtime_package" 2>/dev/null |
                awk '/\/libomp\.so(\.[0-9]+)*$/')
        fi
    fi
    if [[ ! -f "$header" || ! -e "$library" ]]; then
        echo "ERROR: system LLVM OpenMP does not provide a usable omp.h/libomp.so" >&2
        echo "       header='$header' library='$library'" >&2
        echo "       checked packages: $package, $runtime_package" >&2
        return 1
    fi
    library="$(readlink -e "$library")"
    [[ -n "$library" && -e "$library" ]] || {
        echo "ERROR: unable to resolve OpenMP runtime library: $library" >&2
        return 1
    }
    mkdir -p "$include_dir"
    ln -sfn -- "$header" "$include_dir/omp.h"
    [[ -f "$include_dir/omp.h" ]] || {
        echo "ERROR: failed to create isolated OpenMP header: $include_dir/omp.h" >&2
        return 1
    }

    CHIMERA_OPENMP_CMAKE_ARGS=(
        -DGGML_OPENMP=ON
        "-DOpenMP_C_FLAGS=-fopenmp -isystem $include_dir"
        "-DOpenMP_CXX_FLAGS=-fopenmp -isystem $include_dir"
        -DOpenMP_C_LIB_NAMES=omp
        -DOpenMP_CXX_LIB_NAMES=omp
        "-DOpenMP_omp_LIBRARY=$library"
    )
    echo "system LLVM OpenMP: header=$header include=$include_dir library=$library"
}

verify_chimera_openmp_build() {
    local build_dir="$1"
    local commands="$build_dir/compile_commands.json"
    [[ -f "$commands" ]] || {
        echo "ERROR: missing compile_commands.json: $commands" >&2
        return 1
    }
    grep -q -- '-DGGML_USE_OPENMP' "$commands" || {
        echo "ERROR: llama.cpp was configured without GGML_USE_OPENMP: $build_dir" >&2
        echo "       inspect CMake output for 'OpenMP not found'" >&2
        return 1
    }
}

# Verify the complete single-face census chain before touching a real build.
# The probe intentionally goes through the installed `chimera-pkg` wrapper rather
# than invoking clang directly: an old Python wrapper, patched clang, or pass
# plugin must fail here instead of producing an empty new TSV alongside an
# old JSONL stream.
verify_chimera_implicit_vector_census_toolchain() (
    set -euo pipefail
CHIMERA_PKG="${CHIMERA_PKG:-chimera-pkg}"
CHIMERA_USER="${CHIMERA_USER:-chimera-user}"
    local probe_dir source decision census assembly
    probe_dir="$(mktemp -d)"
    trap 'rm -rf "$probe_dir"' EXIT
    source="$probe_dir/probe.c"
    decision="$probe_dir/probe.json"
    assembly="$probe_dir/probe.s"
    census="$probe_dir/probe.gate_names.implicit_vector_census.tsv"

    cat >"$source" <<'EOF'
void chimera_probe_lv(float *__restrict dst, const float *__restrict src) {
    for (int i = 0; i < 64; ++i)
        dst[i] = src[i] + 1.0f;
}

void chimera_probe_memop(void *dst, const void *src) {
    __builtin_memcpy(dst, src, 64);
}
EOF
    python3 - "$decision" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "decision": {
        "vector_gate": {"enabled": True},
        "gate": {"enabled": True, "names": [
            "chimera_probe_lv", "chimera_probe_memop",
        ]},
        "function_pointer_plugin": False,
        "stack_object_plugin": False,
    },
}, indent=2), encoding="utf-8")
PY

    _probe_failure() {
        local message="$1"
        echo "ERROR: $message" >&2
        echo "       chimera=$(command -v chimera-pkg)" >&2
        echo "       clang=${TOOLCHAIN_ROOT:-<unset>}/llvm/bin/clang" >&2
        echo "       plugin=${PLUGIN_DIR:-<unset>}/ChimeraVectorGate.so" >&2
        echo "       census=$census" >&2
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
            echo "       release wheel resources may be incomplete or not executable; reinstall the wheel and verify toolchain resources" >&2
            echo "       do not rebuild from site-packages/third_party; release wheels do not ship LLVM source" >&2
        else
            echo "       rebuild with: make develop" >&2
            echo "         $CHIMERA_DEV toolchain build patched-llvm --llvm-src '$REPO_ROOT/third_party/llvm' --toolchain-build '${TOOLCHAIN_ROOT:-$HOME/.chimera/toolchain_build}'" >&2
            echo "         $CHIMERA_DEV toolchain build llvm-plugin --plugins stackobject vector-gate --llvm-src '$REPO_ROOT/third_party/llvm' --toolchain-build '${TOOLCHAIN_ROOT:-$HOME/.chimera/toolchain_build}'" >&2
        fi
        return 1
    }

    if ! $CHIMERA_PKG llvm --list "$decision" -- -O2 -march=rv64gcv \
            -S "$source" -o "$assembly"; then
        _probe_failure "Chimera implicit-vector census toolchain probe failed"
        return 1
    fi

    if ! grep -Fq $'implicit-vector-census\tLV\tchimera_probe_lv\tblocked' \
            "$census" || \
       ! grep -Fq $'implicit-vector-census\tMEMOP\tchimera_probe_memop\tblocked' \
            "$census"; then
        _probe_failure "installed wrapper/LLVM/plugin did not emit the expected census"
        return 1
    fi
    echo "implicit-vector census toolchain probe: LV/MEMOP blocked records verified"
)

parse_llama_build_args() {
    JOBS="${CHIMERA_LLAMA_JOBS:-2}"
    BUILD_TARGETS=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -j|--jobs)
                [[ $# -ge 2 ]] || { echo "ERROR: $1 需要数值参数" >&2; return 2; }
                JOBS="$2"
                shift 2
                ;;
            -j*)
                JOBS="${1#-j}"
                shift
                ;;
            --target|-t)
                [[ $# -ge 2 ]] || { echo "ERROR: $1 需要目标名" >&2; return 2; }
                BUILD_TARGETS+=(--target "$2")
                shift 2
                ;;
            --target=*)
                BUILD_TARGETS+=(--target "${1#--target=}")
                shift
                ;;
            -h|--help)
                echo "用法: bash $0 [--target 目标]... [-j N]"
                echo "  --target/-t  指定构建目标（可重复；默认 llama-perplexity）"
                echo "  -j/--jobs    并行度（默认 2）"
                exit 0
                ;;
            *)
                echo "ERROR: 未知参数: $1（支持 --target/-t、-j/--jobs）" >&2
                return 2
                ;;
        esac
    done

    if [[ ${#BUILD_TARGETS[@]} -eq 0 ]]; then
        BUILD_TARGETS=(--target llama-perplexity)
    fi
}

# ---------------------------------------------------------------
# Bootstrap and resource checks
# ---------------------------------------------------------------

_chimera_error() {
    echo "ERROR: $*" >&2
    return 1
}

ensure_chimera_host_tools() {
    local missing=() tool
    for tool in bash git cmake ninja make flock python3 awk grep sed mktemp readlink ln rm cp find \
        chmod sha256sum df ls cmp dirname tail tr uname; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        _chimera_error "缺少宿主工具：${missing[*]}"
        return 1
    fi

    if [[ "${CHIMERA_SKIP_BASELINE_COMPILER:-0}" != "1" ]]; then
        local compiler compiler_missing=()
        for compiler in "${BASELINE_CC:-cc}" "${BASELINE_CXX:-c++}"; do
            command -v "$compiler" >/dev/null 2>&1 || compiler_missing+=("$compiler")
        done
        if [[ ${#compiler_missing[@]} -gt 0 ]]; then
            _chimera_error "缺少宿主 C/C++ 编译器：${compiler_missing[*]}"
            return 1
        fi
    fi

    if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
        _chimera_error "构建脚本只支持 Linux（当前：$(uname -s 2>/dev/null || echo unknown)）"
        return 1
    fi
    local machine
    machine="$(uname -m 2>/dev/null || true)"
    if [[ "$machine" != "riscv64" && "$machine" != "riscv" ]]; then
        _chimera_error "构建脚本需要 riscv64 宿主（当前：${machine:-unknown}）"
        return 1
    fi
    if ! python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit(f"Python 3.11+ required (current: {sys.version.split()[0]})")
PY
    then
        echo "ERROR: Python 3.11+ is required by the Chimera CLI." >&2
        return 1
    fi
    return 0
}

ensure_chimera_cli_current() {
    local cli
    cli="$(command -v chimera-pkg 2>/dev/null || true)"
    [[ -n "$cli" ]] || {
        echo "ERROR: Chimera CLI 不在 PATH；请先执行 make install 或 make develop。" >&2
        return 1
    }
    if [[ -n "${CHIMERA_EXAMPLE_DISPATCH_ROOT:-}" ]]; then
        local dispatch_root
        dispatch_root="$(cd "$CHIMERA_EXAMPLE_DISPATCH_ROOT" 2>/dev/null && pwd -P)" || {
            echo "ERROR: example dispatcher source root 不可访问：$CHIMERA_EXAMPLE_DISPATCH_ROOT" >&2
            return 1
        }
        if [[ "$dispatch_root" != "$(cd "$REPO_ROOT" && pwd -P)" ]]; then
            echo "ERROR: example dispatcher source root 与脚本仓库不一致" >&2
            echo "       dispatcher=$dispatch_root" >&2
            echo "       script=$REPO_ROOT" >&2
            return 1
        fi
        return 0
    fi
    if ! python3 - "$REPO_ROOT" <<'PY'
import pathlib, sys
try:
    import chimera
except Exception as error:
    print(f"cannot import chimera: {error}", file=sys.stderr)
    raise SystemExit(1)
root = pathlib.Path(sys.argv[1]).resolve()
module = pathlib.Path(chimera.__file__).resolve()
if root.joinpath("cli", "chimera") not in module.parents:
    print(f"Chimera CLI is not from current repository: {module}", file=sys.stderr)
    raise SystemExit(1)
PY
    then
        echo "ERROR: PATH 中的 Chimera CLI 不是当前仓库版本：$REPO_ROOT" >&2
        echo "       请执行：make install 或 make develop" >&2
        return 1
    fi
}

ensure_chimera_profile() {
    # Profiles are supplied directly to check-elf/prepare.  Keep this helper
    # as a no-op for older build scripts that still call it internally.
    return 0
}

_submodule_dirty() {
    local path="$1"
    git -C "$path" diff --quiet 2>/dev/null || return 0
    git -C "$path" diff --cached --quiet 2>/dev/null || return 0
    return 1
}

ensure_chimera_submodule_clean() {
    local relative="$1" path="$REPO_ROOT/$1"
    if [[ -d "$path" ]] && git -C "$path" rev-parse --git-dir >/dev/null 2>&1 &&
       _submodule_dirty "$path"; then
        echo "ERROR: 子模块存在 tracked/staged 修改，拒绝运行：$relative" >&2
        git -C "$path" status --short >&2 || true
        if [[ "$relative" == "examples/applications/llama-cpp/llama.cpp" && -n "${CHIMERA_EXAMPLE_CLEAN_NAME:-}" ]]; then
            echo "       如确认是中断残留，请删除样例状态文件：$(chimera_example_state_path 2>/dev/null || true)" >&2
        elif [[ "$relative" == "third_party/llvm" ]]; then
            echo "       如确认是中断残留，请执行：$CHIMERA_DEV toolchain clean patched-llvm --llvm-src '$path'" >&2
        fi
        return 1
    fi
    return 0
}

ensure_chimera_submodule() {
    local relative="$1" marker="$2"
    local path="$REPO_ROOT/$relative" expected actual
    expected="$(git -C "$REPO_ROOT" ls-tree HEAD -- "$relative" 2>/dev/null |
        awk '$1 == "160000" {print $3; exit}')"
    [[ -n "$expected" ]] || {
        _chimera_error "超级工程没有记录子模块：$relative"
        return 1
    }
    ensure_chimera_submodule_clean "$relative" || return 1
    if [[ ! -e "$path/$marker" ]]; then
        echo "初始化子模块：$relative"
        git -C "$REPO_ROOT" submodule update --init "$relative" || {
            echo "ERROR: 子模块初始化失败：$relative" >&2
            echo "       可重试：git -C '$REPO_ROOT' submodule update --init '$relative'" >&2
            return 1
        }
    fi
    [[ -e "$path/$marker" ]] || {
        _chimera_error "子模块仍未就绪：$path/$marker"
        return 1
    }
    actual="$(git -C "$path" rev-parse HEAD 2>/dev/null || true)"
    [[ "$actual" == "$expected" ]] || {
        echo "ERROR: 子模块 commit 不匹配：$relative" >&2
        echo "       expected=$expected actual=${actual:-missing}" >&2
        echo "       请手动确认后执行：git -C '$REPO_ROOT' submodule update --init '$relative'" >&2
        if [[ "$relative" == "examples/applications/llama-cpp/llama.cpp" && -n "${CHIMERA_EXAMPLE_CLEAN_NAME:-}" ]]; then
            echo "       如确认是中断残留，请删除样例状态文件：$(chimera_example_state_path 2>/dev/null || true)" >&2
        elif [[ "$relative" == "third_party/llvm" ]]; then
            echo "       如确认是中断残留，请执行：$CHIMERA_DEV toolchain clean patched-llvm --llvm-src '$path'" >&2
        fi
        return 1
    }
}

_toolchain_prefix_ready() {
    [[ -x "$TOOLCHAIN_ROOT/llvm/bin/clang" &&
       -x "$TOOLCHAIN_ROOT/llvm/bin/clang++" &&
       -d "$TOOLCHAIN_ROOT/llvm/lib/cmake/llvm" ]]
}

_plugin_ready() {
    local name
    for name in "$@"; do
        [[ -f "$TOOLCHAIN_ROOT/plugins/lib/chimera/llvm/$name.so" ]] || return 1
    done
}

_shim_ready() {
    [[ -x "$HOME/.chimera/bin/clang" && -x "$HOME/.chimera/bin/clang++" ]]
}

install_llamacpp_scalar() {
    python3 "$REPO_ROOT/examples/scripts/build/install_llamacpp_scalar.py" \
        "$REPO_ROOT/examples/applications/llama-cpp/scalar" \
        "$HOME/.chimera/scalar"
}

bootstrap_llamacpp_dependencies() {
    local mode="${1:-}"
    [[ "$mode" == "stats" || "$mode" == "full" ]] || {
        _chimera_error "bootstrap_llamacpp_dependencies 只接受 stats 或 full"
        return 1
    }
    ensure_example_build_not_interrupted || return 1
    ensure_chimera_host_tools || return 1
    ensure_chimera_cli_current || return 1
    ensure_chimera_profile || return 1
    if [[ "$mode" == "full" ]]; then
        install_llamacpp_scalar || return 1
    fi

    local llvm_src="$REPO_ROOT/third_party/llvm"
    if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" != "1" ]]; then
        ensure_chimera_submodule "examples/applications/llama-cpp/llama.cpp" "CMakeLists.txt" || return 1
        if [[ "$mode" == "full" ]]; then
            ensure_chimera_submodule "third_party/llvm" "llvm/CMakeLists.txt" || return 1
        else
            # stats 不初始化 SVF，但已有 checkout 也不能带着用户修改运行。
            ensure_chimera_submodule_clean "third_party/SVF" || return 1
            # Missing plugins/shims also need the LLVM checkout for the plugin
            # rebuild, even when an older patched-LLVM prefix is still present.
            if ! _toolchain_prefix_ready ||
               ! _plugin_ready ChimeraStackObject ChimeraVectorGate ||
               ! _shim_ready; then
                ensure_chimera_submodule "third_party/llvm" "llvm/CMakeLists.txt" || return 1
            else
                ensure_chimera_submodule_clean "third_party/llvm" || return 1
            fi
        fi
    fi

    if ! _toolchain_prefix_ready; then
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
            _chimera_error "release wheel toolchain is incomplete; rebuild it with chimera-dev toolchain"
            return 1
        fi
        echo "patched LLVM 缺失，开始构建。"
        $CHIMERA_DEV toolchain build patched-llvm \
            --llvm-src "$llvm_src" --toolchain-build "$TOOLCHAIN_ROOT" || return 1
    fi

    local plugins=()
    if [[ "$mode" == "full" ]]; then
        if ! _plugin_ready ChimeraStackObject ChimeraVectorGate ||
           ! _shim_ready; then
            plugins=(stackobject vector-gate)
        fi
    elif ! _plugin_ready ChimeraStackObject ChimeraVectorGate || ! _shim_ready; then
        plugins=(stackobject vector-gate)
    fi
    if [[ ${#plugins[@]} -gt 0 ]]; then
        if [[ "${CHIMERA_EXAMPLE_PACKAGED:-0}" == "1" ]]; then
            _chimera_error "release wheel plugins are incomplete; rebuild them with chimera-dev toolchain"
            return 1
        fi
        echo "$CHIMERA_PKG llvm 插件缺失，开始构建：${plugins[*]}"
        $CHIMERA_DEV toolchain build llvm-plugin --plugins "${plugins[@]}" \
            --llvm-src "$llvm_src" --toolchain-build "$TOOLCHAIN_ROOT" || return 1
    fi

    if ! _toolchain_prefix_ready; then
        _chimera_error "patched LLVM 构建后仍缺少 clang/clang++"
        return 1
    fi
    if ! _shim_ready; then
        _chimera_error "LLVM plugin 构建后仍缺少 compiler shim"
        return 1
    fi
    if [[ "$mode" == "full" ]]; then
        if ! _plugin_ready ChimeraStackObject ChimeraVectorGate; then
            _chimera_error "full bootstrap 后仍缺少 StackObject/VectorGate 插件"
            return 1
        fi
    else
        if ! _plugin_ready ChimeraStackObject ChimeraVectorGate; then
            _chimera_error "stats bootstrap 后仍缺少 StackObject/VectorGate 插件"
            return 1
        fi
    fi
    return 0
}

ensure_stats_decision_dependencies() {
    local decision="$1"
    if python3 - "$decision" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if (document.get("decision") or {}).get("function_pointer_plugin") else 1)
PY
    then
        local fp="$TOOLCHAIN_ROOT/plugins/lib/chimera/llvm/ChimeraFunctionPointer.so"
        if [[ ! -f "$fp" || ! -d "$TOOLCHAIN_ROOT/svf/lib/cmake/SVF" ]]; then
            echo "ERROR: stats 决策需要 FunctionPointer/SVF，但 stats bootstrap 不会自动初始化 SVF。" >&2
            echo "       请先执行：" >&2
            echo "         git -C '$REPO_ROOT' submodule update --init third_party/SVF" >&2
            echo "         $CHIMERA_DEV toolchain build svf --llvm-src '$REPO_ROOT/third_party/llvm' --svf-dir '$REPO_ROOT/third_party/SVF' --toolchain-build '$TOOLCHAIN_ROOT'" >&2
            echo "         $CHIMERA_DEV toolchain build llvm-plugin --plugins function-pointer --llvm-src '$REPO_ROOT/third_party/llvm' --toolchain-build '$TOOLCHAIN_ROOT'" >&2
            return 1
        fi
    fi
    return 0
}

check_chimera_lto_capacity() {
    local meminfo="${CHIMERA_MEMINFO_PATH:-/proc/meminfo}"
    local min_kb=$((16 * 1024 * 1024)) available swap total
    [[ -r "$meminfo" ]] || {
        echo "ERROR: 无法读取 $meminfo，不能验证 FunctionPointer/LTO 的 16 GiB 内存要求；不创建 swap。" >&2
        return 1
    }
    available="$(awk '$1 == "MemAvailable:" {print $2; exit}' "$meminfo")"
    swap="$(awk '$1 == "SwapTotal:" {print $2; exit}' "$meminfo")"
    [[ "$available" =~ ^[0-9]+$ && "$swap" =~ ^[0-9]+$ ]] || {
        echo "ERROR: $meminfo 缺少 MemAvailable/SwapTotal，不能验证 LTO 容量；不创建 swap。" >&2
        return 1
    }
    total=$((available + swap))
    if (( total < min_kb )); then
        echo "ERROR: FunctionPointer/LTO 需要至少 16 GiB 可用内存+swap；当前 $((total / 1024 / 1024)) GiB。" >&2
        echo "       请由管理员预先配置足够 swap 后重试；脚本不会调用 swapon 或创建 swapfile。" >&2
        return 1
    fi
    echo "LTO capacity: $((available / 1024 / 1024)) GiB memory + $((swap / 1024 / 1024)) GiB swap"
}
