# llama.cpp 与 GCC 的端到端命令（K3）

从已有、未经 Chimera patched LLVM 构建的非 stripped ELF 开始：检查原产物 → 仅 stack-object 重编 → 检查并生成 gate 名单 → stack-object + gate 重编 → 严格检查 → prepare、verify、register、run。输入来源须由原构建记录确认；符号表本身不能证明编译器身份。原产物已经通过时，不需要人为制造失败。

Chimera 负责生成每轮的固定编译入口和合并名单。用户只设置路径，再运行正式 CLI 与项目自己的构建命令。`$RUN/stack/cc` 和 `cxx` 是自动生成的 C/C++ 编译器入口，将它们交给构建系统即可；不是 GCC 或 llama.cpp 的可运行产物。

每一块命令按顺序执行，构建命令非零或工具报错时停止，先查看该轮日志。修复阶段的 `check-elf` 不加 `--strict`，允许正常完成但检查失败的报告；最终严格检查必须返回 0、所有检查实际执行且 findings 为 0，才进入 prepare。不能用再次追加名单的循环代替问题定位。

## 公共环境

在已安装新版 Chimera、patched LLVM 和插件的 riscv64 K3 上设置：

```bash
set +e
set +u
tmux set-window-option remain-on-exit on

export CHIMERA="$PWD"  # 从源码仓库根目录运行
export VENV="$CHIMERA/.venv"  # 已安装Chimera的隔离环境
export PATH="$VENV/bin:$PATH"
export CHIMERA_TOOLCHAIN_BUILD="$HOME/.chimera/toolchain_build"
unset PYTHONPATH PYTHONHOME
export JOBS=2
```

先核对已安装的工具链及插件：

```bash
"$CHIMERA_TOOLCHAIN_BUILD/llvm/bin/clang" --version
"$CHIMERA_TOOLCHAIN_BUILD/llvm/bin/clang++" --version
ls -l "$CHIMERA_TOOLCHAIN_BUILD/plugins/lib/chimera/llvm/ChimeraStackObject.so" \
    "$CHIMERA_TOOLCHAIN_BUILD/plugins/lib/chimera/llvm/ChimeraVectorGate.so"
```

这些命令成功时直接进入下面的应用流程。路径不存在时，先定位实际工具链目录并设置 `CHIMERA_TOOLCHAIN_BUILD`。确实需要从源码构建时，必须提供 LLVM Git 源码根目录；普通安装默认不携带庞大的第三方源码。仓库的 `third_party/llvm` 已准备好且工具链源文件在当前仓库时，使用：

```bash
export CHIMERA_TOOLCHAIN_SOURCE_ROOT="$CHIMERA/preprocessing/offline/toolchain/llvm-21.1.0"
chimera-dev toolchain build patched-llvm --llvm-src "$CHIMERA/third_party/llvm"
chimera-dev toolchain build llvm-plugin --plugins stackobject vector-gate
```

上述 LLVM 源码路径必须实际存在，不能拿已安装的 `llvm/bin` 目录代替。错误“third-party bundle is not installed”发生在源码定位阶段，不表示现有编译器或插件已损坏。

下面两套流程各自设置新 `$RUN`。源码与构建依赖需事先准备；从原 ELF 到最终 ELF 使用同一份应用 Profile。新目录不能覆盖旧构建或编译计划。

## llama.cpp

替换原版 ELF 路径。源树应与该版本对应，并已包含目标 VLEN 所需的源码兼容补丁；显式 RVV intrinsic 的兼容性和编译器隐式向量化 gate 是不同问题。源码准备见[示例构建入口](../../examples/scripts/build/build_llamacpp.sh)。

```bash
export RUN=$HOME/.chimera/runs/llamacpp-$(date +%Y%m%d-%H%M%S)
export PROFILE="$CHIMERA/examples/platforms/k3/linux-riscv64-rvv-1024-to-256.toml"
export ORIGINAL_ELF=/实际路径/原版-build/bin/llama-perplexity
export LLAMA_SOURCE="$CHIMERA/examples/applications/llama-cpp/llama.cpp"
export MODEL="$CHIMERA/examples/applications/llama-cpp/model/tinyllama-1.1b-chat-v1.0.Q3_K_S.gguf"
export PROMPT_FILE="$CHIMERA/examples/applications/llama-cpp/prompt/file.txt"
mkdir -p "$RUN"

chimera-pkg check-elf --profile "$PROFILE" --strategy gate --input "$ORIGINAL_ELF" \
    --rebuild-stage metadata --rebuild-dir "$RUN/stack"
```

第一次全新构建仅启用 stack-object：

```bash
cmake -S "$LLAMA_SOURCE" -B "$RUN/build-stack" \
    -DCMAKE_C_COMPILER="$RUN/stack/cc" -DCMAKE_CXX_COMPILER="$RUN/stack/cxx" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS='-march=rv64gcv -mabi=lp64d' \
    -DCMAKE_CXX_FLAGS='-march=rv64gcv -mabi=lp64d' \
    -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_SHARED_LIBS=OFF \
    -DGGML_STATIC=ON -DGGML_SHARED=OFF -DGGML_NATIVE=OFF -DLLAMA_NATIVE=OFF \
    -DGGML_OPENMP=OFF -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF

cmake --build "$RUN/build-stack" --target llama-perplexity -j "$JOBS"

chimera-pkg check-elf --profile "$PROFILE" --strategy gate \
    --input "$RUN/build-stack/bin/llama-perplexity" \
    --rebuild-stage gate --rebuild-dir "$RUN/gate"
```

第二次全新构建保留 stack-object，使用刚生成的 gate 名单：

```bash
cmake -S "$LLAMA_SOURCE" -B "$RUN/build-gate" \
    -DCMAKE_C_COMPILER="$RUN/gate/cc" -DCMAKE_CXX_COMPILER="$RUN/gate/cxx" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS='-march=rv64gcv -mabi=lp64d' \
    -DCMAKE_CXX_FLAGS='-march=rv64gcv -mabi=lp64d' \
    -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_SHARED_LIBS=OFF \
    -DGGML_STATIC=ON -DGGML_SHARED=OFF -DGGML_NATIVE=OFF -DLLAMA_NATIVE=OFF \
    -DGGML_OPENMP=OFF -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF

cmake --build "$RUN/build-gate" --target llama-perplexity -j "$JOBS"

export ELF="$RUN/build-gate/bin/llama-perplexity"
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate --input "$ELF" \
    --json "$RUN/final.check.json" --inheritance-report "$RUN/final.inheritance.json"
```

严格验收通过后依次执行：

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" \
    --workspace llamacpp --workspace-root "$RUN/workspaces"

echo $$ > /proc/set_ai_thread
chimera-user verify --input "$ELF" --workspace "$RUN/workspaces/llamacpp"
chimera-user register --input "$ELF" --workspace "$RUN/workspaces/llamacpp"
chimera-user run --input "$ELF" --workspace "$RUN/workspaces/llamacpp" -- \
    -m "$MODEL" -f "$PROMPT_FILE" -t 1
```

本例关闭 OpenMP，运行单线程 perplexity，减少构建依赖；不是多线程性能或迁移基准。RVV 仍启用，gate 按当前源头名单处理。源码兼容补丁、模型、文本与 Runtime 条件缺失时不能把本页命令视为完整准备。

## GCC（C-only，xgcc 与 cc1）

两个原版 ELF 可沿用已确认的系统 GCC 构建。`PROFILE` 替换为你已选择的 GCC 应用 Profile；如果选择条件范围，在 `safety` 参数中显式设置 `unknown_stack_size_policy="assume-scalar-independent"`，默认保守策略不变。这是条件假设，不是对未知尺寸的独立性证明。使用同一份 Profile 进行所有检查与 prepare，详见[范围说明](../developer/unknown-stack-size-scope.md)。

```bash
export RUN=$HOME/.chimera/runs/gcc-$(date +%Y%m%d-%H%M%S)
export PROFILE=/实际路径/已选择范围策略的GCC应用.toml
export BASELINE_XGCC=/absolute/path/to/gcc-build-baseline/gcc/xgcc
export BASELINE_CC1=/absolute/path/to/gcc-build-baseline/gcc/cc1
export GCC_SOURCE=/absolute/path/to/gcc-15.2.0
mkdir -p "$RUN"

chimera-pkg check-elf --profile "$PROFILE" --strategy gate \
    --input "$BASELINE_XGCC" --input "$BASELINE_CC1" \
    --rebuild-stage metadata --rebuild-dir "$RUN/stack"
```

两个 ELF 顺序检查。完成后，第一次全新 `all-gcc` 构建仅启用 stack-object；build-machine 辅助工具仍用系统编译器：

```bash
mkdir "$RUN/build-stack"
cd "$RUN/build-stack"
"$GCC_SOURCE/configure" --prefix="$RUN/install-stack" --enable-languages=c \
    --disable-bootstrap --disable-multilib --with-system-zlib --enable-checking=release \
    CC="$RUN/stack/cc" CXX="$RUN/stack/cxx" \
    CC_FOR_BUILD=/usr/bin/gcc CXX_FOR_BUILD=/usr/bin/g++ \
    CFLAGS='-O2 -g -march=rv64gcv -mabi=lp64d' \
    CXXFLAGS='-O2 -g -march=rv64gcv -mabi=lp64d' LDFLAGS=''
make -j "$JOBS" all-gcc

chimera-pkg check-elf --profile "$PROFILE" --strategy gate \
    --input "$RUN/build-stack/gcc/xgcc" --input "$RUN/build-stack/gcc/cc1" \
    --rebuild-stage gate --rebuild-dir "$RUN/gate"
```

这一条命令自动合并两份报告的 gate 名单。第二次构建使用新的目录与新入口，不复用 stack 对象：

```bash
mkdir "$RUN/build-gate"
cd "$RUN/build-gate"
"$GCC_SOURCE/configure" --prefix="$RUN/install-gate" --enable-languages=c \
    --disable-bootstrap --disable-multilib --with-system-zlib --enable-checking=release \
    CC="$RUN/gate/cc" CXX="$RUN/gate/cxx" \
    CC_FOR_BUILD=/usr/bin/gcc CXX_FOR_BUILD=/usr/bin/g++ \
    CFLAGS='-O2 -g -march=rv64gcv -mabi=lp64d' \
    CXXFLAGS='-O2 -g -march=rv64gcv -mabi=lp64d' LDFLAGS=''
make -j "$JOBS" all-gcc

export XGCC="$RUN/build-gate/gcc/xgcc"
export CC1="$RUN/build-gate/gcc/cc1"
chimera-pkg check-elf --strict --profile "$PROFILE" --strategy gate \
    --input "$XGCC" --input "$CC1" \
    --json "$RUN/final-reports" --inheritance-report "$RUN/final-inheritance"
```

旧版 Python 包在并行链接时可能报 `elf_registry.json.tmp` 重命名失败。这是注册表写入冲突；保留当前构建目录与固定计划即可。确认没有其他编译或检查进程写注册表后，先核对 JSON 可读，再串行续编；两条命令都成功后重新执行上面的最终严格检查：

```bash
python -m json.tool "$HOME/.chimera/elf_registry.json" > /dev/null && \
    make -C "$RUN/build-gate" -j1 all-gcc
```

JSON 核对失败时停止，保留注册表用于诊断，不自动清空检查凭证。所有写入进程更新到带注册表进程锁的版本后，可恢复原来的并行度；无需重新 configure 或清理已完成对象。

严格验收通过后，先完成驱动的准备与运行：

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$XGCC" \
    --workspace xgcc --workspace-root "$RUN/workspaces"
echo $$ > /proc/set_ai_thread
chimera-user verify --input "$XGCC" --workspace "$RUN/workspaces/xgcc"
chimera-user register --input "$XGCC" --workspace "$RUN/workspaces/xgcc"
chimera-user run --input "$XGCC" --workspace "$RUN/workspaces/xgcc" -- --version
```

**cc1 的整体翻译仍有已知 OOM 阻塞。** 以下对整个 prepare 施加 12 GiB、swap 0 的服务内存限制，防止再次拖垮原机器；这是黑盒保护，不是翻译器修复，也不保证 12 GiB 能完成。需要 systemd 与相应管理权限；prepare 非零时停止，不执行后续 register/run。

```bash
systemd-run --unit "gcc-cc1-prepare-$(date +%s)" --wait --pipe \
    -p Type=exec -p MemoryMax=12G -p MemorySwapMax=0 -p OOMPolicy=stop \
    -p RuntimeMaxSec=6h --setenv="PATH=$PATH" \
    "$VENV/bin/chimera-pkg" prepare --profile "$PROFILE" --input "$CC1" \
    --workspace cc1 --workspace-root "$RUN/workspaces"

chimera-user verify --input "$CC1" --workspace "$RUN/workspaces/cc1"
chimera-user register --input "$CC1" --workspace "$RUN/workspaces/cc1"
printf '%s\n' 'int main(void) { return 0; }' > "$RUN/main.c"
chimera-user run --input "$CC1" --workspace "$RUN/workspaces/cc1" -- \
    -quiet -O2 "$RUN/main.c" -o "$RUN/main.s"
/usr/bin/gcc "$RUN/main.s" -o "$RUN/main"
"$RUN/main"
```

`xgcc --version` 只测试驱动；无系统头文件的 C 编译测试由独立准备、注册的 cc1 完成，再由系统 GCC 链接，最后应返回 0。C++ 的 cc1plus 不在本例范围内。

本页给出通用集成流程；新产物的检查、翻译、数值和迁移结果必须分别以当前实际日志为准。GCC适配的验证层次见[GCC指南](../developer/gcc-workflow.md)，llama参考构建约束见[gate说明](gate-build.md)。
